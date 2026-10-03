"""
Collector for Windows Registry Auto-Start Extensibility Points (ASEPs).
Inspects Run, RunOnce, Winlogon, IFEO Debuggers, Active Setup, AppInit DLLs, and Policies.
"""

import os
from typing import List, Dict, Tuple, Optional
from core.models import StartupEntry, ASEPCategory
from core.collectors.base import BaseCollector

try:
    import winreg
    HKEY_LOCAL_MACHINE = winreg.HKEY_LOCAL_MACHINE
    HKEY_CURRENT_USER = winreg.HKEY_CURRENT_USER
except ImportError:
    winreg = None
    HKEY_LOCAL_MACHINE = 0x80000002
    HKEY_CURRENT_USER = 0x80000001


class RegistryCollector(BaseCollector):
    """Enumerates Windows Registry persistence vectors."""

    # Standard Run & RunOnce targets
    STANDARD_RUN_KEYS = [
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", ASEPCategory.REGISTRY_RUN, "HKLM"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", ASEPCategory.REGISTRY_RUNONCE, "HKLM"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx", ASEPCategory.REGISTRY_RUNONCE, "HKLM"),
        (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", ASEPCategory.REGISTRY_RUN, "HKCU"),
        (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", ASEPCategory.REGISTRY_RUNONCE, "HKCU"),
        (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx", ASEPCategory.REGISTRY_RUNONCE, "HKCU"),
        
        # WOW6432Node (32-bit persistence on 64-bit systems)
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", ASEPCategory.REGISTRY_RUN, "HKLM-WoW64"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", ASEPCategory.REGISTRY_RUNONCE, "HKLM-WoW64"),
        
        # Explorer Policies
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", ASEPCategory.REGISTRY_POLICIES, "HKLM-Policies"),
        (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", ASEPCategory.REGISTRY_POLICIES, "HKCU-Policies"),
    ]

    def collect(self) -> List[StartupEntry]:
        if not winreg:
            return []
        entries: List[StartupEntry] = []
        
        # 1. Enumerate standard Run & RunOnce keys
        entries.extend(self._collect_standard_run_keys())
        
        # 2. Enumerate Winlogon Persistence (Shell, Userinit, Taskman)
        entries.extend(self._collect_winlogon_keys())
        
        # 3. Enumerate Image File Execution Options (IFEO) Debuggers
        entries.extend(self._collect_ifeo_keys())
        
        # 4. Enumerate Active Setup StubPath persistence
        entries.extend(self._collect_active_setup_keys())
        
        # 5. Enumerate AppInit_DLLs
        entries.extend(self._collect_appinit_dlls())

        return entries

    def _get_startup_approved_status(self, root_key: int, entry_name: str) -> bool:
        """Checks StartupApproved status in registry. 0x02 = enabled, 0x03 or other = disabled."""
        subkeys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"
        ]
        for subkey in subkeys:
            try:
                with winreg.OpenKey(root_key, subkey, 0, winreg.KEY_READ) as k:
                    val_bytes, _ = winreg.QueryValueEx(k, entry_name)
                    if isinstance(val_bytes, (bytes, bytearray)) and len(val_bytes) > 0:
                        # 0x02 byte indicates enabled
                        return val_bytes[0] in (0x02, 0x00, 0x01)
            except (FileNotFoundError, OSError):
                continue
        return True  # Default to enabled if not explicitly marked

    def _collect_standard_run_keys(self) -> List[StartupEntry]:
        results: List[StartupEntry] = []
        for root_key, subkey_path, category, context_prefix in self.STANDARD_RUN_KEYS:
            try:
                with winreg.OpenKey(root_key, subkey_path, 0, winreg.KEY_READ) as key:
                    num_values = winreg.QueryInfoKey(key)[1]
                    for i in range(num_values):
                        try:
                            name, val, val_type = winreg.EnumValue(key, i)
                            if not val or not isinstance(val, str):
                                continue
                            
                            resolved_path, args = self.parse_command_line(val)
                            enabled = self._get_startup_approved_status(root_key, name)
                            
                            # Clean remediation command
                            root_str = "HKLM" if root_key == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                            rem_cmd = f'Remove-ItemProperty -Path "{root_str}:\\{subkey_path}" -Name "{name}" -ErrorAction SilentlyContinue'
                            
                            entry = StartupEntry(
                                name=name if name else "(Default)",
                                category=category,
                                location=f"{context_prefix}\\{subkey_path}",
                                raw_command=str(val),
                                resolved_path=resolved_path,
                                arguments=args,
                                enabled=enabled,
                                user_context=context_prefix,
                                remediation_command=rem_cmd
                            )
                            results.append(entry)
                        except (OSError, ValueError):
                            continue
            except (FileNotFoundError, PermissionError, OSError):
                continue
        return results

    def _collect_winlogon_keys(self) -> List[StartupEntry]:
        results: List[StartupEntry] = []
        winlogon_targets = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "HKLM"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "HKCU")
        ]
        
        watch_values = ["Userinit", "Shell", "Taskman", "Notify", "System", "VMApplet"]
        
        for root_key, subkey_path, context in winlogon_targets:
            try:
                with winreg.OpenKey(root_key, subkey_path, 0, winreg.KEY_READ) as key:
                    for val_name in watch_values:
                        try:
                            val, val_type = winreg.QueryValueEx(key, val_name)
                            if not val or not isinstance(val, str):
                                continue
                            
                            val_str = str(val).strip()
                            # Normal defaults:
                            # Userinit -> "C:\Windows\system32\userinit.exe,"
                            # Shell -> "explorer.exe"
                            # If HKCU Shell/Userinit exists or HKLM deviates, it's critical to inspect!
                            for part in val_str.split(','):
                                part = part.strip()
                                if not part:
                                    continue
                                resolved_path, args = self.parse_command_line(part)
                                root_str = "HKLM" if root_key == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                                rem_cmd = f'Set-ItemProperty -Path "{root_str}:\\{subkey_path}" -Name "{val_name}" -Value "explorer.exe"' if val_name == "Shell" else f'Set-ItemProperty -Path "{root_str}:\\{subkey_path}" -Name "{val_name}" -Value "C:\\Windows\\System32\\userinit.exe,"'
                                
                                entry = StartupEntry(
                                    name=f"Winlogon {val_name}",
                                    category=ASEPCategory.REGISTRY_WINLOGON,
                                    location=f"{context}\\{subkey_path}\\{val_name}",
                                    raw_command=part,
                                    resolved_path=resolved_path,
                                    arguments=args,
                                    enabled=True,
                                    user_context=context,
                                    remediation_command=rem_cmd
                                )
                                results.append(entry)
                        except (FileNotFoundError, OSError):
                            continue
            except (FileNotFoundError, PermissionError, OSError):
                continue
        return results

    def _collect_ifeo_keys(self) -> List[StartupEntry]:
        """Scans Image File Execution Options for 'Debugger' persistence."""
        results: List[StartupEntry] = []
        ifeo_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ifeo_path, 0, winreg.KEY_READ) as ifeo_key:
                num_subkeys = winreg.QueryInfoKey(ifeo_key)[0]
                for i in range(num_subkeys):
                    try:
                        target_exe = winreg.EnumKey(ifeo_key, i)
                        sub_path = f"{ifeo_path}\\{target_exe}"
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub_path, 0, winreg.KEY_READ) as target_key:
                            try:
                                debugger_val, _ = winreg.QueryValueEx(target_key, "Debugger")
                                if debugger_val and isinstance(debugger_val, str):
                                    resolved_path, args = self.parse_command_line(debugger_val)
                                    rem_cmd = f'Remove-ItemProperty -Path "HKLM:\\{sub_path}" -Name "Debugger" -ErrorAction SilentlyContinue'
                                    
                                    entry = StartupEntry(
                                        name=f"IFEO Hijack: {target_exe}",
                                        category=ASEPCategory.REGISTRY_IFEO,
                                        location=f"HKLM\\{sub_path}\\Debugger",
                                        raw_command=str(debugger_val),
                                        resolved_path=resolved_path,
                                        arguments=args,
                                        enabled=True,
                                        user_context="HKLM (System-wide)",
                                        remediation_command=rem_cmd
                                    )
                                    results.append(entry)
                            except FileNotFoundError:
                                pass
                    except (OSError, ValueError):
                        continue
        except (FileNotFoundError, PermissionError, OSError):
            pass
        return results

    def _collect_active_setup_keys(self) -> List[StartupEntry]:
        """Scans Active Setup Installed Components for 'StubPath' execution on logon."""
        results: List[StartupEntry] = []
        targets = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Active Setup\Installed Components", "HKLM"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Active Setup\Installed Components", "HKCU")
        ]
        
        for root_key, base_path, context in targets:
            try:
                with winreg.OpenKey(root_key, base_path, 0, winreg.KEY_READ) as base_key:
                    num_subkeys = winreg.QueryInfoKey(base_key)[0]
                    for i in range(num_subkeys):
                        try:
                            guid_key = winreg.EnumKey(base_key, i)
                            full_sub = f"{base_path}\\{guid_key}"
                            with winreg.OpenKey(root_key, full_sub, 0, winreg.KEY_READ) as comp_key:
                                try:
                                    stub_path, _ = winreg.QueryValueEx(comp_key, "StubPath")
                                    if stub_path and isinstance(stub_path, str):
                                        # Get friendly component name if available
                                        try:
                                            comp_name, _ = winreg.QueryValueEx(comp_key, None)
                                        except FileNotFoundError:
                                            comp_name = guid_key
                                            
                                        resolved_path, args = self.parse_command_line(stub_path)
                                        root_str = "HKLM" if root_key == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                                        rem_cmd = f'Remove-ItemProperty -Path "{root_str}:\\{full_sub}" -Name "StubPath" -ErrorAction SilentlyContinue'
                                        
                                        entry = StartupEntry(
                                            name=f"Active Setup: {comp_name or guid_key}",
                                            category=ASEPCategory.REGISTRY_ACTIVE_SETUP,
                                            location=f"{context}\\{full_sub}\\StubPath",
                                            raw_command=str(stub_path),
                                            resolved_path=resolved_path,
                                            arguments=args,
                                            enabled=True,
                                            user_context=context,
                                            remediation_command=rem_cmd
                                        )
                                        results.append(entry)
                                except FileNotFoundError:
                                    pass
                        except (OSError, ValueError):
                            continue
            except (FileNotFoundError, PermissionError, OSError):
                continue
        return results

    def _collect_appinit_dlls(self) -> List[StartupEntry]:
        """Scans AppInit_DLLs keys."""
        results: List[StartupEntry] = []
        targets = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "HKLM"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows", "HKLM-WoW64")
        ]
        
        for root_key, sub_path, context in targets:
            try:
                with winreg.OpenKey(root_key, sub_path, 0, winreg.KEY_READ) as key:
                    try:
                        dlls_val, _ = winreg.QueryValueEx(key, "AppInit_DLLs")
                        if dlls_val and isinstance(dlls_val, str) and dlls_val.strip():
                            for dll in dlls_val.split():
                                norm = self.normalize_path(dll)
                                rem_cmd = f'Set-ItemProperty -Path "HKLM:\\{sub_path}" -Name "AppInit_DLLs" -Value ""'
                                entry = StartupEntry(
                                    name=f"AppInit_DLL: {os.path.basename(dll)}",
                                    category=ASEPCategory.REGISTRY_APPINIT,
                                    location=f"{context}\\{sub_path}\\AppInit_DLLs",
                                    raw_command=dll,
                                    resolved_path=norm,
                                    enabled=True,
                                    user_context=context,
                                    remediation_command=rem_cmd
                                )
                                results.append(entry)
                    except FileNotFoundError:
                        pass
            except (FileNotFoundError, PermissionError, OSError):
                continue
        return results
