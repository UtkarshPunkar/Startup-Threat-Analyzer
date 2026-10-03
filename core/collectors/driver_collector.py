"""
Collector for Windows Boot and System Drivers (Kernel Persistence).
"""

import os
from typing import List
from core.models import StartupEntry, ASEPCategory
from core.collectors.base import BaseCollector

try:
    import winreg
except ImportError:
    winreg = None


class DriverCollector(BaseCollector):
    """Enumerates Boot (Start=0) and System (Start=1) start drivers."""

    def collect(self) -> List[StartupEntry]:
        if not winreg:
            return []
        results: List[StartupEntry] = []
        services_key_path = r"SYSTEM\CurrentControlSet\Services"

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, services_key_path, 0, winreg.KEY_READ) as s_key:
                num_subkeys = winreg.QueryInfoKey(s_key)[0]
                for i in range(num_subkeys):
                    try:
                        driver_name = winreg.EnumKey(s_key, i)
                        driver_sub = f"{services_key_path}\\{driver_name}"
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, driver_sub, 0, winreg.KEY_READ) as d_key:
                            try:
                                start_val, _ = winreg.QueryValueEx(d_key, "Start")
                                type_val, _ = winreg.QueryValueEx(d_key, "Type")
                            except FileNotFoundError:
                                continue

                            # Type 1: Kernel Driver, Type 2: File System Driver, Type 8: Recognizer
                            if type_val not in (0x01, 0x02, 0x08):
                                continue

                            # Start 0 = Boot, Start 1 = System
                            if start_val not in (0, 1):
                                continue

                            image_path = ""
                            try:
                                image_path, _ = winreg.QueryValueEx(d_key, "ImagePath")
                            except FileNotFoundError:
                                # Default driver path is System32\drivers\<name>.sys
                                image_path = f"system32\\drivers\\{driver_name}.sys"

                            if not image_path:
                                continue

                            resolved_path, args = self.parse_command_line(image_path)
                            # Handle relative driver path
                            if resolved_path and not os.path.isabs(resolved_path):
                                sys_root = os.environ.get('SystemRoot', r'C:\Windows')
                                resolved_path = os.path.join(sys_root, resolved_path)

                            start_label = "Boot Driver" if start_val == 0 else "System Driver"
                            rem_cmd = f'Set-Service -Name "{driver_name}" -StartupType Disabled -ErrorAction SilentlyContinue'

                            entry = StartupEntry(
                                name=f"Driver: {driver_name}",
                                category=ASEPCategory.DRIVER_STARTUP,
                                location=f"HKLM\\{driver_sub}",
                                raw_command=str(image_path),
                                resolved_path=resolved_path,
                                arguments=args,
                                enabled=True,
                                user_context=f"Kernel Space ({start_label})",
                                remediation_command=rem_cmd
                            )
                            results.append(entry)
                    except (OSError, ValueError):
                        continue
        except (FileNotFoundError, PermissionError, OSError):
            pass

        return results
