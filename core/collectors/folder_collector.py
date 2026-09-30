"""
Collector for Windows Startup Folders (User & All Users).
Parses direct executables, scripts, and .lnk shortcut files with argument extraction.
"""

import os
import struct
import subprocess
from typing import List, Tuple, Optional
from core.models import StartupEntry, ASEPCategory
from core.collectors.base import BaseCollector


class FolderCollector(BaseCollector):
    """Enumerates filesystem startup folders (User and System-wide)."""

    def collect(self) -> List[StartupEntry]:
        entries: List[StartupEntry] = []
        
        # User Startup Directory
        appdata = os.environ.get('APPDATA', '')
        if appdata:
            user_startup = os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup")
            if os.path.isdir(user_startup):
                entries.extend(self._scan_directory(user_startup, "User Startup Folder", "HKCU"))

        # All Users / System Startup Directory
        progdata = os.environ.get('ProgramData', r"C:\ProgramData")
        if progdata:
            all_users_startup = os.path.join(progdata, r"Microsoft\Windows\Start Menu\Programs\Startup")
            if os.path.isdir(all_users_startup):
                entries.extend(self._scan_directory(all_users_startup, "All Users Startup Folder", "System-wide"))

        return entries

    def _scan_directory(self, dir_path: str, location_label: str, context: str) -> List[StartupEntry]:
        results: List[StartupEntry] = []
        try:
            for item in os.listdir(dir_path):
                # Ignore desktop.ini
                if item.lower() == "desktop.ini":
                    continue
                
                full_path = os.path.join(dir_path, item)
                if not os.path.isfile(full_path):
                    continue

                ext = os.path.splitext(item)[1].lower()
                rem_cmd = f'Remove-Item -Path "{full_path}" -Force -ErrorAction SilentlyContinue'
                
                if ext == ".lnk":
                    target_path, args = self._parse_lnk_file(full_path)
                    raw_cmd = f'"{target_path}" {args}'.strip() if args else target_path
                    entry = StartupEntry(
                        name=f"Shortcut: {item}",
                        category=ASEPCategory.STARTUP_FOLDER,
                        location=f"{location_label} ({full_path})",
                        raw_command=raw_cmd or full_path,
                        resolved_path=self.normalize_path(target_path) if target_path else full_path,
                        arguments=args,
                        enabled=True,
                        user_context=context,
                        remediation_command=rem_cmd
                    )
                    results.append(entry)
                else:
                    # Direct executable or script (.exe, .bat, .vbs, .ps1, .cmd, etc.)
                    entry = StartupEntry(
                        name=f"Startup File: {item}",
                        category=ASEPCategory.STARTUP_FOLDER,
                        location=f"{location_label} ({full_path})",
                        raw_command=full_path,
                        resolved_path=full_path,
                        arguments="",
                        enabled=True,
                        user_context=context,
                        remediation_command=rem_cmd
                    )
                    results.append(entry)
        except (PermissionError, OSError):
            pass
            
        return results

    def _parse_lnk_file(self, lnk_path: str) -> Tuple[str, str]:
        """
        Parses a .lnk Windows shortcut to extract target path and arguments.
        First attempts pure-python binary parsing, falls back to PowerShell COM parser.
        """
        target, args = self._parse_lnk_binary(lnk_path)
        if target:
            return target, args

        # Fallback to PowerShell COM object
        return self._parse_lnk_powershell(lnk_path)

    def _parse_lnk_binary(self, filepath: str) -> Tuple[str, str]:
        """Pure-Python parser for Windows Shell Link (.lnk) binary format."""
        try:
            with open(filepath, 'rb') as f:
                content = f.read()

            if len(content) < 76 or content[:4] != b'\x4c\x00\x00\x00':
                return "", ""

            # Check GUID: {00021401-0000-0000-C000-000000000046}
            guid = content[4:20]
            if guid != b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46':
                return "", ""

            flags = struct.unpack('<I', content[20:24])[0]
            has_link_target_id_list = (flags & 0x01) != 0
            has_link_info = (flags & 0x02) != 0
            has_name = (flags & 0x04) != 0
            has_rel_path = (flags & 0x08) != 0
            has_working_dir = (flags & 0x10) != 0
            has_arguments = (flags & 0x20) != 0
            is_unicode = (flags & 0x80) != 0

            pos = 76
            if has_link_target_id_list:
                if len(content) >= pos + 2:
                    id_list_size = struct.unpack('<H', content[pos:pos+2])[0]
                    pos += 2 + id_list_size

            target_path = ""
            if has_link_info:
                if len(content) >= pos + 4:
                    link_info_size = struct.unpack('<I', content[pos:pos+4])[0]
                    if len(content) >= pos + 28:
                        header_size = struct.unpack('<I', content[pos+4:pos+8])[0]
                        local_base_offset = struct.unpack('<I', content[pos+16:pos+20])[0]
                        if local_base_offset != 0 and pos + local_base_offset < len(content):
                            # Read null-terminated string
                            null_idx = content.find(b'\x00', pos + local_base_offset)
                            if null_idx != -1:
                                target_path = content[pos + local_base_offset:null_idx].decode('ansi', errors='ignore')
                    pos += link_info_size

            def read_string_data(offset: int) -> Tuple[str, int]:
                if offset + 2 > len(content):
                    return "", offset
                str_len = struct.unpack('<H', content[offset:offset+2])[0]
                offset += 2
                if is_unicode:
                    byte_len = str_len * 2
                    if offset + byte_len > len(content):
                        return "", offset
                    val = content[offset:offset+byte_len].decode('utf-16le', errors='ignore')
                    return val, offset + byte_len
                else:
                    if offset + str_len > len(content):
                        return "", offset
                    val = content[offset:offset+str_len].decode('ansi', errors='ignore')
                    return val, offset + str_len

            if has_name:
                _, pos = read_string_data(pos)
            if has_rel_path:
                rel_p, pos = read_string_data(pos)
                if not target_path and rel_p:
                    target_path = rel_p
            if has_working_dir:
                _, pos = read_string_data(pos)
            
            args = ""
            if has_arguments:
                args, pos = read_string_data(pos)

            return target_path, args
        except Exception:
            return "", ""

    def _parse_lnk_powershell(self, filepath: str) -> Tuple[str, str]:
        """Fallback .lnk parser using PowerShell WScript.Shell COM object."""
        try:
            esc_path = filepath.replace("'", "''")
            ps_script = f"""
            $sh = New-Object -ComObject WScript.Shell
            $sc = $sh.CreateShortcut('{esc_path}')
            "$($sc.TargetPath)|||$($sc.Arguments)"
            """
            proc = subprocess.run(
                ['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
                capture_output=True,
                text=True,
                timeout=5
            )
            out = proc.stdout.strip()
            if "|||" in out:
                parts = out.split("|||", 1)
                return parts[0].strip(), parts[1].strip()
        except Exception:
            pass
        return "", ""
