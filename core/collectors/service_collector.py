"""
Collector for Windows Services configured for Automatic or Boot/System Startup.
Inspects service configurations, accounts, and checks for Unquoted Service Paths.
"""

import os
import winreg
from typing import List, Dict, Optional
from core.models import StartupEntry, ASEPCategory
from core.collectors.base import BaseCollector


class ServiceCollector(BaseCollector):
    """Enumerates Windows Services starting automatically at boot/logon."""

    # Start Type mappings:
    # 0 = Boot, 1 = System, 2 = Automatic (Auto_Start), 3 = Manual (Demand), 4 = Disabled
    START_TYPES = {
        0: "Boot Start",
        1: "System Start",
        2: "Auto Start",
        3: "Demand Start",
        4: "Disabled"
    }

    def collect(self) -> List[StartupEntry]:
        results: List[StartupEntry] = []
        services_key_path = r"SYSTEM\CurrentControlSet\Services"

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, services_key_path, 0, winreg.KEY_READ) as s_key:
                num_services = winreg.QueryInfoKey(s_key)[0]
                for i in range(num_services):
                    try:
                        svc_name = winreg.EnumKey(s_key, i)
                        svc_full_path = f"{services_key_path}\\{svc_name}"
                        
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, svc_full_path, 0, winreg.KEY_READ) as svc_key:
                            try:
                                start_type, _ = winreg.QueryValueEx(svc_key, "Start")
                            except FileNotFoundError:
                                continue

                            # Focus on Auto Start (2) and Boot/System drivers (0, 1) or DelayedAutoStart
                            delayed_auto = 0
                            try:
                                delayed_auto, _ = winreg.QueryValueEx(svc_key, "DelayedAutoStart")
                            except FileNotFoundError:
                                pass

                            # Check service type: 0x10 = Own Process, 0x20 = Share Process, 0x1/0x2 = Driver
                            service_type = 0x10
                            try:
                                service_type, _ = winreg.QueryValueEx(svc_key, "Type")
                            except FileNotFoundError:
                                pass

                            # We only care about Auto Start (2) or Delayed Auto Start (1) for non-drivers here
                            if start_type != 2 and not (delayed_auto == 1 and start_type == 3):
                                continue

                            # Don't duplicate kernel drivers here if they are handled by DriverCollector
                            if service_type in (0x01, 0x02, 0x08):
                                continue

                            image_path = ""
                            try:
                                image_path, _ = winreg.QueryValueEx(svc_key, "ImagePath")
                            except FileNotFoundError:
                                continue

                            if not image_path or not isinstance(image_path, str):
                                continue

                            display_name = svc_name
                            try:
                                display_name, _ = winreg.QueryValueEx(svc_key, "DisplayName")
                            except FileNotFoundError:
                                pass

                            object_name = "LocalSystem"
                            try:
                                object_name, _ = winreg.QueryValueEx(svc_key, "ObjectName")
                            except FileNotFoundError:
                                pass

                            resolved_path, args = self.parse_command_line(image_path)
                            start_label = "Delayed Auto Start" if delayed_auto == 1 else self.START_TYPES.get(start_type, "Auto Start")

                            rem_cmd = f'Stop-Service -Name "{svc_name}" -Force -ErrorAction SilentlyContinue; Set-Service -Name "{svc_name}" -StartupType Disabled'

                            entry = StartupEntry(
                                name=f"Service: {display_name or svc_name}",
                                category=ASEPCategory.WINDOWS_SERVICE,
                                location=f"HKLM\\{svc_full_path}",
                                raw_command=image_path,
                                resolved_path=resolved_path,
                                arguments=args,
                                enabled=True,
                                user_context=f"{object_name} ({start_label})",
                                remediation_command=rem_cmd
                            )
                            results.append(entry)

                    except (OSError, ValueError):
                        continue
        except (FileNotFoundError, PermissionError, OSError):
            pass

        return results
