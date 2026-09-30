"""
MITRE ATT&CK Matrix Knowledge Base and Mapping Engine.
Enriches forensic findings with ATT&CK Tactics, Techniques, and Mitigation Playbooks.
"""

from typing import Dict, Any, Optional


class MITREMapper:
    """Provides MITRE ATT&CK mapping and mitigation guidance for persistence vectors."""

    TECHNIQUES = {
        "T1547.001": {
            "name": "Registry Run Keys / Startup Folder",
            "tactics": ["Persistence (TA0003)", "Privilege Escalation (TA0004)"],
            "url": "https://attack.mitre.org/techniques/T1547/001/",
            "mitigation": "Audit Run/RunOnce registry keys and Startup folders; restrict write permissions; enforce AppLocker/WDAC application whitelisting."
        },
        "T1546.012": {
            "name": "Image File Execution Options (IFEO) Hijack",
            "tactics": ["Persistence (TA0003)", "Privilege Escalation (TA0004)", "Defense Evasion (TA0005)"],
            "url": "https://attack.mitre.org/techniques/T1546/012/",
            "mitigation": "Audit 'HKLM\\...\\Image File Execution Options' for unauthorized 'Debugger' keys; enable Sysmon Event ID 12/13 monitoring."
        },
        "T1546.003": {
            "name": "WMI Event Subscription",
            "tactics": ["Persistence (TA0003)", "Privilege Escalation (TA0004)"],
            "url": "https://attack.mitre.org/techniques/T1546/003/",
            "mitigation": "Inspect root\\subscription namespace for unauthorized CommandLineEventConsumer or ActiveScriptEventConsumer; enable Microsoft-Windows-WMI-Activity/Operational logs."
        },
        "T1543.003": {
            "name": "Windows Service Execution",
            "tactics": ["Persistence (TA0003)", "Privilege Escalation (TA0004)"],
            "url": "https://attack.mitre.org/techniques/T1543/003/",
            "mitigation": "Enforce driver/service signing, restrict Service Control Manager (SCM) access, monitor Event ID 7045 (A service was installed in the system)."
        },
        "T1053.005": {
            "name": "Scheduled Task Persistence",
            "tactics": ["Execution (TA0002)", "Persistence (TA0003)", "Privilege Escalation (TA0004)"],
            "url": "https://attack.mitre.org/techniques/T1053/005/",
            "mitigation": "Audit Task Scheduler logs (Event IDs 4698, 4702), restrict schtasks.exe usage, review actions pointing to volatile or script interpreters."
        },
        "T1036.005": {
            "name": "Masquerading: Match Legitimate Name or Location",
            "tactics": ["Defense Evasion (TA0005)"],
            "url": "https://attack.mitre.org/techniques/T1036/005/",
            "mitigation": "Cross-reference binary file paths against known Windows system paths; verify Authenticode digital signatures against Microsoft trusted roots."
        },
        "T1027.002": {
            "name": "Software Packing / High Entropy Payload",
            "tactics": ["Defense Evasion (TA0005)"],
            "url": "https://attack.mitre.org/techniques/T1027/002/",
            "mitigation": "Employ automated unpackers and memory scanning; monitor for sudden memory allocation with PAGE_EXECUTE_READWRITE."
        },
        "T1059.001": {
            "name": "Command and Scripting Interpreter: PowerShell",
            "tactics": ["Execution (TA0002)"],
            "url": "https://attack.mitre.org/techniques/T1059/001/",
            "mitigation": "Enable PowerShell Script Block Logging (Event ID 4104), Transcription Logging, and Constrained Language Mode."
        },
        "T1218": {
            "name": "System Binary Proxy Execution (LOLBins)",
            "tactics": ["Defense Evasion (TA0005)"],
            "url": "https://attack.mitre.org/techniques/T1218/",
            "mitigation": "Block or monitor proxy execution of mshta.exe, certutil.exe, regsvr32.exe, rundll32.exe via Windows Defender Application Control (WDAC)."
        },
        "T1574.009": {
            "name": "Path Interception by Unquoted Path",
            "tactics": ["Persistence (TA0003)", "Privilege Escalation (TA0004)"],
            "url": "https://attack.mitre.org/techniques/T1574/009/",
            "mitigation": "Ensure all service binary paths with whitespace are enclosed in quotation marks in the registry."
        },
        "T1070.006": {
            "name": "Indicator Removal: Timestomp",
            "tactics": ["Defense Evasion (TA0005)"],
            "url": "https://attack.mitre.org/techniques/T1070/006/",
            "mitigation": "Compare PE compile header timestamp against NTFS Master File Table ($MFT) $STANDARD_INFORMATION and $FILE_NAME timestamps."
        }
    }

    @classmethod
    def get_details(cls, technique_id: str) -> Dict[str, Any]:
        """Returns details for a MITRE technique ID."""
        return cls.TECHNIQUES.get(technique_id, {
            "name": "Persistence & Execution Technique",
            "tactics": ["Persistence (TA0003)"],
            "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
            "mitigation": "Inspect entry legitimacy, verify digital signatures, and apply defense-in-depth principles."
        })
