"""
Forensic Heuristic Rules Engine & Suspicion Scoring.
Evaluates 15+ threat indicators across ASEP categories, file attributes, signatures, and command lines.
"""

import os
import re
from typing import List, Tuple
from core.models import (
    StartupEntry, ASEPCategory, ThreatSeverity, HeuristicFinding, 
    DigitalSignatureInfo, PEFileInfo
)
from core.analyzer.mitre_mapper import MITREMapper


class HeuristicAnalyzer:
    """Evaluates startup entries against digital forensic threat heuristics."""

    SYSTEM_MASQUERADE_TARGETS = [
        "svchost.exe", "csrss.exe", "lsass.exe", "explorer.exe", "services.exe",
        "smss.exe", "winlogon.exe", "taskhost.exe", "taskhostw.exe", "conhost.exe",
        "spoolsv.exe", "runtimebroker.exe", "dwm.exe", "sihost.exe"
    ]

    SUSPICIOUS_PATH_KEYWORDS = [
        r"\temp", r"\tmp", r"\appdata\local\temp", r"\users\public",
        r"\perflogs", r"\downloads", r"\$recycle.bin", r"c:\temp", r"c:\tmp"
    ]

    LOLBINS = [
        "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "regsvr32.exe",
        "certutil.exe", "rundll32.exe", "cscript.exe", "wscript.exe",
        "bitsadmin.exe", "msbuild.exe", "installutil.exe", "bash.exe"
    ]

    @classmethod
    def analyze_entry(cls, entry: StartupEntry) -> None:
        """
        Runs all heuristic rules against the given startup entry, populating its
        findings list, calculating composite suspicion score, and determining severity.
        """
        findings: List[HeuristicFinding] = []
        raw_score = 0

        # Run individual heuristic rule detectors
        cls._check_masquerading(entry, findings)
        cls._check_suspicious_paths(entry, findings)
        cls._check_obfuscated_cmdline(entry, findings)
        cls._check_lolbin_execution(entry, findings)
        cls._check_ifeo_hijack(entry, findings)
        cls._check_winlogon_tampering(entry, findings)
        cls._check_wmi_persistence(entry, findings)
        cls._check_unquoted_service_path(entry, findings)
        cls._check_double_extension(entry, findings)
        cls._check_signature_anomalies(entry, findings)
        cls._check_entropy_and_packing(entry, findings)
        cls._check_pe_anomalies(entry, findings)
        cls._check_metadata_impersonation(entry, findings)
        cls._check_orphaned_entry(entry, findings)

        # Calculate composite score
        for f in findings:
            raw_score += f.score_impact

        # Safe trusted publisher discount
        if entry.signature and entry.signature.is_trusted_publisher and entry.signature.status == "Valid":
            # If signed by Microsoft/Google/etc and no critical masquerading or LOLBin abuse
            has_crit = any(f.severity == ThreatSeverity.CRITICAL for f in findings)
            if not has_crit:
                raw_score = max(0, raw_score - 30)

        # Cap score between 0 and 100
        final_score = min(100, max(0, raw_score))
        entry.total_score = final_score
        entry.findings = findings

        # Determine overall threat severity for this entry
        if final_score >= 80 or any(f.severity == ThreatSeverity.CRITICAL for f in findings):
            entry.severity = ThreatSeverity.CRITICAL
        elif final_score >= 60 or any(f.severity == ThreatSeverity.HIGH for f in findings):
            entry.severity = ThreatSeverity.HIGH
        elif final_score >= 35 or any(f.severity == ThreatSeverity.MEDIUM for f in findings):
            entry.severity = ThreatSeverity.MEDIUM
        elif final_score >= 15 or any(f.severity == ThreatSeverity.LOW for f in findings):
            entry.severity = ThreatSeverity.LOW
        else:
            entry.severity = ThreatSeverity.CLEAN

    @classmethod
    def _check_masquerading(cls, entry: StartupEntry, findings: List[HeuristicFinding]):
        """Detects system binary masquerading in non-system directories."""
        path = (entry.resolved_path or "").lower()
        if not path:
            return

        filename = os.path.basename(path)
        if filename in cls.SYSTEM_MASQUERADE_TARGETS:
            sys_root = os.environ.get('SystemRoot', r'C:\Windows').lower()
            system32 = os.path.join(sys_root, 'system32')
            syswow64 = os.path.join(sys_root, 'syswow64')
            win_dir = sys_root

            is_valid_sys_loc = False
            if filename == "explorer.exe":
                is_valid_sys_loc = path.startswith(win_dir) or path.startswith(system32)
            else:
                is_valid_sys_loc = path.startswith(system32) or path.startswith(syswow64)

            if not is_valid_sys_loc:
                mitre = MITREMapper.get_details("T1036.005")
                findings.append(HeuristicFinding(
                    rule_id="RULE_MASQUERADING_SYSTEM",
                    rule_name="Critical System Process Masquerading",
                    score_impact=50,
                    severity=ThreatSeverity.CRITICAL,
                    description=f"Binary is masquerading as legitimate Windows system file '{filename}' but executes from unauthorized path '{entry.resolved_path}'.",
                    mitre_attack_id="T1036.005",
                    mitre_tactic="Defense Evasion (TA0005)",
                    mitre_technique="Masquerading: Match Legitimate Name or Location",
                    remediation_advice=mitre["mitigation"]
                ))

    @classmethod
    def _check_suspicious_paths(cls, entry: StartupEntry, findings: List[HeuristicFinding]):
        """Detects execution from writable / volatile directories."""
        path = (entry.resolved_path or entry.raw_command or "").lower()
        for kw in cls.SUSPICIOUS_PATH_KEYWORDS:
            if kw in path:
                mitre = MITREMapper.get_details("T1547.001")
                findings.append(HeuristicFinding(
                    rule_id="RULE_SUSPICIOUS_PATH",
                    rule_name="Suspicious Writable Execution Directory",
                    score_impact=35,
                    severity=ThreatSeverity.HIGH,
                    description=f"Startup program executes from a high-risk volatile or user-writable directory matching '{kw}'.",
                    mitre_attack_id="T1547.001",
                    mitre_tactic="Persistence (TA0003)",
                    mitre_technique="Registry Run Keys / Startup Folder",
                    remediation_advice="Investigate binary provenance, check write permissions, and remove unauthorized startup entry."
                ))
                break

    @classmethod
    def _check_obfuscated_cmdline(cls, entry: StartupEntry, findings: List[HeuristicFinding]):
        """Detects encoded PowerShell commands, hidden windows, and download cradles."""
        cmd = f"{entry.raw_command} {entry.arguments}".lower()
        
        obf_patterns = [
            (r"-(enc|encodedcommand|e)\s+[a-za-z0-9+/=]{10,}", "Base64 Encoded PowerShell Command (-enc)"),
            (r"frombase64string", "Base64 Decoding Routine"),
            (r"downloadstring|downloaddata|downloadfile", "Remote Web Download Cradle"),
            (r"(-w\s+hidden|-windowstyle\s+hidden)", "Hidden Window Execution"),
            (r"(\biex\b|\binvoke-expression\b)", "Dynamic Code Execution (IEX)"),
            (r"mshta\s+javascript:", "Inline MSHTA JavaScript Execution"),
            (r"regsvr32\s+(/s|/u|/i:http)", "Squiblydoo Regsvr32 Remote Scriptlet"),
            (r"certutil\s+(-urlcache|-split)", "Certutil Remote Payload Download")
        ]

        for pat, desc in obf_patterns:
            if re.search(pat, cmd, re.IGNORECASE):
                mitre = MITREMapper.get_details("T1059.001")
                findings.append(HeuristicFinding(
                    rule_id="RULE_OBFUSCATED_CMDLINE",
                    rule_name=f"Obfuscated Command: {desc}",
                    score_impact=45,
                    severity=ThreatSeverity.CRITICAL,
                    description=f"Command line utilizes stealth or obfuscation techniques: {desc} in command string.",
                    mitre_attack_id="T1059.001",
                    mitre_tactic="Execution (TA0002)",
                    mitre_technique="Command and Scripting Interpreter: PowerShell",
                    remediation_advice=mitre["mitigation"]
                ))
                break

    @classmethod
    def _check_lolbin_execution(cls, entry: StartupEntry, findings: List[HeuristicFinding]):
        """Detects Living-Off-The-Land Binaries configured as startup triggers."""
        cmd_target = os.path.basename(entry.resolved_path or "").lower()
        if not cmd_target:
            first_tok = (entry.raw_command or "").split()[0].lower() if entry.raw_command else ""
            cmd_target = os.path.basename(first_tok)

        if cmd_target in cls.LOLBINS:
            # If arguments are present or it's invoked in Run key
            if entry.arguments or entry.category in (ASEPCategory.REGISTRY_RUN, ASEPCategory.REGISTRY_RUNONCE, ASEPCategory.STARTUP_FOLDER):
                mitre = MITREMapper.get_details("T1218")
                findings.append(HeuristicFinding(
                    rule_id="RULE_LOLBIN_EXECUTION",
                    rule_name=f"Living-Off-The-Land Binary ({cmd_target})",
                    score_impact=25,
                    severity=ThreatSeverity.MEDIUM,
                    description=f"Startup persistence leverages native system utility '{cmd_target}' to proxy script or command execution.",
                    mitre_attack_id="T1218",
                    mitre_tactic="Defense Evasion (TA0005)",
                    mitre_technique="System Binary Proxy Execution",
                    remediation_advice=mitre["mitigation"]
                ))

    @classmethod
    def _check_ifeo_hijack(cls, entry: StartupEntry, findings: List[HeuristicFinding]):
        """Detects IFEO Debugger persistence hijacking."""
        if entry.category == ASEPCategory.REGISTRY_IFEO:
            mitre = MITREMapper.get_details("T1546.012")
            findings.append(HeuristicFinding(
                rule_id="RULE_IFEO_DEBUGGER_HIJACK",
                rule_name="Image File Execution Options (IFEO) Hijack",
                score_impact=50,
                severity=ThreatSeverity.CRITICAL,
                description=f"Debugger registry key intercepts target binary execution via '{entry.location}'.",
                mitre_attack_id="T1546.012",
                mitre_tactic="Persistence (TA0003)",
                mitre_technique="Event Triggered Execution: Image File Execution Options",
                remediation_advice=mitre["mitigation"]
            ))

    @classmethod
    def _check_winlogon_tampering(cls, entry: StartupEntry, findings: List[HeuristicFinding]):
        """Detects tampering with Winlogon Userinit or Shell keys."""
        if entry.category == ASEPCategory.REGISTRY_WINLOGON:
            loc = entry.location.lower()
            cmd = (entry.raw_command or "").lower().strip()
            
            if "shell" in loc and cmd != "explorer.exe":
                mitre = MITREMapper.get_details("T1547.001")
                findings.append(HeuristicFinding(
                    rule_id="RULE_WINLOGON_SHELL_TAMPER",
                    rule_name="Winlogon Shell Hijack",
                    score_impact=50,
                    severity=ThreatSeverity.CRITICAL,
                    description=f"Default Windows Explorer shell altered to '{entry.raw_command}'.",
                    mitre_attack_id="T1547.001",
                    mitre_tactic="Persistence (TA0003)",
                    mitre_technique="Boot or Logon Autostart: Winlogon",
                    remediation_advice="Restore default 'explorer.exe' value in Winlogon registry key."
                ))
            elif "userinit" in loc and not cmd.startswith(r"c:\windows\system32\userinit.exe"):
                mitre = MITREMapper.get_details("T1547.001")
                findings.append(HeuristicFinding(
                    rule_id="RULE_WINLOGON_USERINIT_TAMPER",
                    rule_name="Winlogon Userinit Alteration",
                    score_impact=45,
                    severity=ThreatSeverity.CRITICAL,
                    description=f"Userinit startup handler contains unauthorized target '{entry.raw_command}'.",
                    mitre_attack_id="T1547.001",
                    mitre_tactic="Persistence (TA0003)",
                    mitre_technique="Boot or Logon Autostart: Winlogon",
                    remediation_advice="Restore default 'C:\\Windows\\system32\\userinit.exe,' value."
                ))

    @classmethod
    def _check_wmi_persistence(cls, entry: StartupEntry, findings: List[HeuristicFinding]):
        """Detects WMI Event Consumer persistence."""
        if entry.category == ASEPCategory.WMI_SUBSCRIPTION:
            mitre = MITREMapper.get_details("T1546.003")
            findings.append(HeuristicFinding(
                rule_id="RULE_WMI_PERSISTENCE",
                rule_name="WMI Event Subscription Persistence",
                score_impact=35,
                severity=ThreatSeverity.HIGH,
                description=f"Persistent WMI Event Consumer triggers command on system events in '{entry.location}'.",
                mitre_attack_id="T1546.003",
                mitre_tactic="Persistence (TA0003)",
                mitre_technique="Event Triggered Execution: WMI Event Subscription",
                remediation_advice=mitre["mitigation"]
            ))

    @classmethod
    def _check_unquoted_service_path(cls, entry: StartupEntry, findings: List[HeuristicFinding]):
        """Detects unquoted service paths containing spaces (CWE-428 / T1574.009)."""
        if entry.category == ASEPCategory.WINDOWS_SERVICE:
            raw = entry.raw_command.strip()
            # If path has spaces, does NOT start with quote, and contains .exe followed by spaces or args
            if " " in raw and not raw.startswith('"') and not raw.startswith("'"):
                # Exclude svchost or system binaries without spaces before .exe
                first_part = raw.split(".exe")[0] + ".exe" if ".exe" in raw.lower() else raw
                if " " in first_part and not first_part.startswith('"'):
                    mitre = MITREMapper.get_details("T1574.009")
                    findings.append(HeuristicFinding(
                        rule_id="RULE_UNQUOTED_SERVICE_PATH",
                        rule_name="Unquoted Service Path Vulnerability",
                        score_impact=20,
                        severity=ThreatSeverity.MEDIUM,
                        description=f"Service binary path '{raw}' contains spaces without quotation marks, creating local privilege escalation vulnerability.",
                        mitre_attack_id="T1574.009",
                        mitre_tactic="Privilege Escalation (TA0004)",
                        mitre_technique="Hijack Execution Flow: Path Interception by Unquoted Path",
                        remediation_advice=mitre["mitigation"]
                    ))

    @classmethod
    def _check_double_extension(cls, entry: StartupEntry, findings: List[HeuristicFinding]):
        """Detects deceptive double extensions (e.g. report.pdf.exe)."""
        path = (entry.resolved_path or entry.raw_command or "").lower()
        filename = os.path.basename(path)
        pattern = r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|rtf|zip|rar)\.(exe|bat|vbs|ps1|scr|cmd|hta|js|vbe)$"
        if re.search(pattern, filename):
            mitre = MITREMapper.get_details("T1036.005")
            findings.append(HeuristicFinding(
                rule_id="RULE_DOUBLE_EXTENSION",
                rule_name="Deceptive Double File Extension",
                score_impact=45,
                severity=ThreatSeverity.CRITICAL,
                description=f"Binary uses deceptive double extension '{filename}' to disguise executable as document/image.",
                mitre_attack_id="T1036.005",
                mitre_tactic="Defense Evasion (TA0005)",
                mitre_technique="Masquerading: Match Legitimate Name or Location",
                remediation_advice="Immediately quarantine the executable and check origin phishing vectors."
            ))

    @classmethod
    def _check_signature_anomalies(cls, entry: StartupEntry, findings: List[HeuristicFinding]):
        """Detects unsigned, revoked, or invalid digital signatures."""
        if not entry.signature:
            return

        status = entry.signature.status
        if status == "HashMismatch":
            findings.append(HeuristicFinding(
                rule_id="RULE_SIGNATURE_HASH_MISMATCH",
                rule_name="Digital Signature Hash Mismatch (Tampered)",
                score_impact=50,
                severity=ThreatSeverity.CRITICAL,
                description="The binary's digital signature hash does not match computed hash, indicating file tampering or infection.",
                mitre_attack_id="T1547.001",
                mitre_tactic="Defense Evasion (TA0005)",
                mitre_technique="Subvert Trust Controls",
                remediation_advice="Isolate host immediately and verify binary integrity against clean source."
            ))
        elif status in ("Revoked", "CertificateRevoked"):
            findings.append(HeuristicFinding(
                rule_id="RULE_SIGNATURE_REVOKED",
                rule_name="Revoked Digital Certificate",
                score_impact=45,
                severity=ThreatSeverity.HIGH,
                description="The binary was signed with a certificate that has been explicitly revoked by the issuing Certificate Authority.",
                mitre_attack_id="T1547.001",
                mitre_tactic="Defense Evasion (TA0005)",
                mitre_technique="Subvert Trust Controls",
                remediation_advice="Quarantine binary and inspect for known compromised vendor certificates."
            ))
        elif status == "NotSigned":
            # For critical system locations or startup folder, unsigned status is noteworthy
            if entry.category in (ASEPCategory.REGISTRY_WINLOGON, ASEPCategory.REGISTRY_IFEO, ASEPCategory.DRIVER_STARTUP):
                findings.append(HeuristicFinding(
                    rule_id="RULE_UNSIGNED_CRITICAL_ASEP",
                    rule_name="Unsigned Executable in Critical ASEP Vector",
                    score_impact=35,
                    severity=ThreatSeverity.HIGH,
                    description=f"Executable in high-privilege startup vector '{entry.category.value}' lacks a valid digital signature.",
                    mitre_attack_id="T1547.001",
                    mitre_tactic="Persistence (TA0003)",
                    mitre_technique="Registry Run Keys / Startup Folder",
                    remediation_advice="Verify vendor identity and replace with signed production binary."
                ))
            elif entry.category in (ASEPCategory.STARTUP_FOLDER, ASEPCategory.REGISTRY_RUN, ASEPCategory.REGISTRY_RUNONCE):
                findings.append(HeuristicFinding(
                    rule_id="RULE_UNSIGNED_STARTUP_ENTRY",
                    rule_name="Unsigned Startup Executable",
                    score_impact=20,
                    severity=ThreatSeverity.LOW,
                    description=f"Startup entry '{entry.name}' does not possess an Authenticode digital signature.",
                    mitre_attack_id="T1547.001",
                    mitre_tactic="Persistence (TA0003)",
                    mitre_technique="Registry Run Keys / Startup Folder",
                    remediation_advice="Review publisher and verify executable authenticity."
                ))

    @classmethod
    def _check_entropy_and_packing(cls, entry: StartupEntry, findings: List[HeuristicFinding]):
        """Detects packed, encrypted, or high-entropy executables."""
        if not entry.file_info:
            return

        if entry.file_info.entropy > 7.2:
            mitre = MITREMapper.get_details("T1027.002")
            findings.append(HeuristicFinding(
                rule_id="RULE_HIGH_ENTROPY_PACKED",
                rule_name=f"High Shannon Entropy ({entry.file_info.entropy}) / Packed Binary",
                score_impact=30,
                severity=ThreatSeverity.HIGH,
                description=f"File exhibits high Shannon entropy of {entry.file_info.entropy}/8.0, characteristic of packed malware, crypters, or encrypted shellcode.",
                mitre_attack_id="T1027.002",
                mitre_tactic="Defense Evasion (TA0005)",
                mitre_technique="Software Packing / High Entropy Payload",
                remediation_advice=mitre["mitigation"]
            ))

    @classmethod
    def _check_pe_anomalies(cls, entry: StartupEntry, findings: List[HeuristicFinding]):
        """Evaluates anomalies detected during PE structure inspection."""
        if not entry.file_info or not entry.file_info.anomalies:
            return

        for anomaly in entry.file_info.anomalies:
            if "timestomping" in anomaly.lower():
                mitre = MITREMapper.get_details("T1070.006")
                findings.append(HeuristicFinding(
                    rule_id="RULE_TIMESTOMPING_ANOMALY",
                    rule_name="Timestomping Timestamp Anomaly",
                    score_impact=25,
                    severity=ThreatSeverity.MEDIUM,
                    description=anomaly,
                    mitre_attack_id="T1070.006",
                    mitre_tactic="Defense Evasion (TA0005)",
                    mitre_technique="Indicator Removal: Timestomp",
                    remediation_advice=mitre["mitigation"]
                ))
            elif "packer" in anomaly.lower():
                mitre = MITREMapper.get_details("T1027.002")
                findings.append(HeuristicFinding(
                    rule_id="RULE_KNOWN_PACKER_SECTION",
                    rule_name="Known Packer / Crypter Section Detected",
                    score_impact=30,
                    severity=ThreatSeverity.HIGH,
                    description=anomaly,
                    mitre_attack_id="T1027.002",
                    mitre_tactic="Defense Evasion (TA0005)",
                    mitre_technique="Software Packing / High Entropy Payload",
                    remediation_advice=mitre["mitigation"]
                ))
            elif "suspicious api" in anomaly.lower():
                findings.append(HeuristicFinding(
                    rule_id="RULE_SUSPICIOUS_API_IMPORTS",
                    rule_name="Suspicious Injection / Memory APIs",
                    score_impact=20,
                    severity=ThreatSeverity.MEDIUM,
                    description=anomaly,
                    mitre_attack_id="T1055",
                    mitre_tactic="Privilege Escalation (TA0004)",
                    mitre_technique="Process Injection",
                    remediation_advice="Perform dynamic behavioral analysis in sandbox environment."
                ))

    @classmethod
    def _check_metadata_impersonation(cls, entry: StartupEntry, findings: List[HeuristicFinding]):
        """Detects files that claim to be Microsoft/Apple/Google in PE StringTable but lack valid signature."""
        if not entry.file_info:
            return

        company = (entry.file_info.company_name or "").lower()
        if any(corp in company for corp in ["microsoft", "google", "apple", "intel"]):
            if not entry.signature or not entry.signature.is_trusted_publisher or entry.signature.status != "Valid":
                mitre = MITREMapper.get_details("T1036.005")
                findings.append(HeuristicFinding(
                    rule_id="RULE_METADATA_IMPERSONATION",
                    rule_name="Corporate Metadata Impersonation",
                    score_impact=35,
                    severity=ThreatSeverity.HIGH,
                    description=f"File claims CompanyName '{entry.file_info.company_name}' in metadata but lacks a valid digital signature from that entity.",
                    mitre_attack_id="T1036.005",
                    mitre_tactic="Defense Evasion (TA0005)",
                    mitre_technique="Masquerading: Match Legitimate Name or Location",
                    remediation_advice=mitre["mitigation"]
                ))

    @classmethod
    def _check_orphaned_entry(cls, entry: StartupEntry, findings: List[HeuristicFinding]):
        """Detects entries referencing non-existent files on disk."""
        if entry.resolved_path and entry.file_info and not entry.file_info.exists:
            findings.append(HeuristicFinding(
                rule_id="RULE_FILE_NOT_FOUND_ORPHAN",
                rule_name="Orphaned Persistence Entry (Target Missing)",
                score_impact=10,
                severity=ThreatSeverity.LOW,
                description=f"Startup entry references non-existent target path '{entry.resolved_path}'. May be residue of uninstalled app or cleaned malware.",
                mitre_attack_id="T1547.001",
                mitre_tactic="Persistence (TA0003)",
                mitre_technique="Registry Run Keys / Startup Folder",
                remediation_advice="Safe to remove orphaned persistence reference from registry or task scheduler."
            ))
