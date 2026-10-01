"""
Forensic Orchestrator: Coordinates Collection, Static Analysis, Signature Verification,
Heuristic Threat Scoring, and Forensic Assessment Reporting.
"""

import os
import time
import socket
import platform
import getpass
from typing import List, Dict, Any, Optional, Callable
from core.models import (
    StartupEntry, ForensicAssessmentReport, ThreatSeverity, ASEPCategory
)
from core.collectors import (
    RegistryCollector, FolderCollector, TaskCollector,
    ServiceCollector, WMICollector, DriverCollector
)
from core.analyzer import (
    FileInspector, SignatureVerifier, HeuristicAnalyzer, MITREMapper
)
from core.simulation import ScenarioGenerator


class ForensicOrchestrator:
    """Central orchestrator for Windows Startup & Persistence Analysis."""

    def __init__(self):
        self.collectors = [
            RegistryCollector(),
            FolderCollector(),
            TaskCollector(),
            ServiceCollector(),
            WMICollector(),
            DriverCollector()
        ]

    def run_live_scan(self, progress_callback: Optional[Callable[[str, float], None]] = None) -> ForensicAssessmentReport:
        """
        Executes a full live forensic scan against the current Windows machine.
        """
        start_time = time.time()
        if progress_callback:
            progress_callback("Initializing ASEP collectors...", 0.05)

        raw_entries: List[StartupEntry] = []
        
        total_collectors = len(self.collectors)
        for idx, col in enumerate(self.collectors):
            c_name = col.__class__.__name__
            if progress_callback:
                pct = 0.10 + (idx / total_collectors) * 0.40
                progress_callback(f"Collecting persistence vectors via {c_name}...", pct)
            try:
                found = col.collect()
                raw_entries.extend(found)
            except Exception as e:
                pass

        return self._process_and_score(raw_entries, start_time, is_simulation=False, progress_callback=progress_callback)

    def run_simulation_scan(self, progress_callback: Optional[Callable[[str, float], None]] = None) -> ForensicAssessmentReport:
        """
        Loads and analyzes the simulated APT campaign dataset for demonstration and testing.
        """
        start_time = time.time()
        if progress_callback:
            progress_callback("Loading synthetic APT persistence scenario dataset...", 0.20)
            
        raw_entries = ScenarioGenerator.get_simulated_dataset()
        return self._process_and_score(raw_entries, start_time, is_simulation=True, progress_callback=progress_callback)

    def _process_and_score(
        self,
        raw_entries: List[StartupEntry],
        start_time: float,
        is_simulation: bool = False,
        progress_callback: Optional[Callable[[str, float], None]] = None
    ) -> ForensicAssessmentReport:
        """Enriches entries with file inspection, signatures, heuristics, and builds final report."""
        
        # 1. Gather all file paths for batch signature checking
        if progress_callback:
            progress_callback("Verifying Authenticode digital signatures...", 0.55)

        files_to_verify = []
        for e in raw_entries:
            if not e.signature and e.resolved_path and os.path.isfile(e.resolved_path):
                files_to_verify.append(e.resolved_path)

        # Batch verify digital signatures
        sig_map = SignatureVerifier.verify_batch(files_to_verify) if files_to_verify else {}

        # 2. Inspect files (Hashes, Entropy, PE Headers) & attach signatures
        total_entries = len(raw_entries)
        for idx, entry in enumerate(raw_entries):
            if progress_callback and idx % 5 == 0:
                pct = 0.60 + (idx / max(1, total_entries)) * 0.25
                progress_callback(f"Analyzing binary metadata & entropy ({idx+1}/{total_entries})...", pct)

            # Assign signature if not already populated (e.g. In simulation)
            if not entry.signature and entry.resolved_path:
                norm = os.path.normpath(entry.resolved_path).lower()
                entry.signature = sig_map.get(entry.resolved_path, sig_map.get(norm))

            # Inspect PE structure and calculate Shannon entropy
            if not entry.file_info and entry.resolved_path:
                entry.file_info = FileInspector.inspect_file(entry.resolved_path)

        # 3. Run Heuristic Threat Scoring
        if progress_callback:
            progress_callback("Evaluating heuristic threat rules & MITRE ATT&CK mapping...", 0.90)

        for entry in raw_entries:
            HeuristicAnalyzer.analyze_entry(entry)

        # 4. Sort entries by total_score descending (most critical on top)
        raw_entries.sort(key=lambda x: x.total_score, reverse=True)

        duration = time.time() - start_time
        if progress_callback:
            progress_callback("Compiling forensic assessment report...", 0.98)

        # 5. Build Report Object
        report = self._build_report(raw_entries, duration, is_simulation)
        
        if progress_callback:
            progress_callback("Forensic assessment complete!", 1.0)

        return report

    def _build_report(self, entries: List[StartupEntry], duration: float, is_simulation: bool) -> ForensicAssessmentReport:
        """Constructs statistical summaries, risk scores, and remediation playbooks."""
        host_name = "SIMULATED-CORP-WORKSTATION" if is_simulation else socket.gethostname()
        os_ver = f"{platform.system()} {platform.release()} ({platform.version()})"
        target_user = "TargetUser (APT29 Simulation)" if is_simulation else getpass.getuser()

        crit_count = sum(1 for e in entries if e.severity == ThreatSeverity.CRITICAL)
        high_count = sum(1 for e in entries if e.severity == ThreatSeverity.HIGH)
        med_count = sum(1 for e in entries if e.severity == ThreatSeverity.MEDIUM)
        low_count = sum(1 for e in entries if e.severity == ThreatSeverity.LOW)
        clean_count = sum(1 for e in entries if e.severity == ThreatSeverity.CLEAN)

        # Overall System Risk Score calculation (weighted)
        overall_score = 0
        if crit_count > 0:
            overall_score = min(100, 75 + (crit_count * 8) + (high_count * 4))
        elif high_count > 0:
            overall_score = min(74, 50 + (high_count * 6) + (med_count * 2))
        elif med_count > 0:
            overall_score = min(49, 25 + (med_count * 4))
        elif low_count > 0:
            overall_score = min(24, 10 + (low_count * 2))
        else:
            overall_score = 0

        if overall_score >= 75:
            risk_lvl = "CRITICAL"
        elif overall_score >= 50:
            risk_lvl = "HIGH"
        elif overall_score >= 25:
            risk_lvl = "MEDIUM"
        else:
            risk_lvl = "LOW"

        # Category Summary
        cat_summary: Dict[str, int] = {}
        for e in entries:
            cat_val = e.category.value if hasattr(e.category, 'value') else str(e.category)
            cat_summary[cat_val] = cat_summary.get(cat_val, 0) + 1

        # MITRE ATT&CK Summary
        mitre_summary: Dict[str, List[str]] = {}
        for e in entries:
            for f in e.findings:
                if f.mitre_attack_id:
                    if f.mitre_attack_id not in mitre_summary:
                        mitre_summary[f.mitre_attack_id] = []
                    if e.name not in mitre_summary[f.mitre_attack_id]:
                        mitre_summary[f.mitre_attack_id].append(e.name)

        # High Risk Entries
        high_risk = [e for e in entries if e.severity in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH)]

        # Remediation Action Playbook
        playbook = []
        for idx, e in enumerate(high_risk, 1):
            if e.remediation_command:
                playbook.append({
                    "step": idx,
                    "title": f"Neutralize Persistence: {e.name}",
                    "severity": e.severity.value,
                    "target": e.location,
                    "description": f"Execute remediation command to remove unauthorized persistence hook at '{e.location}'.",
                    "command": e.remediation_command
                })

        report = ForensicAssessmentReport(
            host_name=host_name,
            os_version=os_ver,
            target_user=target_user,
            duration_seconds=duration,
            total_analyzed=len(entries),
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            clean_count=clean_count,
            overall_risk_score=overall_score,
            overall_risk_level=risk_lvl,
            category_summary=cat_summary,
            mitre_summary=mitre_summary,
            entries=entries,
            high_risk_entries=high_risk,
            remediation_playbook=playbook
        )

        return report
