"""
Unit tests for Forensic Threat Heuristics and Suspicion Scoring.
"""

import pytest
from core.models import (
    StartupEntry, ASEPCategory, ThreatSeverity, DigitalSignatureInfo, PEFileInfo
)
from core.analyzer.heuristics import HeuristicAnalyzer


def test_masquerading_detection():
    # Masqueraded svchost outside System32
    entry = StartupEntry(
        name="AudioSvc",
        category=ASEPCategory.REGISTRY_RUN,
        raw_command=r"C:\Users\Public\svchost.exe",
        resolved_path=r"C:\Users\Public\svchost.exe",
        signature=DigitalSignatureInfo(is_signed=False, status="NotSigned")
    )
    HeuristicAnalyzer.analyze_entry(entry)
    
    assert entry.severity in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH)
    assert entry.total_score >= 50
    rule_ids = [f.rule_id for f in entry.findings]
    assert "RULE_MASQUERADING_SYSTEM" in rule_ids


def test_obfuscated_powershell_detection():
    entry = StartupEntry(
        name="Updater",
        category=ASEPCategory.SCHEDULED_TASK,
        raw_command="powershell.exe -w hidden -enc JABjAGwAaQBlAG4AdAAg...",
        arguments="-w hidden -enc JABjAGwAaQBlAG4AdAAg..."
    )
    HeuristicAnalyzer.analyze_entry(entry)
    
    assert entry.severity in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH)
    rule_ids = [f.rule_id for f in entry.findings]
    assert "RULE_OBFUSCATED_CMDLINE" in rule_ids


def test_unquoted_service_path_detection():
    entry = StartupEntry(
        name="BackupAgent",
        category=ASEPCategory.WINDOWS_SERVICE,
        raw_command=r"C:\Program Files\Backup Utility\agent.exe",
        resolved_path=r"C:\Program Files\Backup Utility\agent.exe"
    )
    HeuristicAnalyzer.analyze_entry(entry)
    
    rule_ids = [f.rule_id for f in entry.findings]
    assert "RULE_UNQUOTED_SERVICE_PATH" in rule_ids
    assert any(f.severity == ThreatSeverity.MEDIUM for f in entry.findings)


def test_double_extension_detection():
    entry = StartupEntry(
        name="Invoice",
        category=ASEPCategory.STARTUP_FOLDER,
        raw_command=r"C:\Users\Test\AppData\Roaming\Startup\invoice.pdf.exe",
        resolved_path=r"C:\Users\Test\AppData\Roaming\Startup\invoice.pdf.exe"
    )
    HeuristicAnalyzer.analyze_entry(entry)
    
    rule_ids = [f.rule_id for f in entry.findings]
    assert "RULE_DOUBLE_EXTENSION" in rule_ids
    assert entry.severity == ThreatSeverity.CRITICAL
