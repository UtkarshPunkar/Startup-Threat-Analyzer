"""
Data models and schemas for Windows Startup Program & Persistence Analysis.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
import datetime
import uuid


class ASEPCategory(str, Enum):
    """Auto-Start Extensibility Points (ASEP) Categories."""
    REGISTRY_RUN = "Registry Run"
    REGISTRY_RUNONCE = "Registry RunOnce"
    REGISTRY_IFEO = "Image File Execution Options (IFEO)"
    REGISTRY_WINLOGON = "Winlogon Persistence"
    REGISTRY_ACTIVE_SETUP = "Active Setup"
    REGISTRY_APPINIT = "AppInit DLLs"
    REGISTRY_POLICIES = "Explorer Policies Run"
    STARTUP_FOLDER = "Startup Folder (LNK/Binary)"
    SCHEDULED_TASK = "Scheduled Task"
    WINDOWS_SERVICE = "Windows Service"
    WMI_SUBSCRIPTION = "WMI Event Consumer"
    DRIVER_STARTUP = "System Driver"
    OTHER = "Other Persistence"


class ThreatSeverity(str, Enum):
    """Threat Severity Levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CLEAN = "CLEAN"
    INFO = "INFO"


@dataclass
class DigitalSignatureInfo:
    """Authenticode Digital Signature details."""
    is_signed: bool = False
    status: str = "NotSigned"  # Valid, NotSigned, HashMismatch, Expired, Revoked, SelfSigned, CatalogSigned
    signer_name: str = ""
    issuer_name: str = ""
    is_trusted_publisher: bool = False
    serial_number: Optional[str] = None
    timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PESectionInfo:
    """Portable Executable (PE) section metadata."""
    name: str
    virtual_size: int
    raw_size: int
    entropy: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PEFileInfo:
    """Forensic PE file header, cryptographic hashes, and entropy."""
    file_path: str = ""
    exists: bool = False
    file_size: int = 0
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    entropy: float = 0.0  # Shannon entropy: 0.0 - 8.0
    is_high_entropy: bool = False  # > 7.2 indicates packed/encrypted code
    compile_time: Optional[str] = None
    subsystem: Optional[str] = None  # GUI, Console, Native
    imphash: Optional[str] = None
    file_description: Optional[str] = None
    company_name: Optional[str] = None
    product_name: Optional[str] = None
    original_filename: Optional[str] = None
    sections: List[Dict[str, Any]] = field(default_factory=list)
    imports_sample: List[str] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HeuristicFinding:
    """A specific forensic rule violation or anomaly detected on a startup entry."""
    rule_id: str
    rule_name: str
    score_impact: int
    severity: ThreatSeverity
    description: str
    mitre_attack_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    remediation_advice: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['severity'] = self.severity.value
        return d


@dataclass
class StartupEntry:
    """Represents a discovered Auto-Start Extensibility Point (ASEP) entry."""
    entry_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    category: ASEPCategory = ASEPCategory.OTHER
    location: str = ""  # Registry key path, folder path, task name, etc.
    raw_command: str = ""  # Command line string or target
    resolved_path: Optional[str] = None  # Full normalized path to executable binary
    arguments: str = ""  # Command arguments (if separated)
    enabled: bool = True
    user_context: str = "SYSTEM"  # HKCU\user, HKLM, NT AUTHORITY\SYSTEM, etc.
    timestamp_discovered: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    signature: Optional[DigitalSignatureInfo] = None
    file_info: Optional[PEFileInfo] = None
    findings: List[HeuristicFinding] = field(default_factory=list)
    total_score: int = 0  # 0 to 100
    severity: ThreatSeverity = ThreatSeverity.CLEAN
    remediation_command: Optional[str] = None  # Suggested cleanup command (PowerShell / CMD)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "name": self.name,
            "category": self.category.value if isinstance(self.category, ASEPCategory) else str(self.category),
            "location": self.location,
            "raw_command": self.raw_command,
            "resolved_path": self.resolved_path,
            "arguments": self.arguments,
            "enabled": self.enabled,
            "user_context": self.user_context,
            "timestamp_discovered": self.timestamp_discovered,
            "signature": self.signature.to_dict() if self.signature else None,
            "file_info": self.file_info.to_dict() if self.file_info else None,
            "findings": [f.to_dict() for f in self.findings],
            "total_score": self.total_score,
            "severity": self.severity.value if isinstance(self.severity, ThreatSeverity) else str(self.severity),
            "remediation_command": self.remediation_command
        }


@dataclass
class ForensicAssessmentReport:
    """Complete Forensic Assessment Report and Threat Intelligence summary."""
    report_id: str = field(default_factory=lambda: f"FAR-{uuid.uuid4().hex[:8].upper()}")
    scan_timestamp: str = field(default_factory=lambda: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))
    host_name: str = ""
    os_version: str = ""
    target_user: str = ""
    duration_seconds: float = 0.0
    
    # Statistical Metrics
    total_analyzed: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    clean_count: int = 0
    overall_risk_score: int = 0  # 0 to 100 System Risk Score
    overall_risk_level: str = "LOW"
    
    # Aggregated Breakdowns
    category_summary: Dict[str, int] = field(default_factory=dict)
    mitre_summary: Dict[str, List[str]] = field(default_factory=dict)  # Technique -> [Entry Names]
    
    # Findings and Details
    entries: List[StartupEntry] = field(default_factory=list)
    high_risk_entries: List[StartupEntry] = field(default_factory=list)
    remediation_playbook: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "scan_timestamp": self.scan_timestamp,
            "host_name": self.host_name,
            "os_version": self.os_version,
            "target_user": self.target_user,
            "duration_seconds": round(self.duration_seconds, 2),
            "total_analyzed": self.total_analyzed,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "clean_count": self.clean_count,
            "overall_risk_score": self.overall_risk_score,
            "overall_risk_level": self.overall_risk_level,
            "category_summary": self.category_summary,
            "mitre_summary": self.mitre_summary,
            "entries": [e.to_dict() for e in self.entries],
            "high_risk_entries": [e.to_dict() for e in self.high_risk_entries],
            "remediation_playbook": self.remediation_playbook
        }
