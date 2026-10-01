"""
JSON and CSV Exporter for Forensic Assessment data.
"""

import os
import json
import csv
from typing import Dict, Any
from core.models import ForensicAssessmentReport


class JSONExporter:
    """Exports forensic reports to standard JSON and CSV formats."""

    @classmethod
    def export_json(cls, report: ForensicAssessmentReport, output_path: str) -> str:
        """Exports report structure to JSON file."""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report.to_dict(), f, indent=2)
        return output_path

    @classmethod
    def export_csv(cls, report: ForensicAssessmentReport, output_path: str) -> str:
        """Exports all startup entries into a flat CSV format for spreadsheet / SIEM analysis."""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        fieldnames = [
            "entry_id", "name", "category", "severity", "total_score",
            "location", "raw_command", "resolved_path", "enabled", "user_context",
            "is_signed", "signature_status", "signer_name",
            "sha256", "md5", "entropy", "is_high_entropy", "remediation_command", "findings_summary"
        ]

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for entry in report.entries:
                findings_summary = "; ".join([f"{f.rule_name} ({f.severity.value})" for f in entry.findings])
                sig_signed = entry.signature.is_signed if entry.signature else False
                sig_status = entry.signature.status if entry.signature else "Unknown"
                sig_signer = entry.signature.signer_name if entry.signature else ""
                
                sha256 = entry.file_info.sha256 if entry.file_info else ""
                md5 = entry.file_info.md5 if entry.file_info else ""
                entropy = entry.file_info.entropy if entry.file_info else 0.0
                is_high_entropy = entry.file_info.is_high_entropy if entry.file_info else False

                row = {
                    "entry_id": entry.entry_id,
                    "name": entry.name,
                    "category": entry.category.value if hasattr(entry.category, 'value') else str(entry.category),
                    "severity": entry.severity.value if hasattr(entry.severity, 'value') else str(entry.severity),
                    "total_score": entry.total_score,
                    "location": entry.location,
                    "raw_command": entry.raw_command,
                    "resolved_path": entry.resolved_path or "",
                    "enabled": entry.enabled,
                    "user_context": entry.user_context,
                    "is_signed": sig_signed,
                    "signature_status": sig_status,
                    "signer_name": sig_signer,
                    "sha256": sha256,
                    "md5": md5,
                    "entropy": entropy,
                    "is_high_entropy": is_high_entropy,
                    "remediation_command": entry.remediation_command or "",
                    "findings_summary": findings_summary
                }
                writer.writerow(row)

        return output_path
