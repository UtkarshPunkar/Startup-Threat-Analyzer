"""
STIX 2.1 Threat Intelligence Bundle Exporter.
Converts identified suspicious persistence entries into standardized STIX 2.1 JSON objects.
"""

import os
import json
import uuid
import datetime
from typing import Dict, Any, List
from core.models import ForensicAssessmentReport, ThreatSeverity


class STIXExporter:
    """Generates standard STIX 2.1 Bundle containing Indicators, Attack Patterns, and Observed Data."""

    @classmethod
    def export_stix(cls, report: ForensicAssessmentReport, output_path: str) -> str:
        """Exports suspicious/critical startup entries as STIX 2.1 bundle."""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        objects: List[Dict[str, Any]] = []
        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Identity Object (Forensic Inspector)
        identity_id = f"identity--{uuid.uuid4()}"
        identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now_iso,
            "modified": now_iso,
            "name": "WinASEP Forensic Inspector",
            "identity_class": "system"
        }
        objects.append(identity)

        # Iterate over high-risk and critical entries
        for entry in report.entries:
            if entry.severity in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH, ThreatSeverity.MEDIUM):
                # 1. Indicator Object
                indicator_id = f"indicator--{uuid.uuid4()}"
                pattern_parts = []
                
                if entry.file_info and entry.file_info.sha256:
                    pattern_parts.append(f"file:hashes.'SHA-256' = '{entry.file_info.sha256}'")
                if entry.resolved_path:
                    clean_path = entry.resolved_path.replace('\\', '\\\\')
                    pattern_parts.append(f"file:name = '{os.path.basename(clean_path)}'")

                stix_pattern = "[" + " AND ".join(pattern_parts) + "]" if pattern_parts else f"[process:command_line = '{entry.raw_command[:100]}']"

                indicator = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": indicator_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "name": f"Persistence IOC: {entry.name}",
                    "description": f"Detected via {entry.category.value} in {entry.location}. Risk Score: {entry.total_score}/100.",
                    "indicator_types": ["malicious-activity", "anomalous-activity"],
                    "pattern": stix_pattern,
                    "pattern_type": "stix",
                    "valid_from": now_iso,
                    "created_by_ref": identity_id
                }
                objects.append(indicator)

                # 2. Attack Patterns for findings
                for f in entry.findings:
                    if f.mitre_attack_id:
                        attack_pattern_id = f"attack-pattern--{uuid.uuid4()}"
                        attack_pat = {
                            "type": "attack-pattern",
                            "spec_version": "2.1",
                            "id": attack_pattern_id,
                            "created": now_iso,
                            "modified": now_iso,
                            "name": f.rule_name,
                            "description": f.description,
                            "external_references": [
                                {
                                    "source_name": "mitre-attack",
                                    "external_id": f.mitre_attack_id,
                                    "url": f"https://attack.mitre.org/techniques/{f.mitre_attack_id.replace('.', '/')}/"
                                }
                            ]
                        }
                        objects.append(attack_pat)

                        # Relationship: Indicator indicates Attack Pattern
                        rel = {
                            "type": "relationship",
                            "spec_version": "2.1",
                            "id": f"relationship--{uuid.uuid4()}",
                            "created": now_iso,
                            "modified": now_iso,
                            "relationship_type": "indicates",
                            "source_ref": indicator_id,
                            "target_ref": attack_pattern_id
                        }
                        objects.append(rel)

        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(bundle, f, indent=2)

        return output_path
