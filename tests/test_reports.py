"""
Unit tests for Forensic Report generation (PDF, HTML, JSON, CSV, STIX 2.1).
"""

import os
import json
import pytest
from core.orchestrator import ForensicOrchestrator
from core.reporting import (
    PDFReportGenerator, HTMLReportGenerator, JSONExporter, STIXExporter
)


def test_full_report_generation(tmp_path):
    orchestrator = ForensicOrchestrator()
    report = orchestrator.run_simulation_scan()
    assert report is not None
    assert report.total_analyzed > 0

    # 1. PDF Report
    pdf_path = os.path.join(tmp_path, "test_report.pdf")
    PDFReportGenerator.generate(report, pdf_path)
    assert os.path.isfile(pdf_path)
    assert os.path.getsize(pdf_path) > 1000

    # 2. HTML Report
    html_path = os.path.join(tmp_path, "test_report.html")
    HTMLReportGenerator.generate(report, html_path)
    assert os.path.isfile(html_path)
    with open(html_path, 'r', encoding='utf-8') as f:
        html_content = f.read()
        assert report.report_id in html_content

    # 3. JSON Export
    json_path = os.path.join(tmp_path, "test_report.json")
    JSONExporter.export_json(report, json_path)
    assert os.path.isfile(json_path)
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        assert data["report_id"] == report.report_id

    # 4. CSV Export
    csv_path = os.path.join(tmp_path, "test_report.csv")
    JSONExporter.export_csv(report, csv_path)
    assert os.path.isfile(csv_path)

    # 5. STIX 2.1 Export
    stix_path = os.path.join(tmp_path, "test_stix.json")
    STIXExporter.export_stix(report, stix_path)
    assert os.path.isfile(stix_path)
    with open(stix_path, 'r', encoding='utf-8') as f:
        stix_bundle = json.load(f)
        assert stix_bundle["type"] == "bundle"
        assert len(stix_bundle["objects"]) > 0
