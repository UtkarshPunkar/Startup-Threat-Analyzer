"""
FastAPI Server for WinASEP Forensic Inspector Web GUI.
Provides REST API endpoints for scanning, report generation, and interactive telemetry.
"""

import os
import sys
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from core.orchestrator import ForensicOrchestrator
from core.models import ForensicAssessmentReport
from core.reporting import (
    PDFReportGenerator, HTMLReportGenerator, JSONExporter, STIXExporter
)

app = FastAPI(title="WinASEP Forensic Inspector", version="2.0.0")

# Setup static files and templates
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
REPORTS_DIR = os.path.join(os.path.dirname(BASE_DIR), "reports")

os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Global in-memory cache for latest report
orchestrator = ForensicOrchestrator()
latest_report: Optional[ForensicAssessmentReport] = None


class ScanRequest(BaseModel):
    mode: str = "simulation"  # "live" or "simulation"


@app.on_event("startup")
async def startup_event():
    global latest_report
    # Pre-generate simulation scan so dashboard is instantly populated on load
    latest_report = orchestrator.run_simulation_scan()


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Renders main forensic dashboard."""
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/api/report/latest")
async def get_latest_report():
    """Returns the latest forensic assessment report JSON."""
    global latest_report
    if not latest_report:
        latest_report = orchestrator.run_simulation_scan()
    return JSONResponse(content=latest_report.to_dict())


@app.post("/api/scan")
async def trigger_scan(scan_req: ScanRequest):
    """Triggers either a live system scan or a simulated APT scenario scan."""
    global latest_report
    if scan_req.mode == "live":
        latest_report = orchestrator.run_live_scan()
    else:
        latest_report = orchestrator.run_simulation_scan()

    return JSONResponse(content=latest_report.to_dict())


@app.get("/api/export/pdf")
async def export_pdf():
    """Generates and downloads the PDF forensic report."""
    global latest_report
    if not latest_report:
        latest_report = orchestrator.run_simulation_scan()

    pdf_path = os.path.join(REPORTS_DIR, f"Forensic_Report_{latest_report.report_id}.pdf")
    PDFReportGenerator.generate(latest_report, pdf_path)
    
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"Forensic_Assessment_Report_{latest_report.report_id}.pdf"
    )


@app.get("/api/export/html")
async def export_html():
    """Generates and downloads the standalone HTML report."""
    global latest_report
    if not latest_report:
        latest_report = orchestrator.run_simulation_scan()

    html_path = os.path.join(REPORTS_DIR, f"Forensic_Report_{latest_report.report_id}.html")
    HTMLReportGenerator.generate(latest_report, html_path)

    return FileResponse(
        html_path,
        media_type="text/html",
        filename=f"Forensic_Assessment_Report_{latest_report.report_id}.html"
    )


@app.get("/api/export/json")
async def export_json():
    """Downloads structured JSON report."""
    global latest_report
    if not latest_report:
        latest_report = orchestrator.run_simulation_scan()

    json_path = os.path.join(REPORTS_DIR, f"Forensic_Report_{latest_report.report_id}.json")
    JSONExporter.export_json(latest_report, json_path)

    return FileResponse(
        json_path,
        media_type="application/json",
        filename=f"Forensic_Report_{latest_report.report_id}.json"
    )


@app.get("/api/export/csv")
async def export_csv():
    """Downloads flat CSV export of all inspected persistence entries."""
    global latest_report
    if not latest_report:
        latest_report = orchestrator.run_simulation_scan()

    csv_path = os.path.join(REPORTS_DIR, f"Forensic_Entries_{latest_report.report_id}.csv")
    JSONExporter.export_csv(latest_report, csv_path)

    return FileResponse(
        csv_path,
        media_type="text/csv",
        filename=f"Forensic_Entries_{latest_report.report_id}.csv"
    )


@app.get("/api/export/stix")
async def export_stix():
    """Downloads STIX 2.1 JSON Threat Intel Bundle."""
    global latest_report
    if not latest_report:
        latest_report = orchestrator.run_simulation_scan()

    stix_path = os.path.join(REPORTS_DIR, f"STIX21_Bundle_{latest_report.report_id}.json")
    STIXExporter.export_stix(latest_report, stix_path)

    return FileResponse(
        stix_path,
        media_type="application/json",
        filename=f"STIX21_Bundle_{latest_report.report_id}.json"
    )


def start_server(host: str = "127.0.0.1", port: int = 8000):
    """Launches the Uvicorn web server."""
    import uvicorn
    uvicorn.run("web.server:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    start_server()
