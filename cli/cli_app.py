"""
Rich Command Line Interface for Startup Program & Persistence Analysis.
"""

import os
import sys
import argparse
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.text import Text
from rich import box

from core.orchestrator import ForensicOrchestrator
from core.models import ThreatSeverity
from core.reporting import (
    PDFReportGenerator, HTMLReportGenerator, JSONExporter, STIXExporter
)

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

console = Console(highlight=False)


class CLIApp:
    """Handles terminal command line scanning, visualization, and report generation."""

    @classmethod
    def run_scan(cls, simulate: bool = False, export_dir: str = "reports") -> None:
        """Executes forensic scan and renders rich summary tables in terminal."""
        banner = Text()
        banner.append("+--------------------------------------------------------------------------+\n", style="bold cyan")
        banner.append("|           WINASEP FORENSIC INSPECTOR & PERSISTENCE ANALYZER              |\n", style="bold white")
        banner.append("|      Windows Startup Analysis • Heuristic Threat Scoring • DFIR Report   |\n", style="cyan")
        banner.append("+--------------------------------------------------------------------------+", style="bold cyan")
        console.print(banner)

        orchestrator = ForensicOrchestrator()
        
        with Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task_id = progress.add_task("Initializing...", total=100)

            def update_progress(desc: str, pct: float):
                progress.update(task_id, description=desc, completed=int(pct * 100))

            if simulate:
                report = orchestrator.run_simulation_scan(progress_callback=update_progress)
            else:
                report = orchestrator.run_live_scan(progress_callback=update_progress)

        # Print Executive Summary Panel
        risk_color = "red" if report.overall_risk_level == "CRITICAL" else "yellow" if report.overall_risk_level == "HIGH" else "green"
        summary_text = (
            f"[bold]Report ID:[/bold] {report.report_id}  |  [bold]Host:[/bold] {report.host_name}  |  [bold]User:[/bold] {report.target_user}\n"
            f"[bold]Total ASEPs Inspected:[/bold] {report.total_analyzed}  |  [bold]Scan Time:[/bold] {report.duration_seconds:.2f}s\n"
            f"[bold]System Risk Score:[/bold] [{risk_color} bold]{report.overall_risk_score}/100 ({report.overall_risk_level})[/{risk_color} bold]\n\n"
            f"[bold red]Critical:[/bold red] {report.critical_count}   "
            f"[bold orange3]High:[/bold orange3] {report.high_count}   "
            f"[bold yellow]Medium:[/bold yellow] {report.medium_count}   "
            f"[bold blue]Low:[/bold blue] {report.low_count}   "
            f"[bold green]Clean:[/bold green] {report.clean_count}"
        )
        console.print(Panel(summary_text, title="[bold white]Forensic Assessment Summary[/bold white]", border_style=risk_color, box=box.ROUNDED))

        # Render High & Critical Threat Table
        if report.high_risk_entries:
            console.print("\n[bold red]=== Critical & High-Risk Persistence Findings ========================[/bold red]")
            table = Table(box=box.ASCII2, show_lines=True)
            table.add_column("Severity", justify="center", style="bold", width=12)
            table.add_column("Score", justify="center", width=7)
            table.add_column("Name & Category", width=30)
            table.add_column("Command / Target", width=36)
            table.add_column("Signature & Hashes", width=28)

            for e in report.high_risk_entries:
                sev_style = "bold red" if e.severity == ThreatSeverity.CRITICAL else "bold orange3"
                sev_badge = f"[{sev_style}]{e.severity.value}[/{sev_style}]"
                score_badge = f"[{sev_style}]{e.total_score}/100[/{sev_style}]"

                name_cat = f"[bold white]{e.name}[/bold white]\n[dim]{e.category.value}[/dim]"
                cmd_trunc = (e.raw_command[:33] + "...") if len(e.raw_command) > 36 else e.raw_command

                sig_str = f"Sig: {e.signature.status}" if e.signature else "Sig: N/A"
                hash_str = f"SHA256: {e.file_info.sha256[:8]}..." if e.file_info and e.file_info.sha256 else ""
                ent_str = f"Entropy: {e.file_info.entropy}" if e.file_info else ""
                details = f"[cyan]{sig_str}[/cyan]\n[dim]{hash_str}\n{ent_str}[/dim]"

                table.add_row(sev_badge, score_badge, name_cat, cmd_trunc, details)

            console.print(table)

        # Generate Reports
        os.makedirs(export_dir, exist_ok=True)
        pdf_path = os.path.join(export_dir, f"Forensic_Report_{report.report_id}.pdf")
        html_path = os.path.join(export_dir, f"Forensic_Report_{report.report_id}.html")
        json_path = os.path.join(export_dir, f"Forensic_Report_{report.report_id}.json")
        csv_path = os.path.join(export_dir, f"Forensic_Entries_{report.report_id}.csv")
        stix_path = os.path.join(export_dir, f"STIX21_Bundle_{report.report_id}.json")

        console.print("\n[bold cyan]=== Generating Forensic Deliverables ================================[/bold cyan]")
        
        try:
            PDFReportGenerator.generate(report, pdf_path)
            console.print(f"[bold green][+][/bold green] Enterprise PDF Report:   [underline]{pdf_path}[/underline]")
        except Exception as e:
            console.print(f"[bold red][-][/bold red] PDF generation error: {e}")

        try:
            HTMLReportGenerator.generate(report, html_path)
            console.print(f"[bold green][+][/bold green] Interactive HTML Report: [underline]{html_path}[/underline]")
        except Exception as e:
            console.print(f"[bold red][-][/bold red] HTML generation error: {e}")

        try:
            JSONExporter.export_json(report, json_path)
            JSONExporter.export_csv(report, csv_path)
            STIXExporter.export_stix(report, stix_path)
            console.print(f"[bold green][+][/bold green] Structured Data & STIX:  [underline]{json_path}[/underline] | [underline]{csv_path}[/underline] | [underline]{stix_path}[/underline]")
        except Exception as e:
            console.print(f"[bold red][-][/bold red] Data export error: {e}")

        console.print("\n[bold green][+] Scan completed successfully![/bold green]\n")
