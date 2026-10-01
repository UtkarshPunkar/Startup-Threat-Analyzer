"""
WinASEP Forensic Inspector & Persistence Analyzer.
Main CLI & Web Application Entry Point.
"""

import sys
import argparse
from cli.cli_app import CLIApp


def main():
    parser = argparse.ArgumentParser(
        description="WinASEP Forensic Inspector: Windows Startup & Persistence Analysis Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  py main.py scan                     Run live forensic scan on local Windows system
  py main.py simulate                 Run analysis on synthetic APT campaign dataset
  py main.py web --port 8000          Launch interactive Cyber DFIR Web GUI
  py main.py scan --export-dir ./out  Export forensic PDF/HTML/JSON reports to custom directory
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Operational mode")

    # Command: scan (Live System Scan)
    scan_parser = subparsers.add_parser("scan", help="Run a live forensic scan on the local Windows system")
    scan_parser.add_argument("--export-dir", default="reports", help="Directory to save generated forensic reports")

    # Command: simulate (APT Scenario)
    sim_parser = subparsers.add_parser("simulate", help="Run analysis on synthetic APT campaign simulation dataset")
    sim_parser.add_argument("--export-dir", default="reports", help="Directory to save generated forensic reports")

    # Command: web (FastAPI Web GUI)
    web_parser = subparsers.add_parser("web", help="Launch the modern interactive Web GUI")
    web_parser.add_argument("--host", default="127.0.0.1", help="Host address to bind web server (default: 127.0.0.1)")
    web_parser.add_argument("--port", type=int, default=8000, help="Port number for web server (default: 8000)")

    args = parser.parse_args()

    if args.command == "scan":
        CLIApp.run_scan(simulate=False, export_dir=args.export_dir)
    elif args.command == "simulate":
        CLIApp.run_scan(simulate=True, export_dir=args.export_dir)
    elif args.command == "web":
        from web.server import start_server
        print(f"\n[*] Starting WinASEP Forensic Dashboard on http://{args.host}:{args.port}")
        print("[*] Press CTRL+C to terminate web server.\n")
        start_server(host=args.host, port=args.port)
    else:
        # If no arguments provided, show help and run interactive prompt
        CLIApp.run_scan(simulate=True, export_dir="reports")


if __name__ == "__main__":
    main()
