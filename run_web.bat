@echo off
title WinASEP Forensic Inspector - Web Dashboard
echo =====================================================================
echo Launching WinASEP Forensic Inspector Interactive Web GUI...
echo Access the dashboard at: http://127.0.0.1:8000
echo =====================================================================
py main.py web --port 8000
pause
