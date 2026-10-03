# WinASEP Forensic Inspector: Windows Startup & Persistence Threat Analysis Suite

---

## 🎯 Executive Overview & Project Purpose

**WinASEP Forensic Inspector** is a Digital Forensics & Incident Response (DFIR) framework designed to perform automated inspection of **Auto-Start Extensibility Points (ASEPs)** in Windows operating systems. It detects covert persistence mechanisms, evaluates heuristic threat indicators, computes Shannon entropy, verifies Authenticode digital signatures, maps tactics to the **MITRE ATT&CK® Matrix**, and generates enterprise-grade **Forensic Assessment Reports** in PDF, HTML, JSON, CSV, and STIX 2.1 formats.

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                     WinASEP FORENSIC INSPECTOR ARCHITECTURE                   │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  [ Multi-Vector ASEP Collectors ]                                             │
│   ├── Registry Run / RunOnce / WOW6432Node                                    │
│   ├── Winlogon (Userinit / Shell / Notify)                                    │
│   ├── Image File Execution Options (IFEO Debuggers)                           │
│   ├── Active Setup (StubPath) & AppInit_DLLs                                  │
│   ├── User & System Startup Folders (.LNK Binary Parsing)                     │
│   ├── Scheduled Tasks (Logon, Boot, Idle Triggers)                            │
│   ├── Windows Services (Auto_Start, Unquoted Service Paths)                   │
│   ├── WMI Event Subscriptions (CommandLine & ActiveScript Consumers)          │
│   └── Boot / System Drivers                                                   │
│                                │                                              │
│                                ▼                                              │
│  [ Deep Forensic Analysis & Cryptographic Engine ]                            │
│   ├── Hashes: MD5, SHA-1, SHA-256                                             │
│   ├── PE Header Analysis (Timestamps, Subsystems, Imphash, Sections)          │
│   ├── Shannon Entropy Calculation (Packing & Encrypted Payload Detection)     │
│   └── Authenticode & Catalog Digital Signature Verification                   │
│                                │                                              │
│                                ▼                                              │
│  [ Heuristic Threat Scoring & MITRE ATT&CK Engine ]                           │
│   ├── 15+ Forensic Rule Detectors (Masquerading, LOLBins, Timestomping)       │
│   ├── Composite Suspicion Score (0 - 100) & Severity Classification          │
│   └── MITRE ATT&CK Technique Mapping & Remediation Generation                 │
│                                │                                              │
│                                ▼                                              │
│  [ Forensic Assessment Reporting & Interfaces ]                               │
│   ├── Enterprise Forensic PDF Report (ReportLab)                              │
│   ├── Standalone Interactive HTML5 Cyber Dashboard Report                     │
│   ├── STIX 2.1 Threat Intel Bundle & SIEM CSV / JSON Exporters                │
│   ├── Rich Colored Terminal CLI                                               │
│   └── FastAPI Dark-Mode Interactive Web GUI (http://127.0.0.1:8000)           │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start Guide

### 1. Requirements & Installation
Ensure Python 3.10+ is available:
```powershell
py -m pip install -r requirements.txt
```

### 2. Launch Interactive Cyber Web Dashboard
Double-click `run_web.bat` or run:
```powershell
py main.py web --port 8000
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser.

### 3. Run a Live System Scan via CLI
Double-click `run_cli.bat` or run:
```powershell
py main.py scan --export-dir reports
```

### 4. Run an APT Campaign Simulation
To test and demonstrate the forensic analyzer against a synthetic APT persistence dataset:
```powershell
py main.py simulate --export-dir reports
```

### 5. Run Automated Test Suite
```powershell
py -m pytest -v
```

---

## 📊 Generated Forensic Deliverables

When a scan is executed, the tool automatically compiles all findings into the `reports/` folder:
1. **`Forensic_Report_<ID>.pdf`**: Publication-ready audit report with executive risk radar, detailed finding sheets, digital signature tables, and incident response playbook.
2. **`Forensic_Report_<ID>.html`**: Standalone interactive single-file HTML report with real-time filtering, search, and MITRE technique links.
3. **`STIX21_Bundle_<ID>.json`**: Standardized STIX 2.1 JSON bundle for SOC/SIEM integration (Splunk, Microsoft Sentinel, Elasticsearch).
4. **`Forensic_Entries_<ID>.csv`**: Flat tabular dataset of all persistence entries for data analysis and spreadsheet auditing.
5. **`Forensic_Report_<ID>.json`**: Machine-readable full forensic report.

---
