# WinASEP Forensic Inspector: Windows Startup & Persistence Threat Analysis Suite

[![Windows Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20%7C%20Server-0078D6?logo=windows)](https://microsoft.com)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-Web%20Dashboard-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Persistence%20TA0003-red)](https://attack.mitre.org)
[![STIX 2.1](https://img.shields.io/badge/Threat%20Intel-STIX%202.1-blue)](https://oasis-open.github.io/cti-documentation/)

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

---

## 🔍 Inspected Auto-Start Extensibility Points (ASEP)

| Vector Category | Persistence Mechanism | Forensic Significance |
| :--- | :--- | :--- |
| **Registry Run / RunOnce** | `HKLM\SOFTWARE\...\\Run`, `HKCU\SOFTWARE\...\\Run`, `WOW6432Node` | Primary user-mode autostart location; tracks enabled/disabled flags via `StartupApproved`. |
| **Winlogon Hooks** | `Winlogon\Shell`, `Winlogon\Userinit`, `Notify`, `Taskman` | Hijacking default Windows shell or user initialization routines. |
| **IFEO Debuggers** | `Image File Execution Options\<target>\Debugger` | Intercepts legitimate binaries (e.g., `sethc.exe`, `utilman.exe`, `taskmgr.exe`). |
| **Active Setup** | `Active Setup\Installed Components\<GUID>\StubPath` | Executes payload once per user logon session. |
| **AppInit DLLs** | `Windows NT\CurrentVersion\Windows\AppInit_DLLs` | Injects malicious DLL into every user-mode process loading `user32.dll`. |
| **Startup Folders** | User & All Users Startup Directories (`.lnk`, `.exe`, scripts) | Direct file placement; parses Windows Shell Link binary structure. |
| **Scheduled Tasks** | Task Scheduler tasks triggered at logon, boot, or periodic intervals | Preferred vector for advanced APT groups (e.g., APT29, Cobalt Strike). |
| **Windows Services** | Services with `Start = 2` (Auto Start) or `DelayedAutoStart = 1` | System-level persistence; checks for **Unquoted Service Path (CWE-428)** vulnerabilities. |
| **WMI Event Subscriptions** | `__EventFilter` linked to `CommandLineEventConsumer` | Fileless persistence executing commands on specific WMI trigger events. |
| **System Drivers** | Kernel & File System Drivers (`Start = 0` / `1`) | Ring-0 persistence running during early OS boot phases. |

---

## 🛡️ Heuristic Rules & Threat Detection Engine

The analyzer computes a **Composite Suspicion Score (0 to 100)** for every detected entry:

| Rule ID | Heuristic Description | Severity | Score Impact | MITRE ATT&CK |
| :--- | :--- | :---: | :---: | :--- |
| `RULE_MASQUERADING_SYSTEM` | System binary name (`svchost.exe`, `csrss.exe`) outside `System32` | **CRITICAL** | +50 pts | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) |
| `RULE_OBFUSCATED_CMDLINE` | Base64 encoded PowerShell (`-enc`), `IEX`, download cradles | **CRITICAL** | +45 pts | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |
| `RULE_IFEO_DEBUGGER_HIJACK` | Intercepts standard execution using IFEO Debugger key | **CRITICAL** | +50 pts | [T1546.012](https://attack.mitre.org/techniques/T1546/012/) |
| `RULE_DOUBLE_EXTENSION` | Deceptive extensions (e.g. `report.pdf.exe`, `invoice.doc.vbs`) | **CRITICAL** | +45 pts | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) |
| `RULE_SIGNATURE_HASH_MISMATCH` | Authenticode signature hash tampered or invalid | **CRITICAL** | +50 pts | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) |
| `RULE_SUSPICIOUS_PATH` | Executes from `%TEMP%`, `%APPDATA%`, `C:\Users\Public`, `Downloads` | **HIGH** | +35 pts | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) |
| `RULE_HIGH_ENTROPY_PACKED` | Shannon entropy > 7.2 or known packer sections (`.upx`, `.vmp`) | **HIGH** | +30 pts | [T1027.002](https://attack.mitre.org/techniques/T1027/002/) |
| `RULE_WMI_PERSISTENCE` | Active WMI Event Consumer subscription | **HIGH** | +35 pts | [T1546.003](https://attack.mitre.org/techniques/T1546/003/) |
| `RULE_METADATA_IMPERSONATION` | Metadata claims "Microsoft/Google" but lacks valid signature | **HIGH** | +35 pts | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) |
| `RULE_LOLBIN_EXECUTION` | Invokes LOLBins (`powershell.exe`, `mshta.exe`, `certutil.exe`) | **MEDIUM** | +25 pts | [T1218](https://attack.mitre.org/techniques/T1218/) |
| `RULE_UNQUOTED_SERVICE_PATH` | Service binary path contains spaces without quotes (CWE-428) | **MEDIUM** | +20 pts | [T1574.009](https://attack.mitre.org/techniques/T1574/009/) |
| `RULE_TIMESTOMPING_ANOMALY` | Compilation timestamp far in future or predating file creation | **MEDIUM** | +25 pts | [T1070.006](https://attack.mitre.org/techniques/T1070/006/) |
| `RULE_ORPHANED_ENTRY` | Persistence entry points to missing/deleted file | **LOW** | +10 pts | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) |

---

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

## 🧪 Forensic Assessment Report Sample Output

```
+--------------------------------------------------------------------------+
|           WINASEP FORENSIC INSPECTOR & PERSISTENCE ANALYZER              |
|      Windows Startup Analysis • Heuristic Threat Scoring • DFIR Report   |
+--------------------------------------------------------------------------+

┌──────────────────────── Forensic Assessment Summary ────────────────────────┐
│ Report ID: FAR-8236E912  |  Host: SIMULATED-CORP-WORKSTATION  |  User:      │
│ TargetUser (APT29 Simulation)                                               │
│ Total ASEPs Inspected: 9  |  Scan Time: 0.26s                               │
│ System Risk Score: 100/100 (CRITICAL)                                       │
│                                                                             │
│ Critical: 5   High: 0   Medium: 1   Low: 0   Clean: 3                       │
└─────────────────────────────────────────────────────────────────────────────┘

=== Critical & High-Risk Persistence Findings ========================
+----++----------------------+----------------------------+-------------------+
| S… || Name & Category      | Command / Target           | Signature &       |
|    ||                      |                            | Hashes            |
+----++----------------------+----------------------------+-------------------+
| C… || WinAudioHelper       | "C:\Users\Public\svchost.… | Sig: NotSigned    |
|    || Registry Run         | --background --stratum=... | SHA256: 8f4e2b... |
|    ||                      |                            | Entropy: 7.86     |
+----++----------------------+----------------------------+-------------------+
| C… || WMI Subscription:    | mshta.exe javascript:a=... | Sig: Valid        |
|    || SystemHealthSync     | powershell -nop -c IEX ... | SHA256: 7b70b2... |
|    || WMI Event Consumer   |                            | Entropy: 2.4653   |
+----++----------------------+----------------------------+-------------------+
| C… || Startup File:        | C:\Users\...\Q3_Report...  | Sig: NotSigned    |
|    || Q3_Audit_Report.pdf  | .pdf.exe                   | SHA256: 4cf829... |
|    || Startup Folder       |                            | Entropy: 7.68     |
+----++----------------------+----------------------------+-------------------+

=== Generating Forensic Deliverables ================================
[+] Enterprise PDF Report:   reports\Forensic_Report_FAR-8236E912.pdf
[+] Interactive HTML Report: reports\Forensic_Report_FAR-8236E912.html
[+] Structured Data & STIX:  reports\Forensic_Report_FAR-8236E912.json | reports\Forensic_Entries_FAR-8236E912.csv | reports\STIX21_Bundle_FAR-8236E912.json

[+] Scan completed successfully!
```

---

## 🛠️ Remediation & Incident Response Playbook

WinASEP automatically generates precision one-liner PowerShell cleanup commands for each detected threat:

- **Registry Run Key Cleanup:**
  ```powershell
  Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WinAudioHelper"
  ```
- **Malicious Scheduled Task Unregistration:**
  ```powershell
  Unregister-ScheduledTask -TaskName "\Microsoft\Windows\Maintenance\TelemetryUpdate" -Confirm:$false
  ```
- **IFEO Debugger Neutralization:**
  ```powershell
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" -Name "Debugger"
  ```
- **WMI Event Consumer Removal:**
  ```powershell
  Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Filter "Name='SystemHealthSync'" | Remove-CimInstance
  ```
- **Unquoted Service Path Fix:**
  ```powershell
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CloudAgent" -Name "ImagePath" -Value '"C:\Program Files\Enterprise Cloud Agent\service\agent_service.exe" --start'
  ```

---

## 📄 License & Attribution
Developed for Digital Forensics & Incident Response (DFIR) analysts, cybersecurity researchers, and system administrators for educational and forensic audit use.
