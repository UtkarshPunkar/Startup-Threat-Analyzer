"""
Standalone Interactive HTML Forensic Assessment Report Generator.
Produces a self-contained, responsive, dark-mode cyber forensic dashboard report.
"""

import os
import json
from typing import Dict, Any
from core.models import ForensicAssessmentReport


class HTMLReportGenerator:
    """Generates standalone single-file interactive HTML reports."""

    @classmethod
    def generate(cls, report: ForensicAssessmentReport, output_path: str) -> str:
        """Renders report data into a standalone HTML file."""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        report_dict = report.to_dict()
        report_json_escaped = json.dumps(report_dict, indent=2).replace("</script>", "<\\/script>")

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Forensic Assessment Report - {report.report_id}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-base: #0a0f1d;
      --bg-surface: #111a2e;
      --bg-card: #16223b;
      --border-color: #243556;
      --accent-cyan: #00f2fe;
      --accent-blue: #4facfe;
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --color-critical: #ff3366;
      --color-high: #ff9900;
      --color-medium: #ffcc00;
      --color-low: #38bdf8;
      --color-clean: #10b981;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background-color: var(--bg-base);
      color: var(--text-main);
      font-family: 'Inter', -apple-system, sans-serif;
      line-height: 1.5;
      padding: 30px 20px;
    }}
    .container {{
      max-width: 1280px;
      margin: 0 auto;
    }}
    /* Header */
    .header {{
      background: linear-gradient(135deg, rgba(17,26,46,0.9), rgba(22,34,59,0.7));
      border: 1px solid var(--border-color);
      border-left: 4px solid var(--accent-cyan);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.3);
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
    }}
    .header-title h1 {{
      font-size: 24px;
      font-weight: 800;
      letter-spacing: -0.5px;
      background: linear-gradient(90deg, #00f2fe, #4facfe);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }}
    .header-title p {{
      color: var(--text-muted);
      font-size: 13px;
      margin-top: 4px;
    }}
    .header-badges {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }}
    .badge {{
      background: rgba(255,255,255,0.06);
      border: 1px solid var(--border-color);
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 12px;
      color: var(--text-muted);
    }}
    .badge strong {{ color: var(--text-main); }}

    /* Risk Metrics Grid */
    .metrics-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}
    .metric-card {{
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 16px;
      text-align: center;
      position: relative;
      overflow: hidden;
    }}
    .metric-card.critical {{ border-top: 3px solid var(--color-critical); }}
    .metric-card.high {{ border-top: 3px solid var(--color-high); }}
    .metric-card.medium {{ border-top: 3px solid var(--color-medium); }}
    .metric-card.low {{ border-top: 3px solid var(--color-low); }}
    .metric-card.clean {{ border-top: 3px solid var(--color-clean); }}
    .metric-card.score {{ border-top: 3px solid var(--accent-cyan); }}
    .metric-value {{
      font-size: 28px;
      font-weight: 800;
      font-family: 'Fira Code', monospace;
      margin-top: 4px;
    }}
    .metric-label {{
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-muted);
    }}

    /* Controls & Filter Bar */
    .controls-bar {{
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 16px;
      margin-bottom: 24px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }}
    .search-row {{
      display: flex;
      gap: 12px;
    }}
    .search-input {{
      flex: 1;
      background: rgba(0,0,0,0.3);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      padding: 10px 14px;
      color: var(--text-main);
      font-family: 'Inter', sans-serif;
      font-size: 13px;
    }}
    .search-input:focus {{
      outline: none;
      border-color: var(--accent-cyan);
    }}
    .filter-pills {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }}
    .filter-btn {{
      background: rgba(255,255,255,0.05);
      border: 1px solid var(--border-color);
      color: var(--text-muted);
      padding: 6px 12px;
      border-radius: 20px;
      font-size: 12px;
      cursor: pointer;
      transition: all 0.2s ease;
    }}
    .filter-btn:hover, .filter-btn.active {{
      background: var(--accent-cyan);
      color: #050b14;
      border-color: var(--accent-cyan);
      font-weight: 600;
    }}

    /* Findings List */
    .entries-container {{
      display: flex;
      flex-direction: column;
      gap: 14px;
    }}
    .entry-card {{
      background: var(--bg-surface);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      overflow: hidden;
      transition: border-color 0.2s ease;
    }}
    .entry-card.critical {{ border-left: 4px solid var(--color-critical); }}
    .entry-card.high {{ border-left: 4px solid var(--color-high); }}
    .entry-card.medium {{ border-left: 4px solid var(--color-medium); }}
    .entry-card.low {{ border-left: 4px solid var(--color-low); }}
    .entry-card.clean {{ border-left: 4px solid var(--color-clean); }}

    .entry-header {{
      padding: 14px 18px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      cursor: pointer;
      background: rgba(255,255,255,0.02);
    }}
    .entry-title-area {{
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    .severity-tag {{
      font-size: 11px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 4px;
      text-transform: uppercase;
      font-family: 'Fira Code', monospace;
    }}
    .severity-tag.critical {{ background: rgba(255,51,102,0.2); color: var(--color-critical); border: 1px solid var(--color-critical); }}
    .severity-tag.high {{ background: rgba(255,153,0,0.2); color: var(--color-high); border: 1px solid var(--color-high); }}
    .severity-tag.medium {{ background: rgba(255,204,0,0.2); color: var(--color-medium); border: 1px solid var(--color-medium); }}
    .severity-tag.low {{ background: rgba(56,189,248,0.2); color: var(--color-low); border: 1px solid var(--color-low); }}
    .severity-tag.clean {{ background: rgba(16,185,129,0.2); color: var(--color-clean); border: 1px solid var(--color-clean); }}

    .entry-name {{
      font-size: 14px;
      font-weight: 600;
    }}
    .entry-category {{
      font-size: 12px;
      color: var(--text-muted);
    }}
    .entry-body {{
      padding: 16px 18px;
      border-top: 1px solid rgba(255,255,255,0.05);
      background: var(--bg-card);
      display: grid;
      grid-template-columns: 1fr;
      gap: 12px;
    }}
    .info-row {{
      display: grid;
      grid-template-columns: 140px 1fr;
      font-size: 12px;
      gap: 8px;
    }}
    .info-label {{
      color: var(--text-muted);
      font-weight: 500;
    }}
    .info-value {{
      font-family: 'Fira Code', monospace;
      color: #e2e8f0;
      word-break: break-all;
    }}
    .findings-box {{
      background: rgba(0,0,0,0.3);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      padding: 12px;
      margin-top: 8px;
    }}
    .finding-item {{
      margin-bottom: 8px;
      font-size: 12px;
    }}
    .finding-item:last-child {{ margin-bottom: 0; }}
    .finding-name {{
      font-weight: 600;
      color: var(--accent-cyan);
    }}
    .mitre-badge {{
      display: inline-block;
      background: rgba(79,172,254,0.15);
      border: 1px solid rgba(79,172,254,0.4);
      color: #60a5fa;
      font-size: 11px;
      padding: 2px 6px;
      border-radius: 4px;
      margin-left: 6px;
      text-decoration: none;
    }}
    .remediation-box {{
      background: rgba(16,185,129,0.08);
      border: 1px solid rgba(16,185,129,0.3);
      border-radius: 6px;
      padding: 10px 12px;
      font-size: 12px;
      margin-top: 6px;
    }}
    .rem-code {{
      font-family: 'Fira Code', monospace;
      color: #34d399;
      background: rgba(0,0,0,0.4);
      padding: 4px 8px;
      border-radius: 4px;
      display: block;
      margin-top: 4px;
    }}

    @media print {{
      body {{ background: #fff; color: #000; padding: 0; }}
      .header, .metric-card, .entry-card, .entry-body {{ background: #fff; color: #000; border-color: #ccc; }}
      .controls-bar {{ display: none; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <header class="header">
      <div class="header-title">
        <h1>Windows Startup Program Forensic Assessment</h1>
        <p>Auto-Start Extensibility Points (ASEP) &amp; Threat Intelligence Report</p>
      </div>
      <div class="header-badges">
        <div class="badge">Report: <strong>{report.report_id}</strong></div>
        <div class="badge">Host: <strong>{report.host_name or "Localhost"}</strong></div>
        <div class="badge">Time: <strong>{report.scan_timestamp}</strong></div>
      </div>
    </header>

    <!-- Metrics -->
    <div class="metrics-grid">
      <div class="metric-card score">
        <div class="metric-label">System Risk Score</div>
        <div class="metric-value" style="color: var(--accent-cyan);">{report.overall_risk_score} / 100</div>
      </div>
      <div class="metric-card critical">
        <div class="metric-label">Critical Threats</div>
        <div class="metric-value" style="color: var(--color-critical);">{report.critical_count}</div>
      </div>
      <div class="metric-card high">
        <div class="metric-label">High Risk</div>
        <div class="metric-value" style="color: var(--color-high);">{report.high_count}</div>
      </div>
      <div class="metric-card medium">
        <div class="metric-label">Medium Risk</div>
        <div class="metric-value" style="color: var(--color-medium);">{report.medium_count}</div>
      </div>
      <div class="metric-card low">
        <div class="metric-label">Low Risk</div>
        <div class="metric-value" style="color: var(--color-low);">{report.low_count}</div>
      </div>
      <div class="metric-card clean">
        <div class="metric-label">Clean Baseline</div>
        <div class="metric-value" style="color: var(--color-clean);">{report.clean_count}</div>
      </div>
    </div>

    <!-- Controls -->
    <div class="controls-bar">
      <div class="search-row">
        <input type="text" id="searchInput" class="search-input" placeholder="Search startup entries by process name, location, command, hash, or rule...">
      </div>
      <div class="filter-pills" id="severityFilters">
        <button class="filter-btn active" data-sev="ALL">All Severities</button>
        <button class="filter-btn" data-sev="CRITICAL">Critical ({report.critical_count})</button>
        <button class="filter-btn" data-sev="HIGH">High ({report.high_count})</button>
        <button class="filter-btn" data-sev="MEDIUM">Medium ({report.medium_count})</button>
        <button class="filter-btn" data-sev="LOW">Low ({report.low_count})</button>
        <button class="filter-btn" data-sev="CLEAN">Clean ({report.clean_count})</button>
      </div>
    </div>

    <!-- Entries -->
    <div class="entries-container" id="entriesContainer"></div>
  </div>

  <script>
    const reportData = {report_json_escaped};
    let currentSeverity = 'ALL';
    let searchQuery = '';

    function renderEntries() {{
      const container = document.getElementById('entriesContainer');
      container.innerHTML = '';

      const filtered = reportData.entries.filter(e => {{
        if (currentSeverity !== 'ALL' && e.severity !== currentSeverity) return false;
        if (searchQuery) {{
          const q = searchQuery.toLowerCase();
          const matchName = e.name.toLowerCase().includes(q);
          const matchCmd = e.raw_command.toLowerCase().includes(q);
          const matchLoc = e.location.toLowerCase().includes(q);
          const matchHash = e.file_info && (e.file_info.sha256 || '').toLowerCase().includes(q);
          const matchFinding = e.findings && e.findings.some(f => f.rule_name.toLowerCase().includes(q) || f.description.toLowerCase().includes(q));
          return matchName || matchCmd || matchLoc || matchHash || matchFinding;
        }}
        return true;
      }});

      if (filtered.length === 0) {{
        container.innerHTML = '<div style="text-align:center; padding: 40px; color: var(--text-muted);">No persistence entries match the active filters.</div>';
        return;
      }}

      filtered.forEach((e, idx) => {{
        const card = document.createElement('div');
        const sevClass = e.severity.toLowerCase();
        card.className = `entry-card ${{sevClass}}`;

        let findingsHtml = '';
        if (e.findings && e.findings.length > 0) {{
          findingsHtml = '<div class="findings-box"><div style="font-weight:600; margin-bottom:6px; font-size:12px; color:var(--text-muted);">Triggered Threat Rules &amp; ATT&amp;CK Mapping:</div>';
          e.findings.forEach(f => {{
            const mitreBadge = f.mitre_attack_id ? `<a class="mitre-badge" href="https://attack.mitre.org/techniques/${{f.mitre_attack_id.replace('.','/')}}/" target="_blank">${{f.mitre_attack_id}}</a>` : '';
            findingsHtml += `<div class="finding-item"><span class="finding-name">• [${{f.severity}}] ${{f.rule_name}}</span> ${{mitreBadge}}<div style="color:var(--text-muted); margin-top:2px;">${{f.description}}</div></div>`;
          }});
          findingsHtml += '</div>';
        }}

        let sigHtml = 'N/A';
        if (e.signature) {{
          sigHtml = `Status: <strong>${{e.signature.status}}</strong> | Signer: <em>${{e.signature.signer_name || 'None'}}</em>`;
        }}

        let fileHtml = 'File Missing / Non-binary';
        if (e.file_info && e.file_info.exists) {{
          fileHtml = `SHA256: ${{e.file_info.sha256 || 'N/A'}}<br>Entropy: <strong>${{e.file_info.entropy}} / 8.0</strong> ${{e.file_info.is_high_entropy ? '<span style=\"color:var(--color-critical)\">(PACKED)</span>' : ''}}`;
        }}

        let remHtml = '';
        if (e.remediation_command) {{
          remHtml = `<div class="remediation-box"><span style="font-weight:600; color:#10b981;">Recommended Cleanup:</span><span class="rem-code">${{e.remediation_command}}</span></div>`;
        }}

        card.innerHTML = `
          <div class="entry-header" onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'grid' : 'none'">
            <div class="entry-title-area">
              <span class="severity-tag ${{sevClass}}">${{e.severity}} (${{e.total_score}}/100)</span>
              <div>
                <div class="entry-name">${{e.name}}</div>
                <div class="entry-category">${{e.category}} &bull; ${{e.location}}</div>
              </div>
            </div>
            <div style="font-size:12px; color:var(--text-muted);">▼ Details</div>
          </div>
          <div class="entry-body">
            <div class="info-row"><span class="info-label">Command Line:</span><span class="info-value">${{e.raw_command}}</span></div>
            <div class="info-row"><span class="info-label">Resolved Binary:</span><span class="info-value">${{e.resolved_path || 'N/A'}}</span></div>
            <div class="info-row"><span class="info-label">Digital Signature:</span><span class="info-value">${{sigHtml}}</span></div>
            <div class="info-row"><span class="info-label">Cryptographic Hash:</span><span class="info-value">${{fileHtml}}</span></div>
            ${{findingsHtml}}
            ${{remHtml}}
          </div>
        `;
        container.appendChild(card);
      }});
    }}

    // Search and filter listeners
    document.getElementById('searchInput').addEventListener('input', (e) => {{
      searchQuery = e.target.value;
      renderEntries();
    }});

    document.querySelectorAll('#severityFilters .filter-btn').forEach(btn => {{
      btn.addEventListener('click', () => {{
        document.querySelectorAll('#severityFilters .filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentSeverity = btn.getAttribute('data-sev');
        renderEntries();
      }});
    }});

    renderEntries();
  </script>
</body>
</html>
"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return output_path
