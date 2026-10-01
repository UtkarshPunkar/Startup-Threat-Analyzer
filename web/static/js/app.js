/**
 * WinASEP Forensic Inspector - Client-side UI & Inspection Logic
 */

let currentReport = null;
let currentSeverity = 'ALL';
let currentCategory = 'ALL';
let searchQuery = '';
let activeEntry = null;

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  fetchLatestReport();
  setupFilterListeners();
  setupSearchListener();
});

async function fetchLatestReport() {
  showLoading(true, "Loading forensic report data...");
  try {
    const res = await fetch('/api/report/latest');
    if (!res.ok) throw new Error("Failed to load report");
    currentReport = await res.json();
    renderDashboard();
  } catch (err) {
    console.error("Fetch error:", err);
  } finally {
    showLoading(false);
  }
}

async function triggerScan(mode) {
  const label = mode === 'live' ? 'Executing live system scan on Windows ASEPs...' : 'Loading synthetic APT persistence scenarios...';
  showLoading(true, label);

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode })
    });

    if (!res.ok) throw new Error("Scan request failed");
    currentReport = await res.json();
    renderDashboard();
  } catch (err) {
    alert("Error executing scan: " + err.message);
  } finally {
    showLoading(false);
  }
}

function renderDashboard() {
  if (!currentReport) return;

  // Render Stats
  document.getElementById('statRiskScore').innerText = `${currentReport.overall_risk_score} / 100`;
  document.getElementById('statRiskLevel').innerText = `Risk Level: ${currentReport.overall_risk_level}`;
  document.getElementById('statCritical').innerText = currentReport.critical_count;
  document.getElementById('statHigh').innerText = currentReport.high_count;
  document.getElementById('statMedLow').innerText = currentReport.medium_count + currentReport.low_count;
  document.getElementById('statTotal').innerText = currentReport.total_analyzed;
  document.getElementById('statHostInfo').innerText = `Host: ${currentReport.host_name || 'Localhost'} (${currentReport.target_user || 'User'})`;

  // Render Table
  renderTable();
}

function renderTable() {
  const tbody = document.getElementById('findingsTableBody');
  tbody.innerHTML = '';

  if (!currentReport || !currentReport.entries) return;

  const filtered = currentReport.entries.filter(e => {
    // Severity Filter
    if (currentSeverity !== 'ALL' && e.severity !== currentSeverity) return false;

    // Category Filter
    if (currentCategory !== 'ALL' && !e.category.includes(currentCategory)) return false;

    // Search Query
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchName = (e.name || '').toLowerCase().includes(q);
      const matchCmd = (e.raw_command || '').toLowerCase().includes(q);
      const matchLoc = (e.location || '').toLowerCase().includes(q);
      const matchHash = e.file_info && (e.file_info.sha256 || '').toLowerCase().includes(q);
      const matchRule = e.findings && e.findings.some(f => f.rule_name.toLowerCase().includes(q) || f.description.toLowerCase().includes(q));
      return matchName || matchCmd || matchLoc || matchHash || matchRule;
    }

    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 40px; color: var(--text-muted);">No persistence entries match the current filter criteria.</td></tr>`;
    return;
  }

  filtered.forEach(entry => {
    const tr = document.createElement('tr');
    tr.className = 'table-row';
    tr.onclick = () => openInspector(entry);

    const sev = entry.severity.toLowerCase();
    const sigStatus = entry.signature ? entry.signature.status : 'N/A';
    const sigColor = (sigStatus === 'Valid' || sigStatus === 'CatalogSigned') ? 'var(--color-clean)' : 'var(--color-high)';

    tr.innerHTML = `
      <td><span class="badge-sev ${sev}">${entry.severity}</span></td>
      <td><span style="font-family:var(--font-mono); font-weight:700;">${entry.total_score}</span></td>
      <td>
        <div style="font-weight:600; color:#fff;">${escapeHtml(entry.name)}</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:2px;"><span class="tag-cat">${entry.category}</span></div>
      </td>
      <td>
        <div class="mono-preview" title="${escapeHtml(entry.raw_command)}">${escapeHtml(entry.raw_command)}</div>
        <div style="font-size:11px; color:var(--text-dim); margin-top:2px;">📍 ${escapeHtml(entry.location)}</div>
      </td>
      <td>
        <span style="font-size:12px; color:${sigColor}; font-weight:600;">● ${sigStatus}</span>
        ${entry.signature && entry.signature.signer_name ? `<div style="font-size:10px; color:var(--text-muted); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:160px;">${escapeHtml(entry.signature.signer_name)}</div>` : ''}
      </td>
      <td>
        <button class="btn btn-secondary" style="padding:4px 10px; font-size:11px;" onclick="event.stopPropagation(); openInspector(${JSON.stringify(entry).replace(/"/g, '&quot;')})">
          Inspect
        </button>
      </td>
    `;

    tbody.appendChild(tr);
  });
}

function openInspector(entry) {
  activeEntry = entry;

  document.getElementById('modalTitle').innerText = entry.name;
  document.getElementById('modalSub').innerText = `${entry.category} • Risk Score: ${entry.total_score}/100 [${entry.severity}]`;

  // Populate Overview
  document.getElementById('mEntryId').innerText = entry.entry_id || 'N/A';
  document.getElementById('mCategory').innerText = entry.category || 'N/A';
  document.getElementById('mLocation').innerText = entry.location || 'N/A';
  document.getElementById('mRawCommand').innerText = entry.raw_command || 'N/A';
  document.getElementById('mResolvedPath').innerText = entry.resolved_path || 'N/A';
  document.getElementById('mUserContext').innerText = entry.user_context || 'N/A';
  document.getElementById('mEnabled').innerText = entry.enabled ? 'Enabled (Active)' : 'Disabled';

  // Populate PE & Crypto
  const fi = entry.file_info;
  document.getElementById('mSha256').innerText = fi && fi.sha256 ? fi.sha256 : 'N/A';
  document.getElementById('mMd5').innerText = fi && fi.md5 ? fi.md5 : 'N/A';
  document.getElementById('mFileSize').innerText = fi && fi.file_size ? `${(fi.file_size / 1024).toFixed(1)} KB (${fi.file_size} bytes)` : 'N/A';
  document.getElementById('mEntropy').innerText = fi ? `${fi.entropy} / 8.0 ${fi.is_high_entropy ? '(HIGH ENTROPY / PACKED)' : ''}` : 'N/A';
  document.getElementById('mCompileTime').innerText = fi && fi.compile_time ? fi.compile_time : 'N/A';
  document.getElementById('mSubsystem').innerText = fi && fi.subsystem ? fi.subsystem : 'N/A';
  document.getElementById('mCompany').innerText = fi && fi.company_name ? fi.company_name : 'N/A';

  const anomaliesBox = document.getElementById('mAnomaliesBox');
  if (fi && fi.anomalies && fi.anomalies.length > 0) {
    anomaliesBox.innerHTML = `
      <div style="font-size:12px; font-weight:600; color:var(--color-critical); margin-bottom:4px;">Detected Structural Anomalies:</div>
      <ul style="font-size:12px; color:var(--text-muted); padding-left:18px;">
        ${fi.anomalies.map(a => `<li>${escapeHtml(a)}</li>`).join('')}
      </ul>
    `;
  } else {
    anomaliesBox.innerHTML = '<div style="font-size:12px; color:var(--text-dim);">No PE structural anomalies detected.</div>';
  }

  // Populate Digital Signature
  const sig = entry.signature;
  document.getElementById('mSigStatus').innerText = sig ? sig.status : 'Not Signed';
  document.getElementById('mSigSigner').innerText = sig && sig.signer_name ? sig.signer_name : 'None';
  document.getElementById('mSigIssuer').innerText = sig && sig.issuer_name ? sig.issuer_name : 'None';
  document.getElementById('mSigTrusted').innerText = sig ? (sig.is_trusted_publisher ? 'Yes (Verified Vendor)' : 'No / Unknown') : 'No';

  // Populate Heuristics & ATT&CK
  const fContainer = document.getElementById('mFindingsList');
  if (entry.findings && entry.findings.length > 0) {
    fContainer.innerHTML = entry.findings.map(f => {
      const mitreLink = f.mitre_attack_id ? `<a class="btn btn-secondary" style="padding:2px 8px; font-size:11px; text-decoration:none;" href="https://attack.mitre.org/techniques/${f.mitre_attack_id.replace('.','/')}/" target="_blank">🔗 MITRE ${f.mitre_attack_id}</a>` : '';
      return `
        <div style="background: rgba(0,0,0,0.3); border: 1px solid var(--border-color); border-radius: 8px; padding: 12px; margin-bottom: 10px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <div style="font-weight:700; color:var(--accent-cyan); font-size:13px;">[${f.severity}] ${escapeHtml(f.rule_name)} (+${f.score_impact} pts)</div>
            ${mitreLink}
          </div>
          <div style="font-size:12px; color:#e2e8f0; margin-top:6px;">${escapeHtml(f.description)}</div>
          ${f.remediation_advice ? `<div style="font-size:11px; color:var(--text-muted); margin-top:6px;"><strong>Mitigation:</strong> ${escapeHtml(f.remediation_advice)}</div>` : ''}
        </div>
      `;
    }).join('');
  } else {
    fContainer.innerHTML = '<div style="font-size:12px; color:var(--text-muted);">No heuristic rule violations detected for this entry.</div>';
  }

  // Populate Remediation
  document.getElementById('mRemCommand').innerText = entry.remediation_command || `# No automated remediation command needed for this entry.`;

  // Default to first tab
  switchModalTab('tabOverview');

  document.getElementById('inspectorModal').classList.add('active');
}

function closeModal() {
  document.getElementById('inspectorModal').classList.remove('active');
}

function switchModalTab(tabId) {
  document.querySelectorAll('.modal-tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

  event.target.classList.add('active');
  const target = document.getElementById(tabId);
  if (target) target.classList.add('active');
}

function copyRemediation() {
  const cmd = document.getElementById('mRemCommand').innerText;
  navigator.clipboard.writeText(cmd).then(() => {
    const btn = document.querySelector('.copy-btn');
    btn.innerText = 'Copied!';
    setTimeout(() => { btn.innerText = 'Copy Command'; }, 2000);
  });
}

function setupFilterListeners() {
  // Severity filter pills
  document.querySelectorAll('#sevFilterGroup .pill-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('#sevFilterGroup .pill-btn').forEach(b => b.classList.remove('active'));
      e.target.classList.add('active');
      currentSeverity = e.target.getAttribute('data-val');
      renderTable();
    });
  });

  // Category filter pills
  document.querySelectorAll('#catFilterGroup .pill-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('#catFilterGroup .pill-btn').forEach(b => b.classList.remove('active'));
      e.target.classList.add('active');
      currentCategory = e.target.getAttribute('data-val');
      renderTable();
    });
  });
}

function setupSearchListener() {
  const input = document.getElementById('searchInput');
  input.addEventListener('input', (e) => {
    searchQuery = e.target.value;
    renderTable();
  });
}

function showLoading(show, text = "Loading...") {
  const overlay = document.getElementById('loadingOverlay');
  document.getElementById('loadingStatusText').innerText = text;
  if (show) {
    overlay.classList.add('active');
  } else {
    overlay.classList.remove('active');
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
