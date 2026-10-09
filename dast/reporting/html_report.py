"""HTML Reporting module for generating interactive, visual DAST audit reports."""

from __future__ import annotations

import base64
import html
from pathlib import Path
from typing import Any

from dast.models import EvidenceType, Finding, ScanResult, Severity


class HTMLReporter:
    """Generates standalone, responsive HTML security assessment reports."""

    SEVERITY_COLORS = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#d97706",
        "LOW": "#2563eb",
        "INFO": "#64748b",
    }

    SEVERITY_BG = {
        "CRITICAL": "#fef2f2",
        "HIGH": "#fff7ed",
        "MEDIUM": "#fffbeb",
        "LOW": "#eff6ff",
        "INFO": "#f8fafc",
    }

    @staticmethod
    def _get_image_src(path_str: str | None) -> str | None:
        """Read local screenshot file and convert to inline data URI if it exists."""
        if not path_str:
            return None
        try:
            p = Path(path_str)
            if p.exists() and p.is_file():
                b64_data = base64.b64encode(p.read_bytes()).decode("ascii")
                return f"data:image/png;base64,{b64_data}"
        except Exception:
            pass
        return html.escape(path_str)

    @classmethod
    def generate(cls, scan_result: ScanResult) -> str:
        """Render ScanResult into a polished standalone HTML report."""
        summary = scan_result.summary or {}
        sev_counts = summary.get("severity_breakdown", {})
        total_findings = len(scan_result.findings)
        total_endpoints = len(scan_result.scanned_endpoints)
        duration = f"{scan_result.duration_seconds:.2f}s"
        target_url = scan_result.target.url
        start_time_str = scan_result.start_time.strftime("%Y-%m-%d %H:%M:%S UTC")

        crit_count = sev_counts.get("CRITICAL", 0)
        high_count = sev_counts.get("HIGH", 0)
        med_count = sev_counts.get("MEDIUM", 0)
        low_count = sev_counts.get("LOW", 0)
        info_count = sev_counts.get("INFO", 0)

        confirmed_count = sum(1 for f in scan_result.findings if not f.is_false_positive)
        fp_count = sum(1 for f in scan_result.findings if f.is_false_positive)

        # Build findings cards
        findings_html = []
        for idx, f in enumerate(scan_result.findings, start=1):
            findings_html.append(cls._render_finding_card(f, idx))

        findings_block = "\n".join(findings_html) if findings_html else (
            '<div class="no-findings">'
            '<svg width="48" height="48" fill="none" stroke="#10b981" viewBox="0 0 24 24">'
            '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" '
            'd="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>'
            '<h3>Zero Vulnerabilities Detected</h3>'
            '<p>No security flaws matched the active audit profiles during this assessment.</p>'
            '</div>'
        )

        # Build endpoints table
        endpoints_rows = []
        for ep in scan_result.scanned_endpoints:
            params_str = ", ".join(ep.get_all_param_names()) or "<em>None</em>"
            endpoints_rows.append(
                f"<tr>"
                f'<td><span class="method-badge method-{ep.method.value.lower()}">{html.escape(ep.method.value)}</span></td>'
                f'<td class="mono">{html.escape(ep.url)}</td>'
                f"<td>{params_str}</td>"
                f"</tr>"
            )
        endpoints_table_body = "\n".join(endpoints_rows)

        # Build detector timings table
        detector_timings = summary.get("detector_timings", {})
        timings_rows = []
        for det_name, det_secs in sorted(detector_timings.items(), key=lambda x: x[1], reverse=True):
            timings_rows.append(
                f"<tr>"
                f'<td class="mono"><strong>{html.escape(det_name)}</strong></td>'
                f'<td style="color: #38bdf8; font-weight:600;">{det_secs:.2f}s</td>'
                f"</tr>"
            )
        timings_table_body = "\n".join(timings_rows) if timings_rows else "<tr><td colspan='2'><em>No timing data available</em></td></tr>"

        # HTML Template
        doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DAST Security Audit Report - {html.escape(target_url)}</title>
<style>
  :root {{
    --bg: #0f172a;
    --card-bg: #1e293b;
    --border: #334155;
    --text-main: #f8fafc;
    --text-muted: #94a3b8;
    --accent: #38bdf8;
    --crit: #ef4444;
    --high: #f97316;
    --med: #f59e0b;
    --low: #3b82f6;
    --info: #64748b;
    --success: #10b981;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg);
    color: var(--text-main);
    line-height: 1.5;
    padding: 24px;
  }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border);
    padding-bottom: 20px;
    margin-bottom: 24px;
  }}
  .logo-title h1 {{ font-size: 24px; font-weight: 700; color: #fff; }}
  .logo-title p {{ color: var(--text-muted); font-size: 14px; }}
  .scan-meta {{ text-align: right; font-size: 13px; color: var(--text-muted); }}
  .scan-meta strong {{ color: var(--text-main); }}

  /* Metric Cards */
  .metrics-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }}
  .metric-card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    text-align: center;
  }}
  .metric-card .num {{ font-size: 32px; font-weight: 800; line-height: 1.1; margin-bottom: 4px; }}
  .metric-card .label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); }}
  .num-crit {{ color: var(--crit); }}
  .num-high {{ color: var(--high); }}
  .num-med {{ color: var(--med); }}
  .num-low {{ color: var(--low); }}
  .num-info {{ color: var(--info); }}
  .num-total {{ color: var(--accent); }}

  /* Controls */
  .filter-bar {{
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    align-items: center;
    background: var(--card-bg);
    padding: 14px 18px;
    border-radius: 8px;
    border: 1px solid var(--border);
    margin-bottom: 24px;
  }}
  .filter-btn {{
    background: #334155;
    color: #fff;
    border: none;
    padding: 6px 14px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 13px;
    font-weight: 600;
    transition: background 0.15s;
  }}
  .filter-btn:hover, .filter-btn.active {{ background: var(--accent); color: #0f172a; }}
  .search-input {{
    flex: 1;
    min-width: 220px;
    padding: 7px 12px;
    background: #0f172a;
    border: 1px solid var(--border);
    border-radius: 6px;
    color: #fff;
    font-size: 13px;
  }}

  /* Findings list */
  .section-title {{ font-size: 18px; font-weight: 700; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }}
  .finding-card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 16px;
    overflow: hidden;
    transition: border-color 0.15s;
  }}
  .finding-card:hover {{ border-color: #475569; }}
  .finding-header {{
    padding: 16px 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    cursor: pointer;
    background: rgba(255,255,255,0.02);
  }}
  .finding-title-group {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
  .badge {{
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    padding: 3px 8px;
    border-radius: 4px;
    letter-spacing: 0.05em;
  }}
  .badge-CRITICAL {{ background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid #ef4444; }}
  .badge-HIGH {{ background: rgba(249,115,22,0.2); color: #fb923c; border: 1px solid #f97316; }}
  .badge-MEDIUM {{ background: rgba(245,158,11,0.2); color: #fcd34d; border: 1px solid #f59e0b; }}
  .badge-LOW {{ background: rgba(59,130,246,0.2); color: #60a5fa; border: 1px solid #3b82f6; }}
  .badge-INFO {{ background: rgba(100,116,139,0.2); color: #94a3b8; border: 1px solid #64748b; }}

  .badge-evidence {{ background: #334155; color: #cbd5e1; }}
  .badge-detector {{ background: #1e1b4b; color: #a5b4fc; border: 1px solid #4338ca; }}

  .finding-body {{ padding: 20px; border-top: 1px solid var(--border); display: none; }}
  .finding-body.open {{ display: block; }}

  .detail-row {{ margin-bottom: 16px; }}
  .detail-label {{ font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px; }}
  .detail-content {{ font-size: 14px; color: #cbd5e1; }}
  .url-bar {{
    background: #0f172a;
    padding: 8px 12px;
    border-radius: 6px;
    font-family: monospace;
    font-size: 13px;
    border: 1px solid var(--border);
    word-break: break-all;
  }}
  .method-badge {{ font-size: 11px; font-weight: 800; padding: 2px 6px; border-radius: 4px; margin-right: 6px; }}
  .method-get {{ background: #065f46; color: #34d399; }}
  .method-post {{ background: #1e3a8a; color: #60a5fa; }}

  /* Evidence Box */
  .evidence-box {{
    background: #020617;
    border: 1px solid #1e293b;
    border-radius: 6px;
    padding: 14px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 13px;
    color: #e2e8f0;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
    line-height: 1.45;
  }}

  .remediation-box {{
    background: rgba(16,185,129,0.08);
    border: 1px solid rgba(16,185,129,0.3);
    border-radius: 6px;
    padding: 14px;
    color: #d1fae5;
    font-size: 13.5px;
  }}

  /* Table */
  table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }}
  th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); }}
  th {{ background: #1e293b; color: var(--text-muted); font-size: 11px; text-transform: uppercase; }}
  .mono {{ font-family: monospace; }}

  .no-findings {{
    text-align: center;
    padding: 48px;
    background: var(--card-bg);
    border-radius: 8px;
    border: 1px solid var(--border);
  }}
  .no-findings h3 {{ color: var(--success); margin: 12px 0 6px; font-size: 18px; }}
  .no-findings p {{ color: var(--text-muted); font-size: 14px; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="logo-title">
      <h1>Dynamic Application Security Testing (DAST) Report</h1>
      <p>Target Assessment: <strong>{html.escape(target_url)}</strong></p>
    </div>
    <div class="scan-meta">
      <div>Scan Date: <strong>{start_time_str}</strong></div>
      <div>Duration: <strong>{duration}</strong></div>
      <div>Endpoints Crawled: <strong>{total_endpoints}</strong></div>
    </div>
  </header>

  <!-- Metrics Grid -->
  <!-- Metrics Grid -->
  <div class="metrics-grid">
    <div class="metric-card">
      <div class="num num-total">{total_findings}</div>
      <div class="label">Total Findings</div>
    </div>
    <div class="metric-card">
      <div class="num" style="color: #10b981;">{confirmed_count}</div>
      <div class="label">Confirmed (AI)</div>
    </div>
    <div class="metric-card">
      <div class="num" style="color: #f97316;">{fp_count}</div>
      <div class="label">False Positives (AI)</div>
    </div>
    <div class="metric-card">
      <div class="num num-crit">{crit_count}</div>
      <div class="label">Critical</div>
    </div>
    <div class="metric-card">
      <div class="num num-high">{high_count}</div>
      <div class="label">High</div>
    </div>
    <div class="metric-card">
      <div class="num num-med">{med_count}</div>
      <div class="label">Medium</div>
    </div>
    <div class="metric-card">
      <div class="num num-low">{low_count}</div>
      <div class="label">Low</div>
    </div>
    <div class="metric-card">
      <div class="num num-info">{info_count}</div>
      <div class="label">Informational</div>
    </div>
  </div>

  <!-- Filtering & Search -->
  <div class="filter-bar">
    <button class="filter-btn active" style="border: 1px solid #10b981; color: #34d399;" onclick="filterFindings('CONFIRMED')">✓ Confirmed ({confirmed_count})</button>
    <button class="filter-btn" style="border: 1px solid #f97316; color: #fdba74;" onclick="filterFindings('FALSE_POSITIVE')">⚠️ False Positives ({fp_count})</button>
    <button class="filter-btn" onclick="filterFindings('ALL')">All ({total_findings})</button>
    <button class="filter-btn" onclick="filterFindings('CRITICAL')">Critical ({crit_count})</button>
    <button class="filter-btn" onclick="filterFindings('HIGH')">High ({high_count})</button>
    <button class="filter-btn" onclick="filterFindings('MEDIUM')">Medium ({med_count})</button>
    <button class="filter-btn" onclick="filterFindings('LOW')">Low ({low_count})</button>
    <input type="text" id="searchInput" class="search-input" placeholder="Search findings by title, URL, parameter..." onkeyup="searchFindings()">
  </div>

  <!-- Findings Section -->
  <div class="section-title">
    <span>Vulnerability Findings</span>
  </div>
  <div id="findingsContainer">
    {findings_block}
  </div>

  <!-- Detector Execution Timings -->
  <div class="section-title" style="margin-top: 36px;">
    <span>Detector Execution Times & Performance</span>
  </div>
  <div style="background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; overflow-x: auto; margin-bottom: 30px;">
    <table>
      <thead>
        <tr>
          <th>Detector Plugin</th>
          <th style="width: 180px;">Total Duration</th>
        </tr>
      </thead>
      <tbody>
        {timings_table_body}
      </tbody>
    </table>
  </div>

  <!-- Scanned Endpoints -->
  <div class="section-title">
    <span>Scanned Scope & Discovered Endpoints ({total_endpoints})</span>
  </div>
  <div style="background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; overflow-x: auto;">
    <table>
      <thead>
        <tr>
          <th style="width: 80px;">Method</th>
          <th>URL Path</th>
          <th>Parameters</th>
        </tr>
      </thead>
      <tbody>
        {endpoints_table_body}
      </tbody>
    </table>
  </div>
</div>

<script>
  function toggleFinding(id) {{
    const el = document.getElementById(id);
    if (el) {{
      el.classList.toggle('open');
    }}
  }}

  let currentFilter = 'CONFIRMED';
  document.addEventListener('DOMContentLoaded', () => {{
    applyFilters();
  }});

  function filterFindings(filterType) {{
    currentFilter = filterType;
    document.querySelectorAll('.filter-btn').forEach(btn => {{
      btn.classList.remove('active');
      if (
        (filterType === 'ALL' && btn.innerText.startsWith('All')) ||
        (filterType === 'CONFIRMED' && btn.innerText.includes('Confirmed')) ||
        (filterType === 'FALSE_POSITIVE' && btn.innerText.includes('False Positives')) ||
        (btn.innerText.startsWith(filterType))
      ) {{
        btn.classList.add('active');
      }}
    }});
    applyFilters();
  }}

  function searchFindings() {{
    applyFilters();
  }}

  function applyFilters() {{
    const term = document.getElementById('searchInput').value.toLowerCase();
    const cards = document.querySelectorAll('.finding-card');
    cards.forEach(card => {{
      const cardSev = card.getAttribute('data-severity');
      const isFp = card.getAttribute('data-is-fp') === 'true';
      const text = card.innerText.toLowerCase();

      let matchesFilter = true;
      if (currentFilter === 'ALL') {{
        matchesFilter = true;
      }} else if (currentFilter === 'CONFIRMED') {{
        matchesFilter = !isFp;
      }} else if (currentFilter === 'FALSE_POSITIVE') {{
        matchesFilter = isFp;
      }} else {{
        matchesFilter = (cardSev === currentFilter);
      }}

      const matchesSearch = (!term || text.includes(term));
      card.style.display = (matchesFilter && matchesSearch) ? 'block' : 'none';
    }});
  }}
</script>
</body>
</html>
"""
        return doc

    @classmethod
    def _render_finding_card(cls, f: Finding, idx: int) -> str:
        """Render a single finding collapsible card with screenshots and terminal outputs."""
        sev_str = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
        ev_type_str = f.evidence_type.value if hasattr(f.evidence_type, "value") else str(f.evidence_type)
        param_tag = f"&bull; Param: <code>{html.escape(f.parameter)}</code>" if f.parameter else ""

        # Format Evidence content
        evidence_content = ""
        if getattr(f, "captured_dialog", None):
            evidence_content += (
                f'<div class="detail-label" style="color: #38bdf8;">⚡ JavaScript Dialog Intercepted:</div>'
                f'<div class="evidence-box" style="border-color: #0284c7; background: #082f49; color: #7dd3fc; margin-bottom: 12px;">'
                f'&#9889; {html.escape(f.captured_dialog)} [Live Execution Confirmed in Headless Browser]'
                f'</div>\n'
            )

        if f.terminal_output:
            evidence_content += (
                f'<div class="detail-label" style="color: #34d399; margin-top: 10px;">💻 Terminal / CLI Diagnostic Output:</div>'
                f'<div style="background:#020617; border:1px solid #1e293b; border-radius:6px; margin-top:6px; margin-bottom:12px; overflow:hidden;">'
                f'  <div style="background:#0f172a; padding:6px 12px; border-bottom:1px solid #1e293b; font-size:11px; color:#64748b; font-family:monospace;">'
                f'    ● ● ● &nbsp; Terminal Session'
                f'  </div>'
                f'  <pre class="evidence-box" style="border:none; margin:0; border-radius:0;">{html.escape(f.terminal_output)}</pre>'
                f'</div>\n'
            )

        if f.evidence:
            evidence_content += f'<div class="detail-label">Technical Evidence:</div><div class="evidence-box">{html.escape(f.evidence)}</div>\n'

        # Format Screenshot attachments
        screenshot_block = ""
        if f.screenshot_path:
            img_src = cls._get_image_src(f.screenshot_path)
            screenshot_block += (
                f'<div class="detail-label" style="color: #a78bfa; margin-top: 14px;">📸 Visual Screenshot Evidence:</div>'
                f'<div style="margin-top: 6px; border: 1px solid var(--border); border-radius: 6px; overflow: hidden; background: #000; max-width: 860px;">'
                f'  <a href="{img_src}" target="_blank">'
                f'    <img src="{img_src}" alt="Screenshot Proof" style="width: 100%; display: block; max-height: 480px; object-fit: contain;" />'
                f'  </a>'
                f'  <div style="padding: 6px 12px; font-size: 11px; background: #0f172a; color: var(--text-muted);">'
                f'    Path: <code>{html.escape(f.screenshot_path)}</code> (Click image to view full resolution)'
                f'  </div>'
                f'</div>'
            )

        if f.step_screenshots and len(f.step_screenshots) > 1:
            step_cards = []
            for s_idx, s_path in enumerate(f.step_screenshots, start=1):
                s_src = cls._get_image_src(s_path)
                s_name = Path(s_path).stem.replace("_", " ")
                if "step-1" in s_name.lower() or "step 1" in s_name.lower() or "navigated" in s_name.lower():
                    step_title = "Step 1: Navigated to Form"
                elif "step-2" in s_name.lower() or "step 2" in s_name.lower() or "filled" in s_name.lower():
                    step_title = "Step 2: Filled Payload"
                elif "step-3" in s_name.lower() or "step 3" in s_name.lower() or "submitted" in s_name.lower() or "result" in s_name.lower():
                    step_title = "Step 3: Execution / Form Submission Result"
                else:
                    step_title = f"Step {s_idx}: {s_name.title()}"

                step_cards.append(
                    f'<div style="flex: 1; min-width: 240px; max-width: 360px; background: #0f172a; border: 1px solid var(--border); border-radius: 6px; overflow: hidden; margin-top: 8px;">'
                    f'  <div style="padding: 6px 10px; font-size: 11px; font-weight: 600; color: #38bdf8; background: #1e293b; border-bottom: 1px solid var(--border);">{html.escape(step_title)}</div>'
                    f'  <a href="{s_src}" target="_blank">'
                    f'    <img src="{s_src}" alt="{html.escape(step_title)}" style="width: 100%; display: block; max-height: 200px; object-fit: cover;" />'
                    f'  </a>'
                    f'  <div style="padding: 4px 8px; font-size: 10px; color: var(--text-muted); text-overflow: ellipsis; overflow: hidden; white-space: nowrap;">{html.escape(s_path)}</div>'
                    f'</div>'
                )

            screenshot_block += (
                f'<div class="detail-label" style="color: #38bdf8; margin-top: 12px;">📸 Diagnostic Steps ({len(f.step_screenshots)} captured):</div>'
                f'<div style="display: flex; flex-wrap: wrap; gap: 12px; margin-top: 6px;">'
                f'{"".join(step_cards)}'
                f'</div>'
            )

        # Format HTTP Traffic metadata if present
        http_traffic_block = ""
        if f.request_metadata or f.response_metadata:
            http_traffic_block = '<div class="detail-label" style="margin-top: 14px;">HTTP Audit Traffic:</div>'
            if f.request_metadata:
                req_headers_str = "\n".join(f"{k}: {v}" for k, v in f.request_metadata.headers.items())
                http_traffic_block += (
                    f'<div class="detail-label" style="font-size:11px; margin-top:6px;">HTTP Request:</div>'
                    f'<div class="evidence-box">{html.escape(f.request_metadata.method)} {html.escape(f.request_metadata.url)}\n'
                    f'{html.escape(req_headers_str)}\n\n'
                    f'{html.escape(f.request_metadata.body or "")}</div>'
                )
            if f.response_metadata:
                res_headers_str = "\n".join(f"{k}: {v}" for k, v in f.response_metadata.headers.items())
                body_prev = f.response_metadata.body_preview or ""
                http_traffic_block += (
                    f'<div class="detail-label" style="font-size:11px; margin-top:6px;">HTTP Response ({f.response_metadata.status_code} in {f.response_metadata.latency_ms:.1f}ms):</div>'
                    f'<div class="evidence-box">Status: {f.response_metadata.status_code}\n'
                    f'{html.escape(res_headers_str)}\n\n'
                    f'{html.escape(body_prev)}</div>'
                )

        ai_badge = ""
        ai_block = ""
        if f.ai_validation_status:
            if f.is_false_positive:
                ai_badge = '<span class="badge" style="background: #f97316; color: #fff;">⚠️ AI: False Positive</span>'
            else:
                ai_badge = '<span class="badge" style="background: #10b981; color: #fff;">✓ AI: Confirmed</span>'

            conf_pct = f"{f.ai_confidence_score * 100:.0f}%" if f.ai_confidence_score is not None else "N/A"
            border_col = "#ea580c" if f.is_false_positive else "#0284c7"
            bg_col = "#431407" if f.is_false_positive else "#082f49"
            text_col = "#fdba74" if f.is_false_positive else "#7dd3fc"
            status_title = "FALSE POSITIVE" if f.is_false_positive else "CONFIRMED VULNERABILITY"

            ai_block = f"""
        <div class="detail-row">
          <div class="detail-label" style="color: #38bdf8;">🤖 AI Finding Validation (Google Gemini):</div>
          <div style="background: {bg_col}; border: 1px solid {border_col}; border-radius: 6px; padding: 12px 14px; margin-top: 6px; color: {text_col}; font-size: 13px;">
            <div style="font-weight: 600; margin-bottom: 6px; display: flex; justify-content: space-between; align-items: center;">
              <span>Status: <strong>{status_title}</strong></span>
              <span style="font-size: 12px; background: rgba(0,0,0,0.25); padding: 2px 8px; border-radius: 4px;">AI Confidence: {conf_pct}</span>
            </div>
            <div style="line-height: 1.45; color: #e2e8f0;">{html.escape(f.ai_validation_reasoning or "")}</div>
          </div>
        </div>
            """

        fp_border_style = 'style="border-left: 4px solid #f97316;"' if f.is_false_positive else ""
        card = f"""
    <div class="finding-card" data-severity="{html.escape(sev_str)}" data-is-fp="{str(f.is_false_positive).lower()}" {fp_border_style}>
      <div class="finding-header" onclick="toggleFinding('finding-body-{idx}')">
        <div class="finding-title-group">
          <span class="badge badge-{html.escape(sev_str)}">{html.escape(sev_str)}</span>
          <span class="badge badge-detector">{html.escape(f.detector_name)}</span>
          <span class="badge badge-evidence">{html.escape(ev_type_str)}</span>
          {ai_badge}
          <strong>{html.escape(f.title)}</strong>
        </div>
        <div style="font-size: 13px; color: var(--text-muted);">
          <span>Click to view details &#9662;</span>
        </div>
      </div>
      <div id="finding-body-{idx}" class="finding-body">
        <div class="detail-row">
          <div class="detail-label">Vulnerable Endpoint</div>
          <div class="url-bar">
            <span class="method-badge method-{html.escape(f.method.lower())}">{html.escape(f.method)}</span>
            {html.escape(f.url)} {param_tag}
          </div>
        </div>

        {ai_block}

        <div class="detail-row">
          <div class="detail-label">Vulnerability Description</div>
          <div class="detail-content">{html.escape(f.description)}</div>
        </div>

        <div class="detail-row">
          {evidence_content}
          {screenshot_block}
          {http_traffic_block}
        </div>

        <div class="detail-row" style="margin-bottom: 0;">
          <div class="detail-label">Recommended Remediation</div>
          <div class="remediation-box">{html.escape(f.remediation)}</div>
        </div>
      </div>
    </div>
        """
        return card

    @classmethod
    def save(cls, scan_result: ScanResult, file_path: str | Path) -> Path:
        """Write standalone HTML report directly to filesystem."""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = cls.generate(scan_result)
        path.write_text(content, encoding="utf-8")
        return path

