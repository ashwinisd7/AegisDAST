"""PDF Reporting module for generating executive, evidence-backed security audit PDF reports.

Includes confirmed True-Positive vulnerabilities, visual screenshot proofs,
reproduction steps with curl commands, technical evidence, and remediation guidance.
"""

from __future__ import annotations

import base64
import html
import logging
from pathlib import Path
import re
from typing import Any

from dast.models import EvidenceType, Finding, ScanResult, Severity

logger = logging.getLogger(__name__)


class PDFReporter:
    """Generates comprehensive PDF security assessment reports for executive and technical teams."""

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

    REMEDIATIONS = {
        "sql_injection": (
            "1. Use Parameterized Queries / Prepared Statements (e.g. PDO, PreparedStatement) for all database queries.\n"
            "2. Utilize an established Object Relational Mapper (ORM) with automated parameter binding.\n"
            "3. Enforce strict input validation using allowlists for sorting columns and table names.\n"
            "4. Apply the Principle of Least Privilege to database user accounts."
        ),
        "command_injection": (
            "1. Avoid passing user-supplied input directly to system shell execution functions (e.g., exec(), system(), popen(), shell_exec()).\n"
            "2. Use safe, parameterized API alternatives (e.g., subprocess.run(['cmd', arg], shell=False) or execve()).\n"
            "3. Enforce strict character allowlists (e.g. alphanumeric only) and reject command delimiters (; && || ` $).\n"
            "4. Run web services in minimal, unprivileged containerized sandboxes."
        ),
        "reflected_xss": (
            "1. Apply context-aware output encoding (HTML Entity, Attribute, JavaScript, CSS) before rendering user input in responses.\n"
            "2. Implement a robust Content Security Policy (CSP) with strict script-src directives (e.g. nonces or hashes).\n"
            "3. Enable HttpOnly and SameSite flags on all sensitive session cookies.\n"
            "4. Utilize modern web frameworks with built-in contextual auto-escaping (e.g. React, Angular, Vue)."
        ),
        "stored_xss": (
            "1. Sanitize and validate all incoming data against strict allowlists before persisting to the database.\n"
            "2. Apply context-aware output encoding whenever stored content is displayed to users.\n"
            "3. Deploy a strict Content Security Policy (CSP) preventing execution of inline scripts and untrusted domains.\n"
            "4. Set HttpOnly and Secure flags on all authentication cookies."
        ),
        "file_inclusion": (
            "1. Never pass raw user input into file-system inclusion functions (include, require, readFile).\n"
            "2. Restrict allowed files to a strict hardcoded allowlist or dictionary mapping.\n"
            "3. Ensure open_basedir restrictions are active in runtime environment.\n"
            "4. Disable allow_url_include and allow_url_fopen in php.ini if not required."
        ),
        "csrf": (
            "1. Implement unique, cryptographically random Anti-CSRF tokens for all state-changing POST/PUT/DELETE requests.\n"
            "2. Enforce SameSite=Strict or SameSite=Lax on all session cookies.\n"
            "3. Validate custom request headers (e.g. X-Requested-With, Origin, Referer).\n"
            "4. Require re-authentication or multi-factor confirmation for critical actions."
        ),
        "cookie_security": (
            "1. Set the Secure flag on all cookies to ensure transmission only over encrypted TLS (HTTPS).\n"
            "2. Set the HttpOnly flag to prevent client-side JavaScript access via document.cookie.\n"
            "3. Set SameSite=Lax or SameSite=Strict to defend against Cross-Site Request Forgery.\n"
            "4. Implement cookie prefixes (__Host- and __Secure-) where applicable."
        ),
        "security_headers": (
            "1. Add Content-Security-Policy with strict directives.\n"
            "2. Add Strict-Transport-Security (HSTS) with max-age=31536000; includeSubDomains.\n"
            "3. Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.\n"
            "4. Add X-Content-Type-Options: nosniff to block MIME-type confusion.\n"
            "5. Add Referrer-Policy: strict-origin-when-cross-origin."
        ),
        "cors_misconfiguration": (
            "1. Avoid reflecting the client's Origin header in Access-Control-Allow-Origin.\n"
            "2. Do not combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.\n"
            "3. Implement an explicit whitelist of trusted, authorized domains."
        ),
        "file_upload": (
            "1. Validate uploaded file extensions and MIME types against a strict whitelist.\n"
            "2. Store uploaded files outside the web root directory with non-executable permissions.\n"
            "3. Rename uploaded files to cryptographically generated random UUIDs upon storage.\n"
            "4. Scan all uploaded files with antivirus and content verification engines."
        ),
        "weak_session_ids": (
            "1. Utilize a cryptographically secure pseudo-random number generator (CSPRNG) with at least 128 bits of entropy.\n"
            "2. Regenerate session identifiers upon user login, logout, and privilege elevation.\n"
            "3. Invalidate and purge expired session tokens on the server side."
        ),
    }

    @staticmethod
    def _get_image_base64(path_str: str | None) -> str | None:
        """Convert screenshot image to base64 data URI."""
        if not path_str:
            return None
        try:
            p = Path(path_str)
            if p.exists() and p.is_file():
                b64_data = base64.b64encode(p.read_bytes()).decode("ascii")
                suffix = p.suffix.lower().lstrip(".") or "png"
                return f"data:image/{suffix};base64,{b64_data}"
        except Exception:
            pass
        return None

    @classmethod
    def _build_reproduction_steps(cls, finding: Finding) -> str:
        """Generate formatted step-by-step reproduction guide with curl command."""
        method_str = finding.method.value if hasattr(finding.method, "value") else str(finding.method)
        steps = []
        steps.append(f"1. Target Endpoint: {method_str} {finding.url}")
        if finding.parameter:
            steps.append(f"2. Vulnerable Parameter: '{finding.parameter}'")

        payload_clean = getattr(finding, "payload", None) or getattr(finding, "evidence", "N/A")
        if len(payload_clean) > 80:
            payload_clean = payload_clean[:77] + "..."
        steps.append(f"3. Exploit Payload / Trigger: {payload_clean}")

        # Build copy-paste curl command
        curl_cmd = f"curl -i -k -X {method_str}"
        payload_val = getattr(finding, "payload", None) or "PAYLOAD"
        if method_str.upper() == "POST":
            if finding.parameter:
                curl_cmd += f" --data \"{finding.parameter}={payload_val}\""
            curl_cmd += f' "{finding.url}"'
        else:
            if finding.parameter:
                sep = "&" if "?" in finding.url else "?"
                curl_cmd += f' "{finding.url}{sep}{finding.parameter}={payload_val}"'
            else:
                curl_cmd += f' "{finding.url}"'

        steps.append(f"\n4. Automated Reproduction Command:\n   {curl_cmd}")
        return "\n".join(steps)

    @classmethod
    def _get_remediation(cls, finding: Finding) -> str:
        """Return tailored remediation guidance for finding."""
        if finding.remediation:
            return finding.remediation

        det_key = finding.detector_name.lower().replace("-", "_")
        for k, rem in cls.REMEDIATIONS.items():
            if k in det_key or det_key in k:
                return rem

        # General remediation fallback
        return (
            "1. Implement strict input validation and sanitization for all user-supplied data.\n"
            "2. Enforce output encoding and defense-in-depth security controls.\n"
            "3. Follow the OWASP Application Security Verification Standard (ASVS) guidelines."
        )

    @classmethod
    def generate_html_for_pdf(cls, scan_result: ScanResult) -> str:
        """Generate print-optimized HTML layout specifically designed for PDF rendering."""
        summary = scan_result.summary or {}
        target_url = scan_result.target.url
        start_time_str = scan_result.start_time.strftime("%Y-%m-%d %H:%M:%S UTC")
        duration = f"{scan_result.duration_seconds:.2f}s"

        # Filter strictly for Confirmed True Positives
        confirmed_findings = [f for f in scan_result.findings if not f.is_false_positive]
        total_findings = len(confirmed_findings)

        crit_count = sum(1 for f in confirmed_findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in confirmed_findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in confirmed_findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in confirmed_findings if f.severity == Severity.LOW)
        info_count = sum(1 for f in confirmed_findings if f.severity == Severity.INFO)

        # Risk posture calculations
        if crit_count > 0:
            posture_level = "CRITICAL RISK"
            posture_color = "#dc2626"
            posture_bg = "#fef2f2"
            posture_border = "#fca5a5"
            posture_desc = "Immediate remediation required. High-impact critical vulnerabilities detected in active endpoints."
            posture_bar = "95%"
        elif high_count > 0:
            posture_level = "HIGH RISK"
            posture_color = "#ea580c"
            posture_bg = "#fff7ed"
            posture_border = "#fdba74"
            posture_desc = "Severe vulnerabilities identified that could lead to unauthorized access or severe system compromise."
            posture_bar = "75%"
        elif med_count > 0:
            posture_level = "MEDIUM RISK"
            posture_color = "#d97706"
            posture_bg = "#fffbeb"
            posture_border = "#fde68a"
            posture_desc = "Moderate security weaknesses detected. Remediation recommended in next release cycle."
            posture_bar = "50%"
        elif low_count > 0:
            posture_level = "LOW / INFORMATIONAL"
            posture_color = "#2563eb"
            posture_bg = "#eff6ff"
            posture_border = "#bfdbfe"
            posture_desc = "Minor findings and configuration improvements identified."
            posture_bar = "25%"
        else:
            posture_level = "SECURE POSTURE"
            posture_color = "#16a34a"
            posture_bg = "#f0fdf4"
            posture_border = "#86efac"
            posture_desc = "No confirmed security vulnerabilities detected across all audited endpoints."
            posture_bar = "5%"

        findings_html_blocks = []
        index_rows = []
        for idx, f in enumerate(confirmed_findings, start=1):
            sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            sev_color = cls.SEVERITY_COLORS.get(sev_str, "#2563eb")
            sev_bg = cls.SEVERITY_BG.get(sev_str, "#eff6ff")
            method_str = f.method.value if hasattr(f.method, "value") else str(f.method)

            # Method badge color
            m_upper = method_str.upper()
            if m_upper == "GET":
                m_color = "#0284c7"
                m_bg = "#e0f2fe"
            elif m_upper == "POST":
                m_color = "#16a34a"
                m_bg = "#dcfce7"
            elif m_upper in ("PUT", "PATCH"):
                m_color = "#d97706"
                m_bg = "#fef3c7"
            elif m_upper == "DELETE":
                m_color = "#dc2626"
                m_bg = "#fee2e2"
            else:
                m_color = "#475569"
                m_bg = "#f1f5f9"

            # Index entry
            endpoint_display = f"{method_str} {f.url}"
            if f.parameter:
                endpoint_display += f" ({f.parameter})"
            index_rows.append(f"""
            <tr>
              <td style="text-align: center; font-weight: 700; color: #64748b;">#{idx}</td>
              <td style="text-align: center;">
                <span class="sev-badge" style="background: {sev_bg}; color: {sev_color}; border: 1px solid {sev_color}; font-size: 7pt; padding: 2px 6px;">
                  {sev_str}
                </span>
              </td>
              <td>
                <a href="#finding-{idx}" class="index-link" style="color: #0369a1; font-weight: 700; text-decoration: none;">
                  {html.escape(f.title)}
                </a>
              </td>
              <td style="font-family: monospace; font-size: 8pt; color: #334155;">
                <span style="display: inline-block; padding: 1px 4px; border-radius: 3px; font-size: 7pt; font-weight: 700; background: {m_bg}; color: {m_color}; margin-right: 4px;">{m_upper}</span>{html.escape(f.url[:50])}{'...' if len(f.url) > 50 else ''}{f' <span style="color:#0284c7;">[{html.escape(f.parameter)}]</span>' if f.parameter else ''}
              </td>
              <td style="text-align: center;">
                <a href="#finding-{idx}" class="jump-btn" style="display: inline-block; padding: 2px 8px; background: #e0f2fe; color: #0284c7; border: 1px solid #bae6fd; border-radius: 4px; font-size: 7.5pt; font-weight: 700; text-decoration: none;">
                  Jump &rarr;
                </a>
              </td>
            </tr>
            """)

            repro_guide = cls._build_reproduction_steps(f)
            remediation = cls._get_remediation(f)

            # Screenshots
            screenshot_html = ""
            img_b64 = cls._get_image_base64(f.screenshot_path)
            if img_b64:
                screenshot_html = f"""
                <div class="evidence-card">
                  <div class="section-title">📸 Visual Screenshot Proof of Execution</div>
                  <div class="browser-mockup-frame">
                    <div class="browser-mockup-bar">
                      <span class="dot dot-red"></span>
                      <span class="dot dot-yellow"></span>
                      <span class="dot dot-green"></span>
                      <span class="browser-mockup-url">{html.escape(f.url)}</span>
                    </div>
                    <div class="screenshot-img-box">
                      <img src="{img_b64}" alt="Visual Exploit Evidence" />
                    </div>
                  </div>
                </div>
                """

            findings_html_blocks.append(f"""
            <div id="finding-{idx}" class="finding-page-card">
              <div class="finding-header" style="border-left: 6px solid {sev_color};">
                <div class="finding-title-row">
                  <span class="finding-idx">#{idx}</span>
                  <span class="sev-badge" style="background: {sev_bg}; color: {sev_color}; border: 1px solid {sev_color};">
                    {sev_str}
                  </span>
                  <span class="det-badge">{html.escape(f.detector_name)}</span>
                  <span class="confirmed-badge">✓ Confirmed True Positive</span>
                </div>
                <h2 class="finding-title">{html.escape(f.title)}</h2>
                <div class="finding-target-meta">
                  <span style="display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 8pt; font-weight: 800; background: {m_bg}; color: {m_color}; margin-right: 6px;">{m_upper}</span>
                  <strong>Endpoint:</strong> <code>{html.escape(f.url)}</code>
                  {f' | <strong>Parameter:</strong> <code>{html.escape(f.parameter)}</code>' if f.parameter else ''}
                </div>
              </div>

              <div class="finding-body">
                <div class="section-block">
                  <div class="section-title">📝 Vulnerability Overview & Impact</div>
                  <p>{html.escape(f.description)}</p>
                </div>

                <div class="section-block">
                  <div class="section-title">🔍 Step-by-Step Reproduction Guide</div>
                  <div class="terminal-mockup-frame">
                    <div class="terminal-mockup-bar">
                      <span class="dot dot-red"></span>
                      <span class="dot dot-yellow"></span>
                      <span class="dot dot-green"></span>
                      <span class="terminal-title">bash &mdash; reproduction command</span>
                    </div>
                    <pre class="code-box">{html.escape(repro_guide)}</pre>
                  </div>
                </div>

                <div class="section-block">
                  <div class="section-title">🔬 Technical Proof & Raw Evidence</div>
                  <pre class="code-box">{html.escape(f.evidence or "No raw payload response captured.")}</pre>
                </div>

                {f'''
                <div class="section-block ai-rationale">
                  <div class="section-title">🤖 AI Verification Rationale (Google Gemini)</div>
                  <p>{html.escape(f.ai_validation_reasoning)}</p>
                </div>
                ''' if f.ai_validation_reasoning else ''}

                {screenshot_html}

                <div class="section-block remediation-block">
                  <div class="section-title">🛡️ Remediation & Fix Guidance</div>
                  <pre class="remediation-box">{html.escape(remediation)}</pre>
                </div>
              </div>
            </div>
            """)

        # Vulnerability Index Table
        index_table_html = ""
        if index_rows:
            index_table_html = f"""
            <div class="index-box">
              <div class="summary-title" style="color: #0369a1; margin-bottom: 10px;">📑 Vulnerability Index (Click item to navigate)</div>
              <table class="index-table">
                <thead>
                  <tr>
                    <th style="width: 36px; text-align: center;">#</th>
                    <th style="width: 80px; text-align: center;">Severity</th>
                    <th>Vulnerability Title</th>
                    <th>Affected Endpoint</th>
                    <th style="width: 70px; text-align: center;">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {''.join(index_rows)}
                </tbody>
              </table>
            </div>
            """

        # Authentication & Session Verification Screenshots
        auth_section_html = ""
        if scan_result.auth_screenshots:
            auth_cards = []
            for a_idx, a_path in enumerate(scan_result.auth_screenshots, start=1):
                a_b64 = cls._get_image_base64(a_path)
                if a_b64:
                    fname = Path(a_path).name.replace("_", " ")
                    auth_cards.append(f"""
                    <div class="auth-screenshot-card">
                      <div class="auth-screenshot-title">Step {a_idx}: {html.escape(fname)}</div>
                      <div class="screenshot-img-box">
                        <img src="{a_b64}" alt="Authentication Step {a_idx}" />
                      </div>
                    </div>
                    """)
            if auth_cards:
                auth_section_html = f"""
                <div class="auth-verification-box">
                  <div class="summary-title" style="color: #0369a1;">🔐 Authentication & Session Establishment Verification</div>
                  <p style="font-size: 8.5pt; color: #475569; margin-bottom: 12px;">Visual diagnostic sequence verifying credentials, form submission, and landing on authenticated scope.</p>
                  <div class="auth-grid">
                    {''.join(auth_cards)}
                  </div>
                </div>
                """

        findings_content = "\n".join(findings_html_blocks) if findings_html_blocks else """
        <div class="no-vulns-card">
          <h3>✅ Zero Confirmed Vulnerabilities Detected</h3>
          <p>No confirmed true-positive security vulnerabilities were identified during this assessment.</p>
        </div>
        """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>DAST Security Audit Report</title>
<style>
  @page {{
    size: A4 portrait;
    margin: 14mm 12mm 14mm 12mm;
    @bottom-right {{
      content: "Page " counter(page) " of " counter(pages);
      font-size: 8pt;
      color: #64748b;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }}
    @bottom-left {{
      content: "DAST Security Audit Report";
      font-size: 8pt;
      color: #64748b;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }}
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    color: #0f172a;
    background: #ffffff;
    font-size: 9.5pt;
    line-height: 1.5;
  }}
  
  /* Dedicated Cover Page Container */
  .cover-page {{
    page-break-after: always;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    min-height: 920px;
  }}

  /* Hero Banner with Sleek Tech Gradient */
  .hero-banner {{
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 55%, #0369a1 100%);
    border-radius: 12px;
    padding: 24px 28px;
    color: #ffffff;
    box-shadow: 0 10px 25px -5px rgba(15, 23, 42, 0.2);
    position: relative;
    overflow: hidden;
    margin-bottom: 20px;
    border: 1px solid #334155;
  }}
  .hero-tagline {{
    display: inline-block;
    padding: 3px 10px;
    background: rgba(56, 189, 248, 0.18);
    border: 1px solid #38bdf8;
    color: #38bdf8;
    font-size: 7.5pt;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    border-radius: 20px;
    margin-bottom: 12px;
  }}
  .hero-title-row {{
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  .hero-title {{
    font-size: 22pt;
    font-weight: 800;
    letter-spacing: -0.02em;
    line-height: 1.15;
    color: #ffffff;
  }}
  .hero-sub {{
    font-size: 10pt;
    color: #94a3b8;
    margin-top: 6px;
    font-weight: 500;
  }}
  .hero-badge-verified {{
    background: rgba(16, 185, 129, 0.2);
    border: 1px solid #10b981;
    color: #34d399;
    padding: 6px 12px;
    border-radius: 8px;
    font-size: 8pt;
    font-weight: 700;
    text-align: right;
    white-space: nowrap;
  }}

  /* Target Audit Scope Profile Card */
  .profile-card {{
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    padding: 16px 20px;
    margin-bottom: 20px;
  }}
  .profile-card-header {{
    font-size: 10pt;
    font-weight: 800;
    color: #0369a1;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    gap: 6px;
  }}
  .profile-grid {{
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 12px 20px;
    font-size: 8.5pt;
  }}
  .profile-item {{
    display: flex;
    flex-direction: column;
  }}
  .profile-label {{
    font-size: 7.5pt;
    font-weight: 700;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    margin-bottom: 2px;
  }}
  .profile-val {{
    font-size: 9pt;
    font-weight: 700;
    color: #0f172a;
    word-break: break-all;
  }}

  /* Executive Security Posture Widget */
  .posture-box {{
    background: #ffffff;
    border: 1.5px solid {posture_border};
    border-radius: 10px;
    padding: 16px 20px;
    margin-bottom: 20px;
    background-color: {posture_bg};
  }}
  .posture-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
  }}
  .posture-status {{
    font-size: 13pt;
    font-weight: 900;
    color: {posture_color};
    letter-spacing: -0.01em;
  }}
  .posture-desc {{
    font-size: 8.5pt;
    color: #475569;
    margin-bottom: 10px;
  }}
  .posture-meter-bg {{
    width: 100%;
    height: 8px;
    background: #e2e8f0;
    border-radius: 4px;
    overflow: hidden;
  }}
  .posture-meter-fill {{
    height: 100%;
    width: {posture_bar};
    background: linear-gradient(90deg, #10b981 0%, #f59e0b 50%, #dc2626 100%);
    border-radius: 4px;
  }}

  /* Metric KPI Grid */
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 8px;
    text-align: center;
    margin-bottom: 20px;
  }}
  .kpi-card {{
    background: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    padding: 12px 6px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.02);
  }}
  .kpi-num {{
    font-size: 18pt;
    font-weight: 900;
    line-height: 1;
    font-family: 'Courier New', Courier, monospace;
  }}
  .kpi-label {{
    font-size: 7pt;
    text-transform: uppercase;
    color: #64748b;
    font-weight: 800;
    margin-top: 5px;
    letter-spacing: 0.04em;
  }}

  /* Feature / Methodology Highlights Bento Box */
  .bento-grid {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 10px;
    margin-bottom: 16px;
  }}
  .bento-tile {{
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 12px 14px;
  }}
  .bento-icon-title {{
    font-size: 8.5pt;
    font-weight: 800;
    color: #0f172a;
    margin-bottom: 4px;
    display: flex;
    align-items: center;
    gap: 6px;
  }}
  .bento-desc {{
    font-size: 7.5pt;
    color: #64748b;
    line-height: 1.4;
  }}

  /* Findings Cards & Sections */
  .finding-page-card {{
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    margin-bottom: 24px;
    background: #ffffff;
    page-break-inside: avoid;
    break-inside: avoid;
    overflow: hidden;
  }}
  .finding-header {{
    padding: 14px 16px;
    background: #f8fafc;
    border-bottom: 1px solid #e2e8f0;
  }}
  .finding-title-row {{
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 6px;
  }}
  .finding-idx {{
    font-size: 9pt;
    font-weight: 800;
    color: #475569;
  }}
  .sev-badge {{
    font-size: 8pt;
    font-weight: 800;
    padding: 2px 8px;
    border-radius: 4px;
    text-transform: uppercase;
  }}
  .det-badge {{
    background: #e2e8f0;
    color: #334155;
    font-size: 7.5pt;
    font-weight: 700;
    padding: 2px 6px;
    border-radius: 4px;
    font-family: monospace;
  }}
  .confirmed-badge {{
    background: #dcfce7;
    color: #166534;
    border: 1px solid #86efac;
    font-size: 7.5pt;
    font-weight: 700;
    padding: 2px 6px;
    border-radius: 4px;
  }}
  .finding-title {{
    font-size: 13pt;
    font-weight: 700;
    color: #0f172a;
    margin-bottom: 6px;
  }}
  .finding-target-meta {{
    font-size: 8.5pt;
    color: #475569;
  }}
  .finding-target-meta code {{
    background: #e2e8f0;
    padding: 1px 4px;
    border-radius: 3px;
    font-family: monospace;
    font-size: 8.5pt;
  }}

  .finding-body {{
    padding: 16px;
  }}
  .section-block {{
    margin-bottom: 14px;
  }}
  .section-title {{
    font-size: 9pt;
    font-weight: 700;
    color: #334155;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    margin-bottom: 5px;
  }}

  /* Window / Terminal Mockup Frames */
  .terminal-mockup-frame {{
    border: 1px solid #334155;
    border-radius: 6px;
    overflow: hidden;
    background: #0f172a;
  }}
  .terminal-mockup-bar {{
    background: #1e293b;
    padding: 5px 10px;
    display: flex;
    align-items: center;
    gap: 6px;
    border-bottom: 1px solid #334155;
  }}
  .terminal-title {{
    font-size: 7.5pt;
    color: #94a3b8;
    font-family: monospace;
    margin-left: 6px;
  }}
  .dot {{
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
  }}
  .dot-red {{ background: #ef4444; }}
  .dot-yellow {{ background: #f59e0b; }}
  .dot-green {{ background: #10b981; }}

  .browser-mockup-frame {{
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    overflow: hidden;
    background: #0f172a;
    margin-top: 6px;
  }}
  .browser-mockup-bar {{
    background: #1e293b;
    padding: 6px 10px;
    display: flex;
    align-items: center;
    gap: 6px;
    border-bottom: 1px solid #334155;
  }}
  .browser-mockup-url {{
    background: #0f172a;
    color: #38bdf8;
    padding: 2px 10px;
    border-radius: 4px;
    font-size: 7.5pt;
    font-family: monospace;
    flex-grow: 1;
    margin-left: 6px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }}

  .code-box {{
    background: #0f172a;
    color: #f1f5f9;
    padding: 10px 12px;
    font-family: 'Courier New', Courier, monospace;
    font-size: 8pt;
    white-space: pre-wrap;
    word-break: break-all;
    border: none;
    border-radius: 0 0 6px 6px;
  }}
  .ai-rationale {{
    background: #f0f9ff;
    border: 1px solid #bae6fd;
    border-radius: 6px;
    padding: 10px 12px;
    font-size: 8.5pt;
    color: #0369a1;
  }}
  .remediation-box {{
    background: #f0fdf4;
    border: 1px solid #bbf7d0;
    color: #166534;
    border-radius: 6px;
    padding: 10px 12px;
    font-size: 8.5pt;
    white-space: pre-wrap;
    line-height: 1.45;
  }}
  
  .screenshot-img-box {{
    background: #000000;
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 2px;
  }}
  .screenshot-img-box img {{
    max-width: 100%;
    max-height: 380px;
    display: block;
    object-fit: contain;
  }}

  .auth-verification-box {{
    background: #f0f9ff;
    border: 1px solid #bae6fd;
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 24px;
    page-break-inside: avoid;
    break-inside: avoid;
  }}
  .auth-grid {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 10px;
  }}
  .auth-screenshot-card {{
    background: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: 8px;
  }}
  .auth-screenshot-title {{
    font-size: 7.5pt;
    font-weight: 700;
    color: #0369a1;
    text-transform: uppercase;
    margin-bottom: 4px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }}

  .index-box {{
    background: #f8fafc;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 24px;
    page-break-inside: avoid;
    break-inside: avoid;
  }}
  .summary-title {{
    font-size: 11pt;
    font-weight: 800;
    color: #1e293b;
    margin-bottom: 8px;
  }}
  .index-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 8.5pt;
  }}
  .index-table th {{
    background: #e2e8f0;
    color: #334155;
    padding: 7px 10px;
    font-weight: 700;
    text-transform: uppercase;
    font-size: 7.5pt;
    border: 1px solid #cbd5e1;
    text-align: left;
  }}
  .index-table td {{
    padding: 7px 10px;
    border: 1px solid #e2e8f0;
    background: #ffffff;
    vertical-align: middle;
  }}
  .index-table tr:hover td {{
    background: #f0f9ff;
  }}
  .index-link:hover {{
    text-decoration: underline !important;
    color: #0284c7 !important;
  }}

  .no-vulns-card {{
    text-align: center;
    padding: 40px;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
  }}
  .no-vulns-card h3 {{ color: #166534; font-size: 14pt; margin-bottom: 6px; }}
  .no-vulns-card p {{ color: #64748b; }}
</style>
</head>
<body>

  <!-- ==================== DEDICATED COVER & EXECUTIVE DASHBOARD (PAGE 1) ==================== -->
  <div class="cover-page">
    <div>
      <!-- Creative Hero Brand Header -->
      <div class="hero-banner">
        <div class="hero-tagline">🛡️ DAST Automated Exploit & Penetration Audit</div>
        <div class="hero-title-row">
          <div>
            <h1 class="hero-title">DAST Security Audit Report</h1>
            <p class="hero-sub">Dynamic Application Security Testing & Verified Proof-of-Exploit Assessment</p>
          </div>
          <div class="hero-badge-verified">
            ✓ 100% Confirmed True-Positives<br/>
            <span style="font-size: 7pt; color: #94a3b8; font-weight: normal;">Multimodal AI & Browser Verified</span>
          </div>
        </div>
      </div>

      <!-- Scope & Target Profile Matrix Card -->
      <div class="profile-card">
        <div class="profile-card-header">🌐 Target Assessment Scope & Execution Profile</div>
        <div class="profile-grid">
          <div class="profile-item">
            <span class="profile-label">Target System</span>
            <span class="profile-val">{html.escape(target_url)}</span>
          </div>
          <div class="profile-item">
            <span class="profile-label">Assessment Completed</span>
            <span class="profile-val">{start_time_str}</span>
          </div>
          <div class="profile-item">
            <span class="profile-label">Scan Execution Duration</span>
            <span class="profile-val">{duration}</span>
          </div>
          <div class="profile-item">
            <span class="profile-label">Audited Attack Surface</span>
            <span class="profile-val">{len(scan_result.scanned_endpoints)} Endpoints Profiled</span>
          </div>
        </div>
      </div>

      <!-- Executive Security Posture Widget -->
      <div class="posture-box">
        <div class="posture-header">
          <div>
            <span style="font-size: 8pt; font-weight: 800; color: #64748b; text-transform: uppercase;">Overall Security Posture Rating</span>
            <div class="posture-status">{posture_level}</div>
          </div>
          <div style="text-align: right;">
            <span style="font-size: 16pt; font-weight: 900; color: {posture_color};">{crit_count + high_count}</span>
            <span style="font-size: 8pt; color: #64748b; display: block;">Actionable Threats</span>
          </div>
        </div>
        <div class="posture-desc">{posture_desc}</div>
        <div class="posture-meter-bg">
          <div class="posture-meter-fill"></div>
        </div>
      </div>

      <!-- High-Impact Severity Metrics Breakdown -->
      <div class="kpi-grid">
        <div class="kpi-card" style="border-top: 3px solid #0284c7;">
          <div class="kpi-num" style="color: #0284c7;">{total_findings}</div>
          <div class="kpi-label">Confirmed Vulns</div>
        </div>
        <div class="kpi-card" style="border-top: 3px solid #dc2626;">
          <div class="kpi-num" style="color: #dc2626;">{crit_count}</div>
          <div class="kpi-label">Critical</div>
        </div>
        <div class="kpi-card" style="border-top: 3px solid #ea580c;">
          <div class="kpi-num" style="color: #ea580c;">{high_count}</div>
          <div class="kpi-label">High</div>
        </div>
        <div class="kpi-card" style="border-top: 3px solid #d97706;">
          <div class="kpi-num" style="color: #d97706;">{med_count}</div>
          <div class="kpi-label">Medium</div>
        </div>
        <div class="kpi-card" style="border-top: 3px solid #2563eb;">
          <div class="kpi-num" style="color: #2563eb;">{low_count}</div>
          <div class="kpi-label">Low / Info</div>
        </div>
        <div class="kpi-card" style="border-top: 3px solid #64748b;">
          <div class="kpi-num" style="color: #64748b;">{len(scan_result.scanned_endpoints)}</div>
          <div class="kpi-label">Endpoints</div>
        </div>
      </div>

      <!-- Feature & Methodology Highlights Bento Box -->
      <div class="bento-grid">
        <div class="bento-tile">
          <div class="bento-icon-title">⚡ Automated Exploit Proofs</div>
          <div class="bento-desc">Every finding includes copy-ready curl commands and execution steps verified against active runtime responses.</div>
        </div>
        <div class="bento-tile">
          <div class="bento-icon-title">📸 Visual & DOM Evidence</div>
          <div class="bento-desc">Screenshots and live browser dialog alerts captured in headless Chromium for definitive audit proof.</div>
        </div>
        <div class="bento-tile">
          <div class="bento-icon-title">🛡️ Hardening Guidance</div>
          <div class="bento-desc">Clear, actionable remediation code patterns and best practices tailored to eliminate each attack vector.</div>
        </div>
      </div>
    </div>
  </div>

  <!-- ==================== SUBSEQUENT PAGES: INDEX & TECHNICAL FINDINGS ==================== -->

  <!-- Interactive Vulnerability Index / Table of Contents -->
  {index_table_html}

  <!-- Authentication & Session Establishment Sequence -->
  {auth_section_html}

  <!-- Detailed Confirmed True Positive Findings -->
  <div class="findings-container">
    {findings_content}
  </div>

</body>
</html>
"""

    @classmethod
    def generate_pdf_bytes(cls, scan_result: ScanResult) -> bytes:
        """Render ScanResult to high-resolution PDF binary bytes via Playwright or ReportLab fallback."""
        html_content = cls.generate_html_for_pdf(scan_result)

        # Primary: Playwright headless Chromium PDF generation
        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.set_content(html_content, wait_until="load")
                page.wait_for_timeout(300)
                pdf_bytes = page.pdf(
                    format="A4",
                    print_background=True,
                    margin={"top": "12mm", "bottom": "12mm", "left": "10mm", "right": "10mm"},
                )
                browser.close()
                return pdf_bytes
        except Exception as pw_exc:
            logger.warning("[PDF] Playwright PDF generation notice: %s. Using ReportLab fallback...", pw_exc)

        # Fallback: ReportLab PDF generator
        return cls._generate_reportlab_pdf(scan_result)

    @classmethod
    def _generate_reportlab_pdf(cls, scan_result: ScanResult) -> bytes:
        """ReportLab fallback PDF generation engine."""
        import io
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
        from reportlab.lib import colors

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        story = []

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Title"],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0369a1"),
            alignment=0,
        )
        h2_style = ParagraphStyle(
            "H2",
            parent=styles["Heading2"],
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=10,
            spaceAfter=6,
        )
        body_style = ParagraphStyle("Body", parent=styles["BodyText"], fontSize=8.5, leading=12)
        code_style = ParagraphStyle(
            "Code",
            parent=styles["Code"],
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#f8fafc"),
            backColor=colors.HexColor("#0f172a"),
        )

        story.append(Paragraph("DAST Security Audit Report", title_style))
        story.append(Paragraph(f"Target URL: {html.escape(scan_result.target.url)}", body_style))
        story.append(Paragraph(f"Scan Completed: {scan_result.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}", body_style))
        story.append(Spacer(1, 14))

        confirmed = [f for f in scan_result.findings if not f.is_false_positive]
        story.append(Paragraph(f"Confirmed Vulnerabilities ({len(confirmed)} findings)", h2_style))
        story.append(Spacer(1, 8))

        if confirmed:
            story.append(Paragraph("<b>Table of Contents / Findings Index:</b>", h2_style))
            for idx, f in enumerate(confirmed, 1):
                sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                story.append(Paragraph(f'<a href="#finding_{idx}" color="#0369a1"><b>#{idx} [{sev_str}] {html.escape(f.title)}</b> - {html.escape(f.url)}</a>', body_style))
            story.append(Spacer(1, 12))

        for idx, f in enumerate(confirmed, 1):
            sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            method_str = f.method.value if hasattr(f.method, "value") else str(f.method)
            story.append(Paragraph(f'<a name="finding_{idx}"/><b>#{idx} [{sev_str}] {html.escape(f.title)}</b>', h2_style))
            story.append(Paragraph(f"<b>Endpoint:</b> {html.escape(method_str)} {html.escape(f.url)} (Param: {html.escape(f.parameter or 'N/A')})", body_style))
            story.append(Paragraph(f"<b>Description:</b> {html.escape(f.description)}", body_style))
            story.append(Spacer(1, 4))
            story.append(Paragraph("<b>Reproduction & Exploit:</b>", body_style))
            story.append(Paragraph(html.escape(cls._build_reproduction_steps(f)), code_style))
            story.append(Spacer(1, 4))
            story.append(Paragraph("<b>Remediation Guidance:</b>", body_style))
            story.append(Paragraph(html.escape(cls._get_remediation(f)), body_style))
            story.append(Spacer(1, 14))

        doc.build(story)
        return buffer.getvalue()

    @classmethod
    def save(cls, scan_result: ScanResult, destination_path: str = "dast-report.pdf") -> Path:
        """Render and save PDF security report to disk."""
        pdf_bytes = cls.generate_pdf_bytes(scan_result)
        out_path = Path(destination_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(pdf_bytes)
        logger.info("PDF security audit report saved to: %s (%d bytes)", out_path.resolve(), len(pdf_bytes))
        return out_path
