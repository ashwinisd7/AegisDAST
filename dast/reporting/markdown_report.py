"""Markdown Reporting module for human-readable assessment summaries."""

from __future__ import annotations

from pathlib import Path

from dast.models import Finding, ScanResult, Severity


class MarkdownReporter:
    """Generates clean GitHub-flavored Markdown assessment reports."""

    @classmethod
    def generate(cls, scan_result: ScanResult) -> str:
        """Render ScanResult into structured Markdown format."""
        summary = scan_result.summary or {}
        sev_counts = summary.get("severity_breakdown", {})
        total_findings = len(scan_result.findings)
        total_endpoints = len(scan_result.scanned_endpoints)
        duration = f"{scan_result.duration_seconds:.2f}s"
        target_url = scan_result.target.url
        start_time_str = scan_result.start_time.strftime("%Y-%m-%d %H:%M:%S UTC")

        confirmed_findings = [f for f in scan_result.findings if not f.is_false_positive]
        false_positive_findings = [f for f in scan_result.findings if f.is_false_positive]
        confirmed_count = len(confirmed_findings)
        fp_count = len(false_positive_findings)

        lines = [
            f"# DAST Security Assessment Report",
            f"",
            f"**Target URL:** `{target_url}`  ",
            f"**Scan Timestamp:** {start_time_str}  ",
            f"**Audit Duration:** {duration}  ",
            f"**Total Crawled Endpoints:** {total_endpoints}  ",
            f"**Total Findings:** {total_findings} (Confirmed: {confirmed_count}, False Positives: {fp_count})  ",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            f"| Metric / Severity | Count |",
            f"| :--- | :---: |",
            f"| **Confirmed Findings (AI)** | **{confirmed_count}** |",
            f"| **False Positives (AI)** | **{fp_count}** |",
            f"| **CRITICAL** | {sev_counts.get('CRITICAL', 0)} |",
            f"| **HIGH** | {sev_counts.get('HIGH', 0)} |",
            f"| **MEDIUM** | {sev_counts.get('MEDIUM', 0)} |",
            f"| **LOW** | {sev_counts.get('LOW', 0)} |",
            f"| **INFO** | {sev_counts.get('INFO', 0)} |",
            f"| **TOTAL** | **{total_findings}** |",
            f"",
            f"---",
            f"",
            f"## Confirmed Vulnerability Findings ({len(confirmed_findings)})",
            f"",
        ]

        if not confirmed_findings:
            lines.append("No confirmed security vulnerabilities identified matching the active test profiles.")
            lines.append("")
        else:
            for idx, f in enumerate(confirmed_findings, start=1):
                sev_val = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
                ev_type = f.evidence_type.value if hasattr(f.evidence_type, "value") else str(f.evidence_type)
                param_info = f" `[{f.parameter}]`" if f.parameter else ""

                ai_status_line = ""
                if f.ai_validation_status:
                    tag = "FALSE POSITIVE (⚠️ Disputed)" if f.is_false_positive else "CONFIRMED VULNERABILITY (✓ Verified)"
                    conf_str = f" ({f.ai_confidence_score * 100:.0f}% confidence)" if f.ai_confidence_score is not None else ""
                    ai_status_line = f"* **AI Validation (Gemini):** `{tag}`{conf_str}\n"

                lines.extend([
                    f"### {idx}. [{sev_val}] {f.title}",
                    f"",
                    f"* **Detector Plugin:** `{f.detector_name}`",
                    f"* **Evidence Type:** `{ev_type}`",
                    f"* **Affected URL:** `{f.method} {f.url}`{param_info}",
                ])
                if ai_status_line:
                    lines.append(ai_status_line)
                lines.extend([
                    f"",
                    f"#### Description",
                    f"{f.description}",
                    f"",
                ])

                if f.ai_validation_reasoning:
                    lines.extend([
                        f"#### AI Technical Rationale (Google Gemini)",
                        f"> {f.ai_validation_reasoning}",
                        f"",
                    ])

                if getattr(f, "captured_dialog", None):
                    lines.extend([
                        f"#### Intercepted JavaScript Dialog",
                        f"```javascript",
                        f"{f.captured_dialog}",
                        f"```",
                        f"",
                    ])

                if f.terminal_output:
                    lines.extend([
                        f"#### Terminal / Diagnostic Output",
                        f"```text",
                        f.terminal_output,
                        f"```",
                        f"",
                    ])

                if f.evidence:
                    lines.extend([
                        f"#### Technical Evidence",
                        f"```text",
                        f.evidence,
                        f"```",
                        f"",
                    ])

                if f.screenshot_path:
                    lines.extend([
                        f"#### Visual Screenshot Evidence",
                        f"![Screenshot Evidence]({f.screenshot_path})",
                        f"*File Path: `{f.screenshot_path}`*",
                        f"",
                    ])

                if f.step_screenshots and len(f.step_screenshots) > 1:
                    lines.extend([
                        f"#### Diagnostic Step Screenshots ({len(f.step_screenshots)} captured)",
                    ])
                    for s_idx, s_path in enumerate(f.step_screenshots, start=1):
                        lines.append(f"- Step {s_idx}: `{s_path}`")
                    lines.append("")

                if f.request_metadata:
                    req_hdrs = "\n".join(f"{k}: {v}" for k, v in f.request_metadata.headers.items())
                    lines.extend([
                        f"#### HTTP Request Evidence",
                        f"```http",
                        f"{f.request_metadata.method} {f.request_metadata.url}",
                        req_hdrs,
                        f"",
                        f.request_metadata.body or "",
                        f"```",
                        f"",
                    ])

                if f.response_metadata:
                    res_hdrs = "\n".join(f"{k}: {v}" for k, v in f.response_metadata.headers.items())
                    lines.extend([
                        f"#### HTTP Response Evidence",
                        f"```http",
                        f"HTTP/1.1 {f.response_metadata.status_code} ({f.response_metadata.latency_ms:.1f}ms)",
                        res_hdrs,
                        f"",
                        f.response_metadata.body_preview or "",
                        f"```",
                        f"",
                    ])

                lines.extend([
                    f"#### Remediation",
                    f"> {f.remediation}",
                    f"",
                    f"---",
                    f"",
                ])

        if false_positive_findings:
            lines.extend([
                f"## Filtered False Positives ({len(false_positive_findings)})",
                f"",
                f"> The following candidate alerts were evaluated and determined to be **False Positives**.",
                f"",
            ])
            for idx, f in enumerate(false_positive_findings, start=1):
                sev_val = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
                param_info = f" `[{f.parameter}]`" if f.parameter else ""
                conf_str = f" ({f.ai_confidence_score * 100:.0f}% confidence)" if f.ai_confidence_score is not None else ""
                lines.extend([
                    f"### FP-{idx}. [{sev_val}] {f.title}",
                    f"* **Detector Plugin:** `{f.detector_name}`",
                    f"* **Affected URL:** `{f.method} {f.url}`{param_info}",
                    f"* **AI Assessment:** `FALSE POSITIVE`{conf_str}",
                    f"* **Reasoning:** {f.ai_validation_reasoning or f.description}",
                    f"",
                    f"---",
                    f"",
                ])

        lines.extend([
            f"## Scanned Endpoints ({total_endpoints})",
            f"",
            f"| Method | URL Path | Parameters |",
            f"| :---: | :--- | :--- |",
        ])

        for ep in scan_result.scanned_endpoints:
            params_str = ", ".join(f"`{p}`" for p in ep.get_all_param_names()) or "*None*"
            lines.append(f"| `{ep.method.value}` | `{ep.url}` | {params_str} |")

        lines.append("")

        detector_timings = summary.get("detector_timings", {})
        if detector_timings:
            lines.extend([
                f"## Detector Execution Times",
                f"",
                f"| Detector | Execution Time |",
                f"| :--- | :---: |",
            ])
            for det_name, det_secs in sorted(detector_timings.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"| `{det_name}` | {det_secs:.2f}s |")
            lines.append("")

        return "\n".join(lines)

    @classmethod
    def save(cls, scan_result: ScanResult, file_path: str | Path) -> Path:
        """Write Markdown report directly to filesystem."""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = cls.generate(scan_result)
        path.write_text(content, encoding="utf-8")
        return path

