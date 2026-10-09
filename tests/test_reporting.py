"""Tests for JSON reporting subsystem."""

import json
from pathlib import Path

from dast.models import Endpoint, Finding, HttpMethod, ScanResult, Severity, Target
from dast.reporting.json_report import JSONReporter


def test_json_reporting(tmp_path: Path):
    target = Target(url="http://target.local")
    endpoint = Endpoint(url="http://target.local/api", method=HttpMethod.GET)
    finding = Finding(
        title="Sample Finding",
        severity=Severity.MEDIUM,
        confidence="HIGH",  # type: ignore
        url="http://target.local/api",
        method="GET",
        evidence="Found issue",
        description="Description",
        remediation="Fix it",
        detector_name="mock_detector",
    )

    result = ScanResult(
        target=target,
        scanned_endpoints=[endpoint],
        findings=[finding],
        active_detectors=["mock_detector"],
    )
    result.finalize()

    # 1. Test generate JSON string
    json_str = JSONReporter.generate(result)
    parsed = json.loads(json_str)
    assert parsed["target"]["url"] == "http://target.local"
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["title"] == "Sample Finding"
    assert parsed["summary"]["total_findings"] == 1

    # 2. Test save to file
    out_file = tmp_path / "subdir" / "audit-report.json"
    saved_path = JSONReporter.save(result, out_file)
    assert saved_path.exists()

    file_data = json.loads(saved_path.read_text(encoding="utf-8"))
    assert file_data["summary"]["total_endpoints"] == 1


def test_html_reporting(tmp_path: Path):
    from dast.reporting.html_report import HTMLReporter

    target = Target(url="http://target.local")
    endpoint = Endpoint(url="http://target.local/api", method=HttpMethod.GET)
    finding = Finding(
        title="SQL Injection Vulnerability",
        severity=Severity.HIGH,
        confidence="CERTAIN",  # type: ignore
        url="http://target.local/api",
        method="GET",
        evidence="Root syntax error leaked",
        terminal_output="| 1 | token1 |\n| 2 | token2 |",
        captured_dialog="alert(1)",
        screenshot_path="evidence/screenshots/finding_1.png",
        step_screenshots=["evidence/step1.png", "evidence/step2.png"],
        description="Raw SQL query concatenation",
        remediation="Use parameterized queries",
        detector_name="sqli",
    )

    result = ScanResult(
        target=target,
        scanned_endpoints=[endpoint],
        findings=[finding],
        active_detectors=["sqli"],
    )
    result.finalize()
    result.summary["detector_timings"] = {"sqli": 1.25, "reflected_xss": 0.50}

    # 1. Test generate HTML string
    html_content = HTMLReporter.generate(result)
    assert "<!DOCTYPE html>" in html_content
    assert "DAST Security Audit Report" in html_content
    assert "SQL Injection Vulnerability" in html_content
    assert "HIGH" in html_content
    assert "token1" in html_content
    assert "alert(1)" in html_content
    assert "Visual Screenshot Evidence" in html_content
    assert "finding_1.png" in html_content
    assert "Diagnostic Steps (2 captured)" in html_content
    assert "Detector Execution Times" in html_content
    assert "1.25s" in html_content

    # 2. Test save HTML file
    out_file = tmp_path / "report.html"
    saved_path = HTMLReporter.save(result, out_file)
    assert saved_path.exists()
    assert "SQL Injection Vulnerability" in saved_path.read_text(encoding="utf-8")


def test_markdown_reporting(tmp_path: Path):
    from dast.reporting.markdown_report import MarkdownReporter

    target = Target(url="http://target.local")
    endpoint = Endpoint(url="http://target.local/login", method=HttpMethod.POST)
    finding = Finding(
        title="Predictable Session ID",
        severity=Severity.CRITICAL,
        confidence="HIGH",  # type: ignore
        url="http://target.local/login",
        method="POST",
        evidence="Sequential integer counter",
        terminal_output="[+] Tokens: 101, 102, 103",
        captured_dialog="confirm(1)",
        screenshot_path="evidence/screenshots/weak_sess.png",
        step_screenshots=["evidence/s1.png", "evidence/s2.png"],
        description="Session tokens are predictable",
        remediation="Use CSPRNG",
        detector_name="weak_session_ids",
    )

    result = ScanResult(
        target=target,
        scanned_endpoints=[endpoint],
        findings=[finding],
        active_detectors=["weak_session_ids"],
    )
    result.finalize()
    result.summary["detector_timings"] = {"weak_session_ids": 0.85, "csrf": 0.12}

    # 1. Test generate Markdown string
    md_content = MarkdownReporter.generate(result)
    assert "# DAST Security Assessment Report" in md_content
    assert "CRITICAL" in md_content
    assert "Predictable Session ID" in md_content
    assert "weak_session_ids" in md_content
    assert "confirm(1)" in md_content
    assert "Terminal / Diagnostic Output" in md_content
    assert "[+] Tokens: 101, 102, 103" in md_content
    assert "Visual Screenshot Evidence" in md_content
    assert "![Screenshot Evidence](evidence/screenshots/weak_sess.png)" in md_content
    assert "Diagnostic Step Screenshots (2 captured)" in md_content
    assert "## Detector Execution Times" in md_content
    assert "`weak_session_ids` | 0.85s" in md_content

    # 2. Test save Markdown file
    out_file = tmp_path / "report.md"
    saved_path = MarkdownReporter.save(result, out_file)
    assert saved_path.exists()
    assert "Predictable Session ID" in saved_path.read_text(encoding="utf-8")


def test_pdf_reporting(tmp_path: Path):
    from dast.reporting.pdf_report import PDFReporter

    target = Target(url="http://target.local")
    endpoint = Endpoint(url="http://target.local/vulnerabilities/fi/", method=HttpMethod.GET)
    finding = Finding(
        title="File Inclusion Vulnerability",
        severity=Severity.HIGH,
        confidence="CERTAIN",  # type: ignore
        url="http://target.local/vulnerabilities/fi/",
        method="GET",
        parameter="page",
        payload="../../etc/passwd",
        evidence="root:x:0:0:root:/root:/bin/bash",
        screenshot_path="evidence/screenshots/fi.png",
        description="Local File Inclusion allows reading sensitive configuration and system files.",
        remediation="Restrict included files to a strict whitelist and disable allow_url_include.",
        detector_name="file_inclusion",
        is_false_positive=False,
    )

    result = ScanResult(
        target=target,
        scanned_endpoints=[endpoint],
        findings=[finding],
        active_detectors=["file_inclusion"],
    )
    result.finalize()

    # 1. Test generate HTML layout for PDF
    pdf_html = PDFReporter.generate_html_for_pdf(result)
    assert "DAST Security Audit Report" in pdf_html
    assert "CONFIDENTIAL" not in pdf_html
    assert "&bull;" not in pdf_html
    assert "Vulnerability Index" in pdf_html
    assert "#finding-1" in pdf_html
    assert "File Inclusion Vulnerability" in pdf_html
    assert "HIGH" in pdf_html
    assert "Step-by-Step Reproduction Guide" in pdf_html
    assert "curl -i -k -X GET" in pdf_html
    assert "Remediation & Fix Guidance" in pdf_html
    assert "root:x:0:0:root" in pdf_html

    # 2. Test PDF binary generation and saving
    out_pdf = tmp_path / "report.pdf"
    saved_path = PDFReporter.save(result, str(out_pdf))
    assert saved_path.exists()
    assert saved_path.stat().st_size > 500
    # PDF magic header check: %PDF-
    header = saved_path.read_bytes()[:5]
    assert header == b"%PDF-"

