"""Command-line interface for the DAST security framework."""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Sequence

from dast.detectors.registry import default_registry
from dast.models import Target
from dast.reporting import HTMLReporter, JSONReporter, MarkdownReporter, PDFReporter
from dast.scanner import Scanner


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument specification."""
    parser = argparse.ArgumentParser(
        prog="dast",
        description="Modular Dynamic Application Security Testing (DAST) Framework for Authorized Audits.",
    )

    parser.add_argument(
        "url",
        nargs="?",
        help="Target base URL to audit (e.g., http://localhost:8000 or https://authorized-site.com)",
    )
    parser.add_argument(
        "--url",
        dest="flag_url",
        help="Alternative flag to specify target URL",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="dast-report.json",
        help="Output destination path for JSON report (default: dast-report.json)",
    )
    parser.add_argument(
        "--html",
        dest="html_output",
        default="dast-report.html",
        help="Output destination path for interactive HTML report (default: dast-report.html)",
    )
    parser.add_argument(
        "--pdf",
        dest="pdf_output",
        default="dast-report.pdf",
        help="Output destination path for executive PDF report (default: dast-report.pdf)",
    )
    parser.add_argument(
        "--markdown",
        dest="md_output",
        help="Optional output destination path for Markdown report (e.g. dast-report.md)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=2,
        help="Maximum crawl recursion depth (default: 2)",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=20,
        help="Maximum pages to crawl and analyze (default: 20)",
    )
    parser.add_argument(
        "-d",
        "--detectors",
        default="all",
        help="Comma-separated list of detectors to run, or 'all' (default: all)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Rate-limiting delay in seconds between HTTP requests (default: 0.0)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP request timeout in seconds (default: 10.0)",
    )
    parser.add_argument(
        "-u",
        "--auth",
        "--user",
        dest="auth",
        help="Target credentials in 'username:password' format for HTTP Basic / session auth",
    )
    parser.add_argument(
        "--login-url",
        dest="login_url",
        help="Optional form login URL for automated session authentication",
    )
    parser.add_argument(
        "--after-auth-url",
        "--landing-url",
        dest="after_auth_url",
        help="Optional authenticated landing page URL (e.g. /portal.php or /index.php) to verify login",
    )
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        dest="headers",
        default=[],
        help="Custom header in 'Key: Value' format (can be specified multiple times)",
    )
    parser.add_argument(
        "--allowed-hosts",
        help="Additional comma-separated list of hostnames allowed in scan scope",
    )
    parser.add_argument(
        "--list-detectors",
        action="store_true",
        help="List all registered vulnerability detector plugins and exit",
    )
    parser.add_argument(
        "-c",
        "--category",
        help="Filter detectors by vulnerability taxonomy category (injection, xss, cookie_based, broken_auth, file_handling, misconfiguration)",
    )
    parser.add_argument(
        "--requirement",
        help="Filter detectors by runtime requirement (requests, browser, mechanicalsoup)",
    )
    parser.add_argument(
        "--browser",
        action="store_true",
        help="Enable Playwright headless browser for step-by-step screenshots and visual evidence capture",
    )
    parser.add_argument(
        "--browser-dir",
        default="evidence/screenshots",
        help="Directory to save browser screenshots (default: evidence/screenshots)",
    )
    parser.add_argument(
        "--gemini-api-key",
        help="Google Gemini API key for automated false-positive validation",
    )
    parser.add_argument(
        "--gemini-model",
        default="gemini-3.1-flash-lite",
        help="Google Gemini model identifier (default: gemini-3.1-flash-lite)",
    )
    parser.add_argument(
        "--no-ai-validation",
        action="store_true",
        help="Disable Gemini AI false-positive finding validation",
    )
    parser.add_argument(
        "--kafka-bootstrap-servers",
        default="localhost:9092",
        help="Kafka bootstrap server(s) address (default: localhost:9092)",
    )
    parser.add_argument(
        "--kafka-topic",
        default="dast-discovered-urls",
        help="Kafka topic for streaming discovered endpoints (default: dast-discovered-urls)",
    )
    parser.add_argument(
        "--no-kafka",
        action="store_true",
        help="Disable external Kafka broker and use local in-memory streaming queue",
    )
    parser.add_argument(
        "-w",
        "--max-workers",
        dest="max_workers",
        type=int,
        default=5,
        help="Number of concurrent worker threads for parallel detector scanning (default: 5)",
    )
    parser.add_argument(
        "-g",
        "--gui",
        action="store_true",
        help="Launch interactive Web GUI dashboard and REST API control server",
    )
    parser.add_argument(
        "--gui-port",
        type=int,
        default=5000,
        help="Port to bind the Web GUI server (default: 5000)",
    )
    parser.add_argument(
        "--gui-host",
        default="127.0.0.1",
        help="Host address to bind the Web GUI server (default: 127.0.0.1)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose diagnostic debug logging",
    )

    return parser


def parse_headers(header_args: list[str]) -> dict[str, str]:
    """Parse list of 'Key: Value' header strings into dictionary."""
    headers: dict[str, str] = {}
    for h in header_args:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # Silence verbose third-party HTTP transport logs unless explicitly requested
    if not args.verbose:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)

    # If GUI mode requested, launch web dashboard
    if getattr(args, "gui", False):
        from dast.gui.app import launch_gui
        launch_gui(host=args.gui_host, port=args.gui_port)
        return 0

    # Ensure builtin detectors are discovered
    default_registry.discover_builtin()

    if args.list_detectors:
        from dast.config import is_detector_active
        print("=" * 80)
        print("  Available Detector Plugins (Categorized by Vulnerability Taxonomy)")
        print("=" * 80)
        by_category = default_registry.list_by_category()
        for cat_name, detector_names in by_category.items():
            print(f"\n[Category: {cat_name.upper()}]")
            for name in detector_names:
                cls = default_registry.get_class(name)
                ev_type = getattr(cls, "default_evidence_type", "")
                ev_str = ev_type.value if hasattr(ev_type, "value") else str(ev_type)
                desc = cls.description if cls else ""
                status_str = "ACTIVE" if is_detector_active(name) else "INACTIVE"
                print(f"  - {name:<18} [{status_str:<8}] [Evidence: {ev_str:<15}] : {desc}")
        return 0

    target_url = args.url or args.flag_url
    if not target_url:
        parser.error("A target URL must be provided (e.g. 'dast http://localhost:8000').")

    # Scope configuration
    allowed = []
    if args.allowed_hosts:
        allowed = [h.strip() for h in args.allowed_hosts.split(",") if h.strip()]

    custom_headers = parse_headers(args.headers)

    auth_tuple: tuple[str, str] | None = None
    if args.auth:
        if ":" in args.auth:
            u, p = args.auth.split(":", 1)
            auth_tuple = (u.strip(), p.strip())
        else:
            auth_tuple = (args.auth.strip(), "")

    try:
        target = Target(
            url=target_url,
            allowed_hosts=allowed,
            max_depth=args.max_depth,
            max_pages=args.max_pages,
            custom_headers=custom_headers,
            auth=auth_tuple,
            login_url=args.login_url,
            after_auth_url=args.after_auth_url,
        )
    except Exception as exc:
        print(f"[!] Invalid target specification: {exc}", file=sys.stderr)
        return 1

    selected_detectors = None
    if args.detectors and args.detectors.lower() != "all":
        selected_detectors = [d.strip() for d in args.detectors.split(",") if d.strip()]

    selected_categories = None
    if args.category:
        selected_categories = [c.strip().lower() for c in args.category.split(",") if c.strip()]

    print("=" * 60)
    print(f"  DAST Security Scanner")
    print(f"  Target:     {target.url}")
    print(f"  Scope:      {target.allowed_hosts or target.get_primary_host()}")
    if target.auth:
        print(f"  Auth:       {target.auth[0]}:****")
    if target.login_url:
        print(f"  Login URL:  {target.login_url}")
    print(f"  Max Depth:  {target.max_depth} | Max Pages: {target.max_pages}")
    print(f"  Detectors:  {args.detectors}")
    if selected_categories:
        print(f"  Categories: {', '.join(selected_categories)}")
    print("=" * 60)

    selected_requirements = None
    if args.requirement:
        selected_requirements = [r.strip().lower() for r in args.requirement.split(",") if r.strip()]

    scanner = Scanner(
        target=target,
        registry=default_registry,
        selected_detectors=selected_detectors,
        categories=selected_categories,
        requirements=selected_requirements,
        timeout=args.timeout,
        delay=args.delay,
        enable_browser=args.browser,
        browser_dir=args.browser_dir,
        enable_ai_validation=not args.no_ai_validation,
        gemini_api_key=args.gemini_api_key,
        gemini_model=args.gemini_model,
        use_kafka=not args.no_kafka,
        kafka_bootstrap_servers=args.kafka_bootstrap_servers,
        kafka_topic=args.kafka_topic,
        max_workers=args.max_workers,
    )

    result = scanner.run()

    # 1. Save JSON Machine-Readable Report
    report_path = JSONReporter.save(result, args.output)

    # 2. Save Interactive HTML Report
    html_path = None
    if args.html_output:
        html_path = HTMLReporter.save(result, args.html_output)

    # 3. Save Markdown Report if requested
    md_path = None
    if args.md_output:
        md_path = MarkdownReporter.save(result, args.md_output)

    # 4. Save Executive PDF Report
    pdf_path = None
    if getattr(args, "pdf_output", None):
        try:
            pdf_path = PDFReporter.save(result, args.pdf_output)
        except Exception as pdf_err:
            logger.warning("Notice generating PDF report: %s", pdf_err)

    # 5. Print Rich Terminal Assessment Summary
    print("\n" + "=" * 80)
    print("  DAST Assessment Summary")
    print("=" * 80)
    print(f"  Target URL         : {result.target.url}")
    print(f"  Endpoints Analyzed : {len(result.scanned_endpoints)}")
    print(f"  Total Findings     : {len(result.findings)}")
    if "confirmed_findings" in result.summary:
        print(f"  Confirmed (AI)     : {result.summary.get('confirmed_findings', 0)}")
        print(f"  False Positives    : {result.summary.get('false_positives', 0)}")
    print(f"  Duration           : {result.duration_seconds:.2f}s")
    print("\n  Severity Breakdown :")
    for sev, count in result.summary.get("severity_breakdown", {}).items():
        if count > 0:
            print(f"    - {sev:<12}: {count}")

    if result.findings:
        print("\n  Identified Vulnerabilities:")
        print(f"  {'#':<3} {'Severity':<10} {'Detector':<18} {'AI Status':<16} {'Finding Title'}")
        print("  " + "-" * 88)
        for idx, f in enumerate(result.findings, start=1):
            sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            ai_tag = "[FP]" if f.is_false_positive else ("[CONFIRMED]" if f.ai_validation_status else "[UNCHECKED]")
            print(f"  {idx:<3} {sev_str:<10} {f.detector_name:<18} {ai_tag:<16} {f.title}")

    det_timings = result.summary.get("detector_timings", {})
    if det_timings:
        print("\n  Detector Execution Times:")
        print(f"  {'Detector Plugin':<28} {'Duration':<10}")
        print("  " + "-" * 40)
        for det_name, det_secs in sorted(det_timings.items(), key=lambda x: x[1], reverse=True):
            print(f"  {det_name:<28} {det_secs:.2f}s")

    print("\n" + "=" * 80)
    print("  Generated Reports")
    print("=" * 80)
    print(f"  [+] Machine-Readable JSON : {report_path.resolve()}")
    if html_path:
        print(f"  [+] Interactive HTML      : {html_path.resolve()}")
    if pdf_path:
        print(f"  [+] Executive PDF Report  : {pdf_path.resolve()}")
    if md_path:
        print(f"  [+] GitHub Markdown       : {md_path.resolve()}")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(main())
