"""Standalone Debugger for DAST Detectors.

Enables targeted testing of a specific vulnerability detector against a specific
endpoint URL, with verbose diagnostic logging, request/response tracking,
and visual evidence verification.

Usage Examples:
    # Debug Reflected XSS on DVWA
    python debug_detector.py https://pentest-ground.com:4280/vulnerabilities/xss_r/ -d xss -p name=test -H "Cookie: PHPSESSID=...; security=low"

    # Debug SQL Injection on a GET endpoint
    python debug_detector.py https://pentest-ground.com:4280/vulnerabilities/sqli/ -d sqli -p id=1 -H "Cookie: PHPSESSID=...; security=low"

    # Debug Command Injection on a POST endpoint
    python debug_detector.py https://pentest-ground.com:4280/vulnerabilities/exec/ -d command_injection -m POST -b ip=127.0.0.1 -H "Cookie: PHPSESSID=...; security=low"

    # List all available detector names
    python debug_detector.py --list
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
import sys
import time
from urllib.parse import parse_qs, urlparse, urlunparse

from dast.browser import BrowserManager
from dast.detectors.registry import default_registry
from dast.http_client import HTTPClient
from dast.models import DetectorRequirement, Endpoint, EvidenceType, HttpMethod


def setup_logger(verbose: bool) -> logging.Logger:
    """Configure detailed console logging format."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    # Silence third-party noise unless in debug mode
    if not verbose:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        logging.getLogger("playwright").setLevel(logging.WARNING)
    return logging.getLogger("dast.debugger")


def parse_key_value(items: list[str] | None) -> dict[str, str]:
    """Parse a list of 'key=val' strings into a dictionary."""
    result: dict[str, str] = {}
    if not items:
        return result
    for item in items:
        if "=" in item:
            k, v = item.split("=", 1)
            result[k.strip()] = v.strip()
        else:
            result[item.strip()] = ""
    return result


def parse_headers(items: list[str] | None) -> dict[str, str]:
    """Parse a list of 'Header: Value' strings into a dictionary."""
    result: dict[str, str] = {}
    if not items:
        return result
    for item in items:
        if ":" in item:
            k, v = item.split(":", 1)
            result[k.strip()] = v.strip()
    return result


def build_parser() -> argparse.ArgumentParser:
    """Configure CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="debug_detector",
        description="DAST Specific Detector Debugger - Test a single detector against a target URL.",
    )
    parser.add_argument(
        "url",
        nargs="?",
        help="Target endpoint URL (e.g., https://pentest-ground.com:4280/vulnerabilities/xss_r/)",
    )
    parser.add_argument(
        "-d",
        "--detector",
        help="Name of the detector to execute (e.g., xss, sqli, command_injection, stored_xss)",
    )
    parser.add_argument(
        "-m",
        "--method",
        default="GET",
        choices=["GET", "POST"],
        help="HTTP Method (default: GET)",
    )
    parser.add_argument(
        "-p",
        "--param",
        action="append",
        dest="params",
        help="Query parameter in 'name=value' format (can be specified multiple times, e.g., -p name=test -p Submit=Submit)",
    )
    parser.add_argument(
        "-b",
        "--body",
        action="append",
        dest="body_params",
        help="Form body parameter in 'name=value' format for POST requests",
    )
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        dest="headers",
        help="Custom header in 'Key: Value' format (e.g., -H 'Cookie: PHPSESSID=xyz; security=low')",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Disable headless browser screenshot engine even if supported by the detector",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable DEBUG level logging to inspect raw probes and network traffic",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all registered detectors and exit",
    )
    return parser


def main() -> int:
    if sys.platform == "win32":
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            if hasattr(sys.stderr, "reconfigure"):
                sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = build_parser()
    args = parser.parse_args()

    # Discover all built-in detectors
    default_registry.discover_builtin()

    if args.list:
        print("\n=== Registered DAST Detectors ===")
        for cat, dets in default_registry.list_by_category().items():
            print(f"\n[{cat}]")
            for d in dets:
                cls = default_registry.get_class(d)
                desc = cls.description if cls else ""
                print(f"  - {d:20s} : {desc}")
        print()
        return 0

    if not args.url:
        print("[ERROR] Please provide a target URL to debug.")
        parser.print_help()
        return 1

    if not args.detector:
        print("[ERROR] Please specify the detector to debug using -d / --detector.")
        print(f"Available detectors: {', '.join(default_registry.list_available())}")
        return 1

    logger = setup_logger(args.verbose)

    det_cls = default_registry.get_class(args.detector)
    if not det_cls:
        print(f"[ERROR] Unknown detector '{args.detector}'.")
        print(f"Available: {', '.join(default_registry.list_available())}")
        return 1

    detector = det_cls()
    parsed_headers = parse_headers(args.headers)
    query_params = parse_key_value(args.params)
    body_params = parse_key_value(args.body_params)

    # Extract any query parameters already embedded in the URL
    parsed_url = urlparse(args.url)
    if parsed_url.query:
        from_url = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed_url.query).items()}
        for k, v in from_url.items():
            if k not in query_params:
                query_params[k] = v
        # Canonicalize clean URL without query
        clean_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path or "/", "", "", ""))
    else:
        clean_url = args.url

    method = HttpMethod.POST if args.method.upper() == "POST" else HttpMethod.GET

    endpoint = Endpoint(
        url=clean_url,
        method=method,
        params=query_params,
        body_params=body_params,
        headers=parsed_headers,
    )

    print("=" * 80)
    print("  DAST DETECTOR DEBUGGER")
    print("=" * 80)
    print(f"Target URL       : {endpoint.url}")
    print(f"HTTP Method      : {endpoint.method.value}")
    print(f"Query Params     : {endpoint.params or '(none)'}")
    print(f"Body Params      : {endpoint.body_params or '(none)'}")
    print(f"Headers/Cookies  : {list(parsed_headers.keys()) or '(none)'}")
    print(f"Detector Name    : {detector.name}")
    print(f"Detector Category: {detector.category.value}")
    print(f"Requirement      : {detector.requirement.value}")
    print(f"Evidence Type    : {detector.default_evidence_type.value}")
    print("-" * 80)

    # Determine browser requirement
    needs_browser = (
        not args.no_browser
        and (
            detector.requirement == DetectorRequirement.BROWSER
            or detector.default_evidence_type == EvidenceType.SCREENSHOT
            or detector.name in ("xss", "sqli", "command_injection", "stored_xss")
        )
    )

    screenshot_dir = Path("evidence/screenshots")
    screenshot_dir.mkdir(parents=True, exist_ok=True)

    browser = None
    if needs_browser:
        print("[*] Initializing headless Playwright Chromium instance...")
        try:
            browser = BrowserManager(
                output_dir=str(screenshot_dir),
                custom_headers=parsed_headers,
                base_url=endpoint.url,
            )
            browser.start()
            print("[+] Headless browser successfully started.")
        except Exception as exc:
            print(f"[!] Warning: Could not initialize browser ({exc}). Running network-only.")
            browser = None

    try:
        with HTTPClient(default_headers=parsed_headers, verify_ssl=False, timeout=10.0) as client:
            # 1. Connectivity & Session Check
            print("[*] Checking baseline target response...")
            if endpoint.method == HttpMethod.POST:
                baseline_resp, _, _ = client.post(endpoint.url, data=endpoint.body_params)
            else:
                baseline_resp, _, _ = client.get(endpoint.url, params=endpoint.params)

            if not baseline_resp:
                print("[!] ERROR: Target did not respond or returned a network connection error.")
                return 1

            print(f"[+] Baseline Status Code: {baseline_resp.status_code}")
            print(f"[+] Response Size       : {len(baseline_resp.content)} bytes")

            # Check if redirected to login
            if baseline_resp.status_code in (301, 302):
                loc = baseline_resp.headers.get("Location", "")
                print(f"[!] NOTICE: Server redirected to '{loc}'.")
                if "login" in loc.lower():
                    print("[!] WARNING: Target requires authentication. Provide session cookie via: -H 'Cookie: ...'")

            if "login.php" in baseline_resp.text and "login" not in endpoint.url.lower():
                print("[!] WARNING: Page contains login form. Session might be unauthenticated. Check your Cookie header.")

            # Check if endpoint has testable parameters for injection detectors
            all_params = endpoint.get_all_param_names()
            if not all_params and detector.category.value in ("injection", "xss"):
                print(f"[!] NOTICE: Endpoint has 0 testable parameters.")
                print(f"    Parameters can be passed using: -p name=test or -b name=test")

            # 2. Run the specific detector
            print(f"\n[*] Starting scan with detector '{detector.name}'...")
            t_start = time.time()
            try:
                findings = detector.scan(endpoint, client, browser=browser)
            except TypeError:
                findings = detector.scan(endpoint, client)
            except Exception as exc:
                print(f"\n[ERROR] Detector raised an exception: {exc}")
                import traceback
                traceback.print_exc()
                return 1

            duration = time.time() - t_start
            print(f"[+] Scan completed in {duration:.2f} seconds.")
            print("=" * 80)

            # 3. Present Results
            if findings:
                print(f"\n[!!!] VULNERABILITY CONFIRMED: Found {len(findings)} finding(s)!\n")
                for i, f in enumerate(findings, start=1):
                    sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                    print(f"--- Finding #{i}: {f.title} [{sev}] ---")
                    print(f"  URL        : {f.url}")
                    print(f"  Parameter  : {f.parameter or 'N/A'}")
                    print(f"  Confidence : {f.confidence.value}")
                    print(f"  Evidence Type: {f.evidence_type.value}")
                    if f.screenshot_path:
                        exists = Path(f.screenshot_path).exists()
                        size = Path(f.screenshot_path).stat().st_size if exists else 0
                        print(f"  Screenshot : {f.screenshot_path} (exists={exists}, size={size} bytes)")
                    if f.captured_dialog:
                        print(f"  JS Dialog  : {f.captured_dialog}")
                    if f.terminal_output:
                        print("  Terminal Output:")
                        print(f.terminal_output)
                    print("  Evidence Summary:")
                    for line in f.evidence.splitlines():
                        print(f"    {line}")
                    print(f"  Remediation: {f.remediation[:150]}...")
                    print()
            else:
                print("\n[i] NO VULNERABILITIES DETECTED on this endpoint by this detector.")
                print("\nDiagnostic Checklist:")
                print("  1. Verify the parameter name exists (e.g. is it 'name', 'id', 'ip', 'include'?)")
                print("  2. If testing DVWA or an authenticated lab, ensure you passed the session cookie:")
                print("     -H 'Cookie: PHPSESSID=...; security=low'")
                print("  3. For POST endpoints, make sure you use '-m POST' and '-b param=value'")
                print("  4. Run with '-v' (verbose mode) to inspect probe requests and server reflection.")
            print("=" * 80)

    finally:
        if browser:
            browser.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
