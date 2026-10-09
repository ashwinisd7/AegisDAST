"""Tests for Scanner orchestrator."""

import httpx
import pytest

from dast.models import Target
from dast.scanner import Scanner


def test_scanner_end_to_end_flow():
    html_content = """
    <!DOCTYPE html>
    <html>
    <head><title>App</title></head>
    <body>
        <a href="/status">Status</a>
    </body>
    </html>
    """

    def handler(request: httpx.Request):
        # Missing security headers to trigger SecurityHeadersDetector
        return httpx.Response(200, text=html_content, headers={"Content-Type": "text/html"})

    transport = httpx.MockTransport(handler)
    target = Target(url="http://testapp.local", max_depth=1, max_pages=5)

    scanner = Scanner(
        target=target,
        selected_detectors=["security_headers"],
        transport=transport,
    )

    result = scanner.run()

    assert len(result.scanned_endpoints) >= 1
    assert len(result.findings) > 0
    assert result.duration_seconds >= 0.0
    assert "security_headers" in result.active_detectors
    assert result.summary["total_findings"] == len(result.findings)


def test_scanner_stop_cancellation():
    html_content = "<html><body><a href='/1'>1</a><a href='/2'>2</a><a href='/3'>3</a></body></html>"

    def handler(request: httpx.Request):
        return httpx.Response(200, text=html_content, headers={"Content-Type": "text/html"})

    transport = httpx.MockTransport(handler)
    target = Target(url="http://testapp.local", max_depth=5, max_pages=100)

    scanner = Scanner(
        target=target,
        selected_detectors=["security_headers"],
        transport=transport,
    )
    # Stop before/during running
    scanner.stop()
    assert scanner.stop_event.is_set()

    result = scanner.run()
    assert result is not None
