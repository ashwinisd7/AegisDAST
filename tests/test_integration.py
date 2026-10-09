"""End-to-end integration test against the local test lab."""

from http.server import ThreadingHTTPServer
import threading
import time

from dast.models import Target
from dast.reporting.json_report import JSONReporter
from dast.scanner import Scanner
from examples.local_lab import LabHandler


def test_live_lab_scan(tmp_path):
    server_address = ("127.0.0.1", 8769)
    httpd = ThreadingHTTPServer(server_address, LabHandler)

    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.1)

    try:
        target = Target(
            url="http://127.0.0.1:8769",
            max_depth=2,
            max_pages=20,
        )
        scanner = Scanner(
            target=target,
            selected_detectors=["security_headers", "cors", "xss", "sqli", "ssrf", "cookies"],
            enable_ai_validation=False,
            use_kafka=False,
        )
        result = scanner.run()

        # Check endpoints were crawled
        endpoint_urls = [ep.url for ep in result.scanned_endpoints]
        assert "http://127.0.0.1:8769/" in endpoint_urls
        assert "http://127.0.0.1:8769/search" in endpoint_urls
        assert "http://127.0.0.1:8769/api/profile" in endpoint_urls
        assert "http://127.0.0.1:8769/db-query" in endpoint_urls

        # Check findings were detected
        detector_names = {f.detector_name for f in result.findings}
        assert "security_headers" in detector_names
        assert "cors" in detector_names
        assert any("xss" in d for d in detector_names)
        assert any("sqli" in d for d in detector_names)
        assert "ssrf" in detector_names
        assert any("cookie" in d for d in detector_names)

        # Check evidence types were categorized
        evidence_types = {f.evidence_type for f in result.findings}
        from dast.models import EvidenceType
        assert EvidenceType.HTTP_TRAFFIC in evidence_types
        assert EvidenceType.TERMINAL_OUTPUT in evidence_types
        assert EvidenceType.DB_ERROR in evidence_types

        # Check reporting
        out_file = tmp_path / "live_report.json"
        saved = JSONReporter.save(result, out_file)
        assert saved.exists()
        assert saved.stat().st_size > 0

    finally:
        httpd.shutdown()
        httpd.server_close()
