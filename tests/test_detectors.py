"""Tests for individual detector plugins across categorized vulnerability taxonomy."""

import httpx
import pytest

from dast.detectors.broken_auth.brute_force.detector import BruteForceDetector
from dast.detectors.broken_auth.insecure_captcha.detector import InsecureCaptchaDetector
from dast.detectors.cookie_based.cookies.detector import CookieSecurityDetector
from dast.detectors.cookie_based.csrf.detector import CSRFDetector
from dast.detectors.cookie_based.weak_session_ids.detector import WeakSessionIDDetector
from dast.detectors.file_handling.file_upload.detector import FileUploadDetector
from dast.detectors.injection.command_injection.detector import CommandInjectionDetector
from dast.detectors.injection.file_inclusion.detector import FileInclusionDetector
from dast.detectors.injection.sqli.detector import SQLiDetector
from dast.detectors.injection.ssrf.detector import SSRFDetector
from dast.detectors.misconfiguration.cors.detector import CORSDetector
from dast.detectors.misconfiguration.csp_bypass.detector import CSPBypassDetector
from dast.detectors.misconfiguration.javascript.detector import JavaScriptDetector
from dast.detectors.misconfiguration.open_redirect.detector import OpenRedirectDetector
from dast.detectors.misconfiguration.security_headers.detector import SecurityHeadersDetector
from dast.detectors.xss.dom.detector import DOMXSSDetector
from dast.detectors.xss.reflected.detector import ReflectedXSSDetector
from dast.detectors.xss.stored.detector import StoredXSSDetector
from dast.http_client import HTTPClient
from dast.models import DetectorCategory, Endpoint, EvidenceType, HttpMethod, Severity


def test_security_headers_missing():
    def handler(request: httpx.Request):
        return httpx.Response(200, text="<html><body>App</body></html>")

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = SecurityHeadersDetector()
        assert detector.category == DetectorCategory.MISCONFIGURATION
        assert detector.default_evidence_type == EvidenceType.HTTP_TRAFFIC

        endpoint = Endpoint(url="http://app.local/", method=HttpMethod.GET)
        findings = detector.scan(endpoint, client)

        assert len(findings) > 0
        for f in findings:
            assert f.evidence_type == EvidenceType.HTTP_TRAFFIC


def test_cors_reflection_vulnerability():
    def handler(request: httpx.Request):
        origin = request.headers.get("Origin", "")
        return httpx.Response(
            200,
            text="{}",
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            },
        )

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = CORSDetector()
        assert detector.category == DetectorCategory.MISCONFIGURATION
        assert detector.default_evidence_type == EvidenceType.HTTP_TRAFFIC

        endpoint = Endpoint(url="http://app.local/api/profile", method=HttpMethod.GET)
        findings = detector.scan(endpoint, client)

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence_type == EvidenceType.HTTP_TRAFFIC


def test_reflected_xss_detector():
    def handler(request: httpx.Request):
        q_val = request.url.params.get("q", "")
        return httpx.Response(
            200,
            text=f"<html><body>Search Results for: {q_val}</body></html>",
            headers={"Content-Type": "text/html"},
        )

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = ReflectedXSSDetector()
        assert detector.category == DetectorCategory.XSS
        assert detector.default_evidence_type == EvidenceType.SCREENSHOT

        endpoint = Endpoint(
            url="http://app.local/search",
            method=HttpMethod.GET,
            params={"q": "original"},
        )
        findings = detector.scan(endpoint, client)

        assert len(findings) == 1
        assert "Reflected Cross-Site Scripting (XSS)" in findings[0].title
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence_type == EvidenceType.SCREENSHOT


def test_reflected_xss_detector_inert_attribute_rejected():
    """Verify that user input reflected inside inert <script src="..."> is NOT flagged as XSS (no false positive)."""
    def handler(request: httpx.Request):
        include_val = request.url.params.get("include", "")
        # Emulate DVWA CSP page where input is placed inside script src attribute without execution
        return httpx.Response(
            200,
            text=f'<html><body><script src="{include_val}"></script><p>CSP Test</p></body></html>',
            headers={"Content-Type": "text/html"},
        )

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = ReflectedXSSDetector()
        endpoint = Endpoint(
            url="http://app.local/vulnerabilities/csp/",
            method=HttpMethod.GET,
            params={"include": "some_file.js"},
        )
        findings = detector.scan(endpoint, client)
        assert len(findings) == 0


def test_reflected_xss_detector_html_encoded_rejected():
    """Verify that HTML-entity encoded reflections are NOT flagged as XSS."""
    def handler(request: httpx.Request):
        q_val = request.url.params.get("q", "")
        encoded = q_val.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
        return httpx.Response(
            200,
            text=f"<html><body>Search Results: {encoded}</body></html>",
            headers={"Content-Type": "text/html"},
        )

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = ReflectedXSSDetector()
        endpoint = Endpoint(
            url="http://app.local/search",
            method=HttpMethod.GET,
            params={"q": "original"},
        )
        findings = detector.scan(endpoint, client)
        assert len(findings) == 0


def test_dom_xss_detector_direct_flow_detected():
    """Verify DOM XSS detector catches direct source-to-sink flow."""
    def handler(request: httpx.Request):
        return httpx.Response(
            200,
            text="""<html><body>
            <script>
                var pos = document.URL.indexOf("default=") + 8;
                document.write(decodeURI(document.URL.substring(pos)));
            </script>
            </body></html>""",
            headers={"Content-Type": "text/html"},
        )

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = DOMXSSDetector()
        endpoint = Endpoint(
            url="http://app.local/vulnerabilities/xss_d/",
            method=HttpMethod.GET,
            params={"default": "English"},
        )
        findings = detector.scan(endpoint, client)
        assert len(findings) >= 1
        assert "DOM" in findings[0].title


def test_dom_xss_detector_benign_scripts_rejected():
    """Verify DOM XSS detector does not flag harmless scripts having sources/sinks in disjoint logic."""
    def handler(request: httpx.Request):
        return httpx.Response(
            200,
            text="""<html><body>
            <div id="status">Loading</div>
            <script>
                // Benign usage of location and innerHTML in separate scopes
                console.log("Current page is " + window.location.pathname);
                function updateClock() {
                    document.getElementById('status').innerHTML = "Ready";
                }
                updateClock();
            </script>
            </body></html>""",
            headers={"Content-Type": "text/html"},
        )

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = DOMXSSDetector()
        endpoint = Endpoint(
            url="http://app.local/vulnerabilities/csp/",
            method=HttpMethod.GET,
            params={"include": "include.js"},
        )
        findings = detector.scan(endpoint, client)
        assert len(findings) == 0



def test_sqli_detector_trigger():
    def handler(request: httpx.Request):
        id_val = request.url.params.get("id", "")
        if "'" in id_val:
            return httpx.Response(500, text="Fatal error: You have an error in your SQL syntax near '''")
        return httpx.Response(200, text="User Profile")

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = SQLiDetector()
        assert detector.category == DetectorCategory.INJECTION
        assert detector.default_evidence_type == EvidenceType.DB_ERROR

        endpoint = Endpoint(
            url="http://app.local/user",
            method=HttpMethod.GET,
            params={"id": "10"},
        )
        findings = detector.scan(endpoint, client)

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence_type == EvidenceType.DB_ERROR
        assert "Database Error Evidence" in findings[0].evidence


def test_sqli_detector_boolean_blind():
    def handler(request: httpx.Request):
        id_val = request.url.params.get("id", "")
        # Return truncated / missing response on false condition
        if "' AND '1'='2" in id_val or "1 AND 1=2" in id_val:
            return httpx.Response(200, text="User not found.")
        # Baseline / True condition returns full user profile
        return httpx.Response(200, text="User Profile: " + ("A" * 350))

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = SQLiDetector()
        endpoint = Endpoint(
            url="http://app.local/user",
            method=HttpMethod.GET,
            params={"id": "10"},
        )
        findings = detector.scan(endpoint, client)

        assert len(findings) == 1
        assert "Boolean Differential" in findings[0].title
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence_type == EvidenceType.HTTP_TRAFFIC
        assert "HTTP Differential Traffic Evidence" in findings[0].evidence


def test_sqli_detector_time_blind():
    import time

    def handler(request: httpx.Request):
        id_val = request.url.params.get("id", "")
        if "SLEEP(2)" in id_val:
            time.sleep(1.85)
            return httpx.Response(200, text="User Profile")
        return httpx.Response(200, text="User Profile")

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = SQLiDetector()
        endpoint = Endpoint(
            url="http://app.local/user",
            method=HttpMethod.GET,
            params={"id": "10"},
        )
        findings = detector.scan(endpoint, client)

        assert len(findings) == 1
        assert "Time-Based Delay" in findings[0].title
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence_type == EvidenceType.HTTP_TRAFFIC
        assert "HTTP Timing Evidence" in findings[0].evidence


def test_ssrf_detector_candidate_parameter():
    def handler(request: httpx.Request):
        return httpx.Response(200, text="Remote content fetched")

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = SSRFDetector()
        assert detector.category == DetectorCategory.INJECTION
        assert detector.default_evidence_type == EvidenceType.HTTP_TRAFFIC

        endpoint = Endpoint(
            url="http://app.local/fetch",
            method=HttpMethod.GET,
            params={"url": "https://example.com/data"},
        )
        findings = detector.scan(endpoint, client)

        assert len(findings) == 1
        assert findings[0].evidence_type == EvidenceType.HTTP_TRAFFIC


def test_cookie_security_detector():
    def handler(request: httpx.Request):
        return httpx.Response(
            200,
            text="Welcome",
            headers={"Set-Cookie": "session_id=12345; Path=/; SameSite=None"},
        )

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = CookieSecurityDetector()
        assert detector.category == DetectorCategory.COOKIE_BASED
        assert detector.default_evidence_type == EvidenceType.TERMINAL_OUTPUT

        endpoint = Endpoint(url="http://app.local/login", method=HttpMethod.GET)
        findings = detector.scan(endpoint, client)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.evidence_type == EvidenceType.TERMINAL_OUTPUT
        assert finding.terminal_output is not None
        assert "session_id" in finding.terminal_output
        assert "Missing 'Secure' flag" in finding.evidence


def test_csrf_detector():
    html = """
    <html>
        <body>
            <form action="/transfer" method="POST">
                <input type="text" name="amount" value="100"/>
                <input type="submit" value="Submit"/>
            </form>
        </body>
    </html>
    """

    def handler(request: httpx.Request):
        return httpx.Response(200, text=html, headers={"Content-Type": "text/html"})

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = CSRFDetector()
        assert detector.category == DetectorCategory.COOKIE_BASED
        assert detector.default_evidence_type == EvidenceType.DOM_EVIDENCE

        endpoint = Endpoint(url="http://app.local/transfer", method=HttpMethod.GET)
        findings = detector.scan(endpoint, client)

        assert len(findings) == 1
        assert findings[0].evidence_type == EvidenceType.DOM_EVIDENCE
        assert "Missing Anti-CSRF Token" in findings[0].title


def test_csrf_detector_sensitive_get_form():
    """Test detection of sensitive state-changing GET forms (such as DVWA password change)."""
    html = """
    <html>
        <body>
            <form action="#" method="GET">
                New password:<br />
                <input type="password" AUTOCOMPLETE="off" name="password_new"><br />
                Confirm password:<br />
                <input type="password" AUTOCOMPLETE="off" name="password_conf"><br />
                <input type="submit" value="Change" name="Change">
            </form>
        </body>
    </html>
    """

    def handler(request: httpx.Request):
        return httpx.Response(200, text=html, headers={"Content-Type": "text/html"})

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = CSRFDetector()
        endpoint = Endpoint(url="http://app.local/vulnerabilities/csrf/", method=HttpMethod.GET)
        findings = detector.scan(endpoint, client)

        assert len(findings) == 1
        assert "CSRF" in findings[0].title or "Anti-CSRF" in findings[0].title
        assert findings[0].severity == Severity.HIGH
        assert "password_new" in findings[0].evidence



def test_javascript_detector_secret_leak():
    js_code = """
    // Config file
    const AWS_KEY = "AKIA1234567890ABCDEF";
    function load() { console.log("ready"); }
    """

    def handler(request: httpx.Request):
        return httpx.Response(200, text=js_code, headers={"Content-Type": "application/javascript"})

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = JavaScriptDetector()
        assert detector.category == DetectorCategory.MISCONFIGURATION
        assert detector.default_evidence_type == EvidenceType.DOM_EVIDENCE

        endpoint = Endpoint(url="http://app.local/static/bundle.js", method=HttpMethod.GET)
        findings = detector.scan(endpoint, client)

        assert len(findings) >= 1
        assert any("AWS Access Key ID" in f.title for f in findings)
        assert findings[0].evidence_type == EvidenceType.DOM_EVIDENCE


def test_file_inclusion_detector():
    def handler(request: httpx.Request):
        val = request.url.params.get("page", "")
        if "passwd" in val:
            return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
        return httpx.Response(200, text="Welcome page")

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = FileInclusionDetector()
        assert detector.category == DetectorCategory.INJECTION
        assert detector.default_evidence_type == EvidenceType.HTTP_TRAFFIC

        endpoint = Endpoint(url="http://app.local/index.php", method=HttpMethod.GET, params={"page": "home"})
        findings = detector.scan(endpoint, client)

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence_type == EvidenceType.HTTP_TRAFFIC


def test_file_inclusion_medium_level():
    def handler(request: httpx.Request):
        val = request.url.params.get("page", "")
        # Emulate DVWA Medium single-pass str_replace("../", "", $val)
        filtered = val.replace("../", "").replace("..\\", "")
        if filtered.startswith("../") and "etc/passwd" in filtered:
            return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash\n")
        return httpx.Response(200, text="Welcome page")

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = FileInclusionDetector()
        endpoint = Endpoint(url="http://app.local/vulnerabilities/fi/", method=HttpMethod.GET, params={"page": "include.php"})
        findings = detector.scan(endpoint, client)

        assert len(findings) == 1
        assert "Medium Level" in findings[0].title
        assert findings[0].severity == Severity.HIGH


def test_file_inclusion_high_level():
    import fnmatch

    def handler(request: httpx.Request):
        val = request.url.params.get("page", "")
        # Emulate DVWA High fnmatch("file*", $val)
        if not fnmatch.fnmatch(val, "file*") and val != "include.php":
            return httpx.Response(200, text="ERROR: File not found!")
        if "passwd" in val:
            return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash\n")
        return httpx.Response(200, text="Welcome page")

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = FileInclusionDetector()
        endpoint = Endpoint(url="http://app.local/vulnerabilities/fi/", method=HttpMethod.GET, params={"page": "file1.php"})
        findings = detector.scan(endpoint, client)

        assert len(findings) == 1
        assert "High Level" in findings[0].title
        assert findings[0].severity == Severity.HIGH


def test_file_inclusion_impossible_level():
    def handler(request: httpx.Request):
        val = request.url.params.get("page", "")
        if val not in ("include.php", "file1.php", "file2.php", "file3.php"):
            return httpx.Response(200, text="ERROR: File not found!")
        return httpx.Response(200, text="Welcome page")

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = FileInclusionDetector()
        endpoint = Endpoint(url="http://app.local/vulnerabilities/fi/", method=HttpMethod.GET, params={"page": "file1.php"})
        findings = detector.scan(endpoint, client)

        assert len(findings) == 0


def test_command_injection_detector():
    def handler(request: httpx.Request):
        ip_val = request.url.params.get("ip", "")
        if "CMDINJ" in ip_val:
            return httpx.Response(200, text="PING 127.0.0.1\nCMDINJ\n")
        return httpx.Response(200, text="PING 127.0.0.1 56 data bytes")

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = CommandInjectionDetector()
        assert detector.category == DetectorCategory.INJECTION
        assert detector.default_evidence_type == EvidenceType.HTTP_TRAFFIC

        endpoint = Endpoint(url="http://app.local/ping", method=HttpMethod.GET, params={"ip": "127.0.0.1"})
        findings = detector.scan(endpoint, client)

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "OS Command Injection" in findings[0].title
        assert "CMDINJ" in findings[0].evidence


def test_file_upload_detector():
    html = """
    <html>
        <body>
            <form action="/upload" method="POST" enctype="multipart/form-data">
                <input type="file" name="attachment" />
                <button type="submit">Upload</button>
            </form>
        </body>
    </html>
    """

    def handler(request: httpx.Request):
        return httpx.Response(200, text=html, headers={"Content-Type": "text/html"})

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = FileUploadDetector()
        assert detector.category == DetectorCategory.FILE_HANDLING
        assert detector.default_evidence_type == EvidenceType.DOM_EVIDENCE

        endpoint = Endpoint(url="http://app.local/upload", method=HttpMethod.GET)
        findings = detector.scan(endpoint, client)

        assert len(findings) == 1
        assert "File Upload" in findings[0].title
        assert findings[0].evidence_type == EvidenceType.DOM_EVIDENCE


def test_weak_session_ids_low_level():
    """DVWA Low: Sequential integer counter (1, 2, 3, 4...)."""
    counter = 0

    def handler(request: httpx.Request):
        nonlocal counter
        counter += 1
        return httpx.Response(
            200,
            text="Session Generated",
            headers={"Set-Cookie": f"dvwaSession={counter}; Path=/"},
        )

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = WeakSessionIDDetector()
        endpoint = Endpoint(url="http://app.local/vulnerabilities/weak_id/", method=HttpMethod.POST)
        findings = detector.scan(endpoint, client)

        low_finding = next((f for f in findings if "Low Level" in f.title), None)
        assert low_finding is not None
        assert low_finding.severity == Severity.CRITICAL
        assert "Predicted Next Token" in low_finding.evidence
        assert "| 5" in low_finding.evidence
        assert "Sequential Integer Counter" in low_finding.evidence


def test_weak_session_ids_medium_level():
    """DVWA Medium: Unix epoch timestamp counter."""
    base_time = 1712398450
    step = 0

    def handler(request: httpx.Request):
        nonlocal step
        ts = base_time + step
        step += 1
        return httpx.Response(
            200,
            text="Session Generated",
            headers={"Set-Cookie": f"dvwaSession={ts}; Path=/"},
        )

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = WeakSessionIDDetector()
        endpoint = Endpoint(url="http://app.local/vulnerabilities/weak_id/", method=HttpMethod.POST)
        findings = detector.scan(endpoint, client)

        med_finding = next((f for f in findings if "Medium Level" in f.title), None)
        assert med_finding is not None
        assert med_finding.severity == Severity.HIGH
        assert "System Unix Epoch Timestamp" in med_finding.evidence


def test_weak_session_ids_high_level():
    """DVWA High: MD5 hash of sequential counter."""
    import hashlib
    counter = 0

    def handler(request: httpx.Request):
        nonlocal counter
        counter += 1
        md5_val = hashlib.md5(str(counter).encode()).hexdigest()
        return httpx.Response(
            200,
            text="Session Generated",
            headers={"Set-Cookie": f"dvwaSession={md5_val}; Path=/vulnerabilities/weak_id/; Domain=app.local"},
        )

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = WeakSessionIDDetector()
        endpoint = Endpoint(url="http://app.local/vulnerabilities/weak_id/", method=HttpMethod.POST)
        findings = detector.scan(endpoint, client)

        high_finding = next((f for f in findings if "High Level" in f.title), None)
        assert high_finding is not None
        assert high_finding.severity == Severity.HIGH
        assert "Cracked Hash: Token #1 = MD5(1)" in high_finding.evidence
        # 5th token predicted: md5(5) == e4da3b7fbbce2345d7772b0674a318d5
        expected_md5_5 = hashlib.md5(b"5").hexdigest()
        assert expected_md5_5 in high_finding.evidence


def test_weak_session_ids_impossible_level():
    """DVWA Impossible: CSPRNG hash with Secure, HttpOnly, and strict scoping."""
    import secrets

    def handler(request: httpx.Request):
        secure_token = secrets.token_hex(20)  # 40 hex chars
        return httpx.Response(
            200,
            text="Session Generated",
            headers={
                "Set-Cookie": f"dvwaSession={secure_token}; Path=/vulnerabilities/weak_id/; Domain=app.local; Secure; HttpOnly; SameSite=Strict"
            },
        )

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        detector = WeakSessionIDDetector()
        endpoint = Endpoint(url="https://app.local/vulnerabilities/weak_id/", method=HttpMethod.POST)
        findings = detector.scan(endpoint, client)

        # In Impossible level: No weak predictability findings and no missing flag findings
        assert len(findings) == 0


def test_stored_xss_detector_true_positive():
    """Verify Stored XSS detector identifies persistent markup rendered on subsequent page retrieval."""
    from dast.detectors.xss.stored.detector import StoredXSSDetector
    from dast.models import FormModel, InputField

    db_entries: list[str] = []

    def handler(request: httpx.Request):
        if request.method == "POST":
            # Extract form body
            import urllib.parse
            parsed = urllib.parse.parse_qs(request.read().decode())
            comment = parsed.get("comment", [""])[0]
            db_entries.append(comment)
            return httpx.Response(200, text="<html><body>Comment Saved</body></html>")
        else:
            rendered = "".join(f"<div>{e}</div>" for e in db_entries)
            return httpx.Response(200, text=f"<html><body><h2>Guestbook</h2>{rendered}</body></html>")

    transport = httpx.MockTransport(handler)
    form = FormModel(
        action="http://app.local/vulnerabilities/xss_s/",
        method="POST",
        inputs=[InputField(name="comment", input_type="textarea"), InputField(name="btnSign", input_type="submit", value="Sign")],
    )
    endpoint = Endpoint(
        url="http://app.local/vulnerabilities/xss_s/",
        method=HttpMethod.GET,
        forms=[form],
    )

    with HTTPClient(transport=transport) as client:
        detector = StoredXSSDetector()
        findings = detector.scan(endpoint, client)
        assert len(findings) == 1
        assert "Stored Cross-Site Scripting" in findings[0].title
        assert "persisted in backend" in findings[0].evidence


def test_stored_xss_detector_false_positive_prevention_on_ephemeral_form():
    """Verify Stored XSS detector does NOT flag forms whose values do not persist (e.g. JavaScript Attacks page)."""
    from dast.detectors.xss.stored.detector import StoredXSSDetector
    from dast.models import FormModel, InputField

    def handler(request: httpx.Request):
        # Ephemeral form: GET always returns default static page without persisting input
        return httpx.Response(
            200,
            text='<html><body><h2>JavaScript Attacks</h2><form><input name="phrase" value="ChangeMe"><input type="submit" value="Submit"></form></body></html>',
        )

    transport = httpx.MockTransport(handler)
    form = FormModel(
        action="http://app.local/vulnerabilities/javascript/",
        method="POST",
        inputs=[InputField(name="phrase", input_type="text"), InputField(name="Submit", input_type="submit", value="Submit")],
    )
    endpoint = Endpoint(
        url="http://app.local/vulnerabilities/javascript/",
        method=HttpMethod.GET,
        forms=[form],
    )

    with HTTPClient(transport=transport) as client:
        detector = StoredXSSDetector()
        findings = detector.scan(endpoint, client)
        assert len(findings) == 0

