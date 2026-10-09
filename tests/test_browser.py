"""Tests for Playwright browser screenshot automation and evidence capture."""

from pathlib import Path
import httpx
import pytest

from dast.browser import BrowserManager
from dast.detectors.xss.reflected.detector import ReflectedXSSDetector as ReflectedInputDetector
from dast.http_client import HTTPClient
from dast.models import Endpoint, EvidenceType, HttpMethod, Severity


def test_browser_manager_lifecycle_and_capture(tmp_path: Path):
    screenshot_dir = tmp_path / "screenshots"
    with BrowserManager(output_dir=screenshot_dir, headless=True) as browser:
        assert browser.is_available

        html = "<html><body><h1>Security Audit Verification</h1><p>Test Evidence</p></body></html>"
        path = browser.capture_step("test_step_render", html_content=html)

        assert path is not None
        p = Path(path)
        assert p.exists()
        assert p.stat().st_size > 0
        assert p.suffix == ".png"


def test_xss_detector_with_browser_step_screenshots(tmp_path: Path):
    screenshot_dir = tmp_path / "xss_screenshots"

    def handler(request: httpx.Request):
        q_val = request.url.params.get("q", "")
        return httpx.Response(
            200,
            text=f"<html><body><h2>Search</h2><div>Results for: {q_val}</div></body></html>",
            headers={"Content-Type": "text/html"},
        )

    transport = httpx.MockTransport(handler)

    with BrowserManager(output_dir=screenshot_dir, headless=True) as browser:
        with HTTPClient(transport=transport) as client:
            detector = ReflectedInputDetector()
            endpoint = Endpoint(
                url="http://app.local/search",
                method=HttpMethod.GET,
                params={"q": "original"},
            )

            findings = detector.scan(endpoint, client, browser=browser)

            assert len(findings) >= 1
            xss_finding = findings[0]
            assert xss_finding.severity == Severity.HIGH
            assert xss_finding.evidence_type == EvidenceType.SCREENSHOT

            # Verify step screenshots were captured
            assert len(xss_finding.step_screenshots) > 0
            for shot_path in xss_finding.step_screenshots:
                assert Path(shot_path).exists()
                assert Path(shot_path).stat().st_size > 0

            # Verify final screenshot is attached to the finding
            assert xss_finding.screenshot_path is not None
            assert Path(xss_finding.screenshot_path).exists()
            assert xss_finding.screenshot_path == xss_finding.step_screenshots[-1]


def test_browser_dialog_capture_alert_confirm_prompt(tmp_path: Path):
    """Verify BrowserManager listens for and intercepts alert(), confirm(), and prompt() dialogs."""
    screenshot_dir = tmp_path / "dialog_screenshots"
    with BrowserManager(output_dir=screenshot_dir, headless=True) as browser:
        assert browser.is_available

        # 1. Test alert() interception
        browser.clear_dialogs()
        html_alert = "<html><body><script>alert('XSS_ALERT_TRIGGER');</script></body></html>"
        browser.capture_step("test_alert", html_content=html_alert)

        assert browser.has_dialog("alert")
        assert browser.last_dialog is not None
        assert browser.last_dialog.type == "alert"
        assert browser.last_dialog.message == "XSS_ALERT_TRIGGER"
        assert str(browser.last_dialog) == "alert('XSS_ALERT_TRIGGER')"

        # 2. Test confirm() interception
        html_confirm = "<html><body><script>confirm('XSS_CONFIRM_TRIGGER');</script></body></html>"
        browser.capture_step("test_confirm", html_content=html_confirm)

        assert browser.has_dialog("confirm")
        assert browser.last_dialog is not None
        assert browser.last_dialog.type == "confirm"
        assert browser.last_dialog.message == "XSS_CONFIRM_TRIGGER"

        # 3. Test prompt() interception
        html_prompt = "<html><body><script>prompt('XSS_PROMPT_TRIGGER', 'default_val');</script></body></html>"
        browser.capture_step("test_prompt", html_content=html_prompt)

        assert browser.has_dialog("prompt")
        assert browser.last_dialog is not None
        assert browser.last_dialog.type == "prompt"
        assert browser.last_dialog.message == "XSS_PROMPT_TRIGGER"

        # 4. Verify all three dialog types were recorded in history
        all_types = [d.type for d in browser.captured_dialogs]
        assert "alert" in all_types
        assert "confirm" in all_types
        assert "prompt" in all_types


def test_xss_detector_captures_visual_dom_evidence(tmp_path: Path):
    """Verify ReflectedXSSDetector records visual DOM execution (red background & <h1>XSS</h1>) and captures screenshot."""
    screenshot_dir = tmp_path / "xss_visual_screenshots"

    def handler(request: httpx.Request):
        q_val = request.url.params.get("q", "")
        return httpx.Response(
            200,
            text=f"<html><body><div>Search results: {q_val}</div></body></html>",
            headers={"Content-Type": "text/html"},
        )

    transport = httpx.MockTransport(handler)

    with BrowserManager(output_dir=screenshot_dir, headless=True) as browser:
        with HTTPClient(transport=transport) as client:
            detector = ReflectedInputDetector()
            endpoint = Endpoint(
                url="http://app.local/search",
                method=HttpMethod.GET,
                params={"q": "initial"},
            )

            findings = detector.scan(endpoint, client, browser=browser)

            assert len(findings) >= 1
            xss_finding = findings[0]
            assert xss_finding.severity == Severity.HIGH
            assert xss_finding.screenshot_path is not None
            assert Path(xss_finding.screenshot_path).exists()
            assert "Screenshot & DOM Evidence" in xss_finding.evidence


def test_browser_dialog_visual_overlay_rendered(tmp_path: Path):
    """Verify that when a dialog is captured, BrowserManager renders visual dialog overlay into screenshot."""
    screenshot_dir = tmp_path / "overlay_screenshots"
    with BrowserManager(output_dir=screenshot_dir, headless=True) as browser:
        assert browser.is_available
        html_with_alert = "<html><body><h1>Target Page</h1><script>alert('POC_ALERT_VAL');</script></body></html>"
        shot_path = browser.capture_step("test_alert_visual", html_content=html_with_alert)

        assert shot_path is not None
        p = Path(shot_path)
        assert p.exists()
        assert p.stat().st_size > 0
        assert browser.has_dialog("alert")
        assert browser.last_dialog is not None
        assert browser.last_dialog.message == "POC_ALERT_VAL"


def test_sqli_detector_with_browser_screenshot(tmp_path: Path):
    """Verify SQLiDetector captures screenshot evidence when browser is available."""
    screenshot_dir = tmp_path / "sqli_screenshots"

    def handler(request: httpx.Request):
        id_val = request.url.params.get("id", "")
        if "'" in id_val:
            return httpx.Response(500, text="Fatal error: You have an error in your SQL syntax near '''")
        return httpx.Response(200, text="User Profile")

    transport = httpx.MockTransport(handler)
    with BrowserManager(output_dir=screenshot_dir, headless=True) as browser:
        with HTTPClient(transport=transport) as client:
            from dast.detectors.injection.sqli.detector import SQLiDetector
            detector = SQLiDetector()
            endpoint = Endpoint(url="http://app.local/user", method=HttpMethod.GET, params={"id": "1"})
            findings = detector.scan(endpoint, client, browser=browser)

            assert len(findings) >= 1
            assert findings[0].screenshot_path is not None
            assert Path(findings[0].screenshot_path).exists()
            assert findings[0].evidence_type == EvidenceType.DB_ERROR


def test_command_injection_detector_with_browser_screenshot(tmp_path: Path):
    """Verify CommandInjectionDetector captures screenshot evidence when browser is available."""
    screenshot_dir = tmp_path / "cmdi_screenshots"

    def handler(request: httpx.Request):
        ip_val = request.url.params.get("ip", "")
        if "CMDINJ" in ip_val:
            return httpx.Response(200, text="PING 127.0.0.1\nCMDINJ\n")
        return httpx.Response(200, text="PING 127.0.0.1 56 data bytes")

    transport = httpx.MockTransport(handler)
    with BrowserManager(output_dir=screenshot_dir, headless=True) as browser:
        with HTTPClient(transport=transport) as client:
            from dast.detectors.injection.command_injection.detector import CommandInjectionDetector
            detector = CommandInjectionDetector()
            endpoint = Endpoint(url="http://app.local/ping", method=HttpMethod.GET, params={"ip": "127.0.0.1"})
            findings = detector.scan(endpoint, client, browser=browser)

            assert len(findings) >= 1
            assert findings[0].screenshot_path is not None
            assert Path(findings[0].screenshot_path).exists()
            assert findings[0].evidence_type in (EvidenceType.SCREENSHOT, EvidenceType.HTTP_TRAFFIC)


def test_browser_fill_and_submit_form_lifecycle(tmp_path: Path):
    """Verify BrowserManager.fill_and_submit_form enters input, clicks submit, and captures screenshot."""
    screenshot_dir = tmp_path / "form_screenshots"
    with BrowserManager(output_dir=screenshot_dir, headless=True) as browser:
        assert browser.is_available

        # Serve inline data URL with interactive form
        form_html = (
            "<html><body>"
            "<form onsubmit=\"event.preventDefault(); document.getElementById('status').innerText='SUBMITTED:' + document.getElementById('target').value;\">"
            "<input id='target' name='query' value='initial'>"
            "<input type='submit' name='Submit' value='Submit'>"
            "<div id='status'>ready</div>"
            "</form>"
            "</body></html>"
        )
        data_url = "data:text/html;charset=utf-8," + form_html.replace('"', "%22").replace(" ", "%20").replace("'", "%27")

        page_content, _ = browser.fill_and_submit_form(
            url=data_url,
            target_param="query",
            payload="test_payload_val",
            companion_fields={"Submit": "Submit"},
            step_name="test_form_submit",
            detector_name="command_injection",
        )

        assert "SUBMITTED:test_payload_val" in page_content

        # Save buffered step screenshots when finding is generated
        saved_files = browser.save_interaction_steps("command_injection")
        assert len(saved_files) == 3
        cmdi_dir = screenshot_dir / "command_injection"
        assert cmdi_dir.exists()
        disk_files = [f.name for f in cmdi_dir.iterdir()]
        assert any("step_1_navigated_to_form" in f or "step-1" in f for f in disk_files)
        assert any("step_2_filled_payload" in f or "step-2" in f for f in disk_files)
        assert any("step_3_submitted_form_result" in f or "step-3" in f for f in disk_files)


def test_sqli_form_filling_detection():
    """Verify SQLiDetector detects SQL syntax error returned during browser form submission."""
    from dast.detectors.injection.sqli.detector import SQLiDetector
    from dast.models import FormModel, InputField

    class MockFormBrowser:
        def fill_and_submit_form(self, url, target_param, payload, companion_fields=None, detector_name="", **kwargs):
            if "'" in payload:
                return "<html><body>Fatal error: You have an error in your SQL syntax near '''</body></html>", "/fake/shot.png"
            return "<html><body>OK</body></html>", None

        def save_interaction_steps(self, detector_name):
            return ["/fake/step-1.png", "/fake/step-2.png"]

    form = FormModel(
        action="http://app.local/form_login",
        method="POST",
        inputs=[InputField(name="username", input_type="text"), InputField(name="Submit", input_type="submit", value="Submit")],
    )
    detector = SQLiDetector()
    endpoint = Endpoint(url="http://app.local/form_login", method=HttpMethod.POST, body_params={"username": "admin"}, forms=[form])

    transport = httpx.MockTransport(lambda r: httpx.Response(200, text="OK"))
    with HTTPClient(transport=transport) as client:
        findings = detector.scan(endpoint, client, browser=MockFormBrowser())
        assert len(findings) >= 1
        f = findings[0]
        assert "Form Field" in f.title or "SQL" in f.title
        assert f.evidence_type == EvidenceType.DB_ERROR
        assert f.step_screenshots == ["/fake/step-1.png", "/fake/step-2.png"]


def test_command_injection_form_filling_detection():
    """Verify CommandInjectionDetector detects canary returned during browser form submission."""
    from dast.detectors.injection.command_injection.detector import CommandInjectionDetector
    from dast.models import FormModel, InputField

    class MockFormBrowser:
        def fill_and_submit_form(self, url, target_param, payload, companion_fields=None, detector_name="", **kwargs):
            # Check for canary injection in payload
            if "CMDINJ" in payload:
                return "<html><body>PING 127.0.0.1\nCMDINJ</body></html>", "/fake/cmdi_shot.png"
            return "<html><body>PING 127.0.0.1 56 data bytes</body></html>", None

        def save_interaction_steps(self, detector_name):
            return ["/fake/step-1.png", "/fake/step-2.png"]

    form = FormModel(
        action="http://app.local/ping",
        method="POST",
        inputs=[InputField(name="ip", input_type="text"), InputField(name="Submit", input_type="submit", value="Submit")],
    )
    detector = CommandInjectionDetector()
    endpoint = Endpoint(url="http://app.local/ping", method=HttpMethod.POST, body_params={"ip": "127.0.0.1"}, forms=[form])

    transport = httpx.MockTransport(lambda r: httpx.Response(200, text="PING 127.0.0.1"))
    with HTTPClient(transport=transport) as client:
        findings = detector.scan(endpoint, client, browser=MockFormBrowser())
        assert len(findings) >= 1
        f = findings[0]
        assert "Form Field" in f.title or "Command Injection" in f.title
        assert f.evidence_type in (EvidenceType.SCREENSHOT, EvidenceType.HTTP_TRAFFIC)
        assert f.step_screenshots == ["/fake/step-1.png", "/fake/step-2.png"]


def test_xss_form_filling_detection():
    """Verify ReflectedXSSDetector detects DOM execution triggered during browser form submission."""
    from dast.detectors.xss.reflected.detector import ReflectedXSSDetector
    from dast.models import FormModel, InputField

    class MockFormBrowser:
        def __init__(self):
            self.captured_dialogs = []

        def fill_and_submit_form(self, url, target_param, payload, companion_fields=None, detector_name="", **kwargs):
            return "<html><body style='background-color: red'><h1>dastXSS</h1></body></html>", "/fake/xss_shot.png"

        def check_xss_dom_execution(self):
            return True

        def save_interaction_steps(self, detector_name):
            return ["/fake/step-1.png", "/fake/step-2.png"]

    form = FormModel(
        action="http://app.local/form_xss",
        method="GET",
        inputs=[InputField(name="txtName", input_type="text"), InputField(name="Submit", input_type="submit", value="Submit")],
    )
    detector = ReflectedXSSDetector()
    endpoint = Endpoint(url="http://app.local/form_xss", method=HttpMethod.GET, params={"txtName": "test"}, forms=[form])

    transport = httpx.MockTransport(lambda r: httpx.Response(200, text="<html><body>Initial <script> <img <svg</body></html>"))
    with HTTPClient(transport=transport) as client:
        findings = detector.scan(endpoint, client, browser=MockFormBrowser())
        assert len(findings) >= 1
        f = findings[0]
        assert "Form Field" in f.title or "XSS" in f.title
        assert f.evidence_type == EvidenceType.SCREENSHOT
        assert f.step_screenshots == ["/fake/step-1.png", "/fake/step-2.png"]


def test_render_terminal_screenshot(tmp_path: Path):
    """Verify BrowserManager.render_terminal_screenshot generates realistic terminal window PNG."""
    screenshot_dir = tmp_path / "term_screenshots"
    with BrowserManager(output_dir=screenshot_dir, headless=True) as browser:
        assert browser.is_available
        shot_path = browser.render_terminal_screenshot(
            command="expr 823 + 64194",
            output="65017",
            detector_name="command_injection",
            title="Terminal Test",
        )
        assert shot_path is not None
        p = Path(shot_path)
        assert p.exists()
        assert p.stat().st_size > 0
        assert p.parent.name == "command_injection"

