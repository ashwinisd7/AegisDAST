"""Insecure CAPTCHA Validation & Bypass Detector.

Category: Broken Authentication
Evidence Type: DOM Evidence (Form CAPTCHA element and server bypass differential)
"""

from __future__ import annotations

import re
from typing import Any

from bs4 import BeautifulSoup

from dast.detectors.base import BaseDetector
from dast.http_client import HTTPClient
from dast.models import (
    Confidence,
    DetectorCategory,
    Endpoint,
    EvidenceType,
    Finding,
    HttpMethod,
    Severity,
)


class InsecureCaptchaDetector(BaseDetector):
    """Detects forms with client-side only or bypassable CAPTCHA implementations."""

    name = "insecure_captcha"
    description = "Audits forms implementing CAPTCHA to verify strict server-side validation enforcement"
    category = DetectorCategory.BROKEN_AUTH
    default_evidence_type = EvidenceType.DOM_EVIDENCE

    CAPTCHA_FIELD_PATTERNS = re.compile(
        r"(captcha|g-recaptcha|h-captcha|turnstile|recaptcha_response_field|challenge)",
        re.I,
    )

    def scan(
        self,
        endpoint: Endpoint,
        client: HTTPClient,
        browser: Any | None = None,
        session: Any | None = None,
        **kwargs: Any,
    ) -> list[Finding]:
        """Audit endpoint forms for bypassable CAPTCHA validation."""
        findings: list[Finding] = []

        resp, req_meta, res_meta = client.get(endpoint.url)
        if not resp or not resp.text:
            return findings

        content_type = resp.headers.get("Content-Type", "").lower()
        if "text/html" not in content_type:
            return findings

        soup = BeautifulSoup(resp.text, "html.parser")
        for form in soup.find_all("form"):
            method = form.get("method", "GET").strip().upper()
            if method != "POST":
                continue

            captcha_input = None
            form_fields = {}
            for inp in form.find_all(["input", "textarea"]):
                name = inp.get("name", "")
                if not name:
                    continue
                form_fields[name] = inp.get("value", "test")
                if self.CAPTCHA_FIELD_PATTERNS.search(name):
                    captcha_input = name

            if not captcha_input:
                continue

            # Test bypass: submit the form completely omitting the CAPTCHA field
            test_body = {k: v for k, v in form_fields.items() if k != captcha_input}
            action_url = form.get("action") or endpoint.url

            bypass_resp, b_req, b_res = client.post(action_url, data=test_body)
            if not bypass_resp:
                continue

            # If omitting the captcha yields 200 or 302 without error messages like "invalid captcha"
            lower_text = bypass_resp.text.lower()
            captcha_error = any(w in lower_text for w in ["captcha", "robot", "verification failed"])

            if bypass_resp.status_code in (200, 302) and not captcha_error:
                findings.append(
                    self.create_finding(
                        title=f"Insecure / Bypassable CAPTCHA in Form (Field: '{captcha_input}')",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        url=endpoint.url,
                        method="POST",
                        parameter=captcha_input,
                        evidence=(
                            f"DOM & Traffic Evidence:\n"
                            f"Form Field Detected: '{captcha_input}'\n"
                            f"Bypass Submission: Form was submitted with '{captcha_input}' omitted.\n"
                            f"Server Response: HTTP {bypass_resp.status_code} accepted without requiring CAPTCHA verification."
                        ),
                        evidence_type=self.default_evidence_type,
                        description=(
                            "The application provides a CAPTCHA challenge in the HTML form, but does not strictly "
                            "validate its presence or correctness on the backend. Submitting the request with the "
                            "CAPTCHA parameter omitted allows automated submission bypass."
                        ),
                        remediation=(
                            "Strictly enforce CAPTCHA token verification on the backend server before processing form submissions. "
                            "Reject any requests where the CAPTCHA parameter is missing or empty."
                        ),
                        request_metadata=b_req,
                        response_metadata=b_res,
                    )
                )
                break

        return findings
