"""Cross-Site Request Forgery (CSRF) Detector.

Category: Cookie-Based
Evidence Type: DOM Evidence (Form HTML snippet lacking anti-CSRF token protection)
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


class CSRFDetector(BaseDetector):
    """Detects state-changing HTML forms and sensitive endpoints lacking anti-CSRF tokens."""

    name = "csrf"
    description = "Audits state-changing POST and sensitive GET forms/endpoints for missing anti-CSRF token protections"
    category = DetectorCategory.COOKIE_BASED
    default_evidence_type = EvidenceType.DOM_EVIDENCE

    CSRF_TOKEN_NAMES = re.compile(
        r"(csrf|xsrf|token|_token|authenticity_token|nonce|anti_forgery|user_token)",
        re.I,
    )

    SENSITIVE_PARAM_NAMES = re.compile(
        r"(pass|pwd|password|password_new|password_conf|email|user|admin|role|priv|delete|remove|update|edit|change|transfer|amount|credit|pin|secret|account|token|auth|key)",
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
        """Audit forms and parameters on endpoint for missing anti-CSRF tokens."""
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

            # Check inputs
            has_csrf_token = False
            has_password_input = False
            has_sensitive_input = False
            input_names: list[str] = []

            for inp in form.find_all(["input", "textarea", "select"]):
                inp_type = inp.get("type", "").lower()
                name = inp.get("name", "")
                if name:
                    input_names.append(name)
                if inp_type == "password":
                    has_password_input = True
                if self.CSRF_TOKEN_NAMES.search(name):
                    has_csrf_token = True
                if self.SENSITIVE_PARAM_NAMES.search(name):
                    has_sensitive_input = True

            # If it already has an anti-CSRF token, it is protected
            if has_csrf_token:
                continue

            # Determine if this form requires CSRF protection:
            # 1. Any POST form with non-empty actionable inputs
            # 2. Any GET form with password inputs or sensitive parameter names (e.g., DVWA password change)
            is_state_changing = False
            if method == "POST":
                is_state_changing = True
            elif method == "GET":
                if has_password_input or has_sensitive_input:
                    is_state_changing = True

            if not is_state_changing:
                continue

            action = form.get("action", "") or endpoint.url
            form_snippet = str(form)[:350]
            shot_path = None
            if browser and hasattr(browser, "capture_step") and browser.is_available:
                try:
                    shot_path = browser.capture_step(
                        "csrf_form_evidence",
                        html_content=resp.text,
                        base_url=endpoint.url,
                        detector_name=self.name,
                    )
                except Exception:
                    shot_path = None

            sev = Severity.HIGH if (method == "GET" and (has_password_input or has_sensitive_input)) else Severity.MEDIUM
            title = (
                "Cross-Site Request Forgery (CSRF) via Sensitive GET Form"
                if method == "GET"
                else "Missing Anti-CSRF Token in State-Changing Form"
            )

            desc = (
                f"The form uses HTTP {method} to perform sensitive state-changing operations "
                f"without including a synchronized anti-CSRF token. "
                + (
                    "Using HTTP GET for sensitive state modification allows trivial one-click/zero-click "
                    "exploitation via hyperlinks, <img>, or <iframe> tags without user awareness."
                    if method == "GET"
                    else "If user sessions rely on ambient credentials (cookies), an external attacker can "
                    "induce victim browsers to perform unauthorized actions."
                )
            )

            findings.append(
                self.create_finding(
                    title=title,
                    severity=sev,
                    confidence=Confidence.CERTAIN,
                    url=endpoint.url,
                    method=method,
                    evidence=(
                        f"DOM Form Evidence:\n"
                        f"Form Method: {method}\n"
                        f"Form Action: {action}\n"
                        f"Input Fields: {', '.join(input_names) if input_names else 'N/A'}\n"
                        f"Form HTML Snippet:\n{form_snippet}...\n"
                        "Observed: No hidden anti-CSRF token input field detected inside form."
                    ),
                    evidence_type=EvidenceType.SCREENSHOT if shot_path else self.default_evidence_type,
                    screenshot_path=shot_path,
                    description=desc,
                    remediation=(
                        "1. Convert sensitive state-changing actions from HTTP GET to HTTP POST.\n"
                        "2. Include cryptographically random, unpredictable anti-CSRF tokens in all state-changing HTML forms.\n"
                        "3. Enforce 'SameSite=Lax' or 'SameSite=Strict' on session cookies.\n"
                        "4. Require re-authentication (current password) for critical account actions (e.g., password change, email change)."
                    ),
                    request_metadata=req_meta,
                    response_metadata=res_meta,
                )
            )
            break

        return findings
