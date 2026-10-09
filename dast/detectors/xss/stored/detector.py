"""Stored Cross-Site Scripting (XSS) Detector.

Category: XSS
Evidence Type: Screenshot (Persistent injection reflection evidence)
"""

from __future__ import annotations

import secrets
from typing import Any

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


from dast.detectors.xss.common import (
    XSS_PAYLOADS,
    filter_applicable_xss_payloads,
    is_xss_executed,
)


class StoredXSSDetector(BaseDetector):
    """Detects Stored XSS via persistent state submission and subsequent retrieval checks."""

    name = "stored_xss"
    description = "Audits POST endpoints and state-changing forms for persistent unencoded stored markup"
    category = DetectorCategory.XSS
    default_evidence_type = EvidenceType.SCREENSHOT

    def scan(
        self,
        endpoint: Endpoint,
        client: HTTPClient,
        browser: Any | None = None,
        form_handler: Any | None = None,
        pages: list[Any] | None = None,
        **kwargs: Any,
    ) -> list[Finding]:
        """Audit endpoint for persistent stored XSS reflection."""
        findings: list[Finding] = []

        # 1. Test forms discovered on the endpoint
        if endpoint.forms:
            for form in endpoint.forms:
                target_field = None
                for inp in form.inputs:
                    if inp.name and inp.input_type.lower() in ("text", "search", "textarea", "input", ""):
                        target_field = inp.name
                        break
                if not target_field:
                    continue

                companion_base = {
                    inp.name: inp.value or (inp.name if inp.input_type == "submit" else "")
                    for inp in form.inputs
                    if inp.name and inp.name != target_field
                }

                # Pre-filter symbols & tags using fast probe
                candidate_payloads = filter_applicable_xss_payloads(
                    client=client,
                    url=form.action or endpoint.url,
                    method=form.method,
                    param=target_field,
                    default_data=companion_base,
                )

                for payload in candidate_payloads:
                    if browser and hasattr(browser, "clear_dialogs"):
                        browser.clear_dialogs()

                    if form_handler:
                        resp_text, shot_path = form_handler.fill_and_submit(
                            form=form,
                            payload=payload,
                            target_input=target_field,
                            detector_name=self.name,
                            client=client,
                            browser=browser,
                        )
                    elif browser and hasattr(browser, "fill_and_submit_form"):
                        try:
                            resp_text, shot_path = browser.fill_and_submit_form(
                                url=form.action or endpoint.url,
                                target_param=target_field or "q",
                                payload=payload,
                                companion_fields=companion_base,
                                detector_name=self.name,
                            )
                        except TypeError:
                            resp_text, shot_path = browser.fill_and_submit_form(
                                url=form.action or endpoint.url,
                                target_param=target_field or "q",
                                payload=payload,
                                companion_fields=companion_base,
                            )
                    else:
                        body = dict(companion_base)
                        body[target_field or "q"] = payload
                        if form.method.upper() == "POST":
                            resp, _, _ = client.post(form.action or endpoint.url, data=body)
                        else:
                            resp, _, _ = client.get(form.action or endpoint.url, params=body)
                        resp_text = resp.text if resp else ""

                    # Poll target page to verify persistent storage / DOM execution
                    poll_resp, _, _ = client.get(form.action or endpoint.url)
                    poll_text = poll_resp.text if poll_resp else ""

                    # Stored XSS strictly requires payload persistence in subsequent GET retrieval (poll_text)
                    if poll_text and is_xss_executed(poll_text, payload, browser=browser):
                        step_shots = []
                        if form_handler and hasattr(form_handler, "save_interaction_steps"):
                            step_shots = form_handler.save_interaction_steps(self.name, browser=browser)
                        elif browser and hasattr(browser, "save_interaction_steps"):
                            step_shots = browser.save_interaction_steps(self.name)

                        shot_path = step_shots[-1] if step_shots else None
                        if not shot_path and browser and hasattr(browser, "capture_step") and browser.is_available:
                            try:
                                shot_path = browser.capture_step(
                                    f"stored_xss_{target_field}_evidence",
                                    html_content=poll_text,
                                    base_url=form.action or endpoint.url,
                                    detector_name=self.name,
                                )
                            except Exception:
                                shot_path = None

                        if browser and getattr(browser, "last_dialog", None):
                            d = browser.last_dialog
                            evidence_msg = f"Stored XSS confirmed. Injected payload '{payload}' persisted in backend and triggered JavaScript dialog {d.type}('{d.message}') upon retrieval."
                        elif browser and hasattr(browser, "check_xss_dom_execution") and browser.check_xss_dom_execution():
                            evidence_msg = f"Stored XSS confirmed. Injected payload '{payload}' persisted in backend and executed visual DOM indicators."
                        else:
                            evidence_msg = f"Stored XSS confirmed. Injected payload '{payload}' persisted in backend and rendered without encoding in subsequent page retrieval."

                        findings.append(
                            self.create_finding(
                                title=f"Stored Cross-Site Scripting (XSS) in Form Field '{target_field}'",
                                severity=Severity.HIGH,
                                confidence=Confidence.CERTAIN,
                                url=form.action or endpoint.url,
                                method=form.method,
                                parameter=target_field,
                                evidence=evidence_msg,
                                evidence_type=EvidenceType.SCREENSHOT if shot_path else self.default_evidence_type,
                                screenshot_path=shot_path,
                                step_screenshots=step_shots or ([shot_path] if shot_path else []),
                                description=f"Form field '{target_field}' stores arbitrary HTML/JS markup and renders it unencoded.",
                                remediation="Contextually encode all user-supplied output (HTML entity encoding) and sanitize storage inputs.",
                            )
                        )
                        break

            if findings:
                return findings

        # 2. Test endpoint parameters directly via HTTP
        param_names = endpoint.get_all_param_names()
        for param in param_names:
            is_post = (param in endpoint.body_params) or (endpoint.method == HttpMethod.POST and not endpoint.params)
            method_str = "POST" if is_post else "GET"

            candidate_payloads = filter_applicable_xss_payloads(
                client=client,
                url=endpoint.url,
                method=method_str,
                param=param,
                default_data=dict(endpoint.body_params if is_post else endpoint.params),
            )

            for payload in candidate_payloads:
                if browser and hasattr(browser, "clear_dialogs"):
                    browser.clear_dialogs()

                if is_post:
                    test_body = dict(endpoint.body_params)
                    test_body[param] = payload
                    submit_resp, req_meta, res_meta = client.post(endpoint.url, data=test_body)
                else:
                    test_params = dict(endpoint.params)
                    test_params[param] = payload
                    submit_resp, req_meta, res_meta = client.get(endpoint.url, params=test_params)

                if not submit_resp:
                    continue

                # Subsequent GET request to check persistence
                poll_resp, _, poll_meta = client.get(endpoint.url)
                if not poll_resp or not poll_resp.text:
                    continue

                if is_xss_executed(poll_resp.text, payload, browser=browser):
                    shot_path = None
                    if browser and hasattr(browser, "capture_step"):
                        try:
                            shot_path = browser.capture_step(
                                f"stored_xss_{param}_evidence",
                                html_content=poll_resp.text,
                                base_url=endpoint.url,
                                detector_name=self.name,
                            )
                        except Exception:
                            try:
                                shot_path = browser.capture_step(
                                    f"stored_xss_{param}_evidence",
                                    html_content=poll_resp.text,
                                    base_url=endpoint.url,
                                )
                            except Exception:
                                shot_path = None

                    if browser and getattr(browser, "last_dialog", None):
                        d = browser.last_dialog
                        evidence_msg = (
                            f"Persistent Storage Evidence:\n"
                            f"Submitted {method_str} payload in parameter '{param}': {payload}\n"
                            f"Observed in subsequent GET retrieval: Triggered JavaScript dialog {d.type}('{d.message}')."
                        )
                    else:
                        evidence_msg = (
                            f"Persistent Storage Evidence:\n"
                            f"Submitted {method_str} payload in parameter '{param}': {payload}\n"
                            f"Observed in subsequent GET retrieval: Payload persisted and executed in response HTML."
                        )

                    findings.append(
                        self.create_finding(
                            title=f"Stored Cross-Site Scripting (XSS) in Parameter '{param}'",
                            severity=Severity.HIGH,
                            confidence=Confidence.CERTAIN,
                            url=endpoint.url,
                            method=method_str,
                            parameter=param,
                            evidence=evidence_msg,
                            evidence_type=self.default_evidence_type,
                            screenshot_path=shot_path,
                            description=(
                                f"Parameter '{param}' stores arbitrary HTML markup in backend storage and re-renders "
                                "it unencoded to subsequent viewers, establishing a persistent Stored XSS vulnerability."
                            ),
                            remediation=(
                                "Apply context-aware output encoding on every rendered view, sanitize input with "
                                "a robust HTML sanitizer (e.g., Bleach/DOMPurify), and deploy Content-Security-Policy."
                            ),
                            request_metadata=req_meta,
                            response_metadata=poll_meta,
                        )
                    )
                    break

        return findings
