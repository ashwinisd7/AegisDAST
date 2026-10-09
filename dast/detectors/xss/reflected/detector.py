"""Reflected Cross-Site Scripting (XSS) Detector.

Category: XSS
Evidence Type: Screenshot / DOM Evidence
"""

from __future__ import annotations

import logging
from typing import Any

from dast.detectors.base import BaseDetector
from dast.http_client import HTTPClient
from dast.models import (
    Confidence,
    DetectorCategory,
    DetectorRequirement,
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

logger = logging.getLogger(__name__)


class ReflectedXSSDetector(BaseDetector):
    """Detects reflected XSS using visual payloads and pre-filtered symbol/tag probing."""

    name = "xss"
    description = "Detects reflected XSS by injecting visual payloads into forms and parameters"
    category = DetectorCategory.XSS
    default_evidence_type = EvidenceType.SCREENSHOT
    requirement = DetectorRequirement.BROWSER

    def scan(
        self,
        endpoint: Endpoint,
        client: HTTPClient,
        browser: Any | None = None,
        form_handler: Any | None = None,
        **kwargs: Any,
    ) -> list[Finding]:
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

                # Pre-filter symbols & tags using fast HTTP probe (without taking screenshots)
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
                        shot_path = None

                    if is_xss_executed(resp_text, payload, browser=browser):
                        step_shots = []
                        if form_handler and hasattr(form_handler, "save_interaction_steps"):
                            step_shots = form_handler.save_interaction_steps(self.name, browser=browser)
                        elif browser and hasattr(browser, "save_interaction_steps"):
                            step_shots = browser.save_interaction_steps(self.name)

                        shot_path = step_shots[-1] if step_shots else None
                        if not shot_path and browser and hasattr(browser, "capture_step") and browser.is_available:
                            try:
                                shot_path = browser.capture_step(
                                    f"xss_{target_field}_evidence",
                                    html_content=resp_text,
                                    base_url=form.action or endpoint.url,
                                    detector_name=self.name,
                                )
                            except Exception:
                                shot_path = None

                        if browser and getattr(browser, "last_dialog", None):
                            d = browser.last_dialog
                            evidence_msg = f"Reflected XSS confirmed. Injected payload '{payload}' triggered JavaScript dialog {d.type}('{d.message}') in browser DOM."
                        elif browser and hasattr(browser, "check_xss_dom_execution") and browser.check_xss_dom_execution():
                            evidence_msg = f"Visual XSS confirmed. Injected payload '{payload}' executed in DOM with visual indicators."
                        else:
                            evidence_msg = f"Reflected XSS confirmed. Injected payload '{payload}' reflected without encoding in response body."

                        findings.append(
                            self.create_finding(
                                title=f"Reflected Cross-Site Scripting (XSS) in Form Field '{target_field}'",
                                severity=Severity.HIGH,
                                confidence=Confidence.CERTAIN,
                                url=form.action or endpoint.url,
                                method=form.method,
                                parameter=target_field,
                                evidence=evidence_msg,
                                evidence_type=EvidenceType.SCREENSHOT if shot_path else self.default_evidence_type,
                                screenshot_path=shot_path,
                                step_screenshots=step_shots or ([shot_path] if shot_path else []),
                                description=f"Form field '{target_field}' is vulnerable to reflected Cross-Site Scripting (XSS).",
                                remediation="Contextually encode all user-supplied output (e.g. HTML entity encoding) and enforce a strict CSP.",
                            )
                        )
                        break

            if findings:
                return findings

        # 2. Test endpoint parameters directly via HTTP
        param_names = endpoint.get_all_param_names()
        for param in param_names:
            candidate_payloads = filter_applicable_xss_payloads(
                client=client,
                url=endpoint.url,
                method=endpoint.method.value,
                param=param,
                default_data=dict(endpoint.body_params if endpoint.method == HttpMethod.POST else endpoint.params),
            )

            for payload in candidate_payloads:
                if browser and hasattr(browser, "clear_dialogs"):
                    browser.clear_dialogs()

                if endpoint.method == HttpMethod.POST:
                    body = dict(endpoint.body_params)
                    body[param] = payload
                    resp, req_meta, res_meta = client.post(endpoint.url, data=body)
                else:
                    params = dict(endpoint.params)
                    params[param] = payload
                    resp, req_meta, res_meta = client.get(endpoint.url, params=params)

                resp_text = resp.text if resp else ""

                if is_xss_executed(resp_text, payload, browser=browser):
                    shot_path = None
                    if browser and hasattr(browser, "capture_step"):
                        try:
                            shot_path = browser.capture_step(
                                f"xss_{param}_evidence",
                                html_content=resp_text,
                                base_url=endpoint.url,
                                detector_name=self.name,
                            )
                        except Exception:
                            try:
                                shot_path = browser.capture_step(
                                    f"xss_{param}_evidence",
                                    html_content=resp_text,
                                    base_url=endpoint.url,
                                )
                            except Exception:
                                shot_path = None

                    if browser and getattr(browser, "last_dialog", None):
                        d = browser.last_dialog
                        evidence_msg = f"Screenshot & DOM Evidence:\nReflected XSS confirmed. Injected payload '{payload}' triggered JavaScript dialog {d.type}('{d.message}')."
                    elif browser and hasattr(browser, "check_xss_dom_execution") and browser.check_xss_dom_execution():
                        evidence_msg = f"Screenshot & DOM Evidence:\nVisual XSS confirmed. Injected payload '{payload}' executed in DOM with visual indicators."
                    else:
                        evidence_msg = f"Screenshot & DOM Evidence:\nReflected XSS confirmed. Injected payload '{payload}' reflected without encoding in response body."

                    findings.append(
                        self.create_finding(
                            title=f"Reflected Cross-Site Scripting (XSS) in Parameter '{param}'",
                            severity=Severity.HIGH,
                            confidence=Confidence.CERTAIN,
                            url=endpoint.url,
                            method=endpoint.method.value,
                            parameter=param,
                            evidence=evidence_msg,
                            evidence_type=self.default_evidence_type,
                            screenshot_path=shot_path,
                            description=f"Parameter '{param}' is vulnerable to reflected Cross-Site Scripting (XSS).",
                            remediation="Contextually encode all user-supplied output and enforce a strict Content Security Policy.",
                            request_metadata=req_meta,
                            response_metadata=res_meta,
                        )
                    )
                    break

        return findings

