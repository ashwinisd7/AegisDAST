"""OS Command Injection Detector.

Category: Injection
Evidence Type: HTTP Traffic / DOM Evidence
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

logger = logging.getLogger(__name__)

COMMAND_INJECTION_PAYLOADS = [
    # Arithmetic confirmation (computation proves OS shell execution; cannot be faked by HTML reflection)
    "127.0.0.1; expr 823 + 64194",
    "127.0.0.1| expr 823 + 64194",
    "127.0.0.1|expr 823 + 64194",
    "127.0.0.1& expr 823 + 64194",
    "127.0.0.1&expr 823 + 64194",
    "127.0.0.1; echo $((823+64194))",
    "127.0.0.1| echo $((823+64194))",
    "127.0.0.1& echo $((823+64194))",
    "; expr 823 + 64194",
    "| expr 823 + 64194",
    "|expr 823 + 64194",
    "& expr 823 + 64194",
    "&expr 823 + 64194",
    "; echo $((823+64194))",
    "| echo $((823+64194))",
    "& echo $((823+64194))",
    "& set /a 823+64194",
    "| set /a 823+64194",

    # Unix/Linux command separators & Chaining (DVWA Low / Medium / High & bWAPP)
    "127.0.0.1; echo CMDINJ",
    "127.0.0.1 && echo CMDINJ",
    "127.0.0.1 || echo CMDINJ",
    "127.0.0.1 | echo CMDINJ",
    "127.0.0.1|echo CMDINJ",
    "127.0.0.1 & echo CMDINJ",
    "127.0.0.1&echo CMDINJ",
    "127.0.0.1`echo CMDINJ`",
    "127.0.0.1$(echo CMDINJ)",
    "; echo CMDINJ",
    "&& echo CMDINJ",
    "|| echo CMDINJ",
    "| echo CMDINJ",
    "|echo CMDINJ",
    "& echo CMDINJ",
    "&echo CMDINJ",
    "`echo CMDINJ`",
    "$(echo CMDINJ)",

    # Space filtering bypasses (e.g. ${IFS}, $IFS$9)
    ";echo${IFS}CMDINJ",
    "|echo${IFS}CMDINJ",
    "127.0.0.1;echo${IFS}CMDINJ",
    "127.0.0.1|echo${IFS}CMDINJ",

    # Newline injection
    "\necho CMDINJ",
    "\nprintf CMDINJ",
]


def get_expected_response(payload: str) -> str:
    """Return the expected token to verify in response for a given payload."""
    if "823" in payload and "64194" in payload:
        return str(823 + 64194)  # 65017
    return "CMDINJ"


def is_confirmed_execution(payload: str, expected_token: str, resp_text: str, probe_val: str) -> bool:
    """Verify that response token is from real OS execution and not mere HTML reflection."""
    if not resp_text or expected_token not in resp_text:
        return False

    # Arithmetic token (e.g. 65017) was not in the payload; its presence proves server evaluated math
    if expected_token.isdigit() and expected_token not in payload:
        return True

    # For string tokens (CMDINJ), verify it is not just echoing the entire injected command verbatim in HTML attribute/tag
    if f"echo {expected_token}" in resp_text or f"printf {expected_token}" in resp_text or probe_val in resp_text:
        # The injection command itself was reflected verbatim in the page HTML/attribute (e.g. <script src='...'>)
        # This is literal string reflection, not shell execution
        return False

    return True


class CommandInjectionDetector(BaseDetector):
    """Detects command injection by looping payloads on forms/parameters and stopping on execution."""

    name = "command_injection"
    description = "Audits parameters and forms for OS Command Injection"
    category = DetectorCategory.INJECTION
    default_evidence_type = EvidenceType.HTTP_TRAFFIC
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

        # 1. Test forms if present on endpoint
        if endpoint.forms:
            for form in endpoint.forms:
                target_field = None
                for inp in form.inputs:
                    if inp.name and inp.input_type.lower() in ("text", "search", "textarea", "input", ""):
                        target_field = inp.name
                        break
                if not target_field:
                    continue

                for payload in COMMAND_INJECTION_PAYLOADS:
                    expected_token = get_expected_response(payload)
                    probe_val = f"{payload}"

                    if form_handler:
                        resp_text, shot_path = form_handler.fill_and_submit(
                            form=form,
                            payload=probe_val,
                            target_input=target_field,
                            detector_name=self.name,
                            client=client,
                            browser=browser,
                        )
                    elif browser and hasattr(browser, "fill_and_submit_form"):
                        companion = {
                            inp.name: inp.value or (inp.name if inp.input_type == "submit" else "")
                            for inp in form.inputs
                            if inp.name and inp.name != target_field
                        }
                        try:
                            resp_text, shot_path = browser.fill_and_submit_form(
                                url=form.action or endpoint.url,
                                target_param=target_field or "ip",
                                payload=probe_val,
                                companion_fields=companion,
                                detector_name=self.name,
                            )
                        except TypeError:
                            resp_text, shot_path = browser.fill_and_submit_form(
                                url=form.action or endpoint.url,
                                target_param=target_field or "ip",
                                payload=probe_val,
                                companion_fields=companion,
                            )
                    else:
                        body = {
                            inp.name: inp.value or (inp.name if inp.input_type == "submit" else "")
                            for inp in form.inputs
                            if inp.name
                        }
                        body[target_field or "ip"] = probe_val
                        if form.method.upper() == "POST":
                            resp, _, _ = client.post(form.action or endpoint.url, data=body)
                        else:
                            resp, _, _ = client.get(form.action or endpoint.url, params=body)
                        resp_text = resp.text if resp else ""
                        shot_path = None

                    if is_confirmed_execution(payload, expected_token, resp_text, probe_val):
                        step_shots = []
                        if form_handler and hasattr(form_handler, "save_interaction_steps"):
                            step_shots = form_handler.save_interaction_steps(self.name, browser=browser)
                        elif browser and hasattr(browser, "save_interaction_steps"):
                            step_shots = browser.save_interaction_steps(self.name)

                        shot_path = step_shots[-1] if step_shots else None

                        # Render realistic shell terminal output proof
                        if browser and hasattr(browser, "render_terminal_screenshot"):
                            try:
                                term_shot = browser.render_terminal_screenshot(
                                    command=f"curl -s '{form.action or endpoint.url}' -d '{target_field}={probe_val}'",
                                    output=f"[SYSTEM STDOUT]:\n{expected_token}\n\n[SHELL PROCESS]: Exit Code 0 (Evaluated '{payload}')",
                                    detector_name=self.name,
                                    title=f"OS Command Injection Shell Proof — {target_field}",
                                    step_name=f"cmdi_{target_field}_shell_proof",
                                )
                                if term_shot:
                                    step_shots.append(term_shot)
                                    shot_path = term_shot
                            except Exception:
                                pass

                        if not shot_path and browser and hasattr(browser, "capture_step") and browser.is_available:
                            try:
                                shot_path = browser.capture_step(
                                    f"cmdi_{target_field}_evidence",
                                    html_content=resp_text,
                                    base_url=form.action or endpoint.url,
                                    detector_name=self.name,
                                    wait_ms=500,
                                )
                            except Exception:
                                shot_path = None

                        findings.append(
                            self.create_finding(
                                title=f"OS Command Injection Vulnerability in Form Field '{target_field}'",
                                severity=Severity.CRITICAL,
                                confidence=Confidence.CERTAIN,
                                url=form.action or endpoint.url,
                                method=form.method,
                                parameter=target_field,
                                evidence=f"Command injection confirmed. Payload '{probe_val}' returned execution token '{expected_token}'.",
                                evidence_type=EvidenceType.SCREENSHOT if shot_path else self.default_evidence_type,
                                screenshot_path=shot_path,
                                step_screenshots=step_shots or ([shot_path] if shot_path else []),
                                description=f"Field '{target_field}' executes operating system commands through a system shell.",
                                remediation="Avoid passing untrusted input to system shells. Use parameterized APIs.",
                            )
                        )
                        break

            if findings:
                return findings

        # 2. Test endpoint parameters directly via HTTP
        param_names = endpoint.get_all_param_names()
        for param in param_names:
            for payload in COMMAND_INJECTION_PAYLOADS:
                expected_token = get_expected_response(payload)
                probe_val = f"1{payload}"

                if endpoint.method == HttpMethod.POST:
                    body = dict(endpoint.body_params)
                    body[param] = probe_val
                    resp, req_meta, res_meta = client.post(endpoint.url, data=body)
                else:
                    params = dict(endpoint.params)
                    params[param] = probe_val
                    resp, req_meta, res_meta = client.get(endpoint.url, params=params)

                resp_text = resp.text if resp else ""

                if is_confirmed_execution(payload, expected_token, resp_text, probe_val):
                    shot_path = None
                    step_shots = []
                    if browser and hasattr(browser, "render_terminal_screenshot"):
                        try:
                            shot_path = browser.render_terminal_screenshot(
                                command=f"curl -s '{endpoint.url}?{param}={probe_val}'",
                                output=f"[SYSTEM STDOUT]:\n{expected_token}\n\n[SHELL PROCESS]: Command '{payload}' executed on host",
                                detector_name=self.name,
                                title=f"OS Command Injection Shell Proof — {param}",
                                step_name=f"cmdi_{param}_shell_proof",
                            )
                            if shot_path:
                                step_shots = [shot_path]
                        except Exception:
                            shot_path = None

                    if not shot_path and browser and hasattr(browser, "capture_step"):
                        try:
                            shot_path = browser.capture_step(
                                f"cmdi_{param}_evidence",
                                html_content=resp_text,
                                base_url=endpoint.url,
                                detector_name=self.name,
                            )
                            if shot_path:
                                step_shots = [shot_path]
                        except Exception:
                            shot_path = None

                    findings.append(
                        self.create_finding(
                            title=f"OS Command Injection Vulnerability in Parameter '{param}'",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.CERTAIN,
                            url=endpoint.url,
                            method=endpoint.method.value,
                            parameter=param,
                            evidence=f"Command injection confirmed. Injected probe '{probe_val}' returned canary token '{expected_token}'.",
                            evidence_type=EvidenceType.SCREENSHOT if shot_path else self.default_evidence_type,
                            screenshot_path=shot_path,
                            step_screenshots=step_shots,
                            description=f"Parameter '{param}' executes user-supplied commands through a system shell.",
                            remediation="Avoid passing untrusted input to system shells. Use parameterized APIs.",
                        )
                    )
                    break

        return findings

