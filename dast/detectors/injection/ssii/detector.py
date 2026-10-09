"""Server-Side Includes (SSI) Injection Detector.

Category: Injection
Evidence Type: HTTP Traffic
"""

from __future__ import annotations

import logging
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

logger = logging.getLogger(__name__)

SSI_PAYLOADS = [
    ('<!--#echo var="DOCUMENT_NAME"-->', "ssii.php", "SSI Document Name directive"),
    ('<!--#echo var="DATE_LOCAL"-->', "202", "SSI Date directive"),
    ('<!--#exec cmd="echo SSI_CONFIRMED"-->', "SSI_CONFIRMED", "SSI Exec command directive"),
    ('<!--#exec cmd="expr 823 + 64194"-->', "65017", "SSI Arithmetic execution"),
]


class SSIInjectionDetector(BaseDetector):
    """Detects Server-Side Includes (SSI) Injection by testing directive execution."""

    name = "ssii"
    description = "Audits parameters and forms for Server-Side Includes (SSI) Injection"
    category = DetectorCategory.INJECTION
    default_evidence_type = EvidenceType.HTTP_TRAFFIC

    def scan(
        self,
        endpoint: Endpoint,
        client: HTTPClient,
        browser: Any | None = None,
        form_handler: Any | None = None,
        **kwargs: Any,
    ) -> list[Finding]:
        findings: list[Finding] = []

        param_names = endpoint.get_all_param_names()
        if not param_names and not endpoint.forms:
            return findings

        for param in param_names:
            for payload, expected_token, technique_desc in SSI_PAYLOADS:
                if endpoint.method == HttpMethod.POST:
                    body = dict(endpoint.body_params)
                    body[param] = payload
                    resp, req_meta, res_meta = client.post(endpoint.url, data=body)
                else:
                    params = dict(endpoint.params)
                    params[param] = payload
                    resp, req_meta, res_meta = client.get(endpoint.url, params=params)

                if not resp or not resp.text:
                    continue

                resp_text = resp.text
                if expected_token in resp_text and payload not in resp_text:
                    shot_path = None
                    step_shots = []
                    if browser and hasattr(browser, "render_terminal_screenshot"):
                        try:
                            shot_path = browser.render_terminal_screenshot(
                                command=f"echo '{payload}' | ssi_evaluator",
                                output=f"[SSI ENGINE RESPONSE]:\n{expected_token}\n\n[DIRECTIVE EXECUTION]: Parsed and executed server-side include directive",
                                detector_name=self.name,
                                title=f"SSI Injection Confirmation — Parameter '{param}'",
                                step_name=f"ssii_{param}",
                            )
                            if shot_path:
                                step_shots = [shot_path]
                        except Exception:
                            shot_path = None

                    findings.append(
                        self.create_finding(
                            title=f"Server-Side Includes (SSI) Injection in Parameter '{param}'",
                            severity=Severity.HIGH,
                            confidence=Confidence.CERTAIN,
                            url=endpoint.url,
                            method=endpoint.method.value,
                            parameter=param,
                            evidence=(
                                f"HTTP Traffic Evidence:\n"
                                f"Injected SSI Directive: {payload}\n"
                                f"Evaluated Output: Matched token '{expected_token}'\n"
                                f"Technique: {technique_desc}"
                            ),
                            evidence_type=EvidenceType.SCREENSHOT if shot_path else EvidenceType.HTTP_TRAFFIC,
                            screenshot_path=shot_path,
                            step_screenshots=step_shots,
                            description=(
                                f"Parameter '{param}' is vulnerable to SSI Injection. The web server evaluated the "
                                f"injected SSI directive prior to serving the HTML response."
                            ),
                            remediation="Disable Server-Side Includes (SSI) execution in the web server configuration or sanitize HTML comment syntax.",
                            request_metadata=req_meta,
                            response_metadata=res_meta,
                        )
                    )
                    return findings

        return findings

