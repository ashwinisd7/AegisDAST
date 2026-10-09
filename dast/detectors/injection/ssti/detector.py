"""Server-Side Template Injection (SSTI) Detector.

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

SSTI_PAYLOADS = [
    ("{{7*77}}", "539", "Jinja2 / Twig / Django double brace math evaluation"),
    ("${7*77}", "539", "Smarty / FreeMarker / MVEL expression evaluation"),
    ("<%= 7*77 %>", "539", "ERB / ASP / EJS expression evaluation"),
    ("#{7*77}", "539", "Ruby / Pug expression evaluation"),
    ("*{7*77}", "539", "Spring / Thymeleaf expression evaluation"),
]


class SSTIDetector(BaseDetector):
    """Detects Server-Side Template Injection (SSTI) by verifying mathematical expression resolution."""

    name = "ssti"
    description = "Audits parameters and forms for Server-Side Template Injection (SSTI) execution"
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
            for payload, expected_token, technique_desc in SSTI_PAYLOADS:
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
                    findings.append(
                        self.create_finding(
                            title=f"Server-Side Template Injection (SSTI) in Parameter '{param}'",
                            severity=Severity.HIGH,
                            confidence=Confidence.CERTAIN,
                            url=endpoint.url,
                            method=endpoint.method.value,
                            parameter=param,
                            evidence=(
                                f"HTTP Traffic Evidence (SSTI):\n"
                                f"Injected Template Expression: {payload}\n"
                                f"Resolved Result: Matched evaluated token '{expected_token}'\n"
                                f"Technique: {technique_desc}"
                            ),
                            evidence_type=EvidenceType.HTTP_TRAFFIC,
                            description=(
                                f"Parameter '{param}' is vulnerable to Server-Side Template Injection (SSTI). "
                                f"The server-side template engine parsed and executed the expression '{payload}', "
                                f"evaluating it to '{expected_token}' in the response body."
                            ),
                            remediation="Pass untrusted user input as template data variables rather than concatenating user input directly into template strings.",
                            request_metadata=req_meta,
                            response_metadata=res_meta,
                        )
                    )
                    return findings

        return findings

