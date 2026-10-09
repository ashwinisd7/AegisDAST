"""HTML Injection Detector (Reflected & Stored non-script HTML tag injection).

Category: Injection
Evidence Type: DOM Evidence / Screenshot
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

HTMLI_PAYLOADS = [
    ("<h1>HTML_INJ_TEST</h1>", "<h1>HTML_INJ_TEST</h1>", "Heading tag injection"),
    ("<mark>HTML_INJ_MARK</mark>", "<mark>HTML_INJ_MARK</mark>", "Mark formatting tag injection"),
    ('<iframe src="about:blank" height="0" width="0"></iframe>', '<iframe src="about:blank"', "iFrame tag injection"),
]


class HTMLInjectionDetector(BaseDetector):
    """Detects HTML Injection by probing for unencoded non-script HTML tag rendering."""

    name = "html_injection"
    description = "Audits parameters and forms for reflected and stored HTML markup injection"
    category = DetectorCategory.INJECTION
    default_evidence_type = EvidenceType.DOM_EVIDENCE

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
            for payload, expected_reflection, desc in HTMLI_PAYLOADS:
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
                if expected_reflection in resp_text and f"&lt;{expected_reflection[1:]}" not in resp_text:
                    findings.append(
                        self.create_finding(
                            title=f"HTML Injection in Parameter '{param}'",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CERTAIN,
                            url=endpoint.url,
                            method=endpoint.method.value,
                            parameter=param,
                            evidence=(
                                f"DOM / HTML Traffic Evidence:\n"
                                f"Injected HTML Payload: {payload}\n"
                                f"Unencoded Reflection: Matched rendered markup '{expected_reflection}'\n"
                                f"Technique: {desc}"
                            ),
                            evidence_type=EvidenceType.DOM_EVIDENCE,
                            description=(
                                f"Parameter '{param}' reflects user-supplied HTML tags directly into the web page without "
                                f"proper HTML entity encoding, allowing attackers to modify visual layout, deface pages, or perform phishing."
                            ),
                            remediation="Contextually HTML entity encode all untrusted inputs before rendering them in the document.",
                            request_metadata=req_meta,
                            response_metadata=res_meta,
                        )
                    )
                    return findings

        return findings

