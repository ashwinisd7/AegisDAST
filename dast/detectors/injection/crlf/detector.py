"""CRLF & HTTP Response Splitting Detector.

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

CRLF_PAYLOADS = [
    ("%0d%0aSet-Cookie:dast_crlf=confirmed", "Set-Cookie", "dast_crlf=confirmed"),
    ("%0d%0aX-Injected-Header:dast_crlf", "X-Injected-Header", "dast_crlf"),
    ("\r\nSet-Cookie:dast_crlf=confirmed", "Set-Cookie", "dast_crlf=confirmed"),
]


class CRLFDetector(BaseDetector):
    """Detects HTTP Response Splitting and CRLF Injection in headers and redirects."""

    name = "crlf"
    description = "Audits parameters for CRLF Injection and HTTP Response Splitting"
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
        if not param_names:
            return findings

        for param in param_names:
            for payload, target_hdr, target_val in CRLF_PAYLOADS:
                if endpoint.method == HttpMethod.POST:
                    body = dict(endpoint.body_params)
                    body[param] = payload
                    resp, req_meta, res_meta = client.post(endpoint.url, data=body)
                else:
                    params = dict(endpoint.params)
                    params[param] = payload
                    resp, req_meta, res_meta = client.get(endpoint.url, params=params)

                if not resp:
                    continue

                # Check if injected header was accepted into HTTP response headers
                hdr_val = resp.headers.get(target_hdr, "")
                if target_val in hdr_val or (resp.raw and target_val.encode() in resp.raw):
                    findings.append(
                        self.create_finding(
                            title=f"CRLF Injection / HTTP Response Splitting in Parameter '{param}'",
                            severity=Severity.HIGH,
                            confidence=Confidence.CERTAIN,
                            url=endpoint.url,
                            method=endpoint.method.value,
                            parameter=param,
                            evidence=(
                                f"HTTP Header Evidence:\n"
                                f"Injected Payload: {payload}\n"
                                f"Observed Injected Header: '{target_hdr}: {hdr_val}'"
                            ),
                            evidence_type=EvidenceType.HTTP_TRAFFIC,
                            description=(
                                f"Parameter '{param}' is vulnerable to CRLF Injection. Unfiltered carriage-return and line-feed "
                                f"characters allow attackers to inject arbitrary HTTP response headers or split the response body."
                            ),
                            remediation="Strip CR (\\r) and LF (\\n) characters from all inputs used to construct HTTP response headers or redirects.",
                            request_metadata=req_meta,
                            response_metadata=res_meta,
                        )
                    )
                    return findings

        return findings

