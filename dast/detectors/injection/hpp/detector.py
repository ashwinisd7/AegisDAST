"""HTTP Parameter Pollution (HPP) Detector.

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


class HPPDetector(BaseDetector):
    """Detects HTTP Parameter Pollution by injecting duplicate query parameters."""

    name = "hpp"
    description = "Audits parameters for HTTP Parameter Pollution (HPP) precedence overrides"
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
            # Test duplicate parameter submission with distinct values
            polluted_url = f"{endpoint.url}?{param}=val1&{param}=val2"
            resp, req_meta, res_meta = client.get(polluted_url)
            if not resp or not resp.text:
                continue

            resp_text = resp.text
            # If both or the second overridden value is reflected or processed differently
            if "val2" in resp_text and "val1" not in resp_text:
                findings.append(
                    self.create_finding(
                        title=f"HTTP Parameter Pollution (HPP) in Parameter '{param}'",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        url=endpoint.url,
                        method=endpoint.method.value,
                        parameter=param,
                        evidence=(
                            f"HTTP Traffic Evidence (HPP):\n"
                            f"Submitted Polluted Query: {polluted_url}\n"
                            f"Observation: Backend prioritized the second duplicate parameter 'val2' over 'val1'."
                        ),
                        evidence_type=EvidenceType.HTTP_TRAFFIC,
                        description=(
                            f"Parameter '{param}' is susceptible to HTTP Parameter Pollution (HPP). Supplying duplicate "
                            f"parameters causes the application to override earlier parameters, which can be used to bypass WAFs or business logic."
                        ),
                        remediation="Strictly validate parameter count and reject or normalize repeated duplicate query parameters.",
                        request_metadata=req_meta,
                        response_metadata=res_meta,
                    )
                )
                return findings

        return findings

