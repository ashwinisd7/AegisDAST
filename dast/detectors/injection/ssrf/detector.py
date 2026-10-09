"""Server-Side Request Forgery (SSRF) Detector (Taxonomy: injection).

Identifies parameters accepting external URLs and evaluates potential SSRF exposure.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from dast.detectors.base import BaseDetector
from dast.http_client import HTTPClient
from dast.models import Confidence, DetectorCategory, DetectorRequirement, Endpoint, EvidenceType, Finding, Severity


class SSRFDetector(BaseDetector):
    """Detects parameters vulnerable to Server-Side Request Forgery (SSRF)."""

    name = "ssrf"
    description = "Audits parameters accepting remote addresses for Server-Side Request Forgery vulnerabilities"
    category = DetectorCategory.INJECTION
    requirement = DetectorRequirement.REQUESTS
    default_evidence_type = EvidenceType.HTTP_TRAFFIC

    URL_PARAM_NAMES = re.compile(
        r"^(url|target|dest|destination|uri|feed|callback|webhook|host|domain|site|fetch|proxy|preview)$",
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
        """Audit candidate URL parameters for SSRF indicators."""
        findings: list[Finding] = []

        params = endpoint.params or {}
        for param_name, param_val in params.items():
            val_str = str(param_val)
            is_candidate_name = bool(self.URL_PARAM_NAMES.match(param_name))
            is_url_val = bool(val_str.startswith("http://") or val_str.startswith("https://"))

            if is_candidate_name or is_url_val:
                findings.append(
                    self.create_finding(
                        title=f"Potential SSRF Exposure on Parameter '{param_name}'",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        url=endpoint.url,
                        method=endpoint.method.value,
                        parameter=param_name,
                        evidence=(
                            f"HTTP Traffic Evidence:\n"
                            f"Parameter: {param_name}\n"
                            f"Current Value: {val_str}\n"
                            f"Endpoint: {endpoint.url}\n"
                            f"Reason: Parameter matches known remote resource fetch pattern."
                        ),
                        evidence_type=self.default_evidence_type,
                        description=(
                            f"The parameter '{param_name}' appears to accept remote network targets or URLs. "
                            "If the server fetches or queries this resource without strict egress filtering, "
                            "an attacker may access internal cloud metadata, internal networks, or localhost services."
                        ),
                        remediation=(
                            "Enforce a strict whitelist of allowed destination schemes, hostnames, and IP ranges. "
                            "Block loopback (127.0.0.1/localhost) and internal RFC1918 private subnets."
                        ),
                    )
                )

        return findings
