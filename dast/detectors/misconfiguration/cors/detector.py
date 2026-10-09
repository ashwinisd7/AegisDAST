"""CORS Configuration Detector (Taxonomy: misconfiguration).

Audits Cross-Origin Resource Sharing (CORS) headers for insecure origins
and credential leakage configurations.
"""

from __future__ import annotations

from typing import Any

from dast.detectors.base import BaseDetector
from dast.http_client import HTTPClient
from dast.models import Confidence, DetectorCategory, DetectorRequirement, Endpoint, EvidenceType, Finding, Severity


class CORSDetector(BaseDetector):
    """Detects overly permissive or insecure CORS policies."""

    name = "cors"
    description = "Audits Cross-Origin Resource Sharing headers for insecure origin trust"
    category = DetectorCategory.MISCONFIGURATION
    requirement = DetectorRequirement.REQUESTS
    default_evidence_type = EvidenceType.HTTP_TRAFFIC

    PROBE_ORIGIN = "https://untrusted-audit-origin.example"

    def scan(
        self,
        endpoint: Endpoint,
        client: HTTPClient,
        browser: Any | None = None,
        session: Any | None = None,
        **kwargs: Any,
    ) -> list[Finding]:
        """Test endpoint for CORS misconfigurations."""
        findings: list[Finding] = []

        headers = {"Origin": self.PROBE_ORIGIN}
        resp, req_meta, res_meta = client.get(endpoint.url, headers=headers)
        if not resp:
            return findings

        allow_origin = resp.headers.get("Access-Control-Allow-Origin", "").strip()
        allow_credentials = resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"

        # Case 1: Arbitrary origin reflection with credentials
        if allow_origin == self.PROBE_ORIGIN and allow_credentials:
            findings.append(
                self.create_finding(
                    title="Insecure CORS: Arbitrary Origin Reflected with Credentials",
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    url=endpoint.url,
                    method=endpoint.method.value,
                    evidence=(
                        f"HTTP Traffic Evidence:\n"
                        f"Request Header: Origin: {self.PROBE_ORIGIN}\n"
                        f"Response Header: Access-Control-Allow-Origin: {allow_origin}\n"
                        f"Response Header: Access-Control-Allow-Credentials: true"
                    ),
                    evidence_type=self.default_evidence_type,
                    description=(
                        "The application dynamically reflects arbitrary untrusted origins in "
                        "Access-Control-Allow-Origin while permitting credentials, allowing cross-site data theft."
                    ),
                    remediation=(
                        "Validate origin against a strict whitelist of trusted domains and avoid reflecting "
                        "the request origin header dynamically."
                    ),
                    request_metadata=req_meta,
                    response_metadata=res_meta,
                )
            )

        # Case 2: Insecure Wildcard with credentials (misconfiguration)
        elif allow_origin == "*" and allow_credentials:
            findings.append(
                self.create_finding(
                    title="Insecure CORS: Wildcard Origin with Credentials",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    url=endpoint.url,
                    method=endpoint.method.value,
                    evidence="HTTP Traffic Evidence: Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true",
                    evidence_type=self.default_evidence_type,
                    description=(
                        "The CORS policy specifies wildcard origin (*) alongside credential sharing. "
                        "While standard browsers disallow this combination, it signals broken CORS logic."
                    ),
                    remediation="Do not combine wildcard origins with Access-Control-Allow-Credentials: true.",
                    request_metadata=req_meta,
                    response_metadata=res_meta,
                )
            )

        return findings
