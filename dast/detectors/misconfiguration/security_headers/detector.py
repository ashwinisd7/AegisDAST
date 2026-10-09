"""Security Headers Audit Detector (Taxonomy: misconfiguration).

Audits HTTP response headers for missing OWASP recommended defensive headers
and sensitive technology information disclosures.
"""

from __future__ import annotations

from typing import Any

from dast.detectors.base import BaseDetector
from dast.http_client import HTTPClient
from dast.models import Confidence, DetectorCategory, DetectorRequirement, Endpoint, EvidenceType, Finding, Severity


class SecurityHeadersDetector(BaseDetector):
    """Detector for missing security headers and server banner disclosure."""

    name = "security_headers"
    description = "Audits HTTP responses for missing OWASP defensive security headers and information leakage"
    category = DetectorCategory.MISCONFIGURATION
    requirement = DetectorRequirement.REQUESTS
    default_evidence_type = EvidenceType.HTTP_TRAFFIC

    RECOMMENDED_HEADERS = {
        "Content-Security-Policy": (
            Severity.MEDIUM,
            "Protects against Cross-Site Scripting (XSS), data injection, and clickjacking attacks.",
            "Define and enforce a strict Content-Security-Policy (CSP) restricting trusted sources.",
        ),
        "X-Frame-Options": (
            Severity.MEDIUM,
            "Defends against UI redress attacks (Clickjacking) by disallowing framing.",
            "Set X-Frame-Options to DENY or SAMEORIGIN.",
        ),
        "X-Content-Type-Options": (
            Severity.LOW,
            "Prevents MIME-type sniffing which can lead to script execution via non-executable files.",
            "Set X-Content-Type-Options to 'nosniff'.",
        ),
        "Referrer-Policy": (
            Severity.LOW,
            "Protects sensitive URLs and query parameters from leaking via the HTTP Referer header.",
            "Configure Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
        ),
        "Strict-Transport-Security": (
            Severity.LOW,
            "Enforces secure HTTPS connections and prevents SSL stripping attacks.",
            "Configure HTTP Strict Transport Security (HSTS) with max-age >= 31536000 and includeSubDomains.",
        ),
    }

    DISCLOSURE_HEADERS = [
        ("Server", "Web server vendor and version banner disclosure"),
        ("X-Powered-By", "Underlying runtime framework disclosure"),
        ("X-AspNet-Version", "ASP.NET framework version disclosure"),
    ]

    def scan(
        self,
        endpoint: Endpoint,
        client: HTTPClient,
        browser: Any | None = None,
        session: Any | None = None,
        **kwargs: Any,
    ) -> list[Finding]:
        """Audit endpoint response headers."""
        findings: list[Finding] = []

        resp, req_meta, res_meta = client.get(endpoint.url)
        if not resp:
            return findings

        headers = resp.headers

        # 1. Audit missing defensive headers
        for header_name, (sev, desc, remediate) in self.RECOMMENDED_HEADERS.items():
            if header_name not in headers:
                # If HSTS and not HTTPS, skip or note conditionally
                if header_name == "Strict-Transport-Security" and not endpoint.url.lower().startswith("https://"):
                    continue

                evidence = (
                    f"HTTP Traffic Evidence:\n"
                    f"Missing Recommended Security Header: {header_name}\n"
                    f"Status Code: {resp.status_code}\n"
                    f"Observed Headers: {', '.join(sorted(headers.keys()))}"
                )

                findings.append(
                    self.create_finding(
                        title=f"Missing Security Header: {header_name}",
                        severity=sev,
                        confidence=Confidence.CERTAIN,
                        url=endpoint.url,
                        method=endpoint.method.value,
                        evidence=evidence,
                        evidence_type=self.default_evidence_type,
                        description=desc,
                        remediation=remediate,
                        request_metadata=req_meta,
                        response_metadata=res_meta,
                    )
                )

        # 2. Audit technology banner disclosures
        for header_name, desc in self.DISCLOSURE_HEADERS:
            if header_name in headers:
                val = headers[header_name]
                evidence = (
                    f"HTTP Traffic Evidence:\n"
                    f"Disclosed Header: {header_name}: {val}\n"
                    f"Status Code: {resp.status_code}"
                )
                findings.append(
                    self.create_finding(
                        title=f"Information Disclosure: {header_name} Header",
                        severity=Severity.LOW,
                        confidence=Confidence.CERTAIN,
                        url=endpoint.url,
                        method=endpoint.method.value,
                        evidence=evidence,
                        evidence_type=self.default_evidence_type,
                        description=f"{desc}: '{val}' was returned in the server response.",
                        remediation=f"Configure the web server or reverse proxy to strip or suppress the {header_name} header.",
                        request_metadata=req_meta,
                        response_metadata=res_meta,
                    )
                )

        return findings
