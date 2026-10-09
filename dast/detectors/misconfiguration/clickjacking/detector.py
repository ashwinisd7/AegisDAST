"""Clickjacking (UI Redressing) Detector.

Category: Misconfiguration
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


class ClickjackingDetector(BaseDetector):
    """Detects missing clickjacking framing protections (X-Frame-Options & CSP frame-ancestors)."""

    name = "clickjacking"
    description = "Audits endpoints for missing framing protections and Clickjacking exposure"
    category = DetectorCategory.MISCONFIGURATION
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

        resp, req_meta, res_meta = client.get(endpoint.url)
        if not resp or not resp.text:
            return findings

        # Check only HTML rendering pages with forms or interactive content
        content_type = resp.headers.get("Content-Type", "").lower()
        if "text/html" not in content_type:
            return findings

        x_frame = resp.headers.get("X-Frame-Options", "").upper()
        csp = resp.headers.get("Content-Security-Policy", "").lower()

        has_x_frame = x_frame in ("DENY", "SAMEORIGIN")
        has_frame_ancestors = "frame-ancestors" in csp

        if not has_x_frame and not has_frame_ancestors and (endpoint.forms or "login" in endpoint.url.lower() or "password" in endpoint.url.lower() or "ticket" in endpoint.url.lower()):
            findings.append(
                self.create_finding(
                    title="Missing Clickjacking Defensive Framing Protections",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    url=endpoint.url,
                    method=endpoint.method.value,
                    evidence=(
                        "HTTP Response Header Evidence:\n"
                        f"X-Frame-Options Header: {'Missing' if not x_frame else x_frame}\n"
                        f"CSP frame-ancestors Directive: {'Missing' if not has_frame_ancestors else 'Present'}"
                    ),
                    evidence_type=EvidenceType.HTTP_TRAFFIC,
                    description=(
                        "The page lacks both the X-Frame-Options header and CSP frame-ancestors directive. "
                        "An attacker can frame this target within a transparent <iframe> on a malicious domain "
                        "to trick authenticated users into clicking sensitive UI buttons (Clickjacking)."
                    ),
                    remediation="Set 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors 'self''.",
                    request_metadata=req_meta,
                    response_metadata=res_meta,
                )
            )

        return findings

