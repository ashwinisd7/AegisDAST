"""Low Level File Inclusion Scenario: Direct Path Traversal.

Audits for direct relative and absolute path traversal without input filtering.
Simulates DVWA Low security where user inputs are passed directly to include()/require().
"""

from __future__ import annotations

from typing import Any

from dast.detectors.injection.file_inclusion.scenarios.base import BaseFileInclusionScenario
from dast.http_client import HTTPClient
from dast.models import Confidence, Endpoint, EvidenceType, Finding, Severity


class LowTraversalScenario(BaseFileInclusionScenario):
    """Direct directory traversal probes without obfuscation."""

    name = "low_traversal"
    level = "Low Level"
    technique = "Direct Path Traversal"

    PROBES = [
        ("../../../../../../etc/passwd", "Linux /etc/passwd direct relative traversal"),
        ("..\\..\\..\\..\\..\\..\\windows\\win.ini", "Windows win.ini direct relative traversal"),
        ("/etc/passwd", "Linux absolute file path"),
        ("C:\\windows\\win.ini", "Windows absolute file path"),
    ]

    def evaluate(
        self,
        endpoint: Endpoint,
        param_name: str,
        client: HTTPClient,
        detector: Any,
    ) -> Finding | None:
        """Probe parameter using standard directory traversal sequences."""
        for probe, probe_desc in self.PROBES:
            resp, req_meta, res_meta = self.send_probe(endpoint, client, param_name, probe)
            if not resp or not resp.text:
                continue

            for pattern, sig_desc in self.TARGET_SIGNATURES:
                if pattern.search(resp.text):
                    evidence = (
                        f"HTTP Traffic Evidence (Low Level):\n"
                        f"Probe Type: {probe_desc}\n"
                        f"Injected Payload: {probe}\n"
                        f"Matched Sensitive Indicator: {sig_desc}\n"
                        f"Parameter: {param_name}"
                    )

                    return detector.create_finding(
                        title=f"Path Traversal / Local File Inclusion (Low Level) in Parameter '{param_name}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.CERTAIN,
                        url=endpoint.url,
                        method=endpoint.method.value,
                        parameter=param_name,
                        evidence=evidence,
                        evidence_type=EvidenceType.HTTP_TRAFFIC,
                        description=(
                            f"Parameter '{param_name}' directly incorporates user-supplied file paths into filesystem "
                            f"operations without sanitization (DVWA Low Level behavior). The probe '{probe}' returned "
                            f"sensitive system file contents ({sig_desc})."
                        ),
                        remediation=(
                            "Avoid passing untrusted user input directly to filesystem APIs (e.g. include, require, open). "
                            "Use a hardcoded whitelist of allowed file keys or use os.path.basename / secure path resolvers."
                        ),
                        request_metadata=req_meta,
                        response_metadata=res_meta,
                    )

        return None

