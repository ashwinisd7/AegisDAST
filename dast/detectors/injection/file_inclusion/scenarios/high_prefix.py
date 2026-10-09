"""High Level File Inclusion Scenario: Prefix & Stream Protocol Bypass.

Audits for wildcard prefix allowlists such as fnmatch('file*', $file).
Simulates DVWA High security where inputs are required to begin with a prefix ('file*'),
bypassed by PHP stream wrappers like 'file:///etc/passwd' or prefix-based traversals.
"""

from __future__ import annotations

from typing import Any

from dast.detectors.injection.file_inclusion.scenarios.base import BaseFileInclusionScenario
from dast.http_client import HTTPClient
from dast.models import Confidence, Endpoint, EvidenceType, Finding, Severity


class HighPrefixScenario(BaseFileInclusionScenario):
    """Prefix allowlist bypasses utilizing file:// protocol handlers and prefix traversal."""

    name = "high_prefix"
    level = "High Level"
    technique = "Prefix Whitelist & Stream Wrapper Bypass"

    PROBES = [
        # file:// stream wrapper satisfies fnmatch("file*", ...) and accesses local file directly
        ("file:///etc/passwd", "PHP file:// stream wrapper (/etc/passwd)"),
        ("file:///C:/windows/win.ini", "PHP file:// stream wrapper (win.ini)"),
        ("file/../../../../../../etc/passwd", "Prefix directory traversal (file/...)"),
        ("file1.php/../../../../../../etc/passwd", "Prefix traversal via filename (file1.php/...)"),
    ]

    def evaluate(
        self,
        endpoint: Endpoint,
        param_name: str,
        client: HTTPClient,
        detector: Any,
    ) -> Finding | None:
        """Probe parameter using prefix-satisfying stream wrappers and traversals."""
        for probe, probe_desc in self.PROBES:
            resp, req_meta, res_meta = self.send_probe(endpoint, client, param_name, probe)
            if not resp or not resp.text:
                continue

            for pattern, sig_desc in self.TARGET_SIGNATURES:
                if pattern.search(resp.text):
                    evidence = (
                        f"HTTP Traffic Evidence (High Level):\n"
                        f"Bypass Technique: {probe_desc}\n"
                        f"Injected Payload: {probe}\n"
                        f"Matched Sensitive Indicator: {sig_desc}\n"
                        f"Parameter: {param_name}"
                    )

                    return detector.create_finding(
                        title=f"Local File Inclusion (High Level - Prefix / Stream Bypass) in Parameter '{param_name}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.CERTAIN,
                        url=endpoint.url,
                        method=endpoint.method.value,
                        parameter=param_name,
                        evidence=evidence,
                        evidence_type=EvidenceType.HTTP_TRAFFIC,
                        description=(
                            f"Parameter '{param_name}' enforces a prefix wildcard allowlist (e.g. fnmatch('file*', ...)), "
                            f"which was bypassed using '{probe}'. By supplying a URI handler or path starting with the "
                            "expected prefix, unauthorized filesystem access was successfully achieved."
                        ),
                        remediation=(
                            "Do not rely on prefix or wildcard pattern matching (e.g. fnmatch or startsWith) to authorize "
                            "file access. Enforce an exact key-to-file lookup table (e.g. ['page1' => 'page1.php']) "
                            "and reject all unmatched user input."
                        ),
                        request_metadata=req_meta,
                        response_metadata=res_meta,
                    )

        return None

