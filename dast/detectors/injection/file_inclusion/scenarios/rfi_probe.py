"""Remote File Inclusion (RFI) Scenario.

Audits parameters for Remote File Inclusion (RFI) execution or diagnostic warnings.
Simulates DVWA Low & Medium security RFI vectors (including nested 'hthttp://tp://' bypasses).
"""

from __future__ import annotations

import re
from typing import Any

from dast.detectors.injection.file_inclusion.scenarios.base import BaseFileInclusionScenario
from dast.http_client import HTTPClient
from dast.models import Confidence, Endpoint, EvidenceType, Finding, Severity


class RFIProbeScenario(BaseFileInclusionScenario):
    """Audits parameters for Remote File Inclusion vulnerabilities and allow_url_include disclosures."""

    name = "rfi_probe"
    level = "Low/Medium Level"
    technique = "Remote File Inclusion (RFI)"

    # Safe test URLs (including nested protocol bypasses for Medium Level)
    PROBES = [
        ("http://127.0.0.1:1337/dast_canary.php", "Direct HTTP RFI probe"),
        ("https://127.0.0.1:1337/dast_canary.php", "Direct HTTPS RFI probe"),
        ("hthttp://tp://127.0.0.1:1337/dast_canary.php", "Nested HTTP protocol bypass (hthttp://tp://)"),
        ("hthttps://tps://127.0.0.1:1337/dast_canary.php", "Nested HTTPS protocol bypass (hthttps://tps://)"),
    ]

    # PHP runtime error signatures when remote inclusion is attempted
    RFI_ERROR_PATTERNS = [
        re.compile(r"URL file-access is disabled in the server configuration", re.I),
        re.compile(r"allow_url_include=0", re.I),
        re.compile(r"Warning:\s+(include|require)(_once)?\(http(s)?://", re.I),
        re.compile(r"Failed opening 'http(s)?://", re.I),
        re.compile(r"failed to open stream:\s+HTTP request failed", re.I),
        re.compile(r"no suitable wrapper could be found", re.I),
    ]

    def evaluate(
        self,
        endpoint: Endpoint,
        param_name: str,
        client: HTTPClient,
        detector: Any,
    ) -> Finding | None:
        """Probe parameter with remote URLs and inspect for execution or RFI configuration warnings."""
        for probe, probe_desc in self.PROBES:
            resp, req_meta, res_meta = self.send_probe(endpoint, client, param_name, probe)
            if not resp or not resp.text:
                continue

            for pattern in self.RFI_ERROR_PATTERNS:
                match = pattern.search(resp.text)
                if match:
                    matched_sig = match.group(0)
                    evidence = (
                        f"HTTP Traffic Evidence (RFI Server Disclosure):\n"
                        f"Probe Type: {probe_desc}\n"
                        f"Injected Remote URL: {probe}\n"
                        f"Server Diagnostic Signature: '{matched_sig}'\n"
                        f"Parameter: {param_name}"
                    )

                    return detector.create_finding(
                        title=f"Remote File Inclusion (RFI) Susceptibility in Parameter '{param_name}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.CERTAIN,
                        url=endpoint.url,
                        method=endpoint.method.value,
                        parameter=param_name,
                        evidence=evidence,
                        evidence_type=EvidenceType.HTTP_TRAFFIC,
                        description=(
                            f"Parameter '{param_name}' attempted to fetch a remote HTTP resource when injected with '{probe}'. "
                            f"The backend returned diagnostic warning '{matched_sig}'. This confirms the parameter is passed directly "
                            "to file inclusion functions (include/require) and will result in arbitrary remote code execution if "
                            "'allow_url_include' is enabled."
                        ),
                        remediation=(
                            "Set 'allow_url_include = Off' and 'allow_url_fopen = Off' in php.ini. "
                            "Never pass user-supplied input to file inclusion functions; strictly validate "
                            "inputs against a static whitelist."
                        ),
                        request_metadata=req_meta,
                        response_metadata=res_meta,
                    )

        return None

