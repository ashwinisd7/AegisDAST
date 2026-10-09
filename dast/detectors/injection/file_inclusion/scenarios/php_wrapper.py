"""PHP Wrapper File Inclusion Scenario: Stream Filters & Source Disclosure.

Audits for PHP Stream Wrappers (e.g. php://filter/convert.base64-encode/resource=...).
Permits reading raw source code of PHP scripts or system files without server-side execution.
"""

from __future__ import annotations

import base64
import re
from typing import Any

from dast.detectors.injection.file_inclusion.scenarios.base import BaseFileInclusionScenario
from dast.http_client import HTTPClient
from dast.models import Confidence, Endpoint, EvidenceType, Finding, Severity


class PHPWrapperScenario(BaseFileInclusionScenario):
    """Audits parameters for PHP stream wrappers disclosure."""

    name = "php_wrapper"
    level = "Medium/Advanced Level"
    technique = "PHP Stream Filter Disclosure (php://filter)"

    PROBES = [
        ("php://filter/convert.base64-encode/resource=index.php", "PHP base64 filter on index.php"),
        ("php://filter/read=convert.base64-encode/resource=include.php", "PHP base64 filter on include.php"),
        ("php://filter/convert.base64-encode/resource=../../../../../../etc/passwd", "PHP base64 filter on /etc/passwd"),
        ("php://filter/resource=/etc/passwd", "PHP raw filter on /etc/passwd"),
    ]

    BASE64_PATTERN = re.compile(r"([A-Za-z0-9+/]{40,}={0,2})")

    def evaluate(
        self,
        endpoint: Endpoint,
        param_name: str,
        client: HTTPClient,
        detector: Any,
    ) -> Finding | None:
        """Probe parameter using PHP stream wrappers and inspect for decoded source/system content."""
        for probe, probe_desc in self.PROBES:
            resp, req_meta, res_meta = self.send_probe(endpoint, client, param_name, probe)
            if not resp or not resp.text:
                continue

            # 1. Check for direct target signatures (e.g. raw /etc/passwd disclosure)
            for pattern, sig_desc in self.TARGET_SIGNATURES:
                if pattern.search(resp.text):
                    evidence = (
                        f"HTTP Traffic Evidence (PHP Stream Wrapper):\n"
                        f"Wrapper Technique: {probe_desc}\n"
                        f"Injected Payload: {probe}\n"
                        f"Matched Sensitive Indicator: {sig_desc}\n"
                        f"Parameter: {param_name}"
                    )
                    return detector.create_finding(
                        title=f"PHP Stream Wrapper File Inclusion in Parameter '{param_name}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.CERTAIN,
                        url=endpoint.url,
                        method=endpoint.method.value,
                        parameter=param_name,
                        evidence=evidence,
                        evidence_type=EvidenceType.HTTP_TRAFFIC,
                        description=(
                            f"Parameter '{param_name}' accepts PHP stream wrappers ('{probe}'), allowing direct reading "
                            "of sensitive files through the PHP filter mechanism."
                        ),
                        remediation=(
                            "Disable or disallow stream wrapper protocols in file path handling. Enforce strict allowlists "
                            "and validate input against known local resource names."
                        ),
                        request_metadata=req_meta,
                        response_metadata=res_meta,
                    )

            # 2. Check for Base64 encoded PHP source code disclosure
            b64_matches = self.BASE64_PATTERN.findall(resp.text)
            for token in b64_matches:
                try:
                    decoded = base64.b64decode(token).decode("utf-8", errors="ignore")
                    if any(marker in decoded.lower() for marker in ["<?php", "<?=", "<html", "function", "$_get", "$_post"]):
                        snippet = decoded[:200].strip()
                        evidence = (
                            f"HTTP Traffic Evidence (Source Code Disclosure via php://filter):\n"
                            f"Injected Probe: {probe}\n"
                            f"Base64 Token Disclosed: {token[:40]}...\n"
                            f"Decoded Source Snippet:\n{snippet}\n"
                            f"Parameter: {param_name}"
                        )
                        return detector.create_finding(
                            title=f"PHP Source Code Disclosure (php://filter) in Parameter '{param_name}'",
                            severity=Severity.HIGH,
                            confidence=Confidence.CERTAIN,
                            url=endpoint.url,
                            method=endpoint.method.value,
                            parameter=param_name,
                            evidence=evidence,
                            evidence_type=EvidenceType.HTTP_TRAFFIC,
                            description=(
                                f"Parameter '{param_name}' is vulnerable to source code disclosure via the PHP "
                                f"stream wrapper '{probe}'. Attackers can dump PHP application source code and extract secrets."
                            ),
                            remediation=(
                                "Do not pass user-controlled input into file inclusion functions (include, require, file_get_contents). "
                                "Reject any input containing 'php://' or ':' protocol schemes."
                            ),
                            request_metadata=req_meta,
                            response_metadata=res_meta,
                        )
                except Exception:
                    continue

        return None

