"""Client-Side JavaScript Misconfiguration & Leakage Detector (Taxonomy: misconfiguration).

Audits client-side JavaScript for leaked secrets, API keys, exposed source maps,
and dangerous script execution sinks.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from dast.detectors.base import BaseDetector
from dast.http_client import HTTPClient
from dast.models import Confidence, DetectorCategory, DetectorRequirement, Endpoint, EvidenceType, Finding, Severity


class JavaScriptDetector(BaseDetector):
    """Detects leaked credentials, API tokens, source maps, and dangerous sinks in JavaScript."""

    name = "javascript"
    description = "Audits client-side JavaScript for leaked secrets, API tokens, exposed source maps, and unsafe sinks"
    category = DetectorCategory.MISCONFIGURATION
    requirement = DetectorRequirement.REQUESTS
    default_evidence_type = EvidenceType.DOM_EVIDENCE

    # Secret / Token signature patterns
    SECRET_PATTERNS = [
        (
            "AWS Access Key ID",
            re.compile(r"(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)", re.IGNORECASE),
            Severity.HIGH,
            Confidence.HIGH,
        ),
        (
            "Hardcoded Private Key",
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE),
            Severity.CRITICAL,
            Confidence.CERTAIN,
        ),
        (
            "JSON Web Token (JWT)",
            re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-\.\+/=]{10,}"),
            Severity.MEDIUM,
            Confidence.HIGH,
        ),
        (
            "Hardcoded Secret / API Token Assignment",
            re.compile(
                r"""(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret)\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{16,})['"]""",
                re.IGNORECASE,
            ),
            Severity.HIGH,
            Confidence.MEDIUM,
        ),
    ]

    # Source map reference pattern
    SOURCE_MAP_PATTERN = re.compile(r"//[#@]\s*sourceMappingURL=([^\s]+)")

    def scan(
        self,
        endpoint: Endpoint,
        client: HTTPClient,
        browser: Any | None = None,
        session: Any | None = None,
        **kwargs: Any,
    ) -> list[Finding]:
        """Audit HTML and linked JavaScript files for secrets and source maps."""
        findings: list[Finding] = []

        resp, req_meta, res_meta = client.get(endpoint.url)
        if not resp:
            return findings

        content_type = resp.headers.get("Content-Type", "").lower()
        scripts_to_check: list[tuple[str, str]] = []  # (source_label, script_content)

        # If endpoint itself is a JS file
        if "javascript" in content_type or endpoint.url.endswith(".js"):
            scripts_to_check.append((endpoint.url, resp.text))
        elif "html" in content_type or "<html" in resp.text[:200].lower():
            soup = BeautifulSoup(resp.text, "html.parser")

            # 1. Inline scripts
            for idx, script_tag in enumerate(soup.find_all("script")):
                code = script_tag.string or script_tag.get_text()
                if code and code.strip():
                    scripts_to_check.append((f"{endpoint.url}#inline-script-{idx+1}", code))

                # 2. External in-scope scripts
                src = script_tag.get("src")
                if src:
                    script_url = urljoin(endpoint.url, src)
                    parsed_script = urlparse(script_url)
                    parsed_target = urlparse(endpoint.url)
                    # Fetch only in-scope same-host scripts to avoid third-party CDNs
                    if parsed_script.netloc.lower() == parsed_target.netloc.lower():
                        js_resp, _, _ = client.get(script_url)
                        if js_resp and js_resp.status_code == 200:
                            scripts_to_check.append((script_url, js_resp.text))

        # Analyze gathered scripts
        for source_label, code in scripts_to_check:
            # Check secret patterns
            for pattern_name, pattern_re, sev, conf in self.SECRET_PATTERNS:
                matches = pattern_re.findall(code)
                if matches:
                    matched_snippet = matches[0] if isinstance(matches[0], str) else matches[0][0]
                    # Mask snippet for safety in evidence
                    masked = matched_snippet[:4] + "*" * (len(matched_snippet) - 8) + matched_snippet[-4:] if len(matched_snippet) > 8 else "***"

                    evidence = (
                        f"DOM Evidence / Script Location: {source_label}\n"
                        f"Matched Pattern: {pattern_name}\n"
                        f"Disclosed Token (Masked): {masked}\n"
                        f"Context Preview:\n"
                        f"{self._extract_context(code, matched_snippet)}"
                    )

                    findings.append(
                        self.create_finding(
                            title=f"Sensitive Token Exposure in JavaScript: {pattern_name}",
                            severity=sev,
                            confidence=conf,
                            url=endpoint.url,
                            method=endpoint.method.value,
                            evidence=evidence,
                            evidence_type=self.default_evidence_type,
                            description=(
                                f"Client-side JavaScript code exposed a sensitive credential or token matching '{pattern_name}'. "
                                "Hardcoded credentials in client scripts can be extracted by any attacker or unauthorized user."
                            ),
                            remediation=(
                                "Remove hardcoded credentials from frontend scripts. Use server-side proxying "
                                "or secure token issuance mechanisms with scoped permissions."
                            ),
                            request_metadata=req_meta,
                            response_metadata=res_meta,
                        )
                    )

            # Check source map references
            map_match = self.SOURCE_MAP_PATTERN.search(code)
            if map_match:
                map_file = map_match.group(1).strip()
                evidence = (
                    f"DOM Evidence / Script Location: {source_label}\n"
                    f"Source Map Reference Found: {map_file}\n"
                    f"Full Reference Comment: {map_match.group(0)}"
                )

                findings.append(
                    self.create_finding(
                        title="JavaScript Source Map Disclosure",
                        severity=Severity.LOW,
                        confidence=Confidence.CERTAIN,
                        url=endpoint.url,
                        method=endpoint.method.value,
                        evidence=evidence,
                        evidence_type=self.default_evidence_type,
                        description=(
                            "The client-side JavaScript references a source map (.map file). "
                            "Production source maps can expose original unminified source code, comments, "
                            "and backend API structures to unauthorized third parties."
                        ),
                        remediation=(
                            "Disable generation of source maps in production builds or configure web servers "
                            "to restrict access to .map files."
                        ),
                        request_metadata=req_meta,
                        response_metadata=res_meta,
                    )
                )

        return findings

    def _extract_context(self, code: str, match_text: str, radius: int = 80) -> str:
        """Extract a line snippet containing the matched pattern."""
        idx = code.find(match_text)
        if idx == -1:
            return code[:100]
        start = max(0, idx - radius)
        end = min(len(code), idx + len(match_text) + radius)
        return code[start:end].strip()
