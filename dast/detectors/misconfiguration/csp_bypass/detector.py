"""Content Security Policy (CSP) Bypass & Directive Analyzer.

Category: Security Misconfiguration
Evidence Type: Terminal Output (CSP directive breakdown and bypass vulnerability matrix)
"""

from __future__ import annotations

from typing import Any

from dast.detectors.base import BaseDetector
from dast.http_client import HTTPClient
from dast.models import (
    Confidence,
    DetectorCategory,
    Endpoint,
    EvidenceType,
    Finding,
    Severity,
)


class CSPBypassDetector(BaseDetector):
    """Analyzes Content Security Policy configurations for known bypass weaknesses."""

    name = "csp_bypass"
    description = "Evaluates CSP directives for unsafe bypass expressions and wildcard origins"
    category = DetectorCategory.MISCONFIGURATION
    default_evidence_type = EvidenceType.TERMINAL_OUTPUT

    def scan(
        self,
        endpoint: Endpoint,
        client: HTTPClient,
        browser: Any | None = None,
        session: Any | None = None,
        **kwargs: Any,
    ) -> list[Finding]:
        """Audit endpoint CSP policy for bypass directives."""
        findings: list[Finding] = []

        resp, req_meta, res_meta = client.get(endpoint.url)
        if not resp:
            return findings

        csp_header = resp.headers.get("content-security-policy", "")
        if not csp_header:
            return findings

        # Parse directives
        directives = {}
        for part in csp_header.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split(None, 1)
            d_name = tokens[0].lower()
            d_val = tokens[1] if len(tokens) > 1 else ""
            directives[d_name] = d_val

        weaknesses = []

        # 1. Check script-src / default-src for unsafe-inline
        script_src = directives.get("script-src", directives.get("default-src", ""))
        if "'unsafe-inline'" in script_src:
            weaknesses.append({"directive": "script-src", "value": script_src, "flaw": "Contains 'unsafe-inline' (permits arbitrary inline script execution)"})

        if "'unsafe-eval'" in script_src:
            weaknesses.append({"directive": "script-src", "value": script_src, "flaw": "Contains 'unsafe-eval' (allows string-to-code execution like eval())"})

        if "*" in script_src.split():
            weaknesses.append({"directive": "script-src", "value": script_src, "flaw": "Wildcard '*' source allows script loading from any domain"})

        # 2. Check object-src
        object_src = directives.get("object-src", directives.get("default-src", ""))
        if not object_src or object_src != "'none'":
            weaknesses.append({"directive": "object-src", "value": object_src or "NOT DEFINED", "flaw": "Missing 'object-src: 'none'' (permits Flash/plugin execution)"})

        # 3. Check base-uri
        base_uri = directives.get("base-uri", "")
        if not base_uri or base_uri == "*":
            weaknesses.append({"directive": "base-uri", "value": base_uri or "NOT DEFINED", "flaw": "Missing 'base-uri' (permits base tag injection to hijack relative scripts)"})

        if weaknesses:
            table = self._format_csp_table(weaknesses)
            findings.append(
                self.create_finding(
                    title="Content Security Policy (CSP) Configuration Weakness / Bypass",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    url=endpoint.url,
                    method=endpoint.method.value,
                    evidence=f"Terminal Output Directive Matrix:\n{table}",
                    evidence_type=self.default_evidence_type,
                    terminal_output=table,
                    description=(
                        "The application deploys a Content Security Policy, but includes directives that permit "
                        "bypass (e.g. 'unsafe-inline', 'unsafe-eval', wildcard script sources, or missing object-src/base-uri). "
                        "These relaxations significantly weaken or nullify XSS mitigations."
                    ),
                    remediation=(
                        "1. Remove 'unsafe-inline' and 'unsafe-eval'; migrate to cryptographic nonces or hashes.\n"
                        "2. Enforce 'object-src 'none'' to restrict browser plugins.\n"
                        "3. Enforce 'base-uri 'none'' or 'base-uri 'self''."
                    ),
                    request_metadata=req_meta,
                    response_metadata=res_meta,
                )
            )

        return findings

    @staticmethod
    def _format_csp_table(weaknesses: list[dict[str, str]]) -> str:
        """Format CSP weaknesses as clean terminal table."""
        header = f"{'Directive':<14} | {'Current Value':<32} | {'Identified Weakness'}"
        sep = "-" * 80
        rows = [header, sep]
        for w in weaknesses:
            val_truncated = (w["value"][:29] + "...") if len(w["value"]) > 32 else w["value"]
            rows.append(f"{w['directive']:<14} | {val_truncated:<32} | {w['flaw']}")
        return "\n".join(rows)
