"""Cookie Security Flags Detector.

Category: Cookie-Based
Evidence Type: Terminal Output (Formatted ASCII matrix of cookie security attributes)
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

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

logger = logging.getLogger(__name__)


class CookieSecurityDetector(BaseDetector):
    """Audits session and tracking cookies for missing security flags."""

    name = "cookies"
    description = (
        "Audits cookies to verify Secure, HttpOnly, and SameSite defensive flags "
        "and generates a diagnostic terminal report table."
    )
    category = DetectorCategory.COOKIE_BASED
    default_evidence_type = EvidenceType.TERMINAL_OUTPUT

    def scan(
        self,
        endpoint: Endpoint,
        client: HTTPClient,
        browser: Any | None = None,
        session: Any | None = None,
        **kwargs: Any,
    ) -> list[Finding]:
        """Perform cookie flag security audit."""
        findings: list[Finding] = []

        cookie_records: list[dict[str, Any]] = []

        resp, _, _ = client.get(endpoint.url)
        if not resp:
            return findings

        # Extract set-cookie headers
        if "set-cookie" in resp.headers:
            raw_cookies = (
                resp.headers.get_list("set-cookie")
                if hasattr(resp.headers, "get_list")
                else [resp.headers.get("set-cookie", "")]
            )
            for raw in raw_cookies:
                parts = [p.strip() for p in raw.split(";")]
                if not parts or not parts[0]:
                    continue
                name_val = parts[0].split("=", 1)
                c_name = name_val[0]
                c_val = name_val[1] if len(name_val) > 1 else ""
                lower_parts = [p.lower() for p in parts[1:]]
                is_secure = any(p == "secure" for p in lower_parts)
                is_httponly = any(p == "httponly" for p in lower_parts)
                samesite_part = next(
                    (p.split("=")[1].strip() for p in parts if p.lower().startswith("samesite=")),
                    "None",
                )
                cookie_records.append({
                    "name": c_name,
                    "value": c_val[:10] + "..." if len(c_val) > 10 else c_val,
                    "domain": urlparse(endpoint.url).netloc,
                    "secure": is_secure,
                    "httponly": is_httponly,
                    "samesite": samesite_part,
                })

        if not cookie_records:
            return findings

        insecure_cookies = []
        for cookie in cookie_records:
            issues = []
            if not cookie["secure"]:
                issues.append("Missing 'Secure' flag")
            if not cookie["httponly"]:
                issues.append("Missing 'HttpOnly' flag")
            if cookie["samesite"] in ("None", "none", None):
                issues.append("Missing 'SameSite' attribute")

            if issues:
                cookie["issues"] = issues
                insecure_cookies.append(cookie)

        if not insecure_cookies:
            return findings

        terminal_table = self._format_terminal_table(insecure_cookies)

        findings.append(
            self.create_finding(
                title=f"Insecure Cookie Configuration ({len(insecure_cookies)} cookie(s) affected)",
                severity=Severity.MEDIUM,
                confidence=Confidence.CERTAIN,
                url=endpoint.url,
                method=endpoint.method.value,
                evidence=f"Terminal Output Diagnostic Table:\n{terminal_table}",
                evidence_type=self.default_evidence_type,
                terminal_output=terminal_table,
                screenshot_path=None,
                description=(
                    "One or more HTTP cookies lack recommended defensive flags ('Secure', 'HttpOnly', or 'SameSite'). "
                    "This exposes session identifiers to interception over unencrypted channels, XSS access, and CSRF attacks."
                ),
                remediation=(
                    "1. Always set 'Secure' on cookies served over HTTPS.\n"
                    "2. Enforce 'HttpOnly' for session tokens.\n"
                    "3. Configure 'SameSite=Lax' or 'SameSite=Strict'."
                ),
            )
        )

        return findings

    @staticmethod
    def _format_terminal_table(cookies: list[dict[str, Any]]) -> str:
        """Format cookie audit results as clean ASCII terminal table."""
        header = f"{'Cookie Name':<18} | {'Domain':<16} | {'Secure':<8} | {'HttpOnly':<8} | {'SameSite':<8} | {'Issues'}"
        sep = "-" * len(header)
        rows = [header, sep]
        for c in cookies:
            issues_str = "; ".join(c.get("issues", []))
            sec_str = "YES" if c["secure"] else "NO"
            http_str = "YES" if c["httponly"] else "NO"
            row = f"{c['name']:<18} | {c['domain']:<16} | {sec_str:<8} | {http_str:<8} | {str(c['samesite']):<8} | {issues_str}"
            rows.append(row)
        return "\n".join(rows)
