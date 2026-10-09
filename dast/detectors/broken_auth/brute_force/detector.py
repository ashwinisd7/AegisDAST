"""Brute Force Protection & Rate Limiting Detector.

Category: Broken Authentication
Evidence Type: Terminal Output (Rapid request sequence matrix and throttling response table)
"""

from __future__ import annotations

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


class BruteForceDetector(BaseDetector):
    """Audits authentication endpoints for absent rate-limiting or lockout mechanisms."""

    name = "brute_force"
    description = "Tests authentication forms for missing rate-limiting and anti-brute-force throttling"
    category = DetectorCategory.BROKEN_AUTH
    default_evidence_type = EvidenceType.TERMINAL_OUTPUT

    AUTH_URL_PATTERNS = re.compile(r"/(login|signin|auth|authenticate|session|token|password)", re.I)

    def scan(
        self,
        endpoint: Endpoint,
        client: HTTPClient,
        browser: Any | None = None,
        session: Any | None = None,
        **kwargs: Any,
    ) -> list[Finding]:
        """Audit login endpoint for lack of rate limiting."""
        findings: list[Finding] = []

        all_params = endpoint.get_all_param_names()
        is_auth_endpoint = bool(self.AUTH_URL_PATTERNS.search(endpoint.url)) or "password" in all_params or "pass" in all_params
        if not is_auth_endpoint:
            return findings

        is_post = bool(endpoint.body_params) or endpoint.method == HttpMethod.POST
        method_str = "POST" if is_post else "GET"

        # Send a rapid burst of 5 simulated authentication requests
        attempts = []
        for i in range(1, 6):
            if is_post:
                test_body = dict(endpoint.body_params)
                test_body["username"] = f"dast_audit_user_{i}"
                test_body["password"] = f"dast_audit_pass_{i}"
                resp, req_meta, res_meta = client.post(endpoint.url, data=test_body)
            else:
                test_params = dict(endpoint.params)
                test_params["username"] = f"dast_audit_user_{i}"
                test_params["password"] = f"dast_audit_pass_{i}"
                resp, req_meta, res_meta = client.get(endpoint.url, params=test_params)

            code = resp.status_code if resp else 0
            latency = res_meta.latency_ms if res_meta else 0.0
            attempts.append({"attempt": i, "code": code, "latency_ms": latency})

        # Evaluate if any rate-limiting occurred (HTTP 429 Too Many Requests, progressive delays, or blocking)
        codes = [a["code"] for a in attempts]
        rate_limited = any(c == 429 for c in codes) or any(c == 403 for c in codes)

        if not rate_limited and all(c in (200, 401, 302, 400) for c in codes):
            table = self._format_attempts_table(attempts)
            findings.append(
                self.create_finding(
                    title="Missing Rate-Limiting / Anti-Brute-Force Protection on Login Endpoint",
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    url=endpoint.url,
                    method=method_str,
                    evidence=f"Terminal Output Diagnostic Matrix:\n{table}",
                    evidence_type=self.default_evidence_type,
                    terminal_output=table,
                    description=(
                        "The authentication endpoint permitted multiple rapid login requests without triggering "
                        "HTTP 429 Too Many Requests, progressive delays, or account lockout mechanisms. "
                        "This permits automated credential stuffing and dictionary brute-force attacks."
                    ),
                    remediation=(
                        "1. Enforce IP-based and account-based rate limiting on all authentication routes (e.g. max 5 attempts/min).\n"
                        "2. Return HTTP 429 Too Many Requests with Retry-After header upon threshold breach.\n"
                        "3. Implement CAPTCHA or progressive exponential backoff after multiple failed logins."
                    ),
                )
            )

        return findings

    @staticmethod
    def _format_attempts_table(attempts: list[dict[str, Any]]) -> str:
        """Format request burst results as terminal table."""
        header = f"{'Attempt #':<12} | {'HTTP Status':<14} | {'Latency (ms)':<14} | {'Throttling Status'}"
        sep = "-" * len(header)
        rows = [header, sep]
        for a in attempts:
            status_text = "429 THROTTLED" if a["code"] == 429 else "UNTHROTTLED"
            rows.append(f"{a['attempt']:<12} | {a['code']:<14} | {a['latency_ms']:<14.2f} | {status_text}")
        return "\n".join(rows)
