"""Cookie Defensive Flags and Scope Audit Scenario."""

from __future__ import annotations

from typing import Any

from dast.detectors.cookie_based.weak_session_ids.scenarios.base import BaseSessionScenario
from dast.models import Confidence, Endpoint, EvidenceType, Finding, Severity


class FlagsAuditScenario(BaseSessionScenario):
    """Audits cookie flags (Secure, HttpOnly, SameSite) and Path/Domain scoping."""

    def evaluate(
        self,
        cookie_name: str,
        samples: list[dict[str, Any]],
        endpoint: Endpoint,
        detector: Any,
    ) -> Finding | None:
        if not samples:
            return None

        flags = samples[0]
        missing = []
        is_https = endpoint.url.lower().startswith("https://")

        if not flags.get("httponly", False):
            missing.append("HttpOnly (Exposed to client-side JavaScript / XSS theft)")
        if is_https and not flags.get("secure", False):
            missing.append("Secure (Transmitted unencrypted over plaintext HTTP)")
        if flags.get("samesite") in ("None", "", None):
            missing.append("SameSite=Strict/Lax (Permits cross-site request forgery)")
        if not flags.get("path"):
            missing.append("Path Scope (Not restricted to application path)")

        if missing:
            evidence = (
                f"Cookie Name: {cookie_name}\n"
                f"Missing Security Protections:\n"
                + "\n".join(f"  - {m}" for m in missing)
            )
            return detector.create_finding(
                title=f"Insecure Session Cookie Flags & Scoping: '{cookie_name}'",
                severity=Severity.MEDIUM,
                confidence=Confidence.CERTAIN,
                url=endpoint.url,
                method=endpoint.method.value,
                parameter=cookie_name,
                evidence=evidence,
                evidence_type=EvidenceType.TERMINAL_OUTPUT,
                terminal_output=evidence,
                description=(
                    f"The session cookie '{cookie_name}' is missing defensive attributes. Even with unpredictable "
                    "token generation, missing flags leave the session vulnerable to XSS theft, MITM interception, "
                    "or cross-path leakage."
                ),
                remediation=(
                    "Configure Set-Cookie with: Secure (for HTTPS), HttpOnly, SameSite=Strict or Lax, "
                    "and restrict Path and Domain to the application scope."
                ),
            )

        return None

