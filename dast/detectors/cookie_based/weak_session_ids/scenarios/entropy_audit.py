"""Deficient Entropy Fallback Scenario."""

from __future__ import annotations

from typing import Any

from dast.detectors.cookie_based.weak_session_ids.scenarios.base import BaseSessionScenario
from dast.models import Confidence, Endpoint, Finding, Severity


class EntropyAuditScenario(BaseSessionScenario):
    """Detects session identifiers with low Shannon entropy or insufficient length (< 16 chars)."""

    def evaluate(
        self,
        cookie_name: str,
        samples: list[dict[str, Any]],
        endpoint: Endpoint,
        detector: Any,
    ) -> Finding | None:
        token_values = [s["value"] for s in samples]
        if not token_values:
            return None

        sample_val = token_values[0]
        length = len(sample_val)
        entropy = self.shannon_entropy(sample_val)

        if length < 16 or entropy < 2.5:
            flags = samples[0]
            table = self.format_table(
                title="Weak Session ID Analysis [Low Entropy / Short Length]",
                cookie_name=cookie_name,
                level="DEFICIENT ENTROPY",
                pattern="Low Shannon Entropy / Insufficient Bit Length",
                entropy=f"{entropy:.2f} bits/symbol (WEAK)",
                length=f"{length} chars (< 16 required)",
                next_pred="N/A",
                flags=flags,
                samples=token_values,
            )

            return detector.create_finding(
                title=f"Insufficient Entropy in Session Identifier: '{cookie_name}'",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                url=endpoint.url,
                method=endpoint.method.value,
                parameter=cookie_name,
                evidence=f"Terminal Output Diagnostic Table:\n{table}",
                evidence_type=detector.default_evidence_type,
                terminal_output=table,
                description=(
                    f"Session token '{cookie_name}' exhibits low Shannon entropy ({entropy:.2f}) or insufficient "
                    f"character length ({length}). Session IDs must have >= 128 bits of entropy to resist brute-force."
                ),
                remediation="Increase session token length to at least 128 bits (16 random bytes / 32 hex characters).",
            )

        return None

