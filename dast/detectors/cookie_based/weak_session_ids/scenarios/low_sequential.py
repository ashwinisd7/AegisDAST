"""Low Level Scenario: Sequential Integer Counter."""

from __future__ import annotations

from typing import Any

from dast.detectors.cookie_based.weak_session_ids.scenarios.base import BaseSessionScenario
from dast.models import Confidence, Endpoint, Finding, Severity


class LowSequentialScenario(BaseSessionScenario):
    """Detects sequential integer session counters (e.g. 1, 2, 3, 4...)."""

    def evaluate(
        self,
        cookie_name: str,
        samples: list[dict[str, Any]],
        endpoint: Endpoint,
        detector: Any,
    ) -> Finding | None:
        token_values = [s["value"] for s in samples]
        if len(token_values) < 2 or not all(t.isdigit() for t in token_values):
            return None

        nums = [int(t) for t in token_values]

        # Ignore epoch timestamps (which start >= 1_000_000_000)
        if nums[0] >= 1_000_000_000:
            return None

        diffs = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]

        # Check if difference is constant and small (usually 1)
        if len(set(diffs)) == 1 and 0 < diffs[0] <= 10:
            step = diffs[0]
            next_pred = str(nums[-1] + step)

            first_val = token_values[0]
            length = len(first_val)
            entropy = self.shannon_entropy(first_val)
            flags = samples[0]

            table = self.format_table(
                title="Weak Session ID Analysis [Low Level: Sequential Integer]",
                cookie_name=cookie_name,
                level="LOW LEVEL (Trivially Predictable)",
                pattern=f"Sequential Integer Counter (Step = +{step})",
                entropy=f"{entropy:.2f} bits/symbol (CRITICAL)",
                length=f"{length} chars (CRITICALLY SHORT)",
                next_pred=next_pred,
                flags=flags,
                samples=token_values,
            )

            return detector.create_finding(
                title=f"Predictable Sequential Session Identifier: '{cookie_name}' (Low Level)",
                severity=Severity.CRITICAL,
                confidence=Confidence.CERTAIN,
                url=endpoint.url,
                method=endpoint.method.value,
                parameter=cookie_name,
                evidence=f"Terminal Output Diagnostic Table:\n{table}",
                evidence_type=detector.default_evidence_type,
                terminal_output=table,
                description=(
                    f"The session cookie '{cookie_name}' is generated using a sequential integer counter. "
                    "An attacker can effortlessly predict previous and future session tokens to impersonate "
                    "active users without authentication."
                ),
                remediation=(
                    "Replace integer counters with a cryptographically secure random number generator (CSPRNG, "
                    "e.g. secrets.token_bytes or /dev/urandom) producing at least 128 bits of entropy."
                ),
            )

        return None
