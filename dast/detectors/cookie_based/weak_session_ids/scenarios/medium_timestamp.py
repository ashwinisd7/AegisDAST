"""Medium Level Scenario: Unix Epoch Timestamp Session Generation."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from dast.detectors.cookie_based.weak_session_ids.scenarios.base import BaseSessionScenario
from dast.models import Confidence, Endpoint, Finding, Severity


class MediumTimestampScenario(BaseSessionScenario):
    """Detects timestamp-derived session identifiers (e.g. time() / 1712398450)."""

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
        first = nums[0]

        # Valid epoch range: seconds (10 digits) or milliseconds (13 digits)
        is_seconds = 1_000_000_000 <= first <= 2_500_000_000
        is_millis = 1_000_000_000_000 <= first <= 2_500_000_000_000

        if not (is_seconds or is_millis):
            return None

        diffs = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
        max_allowed_diff = 60000 if is_millis else 60

        if all(0 <= d <= max_allowed_diff for d in diffs):
            epoch_sec = first / 1000.0 if is_millis else float(first)
            dt_str = datetime.fromtimestamp(epoch_sec, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            next_pred = str(nums[-1] + 1)

            first_val = token_values[0]
            length = len(first_val)
            entropy = self.shannon_entropy(first_val)
            flags = samples[0]

            table = self.format_table(
                title="Weak Session ID Analysis [Medium Level: Unix Timestamp]",
                cookie_name=cookie_name,
                level="MEDIUM LEVEL (Time-Based Predictable)",
                pattern=f"System Unix Epoch Timestamp ({dt_str})",
                entropy=f"{entropy:.2f} bits/symbol (LOW)",
                length=f"{length} chars (WEAK)",
                next_pred=next_pred,
                flags=flags,
                samples=token_values,
            )

            return detector.create_finding(
                title=f"Timestamp-Based Predictable Session Identifier: '{cookie_name}' (Medium Level)",
                severity=Severity.HIGH,
                confidence=Confidence.CERTAIN,
                url=endpoint.url,
                method=endpoint.method.value,
                parameter=cookie_name,
                evidence=f"Terminal Output Diagnostic Table:\n{table}",
                evidence_type=detector.default_evidence_type,
                terminal_output=table,
                description=(
                    f"The session cookie '{cookie_name}' is generated from system time (e.g. time()). "
                    "Because Unix timestamps increment by 1 second, an attacker who knows approximate "
                    "login time can iterate the tiny search window and hijack valid sessions."
                ),
                remediation=(
                    "Do not use timestamps as session tokens. Utilize a CSPRNG with at least 128 bits of "
                    "entropy (minimum 16 random bytes / 32 hex characters)."
                ),
            )

        return None
