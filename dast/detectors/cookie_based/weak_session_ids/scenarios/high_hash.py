"""High Level Scenario: Cryptographic Hash of Sequential Counter or Timestamp."""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any

from dast.detectors.cookie_based.weak_session_ids.scenarios.base import BaseSessionScenario
from dast.models import Confidence, Endpoint, Finding, Severity


class HighHashScenario(BaseSessionScenario):
    """Detects MD5/SHA-1 hashes of predictable integers or timestamps."""

    def evaluate(
        self,
        cookie_name: str,
        samples: list[dict[str, Any]],
        endpoint: Endpoint,
        detector: Any,
    ) -> Finding | None:
        token_values = [s["value"] for s in samples]
        if len(token_values) < 2:
            return None

        t0 = token_values[0].lower()
        is_md5 = len(t0) == 32 and bool(re.match(r"^[0-9a-f]{32}$", t0))
        is_sha1 = len(t0) == 40 and bool(re.match(r"^[0-9a-f]{40}$", t0))

        if not (is_md5 or is_sha1):
            return None

        hash_func = hashlib.md5 if is_md5 else hashlib.sha1
        hash_name = "MD5" if is_md5 else "SHA-1"

        # 1. Test sequential integer counter: check range 0 to 25,000
        for i in range(25000):
            if hash_func(str(i).encode()).hexdigest().lower() == t0:
                t1 = token_values[1].lower()
                if hash_func(str(i + 1).encode()).hexdigest().lower() == t1:
                    next_seed = i + len(token_values)
                    next_hash = hash_func(str(next_seed).encode()).hexdigest()

                    first_val = token_values[0]
                    length = len(first_val)
                    entropy = self.shannon_entropy(first_val)
                    flags = samples[0]

                    table = self.format_table(
                        title=f"Weak Session ID Analysis [High Level: {hash_name} Hashed Sequential Counter]",
                        cookie_name=cookie_name,
                        level=f"HIGH LEVEL ({hash_name} Hashed Sequential Counter)",
                        pattern=f"Cracked Hash: Token #1 = {hash_name}({i})",
                        entropy=f"{entropy:.2f} bits/symbol (Pseudo-random Hash)",
                        length=f"{length} chars ({hash_name} Hex Digest)",
                        next_pred=f"{next_hash} ({hash_name}({next_seed}))",
                        flags=flags,
                        samples=token_values,
                    )

                    return detector.create_finding(
                        title=f"Cryptographically Weak Hashed Session Identifier: '{cookie_name}' (High Level)",
                        severity=Severity.HIGH,
                        confidence=Confidence.CERTAIN,
                        url=endpoint.url,
                        method=endpoint.method.value,
                        parameter=cookie_name,
                        evidence=f"Terminal Output Diagnostic Table:\n{table}",
                        evidence_type=detector.default_evidence_type,
                        terminal_output=table,
                        description=(
                            f"The session cookie '{cookie_name}' appears to be a random {hash_name} hash, but its input "
                            f"was cracked as a predictable sequential counter (seed: {i}). Hashing predictable "
                            "inputs does not add true entropy and remains completely vulnerable to prediction."
                        ),
                        remediation=(
                            f"Avoid hashing predictable integers or timestamps. Generate session IDs directly "
                            "from a cryptographically secure random source (e.g. secrets.token_hex(16))."
                        ),
                    )

        # 2. Test Unix timestamp within +/- 1 hour of current time
        curr_ts = int(time.time())
        for ts in range(curr_ts - 3600, curr_ts + 300):
            if hash_func(str(ts).encode()).hexdigest().lower() == t0:
                next_ts = ts + 1
                next_hash = hash_func(str(next_ts).encode()).hexdigest()

                first_val = token_values[0]
                length = len(first_val)
                entropy = self.shannon_entropy(first_val)
                flags = samples[0]

                table = self.format_table(
                    title=f"Weak Session ID Analysis [High Level: {hash_name} Hashed Timestamp]",
                    cookie_name=cookie_name,
                    level=f"HIGH LEVEL ({hash_name} Hashed Timestamp)",
                    pattern=f"Cracked Hash: Token #1 = {hash_name}({ts})",
                    entropy=f"{entropy:.2f} bits/symbol (Pseudo-random Hash)",
                    length=f"{length} chars ({hash_name} Hex Digest)",
                    next_pred=f"{next_hash} ({hash_name}({next_ts}))",
                    flags=flags,
                    samples=token_values,
                )

                return detector.create_finding(
                    title=f"Cryptographically Weak Hashed Session Identifier: '{cookie_name}' (High Level)",
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    url=endpoint.url,
                    method=endpoint.method.value,
                    parameter=cookie_name,
                    evidence=f"Terminal Output Diagnostic Table:\n{table}",
                    evidence_type=detector.default_evidence_type,
                    terminal_output=table,
                    description=(
                        f"The session cookie '{cookie_name}' is generated by hashing an epoch timestamp with {hash_name}. "
                        "An attacker can compute the hashes for candidate seconds and hijack the session."
                    ),
                    remediation=(
                        "Avoid hashing predictable timestamps. Generate session IDs directly from a CSPRNG "
                        "(e.g. secrets.token_hex(16))."
                    ),
                )

        return None
