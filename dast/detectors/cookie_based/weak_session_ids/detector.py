"""Weak Session IDs & Predictability Detector.

Category: Cookie-Based
Evidence Type: Terminal Output (Entropy, Pattern, & Predictability Diagnostic Table)

Main orchestrator running modular scenarios across vulnerability levels:
- Low Level: LowSequentialScenario (Sequential integer counters: 1, 2, 3...)
- Medium Level: MediumTimestampScenario (System epoch timestamps: time())
- High Level: HighHashScenario (Cryptographic MD5/SHA-1 hash cracking)
- Deficient Entropy: EntropyAuditScenario (Short bit-length or low Shannon entropy)
- Defensive Flags: FlagsAuditScenario (Secure, HttpOnly, SameSite, and Path/Domain scoping)
"""

from __future__ import annotations

import logging
import re
from typing import Any

from bs4 import BeautifulSoup

from dast.detectors.base import BaseDetector
from dast.detectors.cookie_based.weak_session_ids.scenarios import (
    BaseSessionScenario,
    EntropyAuditScenario,
    FlagsAuditScenario,
    HighHashScenario,
    LowSequentialScenario,
    MediumTimestampScenario,
)
from dast.http_client import HTTPClient
from dast.models import (
    DetectorCategory,
    Endpoint,
    EvidenceType,
    Finding,
    HttpMethod,
)

logger = logging.getLogger(__name__)


class WeakSessionIDDetector(BaseDetector):
    """Audits session cookies for predictability, timestamps, hashed counters, and missing flags."""

    name = "weak_session_ids"
    description = "Evaluates session token entropy and predictability to detect weak generation algorithms"
    category = DetectorCategory.COOKIE_BASED
    default_evidence_type = EvidenceType.TERMINAL_OUTPUT

    # Cookie name pattern matching session, auth, or challenge cookies (e.g. dvwaSession, PHPSESSID, token)
    SESSION_COOKIE_PATTERN = re.compile(
        r"(session|token|sid|auth|id|user|dvwa|jwt|ticket|remember)",
        re.IGNORECASE,
    )

    SAMPLE_COUNT = 4

    def __init__(self) -> None:
        super().__init__()
        # Ordered by attack criticality / pattern specificity
        self.predictability_scenarios: list[BaseSessionScenario] = [
            LowSequentialScenario(),
            MediumTimestampScenario(),
            HighHashScenario(),
            EntropyAuditScenario(),
        ]
        self.flags_scenario = FlagsAuditScenario()

    def scan(
        self,
        endpoint: Endpoint,
        client: HTTPClient,
        browser: Any | None = None,
        session: Any | None = None,
        **kwargs: Any,
    ) -> list[Finding]:
        """Audit session cookies across predictability scenarios and security attributes."""
        findings: list[Finding] = []

        cookie_samples = self._collect_cookie_samples(endpoint, client, count=self.SAMPLE_COUNT)
        if not cookie_samples:
            return findings

        for cookie_name, samples in cookie_samples.items():
            if not samples:
                continue

            # 1. Run predictability scenarios in order of specificity
            for scenario in self.predictability_scenarios:
                pred_finding = scenario.evaluate(cookie_name, samples, endpoint, self)
                if pred_finding:
                    findings.append(pred_finding)
                    break  # Matched exact algorithmic generation level

            # 2. Run defensive flags & path/domain scope audit
            flag_finding = self.flags_scenario.evaluate(cookie_name, samples, endpoint, self)
            if flag_finding:
                findings.append(flag_finding)

        return findings

    def _collect_cookie_samples(
        self, endpoint: Endpoint, client: HTTPClient, count: int = 4
    ) -> dict[str, list[dict[str, Any]]]:
        """Issue requests to sample session cookie values and attributes."""
        grouped: dict[str, list[dict[str, Any]]] = {}

        for _ in range(count):
            if endpoint.method == HttpMethod.POST:
                resp, _, _ = client.post(endpoint.url, data=endpoint.body_params)
            else:
                resp, _, _ = client.get(endpoint.url, params=endpoint.params)

            if not resp or "set-cookie" not in resp.headers:
                continue

            raw_cookies = (
                resp.headers.get_list("set-cookie")
                if hasattr(resp.headers, "get_list")
                else [resp.headers.get("set-cookie", "")]
            )

            for raw in raw_cookies:
                parsed = self._parse_cookie_header(raw)
                if not parsed or not parsed["name"]:
                    continue

                name = parsed["name"]
                is_session = bool(self.SESSION_COOKIE_PATTERN.search(name)) or len(raw_cookies) <= 2
                if is_session:
                    grouped.setdefault(name, []).append(parsed)

        # Fallback: If GET returned no cookies, check if endpoint has a POST form to trigger cookie issuance
        if not grouped and endpoint.method == HttpMethod.GET:
            try:
                init_resp, _, _ = client.get(endpoint.url)
                if init_resp and init_resp.text:
                    soup = BeautifulSoup(init_resp.text, "html.parser")
                    form = soup.find("form")
                    if form and form.get("method", "get").upper() == "POST":
                        form_data: dict[str, str] = {}
                        for inp in form.find_all("input"):
                            name = inp.get("name")
                            if name:
                                form_data[name] = inp.get("value", "")
                        for _ in range(count):
                            resp, _, _ = client.post(endpoint.url, data=form_data)
                            if resp and "set-cookie" in resp.headers:
                                raw_cookies = (
                                    resp.headers.get_list("set-cookie")
                                    if hasattr(resp.headers, "get_list")
                                    else [resp.headers.get("set-cookie", "")]
                                )
                                for raw in raw_cookies:
                                    parsed = self._parse_cookie_header(raw)
                                    if parsed and parsed["name"]:
                                        name = parsed["name"]
                                        is_session = bool(self.SESSION_COOKIE_PATTERN.search(name)) or len(raw_cookies) <= 2
                                        if is_session:
                                            grouped.setdefault(name, []).append(parsed)
            except Exception:
                pass

        return grouped

    def _parse_cookie_header(self, header_str: str) -> dict[str, Any] | None:
        """Parse raw Set-Cookie header into name, value, and flags."""
        parts = [p.strip() for p in header_str.split(";") if p.strip()]
        if not parts or "=" not in parts[0]:
            return None

        name, value = parts[0].split("=", 1)
        name = name.strip()
        value = value.strip().strip('"')

        attrs = {
            "name": name,
            "value": value,
            "secure": False,
            "httponly": False,
            "samesite": "None",
            "path": None,
            "domain": None,
        }

        for p in parts[1:]:
            low = p.lower()
            if low == "secure":
                attrs["secure"] = True
            elif low == "httponly":
                attrs["httponly"] = True
            elif low.startswith("samesite="):
                attrs["samesite"] = p.split("=", 1)[1].strip()
            elif low.startswith("path="):
                attrs["path"] = p.split("=", 1)[1].strip()
            elif low.startswith("domain="):
                attrs["domain"] = p.split("=", 1)[1].strip()

        return attrs
