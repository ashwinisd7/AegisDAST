"""Open HTTP Redirect Detector.

Category: Security Misconfiguration
Evidence Type: HTTP Traffic (Observed Location header redirection to untrusted domain)
"""

from __future__ import annotations

import re
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
    HttpMethod,
    Severity,
)


class OpenRedirectDetector(BaseDetector):
    """Detects unvalidated external URL redirection vulnerabilities."""

    name = "open_redirect"
    description = "Audits parameters for Open HTTP Redirection to arbitrary third-party domains"
    category = DetectorCategory.MISCONFIGURATION
    default_evidence_type = EvidenceType.HTTP_TRAFFIC

    REDIRECT_PARAMS = re.compile(
        r"^(url|redirect|redirect_to|redirect_url|next|return|return_to|dest|destination|r|target|forward)$",
        re.I,
    )

    PROBE_TARGET = "https://untrusted-redirect.example"

    def scan(
        self,
        endpoint: Endpoint,
        client: HTTPClient,
        browser: Any | None = None,
        session: Any | None = None,
        **kwargs: Any,
    ) -> list[Finding]:
        """Audit endpoint parameters for open redirect behavior."""
        findings: list[Finding] = []

        param_names = endpoint.get_all_param_names()
        if not param_names:
            return findings

        for param in param_names:
            if not self.REDIRECT_PARAMS.match(param):
                continue

            # We must not automatically follow redirects to inspect the Location header
            if endpoint.method == HttpMethod.POST:
                test_body = dict(endpoint.body_params)
                test_body[param] = self.PROBE_TARGET
                resp, req_meta, res_meta = client.request("POST", endpoint.url, data=test_body, follow_redirects=False)
            else:
                test_params = dict(endpoint.params)
                test_params[param] = self.PROBE_TARGET
                resp, req_meta, res_meta = client.request("GET", endpoint.url, params=test_params, follow_redirects=False)

            if not resp:
                continue

            location = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 303, 307, 308) and location:
                parsed_loc = urlparse(location)
                if parsed_loc.netloc == "untrusted-redirect.example":
                    findings.append(
                        self.create_finding(
                            title=f"Open HTTP Redirect Vulnerability in Parameter '{param}'",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CERTAIN,
                            url=endpoint.url,
                            method=endpoint.method.value,
                            parameter=param,
                            evidence=(
                                f"HTTP Traffic Evidence:\n"
                                f"Injected Redirect Target: {self.PROBE_TARGET}\n"
                                f"HTTP Status: {resp.status_code}\n"
                                f"Response Header: Location: {location}\n"
                                f"The server unreservedly redirected clients to an arbitrary external origin."
                            ),
                            evidence_type=self.default_evidence_type,
                            description=(
                                f"Parameter '{param}' specifies a redirect location that is not validated against "
                                "a domain allowlist. Attackers can leverage open redirects in phishing attacks "
                                "or OAuth authorization code theft."
                            ),
                            remediation=(
                                "Avoid accepting full external URLs in redirect parameters. Use relative paths only, "
                                "or validate the target destination against a strict server-side allowlist."
                            ),
                            request_metadata=req_meta,
                            response_metadata=res_meta,
                        )
                    )
                    break

        return findings
