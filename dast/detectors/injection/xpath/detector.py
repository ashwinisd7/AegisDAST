"""XPath & XML Injection Detector.

Category: Injection
Evidence Type: DB Error / HTTP Traffic
"""

from __future__ import annotations

import logging
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

logger = logging.getLogger(__name__)

XPATH_PAYLOADS = [
    ("'", "XPath single quote syntax breaker"),
    ('" or "1"="1', "XPath tautology bypass"),
    ("' or '1'='1", "XPath tautology bypass"),
    ("'] | //* | /['", "XPath node union extraction"),
    ("' or contains(.,'bee') or '1'='2", "XPath contains search"),
    ("1 or 1=1", "XPath numeric tautology"),
]

XPATH_ERROR_PATTERNS = [
    re.compile(r"SimpleXMLElement::xpath\(\)", re.I),
    re.compile(r"XPathException", re.I),
    re.compile(r"Warning:\s+DOMXPath::query\(\)", re.I),
    re.compile(r"xmlXPathEval", re.I),
    re.compile(r"Invalid expression in xpath", re.I),
]


class XPathInjectionDetector(BaseDetector):
    """Detects XML and XPath Injection flaws via syntax breaker probes and XPath engine errors."""

    name = "xpath_injection"
    description = "Audits parameters and forms for XPath & XML query injection vulnerabilities"
    category = DetectorCategory.INJECTION
    default_evidence_type = EvidenceType.DB_ERROR

    def scan(
        self,
        endpoint: Endpoint,
        client: HTTPClient,
        browser: Any | None = None,
        form_handler: Any | None = None,
        **kwargs: Any,
    ) -> list[Finding]:
        findings: list[Finding] = []

        param_names = endpoint.get_all_param_names()
        if not param_names and not endpoint.forms:
            return findings

        for param in param_names:
            for payload, desc in XPATH_PAYLOADS:
                if endpoint.method == HttpMethod.POST:
                    body = dict(endpoint.body_params)
                    body[param] = payload
                    resp, req_meta, res_meta = client.post(endpoint.url, data=body)
                else:
                    params = dict(endpoint.params)
                    params[param] = payload
                    resp, req_meta, res_meta = client.get(endpoint.url, params=params)

                if not resp or not resp.text:
                    continue

                resp_text = resp.text

                # 1. Error-based XPath detection
                matched_err = next((p.search(resp_text) for p in XPATH_ERROR_PATTERNS if p.search(resp_text)), None)
                if matched_err:
                    findings.append(
                        self.create_finding(
                            title=f"XPath Injection (Error-Based) in Parameter '{param}'",
                            severity=Severity.HIGH,
                            confidence=Confidence.CERTAIN,
                            url=endpoint.url,
                            method=endpoint.method.value,
                            parameter=param,
                            evidence=(
                                f"XPath Error Evidence:\n"
                                f"Injected Payload: {payload}\n"
                                f"Matched Engine Error: '{matched_err.group(0)}'\n"
                                f"Technique: {desc}"
                            ),
                            evidence_type=EvidenceType.DB_ERROR,
                            description=(
                                f"Parameter '{param}' is vulnerable to XPath Injection. The backend XPath parser returned "
                                f"an unhandled syntax exception when processing special character tokens."
                            ),
                            remediation="Use parameterized XPath queries or pre-compiled XPath variable resolvers.",
                            request_metadata=req_meta,
                            response_metadata=res_meta,
                        )
                    )
                    return findings

        return findings

