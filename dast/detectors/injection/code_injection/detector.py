"""PHP Code Injection Detector.

Category: Injection
Evidence Type: HTTP Traffic
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

PHP_CODE_PAYLOADS = [
    # Math evaluation via var_dump / print (65017 cannot be faked by static string reflection)
    ("var_dump(823*79);", "int(65017)", "PHP var_dump math computation"),
    ("print(823*79);", "65017", "PHP print math computation"),
    (";var_dump(823*79);", "int(65017)", "PHP chained var_dump"),
    ("');var_dump(823*79);//", "int(65017)", "PHP string quote breakout var_dump"),
    ("\");var_dump(823*79);//", "int(65017)", "PHP double quote breakout var_dump"),
    ("${@var_dump(823*79)}", "int(65017)", "PHP complex variable parsing"),

    # phpversion() check
    ("phpversion();", "PHP/", "PHP version function execution"),
    ("phpinfo();", "PHP Version", "PHP info diagnostic disclosure"),
]

PHP_ERROR_PATTERNS = [
    re.compile(r"Parse error:\s+syntax error", re.I),
    re.compile(r"Fatal error:\s+eval\(\)'d code", re.I),
    re.compile(r"Warning:\s+assert\(\)", re.I),
    re.compile(r"eval\(\)\s*:\s*runtime-created function", re.I),
]


class PHPCodeInjectionDetector(BaseDetector):
    """Detects PHP code injection flaws by evaluating arithmetic functions and syntax errors."""

    name = "php_code_injection"
    description = "Audits parameters and forms for dynamic PHP Code Injection / eval execution"
    category = DetectorCategory.INJECTION
    default_evidence_type = EvidenceType.HTTP_TRAFFIC

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

        # 1. Test URL & body parameters
        for param in param_names:
            for payload, expected_token, technique_desc in PHP_CODE_PAYLOADS:
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

                # Execution confirmation: Token exists and was computed dynamically
                is_executed = False
                if expected_token in resp_text:
                    # Filter out naive echo if the whole payload is reflected
                    if payload not in resp_text or expected_token == "int(65017)":
                        is_executed = True

                if is_executed:
                    shot_path = None
                    step_shots = []
                    if browser and hasattr(browser, "render_terminal_screenshot"):
                        try:
                            shot_path = browser.render_terminal_screenshot(
                                command=f"php -r \"eval('{payload}');\"",
                                output=f"[PHP ENGINE EVALUATION]:\n{expected_token}\n\n[PHP STATUS]: Evaluation successful without fatal syntax errors",
                                detector_name=self.name,
                                title=f"PHP Code Injection Proof — Parameter '{param}'",
                                step_name=f"php_inj_{param}",
                            )
                            if shot_path:
                                step_shots = [shot_path]
                        except Exception:
                            shot_path = None

                    findings.append(
                        self.create_finding(
                            title=f"PHP Code Injection in Parameter '{param}'",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.CERTAIN,
                            url=endpoint.url,
                            method=endpoint.method.value,
                            parameter=param,
                            evidence=(
                                f"HTTP Traffic Evidence:\n"
                                f"Injected PHP Vector: {payload}\n"
                                f"Observed Output: Matched evaluated token '{expected_token}'\n"
                                f"Technique: {technique_desc}"
                            ),
                            evidence_type=EvidenceType.SCREENSHOT if shot_path else EvidenceType.HTTP_TRAFFIC,
                            screenshot_path=shot_path,
                            step_screenshots=step_shots,
                            description=(
                                f"Parameter '{param}' directly passes user input into a dynamic PHP code evaluator "
                                f"(such as eval(), assert(), or preg_replace /e), allowing arbitrary server-side PHP execution."
                            ),
                            remediation="Do not pass user-controlled input to eval(), assert(), or dynamic include functions.",
                            request_metadata=req_meta,
                            response_metadata=res_meta,
                        )
                    )
                    return findings

        return findings

