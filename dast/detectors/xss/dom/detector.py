"""DOM-Based Cross-Site Scripting (DOM XSS) Detector.

Category: XSS
Evidence Type: DOM Evidence (Client-side source-to-sink script flow snippet)
"""

from __future__ import annotations

import re
from typing import Any

from bs4 import BeautifulSoup

from dast.detectors.base import BaseDetector
from dast.http_client import HTTPClient
from dast.models import (
    Confidence,
    DetectorCategory,
    Endpoint,
    EvidenceType,
    Finding,
    Severity,
)


from dast.detectors.xss.common import (
    XSS_PAYLOADS,
    filter_applicable_xss_payloads,
    is_xss_executed,
)


class DOMXSSDetector(BaseDetector):
    """Identifies potential and confirmed DOM-based XSS by detecting unsafe sinks, sources, and evaluating visual DOM execution."""

    name = "dom_xss"
    description = "Analyzes client-side JavaScript for DOM XSS sources flowing into sinks and tests visual payloads in DOM"
    category = DetectorCategory.XSS
    default_evidence_type = EvidenceType.DOM_EVIDENCE

    # Direct source-to-sink flow patterns in same statement
    DIRECT_FLOW_PATTERNS = [
        re.compile(r"document\.write\s*\([^)]*(location\.(search|hash|href|pathname)|document\.(URL|documentURI|referrer)|window\.name)", re.I),
        re.compile(r"\.innerHTML\s*=\s*[^;]*(location\.(search|hash|href|pathname)|document\.(URL|documentURI|referrer)|window\.name)", re.I),
        re.compile(r"\.outerHTML\s*=\s*[^;]*(location\.(search|hash|href|pathname)|document\.(URL|documentURI|referrer)|window\.name)", re.I),
        re.compile(r"\$\s*\([^)]*\)\.html\s*\([^)]*(location\.(search|hash|href|pathname)|document\.(URL|documentURI|referrer)|window\.name)", re.I),
        re.compile(r"eval\s*\([^)]*(location\.(search|hash|href|pathname)|document\.(URL|documentURI|referrer)|window\.name)", re.I),
    ]

    def scan(
        self,
        endpoint: Endpoint,
        client: HTTPClient,
        browser: Any | None = None,
        form_handler: Any | None = None,
        pages: list[Any] | None = None,
        **kwargs: Any,
    ) -> list[Finding]:
        """Audit client-side script blocks and execute visual XSS payloads in browser DOM."""
        findings: list[Finding] = []

        browser_ran = False
        # 1. Live Browser DOM injection with visual XSS payloads
        param_names = endpoint.get_all_param_names() or ["default", "q", "lang", "redirect"]
        if browser and hasattr(browser, "is_available") and browser.is_available:
            browser_ran = True
            for param in param_names:
                for category, payloads in XSS_PAYLOADS.items():
                    for payload in payloads:
                        # Test URL query injection AND URL hash fragment injection
                        test_targets = [
                            f"{endpoint.url}?{param}={payload}",
                            f"{endpoint.url}#{payload}",
                            f"{endpoint.url}?{param}=test#{payload}",
                        ]
                        for test_url in test_targets:
                            try:
                                if hasattr(browser, "_page") and browser._page:
                                    if hasattr(browser, "clear_dialogs"):
                                        browser.clear_dialogs()
                                    browser._page.goto(test_url, wait_until="domcontentloaded", timeout=2500)
                                    browser._page.wait_for_timeout(350)
                                    
                                    xss_triggered = False
                                    if hasattr(browser, "check_xss_dom_execution") and browser.check_xss_dom_execution():
                                        xss_triggered = True
                                    elif hasattr(browser, "has_dialog") and browser.has_dialog():
                                        xss_triggered = True

                                    if xss_triggered:
                                        shot_path = None
                                        if hasattr(browser, "capture_step"):
                                            shot_path = browser.capture_step(
                                                f"dom_xss_{param}_evidence",
                                                base_url=endpoint.url,
                                                detector_name=self.name,
                                            )

                                        findings.append(
                                            self.create_finding(
                                                title=f"DOM-Based Cross-Site Scripting (DOM XSS) in '{param}'",
                                                severity=Severity.HIGH,
                                                confidence=Confidence.CERTAIN,
                                                url=test_url,
                                                method=endpoint.method.value,
                                                parameter=param,
                                                evidence=f"Live DOM XSS confirmed in browser. Injected vector executed in client-side DOM sink.\nTarget URL: {test_url}\nPayload: {payload}",
                                                evidence_type=EvidenceType.SCREENSHOT if shot_path else self.default_evidence_type,
                                                screenshot_path=shot_path,
                                                description=f"Parameter or URL fragment flows into an unsafe client-side DOM sink without sanitization.",
                                                remediation="Avoid passing untrusted URL parameters or location hashes to innerHTML/document.write. Use textContent or DOMPurify.",
                                            )
                                        )
                                        return findings
                            except Exception:
                                pass

        # If browser already ran dynamic tests and found zero execution, do NOT generate static false positives
        if browser_ran:
            return findings

        # 2. Static source-to-sink script pattern inspection via HTTP response (only when browser is disabled)
        resp, req_meta, res_meta = client.get(endpoint.url)
        if not resp or not resp.text:
            return findings

        content_type = resp.headers.get("Content-Type", "").lower()
        if "text/html" not in content_type:
            return findings

        soup = BeautifulSoup(resp.text, "html.parser")
        for script in soup.find_all("script"):
            script_code = script.string
            if not script_code:
                continue

            matched_flow = next((pat.search(script_code) for pat in self.DIRECT_FLOW_PATTERNS if pat.search(script_code)), None)
            if matched_flow:
                snippet = script_code.strip()[:200]
                findings.append(
                    self.create_finding(
                        title="Potential DOM-Based Cross-Site Scripting (DOM XSS)",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        url=endpoint.url,
                        method=endpoint.method.value,
                        evidence=(
                            f"DOM Script Evidence:\n"
                            f"Direct Source-to-Sink Statement: '{matched_flow.group(0)}'\n"
                            f"Code snippet:\n{snippet}..."
                        ),
                        evidence_type=self.default_evidence_type,
                        description=(
                            "The client-side JavaScript directly assigns user-controlled DOM data "
                            "(e.g., location.search/hash) into an execution sink without sanitization."
                        ),
                        remediation="Use textContent or DOMPurify before writing untrusted data to HTML sinks.",
                        request_metadata=req_meta,
                        response_metadata=res_meta,
                    )
                )
                break

        return findings
