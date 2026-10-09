"""File Upload Security Auditor.

Category: File Handling
Evidence Type: DOM Evidence (Multipart form and unrestricted file input elements)
"""

from __future__ import annotations

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


class FileUploadDetector(BaseDetector):
    """Identifies file upload endpoints and audits validation and restriction attributes."""

    name = "file_upload"
    description = "Audits forms for file upload capabilities and lack of client/server restriction controls"
    category = DetectorCategory.FILE_HANDLING
    default_evidence_type = EvidenceType.DOM_EVIDENCE

    def scan(
        self,
        endpoint: Endpoint,
        client: HTTPClient,
        browser: Any | None = None,
        session: Any | None = None,
        **kwargs: Any,
    ) -> list[Finding]:
        """Audit endpoint forms for file upload configurations."""
        findings: list[Finding] = []

        resp, req_meta, res_meta = client.get(endpoint.url)
        if not resp or not resp.text:
            return findings

        content_type = resp.headers.get("Content-Type", "").lower()
        if "text/html" not in content_type:
            return findings

        soup = BeautifulSoup(resp.text, "html.parser")
        for form in soup.find_all("form"):
            file_inputs = form.find_all("input", type="file")
            if not file_inputs:
                continue

            enctype = form.get("enctype", "").lower()
            action = form.get("action", "") or endpoint.url

            for f_inp in file_inputs:
                input_name = f_inp.get("name", "unnamed_file")
                accept_attr = f_inp.get("accept", "")

                has_accept_restriction = bool(accept_attr)
                form_snippet = str(form)[:250]
                shot_path = None
                if browser and hasattr(browser, "capture_step") and browser.is_available:
                    try:
                        shot_path = browser.capture_step(
                            f"upload_{input_name}_evidence",
                            html_content=resp.text,
                            base_url=endpoint.url,
                            detector_name=self.name,
                        )
                    except Exception:
                        shot_path = None

                findings.append(
                    self.create_finding(
                        title=f"Unrestricted / Auditable File Upload Form (Input: '{input_name}')",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CERTAIN,
                        url=endpoint.url,
                        method="POST",
                        parameter=input_name,
                        evidence=(
                            f"DOM Form Evidence:\n"
                            f"Form Action: {action}\n"
                            f"Form Enctype: {enctype or 'application/x-www-form-urlencoded (missing multipart/form-data)'}\n"
                            f"File Input Name: '{input_name}' (accept='{accept_attr or 'NO RESTRICTION'}'\n"
                            f"Snippet:\n{form_snippet}..."
                        ),
                        evidence_type=EvidenceType.SCREENSHOT if shot_path else self.default_evidence_type,
                        screenshot_path=shot_path,
                        description=(
                            f"The endpoint exposes a file upload capability via input '{input_name}'. "
                            f"{'No client-side accept filter is defined. ' if not has_accept_restriction else ''}"
                            "Unrestricted file uploads can permit arbitrary code execution (webshells), "
                            "stored XSS via SVGs/HTML, or denial-of-service via oversized files if server-side validation is deficient."
                        ),
                        remediation=(
                            "1. Validate file extensions against a strict allowlist (not denylist) on the server.\n"
                            "2. Validate file MIME types and inspect file magic bytes.\n"
                            "3. Store uploaded files outside the web document root and serve them with 'Content-Disposition: attachment'.\n"
                            "4. Rename uploaded files to random identifiers to prevent direct execution."
                        ),
                        request_metadata=req_meta,
                        response_metadata=res_meta,
                    )
                )
                break

        return findings
