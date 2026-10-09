"""File Inclusion & Path Traversal Detector.

Category: Injection
Evidence Type: HTTP Traffic

Main orchestrator running modular File Inclusion scenarios across security levels:
- LowTraversalScenario: Direct path traversal (../../../../etc/passwd, DVWA Low Level)
- MediumNestedScenario: Nested single-pass strip bypasses (..././, ....//, DVWA Medium Level)
- HighPrefixScenario: Wildcard prefix & stream bypasses (file:///etc/passwd, DVWA High Level)
- PHPWrapperScenario: PHP stream wrappers (php://filter base64 source code disclosure)
- RFIProbeScenario: Remote File Inclusion probes and allow_url_include disclosure
"""

from __future__ import annotations

import logging
import re
from typing import Any

from dast.detectors.base import BaseDetector
from dast.detectors.injection.file_inclusion.scenarios import (
    BaseFileInclusionScenario,
    HighPrefixScenario,
    LowTraversalScenario,
    MediumNestedScenario,
    PHPWrapperScenario,
    RFIProbeScenario,
)
from dast.http_client import HTTPClient
from dast.models import DetectorCategory, Endpoint, EvidenceType, Finding

logger = logging.getLogger(__name__)


class FileInclusionDetector(BaseDetector):
    """Detects Local/Remote File Inclusion and directory traversal across modular scenarios."""

    name = "file_inclusion"
    description = "Audits parameters for Local/Remote File Inclusion and path traversal leakage"
    category = DetectorCategory.INJECTION
    default_evidence_type = EvidenceType.HTTP_TRAFFIC

    PATH_PARAM_NAMES = re.compile(
        r"^(file|page|doc|document|folder|root|path|include|template|view|load|read|url|filename|dir)$",
        re.I,
    )

    def __init__(self) -> None:
        super().__init__()
        self.scenarios: list[BaseFileInclusionScenario] = [
            LowTraversalScenario(),
            MediumNestedScenario(),
            HighPrefixScenario(),
            PHPWrapperScenario(),
            RFIProbeScenario(),
        ]

    def scan(
        self,
        endpoint: Endpoint,
        client: HTTPClient,
        browser: Any | None = None,
        session: Any | None = None,
        **kwargs: Any,
    ) -> list[Finding]:
        """Audit endpoint parameters across modular file inclusion scenarios."""
        findings: list[Finding] = []

        param_names = endpoint.get_all_param_names()
        if not param_names:
            return findings

        for param in param_names:
            if not self.PATH_PARAM_NAMES.match(param) and len(param_names) > 8:
                continue

            for scenario in self.scenarios:
                logger.info("    [FileInclusion] Testing parameter '%s' with %s...", param, scenario.technique)
                finding = scenario.evaluate(endpoint, param, client, self)
                if finding:
                    if browser and not finding.screenshot_path and browser.is_available:
                        try:
                            shot = browser.capture_step(
                                f"file_inclusion_{param}_{scenario.name}",
                                html_content=finding.response_metadata.body_preview if finding.response_metadata else None,
                                base_url=endpoint.url,
                                detector_name=self.name,
                            )
                            if shot:
                                finding.screenshot_path = shot
                                finding.step_screenshots = [shot]
                        except Exception:
                            pass
                    logger.info("    [FileInclusion] Vulnerability Confirmed: %s in '%s'", finding.title, param)
                    findings.append(finding)
                    break

        return findings
