"""Base detector interface for the DAST framework.

All vulnerability audit modules must inherit from BaseDetector and implement
the scan() contract.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone

from dast.http_client import HTTPClient
from dast.models import (
    Confidence,
    DetectorCategory,
    DetectorRequirement,
    Endpoint,
    EvidenceType,
    Finding,
    HTTPRequestMetadata,
    HTTPResponseMetadata,
    Severity,
)


class BaseDetector(ABC):
    """Abstract base class that all detector plugins must implement."""

    name: str = "base_detector"
    description: str = "Base vulnerability detector interface"
    category: DetectorCategory = DetectorCategory.MISCONFIGURATION
    requirement: DetectorRequirement = DetectorRequirement.REQUESTS
    default_evidence_type: EvidenceType = EvidenceType.HTTP_TRAFFIC

    @abstractmethod
    def scan(
        self,
        endpoint: Endpoint,
        client: HTTPClient,
        browser: Any | None = None,
        session: Any | None = None,
        **kwargs: Any,
    ) -> list[Finding]:
        """Execute non-destructive security evaluation against the given endpoint.

        Args:
            endpoint: Discovered HTTP endpoint and its parameters.
            client: Scoped HTTP client for issuing test requests.
            browser: Optional BrowserManager for DOM evaluation and screenshot capture.
            session: Optional MechanicalSoup / stateful session instance.

        Returns:
            List of standardized Finding objects identified.
        """
        raise NotImplementedError

    def create_finding(
        self,
        title: str,
        severity: Severity,
        confidence: Confidence,
        url: str,
        method: str,
        evidence: str,
        description: str,
        remediation: str,
        parameter: str | None = None,
        request_metadata: HTTPRequestMetadata | None = None,
        response_metadata: HTTPResponseMetadata | None = None,
        screenshot_path: str | None = None,
        step_screenshots: list[str] | None = None,
        evidence_type: EvidenceType | None = None,
        terminal_output: str | None = None,
        captured_dialog: str | None = None,
    ) -> Finding:
        """Helper to construct standardized Finding instances."""
        steps = list(step_screenshots) if step_screenshots is not None else ([screenshot_path] if screenshot_path else [])
        main_shot = screenshot_path or (steps[-1] if steps else None)

        return Finding(
            title=title,
            severity=severity,
            confidence=confidence,
            url=url,
            method=method,
            parameter=parameter,
            evidence=evidence,
            evidence_type=evidence_type or self.default_evidence_type,
            terminal_output=terminal_output,
            description=description,
            remediation=remediation,
            detector_name=self.name,
            timestamp=datetime.now(timezone.utc),
            request_metadata=request_metadata,
            response_metadata=response_metadata,
            screenshot_path=main_shot,
            step_screenshots=steps,
            captured_dialog=captured_dialog,
        )
