"""Standardized Pydantic data models for the DAST framework.

Defines schemas for Targets, Endpoints, HTTP metadata, Security Findings,
PageModel, FormModel, InputField, Resource, and overall Scan Results.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator


class HttpMethod(str, Enum):
    """Supported HTTP Methods."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class Severity(str, Enum):
    """Vulnerability severity levels aligned with CVSS ratings."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    """Confidence level of a reported finding."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CERTAIN = "CERTAIN"


class DetectorCategory(str, Enum):
    """Vulnerability classification taxonomy."""

    INJECTION = "injection"
    XSS = "xss"
    COOKIE_BASED = "cookie_based"
    BROKEN_AUTH = "broken_auth"
    FILE_HANDLING = "file_handling"
    MISCONFIGURATION = "misconfiguration"


class DetectorRequirement(str, Enum):
    """Runtime execution environment requirements for a detector."""

    REQUESTS = "requests"           # Fast, stateless HTTP client (httpx / requests)
    BROWSER = "browser"             # Headless browser environment (Playwright / DOM)
    MECHANICALSOUP = "mechanicalsoup" # Stateful session & form interaction (MechanicalSoup)


class EvidenceType(str, Enum):
    """Categorization of evidence artifact provided by a detector."""

    HTTP_TRAFFIC = "http_traffic"         # Request/response headers, status codes, and body snippets
    DB_ERROR = "db_error"                 # Raw database syntax exception signatures
    TERMINAL_OUTPUT = "terminal_output"   # Formatted CLI/terminal diagnostic output table
    SCREENSHOT = "screenshot"             # Visual browser screenshot file path
    DOM_EVIDENCE = "dom_evidence"         # Rendered DOM tree or canary reflection context


class ResourceType(str, Enum):
    """Categorization of web page sub-resources."""

    CSS = "css"
    JAVASCRIPT = "javascript"
    IMAGE = "image"
    FONT = "font"
    OTHER = "other"


class Resource(BaseModel):
    """Sub-resource referenced by a page (CSS, JavaScript, images)."""

    url: str
    resource_type: ResourceType
    tag: str

    model_config = ConfigDict(extra="ignore")


class InputField(BaseModel):
    """Interactive input element inside a web form."""

    name: str
    input_type: str = Field(default="text", description="HTML input type (text, password, hidden, submit, etc.)")
    placeholder: str = Field(default="", description="Placeholder text displayed inside input")
    required: bool = Field(default=False, description="Whether the field has the required attribute")
    value: str = Field(default="", description="Default or pre-filled value")
    options: list[str] = Field(default_factory=list, description="Available options for select dropdowns")

    model_config = ConfigDict(extra="ignore")


class FormModel(BaseModel):
    """Structured representation of an HTML form."""

    action: str
    method: str = Field(default="GET", description="Form HTTP submission method")
    inputs: list[InputField] = Field(default_factory=list, description="List of input fields in form")

    model_config = ConfigDict(extra="ignore")

    def get_input_names(self) -> list[str]:
        """Return all distinct field names."""
        return [inp.name for inp in self.inputs if inp.name]

    def find_input(self, identifier: str) -> InputField | None:
        """Find an input field by exact name, placeholder, or case-insensitive match."""
        ident_lower = identifier.lower().strip()
        for inp in self.inputs:
            if inp.name == identifier:
                return inp
        for inp in self.inputs:
            if inp.name.lower() == ident_lower:
                return inp
        for inp in self.inputs:
            if inp.placeholder and inp.placeholder.lower() == ident_lower:
                return inp
        for inp in self.inputs:
            if inp.placeholder and ident_lower in inp.placeholder.lower():
                return inp
        return None

    def get_default_data(self) -> dict[str, str]:
        """Construct dictionary of default input values."""
        return {inp.name: inp.value for inp in self.inputs if inp.name}


class PageModel(BaseModel):
    """Comprehensive crawl model representing a visited web page and its contents."""

    url: str
    status_code: int = 200
    content_type: str = "text/html"
    title: str = ""
    links: list[str] = Field(default_factory=list, description="Hyperlinks discovered on page")
    forms: list[FormModel] = Field(default_factory=list, description="HTML forms discovered on page")
    resources: list[Resource] = Field(default_factory=list, description="Sub-resources (CSS, JS, images)")

    model_config = ConfigDict(extra="ignore")


class Target(BaseModel):
    """Specification of an authorized target system to audit."""

    url: str
    allowed_hosts: list[str] = Field(default_factory=list)
    max_depth: int = Field(default=2, ge=0, description="Max crawl recursion depth")
    max_pages: int = Field(default=50, ge=1, description="Max pages to crawl")
    custom_headers: dict[str, str] = Field(
        default_factory=dict, description="Headers included in all requests (e.g., auth tokens)"
    )
    auth: tuple[str, str] | None = Field(
        default=None, description="HTTP credentials as (username, password)"
    )
    login_url: str | None = Field(
        default=None, description="Optional form login URL for automated session authentication"
    )
    after_auth_url: str | None = Field(
        default=None, description="Optional authenticated landing page URL (e.g. /portal.php or /index.php) to verify login"
    )

    model_config = ConfigDict(extra="ignore")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        parsed = urlparse(v)
        if not parsed.scheme or parsed.scheme not in ("http", "https"):
            raise ValueError(f"URL must have http or https scheme: {v}")
        if not parsed.netloc:
            raise ValueError(f"URL missing host/netloc: {v}")
        return v

    def get_primary_host(self) -> str:
        """Extract primary target hostname."""
        parsed = urlparse(self.url)
        return parsed.netloc.split(":")[0].lower()

    def is_in_scope(self, url: str) -> bool:
        """Enforce domain scope to prevent out-of-bounds requests."""
        parsed = urlparse(url)
        if not parsed.netloc:
            return False
        host = parsed.netloc.split(":")[0].lower()
        allowed = [h.lower() for h in self.allowed_hosts] if self.allowed_hosts else [self.get_primary_host()]
        return host in allowed


class Endpoint(BaseModel):
    """Represents a discovered HTTP endpoint with its request parameters."""

    url: str
    method: HttpMethod = HttpMethod.GET
    params: dict[str, Any] = Field(default_factory=dict, description="URL query parameters")
    body_params: dict[str, Any] = Field(default_factory=dict, description="Form or JSON body parameters")
    headers: dict[str, str] = Field(default_factory=dict, description="Endpoint-specific headers")
    content_type: str | None = Field(default=None, description="Request Content-Type")
    forms: list[FormModel] = Field(default_factory=list, description="Associated FormModels on this endpoint")

    model_config = ConfigDict(extra="ignore")

    @property
    def identifier(self) -> str:
        """Unique signature of the endpoint."""
        clean_url = self.url.split("?")[0]
        return f"{self.method.value}:{clean_url}"

    def get_all_param_names(self) -> list[str]:
        """Return names of all testable parameters."""
        names = list(self.params.keys()) + list(self.body_params.keys())
        return sorted(list(set(names)))


class HTTPRequestMetadata(BaseModel):
    """Snapshot of an outgoing HTTP request."""

    url: str
    method: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None


class HTTPResponseMetadata(BaseModel):
    """Snapshot of an incoming HTTP response."""

    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    latency_ms: float = 0.0
    body_preview: str | None = None
    body_length: int = 0


class Finding(BaseModel):
    """Standardized vulnerability finding record."""

    title: str
    severity: Severity
    confidence: Confidence
    url: str
    method: str
    parameter: str | None = None
    evidence: str
    evidence_type: EvidenceType = EvidenceType.HTTP_TRAFFIC
    terminal_output: str | None = Field(default=None, description="Formatted terminal/CLI output evidence")
    screenshot_path: str | None = Field(default=None, description="Path to visual screenshot evidence")
    step_screenshots: list[str] = Field(default_factory=list, description="Ordered paths to diagnostic screenshots")
    captured_dialog: str | None = Field(default=None, description="Intercepted JavaScript dialog message (alert/confirm/prompt)")
    description: str
    remediation: str
    detector_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    request_metadata: HTTPRequestMetadata | None = None
    response_metadata: HTTPResponseMetadata | None = None

    # AI False-Positive Validation metadata
    is_false_positive: bool = False
    ai_validation_status: str | None = Field(default=None, description="AI validation status: CONFIRMED_VULNERABILITY, FALSE_POSITIVE, or NEEDS_REVIEW")
    ai_validation_reasoning: str | None = Field(default=None, description="Detailed explanation from AI validation")
    ai_confidence_score: float | None = Field(default=None, description="AI confidence score from 0.0 to 1.0")

    model_config = ConfigDict(extra="ignore")


class ScanResult(BaseModel):
    """Aggregated results and metadata of a completed scan."""

    target: Target
    scanned_endpoints: list[Endpoint] = Field(default_factory=list)
    scanned_pages: list[PageModel] = Field(default_factory=list, description="Discovered PageModel objects")
    findings: list[Finding] = Field(default_factory=list)
    start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: datetime | None = None
    duration_seconds: float = 0.0
    active_detectors: list[str] = Field(default_factory=list)
    auth_screenshots: list[str] = Field(default_factory=list, description="Ordered screenshot evidence from authentication process")
    summary: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="ignore")

    def finalize(self) -> None:
        """Compute summary statistics and elapsed duration."""
        self.end_time = datetime.now(timezone.utc)
        self.duration_seconds = max(0.0, (self.end_time - self.start_time).total_seconds())

        severity_counts = {sev.value: 0 for sev in Severity}
        for finding in self.findings:
            sev_val = finding.severity.value if isinstance(finding.severity, Severity) else finding.severity
            severity_counts[sev_val] = severity_counts.get(sev_val, 0) + 1

        confirmed_count = sum(1 for f in self.findings if not f.is_false_positive)
        false_positive_count = sum(1 for f in self.findings if f.is_false_positive)

        self.summary = {
            "total_endpoints": len(self.scanned_endpoints),
            "total_pages": len(self.scanned_pages),
            "total_findings": len(self.findings),
            "confirmed_findings": confirmed_count,
            "false_positives": false_positive_count,
            "severity_breakdown": severity_counts,
            "duration_seconds": round(self.duration_seconds, 2),
            "target_url": self.target.url,
        }
