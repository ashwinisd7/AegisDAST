"""Tests for Pydantic models in dast.models."""

import pytest
from pydantic import ValidationError

from dast.models import (
    Confidence,
    Endpoint,
    Finding,
    HttpMethod,
    HTTPRequestMetadata,
    HTTPResponseMetadata,
    ScanResult,
    Severity,
    Target,
)


def test_target_validation():
    target = Target(url="https://app.example.com:8443/test")
    assert target.get_primary_host() == "app.example.com"
    assert target.is_in_scope("https://app.example.com/other-path")
    assert not target.is_in_scope("https://malicious.com/hack")

    # Invalid URL scheme
    with pytest.raises(ValidationError):
        Target(url="ftp://invalid.com")


def test_target_custom_allowed_hosts():
    target = Target(
        url="https://app.example.com",
        allowed_hosts=["app.example.com", "api.example.com"],
    )
    assert target.is_in_scope("https://api.example.com/v1/users")
    assert not target.is_in_scope("https://evil.com")


def test_endpoint_properties():
    endpoint = Endpoint(
        url="https://example.com/search",
        method=HttpMethod.GET,
        params={"q": "test", "page": "1"},
        body_params={"csrf": "token123"},
    )
    assert endpoint.identifier == "GET:https://example.com/search"
    assert endpoint.get_all_param_names() == ["csrf", "page", "q"]


def test_finding_creation():
    finding = Finding(
        title="Sample Finding",
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        url="https://example.com/api",
        method="GET",
        parameter="user_id",
        evidence="Observed anomalous response",
        description="Detailed description",
        remediation="Ensure input validation",
        detector_name="test_detector",
    )
    assert finding.title == "Sample Finding"
    assert finding.severity == Severity.HIGH
    assert finding.parameter == "user_id"


def test_scan_result_finalize():
    target = Target(url="http://localhost:8000")
    endpoint = Endpoint(url="http://localhost:8000/api", method=HttpMethod.GET)
    finding = Finding(
        title="Test Issue",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        url="http://localhost:8000/api",
        method="GET",
        evidence="None",
        description="Desc",
        remediation="Remediation",
        detector_name="test_detector",
    )

    result = ScanResult(
        target=target,
        scanned_endpoints=[endpoint],
        findings=[finding],
        active_detectors=["test_detector"],
    )
    result.finalize()

    assert result.end_time is not None
    assert result.duration_seconds >= 0.0
    assert result.summary["total_endpoints"] == 1
    assert result.summary["total_findings"] == 1
    assert result.summary["severity_breakdown"]["HIGH"] == 1
    assert result.summary["severity_breakdown"]["LOW"] == 0
