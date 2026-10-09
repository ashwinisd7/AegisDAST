"""Unit tests for AI-assisted false-positive validation engine."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import httpx
import pytest

from dast.models import (
    Confidence,
    EvidenceType,
    Finding,
    HTTPRequestMetadata,
    HTTPResponseMetadata,
    Severity,
    Target,
)
from dast.scanner import Scanner
from dast.validator import GeminiFindingValidator


def test_validator_build_prompt() -> None:
    """Verify validator constructs detailed diagnostic prompt from finding metadata."""
    finding = Finding(
        title="SQL Injection in Parameter 'id'",
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        url="http://app.local/item.php",
        method="GET",
        parameter="id",
        evidence="MySQL syntax error near ''1''",
        evidence_type=EvidenceType.DB_ERROR,
        description="SQL injection vulnerability in id parameter.",
        remediation="Use prepared statements.",
        detector_name="sqli",
        request_metadata=HTTPRequestMetadata(url="http://app.local/item.php?id='", method="GET"),
        response_metadata=HTTPResponseMetadata(status_code=500, latency_ms=120.0, body_preview="Fatal error: MySQL syntax"),
    )

    validator = GeminiFindingValidator(api_key="TEST_API_KEY", model="gemini-3.1-flash-lite")
    prompt = validator._build_prompt(finding)

    assert "SQL Injection in Parameter 'id'" in prompt
    assert "MySQL syntax error" in prompt
    assert "gemini" in validator.model


def test_validator_confirmed_vulnerability() -> None:
    """Verify validator correctly processes confirmed vulnerability JSON response from Gemini."""
    gemini_response_payload = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": json.dumps({
                                "is_false_positive": False,
                                "status": "CONFIRMED_VULNERABILITY",
                                "confidence_score": 0.98,
                                "reasoning": "The response clearly exposes an unhandled database syntax error resulting from single quote injection.",
                                "recommended_severity": "HIGH",
                            })
                        }
                    ]
                }
            }
        ]
    }

    transport = httpx.MockTransport(lambda r: httpx.Response(200, json=gemini_response_payload))
    validator = GeminiFindingValidator(api_key="TEST_KEY", transport=transport)

    finding = Finding(
        title="SQL Injection",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        url="http://app.local/page",
        method="GET",
        evidence="Syntax error",
        description="SQLi test",
        remediation="Parametrize",
        detector_name="sqli",
    )

    result = validator.validate_finding(finding)
    assert result is True
    assert finding.is_false_positive is False
    assert finding.ai_validation_status == "CONFIRMED_VULNERABILITY"
    assert "database syntax error" in (finding.ai_validation_reasoning or "")
    assert finding.ai_confidence_score == 0.98


def test_validator_false_positive() -> None:
    """Verify validator flags false positive and updates finding model."""
    gemini_response_payload = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": json.dumps({
                                "is_false_positive": True,
                                "status": "FALSE_POSITIVE",
                                "confidence_score": 0.95,
                                "reasoning": "The reflection occurs in a safely escaped JSON payload context without executable HTML/JS context.",
                                "recommended_severity": "INFO",
                            })
                        }
                    ]
                }
            }
        ]
    }

    transport = httpx.MockTransport(lambda r: httpx.Response(200, json=gemini_response_payload))
    validator = GeminiFindingValidator(api_key="TEST_KEY", transport=transport)

    finding = Finding(
        title="Reflected XSS",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        url="http://app.local/api/search",
        method="GET",
        evidence="Canary token reflected inside quoted string",
        description="XSS test",
        remediation="Encode",
        detector_name="reflected_xss",
    )

    result = validator.validate_finding(finding)
    assert result is True
    assert finding.is_false_positive is True
    assert finding.ai_validation_status == "FALSE_POSITIVE"
    assert "safely escaped" in (finding.ai_validation_reasoning or "")


def test_validator_api_error_resilience() -> None:
    """Verify validator gracefully handles Gemini HTTP errors without failing or altering finding."""
    transport = httpx.MockTransport(lambda r: httpx.Response(429, text="Rate limit exceeded"))
    validator = GeminiFindingValidator(api_key="TEST_KEY", transport=transport)

    finding = Finding(
        title="Command Injection",
        severity=Severity.CRITICAL,
        confidence=Confidence.CERTAIN,
        url="http://app.local/ping",
        method="POST",
        evidence="PING token",
        description="Cmdi",
        remediation="Avoid shell",
        detector_name="command_injection",
    )

    result = validator.validate_finding(finding)
    assert result is False
    assert finding.is_false_positive is False
    assert finding.ai_validation_status is None


def test_validator_multimodal_screenshot_attachment(tmp_path: pytest.TempPathFactory) -> None:
    """Verify validator collects and encodes screenshots as inlineData parts in Gemini API request."""
    # Create fake screenshot image file
    shot_file = tmp_path / "step-1.png"
    shot_file.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRfakeimagebytes")

    captured_payloads = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        data = json.loads(request.content.decode("utf-8"))
        captured_payloads.append(data)
        return httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "text": json.dumps({
                                        "is_false_positive": False,
                                        "status": "CONFIRMED_VULNERABILITY",
                                        "confidence_score": 0.99,
                                        "reasoning": "Visual screenshot confirms DOM element rendering.",
                                    })
                                }
                            ]
                        }
                    }
                ]
            },
        )

    transport = httpx.MockTransport(mock_handler)
    validator = GeminiFindingValidator(api_key="TEST_KEY", transport=transport)

    finding = Finding(
        title="Visual XSS",
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        url="http://app.local/xss",
        method="GET",
        evidence="DOM execution",
        step_screenshots=[str(shot_file)],
        description="Visual XSS",
        remediation="Encode",
        detector_name="reflected_xss",
    )

    result = validator.validate_finding(finding)
    assert result is True
    assert len(captured_payloads) == 1
    req_parts = captured_payloads[0]["contents"][0]["parts"]
    assert len(req_parts) == 2  # 1 text prompt + 1 inlineData image
    assert "inlineData" in req_parts[1]
    assert req_parts[1]["inlineData"]["mimeType"] == "image/png"
    assert req_parts[1]["inlineData"]["data"] != ""


