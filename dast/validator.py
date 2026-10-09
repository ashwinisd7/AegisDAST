"""AI-assisted False-Positive Validation engine powered by Google Gemini.

Performs automated secondary analysis on DAST vulnerability findings to confirm genuine
exploits and filter out false positives based on HTTP telemetry, DOM execution, and error signatures.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from pathlib import Path
import re
from typing import Any, Sequence

import httpx

from dast.models import Finding

logger = logging.getLogger(__name__)

DEFAULT_GEMINI_API_KEY = ""
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"


class GeminiFindingValidator:
    """Validates DAST security findings using Google Gemini models."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.api_key = (api_key or os.environ.get("GEMINI_API_KEY") or DEFAULT_GEMINI_API_KEY).strip()
        self.model = (model or os.environ.get("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL).strip()
        self.timeout = timeout
        self.transport = transport

    def is_configured(self) -> bool:
        """Check if validator has a valid API key configured."""
        return bool(self.api_key and self.api_key.strip())

    def validate_findings(self, findings: Sequence[Finding]) -> None:
        """Execute false-positive validation across all supplied findings."""
        if not findings:
            return

        if not self.is_configured():
            logger.info("[AI-VALIDATOR] Gemini API key not configured. Skipping false-positive validation.")
            return

        masked_key = self.api_key[:6] + "..." + self.api_key[-4:] if len(self.api_key) > 10 else "***"
        logger.info(
            "[AI-VALIDATOR] Initiating AI false-positive validation for %d finding(s) using model '%s' (key: %s)...",
            len(findings),
            self.model,
            masked_key,
        )

        for idx, finding in enumerate(findings, start=1):
            logger.info("[%d/%d] Validating finding: %s", idx, len(findings), finding.title)
            self.validate_finding(finding)

    def _collect_screenshot_parts(self, finding: Finding, max_images: int = 4) -> list[dict[str, Any]]:
        """Collect base64-encoded image parts from finding screenshots for multimodal evaluation."""
        image_paths: list[str] = []
        if finding.step_screenshots:
            image_paths.extend(finding.step_screenshots)
        if finding.screenshot_path and finding.screenshot_path not in image_paths:
            image_paths.append(finding.screenshot_path)

        parts: list[dict[str, Any]] = []
        for path_str in image_paths[:max_images]:
            try:
                p = Path(path_str)
                if p.exists() and p.is_file() and p.stat().st_size <= 10 * 1024 * 1024:
                    raw_bytes = p.read_bytes()
                    b64_data = base64.b64encode(raw_bytes).decode("ascii")
                    mime_type = "image/png"
                    if p.suffix.lower() in (".jpg", ".jpeg"):
                        mime_type = "image/jpeg"
                    elif p.suffix.lower() == ".webp":
                        mime_type = "image/webp"

                    parts.append({
                        "inlineData": {
                            "mimeType": mime_type,
                            "data": b64_data,
                        }
                    })
            except Exception as exc:
                logger.debug("Notice reading screenshot '%s' for AI validator: %s", path_str, exc)

        return parts

    def validate_finding(self, finding: Finding) -> bool:
        """Validate a single finding against Gemini AI and update its validation fields in-place."""
        if not self.is_configured():
            return False

        prompt = self._build_prompt(finding)
        screenshot_parts = self._collect_screenshot_parts(finding)

        parts: list[dict[str, Any]] = [{"text": prompt}]
        if screenshot_parts:
            parts.extend(screenshot_parts)
            logger.debug("Attached %d visual screenshot(s) to Gemini validation payload.", len(screenshot_parts))

        endpoint_url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        )

        payload = {
            "contents": [
                {
                    "parts": parts
                }
            ],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json",
            },
        }

        try:
            with httpx.Client(timeout=self.timeout, transport=self.transport, verify=False) as client:
                resp = client.post(endpoint_url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        parts_resp = candidates[0].get("content", {}).get("parts", [])
                        if parts_resp:
                            raw_text = parts_resp[0].get("text", "")
                            return self._apply_validation_response(finding, raw_text)
                else:
                    logger.warning(
                        "[AI-VALIDATOR] Gemini API returned HTTP %d: %s",
                        resp.status_code,
                        resp.text[:200],
                    )
        except Exception as exc:
            logger.warning("[AI-VALIDATOR] Error contacting Gemini API for finding '%s': %s", finding.title, exc)

        return False

    def _build_prompt(self, finding: Finding) -> str:
        """Construct structured diagnostic prompt for Gemini."""
        req_info = {}
        if finding.request_metadata:
            req_info = {
                "url": finding.request_metadata.url,
                "method": finding.request_metadata.method,
                "headers": finding.request_metadata.headers,
                "body": finding.request_metadata.body,
            }

        res_info = {}
        if finding.response_metadata:
            res_info = {
                "status_code": finding.response_metadata.status_code,
                "latency_ms": finding.response_metadata.latency_ms,
                "body_preview": finding.response_metadata.body_preview,
            }

        context = {
            "title": finding.title,
            "detector_name": finding.detector_name,
            "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            "confidence": finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence),
            "url": finding.url,
            "method": finding.method,
            "parameter": finding.parameter,
            "evidence": finding.evidence,
            "evidence_type": finding.evidence_type.value if hasattr(finding.evidence_type, "value") else str(finding.evidence_type),
            "captured_dialog": finding.captured_dialog,
            "step_screenshots": finding.step_screenshots,
            "request_metadata": req_info,
            "response_metadata": res_info,
        }

        return f"""You are a Principal Application Security Auditor and DAST validation engine.
Analyze the following security finding generated during dynamic web application security testing.
Determine whether this finding is a CONFIRMED_VULNERABILITY or a FALSE_POSITIVE.

Finding Telemetry:
{json.dumps(context, indent=2)}

Evaluation Criteria:
1. Examine if the evidence clearly demonstrates vulnerability exploitation (e.g. SQL syntax error, command output canary execution, visual XSS rendering, missing security control).
2. Check if the response could be a benign reflection, a generic error message, or an irrelevant server response.
3. Assess the confidence level and determine if the reported severity matches the risk.

Respond with strict JSON adhering to this schema:
{{
  "is_false_positive": boolean,
  "status": "CONFIRMED_VULNERABILITY" | "FALSE_POSITIVE" | "NEEDS_REVIEW",
  "confidence_score": float between 0.0 and 1.0,
  "reasoning": "Clear and concise explanation of technical rationale",
  "recommended_severity": "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
}}"""

    def _apply_validation_response(self, finding: Finding, raw_json: str) -> bool:
        """Parse Gemini output and populate finding fields."""
        try:
            # Clean possible markdown code fences
            cleaned = raw_json.strip()
            if cleaned.startswith("```"):
                cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
                cleaned = re.sub(r"\s*```$", "", cleaned)

            parsed = json.loads(cleaned)
            is_fp = bool(parsed.get("is_false_positive", False))
            status = str(parsed.get("status", "CONFIRMED_VULNERABILITY" if not is_fp else "FALSE_POSITIVE"))
            reasoning = str(parsed.get("reasoning", ""))
            confidence_score = float(parsed.get("confidence_score", 0.95))

            finding.is_false_positive = is_fp
            finding.ai_validation_status = status
            finding.ai_validation_reasoning = reasoning
            finding.ai_confidence_score = confidence_score

            status_label = "[FALSE POSITIVE]" if is_fp else "[CONFIRMED]"
            logger.info(
                "[AI-VALIDATOR] %s %s (Confidence: %.0f%%) -> %s",
                status_label,
                finding.title,
                confidence_score * 100,
                reasoning,
            )
            return True
        except Exception as exc:
            logger.warning("[AI-VALIDATOR] Failed to parse validation JSON: %s (Raw: %s)", exc, raw_json[:200])
            return False

