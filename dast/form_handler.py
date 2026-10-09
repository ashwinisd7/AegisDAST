"""Form interaction, payload population, and submission engine.

Simple form handler: takes a form and payload, fills the payload into the form's
input fields, submits the form, and returns the resulting response and screenshot.
"""

from __future__ import annotations

import logging
from typing import Any

from dast.browser import BrowserManager
from dast.http_client import HTTPClient
from dast.models import FormModel, HTTPRequestMetadata, HTTPResponseMetadata

logger = logging.getLogger(__name__)


class FormHandler:
    """Manages form payload population and submission."""

    def __init__(
        self,
        client: HTTPClient | None = None,
        browser: BrowserManager | None = None,
    ) -> None:
        self.client = client
        self.browser = browser

    def fill_form_data(
        self,
        form: FormModel,
        target_input: str,
        value: str,
        companion_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Construct data dictionary for form submission, filling payload only into text inputs."""
        data: dict[str, Any] = {}

        matched_field = form.find_input(target_input)
        target_name = matched_field.name if matched_field else target_input

        for inp in form.inputs:
            if not inp.name:
                continue
            if inp.name == target_name:
                # Fill payload only when input type is text
                if inp.input_type.lower() in ("text", "search", "textarea", "input", ""):
                    data[inp.name] = value
                else:
                    data[inp.name] = inp.value or inp.name or "Submit"
            elif inp.value:
                data[inp.name] = inp.value
            elif inp.input_type in ("hidden", "submit"):
                data[inp.name] = inp.value or inp.name or "Submit"
            else:
                data[inp.name] = inp.value or "test"

        if matched_field:
            if matched_field.input_type.lower() in ("text", "search", "textarea", "input", ""):
                data[target_name] = value
        else:
            data[target_name] = value

        if companion_data:
            data.update(companion_data)

        return data

    def submit_http(
        self,
        form: FormModel,
        target_input: str,
        value: str,
        client: HTTPClient | None = None,
        companion_data: dict[str, Any] | None = None,
    ) -> tuple[Any, HTTPRequestMetadata | None, HTTPResponseMetadata | None]:
        """Submit form via HTTP."""
        c = client or self.client
        if not c:
            raise ValueError("An HTTPClient instance is required for submit_http.")

        payload_data = self.fill_form_data(form, target_input, value, companion_data)
        if form.method.upper() == "POST":
            return c.post(form.action, data=payload_data)
        return c.get(form.action, params=payload_data)

    def submit_browser(
        self,
        form: FormModel,
        target_input: str,
        value: str,
        browser: BrowserManager | None = None,
        companion_data: dict[str, Any] | None = None,
        step_name: str = "form_submit",
        detector_name: str | None = None,
        wait_ms: int = 500,
    ) -> tuple[str, str | None]:
        """Submit form via Playwright browser."""
        b = browser or self.browser
        if not b or not hasattr(b, "fill_and_submit_form"):
            raise ValueError("A BrowserManager instance is required for submit_browser.")

        matched_field = form.find_input(target_input)
        target_name = matched_field.name if matched_field else target_input

        all_data = self.fill_form_data(form, target_input, value, companion_data)
        companion_fields = {k: v for k, v in all_data.items() if k != target_name}

        try:
            try:
                return b.fill_and_submit_form(
                    url=form.action,
                    target_param=target_name,
                    payload=value,
                    companion_fields=companion_fields,
                    step_name=step_name,
                    detector_name=detector_name,
                    wait_ms=wait_ms,
                )
            except TypeError:
                return b.fill_and_submit_form(
                    url=form.action,
                    target_param=target_name,
                    payload=value,
                    companion_fields=companion_fields,
                    step_name=step_name,
                    wait_ms=wait_ms,
                )
        except Exception as exc:
            logger.debug("Notice submitting form via browser: %s. Falling back to HTTP.", exc)
            if self.client:
                resp, _, _ = self.submit_http(
                    form=form,
                    target_input=target_name,
                    value=value,
                    client=self.client,
                    companion_data=companion_data,
                )
                return (resp.text if resp else ""), None
            return "", None

    def fill_and_submit(
        self,
        form: FormModel,
        payload: str,
        target_input: str | None = None,
        companion_data: dict[str, Any] | None = None,
        step_name: str = "form_submit",
        detector_name: str | None = None,
        prefer_browser: bool = False,
        client: HTTPClient | None = None,
        browser: BrowserManager | None = None,
    ) -> tuple[str, str | None]:
        """Fill payload into form inputs, submit, and return response text and screenshot."""
        b = browser or self.browser
        c = client or self.client

        # Auto-detect target input if not specified (only text inputs)
        target = None
        if target_input:
            inp = form.find_input(target_input)
            if inp and inp.input_type.lower() in ("text", "search", "textarea", "input", ""):
                target = inp.name
            elif not inp:
                target = target_input

        if not target:
            for inp in form.inputs:
                if inp.name and inp.input_type.lower() in ("text", "search", "textarea", "input", ""):
                    target = inp.name
                    break

        if not target:
            return "", None

        # Submit via browser only if specifically preferred (e.g. DOM XSS)
        if prefer_browser and b and hasattr(b, "fill_and_submit_form"):
            try:
                res_html, res_img = self.submit_browser(
                    form=form,
                    target_input=target,
                    value=payload,
                    browser=b,
                    companion_data=companion_data,
                    step_name=step_name,
                    detector_name=detector_name,
                )
                if res_html or res_img:
                    return res_html, res_img
            except Exception as exc:
                logger.debug("Browser form submit failed (%s). Using HTTP client fallback.", exc)

        # High-speed HTTP submission (thread-safe for parallel workers)
        if c:
            resp, _, _ = self.submit_http(
                form=form,
                target_input=target,
                value=payload,
                client=c,
                companion_data=companion_data,
            )
            return (resp.text if resp else ""), None

        if b and hasattr(b, "fill_and_submit_form"):
            try:
                return self.submit_browser(
                    form=form,
                    target_input=target,
                    value=payload,
                    browser=b,
                    companion_data=companion_data,
                    step_name=step_name,
                    detector_name=detector_name,
                )
            except Exception:
                return "", None

        return "", None

    def save_interaction_steps(self, detector_name: str | None = None, browser: BrowserManager | None = None) -> list[str]:
        """Save buffered step screenshots from browser when a finding is generated."""
        b = browser or self.browser
        if b and hasattr(b, "save_interaction_steps"):
            return b.save_interaction_steps(detector_name=detector_name)
        return []

    def clear_interaction_steps(self, browser: BrowserManager | None = None) -> None:
        """Clear buffered step screenshots."""
        b = browser or self.browser
        if b and hasattr(b, "clear_interaction_steps"):
            b.clear_interaction_steps()


