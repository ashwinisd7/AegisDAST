"""Base Scenario Interface for File Inclusion & Path Traversal Evaluations."""

from __future__ import annotations

from abc import ABC, abstractmethod
import re
from typing import Any

from dast.http_client import HTTPClient
from dast.models import Endpoint, Finding, HttpMethod


class BaseFileInclusionScenario(ABC):
    """Abstract scenario contract for File Inclusion / Path Traversal testing techniques."""

    name: str = "base_file_inclusion"
    level: str = "Generic"
    technique: str = "Generic File Inclusion"

    # Known system file signatures
    TARGET_SIGNATURES = [
        (re.compile(r"root:.*:0:0:", re.I), "Linux /etc/passwd root user entry"),
        (re.compile(r"daemon:.*:1:1:", re.I), "Linux /etc/passwd daemon entry"),
        (re.compile(r"\[fonts\]|\[extensions\]", re.I), "Windows win.ini configuration header"),
        (re.compile(r"\[boot loader\]", re.I), "Windows boot.ini configuration header"),
        (re.compile(r"127\.0\.0\.1\s+localhost", re.I), "/etc/hosts or Windows hosts file entry"),
        (re.compile(r"<configuration>.*<system\.webServer>", re.I | re.DOTALL), "IIS web.config disclosure"),
    ]

    @abstractmethod
    def evaluate(
        self,
        endpoint: Endpoint,
        param_name: str,
        client: HTTPClient,
        detector: Any,
    ) -> Finding | None:
        """Evaluate a parameter for this file inclusion technique.

        Args:
            endpoint: HTTP endpoint being tested.
            param_name: Name of parameter to probe.
            client: Scoped HTTP client for requests.
            detector: Parent BaseDetector instance.

        Returns:
            A Finding if vulnerable, else None.
        """
        raise NotImplementedError

    @staticmethod
    def send_probe(
        endpoint: Endpoint, client: HTTPClient, param_name: str, probe_val: str
    ):
        """Helper to send injected parameter probe via GET or POST."""
        if endpoint.method == HttpMethod.POST:
            body = dict(endpoint.body_params)
            body[param_name] = probe_val
            return client.post(endpoint.url, data=body)
        else:
            params = dict(endpoint.params)
            params[param_name] = probe_val
            return client.get(endpoint.url, params=params)
