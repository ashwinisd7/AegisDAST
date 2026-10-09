"""Base Scenario Interface for Weak Session ID Evaluations."""

from __future__ import annotations

from abc import ABC, abstractmethod
import math
from typing import Any

from dast.models import Endpoint, Finding


class BaseSessionScenario(ABC):
    """Abstract scenario evaluator for session token predictability."""

    @abstractmethod
    def evaluate(
        self,
        cookie_name: str,
        samples: list[dict[str, Any]],
        endpoint: Endpoint,
        detector: Any,
    ) -> Finding | None:
        """Evaluate a set of cookie samples for this specific scenario pattern.

        Args:
            cookie_name: Name of the session cookie (e.g. 'dvwaSession').
            samples: List of parsed cookie attribute dictionaries across requests.
            endpoint: Discovered HTTP endpoint under audit.
            detector: The parent BaseDetector instance to invoke create_finding().

        Returns:
            A Finding if the scenario vulnerability is confirmed, else None.
        """
        raise NotImplementedError

    @staticmethod
    def shannon_entropy(s: str) -> float:
        """Calculate Shannon entropy in bits per character symbol."""
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
        return -sum(p * math.log(p) / math.log(2.0) for p in prob)

    @staticmethod
    def format_table(
        title: str,
        cookie_name: str,
        level: str,
        pattern: str,
        entropy: str,
        length: str,
        next_pred: str,
        flags: dict[str, Any],
        samples: list[str],
    ) -> str:
        """Render high-clarity ASCII terminal diagnostic table."""
        sep = "+" + "-" * 26 + "+" + "-" * 50 + "+"
        lines = [
            sep,
            f"| {'Audit Category':<24} | {title:<48} |",
            sep,
            f"| {'Cookie Target':<24} | {cookie_name:<48} |",
            f"| {'Identified Level':<24} | {level:<48} |",
            f"| {'Algorithm Pattern':<24} | {pattern:<48} |",
            f"| {'Shannon Entropy':<24} | {entropy:<48} |",
            f"| {'Token Length':<24} | {length:<48} |",
            f"| {'Predicted Next Token':<24} | {next_pred:<48} |",
            sep,
            f"| {'Cookie Flags & Scoping':<24} | {'Secure: ' + str(flags.get('secure', False)) + ' | HttpOnly: ' + str(flags.get('httponly', False)) + ' | SameSite: ' + str(flags.get('samesite', 'None')):<48} |",
            f"| {'Path / Domain Scope':<24} | {'Path: ' + str(flags.get('path')) + ' | Domain: ' + str(flags.get('domain')):<48} |",
            sep,
            "Collected Token Samples:",
        ]
        for idx, sample in enumerate(samples[:4], start=1):
            lines.append(f"  #{idx}: {sample}")

        return "\n".join(lines)

