"""Detector Registry for dynamic plugin discovery and taxonomy lifecycle management."""

from __future__ import annotations

import importlib
import logging
from pathlib import Path
from typing import Sequence

from dast.detectors.base import BaseDetector
from dast.models import DetectorCategory, DetectorRequirement

logger = logging.getLogger(__name__)


class DetectorRegistry:
    """Registry maintaining active and discoverable security detector plugins."""

    def __init__(self) -> None:
        self._registry: dict[str, type[BaseDetector]] = {}

    def register(self, detector_cls: type[BaseDetector]) -> type[BaseDetector]:
        """Register a detector class. Can also be used as a decorator."""
        if not issubclass(detector_cls, BaseDetector):
            raise TypeError(f"{detector_cls} must subclass BaseDetector")
        if not detector_cls.name or detector_cls.name == "base_detector":
            raise ValueError(f"Detector {detector_cls.__name__} must define a valid unique 'name'")

        self._registry[detector_cls.name] = detector_cls
        return detector_cls

    def get_class(self, name: str) -> type[BaseDetector] | None:
        """Lookup detector class by registered name."""
        return self._registry.get(name)

    def list_available(self) -> list[str]:
        """List names of all registered detectors."""
        return sorted(list(self._registry.keys()))

    def list_by_category(self) -> dict[str, list[str]]:
        """Group registered detectors by vulnerability taxonomy category."""
        grouped: dict[str, list[str]] = {}
        for name, cls in self._registry.items():
            cat = cls.category.value if hasattr(cls.category, "value") else str(cls.category)
            grouped.setdefault(cat, []).append(name)
        return {k: sorted(v) for k, v in sorted(grouped.items())}

    def list_by_requirement(self) -> dict[str, list[str]]:
        """Group registered detectors by runtime requirement."""
        grouped: dict[str, list[str]] = {}
        for name, cls in self._registry.items():
            req = cls.requirement.value if hasattr(cls.requirement, "value") else str(cls.requirement)
            grouped.setdefault(req, []).append(name)
        return {k: sorted(v) for k, v in sorted(grouped.items())}

    def list_active(self) -> list[str]:
        """List names of all registered detectors that are currently marked active."""
        from dast.config import is_detector_active
        return [name for name in self.list_available() if is_detector_active(name)]

    def get_instances(
        self,
        selected_names: Sequence[str] | None = None,
        categories: Sequence[DetectorCategory | str] | None = None,
        requirements: Sequence[DetectorRequirement | str] | None = None,
        respect_active_status: bool = True,
    ) -> list[BaseDetector]:
        """Instantiate requested detectors, optionally filtered by name, category, and requirements."""
        classes = list(self._registry.values())

        # Filter by name if specified
        if selected_names and "all" not in selected_names:
            classes = [self._registry[n] for n in selected_names if n in self._registry]
        elif respect_active_status:
            from dast.config import is_detector_active
            classes = [cls for cls in classes if is_detector_active(cls.name)]

        # Filter by category if specified
        if categories:
            cat_values = {c.value if hasattr(c, "value") else str(c) for c in categories}
            classes = [
                cls for cls in classes
                if (cls.category.value if hasattr(cls.category, "value") else str(cls.category)) in cat_values
            ]

        # Filter by requirement if specified
        if requirements:
            req_values = {r.value if hasattr(r, "value") else str(r) for r in requirements}
            classes = [
                cls for cls in classes
                if (cls.requirement.value if hasattr(cls.requirement, "value") else str(cls.requirement)) in req_values
            ]

        return [cls() for cls in classes]

    def discover_builtin(self) -> None:
        """Recursively scan subpackages under dast/detectors/ and load all detector plugins."""
        detectors_dir = Path(__file__).parent

        for path in detectors_dir.rglob("detector.py"):
            relative_parts = path.relative_to(detectors_dir.parent).with_suffix("").parts
            module_path = "dast." + ".".join(relative_parts)

            try:
                module = importlib.import_module(module_path)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseDetector)
                        and attr is not BaseDetector
                        and attr.name != "base_detector"
                    ):
                        self.register(attr)
            except Exception as exc:
                logger.error("Failed to load detector module '%s': %s", module_path, exc)


# Global default registry instance
default_registry = DetectorRegistry()

