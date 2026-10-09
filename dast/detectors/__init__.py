"""Detector plugin module and base interfaces."""

from dast.detectors.base import BaseDetector
from dast.detectors.registry import DetectorRegistry

__all__ = ["BaseDetector", "DetectorRegistry"]
