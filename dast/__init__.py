"""DAST - Modular Dynamic Application Security Testing Framework."""

from dast.config import DETECTOR_STATUS, get_active_detectors, get_inactive_detectors, is_detector_active

__version__ = "0.1.0"
__all__ = ["DETECTOR_STATUS", "is_detector_active", "get_active_detectors", "get_inactive_detectors"]
