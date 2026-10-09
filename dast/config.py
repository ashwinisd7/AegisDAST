"""Central configuration for DAST detector activation status.

You can toggle any detector between True ('active') and False ('inactive').
Only active detectors will be loaded and executed during scans by default.
"""

from __future__ import annotations

from typing import Any

# List of all detectors and their active status (True = active, False = inactive)
DETECTOR_STATUS: dict[str, bool | str] = {
    # Injection Detectors
    "command_injection": True,
    "sqli": True,
    "file_inclusion": True,
    "ssrf": True,
    "php_code_injection": True,
    "ssii": True,
    "xpath_injection": True,
    "xxe": True,
    "html_injection": True,
    "hpp": True,
    "crlf": True,
    "ssti": True,

    # Cross-Site Scripting (XSS) Detectors
    "xss": True,
    "stored_xss": True,
    "dom_xss": True,

    # Cookie & Session Detectors
    "cookies": True,
    "csrf": True,
    "weak_session_ids": True,

    # Broken Authentication Detectors
    "brute_force": True,
    "insecure_captcha": True,

    # File Handling Detectors
    "file_upload": True,

    # Security Misconfiguration Detectors
    "security_headers": True,
    "cors": True,
    "csp_bypass": True,
    "javascript": True,
    "open_redirect": True,
    "clickjacking": True,
}


def is_detector_active(name: str) -> bool:
    """Check if a detector is marked active in DETECTOR_STATUS."""
    val: Any = DETECTOR_STATUS.get(name, True)
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in ("active", "enabled", "true", "1", "yes")
    return bool(val)


def get_active_detectors() -> list[str]:
    """Return a list of all detector names that are currently active."""
    return [name for name, status in DETECTOR_STATUS.items() if is_detector_active(name)]


def get_inactive_detectors() -> list[str]:
    """Return a list of all detector names that are currently inactive."""
    return [name for name, status in DETECTOR_STATUS.items() if not is_detector_active(name)]

