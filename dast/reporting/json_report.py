"""JSON Reporting module for serializing DAST scan results."""

from __future__ import annotations

import json
from pathlib import Path

from dast.models import ScanResult


class JSONReporter:
    """Serializes standardized ScanResult models to structured JSON artifacts."""

    @staticmethod
    def generate(scan_result: ScanResult, indent: int = 2) -> str:
        """Serialize ScanResult to formatted JSON string."""
        data = scan_result.model_dump(mode="json")
        return json.dumps(data, indent=indent)

    @classmethod
    def save(cls, scan_result: ScanResult, file_path: str | Path, indent: int = 2) -> Path:
        """Write serialized scan report directly to filesystem."""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = cls.generate(scan_result, indent=indent)
        path.write_text(content, encoding="utf-8")
        return path
