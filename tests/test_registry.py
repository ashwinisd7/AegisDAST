"""Tests for DetectorRegistry plugin discovery, taxonomy categorization, and requirements."""

import pytest

from dast.detectors.base import BaseDetector
from dast.detectors.registry import DetectorRegistry
from dast.http_client import HTTPClient
from dast.models import DetectorCategory, DetectorRequirement, Endpoint, Finding


class DummyDetector(BaseDetector):
    name = "dummy_test"
    description = "Test detector for unit tests"
    category = DetectorCategory.INJECTION
    requirement = DetectorRequirement.REQUESTS

    def scan(self, endpoint: Endpoint, client: HTTPClient, **kwargs) -> list[Finding]:
        return []


def test_registry_registration_and_retrieval():
    registry = DetectorRegistry()
    registry.register(DummyDetector)

    assert "dummy_test" in registry.list_available()
    assert registry.get_class("dummy_test") is DummyDetector

    instances = registry.get_instances(["dummy_test"])
    assert len(instances) == 1
    assert isinstance(instances[0], DummyDetector)


def test_registry_invalid_registration():
    registry = DetectorRegistry()

    class NotADetector:
        pass

    with pytest.raises(TypeError):
        registry.register(NotADetector)  # type: ignore


def test_registry_builtin_discovery_and_taxonomy_categories():
    registry = DetectorRegistry()
    registry.discover_builtin()

    available = registry.list_available()
    assert "security_headers" in available
    assert "cors" in available
    assert "xss" in available
    assert "sqli" in available
    assert "ssrf" in available
    assert "cookies" in available
    assert "csrf" in available
    assert "brute_force" in available
    assert "file_upload" in available
    assert "javascript" in available

    # Test categorization by vulnerability taxonomy
    by_category = registry.list_by_category()
    assert "injection" in by_category
    assert "xss" in by_category
    assert "cookie_based" in by_category
    assert "broken_auth" in by_category
    assert "file_handling" in by_category
    assert "misconfiguration" in by_category

    assert "sqli" in by_category["injection"]
    assert "xss" in by_category["xss"]
    assert "csrf" in by_category["cookie_based"]
    assert "brute_force" in by_category["broken_auth"]
    assert "file_upload" in by_category["file_handling"]
    assert "security_headers" in by_category["misconfiguration"]

    # Test filtering instances by category (without status filtering)
    inj_instances = registry.get_instances(categories=[DetectorCategory.INJECTION], respect_active_status=False)
    inj_names = {i.name for i in inj_instances}
    assert "sqli" in inj_names
    assert "command_injection" in inj_names
    assert "security_headers" not in inj_names

    xss_instances = registry.get_instances(categories=["xss"], respect_active_status=False)
    xss_names = {i.name for i in xss_instances}
    assert "xss" in xss_names
    assert "stored_xss" in xss_names
    assert "dom_xss" in xss_names
    assert "sqli" not in xss_names


def test_registry_active_status_filtering(monkeypatch):
    from dast.config import DETECTOR_STATUS, is_detector_active

    registry = DetectorRegistry()
    registry.discover_builtin()

    # Ensure both are active in test
    monkeypatch.setitem(DETECTOR_STATUS, "command_injection", True)
    monkeypatch.setitem(DETECTOR_STATUS, "sqli", True)

    active_list = registry.list_active()
    assert "command_injection" in active_list
    assert "sqli" in active_list

    # Toggle one detector to inactive
    monkeypatch.setitem(DETECTOR_STATUS, "command_injection", False)
    assert not is_detector_active("command_injection")

    updated_active = registry.list_active()
    assert "command_injection" not in updated_active
    assert "sqli" in updated_active

    # When getting instances respecting active status, inactive one should not be instantiated
    instances = registry.get_instances(respect_active_status=True)
    instance_names = {i.name for i in instances}
    assert "command_injection" not in instance_names
    assert "sqli" in instance_names

    # When explicitly requested by name, it can still run
    explicit_instances = registry.get_instances(selected_names=["command_injection"])
    assert len(explicit_instances) == 1
    assert explicit_instances[0].name == "command_injection"

