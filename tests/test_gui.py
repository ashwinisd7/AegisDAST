"""Tests for DAST Flask Web GUI Dashboard and API endpoints."""

import json
import pytest
from dast.gui.app import create_app, ScanManager


@pytest.fixture
def app():
    """Create Flask test client application instance."""
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def test_gui_index_page(client):
    """Test that the Web GUI HTML dashboard renders successfully."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"DAST Security Auditor" in response.data
    assert b"Scan Configuration" in response.data
    assert b"Launch Security Assessment" in response.data


def test_gui_api_detectors(client):
    """Test the /api/detectors endpoint returns plugin list."""
    response = client.get("/api/detectors")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert len(data) > 0
    assert "name" in data[0]
    assert "category" in data[0]


def test_gui_api_status(client):
    """Test the /api/scan/status endpoint."""
    response = client.get("/api/scan/status")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "status" in data
    assert data["status"] in ["idle", "running", "completed", "error", "stopped"]
    assert "stats" in data
    assert "findings" in data
    assert "endpoints" in data


def test_gui_api_scan_validation_no_url(client):
    """Test /api/scan/start returns 400 error when URL is missing."""
    response = client.post(
        "/api/scan/start",
        json={"target_url": ""},
        content_type="application/json",
    )
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data


def test_scan_manager_state():
    """Test ScanManager state management and event subscriptions."""
    sm = ScanManager()
    assert sm.status == "idle"
    sub = sm.subscribe()
    assert sub in sm.subscribers

    sm.broadcast("test_event", {"payload": 123})
    event = sub.get_nowait()
    assert event["type"] == "test_event"
    assert event["data"] == {"payload": 123}

    sm.unsubscribe(sub)
    assert sub not in sm.subscribers


def test_scan_manager_stop_cleans_state():
    """Test ScanManager properly stops and clears state and artifacts."""
    sm = ScanManager()
    sm.status = "running"
    sm.current_endpoints.append({"url": "http://example.com/test", "method": "GET", "params": ["id"]})
    sm.current_findings.append({"title": "SQL Injection", "url": "http://example.com/test", "severity": "HIGH"})
    sm.stats["endpoints_crawled"] = 1
    sm.stats["total_findings"] = 1

    ok, msg = sm.stop_scan()
    assert ok is True
    assert sm.status == "idle"
    assert sm.current_scan_id is None
    assert len(sm.current_endpoints) == 0
    assert len(sm.current_findings) == 0
    assert sm.stats["endpoints_crawled"] == 0
    assert sm.stats["total_findings"] == 0


def test_gui_api_stop_endpoint(client):
    """Test the /api/scan/stop endpoint."""
    response = client.post("/api/scan/stop")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data.get("success") is True

