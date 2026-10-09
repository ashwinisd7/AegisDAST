"""Tests for HTTPClient wrapper."""

import httpx
import pytest

from dast.http_client import HTTPClient


def test_http_client_get_success():
    def handler(request: httpx.Request):
        return httpx.Response(
            200,
            text="Hello World",
            headers={"Content-Type": "text/html; charset=utf-8"},
        )

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        resp, req_meta, res_meta = client.get("http://localhost:8000/test")

        assert resp is not None
        assert resp.status_code == 200
        assert req_meta.method == "GET"
        assert req_meta.url == "http://localhost:8000/test"
        assert res_meta is not None
        assert res_meta.status_code == 200
        assert "Hello World" in (res_meta.body_preview or "")


def test_http_client_post_success():
    def handler(request: httpx.Request):
        return httpx.Response(201, text='{"status": "created"}', headers={"Content-Type": "application/json"})

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        resp, req_meta, res_meta = client.post(
            "http://localhost:8000/api/items",
            data={"name": "test_item"},
        )
        assert resp is not None
        assert resp.status_code == 201
        assert req_meta.method == "POST"
        assert res_meta is not None
        assert res_meta.status_code == 201


def test_http_client_network_error_resilience():
    def handler(request: httpx.Request):
        raise httpx.ConnectError("Connection refused by target")

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        resp, req_meta, res_meta = client.get("http://offline-target.test")

        assert resp is None
        assert req_meta.url == "http://offline-target.test"
        assert res_meta is not None
        assert res_meta.status_code == 0
        assert "Network error" in (res_meta.body_preview or "")


def test_http_client_auto_reauthentication_on_session_expiration():
    call_count = 0
    reauth_count = 0

    def handler(request: httpx.Request):
        nonlocal call_count
        call_count += 1
        # First request returns 401 Unauthorized (session expired)
        if call_count == 1:
            return httpx.Response(401, text="Unauthorized: Session Expired")
        # After re-auth, second request returns 200 OK
        return httpx.Response(200, text="Welcome Authenticated User")

    def mock_reauth():
        nonlocal reauth_count
        reauth_count += 1
        return True

    transport = httpx.MockTransport(handler)
    with HTTPClient(transport=transport) as client:
        client.reauth_callback = mock_reauth
        resp, req_meta, res_meta = client.get("http://localhost:8000/protected/resource")

        assert reauth_count == 1
        assert call_count == 2
        assert resp is not None
        assert resp.status_code == 200
        assert "Welcome Authenticated User" in (res_meta.body_preview or "")
