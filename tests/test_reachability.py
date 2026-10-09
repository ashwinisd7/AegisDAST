"""Unit tests for pre-flight reachability checking and authentication module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from dast.browser import BrowserManager
from dast.cli import build_parser, main
from dast.http_client import HTTPClient
from dast.models import Target
from dast.reachability import check_reachability_with_curl, configure_authentication


def test_reachability_with_curl_success() -> None:
    """Test reachability check when curl returns HTTP 200."""
    with patch("shutil.which", return_value="C:\\Windows\\System32\\curl.exe"):
        mock_res = MagicMock(returncode=0, stdout="HTTP/1.1 200 OK\r\nContent-Length: 12\r\n", stderr="")
        with patch("subprocess.run", return_value=mock_res) as mock_run:
            reachable, status, msg = check_reachability_with_curl(
                url="http://localhost:8000",
                auth=("admin", "secret"),
                custom_headers={"X-Test": "Val"},
                timeout=5.0,
            )
            assert reachable is True
            assert status == 200
            assert "200" in msg
            # Check curl invocation arguments
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert "-u" in args
            assert "admin:secret" in args
            assert "-H" in args
            assert "X-Test: Val" in args


def test_reachability_with_curl_401_unauthorized() -> None:
    """Test reachability check when target returns 401 Unauthorized."""
    with patch("shutil.which", return_value="curl"):
        mock_res = MagicMock(returncode=0, stdout="HTTP/1.1 401 Unauthorized\r\n", stderr="")
        with patch("subprocess.run", return_value=mock_res):
            reachable, status, msg = check_reachability_with_curl(
                url="http://localhost:8000/protected",
                auth=("wrong", "pass"),
            )
            assert reachable is True
            assert status == 401


def test_reachability_curl_fallback_to_http() -> None:
    """Test reachability fallback to httpx probe when curl is not found or fails."""
    with patch("shutil.which", return_value=None):
        mock_resp = httpx.Response(status_code=200, request=httpx.Request("GET", "http://testserver"))
        with patch.object(httpx.Client, "get", return_value=mock_resp):
            reachable, status, msg = check_reachability_with_curl(
                url="http://localhost:8000",
                auth=("admin", "pass"),
            )
            assert reachable is True
            assert status == 200


def test_reachability_unreachable_target() -> None:
    """Test reachability check when host is completely unreachable."""
    with patch("shutil.which", return_value=None):
        with patch.object(httpx.Client, "get", side_effect=httpx.ConnectError("Connection refused")):
            reachable, status, msg = check_reachability_with_curl(
                url="http://nonexistent.local:9999",
            )
            assert reachable is False
            assert status == 0
            assert "Unreachable" in msg


def test_configure_authentication_http_and_browser() -> None:
    """Test configuring authentication across HTTPClient and BrowserManager."""
    target = Target(
        url="http://localhost:8000",
        auth=("admin", "password123"),
    )

    client = HTTPClient()
    browser = BrowserManager()

    configured, landing_url = configure_authentication(target, client=client, browser=browser)
    assert configured is True
    assert landing_url == "http://localhost:8000"
    assert client.auth == ("admin", "password123")
    assert isinstance(client._client.auth, httpx.BasicAuth)
    assert browser.http_credentials == {"username": "admin", "password": "password123"}


def test_configure_authentication_form_login() -> None:
    """Test form-based login automation when login_url is provided."""
    target = Target(
        url="http://localhost:8000",
        auth=("admin", "password123"),
        login_url="http://localhost:8000/login",
    )

    mock_client = MagicMock()
    mock_get_resp = MagicMock(status_code=200, text='<input type="hidden" name="user_token" value="xyz999">')
    mock_post_resp = MagicMock(status_code=302, headers={"location": "/dashboard.php"})
    mock_landing_resp = MagicMock(status_code=200, text="<title>Dashboard Area</title>")

    mock_client.get.side_effect = [(mock_get_resp, None, None), (mock_landing_resp, None, None)]
    mock_client.post.return_value = (mock_post_resp, 0.1, None)
    mock_client._client.cookies = {"session": "abc123"}

    configured, landing_url = configure_authentication(target, client=mock_client)
    assert configured is True
    assert "dashboard.php" in landing_url
    mock_client.post.assert_called_once()
    call_args = mock_client.post.call_args
    assert call_args[0][0] == "http://localhost:8000/login"
    assert call_args[1]["data"]["username"] == "admin"
    assert call_args[1]["data"]["password"] == "password123"
    assert call_args[1]["data"]["user_token"] == "xyz999"


def test_crawler_crawls_authenticated_landing_page() -> None:
    """Test crawler visiting authenticated landing page and discovering downstream links."""
    from dast.crawler import Crawler

    target = Target(url="http://app.local", max_depth=2, max_pages=10)

    html_home = '<html><body><a href="/login">Login</a></body></html>'
    html_dashboard = '<html><head><title>Admin Panel</title></head><body><a href="/admin/users">Users</a><a href="/admin/settings">Settings</a></body></html>'
    html_users = '<html><body><h1>User List</h1></body></html>'
    html_settings = '<html><body><h1>Settings</h1></body></html>'

    def router(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/dashboard":
            return httpx.Response(200, text=html_dashboard, headers={"Content-Type": "text/html"})
        elif path == "/admin/users":
            return httpx.Response(200, text=html_users, headers={"Content-Type": "text/html"})
        elif path == "/admin/settings":
            return httpx.Response(200, text=html_settings, headers={"Content-Type": "text/html"})
        return httpx.Response(200, text=html_home, headers={"Content-Type": "text/html"})

    transport = httpx.MockTransport(router)
    with HTTPClient(transport=transport) as client:
        crawler = Crawler(target=target, client=client, seed_urls=["http://app.local/dashboard"])
        endpoints = crawler.crawl()

        discovered_urls = {ep.url for ep in endpoints}
        assert "http://app.local/dashboard" in discovered_urls
        assert "http://app.local/admin/users" in discovered_urls
        assert "http://app.local/admin/settings" in discovered_urls


def test_configure_authentication_with_after_auth_url() -> None:
    """Test login verification when after_auth_url is provided."""
    target = Target(
        url="http://localhost:8000",
        auth=("admin", "password123"),
        login_url="http://localhost:8000/login.php",
        after_auth_url="http://localhost:8000/portal.php",
    )

    mock_client = MagicMock()
    mock_get_resp = MagicMock(status_code=200, text='<form method="POST"><input name="username"><input name="password"></form>')
    mock_post_resp = MagicMock(status_code=302, headers={"location": "/portal.php"})
    mock_portal_resp = MagicMock(status_code=200, text="<title>Member Portal</title><h1>Welcome Admin</h1>", url="http://localhost:8000/portal.php")

    mock_client.get.side_effect = [(mock_get_resp, None, None), (mock_portal_resp, None, None), (mock_portal_resp, None, None)]
    mock_client.post.return_value = (mock_post_resp, 0.1, None)
    mock_client._client.cookies = {"PHPSESSID": "sess123456"}

    configured, landing_url = configure_authentication(target, client=mock_client)
    assert configured is True
    assert "portal.php" in landing_url


def test_cli_auth_argument_parsing() -> None:
    """Test CLI argument parser parsing -u/--auth, --login-url, and --after-auth-url."""
    parser = build_parser()
    args = parser.parse_args([
        "http://localhost:8000",
        "-u", "admin:secret123",
        "--login-url", "http://localhost:8000/login.php",
        "--after-auth-url", "http://localhost:8000/portal.php",
    ])

    assert args.auth == "admin:secret123"
    assert args.login_url == "http://localhost:8000/login.php"
    assert args.after_auth_url == "http://localhost:8000/portal.php"

