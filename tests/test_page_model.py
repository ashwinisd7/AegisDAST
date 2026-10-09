"""Tests for PageModel, FormModel, InputField, Resource, and FormHandler."""

from pathlib import Path
from bs4 import BeautifulSoup
import httpx
import pytest

from dast.crawler import Crawler
from dast.form_handler import FormHandler
from dast.http_client import HTTPClient
from dast.models import (
    Endpoint,
    FormModel,
    HttpMethod,
    InputField,
    PageModel,
    Resource,
    ResourceType,
    Target,
)


def test_user_requested_page_model_schema():
    """Verify PageModel schema directly matches the user's specification."""
    page = PageModel(
        url="https://example.com/login",
        status_code=200,
        content_type="text/html",
        title="Login",
        links=[
            "https://example.com/",
            "https://example.com/register",
        ],
        forms=[
            FormModel(
                action="https://example.com/login",
                method="POST",
                inputs=[
                    InputField(
                        name="username",
                        input_type="text",
                        placeholder="Username",
                        required=True,
                    ),
                    InputField(
                        name="password",
                        input_type="password",
                        required=True,
                    ),
                    InputField(
                        name="csrf_token",
                        input_type="hidden",
                        value="abc123",
                    ),
                ],
            )
        ],
        resources=[
            Resource(
                url="https://example.com/static/app.css",
                resource_type=ResourceType.CSS,
                tag="link",
            ),
            Resource(
                url="https://example.com/static/app.js",
                resource_type=ResourceType.JAVASCRIPT,
                tag="script",
            ),
        ],
    )

    assert page.url == "https://example.com/login"
    assert page.status_code == 200
    assert page.title == "Login"
    assert len(page.links) == 2
    assert len(page.forms) == 1
    assert len(page.resources) == 2

    # Check form structure
    form = page.forms[0]
    assert form.action == "https://example.com/login"
    assert form.method == "POST"
    assert len(form.inputs) == 3

    # Check field lookup by name and by placeholder
    user_field = form.find_input("username")
    assert user_field is not None
    assert user_field.input_type == "text"
    assert user_field.placeholder == "Username"
    assert user_field.required is True

    # Lookup by placeholder
    by_placeholder = form.find_input("Username")
    assert by_placeholder is not None
    assert by_placeholder.name == "username"

    csrf_field = form.find_input("csrf_token")
    assert csrf_field is not None
    assert csrf_field.value == "abc123"

    # Check resources
    css_res = page.resources[0]
    assert css_res.resource_type == ResourceType.CSS
    assert css_res.tag == "link"


def test_crawler_extracts_page_model_and_forms():
    """Verify Crawler parses HTML and constructs PageModel with links, forms, and resources."""
    html_page = """<!DOCTYPE html>
    <html>
    <head>
        <title>Account Portal</title>
        <link rel="stylesheet" href="/static/style.css">
        <script src="/static/bundle.js"></script>
    </head>
    <body>
        <h1>Welcome</h1>
        <a href="/dashboard">Dashboard</a>
        <a href="/profile">Profile</a>
        <img src="/static/logo.png" alt="Logo">

        <form action="/login" method="POST">
            <input type="text" name="user" placeholder="Enter username" required />
            <input type="password" name="pass" placeholder="Password" required />
            <input type="hidden" name="csrf_token" value="sec_token_999" />
            <select name="role">
                <option value="admin">Administrator</option>
                <option value="user">Standard User</option>
            </select>
            <input type="submit" name="Submit" value="Login" />
        </form>
    </body>
    </html>"""

    def handler(request: httpx.Request):
        return httpx.Response(200, text=html_page, headers={"Content-Type": "text/html; charset=utf-8"})

    transport = httpx.MockTransport(handler)
    target = Target(url="http://app.local", max_depth=0)

    with HTTPClient(transport=transport) as client:
        crawler = Crawler(target=target, client=client)
        endpoints = crawler.crawl()
        pages = crawler.get_pages()

        assert len(pages) == 1
        page = pages[0]
        assert page.url == "http://app.local/"
        assert page.title == "Account Portal"
        assert page.status_code == 200
        assert "text/html" in page.content_type

        # Verify links extracted
        assert "http://app.local/dashboard" in page.links
        assert "http://app.local/profile" in page.links

        # Verify resources extracted (CSS, JS, Image)
        resource_urls = [r.url for r in page.resources]
        assert "http://app.local/static/style.css" in resource_urls
        assert "http://app.local/static/bundle.js" in resource_urls
        assert "http://app.local/static/logo.png" in resource_urls

        types = {r.resource_type for r in page.resources}
        assert ResourceType.CSS in types
        assert ResourceType.JAVASCRIPT in types
        assert ResourceType.IMAGE in types

        # Verify forms extracted into FormModel
        assert len(page.forms) == 1
        form = page.forms[0]
        assert form.action == "http://app.local/login"
        assert form.method == "POST"

        inputs_by_name = {inp.name: inp for inp in form.inputs}
        assert "user" in inputs_by_name
        assert inputs_by_name["user"].placeholder == "Enter username"
        assert inputs_by_name["user"].required is True

        assert "csrf_token" in inputs_by_name
        assert inputs_by_name["csrf_token"].value == "sec_token_999"
        assert inputs_by_name["csrf_token"].input_type == "hidden"

        assert "role" in inputs_by_name
        assert inputs_by_name["role"].input_type == "select"
        assert "admin" in inputs_by_name["role"].options

        # Verify endpoint has attached FormModel
        login_ep = [ep for ep in endpoints if "/login" in ep.url]
        assert len(login_ep) == 1
        assert len(login_ep[0].forms) == 1
        assert login_ep[0].forms[0].action == "http://app.local/login"


def test_form_handler_filling_by_placeholder_and_name():
    """Verify FormHandler accurately populates values matching name or placeholder and preserves CSRF tokens."""
    form = FormModel(
        action="http://app.local/submit",
        method="POST",
        inputs=[
            InputField(name="username", input_type="text", placeholder="Username or Email", required=True),
            InputField(name="password", input_type="password", placeholder="Enter Password", required=True),
            InputField(name="user_token", input_type="hidden", value="csrf_secret_abc"),
            InputField(name="submit_btn", input_type="submit", value="SubmitForm"),
        ],
    )

    handler = FormHandler()

    # 1. Fill targeting by placeholder
    filled_by_placeholder = handler.fill_form_data(
        form=form,
        target_input="Username or Email",
        value="admin' OR '1'='1",
    )

    assert filled_by_placeholder["username"] == "admin' OR '1'='1"
    assert filled_by_placeholder["user_token"] == "csrf_secret_abc"
    assert filled_by_placeholder["submit_btn"] == "SubmitForm"

    # 2. Fill targeting by exact name
    filled_by_name = handler.fill_form_data(
        form=form,
        target_input="username",
        value="injected_payload",
    )
    assert filled_by_name["username"] == "injected_payload"
    assert filled_by_name["user_token"] == "csrf_secret_abc"


def test_form_handler_submit_http():
    """Verify FormHandler submits form via HTTPClient with filled data."""
    submitted_data = {}

    def mock_server(request: httpx.Request):
        nonlocal submitted_data
        body_text = request.read().decode("utf-8")
        from urllib.parse import parse_qs
        submitted_data = {k: v[0] for k, v in parse_qs(body_text).items()}
        return httpx.Response(200, text="<html><body>Welcome admin</body></html>")

    transport = httpx.MockTransport(mock_server)

    form = FormModel(
        action="http://app.local/login",
        method="POST",
        inputs=[
            InputField(name="login_id", placeholder="Your Login ID"),
            InputField(name="csrf_token", input_type="hidden", value="token123"),
        ],
    )

    with HTTPClient(transport=transport) as client:
        handler = FormHandler(client=client)
        resp, req_meta, res_meta = handler.submit_http(
            form=form,
            target_input="Your Login ID",
            value="hacked_user",
        )

        assert resp.status_code == 200
        assert "Welcome admin" in resp.text
        assert submitted_data["login_id"] == "hacked_user"
        assert submitted_data["csrf_token"] == "token123"


def test_form_handler_submit_browser():
    """Verify FormHandler invokes browser.fill_and_submit_form properly."""
    class DummyBrowser:
        def __init__(self):
            self.called_with = None

        def fill_and_submit_form(self, url, target_param, payload, companion_fields=None, step_name="", wait_ms=500):
            self.called_with = {
                "url": url,
                "target_param": target_param,
                "payload": payload,
                "companion_fields": companion_fields,
            }
            return "<html><body>Browser Response</body></html>", "/evidence/form.png"

    dummy_browser = DummyBrowser()
    form = FormModel(
        action="http://app.local/contact",
        method="POST",
        inputs=[
            InputField(name="email", placeholder="Enter Email"),
            InputField(name="token", input_type="hidden", value="csrf99"),
        ],
    )

    handler = FormHandler(browser=dummy_browser)
    page_content, shot = handler.submit_browser(
        form=form,
        target_input="Enter Email",
        value="attacker@xss.test",
        step_name="contact_test",
    )

    assert "Browser Response" in page_content
    assert shot == "/evidence/form.png"
    assert dummy_browser.called_with["url"] == "http://app.local/contact"
    assert dummy_browser.called_with["target_param"] == "email"
    assert dummy_browser.called_with["payload"] == "attacker@xss.test"
    assert dummy_browser.called_with["companion_fields"]["token"] == "csrf99"


def test_form_handler_only_fills_text_inputs():
    """Verify FormHandler fills payload only into text inputs and preserves submit/hidden buttons."""
    form = FormModel(
        action="http://app.local/exec",
        method="POST",
        inputs=[
            InputField(name="ip", input_type="text"),
            InputField(name="Submit", input_type="submit", value="Submit"),
            InputField(name="csrf", input_type="hidden", value="token123"),
        ],
    )
    handler = FormHandler()
    filled = handler.fill_form_data(form=form, target_input="ip", value="127.0.0.1; whoami")

    assert filled["ip"] == "127.0.0.1; whoami"
    assert filled["Submit"] == "Submit"
    assert filled["csrf"] == "token123"

    # If target is a submit button, it should not overwrite it with payload
    filled_submit = handler.fill_form_data(form=form, target_input="Submit", value="payload_test")
    assert filled_submit["Submit"] == "Submit"


