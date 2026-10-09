"""Tests for scoped crawler and endpoint discovery."""

import httpx
import pytest

from dast.crawler import Crawler
from dast.http_client import HTTPClient
from dast.models import HttpMethod, Target


def test_crawler_link_and_form_discovery():
    html_page_1 = """
    <!DOCTYPE html>
    <html>
    <head><title>Home</title></head>
    <body>
        <a href="/about">About Us</a>
        <a href="/search?query=security&sort=asc">Search</a>
        <a href="https://external-unauthorized.com/blog">External Link</a>
        <a href="#section2">Anchor</a>
        <form action="/login" method="POST">
            <input type="text" name="username" value="" />
            <input type="password" name="password" value="" />
            <input type="submit" value="Log In" />
        </form>
    </body>
    </html>
    """

    html_page_about = """
    <!DOCTYPE html>
    <html>
    <body>
        <h1>About Us</h1>
        <a href="/contact">Contact</a>
    </body>
    </html>
    """

    def handler(request: httpx.Request):
        path = request.url.path
        if path in ("/", ""):
            return httpx.Response(200, text=html_page_1, headers={"Content-Type": "text/html"})
        elif path == "/about":
            return httpx.Response(200, text=html_page_about, headers={"Content-Type": "text/html"})
        return httpx.Response(200, text="OK", headers={"Content-Type": "text/html"})

    transport = httpx.MockTransport(handler)
    target = Target(url="http://app.local", max_depth=2, max_pages=10)

    with HTTPClient(transport=transport) as client:
        crawler = Crawler(target=target, client=client)
        endpoints = crawler.crawl()

    discovered_urls = {ep.url for ep in endpoints}
    assert "http://app.local/" in discovered_urls
    assert "http://app.local/about" in discovered_urls
    assert "http://app.local/search" in discovered_urls
    assert "http://app.local/login" in discovered_urls
    assert "http://app.local/contact" in discovered_urls

    # Scope enforcement: ensure external link was NOT crawled
    assert not any("external-unauthorized.com" in ep.url for ep in endpoints)

    # Check search endpoint extracted query params
    search_ep = next(ep for ep in endpoints if "/search" in ep.url)
    assert search_ep.method == HttpMethod.GET
    assert search_ep.params.get("query") == "security"
    assert search_ep.params.get("sort") == "asc"

    # Check login POST form endpoint
    login_ep = next(ep for ep in endpoints if "/login" in ep.url)
    assert login_ep.method == HttpMethod.POST
    assert "username" in login_ep.body_params
    assert "password" in login_ep.body_params
    assert len(login_ep.forms) > 0
    assert login_ep.forms[0].action == "http://app.local/login"
    assert login_ep.forms[0].method == "POST"


def test_crawler_form_extraction_and_kafka_streaming():
    """Verify forms on crawled pages are extracted with full inputs and streamed to Kafka."""
    from dast.kafka_stream import KafkaEndpointStream

    html_exec = """
    <!DOCTYPE html>
    <html>
    <body>
        <h2>Command Injection</h2>
        <form name="ping" action="#" method="post">
            <p>Enter an IP address: <input type="text" name="ip" size="30"></p>
            <input type="submit" name="Submit" value="Submit">
        </form>
    </body>
    </html>
    """

    def handler(request: httpx.Request):
        return httpx.Response(200, text=html_exec, headers={"Content-Type": "text/html"})

    transport = httpx.MockTransport(handler)
    target = Target(url="http://app.local/vulnerabilities/exec/", max_depth=1, max_pages=5)
    stream = KafkaEndpointStream(use_kafka=False)

    with HTTPClient(transport=transport) as client:
        crawler = Crawler(target=target, client=client, stream=stream)
        endpoints = crawler.crawl()

    assert len(endpoints) >= 1
    exec_ep = endpoints[0]
    assert exec_ep.url == "http://app.local/vulnerabilities/exec/"
    assert exec_ep.method == HttpMethod.POST
    assert "ip" in exec_ep.body_params
    assert "Submit" in exec_ep.body_params
    assert len(exec_ep.forms) == 1
    assert exec_ep.forms[0].action == "http://app.local/vulnerabilities/exec/"
    assert exec_ep.forms[0].method == "POST"
    assert len(exec_ep.forms[0].inputs) == 2
    assert exec_ep.forms[0].inputs[0].name == "ip"
    assert exec_ep.forms[0].inputs[0].input_type == "text"
    assert exec_ep.forms[0].inputs[1].name == "Submit"
    assert exec_ep.forms[0].inputs[1].input_type == "submit"

    # Verify streamed items received by consumer
    streamed_eps = list(stream.consume_endpoints(timeout=0.1))
    assert len(streamed_eps) >= 1
    consumed = streamed_eps[0]
    assert consumed.url == "http://app.local/vulnerabilities/exec/"
    assert len(consumed.forms) == 1
    assert consumed.forms[0].inputs[0].name == "ip"
    assert consumed.forms[0].inputs[1].name == "Submit"

