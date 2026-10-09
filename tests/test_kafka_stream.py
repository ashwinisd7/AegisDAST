"""Tests for Kafka endpoint streaming pipeline."""

from unittest.mock import MagicMock, patch
import httpx
import pytest

from dast.crawler import Crawler
from dast.http_client import HTTPClient
from dast.kafka_stream import KafkaEndpointStream
from dast.models import Endpoint, HttpMethod, Target
from dast.scanner import Scanner


def test_kafka_stream_fallback_queue_publish_and_consume():
    """Verify local in-memory stream fallback when no live broker is present."""
    stream = KafkaEndpointStream(use_kafka=False)

    ep1 = Endpoint(url="http://test.local/login", method=HttpMethod.POST, body_params={"user": "admin"})
    ep2 = Endpoint(url="http://test.local/search", method=HttpMethod.GET, params={"q": "test"})

    # Publish endpoints
    assert stream.publish_endpoint(ep1) is True
    assert stream.publish_endpoint(ep2) is True
    # Deduplication: same endpoint shouldn't be republished
    assert stream.publish_endpoint(ep1) is False

    stream.send_eof()

    consumed = list(stream.consume_endpoints(timeout=0.5))
    assert len(consumed) == 2
    assert consumed[0].url == "http://test.local/login"
    assert consumed[0].method == HttpMethod.POST
    assert consumed[0].body_params == {"user": "admin"}
    assert consumed[1].url == "http://test.local/search"
    assert consumed[1].params == {"q": "test"}

    stream.close()


def test_kafka_stream_with_mocked_kafka():
    """Verify Kafka producer and consumer interaction with message serialization."""
    mock_producer = MagicMock()
    mock_consumer = MagicMock()

    ep = Endpoint(url="http://test.local/page", method=HttpMethod.GET, params={"id": "1"})

    mock_msg = MagicMock()
    mock_msg.value = {
        "type": "endpoint",
        "data": ep.model_dump(mode="json"),
    }
    mock_eof = MagicMock()
    mock_eof.value = {"type": "eof", "__eof__": True}

    mock_consumer.__iter__.return_value = [mock_msg, mock_eof]

    with patch("socket.create_connection"), \
         patch("kafka.KafkaProducer", return_value=mock_producer), \
         patch("kafka.KafkaConsumer", return_value=mock_consumer):
        stream = KafkaEndpointStream(
            bootstrap_servers="localhost:9092",
            topic="test-topic",
            use_kafka=True,
        )

        assert stream.is_kafka_active is True
        assert stream.publish_endpoint(ep) is True
        mock_producer.send.assert_called()

        stream.send_eof()

        consumed = list(stream.consume_endpoints())
        assert len(consumed) == 1
        assert consumed[0].url == "http://test.local/page"
        assert consumed[0].params == {"id": "1"}

        stream.close()
        mock_producer.close.assert_called()
        mock_consumer.close.assert_called()


def test_crawler_streaming_integration():
    """Verify Crawler streams endpoints in real-time as pages are traversed."""
    html_home = """
    <html><body>
        <a href="/items?cat=tech">Items</a>
        <form action="/submit" method="POST">
            <input name="data" value="123" />
        </form>
    </body></html>
    """

    def handler(request: httpx.Request):
        return httpx.Response(200, text=html_home, headers={"Content-Type": "text/html"})

    transport = httpx.MockTransport(handler)
    target = Target(url="http://shop.local", max_depth=1, max_pages=5)
    stream = KafkaEndpointStream(use_kafka=False)

    with HTTPClient(transport=transport) as client:
        crawler = Crawler(target=target, client=client, stream=stream)
        crawler.crawl()

    consumed = list(stream.consume_endpoints(timeout=0.2))
    assert len(consumed) >= 2
    urls = {ep.url for ep in consumed}
    assert "http://shop.local/" in urls
    assert "http://shop.local/items" in urls
    assert "http://shop.local/submit" in urls

    stream.close()


def test_scanner_with_stream_concurrent_execution():
    """Verify Scanner orchestrates crawling and auditing concurrently via stream."""
    html = """
    <html><head><title>Test App</title></head>
    <body>
        <a href="/page1?id=10">Page 1</a>
        <a href="/page2?id=20">Page 2</a>
    </body></html>
    """

    def handler(request: httpx.Request):
        return httpx.Response(200, text=html, headers={"Content-Type": "text/html"})

    transport = httpx.MockTransport(handler)
    target = Target(url="http://stream-test.local", max_depth=1, max_pages=5)

    scanner = Scanner(
        target=target,
        selected_detectors=["security_headers"],
        transport=transport,
        use_kafka=False,
    )

    result = scanner.run()
    assert len(result.scanned_endpoints) >= 2
    assert len(result.findings) > 0
    assert result.duration_seconds >= 0.0


def test_kafka_stream_graceful_fallback_when_broker_offline():
    """Verify that KafkaEndpointStream gracefully falls back to local queue if broker is offline."""
    stream = KafkaEndpointStream(
        bootstrap_servers="127.0.0.1:59999",  # Non-existent port
        use_kafka=True,
    )
    assert stream.is_kafka_active is False

    ep = Endpoint(url="http://fallback.local/item", method=HttpMethod.GET)
    assert stream.publish_endpoint(ep) is True
    stream.send_eof()

    consumed = list(stream.consume_endpoints(timeout=0.2))
    assert len(consumed) == 1
    assert consumed[0].url == "http://fallback.local/item"
    stream.close()


def test_kafka_stream_publish_url_and_endpoints_helpers():
    """Verify publish_url and publish_endpoints helper methods."""
    stream = KafkaEndpointStream(use_kafka=False)

    published = stream.publish_url(
        url="http://example.local/api/search",
        method="GET",
        params={"q": "admin"},
    )
    assert published is True

    eps = [
        Endpoint(url="http://example.local/api/item1", method=HttpMethod.GET),
        Endpoint(url="http://example.local/api/item2", method=HttpMethod.GET),
    ]
    count = stream.publish_endpoints(eps)
    assert count == 2

    stream.send_eof()
    consumed = list(stream.consume_endpoints(timeout=0.2))
    assert len(consumed) == 3
    stream.close()


def test_scanner_parallel_workers_execution():
    """Verify Scanner orchestrates multiple worker threads in parallel to audit endpoints."""
    html = """
    <html><head><title>Parallel Test</title></head>
    <body>
        <a href="/endpoint1?param=1">Endpoint 1</a>
        <a href="/endpoint2?param=2">Endpoint 2</a>
        <a href="/endpoint3?param=3">Endpoint 3</a>
    </body></html>
    """

    def handler(request: httpx.Request):
        return httpx.Response(200, text=html, headers={"Content-Type": "text/html"})

    transport = httpx.MockTransport(handler)
    target = Target(url="http://parallel-test.local", max_depth=1, max_pages=5)

    scanner = Scanner(
        target=target,
        selected_detectors=["security_headers"],
        transport=transport,
        use_kafka=False,
        max_workers=4,
    )

    result = scanner.run()
    assert len(result.scanned_endpoints) >= 3
    assert len(result.findings) > 0
    assert "security_headers" in result.summary.get("detector_timings", {})

