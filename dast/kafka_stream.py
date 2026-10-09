"""Kafka Event-Driven Endpoint Streaming Pipeline.

Streams discovered Endpoint and URL objects from the Crawler in real-time to
Detector audit workers, enabling concurrent crawling and vulnerability scanning to accelerate scan speed.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import secrets
import threading
from typing import Any, Iterator, Sequence

from dast.models import Endpoint

logger = logging.getLogger(__name__)

DEFAULT_KAFKA_BOOTSTRAP = "localhost:9092"
DEFAULT_KAFKA_TOPIC = "dast-discovered-urls"
DEFAULT_KAFKA_GROUP = "dast-scanner-workers"


class KafkaEndpointStream:
    """Manages Kafka producer-consumer streaming with automatic in-memory queue fallback."""

    def __init__(
        self,
        bootstrap_servers: str | None = None,
        topic: str = DEFAULT_KAFKA_TOPIC,
        group_id: str = DEFAULT_KAFKA_GROUP,
        use_kafka: bool = True,
        scan_id: str | None = None,
    ) -> None:
        self.bootstrap_servers = bootstrap_servers or os.environ.get("KAFKA_BOOTSTRAP_SERVERS", DEFAULT_KAFKA_BOOTSTRAP)
        self.topic = topic or os.environ.get("KAFKA_TOPIC", DEFAULT_KAFKA_TOPIC)
        self.scan_id = scan_id or secrets.token_hex(6)
        # Use scan_id in group_id to guarantee fresh consumer offsets and prevent stale group coordinator collisions
        self.group_id = f"{group_id}-{self.scan_id}" if group_id else f"{DEFAULT_KAFKA_GROUP}-{self.scan_id}"
        self.use_kafka = use_kafka

        self._producer: Any = None
        self._consumer: Any = None
        self._is_kafka_connected = False
        self._fallback_queue: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._published_identifiers: set[str] = set()
        self._lock = threading.Lock()

        if self.use_kafka:
            self._init_kafka()

    def _init_kafka(self) -> bool:
        """Attempt initializing Kafka producer and consumer with fast connectivity pre-check."""
        import socket

        # 1. Fast socket connectivity pre-check
        first_server = self.bootstrap_servers.split(",")[0].strip()
        if ":" in first_server:
            host, port_str = first_server.split(":", 1)
            port = int(port_str)
        else:
            host, port = first_server, 9092

        try:
            with socket.create_connection((host, port), timeout=0.3):
                pass
        except (socket.timeout, OSError) as sock_err:
            logger.debug("[KAFKA] Socket connection to broker %s:%d failed (%s). Using local streaming queue.", host, port, sock_err)
            self._is_kafka_connected = False
            self._producer = None
            self._consumer = None
            return False

        # 2. Broker socket is open, initialize client drivers
        try:
            from kafka import KafkaConsumer, KafkaProducer  # type: ignore

            logger.info("[KAFKA] Connecting to Kafka broker at '%s' (topic: '%s')...", self.bootstrap_servers, self.topic)
            self._producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                request_timeout_ms=3000,
                max_block_ms=3000,
            )

            self._consumer = KafkaConsumer(
                self.topic,
                bootstrap_servers=self.bootstrap_servers,
                group_id=self.group_id,
                auto_offset_reset="earliest",
                enable_auto_commit=True,
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                consumer_timeout_ms=5000,
            )
            self._is_kafka_connected = True
            logger.info("[KAFKA] Connected successfully to Kafka broker '%s'.", self.bootstrap_servers)
            return True
        except Exception as exc:
            logger.info(
                "[KAFKA] Live Kafka broker initialization failed (%s). Using high-speed in-memory streaming queue.",
                exc,
            )
            self._is_kafka_connected = False
            self._producer = None
            self._consumer = None
            return False

    @property
    def is_kafka_active(self) -> bool:
        """Whether connected to an active external Kafka cluster."""
        return self._is_kafka_connected

    def publish_endpoint(self, endpoint: Endpoint) -> bool:
        """Publish discovered Endpoint object to stream topic."""
        method_str = endpoint.method.value if hasattr(endpoint.method, "value") else str(endpoint.method)
        clean_url = endpoint.url.split("?")[0]
        sig = (
            method_str,
            clean_url,
            tuple(sorted(endpoint.params.keys())),
            tuple(sorted(endpoint.body_params.keys())),
            len(endpoint.forms),
        )
        with self._lock:
            # Deduplicate before publishing
            if sig in self._published_identifiers:
                return False
            self._published_identifiers.add(sig)

        payload = {
            "type": "endpoint",
            "scan_id": self.scan_id,
            "data": endpoint.model_dump(mode="json"),
        }

        # Keep fallback queue populated so no endpoints are ever lost
        self._fallback_queue.put(payload)

        if self._is_kafka_connected and self._producer:
            try:
                self._producer.send(self.topic, value=payload)
                self._producer.flush()
                logger.debug("[KAFKA] Published endpoint '%s' to topic '%s' (scan_id=%s)", endpoint.url, self.topic, self.scan_id)
                return True
            except Exception as exc:
                logger.warning("[KAFKA] Failed publishing to Kafka: %s.", exc)

        return True

    def publish_url(
        self,
        url: str,
        method: Any = "GET",
        params: dict[str, Any] | None = None,
        body_params: dict[str, Any] | None = None,
        content_type: str | None = None,
    ) -> bool:
        """Convenience method to construct and publish Endpoint from raw URL and parameters."""
        from dast.models import HttpMethod
        m = HttpMethod(method.upper()) if isinstance(method, str) else method
        endpoint = Endpoint(
            url=url,
            method=m,
            params=params or {},
            body_params=body_params or {},
            content_type=content_type,
        )
        return self.publish_endpoint(endpoint)

    def publish_endpoints(self, endpoints: Sequence[Endpoint]) -> int:
        """Publish a sequence of Endpoint objects to Kafka."""
        count = 0
        for ep in endpoints:
            if self.publish_endpoint(ep):
                count += 1
        return count

    def send_eof(self) -> None:
        """Publish end-of-stream sentinel marker indicating crawling has finished."""
        eof_payload = {"type": "eof", "__eof__": True, "scan_id": self.scan_id}
        self._fallback_queue.put(eof_payload)

        if self._is_kafka_connected and self._producer:
            try:
                self._producer.send(self.topic, value=eof_payload)
                self._producer.flush()
                logger.info("[KAFKA] Dispatched end-of-stream marker to topic '%s' (scan_id=%s).", self.topic, self.scan_id)
            except Exception as exc:
                logger.debug("[KAFKA] Notice sending EOF to Kafka: %s", exc)

    def consume_endpoints(
        self,
        timeout: float = 0.5,
        stop_event: threading.Event | None = None,
    ) -> Iterator[Endpoint]:
        """Consume and yield Endpoint objects in real-time as they are discovered."""
        yielded_from_kafka = 0
        if self._is_kafka_connected and self._consumer:
            try:
                for msg in self._consumer:
                    if stop_event and stop_event.is_set():
                        break
                    data_dict = msg.value
                    if not isinstance(data_dict, dict):
                        continue
                    # Ignore messages from other or old scan runs
                    msg_scan_id = data_dict.get("scan_id")
                    if msg_scan_id is not None and msg_scan_id != self.scan_id:
                        continue
                    if data_dict.get("__eof__") or data_dict.get("type") == "eof":
                        logger.info("[KAFKA] Received end-of-stream marker for scan '%s' from topic '%s'.", self.scan_id, self.topic)
                        break
                    if data_dict.get("type") == "endpoint" and "data" in data_dict:
                        try:
                            ep = Endpoint.model_validate(data_dict["data"])
                            yielded_from_kafka += 1
                            yield ep
                        except Exception as parse_err:
                            logger.debug("[KAFKA] Error parsing endpoint model: %s", parse_err)
                if yielded_from_kafka > 0:
                    return
            except Exception as exc:
                logger.debug("[KAFKA] Consumer loop finished/interrupted: %s", exc)

        # Fallback to local queue if Kafka returned 0 items or disconnected
        while True:
            if stop_event and stop_event.is_set():
                break
            try:
                item = self._fallback_queue.get(timeout=min(timeout, 0.5))
                if item is None:
                    break
                msg_scan_id = item.get("scan_id") if isinstance(item, dict) else None
                if msg_scan_id is not None and msg_scan_id != self.scan_id:
                    continue
                if item.get("__eof__") or item.get("type") == "eof":
                    break
                if item.get("type") == "endpoint" and "data" in item:
                    try:
                        ep = Endpoint.model_validate(item["data"])
                        yield ep
                    except Exception as parse_err:
                        logger.debug("[STREAM] Error parsing endpoint model: %s", parse_err)
            except queue.Empty:
                if stop_event and stop_event.is_set():
                    break
                continue

    def close(self) -> None:
        """Clean up Kafka producer and consumer connections."""
        try:
            if self._producer:
                self._producer.close()
            if self._consumer:
                self._consumer.close()
        except Exception:
            pass
        finally:
            self._producer = None
            self._consumer = None
            self._is_kafka_connected = False

