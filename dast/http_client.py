"""Resilient HTTP client wrapper around httpx for controlled security auditing.

Handles connection pooling, rate limiting, timeout policies, redirect behavior,
and standardized request/response metadata capture.
"""

from __future__ import annotations

import threading
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from dast.models import HTTPRequestMetadata, HTTPResponseMetadata


class HTTPClientError(Exception):
    """Base exception for HTTP client operations."""


class HTTPClient:
    """Production-grade HTTP client with rate-limiting and audit capture."""

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 10.0,
        delay: float = 0.0,
        verify_ssl: bool = True,
        default_headers: dict[str, str] | None = None,
        max_redirects: int = 5,
        transport: httpx.BaseTransport | None = None,
        auth: tuple[str, str] | httpx.Auth | None = None,
    ) -> None:
        self.base_url = base_url
        self.timeout = timeout
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.max_redirects = max_redirects
        self.auth = auth
        self.reauth_callback: Any | None = None
        self._reauth_lock = threading.Lock()
        self._lock = threading.Lock()

        headers = {
            "User-Agent": "DAST-Security-Auditor/1.0 (+authorized-security-assessment)",
            "Accept": "*/*",
        }
        if default_headers:
            headers.update(default_headers)

        self._client = httpx.Client(
            base_url=base_url or "",
            timeout=timeout,
            verify=verify_ssl,
            headers=headers,
            follow_redirects=True,
            max_redirects=max_redirects,
            transport=transport,
            auth=auth,
        )
        self._last_request_time: float = 0.0

    def __enter__(self) -> HTTPClient:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close underlying httpx client transport."""
        self._client.close()

    def _apply_rate_limit(self) -> None:
        """Enforce request throttle delay if configured."""
        if self.delay > 0:
            with self._lock:
                elapsed = time.time() - self._last_request_time
                if elapsed < self.delay:
                    time.sleep(self.delay - elapsed)
                self._last_request_time = time.time()

    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json: Any | None = None,
        headers: dict[str, str] | None = None,
        follow_redirects: bool | None = None,
    ) -> tuple[httpx.Response | None, HTTPRequestMetadata, HTTPResponseMetadata | None]:
        """Execute HTTP request safely with rate limiting and audit capture.

        Returns:
            Tuple of:
            - httpx.Response (or None on failure)
            - HTTPRequestMetadata
            - HTTPResponseMetadata (or None on network failure)
        """
        self._apply_rate_limit()

        req_headers = dict(self._client.headers)
        if headers:
            req_headers.update(headers)

        req_meta = HTTPRequestMetadata(
            url=url,
            method=method.upper(),
            headers=req_headers,
            body=str(json or data) if (json or data) else None,
        )

        redirects = follow_redirects if follow_redirects is not None else True
        start_time = time.perf_counter()

        try:
            resp = self._client.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                json=json,
                headers=headers,
                follow_redirects=redirects,
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            # Check if session expired and re-authentication is available
            if (
                self.reauth_callback
                and resp is not None
                and self._is_session_expired(resp, url)
            ):
                with self._reauth_lock:
                    reauth_success = False
                    try:
                        reauth_success = bool(self.reauth_callback())
                    except Exception:
                        reauth_success = False

                if reauth_success:
                    # Retry the request once with renewed session cookies
                    try:
                        retry_resp = self._client.request(
                            method=method.upper(),
                            url=url,
                            params=params,
                            data=data,
                            json=json,
                            headers=headers,
                            follow_redirects=redirects,
                        )
                        if retry_resp is not None:
                            resp = retry_resp
                            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                    except Exception:
                        pass

            if resp is not None and hasattr(resp, "request") and resp.request is not None:
                req_meta.url = str(resp.request.url)
                req_meta.headers = dict(resp.request.headers)

            resp_headers = dict(resp.headers)
            body_text = resp.text[:500] if resp.text else ""
            res_meta = HTTPResponseMetadata(
                status_code=resp.status_code,
                headers=resp_headers,
                latency_ms=round(elapsed_ms, 2),
                body_preview=body_text,
                body_length=len(resp.content),
            )
            return resp, req_meta, res_meta

        except httpx.RequestError as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            res_meta = HTTPResponseMetadata(
                status_code=0,
                headers={},
                latency_ms=round(elapsed_ms, 2),
                body_preview=f"Network error: {exc!s}",
                body_length=0,
            )
            return None, req_meta, res_meta

    def _is_session_expired(self, resp: httpx.Response, request_url: str) -> bool:
        """Heuristic check to determine if a response indicates session invalidation/expiry."""
        if resp.status_code == 401:
            return True
        final_url = str(resp.url).lower() if hasattr(resp, "url") else ""
        req_url_lower = request_url.lower()
        if "login" not in req_url_lower and ("login" in final_url or "signin" in final_url):
            return True
        return False

    def get(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        follow_redirects: bool | None = None,
    ) -> tuple[httpx.Response | None, HTTPRequestMetadata, HTTPResponseMetadata | None]:
        """Convenience GET request."""
        return self.request("GET", url, params=params, headers=headers, follow_redirects=follow_redirects)

    def post(
        self,
        url: str,
        data: dict[str, Any] | None = None,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[httpx.Response | None, HTTPRequestMetadata, HTTPResponseMetadata | None]:
        """Convenience POST request."""
        return self.request("POST", url, params=params, data=data, json=json, headers=headers)

    def options(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[httpx.Response | None, HTTPRequestMetadata, HTTPResponseMetadata | None]:
        """Convenience OPTIONS request for CORS / preflight checks."""
        return self.request("OPTIONS", url, headers=headers)
