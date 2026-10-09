"""Minimal local test environment for validating the DAST framework.

Runs on Python's built-in http.server (no external server dependencies needed).
Run with:
    python examples/local_lab.py
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class LabHandler(BaseHTTPRequestHandler):
    """Local audit target exhibiting controlled configurations for testing."""

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        # 1. Root page: provides links and forms for the crawler to discover
        if parsed.path in ("/", ""):
            html = """<!DOCTYPE html>
            <html>
            <head><title>DAST Test Lab</title></head>
            <body>
                <h1>Security Audit Test Environment</h1>
                <nav>
                    <a href="/search?q=test">Search Endpoint</a>
                    <a href="/api/profile">User Profile API</a>
                    <a href="/db-query?id=1">Database Query</a>
                    <a href="/fetch-url?url=https://example.com">Remote Fetch</a>
                </nav>
                <form action="/login" method="POST">
                    <input type="text" name="username" value="guest" />
                    <input type="password" name="password" value="guest123" />
                    <input type="submit" value="Login" />
                </form>
            </body>
            </html>"""
            self._send_response(
                200,
                "text/html",
                html,
                extra_headers={"Set-Cookie": "session_id=lab_test_cookie; Path=/; SameSite=None"},
            )

        # 2. Reflected input endpoint (without encoding)
        elif parsed.path == "/search":
            q_val = params.get("q", [""])[0]
            html = f"<html><body><h2>Search Results</h2><p>Results for: {q_val}</p></body></html>"
            self._send_response(200, "text/html", html)

        # 3. CORS reflection endpoint
        elif parsed.path == "/api/profile":
            req_origin = self.headers.get("Origin", "")
            extra_headers = {}
            if req_origin:
                extra_headers["Access-Control-Allow-Origin"] = req_origin
                extra_headers["Access-Control-Allow-Credentials"] = "true"
            self._send_response(200, "application/json", '{"user": "alice", "role": "auditor"}', extra_headers)

        # 4. SQL database query endpoint (simulates database exception leakage)
        elif parsed.path == "/db-query":
            item_id = params.get("id", [""])[0]
            if "'" in item_id:
                error_body = "Database Error: You have an error in your SQL syntax near ''' at line 1"
                self._send_response(500, "text/plain", error_body)
            else:
                self._send_response(200, "text/plain", f"Record {item_id}: Verified")

        # 5. Remote fetch endpoint (SSRF parameter candidate)
        elif parsed.path == "/fetch-url":
            self._send_response(200, "text/plain", "Target response fetched successfully")

        # Fallback 404
        else:
            self._send_response(404, "text/plain", "Not Found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""

        if parsed.path == "/login":
            self._send_response(200, "text/html", "<html><body>Login Processed</body></html>")
        else:
            self._send_response(404, "text/plain", "Not Found")

    def _send_response(
        self,
        status: int,
        content_type: str,
        body: str,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format: str, *args: object) -> None:
        # Suppress standard logging to keep test console clean
        pass


def run_lab(host: str = "127.0.0.1", port: int = 8765) -> None:
    server = HTTPServer((host, port), LabHandler)
    print(f"[*] DAST Test Lab listening on http://{host}:{port}")
    print("[*] Press Ctrl+C to terminate.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down test lab.")
        server.server_close()


if __name__ == "__main__":
    run_lab()

