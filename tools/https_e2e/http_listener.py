"""Simple HTTP listener for e2e testing.

Runs a background HTTP server on a specified host:port.  Every GET request
returns a fixed 200 OK with a short body.  The server runs in a daemon
thread so the test can drive VICE in the main thread.

Binding to port 80 requires root.  The test already runs under sudo
(BridgeEnv needs it), so no special handling is needed here.

Public API:
    start_http_listener(host, port) -> HttpListenerHandle
    stop_http_listener(handle)
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer

# Fixed response body served for every GET.
DEFAULT_RESPONSE_BODY = "HELLO FROM TEST SERVER"


class _Handler(BaseHTTPRequestHandler):
    """Serves a canned 200 OK response for any GET."""

    # Class-level attribute set before server starts.
    response_body: str = DEFAULT_RESPONSE_BODY

    def do_GET(self) -> None:  # noqa: N802
        body = self.response_body.encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    # Silence per-request log lines.
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


@dataclass
class HttpListenerHandle:
    """Returned by start_http_listener; pass to stop_http_listener."""
    server: HTTPServer
    thread: threading.Thread
    host: str
    port: int


def start_http_listener(
    host: str = "10.0.65.1",
    port: int = 80,
    response_body: str = DEFAULT_RESPONSE_BODY,
) -> HttpListenerHandle:
    """Start an HTTP server in a daemon thread. Returns a handle."""
    # Set the response body on the handler class before creating the server.
    _Handler.response_body = response_body

    server = HTTPServer((host, port), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return HttpListenerHandle(server=server, thread=thread, host=host, port=port)


def stop_http_listener(handle: HttpListenerHandle) -> None:
    """Shut the server down cleanly."""
    try:
        handle.server.shutdown()
    except Exception:  # noqa: BLE001
        pass
    try:
        handle.server.server_close()
    except Exception:  # noqa: BLE001
        pass
