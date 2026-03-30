"""Reusable HTTP test server for C64 HTTPS integration testing."""

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

DEFAULT_HOST = "10.0.65.1"
DEFAULT_PORT = 80


class _ReusableHTTPServer(HTTPServer):
    """HTTPServer subclass that sets SO_REUSEADDR before bind."""

    allow_reuse_address = True

RESPONSE_BODY = "HELLO C64"


class _RequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests, recording them for test assertions."""

    def do_GET(self):
        if self.path == "/":
            body = RESPONSE_BODY.encode("ascii")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"Not Found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        self.server.record_request(self.command, self.path, dict(self.headers))

    def log_message(self, format, *args):
        """Suppress default stderr logging during tests."""
        pass


class TestHTTPServer:
    """HTTP server that runs in a background daemon thread.

    Attributes:
        requests: list of dicts recording each received request
                  (keys: method, path, headers).
    """

    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, ssl_context=None):
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.requests = []
        self._lock = threading.Lock()

        self._httpd = _ReusableHTTPServer((host, port), _RequestHandler)

        if ssl_context is not None:
            self._httpd.socket = ssl_context.wrap_socket(
                self._httpd.socket, server_side=True
            )

        # Give the handler a way to record requests back to us.
        self._httpd.record_request = self._record_request

        self._thread = None

    # ---- public API --------------------------------------------------------

    def start(self):
        """Start serving in a daemon thread."""
        self._thread = threading.Thread(target=self._httpd.serve_forever)
        self._thread.daemon = True
        self._thread.start()

    def stop(self):
        """Shut down the server and wait for the thread to exit."""
        self._httpd.shutdown()
        if self._thread is not None:
            self._thread.join()

    # ---- internals ---------------------------------------------------------

    def _record_request(self, method, path, headers):
        with self._lock:
            self.requests.append(
                {"method": method, "path": path, "headers": headers}
            )


def start_test_server(host=DEFAULT_HOST, port=DEFAULT_PORT, ssl_context=None):
    """Create, start, and return a TestHTTPServer instance."""
    server = TestHTTPServer(host=host, port=port, ssl_context=ssl_context)
    server.start()
    return server


if __name__ == "__main__":
    srv = start_test_server()
    print(f"Test server listening on {srv.host}:{srv.port}")
    try:
        srv._thread.join()
    except KeyboardInterrupt:
        print("\nShutting down.")
        srv.stop()
