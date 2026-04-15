"""HTTPS (TLS 1.3) listener for e2e testing.

Runs a background HTTPS server on a specified host:port.  Every GET request
returns a fixed 200 OK with a short body.  The server runs in a daemon
thread so the test can drive VICE in the main thread.

The TLS layer uses a self-signed P-256 ECDSA certificate generated at
import time (cached on disk in the certs/ directory next to this file).
TLS 1.3 is required; older versions are rejected.

Binding to port 443 requires root.  The test already runs under sudo
(BridgeEnv needs it), so no special handling is needed here.

Public API:
    start_https_listener(host, port, response_body) -> HttpsListenerHandle
    stop_https_listener(handle)
"""

from __future__ import annotations

import os
import ssl
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer

# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------

_CERTS_DIR = os.path.join(os.path.dirname(__file__), "certs")
_CERT_PATH = os.path.join(_CERTS_DIR, "server.pem")
_KEY_PATH = os.path.join(_CERTS_DIR, "server.key")

DEFAULT_RESPONSE_BODY = "HELLO FROM HTTPS TEST SERVER"


def _ensure_certs() -> tuple[str, str]:
    """Return (cert_path, key_path), generating them if they don't exist."""
    if os.path.isfile(_CERT_PATH) and os.path.isfile(_KEY_PATH):
        return _CERT_PATH, _KEY_PATH

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import datetime

    key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "www.foo.bar"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("foo.bar"),
                x509.DNSName("www.foo.bar"),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    os.makedirs(_CERTS_DIR, exist_ok=True)

    with open(_KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

    with open(_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return _CERT_PATH, _KEY_PATH


# ---------------------------------------------------------------------------
# HTTPS handler
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class HttpsListenerHandle:
    """Returned by start_https_listener; pass to stop_https_listener."""
    server: HTTPServer
    thread: threading.Thread
    host: str
    port: int
    cert_path: str
    key_path: str


def start_https_listener(
    host: str = "10.0.65.1",
    port: int = 443,
    response_body: str = DEFAULT_RESPONSE_BODY,
) -> HttpsListenerHandle:
    """Start a TLS 1.3 HTTPS server in a daemon thread. Returns a handle."""
    cert_path, key_path = _ensure_certs()

    _Handler.response_body = response_body

    server = HTTPServer((host, port), _Handler)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert_path, key_path)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return HttpsListenerHandle(
        server=server, thread=thread, host=host, port=port,
        cert_path=cert_path, key_path=key_path,
    )


def stop_https_listener(handle: HttpsListenerHandle) -> None:
    """Shut the server down cleanly."""
    try:
        handle.server.shutdown()
    except Exception:  # noqa: BLE001
        pass
    try:
        handle.server.server_close()
    except Exception:  # noqa: BLE001
        pass
