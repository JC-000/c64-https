"""HTTPS (TLS 1.3) listener for e2e testing.

Runs a background HTTPS server on a specified host:port.  Every GET request
returns a fixed 200 OK with a short body.  The server runs in a daemon
thread so the test can drive VICE in the main thread.

The TLS layer uses a self-signed ECDSA certificate.  Two cert profiles
are available:

    "p256" (default) -- P-256 / ecdsa-with-SHA256, generated lazily by
                        this module the first time the listener starts.
    "p384"           -- P-384 / ecdsa-with-SHA384, generated out-of-band
                        with openssl (see tools/https_e2e/certs/README).

TLS 1.3 is required; older versions are rejected.

Binding to port 443 requires root.  The test already runs under sudo
(BridgeEnv needs it), so no special handling is needed here.

Public API:
    start_https_listener(host, port, response_body, cert_profile=None)
        -> HttpsListenerHandle
    stop_https_listener(handle)

Cert profile selection precedence (first match wins):
    1. cert_profile= keyword argument to start_https_listener()
    2. HTTPS_LISTENER_CERT_PROFILE environment variable
    3. "p256" (preserves pre-Phase-4 default behaviour)
"""

from __future__ import annotations

import os
import socket
import ssl
import sys
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer

# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------

_CERTS_DIR = os.path.join(os.path.dirname(__file__), "certs")
_CERT_PATH = os.path.join(_CERTS_DIR, "server.pem")
_KEY_PATH = os.path.join(_CERTS_DIR, "server.key")
_CERT_PATH_P384 = os.path.join(_CERTS_DIR, "server-p384.pem")
_KEY_PATH_P384 = os.path.join(_CERTS_DIR, "server-p384.key")

_CERT_PROFILE_ENV = "HTTPS_LISTENER_CERT_PROFILE"
_DEFAULT_CERT_PROFILE = "p256"
_CERT_PROFILES = ("p256", "p384")

DEFAULT_RESPONSE_BODY = "HELLO FROM HTTPS TEST SERVER"


def _resolve_cert_profile(cert_profile: str | None) -> str:
    """Pick the cert profile from kwarg, env var, or default."""
    if cert_profile is None:
        cert_profile = os.environ.get(_CERT_PROFILE_ENV, _DEFAULT_CERT_PROFILE)
    cert_profile = cert_profile.lower()
    if cert_profile not in _CERT_PROFILES:
        raise ValueError(
            f"unknown cert_profile {cert_profile!r}; "
            f"expected one of {_CERT_PROFILES}"
        )
    return cert_profile


def _ensure_certs_p256() -> tuple[str, str]:
    """Return (cert_path, key_path) for the P-256 profile.

    Generates the cert pair on first use; subsequent calls reuse the
    cached files in the certs/ directory.
    """
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


def _ensure_certs_p384() -> tuple[str, str]:
    """Return (cert_path, key_path) for the P-384 profile.

    Generates the cert pair on first use; subsequent calls reuse the
    cached files in the certs/ directory.  Mirrors _ensure_certs_p256()
    but uses SECP384R1 + SHA-384.
    """
    if os.path.isfile(_CERT_PATH_P384) and os.path.isfile(_KEY_PATH_P384):
        return _CERT_PATH_P384, _KEY_PATH_P384

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import datetime

    key = ec.generate_private_key(ec.SECP384R1())

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
        .sign(key, hashes.SHA384())
    )

    os.makedirs(_CERTS_DIR, exist_ok=True)

    with open(_KEY_PATH_P384, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

    with open(_CERT_PATH_P384, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return _CERT_PATH_P384, _KEY_PATH_P384


def _ensure_certs(cert_profile: str) -> tuple[str, str]:
    """Dispatch to the per-profile cert loader."""
    if cert_profile == "p256":
        return _ensure_certs_p256()
    if cert_profile == "p384":
        return _ensure_certs_p384()
    # Should be unreachable thanks to _resolve_cert_profile().
    raise ValueError(f"unknown cert_profile {cert_profile!r}")


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
    cert_profile: str


def start_https_listener(
    host: str = "10.0.65.1",
    port: int = 443,
    response_body: str = DEFAULT_RESPONSE_BODY,
    cert_profile: str | None = None,
) -> HttpsListenerHandle:
    """Start a TLS 1.3 HTTPS server in a daemon thread. Returns a handle.

    cert_profile selects which self-signed cert the listener presents:
        "p256" (default) -- ECDSA P-256, ecdsa-with-SHA256
        "p384"           -- ECDSA P-384, ecdsa-with-SHA384

    If cert_profile is None, the HTTPS_LISTENER_CERT_PROFILE env var is
    consulted; if that is also unset the default ("p256") is used.
    """
    profile = _resolve_cert_profile(cert_profile)
    cert_path, key_path = _ensure_certs(profile)

    _Handler.response_body = response_body

    server = HTTPServer((host, port), _Handler)

    if sys.platform == "darwin":
        # macOS drops a connection after ~30 s of unACKed retransmission
        # (5 rexmts observed, then RST). A 1 MHz C64 on the ip65 backend
        # ACKs only when it polls, and its crypto stalls run 4-25 min —
        # the server flight sits unACKed far past the default drop time
        # and the kernel RSTs mid-handshake (observed on the feth rig:
        # 5x rexmt of the flight tail over 33 s, RST, then the C64 ACKed
        # into the dead socket 4.5 min later). TCP_RXT_CONNDROPTIME
        # (xnu tcp.h, 0x80) raises that per-socket, set on the listening
        # socket BEFORE the ssl wrap so accepted sockets inherit it.
        # Linux needs nothing: its default retransmit patience is minutes.
        # UCI-backend runs never hit this because the Ultimate firmware's
        # TCP stack ACKs autonomously regardless of C64 polling.
        TCP_RXT_CONNDROPTIME = 0x80
        server.socket.setsockopt(
            socket.IPPROTO_TCP, TCP_RXT_CONNDROPTIME, 7200)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    if profile == "p384":
        # Pin ECDH to the same curve as the cert so the key share matches.
        ctx.set_ecdh_curve("secp384r1")
    ctx.load_cert_chain(cert_path, key_path)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    if sys.platform == "darwin":
        # Belt-and-suspenders: BSD option inheritance across accept() is
        # not guaranteed for TCP-level options, so also set the drop time
        # on each accepted connection explicitly.
        _orig_get_request = server.get_request

        def _get_request_patched():
            conn, addr = _orig_get_request()
            try:
                conn.setsockopt(socket.IPPROTO_TCP, 0x80, 7200)
            except OSError:
                pass
            return conn, addr

        server.get_request = _get_request_patched

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return HttpsListenerHandle(
        server=server, thread=thread, host=host, port=port,
        cert_path=cert_path, key_path=key_path, cert_profile=profile,
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
