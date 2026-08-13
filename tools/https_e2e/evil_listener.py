"""evil_listener.py — a hand-rolled TLS 1.3 server that can lie.

Why this is not `ssl.SSLContext`
--------------------------------
Audit finding F2: nothing in the repo exercised the client's *rejection* of a
bad server Finished. To exercise it, a server has to emit a structurally valid,
correctly-encrypted handshake flight whose Finished verify_data is wrong.
Python's `ssl` module cannot be made to do that — the handshake is entirely
inside OpenSSL and there is no hook between "compute verify_data" and "put it
on the wire". Bit-flipping the ciphertext from outside does not work either:
that breaks the Poly1305 tag, so the client rejects at the AEAD layer and never
reaches the Finished comparison, which would be a false pass for F2.

So the server side is written out by hand here. That is much less work than it
sounds, because the c64-https client is extremely constrained:

  * exactly one cipher suite, TLS_CHACHA20_POLY1305_SHA256 (0x1303)
  * exactly one group, x25519 (0x001d)
  * no SNI, empty legacy_session_id, no PSK, no early data, no HRR
  * no client certificates

This module implements only what that client (and, for self-validation, a
stock OpenSSL client) needs. It is a **test fixture, not a TLS stack** — it has
no security review, no state machine hardening, and no business anywhere near
production.

Modes
-----
``mode="good"``
    A fully correct handshake, then one HTTP response. Used as the control: the
    same code that produces the bad flight must also be able to produce a
    working one, otherwise a client abort proves nothing about *where* the
    client aborted.

``mode="bad_finished"``
    Identical in every byte except one: a single bit is flipped in the server
    Finished ``verify_data`` before it is encrypted. Everything else — the
    record layer, the AEAD tag, the certificate, the CertificateVerify
    signature, the transcript — is correct, so a conforming client must get all
    the way to the Finished HMAC comparison and reject *there*. The server then
    records what the client actually did, in ``client_accepted_finished``: a
    client that goes on to send its own Finished did not check ours.

Self-validation
---------------
``python3 tools/https_e2e/evil_listener.py --selftest`` runs both modes against
Python's own `ssl` client: ``good`` must complete the handshake and return the
body, ``bad_finished`` must raise an SSL error mentioning a bad MAC / decrypt
error. If that self-test does not pass, no conclusion drawn from a C64 run
against this server is worth anything.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import socket
import struct
import sys
import threading
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.x509 import load_pem_x509_certificate

# Record / handshake constants
CT_CHANGE_CIPHER_SPEC = 20
CT_ALERT = 21
CT_HANDSHAKE = 22
CT_APPLICATION_DATA = 23

HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_ENCRYPTED_EXTENSIONS = 8
HS_CERTIFICATE = 11
HS_CERTIFICATE_VERIFY = 15
HS_FINISHED = 20

TLS_CHACHA20_POLY1305_SHA256 = 0x1303
GROUP_X25519 = 0x001D
SIG_ECDSA_SECP256R1_SHA256 = 0x0403

EXT_SUPPORTED_GROUPS = 0x000A
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_KEY_SHARE = 0x0033

HASH_LEN = 32

DEFAULT_BODY = "HELLO FROM TLS SERVER"


class TlsFixtureError(Exception):
    """Something about the peer's flight was not what this fixture supports."""


# ---------------------------------------------------------------------------
# Key schedule (RFC 8446 Section 7.1)
# ---------------------------------------------------------------------------

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * HASH_LEN
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def hkdf_expand_label(secret: bytes, label: bytes, context: bytes,
                      length: int) -> bytes:
    info = struct.pack(">H", length)
    info += bytes([6 + len(label)]) + b"tls13 " + label
    info += bytes([len(context)]) + context
    return _hkdf_expand(secret, info, length)


def derive_secret(secret: bytes, label: bytes, transcript_hash: bytes) -> bytes:
    return hkdf_expand_label(secret, label, transcript_hash, HASH_LEN)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


class TrafficKeys:
    """One direction's AEAD state: key, iv, and a sequence number."""

    def __init__(self, secret: bytes):
        self.secret = secret
        self.key = hkdf_expand_label(secret, b"key", b"", 32)
        self.iv = hkdf_expand_label(secret, b"iv", b"", 12)
        self.aead = ChaCha20Poly1305(self.key)
        self.seq = 0

    def _nonce(self) -> bytes:
        seq = self.seq.to_bytes(12, "big")
        return bytes(a ^ b for a, b in zip(self.iv, seq))

    def encrypt(self, inner_plaintext: bytes) -> bytes:
        length = len(inner_plaintext) + 16
        aad = bytes([CT_APPLICATION_DATA, 0x03, 0x03]) + struct.pack(">H", length)
        ct = self.aead.encrypt(self._nonce(), inner_plaintext, aad)
        self.seq += 1
        return aad + ct

    def decrypt(self, record: bytes) -> tuple[int, bytes]:
        """*record* is a complete TLSCiphertext incl. its 5-byte header."""
        aad = record[:5]
        ct = record[5:]
        pt = self.aead.decrypt(self._nonce(), ct, aad)
        self.seq += 1
        # Strip zero padding, then the inner content type.
        i = len(pt) - 1
        while i >= 0 and pt[i] == 0:
            i -= 1
        if i < 0:
            raise TlsFixtureError("decrypted record is all padding")
        return pt[i], pt[:i]


# ---------------------------------------------------------------------------
# Wire helpers
# ---------------------------------------------------------------------------

def _u24(n: int) -> bytes:
    return bytes([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def _handshake(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + _u24(len(body)) + body


def _plaintext_record(content_type: int, payload: bytes) -> bytes:
    return bytes([content_type, 0x03, 0x03]) + struct.pack(">H", len(payload)) + payload


class RecordReader:
    """Reassembles TLS records from a stream socket."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = bytearray()

    def read_record(self, timeout: float) -> bytes | None:
        """Return one complete record (header included), or None on EOF."""
        deadline = time.monotonic() + timeout
        while True:
            if len(self.buf) >= 5:
                length = struct.unpack(">H", self.buf[3:5])[0]
                if len(self.buf) >= 5 + length:
                    rec = bytes(self.buf[: 5 + length])
                    del self.buf[: 5 + length]
                    return rec
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for a TLS record")
            self.sock.settimeout(remaining)
            chunk = self.sock.recv(4096)
            if not chunk:
                return None
            self.buf += chunk


def parse_client_hello(msg: bytes) -> dict:
    """Extract what the server needs from a ClientHello handshake message."""
    if not msg or msg[0] != HS_CLIENT_HELLO:
        raise TlsFixtureError(
            f"expected ClientHello, got handshake type {msg[0] if msg else 'EOF'}"
        )
    body = msg[4:]
    p = 0
    p += 2                                          # legacy_version
    client_random = body[p:p + 32]
    p += 32
    sid_len = body[p]
    p += 1
    session_id = body[p:p + sid_len]
    p += sid_len
    cs_len = struct.unpack(">H", body[p:p + 2])[0]
    p += 2
    suites = [
        struct.unpack(">H", body[p + i:p + i + 2])[0] for i in range(0, cs_len, 2)
    ]
    p += cs_len
    comp_len = body[p]
    p += 1 + comp_len
    ext_total = struct.unpack(">H", body[p:p + 2])[0]
    p += 2
    end = p + ext_total

    key_share = None
    while p < end:
        ext_type = struct.unpack(">H", body[p:p + 2])[0]
        ext_len = struct.unpack(">H", body[p + 2:p + 4])[0]
        data = body[p + 4:p + 4 + ext_len]
        p += 4 + ext_len
        if ext_type == EXT_KEY_SHARE:
            q = 2                                   # client_shares list length
            while q < len(data):
                group = struct.unpack(">H", data[q:q + 2])[0]
                klen = struct.unpack(">H", data[q + 2:q + 4])[0]
                if group == GROUP_X25519:
                    key_share = data[q + 4:q + 4 + klen]
                    break
                q += 4 + klen

    if TLS_CHACHA20_POLY1305_SHA256 not in suites:
        raise TlsFixtureError(
            "client did not offer TLS_CHACHA20_POLY1305_SHA256 (0x1303); "
            f"offered {[hex(s) for s in suites]}"
        )
    if key_share is None:
        raise TlsFixtureError("client sent no x25519 key_share")

    return {
        "client_random": client_random,
        "session_id": session_id,
        "key_share": key_share,
    }


# ---------------------------------------------------------------------------
# The server
# ---------------------------------------------------------------------------

class EvilTls13Server:
    """One-shot TLS 1.3 server flight, optionally with a corrupted Finished.

    *mode* is ``"good"`` or ``"bad_finished"``. The two modes run the *same*
    code path from end to end; they differ only in whether one bit of the
    server Finished ``verify_data`` is flipped before encryption.

    Deliberately, the server folds the Finished it actually sent into its own
    transcript. A client that wrongly accepts the corrupted Finished therefore
    stays in lockstep with the server and completes the handshake normally,
    ending at HTTP 200 — so a broken client fails loudly and quickly rather
    than hanging and being written off as a flaky timeout.
    """

    def __init__(self, cert_path: str, key_path: str, *,
                 mode: str = "good",
                 body: str = DEFAULT_BODY):
        if mode not in ("good", "bad_finished"):
            raise ValueError(f"unknown mode {mode!r}")
        self.mode = mode
        self.body = body

        with open(cert_path, "rb") as f:
            pem = f.read()
        self.cert_der = load_pem_x509_certificate(pem).public_bytes(
            serialization.Encoding.DER
        )
        with open(key_path, "rb") as f:
            self.key = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(self.key, ec.EllipticCurvePrivateKey):
            raise TlsFixtureError("this fixture only signs with ECDSA P-256")

        self.result: dict = {
            "mode": mode,
            "listening": False,
            "client_hello_seen": False,
            "server_flight_sent": False,
            "finished_corrupted": False,
            # The load-bearing one: did the client go on to send its own
            # Finished after our (possibly corrupted) Finished? A client that
            # checks the server Finished MUST NOT.
            "client_accepted_finished": None,
            "client_reaction": None,
            "client_finished_valid": None,
            "request": None,
            "response_sent": False,
            "client_alert": None,
            "error": None,
        }

    # -- handshake message builders ----------------------------------------

    def _server_hello(self, ch: dict, server_pub: bytes) -> bytes:
        ext = b""
        ext += struct.pack(">HH", EXT_SUPPORTED_VERSIONS, 2) + b"\x03\x04"
        ks = struct.pack(">HH", GROUP_X25519, len(server_pub)) + server_pub
        ext += struct.pack(">HH", EXT_KEY_SHARE, len(ks)) + ks

        body = b"\x03\x03"
        body += os.urandom(32)
        body += bytes([len(ch["session_id"])]) + ch["session_id"]
        body += struct.pack(">H", TLS_CHACHA20_POLY1305_SHA256)
        body += b"\x00"
        body += struct.pack(">H", len(ext)) + ext
        return _handshake(HS_SERVER_HELLO, body)

    def _certificate(self) -> bytes:
        entry = _u24(len(self.cert_der)) + self.cert_der + b"\x00\x00"
        body = b"\x00" + _u24(len(entry)) + entry
        return _handshake(HS_CERTIFICATE, body)

    def _certificate_verify(self, transcript_hash: bytes) -> bytes:
        signed = b"\x20" * 64
        signed += b"TLS 1.3, server CertificateVerify"
        signed += b"\x00"
        signed += transcript_hash
        sig = self.key.sign(signed, ec.ECDSA(hashes.SHA256()))
        body = struct.pack(">H", SIG_ECDSA_SECP256R1_SHA256)
        body += struct.pack(">H", len(sig)) + sig
        return _handshake(HS_CERTIFICATE_VERIFY, body)

    def _finished(self, secret: bytes, transcript_hash: bytes) -> tuple[bytes, bool]:
        finished_key = hkdf_expand_label(secret, b"finished", b"", HASH_LEN)
        verify_data = hmac.new(finished_key, transcript_hash, hashlib.sha256).digest()
        corrupted = False
        if self.mode == "bad_finished":
            # One bit, in the last byte. The message stays the right length and
            # the right shape; only the MAC is wrong, so the client must reach
            # the HMAC comparison to notice.
            verify_data = verify_data[:31] + bytes([verify_data[31] ^ 0x01])
            corrupted = True
        return _handshake(HS_FINISHED, verify_data), corrupted

    # -- the flight ---------------------------------------------------------

    def serve_one(self, sock: socket.socket, timeout: float) -> dict:
        reader = RecordReader(sock)

        rec = reader.read_record(timeout)
        if rec is None:
            raise TlsFixtureError("client closed before sending ClientHello")
        if rec[0] != CT_HANDSHAKE:
            raise TlsFixtureError(f"expected handshake record, got type {rec[0]}")
        ch_msg = rec[5:]
        ch = parse_client_hello(ch_msg)
        self.result["client_hello_seen"] = True

        server_priv = x25519.X25519PrivateKey.generate()
        server_pub = server_priv.public_key().public_bytes_raw()
        shared = server_priv.exchange(
            x25519.X25519PublicKey.from_public_bytes(ch["key_share"])
        )

        sh_msg = self._server_hello(ch, server_pub)
        sock.sendall(_plaintext_record(CT_HANDSHAKE, sh_msg))

        transcript = ch_msg + sh_msg

        early = _hkdf_extract(b"", b"\x00" * HASH_LEN)
        derived = derive_secret(early, b"derived", _sha256(b""))
        handshake_secret = _hkdf_extract(derived, shared)
        c_hs = derive_secret(handshake_secret, b"c hs traffic", _sha256(transcript))
        s_hs = derive_secret(handshake_secret, b"s hs traffic", _sha256(transcript))
        s_keys = TrafficKeys(s_hs)
        c_keys = TrafficKeys(c_hs)

        def send_hs(msg: bytes) -> None:
            # One handshake message per record: the C64 client's
            # tls_recv_encrypted dispatches on tls_rec_buf[0] and handles
            # exactly one message per decrypted record.
            sock.sendall(s_keys.encrypt(msg + bytes([CT_HANDSHAKE])))

        ee = _handshake(HS_ENCRYPTED_EXTENSIONS, b"\x00\x00")
        send_hs(ee)
        transcript += ee

        cert = self._certificate()
        send_hs(cert)
        transcript += cert

        cv = self._certificate_verify(_sha256(transcript))
        send_hs(cv)
        transcript += cv

        fin, corrupted = self._finished(s_hs, _sha256(transcript))
        send_hs(fin)
        self.result["finished_corrupted"] = corrupted
        self.result["server_flight_sent"] = True

        # Fold the Finished we actually SENT. A client that accepts the
        # corrupted Finished folds the same bytes, so its transcript still
        # agrees with ours and the rest of the handshake would succeed. That
        # is deliberate: it means a client with a broken check does not merely
        # stall, it sails through to HTTP 200 — a fast, unambiguous failure
        # signal instead of a test timeout.
        transcript += fin

        master = _hkdf_extract(
            derive_secret(handshake_secret, b"derived", _sha256(b"")),
            b"\x00" * HASH_LEN,
        )
        ap_transcript_hash = _sha256(transcript)
        c_ap = derive_secret(master, b"c ap traffic", ap_transcript_hash)
        s_ap = derive_secret(master, b"s ap traffic", ap_transcript_hash)

        expected_cf_key = hkdf_expand_label(c_hs, b"finished", b"", HASH_LEN)
        expected_cf = hmac.new(
            expected_cf_key, _sha256(transcript), hashlib.sha256
        ).digest()

        # --- What does the client do with our Finished? -------------------
        # This is the whole experiment. Whatever comes back next is recorded
        # as server-side evidence; the client cannot fabricate it.
        while True:
            try:
                rec = reader.read_record(timeout)
            except (TimeoutError, socket.timeout, OSError) as exc:
                self.result["client_accepted_finished"] = False
                self.result["client_reaction"] = f"no response ({type(exc).__name__})"
                return self.result
            if rec is None:
                self.result["client_accepted_finished"] = False
                self.result["client_reaction"] = "closed connection"
                return self.result
            if rec[0] == CT_CHANGE_CIPHER_SPEC:
                continue
            if rec[0] == CT_ALERT:
                self.result["client_accepted_finished"] = False
                self.result["client_reaction"] = f"plaintext alert {rec[5:].hex()}"
                return self.result
            try:
                ctype, pt = c_keys.decrypt(rec)
            except Exception as exc:              # noqa: BLE001 — fixture
                self.result["client_accepted_finished"] = False
                self.result["client_reaction"] = (
                    f"undecryptable record ({type(exc).__name__})"
                )
                return self.result
            if ctype == CT_ALERT:
                self.result["client_accepted_finished"] = False
                self.result["client_reaction"] = f"encrypted alert {pt.hex()}"
                return self.result
            if ctype != CT_HANDSHAKE or not pt or pt[0] != HS_FINISHED:
                self.result["client_accepted_finished"] = False
                self.result["client_reaction"] = (
                    f"unexpected record: inner type {ctype}, "
                    f"first byte {pt[0] if pt else None}"
                )
                return self.result
            self.result["client_accepted_finished"] = True
            self.result["client_reaction"] = "sent its own Finished"
            self.result["client_finished_valid"] = hmac.compare_digest(
                pt[4:36], expected_cf
            )
            break

        c_app = TrafficKeys(c_ap)
        s_app = TrafficKeys(s_ap)

        req = b""
        while b"\r\n\r\n" not in req:
            try:
                rec = reader.read_record(timeout)
            except (TimeoutError, socket.timeout, OSError):
                break
            if rec is None:
                break
            if rec[0] == CT_CHANGE_CIPHER_SPEC:
                continue
            ctype, pt = c_app.decrypt(rec)
            if ctype == CT_APPLICATION_DATA:
                req += pt
            elif ctype == CT_ALERT:
                self.result["client_alert"] = pt.hex()
                break
        self.result["request"] = req

        payload = self.body.encode()
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n" + payload
        )
        sock.sendall(s_app.encrypt(response + bytes([CT_APPLICATION_DATA])))
        self.result["response_sent"] = True
        time.sleep(1.0)
        return self.result

def serve_one_connection(srv: socket.socket, cert_path: str, key_path: str, *,
                         mode: str, body: str, timeout: float,
                         result: dict) -> None:
    """Accept exactly one connection and run the flight. Fills *result*."""
    conn = None
    try:
        srv.settimeout(timeout)
        srv.listen(1)
        result["listening"] = True
        conn, addr = srv.accept()
        result["client_addr"] = addr
        server = EvilTls13Server(cert_path, key_path, mode=mode, body=body)
        result.update(server.result)
        result["client_addr"] = addr
        result["listening"] = True
        try:
            server.serve_one(conn, timeout)
        finally:
            result.update(server.result)
            result["client_addr"] = addr
            result["listening"] = True
    except Exception as exc:                      # noqa: BLE001 — fixture
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        for s in (conn, srv):
            try:
                if s is not None:
                    s.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Self-test against Python's own ssl client
# ---------------------------------------------------------------------------

def _selftest() -> int:
    import ssl

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from https_listener import _ensure_certs_p256  # noqa: PLC0415

    cert_path, key_path = _ensure_certs_p256()
    failures = 0

    for mode, expect in (("good", "handshake completes"),
                         ("bad_finished", "client rejects")):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]

        result: dict = {}
        t = threading.Thread(
            target=serve_one_connection,
            args=(srv, cert_path, key_path),
            kwargs=dict(mode=mode, body=DEFAULT_BODY, timeout=20.0,
                        result=result),
            daemon=True,
        )
        t.start()
        time.sleep(0.2)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cafile=cert_path)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3

        ok = False
        detail = ""
        try:
            raw = socket.create_connection(("127.0.0.1", port), timeout=20.0)
            with ctx.wrap_socket(raw, server_hostname="www.foo.bar") as tls:
                tls.sendall(b"GET / HTTP/1.1\r\nHost: www.foo.bar\r\n\r\n")
                data = tls.recv(4096)
            if mode == "good":
                ok = b"200 OK" in data and DEFAULT_BODY.encode() in data
                detail = repr(data[:80])
            else:
                detail = f"handshake COMPLETED — server never rejected: {data[:60]!r}"
        except ssl.SSLError as exc:
            detail = f"{type(exc).__name__}: {exc}"
            if mode == "bad_finished":
                ok = True
        except Exception as exc:                  # noqa: BLE001
            detail = f"{type(exc).__name__}: {exc}"

        t.join(timeout=25.0)

        verdict = "PASS" if ok else "FAIL"
        print(f"  {verdict}: mode={mode:<13} expect {expect}")
        print(f"        client saw : {detail}")
        print(f"        server saw : {result}")
        if not ok:
            failures += 1

    print()
    if failures:
        print(f"  [-] evil_listener self-test: {failures} FAILED")
    else:
        print("  [+] evil_listener self-test: ALL PASSED")
    return 1 if failures else 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    print(__doc__)
    print("Run with --selftest to validate against Python's ssl client.")
