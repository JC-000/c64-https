#!/usr/bin/env python3
"""test_tls_deframer.py - VICE acceptance suite for the streaming handshake
deframer (sprint W1/W2).

WHAT THIS IS
------------
An *independent* acceptance gate for the record/message deframer that a
parallel lane is adding to ``src/tls13.s`` / ``src/tls_record_io.s`` /
``src/tls_cert.s``.  It was written without sight of that implementation:
every expectation here is derived from RFC 8446 handshake reassembly and the
sprint plan, so a build that satisfies this suite satisfies the spec, not one
particular author's code.

THE PROBLEM THE DEFRAMER SOLVES (RFC 8446 §5.1)
----------------------------------------------
Handshake messages are ``TYPE(1) || LEN(3) || BODY``, packed back-to-back in
the handshake content stream.  TLS records fragment that stream *arbitrarily*:

  (a) one record can carry two whole messages (EncryptedExtensions + the start
      of Certificate is the real-world pattern; CertificateVerify + Finished
      likewise),
  (b) one message can span several records, split at *any* offset — including
      inside the 4-byte message header,
  (c) the Certificate message (~2.7 KB, multi-cert chain) spans ~6 records;
      only the first (leaf) cert must be captured, the rest counted+discarded,
  (d) a leaf certificate larger than ``cert_buf`` (2048 B UCI / 1536 B ip65,
      read from labels.txt ``cert_buf_size``) must produce a clean
      "certificate too large" error, never a buffer overflow — while a
      Wikipedia-sized ~1636 B leaf must be ACCEPTED on the UCI build.

The current code (``tls13.s`` ~555-660) assumes exactly one message per record.
Every scenario below that is marked ``[deframer]`` therefore FAILS on the
pre-deframer build and is EXPECTED to — that is the whole point of an
acceptance gate written ahead of the code.  Scenarios marked ``[plumbing]``
exercise only the one-message-per-record path that already works, so they pass
today and prove the rig itself (ring priming, decrypt, dispatch, transcript,
cert parsing) is sound.

HOW IT DRIVES THE REAL SEAM
---------------------------
No internal deframer symbol is named here, so the suite cannot rot when the
implementation names things differently.  It drives the *public* entry the
deframer sits behind — ``tls_recv_encrypted`` — exactly as ``tls_connect``
does, over genuinely AEAD-encrypted records:

  1. ``net_poll`` is patched to a bare ``RTS`` so the routine's built-in NIC
     pump is inert; every byte comes from the pre-primed TCP receive ring.
  2. Encrypted TLS records (ChaCha20-Poly1305 under a fixed handshake read key)
     are written straight into ``tcp_recv_buf`` and the ring head/tail set, so
     ``tls_record_recv_and_decrypt`` decrypts them the same way it decrypts
     records off the wire.
  3. ``tls_recv_encrypted`` is called until the flight is drained.

ORACLES (implementation-independent)
------------------------------------
  * ``ecdsa_pubkey_x`` / ``ecdsa_pubkey_y`` == the leaf cert's public key.
    This is the load-bearing discriminator: it is populated only if the
    Certificate message was *fully reassembled and parsed*.  A build that
    dispatches only the first message of a two-message record, or mis-handles a
    Certificate split across records, leaves it at its poison value.
  * the running transcript (read via ``tls_transcript_hash``) ==
    SHA-256(concatenated handshake messages).  Proves every message's bytes
    were folded regardless of record framing.
  * for the oversized-leaf case, ``cert_buf`` itself is pre-filled with a
    sentinel pattern that must survive the flight untouched, and no valid
    pubkey may be extracted.  The CertificateEntry's 24-bit length field
    arrives before any cert_data byte, so a correct implementation can (and
    must) reject an oversized leaf BEFORE copying anything — "reject on the
    length field" is the only overflow oracle this memory map permits, because
    the byte after ``cert_buf``'s cap is ``tls_rec_buf[0]`` ($A600 under both
    cfgs), which the record layer legitimately writes on every flight.  (An
    earlier revision put a sentinel at ``cert_buf+1536`` and was therefore
    unpassable by ANY implementation — caught by the deframer lane's first run
    against it.)

Both crypto-verified messages (CertificateVerify, Finished) are intentionally
absent from this suite: their transcript discipline needs a self-consistent
real handshake and is the job of the end-to-end re-framing test
(``tools/https_e2e/evil_listener.py`` ``RECORD_FRAME=...`` + the live rig).
Here we use EncryptedExtensions (accepted + folded, no crypto) and Certificate
(parsed + folded, no signature check), which is all the deframer's *framing*
logic needs.

Vectors are fully deterministic (fixed key/iv/seq, repo test cert), so a
failure reproduces byte-for-byte.

BACKEND: the deframer ships UCI-only (``TLS_STREAM_DEFRAME`` defaults ON for
``BACKEND=uci``, OFF for ip65, which has no code/BSS headroom).  This suite
therefore builds ``make BACKEND=uci`` by default; on an ip65 build the nine
``[deframer]`` scenarios xfail BY DESIGN, not by defect.  The suite itself is
backend-agnostic — every address comes from ``build/labels.txt``.

Usage:
    python3 tools/test_tls_deframer.py [--verbose]

Env:
    C64_SKIP_BUILD=1             reuse the already-built PRG
    DEFRAMER_BUILD_BACKEND=ip65  build the ip65 image instead (deframer
                                 scenarios then xfail by design)

Requires: Python 3.10+, c64_test_harness, VICE x64sc, cryptography
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from c64_test_harness import (
    Labels,
    ViceInstanceManager,
    read_bytes,
    write_bytes,
    jsr,
    wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _vice_helpers import default_vice_config  # noqa: E402

PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

# --- TLS constants (mirror src/constants.inc) ---
TLS_CT_HANDSHAKE = 22
TLS_CT_APPLICATION = 23
TLS_HS_ENCRYPTED_EXT = 8
TLS_HS_CERTIFICATE = 11
TLS_HS_CERT_VERIFY = 15
TLS_HS_FINISHED = 20
TLS_STATE_ENCRYPTED_EXT = 3
TLS_STATE_CERTIFICATE = 4          # >= ENCRYPTED_EXT(3): decrypt with hs read keys
TLS_STATE_CERT_VERIFY = 5
TLS_STATE_FINISHED = 6

# Since issue #152 the dispatcher refuses any handshake message that is not
# the one `tls_state` says is due, so the rig must step the state before each
# received message exactly as `tls_connect` does — one state per message, not
# one per flight. Every value here is >= ENCRYPTED_EXT and < CONNECTED, so the
# record layer still decrypts with the handshake read keys throughout.
STATE_FOR_TYPE = {
    TLS_HS_ENCRYPTED_EXT: TLS_STATE_ENCRYPTED_EXT,
    TLS_HS_CERTIFICATE: TLS_STATE_CERTIFICATE,
    TLS_HS_CERT_VERIFY: TLS_STATE_CERT_VERIFY,
    TLS_HS_FINISHED: TLS_STATE_FINISHED,
}

# cert_buf capacity — resolved in main() from build/labels.txt
# (`cert_buf_size`, an absolute export in src/exports.s: 2048 under UCI,
# 1536 under ip65 — src/net/<backend>/net_tuning.inc). Never hardcode
# either number here: the Wikipedia growth made the size
# backend-conditional, and the oversize/boundary vectors below scale
# with it.
CERT_BUF_MAX = None

# Fixed handshake read key/iv/seq so every record is reproducible.
HS_READ_KEY = bytes((i * 7 + 3) & 0xFF for i in range(32))
HS_READ_IV = bytes((i * 11 + 5) & 0xFF for i in range(12))

POISON = 0xA5
SENTINEL = 0x5A

REQUIRED_LABELS = [
    "tls_recv_encrypted",
    "net_poll",
    "tcp_recv_buf", "tcp_recv_head", "tcp_recv_tail",
    "tls_rec_buf", "tls_rec_len", "tls_rec_type",
    "tls_recv_state", "tls_recv_count",
    "tls_state",
    "tls_hs_read_key", "tls_hs_read_iv", "tls_read_seq",
    "tls_transcript", "tls_transcript_init", "tls_transcript_hash",
    "ecdsa_pubkey_x", "ecdsa_pubkey_y",
    "cert_buf",
    "cert_buf_size",
    "sqtab_init",
]

RTS = 0x60


# ---------------------------------------------------------------------------
# Handshake-message + record construction
# ---------------------------------------------------------------------------

def _u24(n: int) -> bytes:
    return bytes([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def hs_message(msg_type: int, body: bytes) -> bytes:
    """One handshake message: TYPE(1) || LEN(3) || BODY."""
    return bytes([msg_type]) + _u24(len(body)) + body


def encrypted_extensions() -> bytes:
    # Empty EncryptedExtensions: a 2-byte (zero-length) extensions block.
    return hs_message(TLS_HS_ENCRYPTED_EXT, b"\x00\x00")


def certificate_message(cert_der: bytes) -> bytes:
    """A TLS 1.3 Certificate message carrying one entry (matches the shape the
    server fixture emits): context(0) || cert_list_len(24) ||
    [ cert_data_len(24) || cert_data || ext_len(16)=0 ]."""
    entry = _u24(len(cert_der)) + cert_der + b"\x00\x00"
    body = b"\x00" + _u24(len(entry)) + entry
    return hs_message(TLS_HS_CERTIFICATE, body)


def encrypt_record(inner_plaintext: bytes, seq: int) -> bytes:
    """Build one TLSCiphertext record (5-byte header + ct + tag).

    inner_plaintext already includes its trailing inner content-type byte.
    """
    padded_seq = b"\x00" * 4 + seq.to_bytes(8, "big")
    nonce = bytes(a ^ b for a, b in zip(HS_READ_IV, padded_seq))
    total = len(inner_plaintext) + 16
    aad = bytes([TLS_CT_APPLICATION, 0x03, 0x03, (total >> 8) & 0xFF, total & 0xFF])
    ct = ChaCha20Poly1305(HS_READ_KEY).encrypt(nonce, inner_plaintext, aad)
    return aad + ct


def records_from_chunks(chunks: list[bytes]) -> bytes:
    """Encrypt each handshake-stream *chunk* as its own record, seq 0,1,2,...

    Each record's inner plaintext = chunk || CT_HANDSHAKE, exactly as the wire
    carries a fragment of the handshake content stream.
    """
    out = bytearray()
    for i, chunk in enumerate(chunks):
        out += encrypt_record(chunk + bytes([TLS_CT_HANDSHAKE]), i)
    return bytes(out), len(chunks)


def chunk_bytes(stream: bytes, sizes: list[int]) -> list[bytes]:
    """Slice *stream* into pieces of the given sizes (last piece takes the
    remainder if sizes run short)."""
    out = []
    pos = 0
    for s in sizes:
        if pos >= len(stream):
            break
        out.append(stream[pos:pos + s])
        pos += s
    if pos < len(stream):
        out.append(stream[pos:])
    return out


# ---------------------------------------------------------------------------
# C64 plumbing
# ---------------------------------------------------------------------------

def prime_ring(transport, labels, record_bytes: bytes) -> None:
    """Load encrypted records into the TCP receive ring and set head/tail."""
    n = len(record_bytes)
    assert n < 0x1000, f"flight {n} B exceeds the 4 KB ring"
    write_bytes(transport, labels["tcp_recv_buf"], record_bytes)
    # head = 0, tail = n  (both 16-bit little-endian)
    write_bytes(transport, labels["tcp_recv_head"], [0, 0])
    write_bytes(transport, labels["tcp_recv_tail"], [n & 0xFF, (n >> 8) & 0xFF])


def reset_recv_state(transport, labels) -> None:
    write_bytes(transport, labels["tls_recv_state"], [0])
    write_bytes(transport, labels["tls_recv_count"], [0, 0])
    write_bytes(transport, labels["tls_read_seq"], b"\x00" * 8)
    write_bytes(transport, labels["tls_state"], [TLS_STATE_CERTIFICATE])
    # Fresh-connection deframer reset, exactly as tls_connect does after
    # ServerHello (src/tls13.s @ `jsr tls_deframe_init`). Each scenario
    # is a fresh simulated connection; without this, a scenario that
    # aborts MID-STREAM (the oversized-leaf reject) leaks DF_MODE_STREAM
    # state into the next scenario's flight — invisible while the
    # error vector ran last, real once anything follows it. Conditional
    # because pre-deframer / ip65 builds export no such symbol (their
    # deframer scenarios xfail by design).
    if labels.address("tls_deframe_init") is not None:
        jsr(transport, labels["tls_deframe_init"], timeout=30.0)


def ring_is_empty(transport, labels) -> bool:
    head = read_bytes(transport, labels["tcp_recv_head"], 2)
    tail = read_bytes(transport, labels["tcp_recv_tail"], 2)
    return head == tail


def states_for_stream(stream: bytes) -> list[int]:
    """tls_state for each handshake message in the plaintext *stream*.

    Walks the 4-byte message headers. A trailing partial message contributes
    nothing; an unknown type maps to CERTIFICATE, the state this rig has
    always used as its default.
    """
    states: list[int] = []
    i = 0
    while i + 4 <= len(stream):
        body_len = int.from_bytes(stream[i + 1:i + 4], "big")
        states.append(STATE_FOR_TYPE.get(stream[i], TLS_STATE_CERTIFICATE))
        i += 4 + body_len
    return states


def drive_flight(transport, labels, record_bytes, n_records, n_msgs,
                 msg_states=None):
    """Prime the ring and pump tls_recv_encrypted until the flight drains.

    Returns the list of carry flags observed (diagnostic only; the oracle is
    end-state, so a build whose call granularity differs is still judged
    fairly — one call may consume one message or the whole flight).

    Early exit: once the ring is empty and *n_msgs* calls have succeeded,
    nothing more can arrive (net_poll is an RTS), so stop rather than let a
    surplus call spin tls_recv_encrypted's 65,536-poll timeout loop. A C=1
    return also ends the flight (error, or drained + timed out).
    """
    reset_recv_state(transport, labels)
    prime_ring(transport, labels, record_bytes)
    carries = []
    successes = 0
    # An upper bound on calls under any sane design: never more than one call
    # per record, plus slack for a drain call. Capped so a wedged build cannot
    # spin the suite forever.
    max_calls = min(n_records + 2, 8)
    for _ in range(max_calls):
        # Step tls_state to the message this call is meant to receive
        # (issue #152 — see STATE_FOR_TYPE).
        if msg_states:
            state = (msg_states[successes] if successes < len(msg_states)
                     else msg_states[-1])
            write_bytes(transport, labels["tls_state"], [state])
        regs = jsr(transport, labels["tls_recv_encrypted"], timeout=120.0)
        carry = None
        if regs:
            for k in ("FL", "P", "FLAGS", "SR"):
                if k in regs:
                    carry = regs[k] & 0x01
                    break
        carries.append(carry)
        if carry == 0:
            successes += 1
        if carry == 1:
            break
        if successes >= n_msgs and ring_is_empty(transport, labels):
            break
    return carries


def read_pubkey(transport, labels):
    x = read_bytes(transport, labels["ecdsa_pubkey_x"], 32)
    y = read_bytes(transport, labels["ecdsa_pubkey_y"], 32)
    return x, y


def read_transcript(transport, labels):
    """Snapshot the running transcript hash into tls_transcript and read it."""
    jsr(transport, labels["tls_transcript_hash"], timeout=60.0)
    return read_bytes(transport, labels["tls_transcript"], 32)


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

class Scenario:
    def __init__(self, name, kind, chunks, expect_pubkey, expect_transcript,
                 expect_overflow_safe=False, n_msgs=1):
        self.name = name
        self.kind = kind                        # "plumbing" or "deframer"
        self.chunks = chunks
        self.expect_pubkey = expect_pubkey      # (x, y) or None
        self.expect_transcript = expect_transcript  # bytes or None
        self.expect_overflow_safe = expect_overflow_safe
        self.n_msgs = n_msgs                    # handshake messages in flight


def build_scenarios(cert_der, pubkey_xy, wiki_leaf=None):
    ee = encrypted_extensions()
    cert = certificate_message(cert_der)
    px, py = pubkey_xy

    scenarios = []

    # --- plumbing: one message per record (works today, proves the rig) ---
    stream = ee + cert
    scenarios.append(Scenario(
        "plumbing/one_msg_per_record",
        "plumbing",
        [ee, cert],
        (px, py),
        hashlib.sha256(stream).digest(),
        n_msgs=2,
    ))

    # A lone Certificate in a single record — the simplest reassembly-free
    # cert parse. Also passes today.
    scenarios.append(Scenario(
        "plumbing/cert_single_record",
        "plumbing",
        [cert],
        (px, py),
        hashlib.sha256(cert).digest(),
    ))

    # --- deframer (a): two whole messages in one record ---
    scenarios.append(Scenario(
        "deframer/two_msgs_one_record",
        "deframer",
        [ee + cert],
        (px, py),
        hashlib.sha256(ee + cert).digest(),
        n_msgs=2,
    ))

    # --- deframer (b): one message split across records ---
    # mid-body split of the Certificate message.
    scenarios.append(Scenario(
        "deframer/cert_split_mid_body",
        "deframer",
        chunk_bytes(cert, [200]),
        (px, py),
        hashlib.sha256(cert).digest(),
    ))

    # split INSIDE the 4-byte handshake header, at each of offsets 1/2/3.
    for k in (1, 2, 3):
        scenarios.append(Scenario(
            f"deframer/cert_split_in_header@{k}",
            "deframer",
            chunk_bytes(cert, [k]),
            (px, py),
            hashlib.sha256(cert).digest(),
        ))

    # split exactly on the header/body boundary (offset 4).
    scenarios.append(Scenario(
        "deframer/cert_split_header_body_boundary",
        "deframer",
        chunk_bytes(cert, [4]),
        (px, py),
        hashlib.sha256(cert).digest(),
    ))

    # exact message-boundary case: a record ends mid-flight exactly at the EE
    # message boundary, and the Certificate spans two records.
    half = len(cert) // 2
    scenarios.append(Scenario(
        "deframer/msg_boundary_and_cert_span",
        "deframer",
        [ee + cert[:half], cert[half:]],
        (px, py),
        hashlib.sha256(ee + cert).digest(),
        n_msgs=2,
    ))

    # certificate spanning many small records (the real ~6-record pattern).
    scenarios.append(Scenario(
        "deframer/cert_many_records",
        "deframer",
        chunk_bytes(cert, [64, 64, 64, 64, 64]),
        (px, py),
        hashlib.sha256(cert).digest(),
    ))

    # --- deframer: MFL-512 real-server record shape ---
    # Records carrying EXACTLY 512 content bytes (inner plaintext 513: the
    # inner content-type byte sits at index 512, i.e. page 2 of tls_rec_buf).
    # This is what a max_fragment_length-honoring server (github.com) sends,
    # and it is one byte past every local fixture: the record layer's
    # inner-type extraction had a two-page dispatch that misread index 512
    # as tls_rec_buf[256], aborting the handshake with a bogus content type.
    # Found live against github.com 2026-08-21; keep this vector so the
    # class stays covered.
    # The vector must be adversarial BY CONSTRUCTION: the buggy dispatch read
    # tls_rec_buf[256] as the inner type, so a record whose content byte 256
    # happens to be $16 passes by luck (the first draft of this vector did).
    # A 512-byte EE message padded with zeros pins content[256] to $00.
    ee_big = hs_message(TLS_HS_ENCRYPTED_EXT, b"\x01\xfa" + b"\x00" * 506)
    assert len(ee_big) == 512
    assert ee_big[256] != TLS_CT_HANDSHAKE
    scenarios.append(Scenario(
        "deframer/mfl512_full_records",
        "deframer",
        chunk_bytes(ee_big + cert, [512]),
        (px, py),
        hashlib.sha256(ee_big + cert).digest(),
        n_msgs=2,
    ))

    # --- deframer: wikipedia-SHAPED flight (2026-08-22 stall forensics) ---
    # Real en.wikipedia.org shape: EE in a small record, then a multi-cert
    # Certificate whose FIRST entry is the 1636 B leaf (> the historical
    # 1536 B cap — the reason for the 2048 UCI cert_buf), spanning many
    # 512-content records. This pins the CONSUMER side: deframer + record
    # layer + multi-cert framing keep the big leaf and discard the rest.
    #
    # NOTE — SCOPE: this harness primes the whole flight into the ring up
    # front with net_poll stubbed to RTS, so it CANNOT reproduce the
    # actual hardware stall, which is in the ADAPTER fill loop
    # (src/net/uci/net.s net_poll requesting >ring-free and the response
    # drain discarding the overflow — fixed there by clamping the
    # SOCKET_READ maxlen to ring free space). That fix is validated on
    # hardware / a poll-driven rig, NOT here. Kept under the 4 KB ring
    # (leaf 1636 + one 656 intermediate) so prime_ring can hold it.
    if wiki_leaf is not None and len(wiki_leaf[0]) <= CERT_BUF_MAX:
        shaped_leaf, shaped_xy = wiki_leaf
    else:
        shaped_leaf, shaped_xy = cert_der, (px, py)
    shaped_inter = bytes([0x30, 0x82]) + (656 - 4).to_bytes(2, "big") + \
        bytes((i * 7 + 656) & 0xFF for i in range(656 - 4))
    entries = b""
    for c in (shaped_leaf, shaped_inter):
        entries += len(c).to_bytes(3, "big") + c + b"\x00\x00"
    body = b"\x00" + len(entries).to_bytes(3, "big") + entries
    shaped_cert = hs_message(TLS_HS_CERTIFICATE, body)
    scenarios.append(Scenario(
        "deframer/wikipedia_shaped_flight",
        "deframer",
        [ee] + chunk_bytes(shaped_cert, [512] * 6),
        shaped_xy,
        hashlib.sha256(ee + shaped_cert).digest(),
        n_msgs=2,
    ))

    # --- deframer (d): oversized leaf must error, not overflow ---
    # A single-entry Certificate whose cert_data exceeds cert_buf
    # (CERT_BUF_MAX, read from labels.txt — 2048 UCI / 1536 ip65).
    big_leaf = b"\x30\x82" + (CERT_BUF_MAX + 200).to_bytes(2, "big") + \
        bytes((i * 3) & 0xFF for i in range(CERT_BUF_MAX + 160))
    big_cert = certificate_message(big_leaf)
    scenarios.append(Scenario(
        "deframer/oversized_leaf_errors",
        "deframer",
        chunk_bytes(big_cert, [480, 480, 480, 480, 480]),
        None,                                   # must NOT extract a pubkey
        None,                                   # transcript not asserted
        expect_overflow_safe=True,
    ))

    # --- wiki gate: a ~1636 B leaf (en.wikipedia.org's leaf size) ---
    # The whole point of the 2048 B UCI cert_buf: a leaf bigger than the
    # historical 1536 B cap but under 2048 must be ACCEPTED and fully
    # parsed (real minted P-256 cert, pubkey extraction is the oracle).
    # On a 1536 B build (ip65 cap) the same leaf must instead be the
    # clean TOO_BIG reject, cert_buf untouched.
    if wiki_leaf is not None:
        wleaf_der, (wx, wy) = wiki_leaf
        wcert = certificate_message(wleaf_der)
        if len(wleaf_der) <= CERT_BUF_MAX:
            scenarios.append(Scenario(
                "deframer/wikipedia_sized_leaf_accepted",
                "deframer",
                chunk_bytes(wcert, [480, 480, 480]),
                (wx, wy),
                hashlib.sha256(wcert).digest(),
            ))
        else:
            scenarios.append(Scenario(
                "deframer/wikipedia_sized_leaf_errors",
                "deframer",
                chunk_bytes(wcert, [480, 480, 480]),
                None,
                None,
                expect_overflow_safe=True,
            ))

    return scenarios


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_scenario(transport, labels, sc):
    """Return (ok, detail)."""
    # Poison the observables so a stale value from a prior scenario cannot be
    # mistaken for a fresh extraction.
    write_bytes(transport, labels["ecdsa_pubkey_x"], bytes([POISON]) * 32)
    write_bytes(transport, labels["ecdsa_pubkey_y"], bytes([POISON]) * 32)
    write_bytes(transport, labels["tls_transcript"], bytes([POISON]) * 32)
    if sc.expect_overflow_safe:
        # Fill cert_buf ITSELF with the sentinel. The CertificateEntry length
        # field precedes the cert bytes, so a correct implementation rejects an
        # oversized leaf before copying anything — cert_buf must come back
        # untouched. A sentinel *past* cert_buf would be useless here: the next
        # byte is tls_rec_buf[0], which the record layer legitimately writes.
        write_bytes(transport, labels["cert_buf"],
                    bytes([SENTINEL]) * CERT_BUF_MAX)

    # Fresh running transcript so the fold accumulates exactly this flight.
    jsr(transport, labels["tls_transcript_init"], timeout=60.0)
    write_bytes(transport, labels["tls_hs_read_key"], HS_READ_KEY)
    write_bytes(transport, labels["tls_hs_read_iv"], HS_READ_IV)

    record_bytes, n_records = records_from_chunks(sc.chunks)
    carries = drive_flight(transport, labels, record_bytes, n_records,
                           sc.n_msgs,
                           states_for_stream(b"".join(sc.chunks)))

    problems = []

    if sc.expect_pubkey is not None:
        gx, gy = read_pubkey(transport, labels)
        ex, ey = sc.expect_pubkey
        if gx != ex or gy != ey:
            problems.append(
                f"pubkey mismatch (Certificate not fully reassembled/parsed)\n"
                f"      want x {ex.hex()}\n      got  x {gx.hex()}\n"
                f"      want y {ey.hex()}\n      got  y {gy.hex()}"
            )

    if sc.expect_transcript is not None:
        got_t = read_transcript(transport, labels)
        if got_t != sc.expect_transcript:
            problems.append(
                f"transcript mismatch (a message's bytes were not folded)\n"
                f"      want {sc.expect_transcript.hex()}\n"
                f"      got  {got_t.hex()}"
            )

    if sc.expect_overflow_safe:
        buf = read_bytes(transport, labels["cert_buf"], CERT_BUF_MAX)
        if buf != bytes([SENTINEL]) * CERT_BUF_MAX:
            first = next(i for i, b in enumerate(buf) if b != SENTINEL)
            problems.append(
                f"cert_buf written during an oversized-leaf flight (first "
                f"clobber at cert_buf+{first}, ${buf[first]:02X}) — the size "
                f"guard must fire on the CertificateEntry length field, "
                f"BEFORE any cert_data byte is copied"
            )
        gx, gy = read_pubkey(transport, labels)
        if gx != bytes([POISON]) * 32 or gy != bytes([POISON]) * 32:
            problems.append(
                "oversized leaf still produced a pubkey — the size guard did "
                "not fire before extraction"
            )

    detail = ""
    if problems:
        detail = "\n    " + "\n    ".join(problems)
    if VERBOSE:
        detail += f"\n    carries={carries} records={n_records}"
    return (not problems), detail


def run_tests(transport, labels, cert_der, pubkey_xy, wiki_leaf=None):
    print("\n  Initializing sqtab (Poly1305 multiply table)...")
    jsr(transport, labels["sqtab_init"], timeout=60.0)

    # Neutralize the NIC pump: every byte comes from the primed ring.
    write_bytes(transport, labels["net_poll"], [RTS])
    print("  net_poll patched to RTS (ring-driven, no live NIC)")

    scenarios = build_scenarios(cert_der, pubkey_xy, wiki_leaf)

    plumb_pass = plumb_fail = defr_pass = defr_fail = 0
    for sc in scenarios:
        ok, detail = run_scenario(transport, labels, sc)
        verdict = "PASS" if ok else "FAIL"
        tag = f"[{sc.kind}]"
        print(f"  {verdict} {tag:<11} {sc.name}{detail}")
        if sc.kind == "plumbing":
            if ok:
                plumb_pass += 1
            else:
                plumb_fail += 1
        else:
            if ok:
                defr_pass += 1
            else:
                defr_fail += 1

    return plumb_pass, plumb_fail, defr_pass, defr_fail


# ---------------------------------------------------------------------------
# Cert fixture
# ---------------------------------------------------------------------------

def load_cert_fixture():
    """Return (cert_der, (pubkey_x, pubkey_y)) from the repo P-256 test cert."""
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.primitives import serialization

    sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools", "https_e2e"))
    from ensure_certs import ensure_certs  # noqa: PLC0415

    cert_path, _ = ensure_certs("p256")
    pem = open(cert_path, "rb").read()
    cert = load_pem_x509_certificate(pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    nums = cert.public_key().public_numbers()
    return der, (nums.x.to_bytes(32, "big"), nums.y.to_bytes(32, "big"))


def build_wiki_leaf(target: int = 1636):
    """Mint a real, parseable ~1636 B P-256 leaf (en.wikipedia.org's size).

    Uses the padded-cert generator from tools/https_e2e/chain_certs.py
    (standard v3 shape: SPKI before the padding extension, so the C64's
    skip-and-seek parser extracts the key the same way it does for the
    repo cert). The key is minted fresh per run, so the expected pubkey
    comes from the cert itself rather than a fixed vector; everything
    else about the scenario stays deterministic. Sizing converges in a
    couple of passes (the ECDSA signature length wobbles by ±2 B, which
    is irrelevant to the gate — anything in (1536, 2048] exercises it).
    """
    from cryptography.x509 import load_der_x509_certificate

    sys.path.insert(0, os.path.join(PROJECT_ROOT, "tools", "https_e2e"))
    from chain_certs import build_padded_intermediate  # noqa: PLC0415

    pad = 1200
    der = build_padded_intermediate("C64 Wiki-Sized Leaf", pad)
    for _ in range(4):
        if len(der) == target:
            break
        pad += target - len(der)
        der = build_padded_intermediate("C64 Wiki-Sized Leaf", pad)
    if not (1536 < len(der) <= 2048):
        raise RuntimeError(f"wiki leaf sizing failed: {len(der)} B")
    nums = load_der_x509_certificate(der).public_key().public_numbers()
    return der, (nums.x.to_bytes(32, "big"), nums.y.to_bytes(32, "big"))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    global VERBOSE
    os.chdir(PROJECT_ROOT)

    if "--verbose" in sys.argv:
        VERBOSE = True

    if os.environ.get("C64_SKIP_BUILD"):
        print("\n=== Building (skipped: C64_SKIP_BUILD set) ===")
    else:
        # UCI by default: the deframer is TLS_STREAM_DEFRAME, ON only under
        # BACKEND=uci (ip65 has no headroom — its deframer scenarios xfail by
        # design). make clean first: make tracks timestamps, not the command
        # line, so a backend switch without clean produces a mixed link.
        backend = os.environ.get("DEFRAMER_BUILD_BACKEND", "uci")
        print(f"\n=== Building (BACKEND={backend}) ===")
        subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
        result = subprocess.run(["make", f"BACKEND={backend}"],
                                capture_output=True, text=True,
                                cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            return 1
        print("  Build OK")

    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found")
        return 1

    labels = Labels.from_file(LABELS_PATH)
    missing = [n for n in REQUIRED_LABELS if labels.address(n) is None]
    if missing:
        print(f"FATAL: required label(s) not found: {', '.join(missing)}")
        return 1

    global CERT_BUF_MAX
    CERT_BUF_MAX = labels.address("cert_buf_size")
    print(f"  cert_buf capacity: {CERT_BUF_MAX} B (labels.txt cert_buf_size)")

    cert_der, pubkey_xy = load_cert_fixture()
    print(f"  Test cert: {len(cert_der)} B DER, "
          f"pubkey x={pubkey_xy[0][:6].hex()}...")
    wiki_leaf = build_wiki_leaf()
    print(f"  Wiki-sized leaf: {len(wiki_leaf[0])} B DER "
          f"({'fits' if len(wiki_leaf[0]) <= CERT_BUF_MAX else 'over cap'})")

    config = default_vice_config(prg_path=PRG_PATH, warp=True, ntsc=True,
                                 sound=False)
    print("\n=== Starting VICE ===")
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"  VICE PID={inst.pid}, port={inst.port}")

        grid = wait_for_text(transport, "Q=QUIT", timeout=120.0, verbose=False)
        if grid is None:
            print("FATAL: Main menu did not appear")
            mgr.release(inst)
            return 1
        print("  Main menu ready")

        print("\n=== Deframer scenarios ===")
        try:
            pp, pf, dp, df = run_tests(transport, labels, cert_der,
                                       pubkey_xy, wiki_leaf)
        finally:
            mgr.release(inst)

    print("\n" + "=" * 64)
    print("RESULTS")
    print("=" * 64)
    print(f"  plumbing (must pass on ANY build): {pp}/{pp + pf} passed")
    print(f"  deframer (W1/W2 acceptance gate):  {dp}/{dp + df} passed")
    print()
    if pf:
        print("  [-] PLUMBING FAILED — the rig itself is broken; deframer")
        print("      results below are not trustworthy. Fix plumbing first.")
        print("=" * 64)
        return 1
    if df:
        print(f"  [x] {df} deframer scenario(s) not yet satisfied.")
        print("      EXPECTED on the pre-deframer build; this is the gate the")
        print("      streaming-deframer lane must turn green.")
        print("=" * 64)
        # Non-zero so CI/callers see the gate is not yet met, but plumbing is OK.
        return 2
    print("  [+] Deframer acceptance gate: ALL scenarios PASSED")
    print("=" * 64)
    return 0


if __name__ == "__main__":
    sys.exit(main())
