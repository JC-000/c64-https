#!/usr/bin/env python3
"""test_aead_fail_closed.py — issue #239: an AEAD tag failure must fail
closed, fast, instead of reading as "no record yet".

WHAT THIS PINS
--------------
``tls_record_recv_and_decrypt`` (src/tls_record_io.s) used to return a bare
C=1 for three different things: "no complete record yet", "malformed header
skipped", and "AEAD tag failed".  Every caller loops on C=1, so a tag
failure was counted as an idle tick.  After one lost or altered byte
``tls_read_seq`` never advances again, so every later record fails too, and
the fetch sat out its whole 65,536-tick budget — ~87 minutes against a live
UCI socket, which every rig reads as a hang — with ``tls_state`` still
CONNECTED and nothing to say why.  The handshake receive loop
(``tls_recv_encrypted``, both the ip65 and the streaming-deframer variant)
had the same conflation.

The fix latches the failure: ``tls_state = TLS_STATE_ERROR`` ($FF),
``tls_last_state`` = the state the failure hit, ``tls_recv_sub_progress``
= $0B.  Each looping caller tests bit 7 of ``tls_state`` before counting a
tick, and ``tls_connect``'s error exit no longer overwrites the
``tls_last_state`` the record layer wrote.

Two neighbours of the same conflation are pinned here too:

  * a record header that fails validation once records are encrypted is
    latched the same way (sub-progress $0C) instead of resyncing a byte at
    a time through ciphertext; before the handshake keys it still resyncs
    (control case);
  * an alert record (close_notify) ends ``http_recv_body``'s loop at once
    and lets the framing verdict decide — C=1 when short of
    Content-Length, C=0 for an unframed body — instead of being an idle
    tick. It is an orderly close, so ``tls_state`` is NOT latched. Any
    OTHER alert (AlertDescription != 0), or an alert that is not exactly
    2 B, returns C=1 at once.

Added after adversarial review of PR #240:

  * records of 16 B or less after the keys are rejected ($0C) before
    ``tls_record_decrypt``, whose unchecked ``tls_rec_len - 16`` underflowed
    and swept ~64 KB of memory (I/O included) through Poly1305.
    ``tls_enc_aead_len`` is poisoned as the witness that the decrypt was
    never entered; a 17-byte record is the accepted boundary control;
  * the frame check is exercised in the handshake states (3 and 6), not
    only CONNECTED; CCS after the keys is a green control on both paths;
  * with the REU body sink on (UCI builds), an abort still finalizes the
    partial body (``http_body_finish``);
  * ``tls_connect`` drops an earlier connection's unread ring bytes and
    record-reader state (``tls_rx_reset``), so stale ciphertext is not read
    as the next ServerHello. Driven through the real ``tls_connect`` with
    key generation / ClientHello / the ServerHello parser stubbed, and the
    new server's bytes becoming visible only on the first poll.

Menu wait: ``C64_INIT_WAIT`` seconds (default 120; a comb image's boot
precompute needs ~135 s in VICE).

HOW IT DRIVES THE C64
---------------------
No network, no listener.  Real TLS 1.3 records (ChaCha20-Poly1305, sealed on
the host with ``cryptography`` under a random key/IV that the suite also
writes into the C64's key slots) are placed in the real TCP receive ring
(``tcp_recv_buf`` / ``tcp_recv_head`` / ``tcp_recv_tail``), so the path under
test is the shipped one end to end: ``net_recv_byte`` -> ``tls_recv_record``
-> ``tls_record_decrypt`` -> ``tls_recv`` / ``tls_recv_encrypted`` ->
``http_recv_body``.  Only ``net_poll`` is replaced, by a stub that counts its
calls in a 24-bit counter and returns.

That counter is the discriminator.  An unfixed build returns C=1 too — it
just gets there after 65,536 more idle ticks (131,000+ polls here; seconds
under warp with ``net_poll`` stubbed, ~87 min on hardware).  A carry check
alone would pass it.  So every negative case asserts:

  * C=1,
  * ``tls_state`` = $FF, ``tls_last_state`` = the state that was live,
    ``tls_recv_sub_progress`` = $0B,
  * at most a handful of polls (a fixed build polls 1-2 times, then stops),
  * ``tls_read_seq`` did not advance past the last good record.

The red run is bounded by the unfixed code's own tick budget, and each JSR
additionally by a harness timeout that is scored FAIL, never a hang.

Controls, green before AND after the fix:
  * a VALID record decrypts and parses (C=0, HTTP 200, read_seq advances) —
    proves the key/nonce plumbing, so a failing tag in the other cases is
    the corruption and not a mis-set key;
  * ``tls_connect``'s error exit on a non-ERROR state still records it.

Backend-agnostic: run it against an ip65 or a BACKEND=uci build.  The
handshake case enters ``tls_recv_encrypted`` directly, calling
``tls_deframe_init`` first when the build has the streaming deframer.

Usage:
    C64_SKIP_BUILD=1 python3 tools/test_aead_fail_closed.py
"""

import os
import secrets
import subprocess
import sys

from c64_test_harness import (
    Labels, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)
from _vice_helpers import default_vice_config
from _skip_policy import cannot_run, verdict

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:  # handled as an involuntary skip in main()/run_tests()
    ChaCha20Poly1305 = None

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

# Present on BOTH an unfixed and a fixed build: requiring a label only the
# fix introduces would make the red run fail for the wrong reason.
REQUIRED_LABELS = [
    "http_recv_body",
    "tls_record_recv_and_decrypt",
    "net_poll",
    "tls_recv_encrypted",
    "tls_connect",
    "tls_send",
    "tls_state",
    "tls_last_state",
    "tls_recv_sub_progress",
    "tls_recv_state",
    "tls_recv_count",
    "tls_read_seq",
    "tls_app_read_key",
    "tls_app_read_iv",
    "tls_hs_read_key",
    "tls_hs_read_iv",
    "tcp_recv_buf",
    "tcp_recv_head",
    "tcp_recv_tail",
    "tcp_recv_overflow",
    "http_status",
    "http_parse_state",
    "http_body_total",
    "http_body_sink",
    "http_cl_valid",
    "http_chunked",
    "http_resp_len",
    "http_resp_buf",
    "http_sink_flushed",
    "tls_rec_type",
    "tls_rec_len",
    "tls_enc_aead_len",
    "tls_recv_progress",
    "drbg_fill_bytes",
    "tls_ecdh_generate_keypair",
    "tls_send_client_hello",
    "tls_parse_server_hello",
]

# src/constants.inc
TLS_STATE_SERVER_HELLO = 2
TLS_STATE_ENCRYPTED_EXT = 3
TLS_STATE_CERTIFICATE = 4
TLS_STATE_CERT_VERIFY = 5
TLS_STATE_FINISHED = 6
TLS_STATE_CONNECTED = 7
TLS_STATE_ERROR = 0xFF
TLS_CT_CHANGE_CIPHER = 20
TLS_CT_HANDSHAKE = 22
TLS_CT_APPLICATION = 23
TLS_CT_ALERT = 21
TCP_RECV_MASK = 0x0FFF

SUB_PROGRESS_AUTH_FAIL = 0x0B
SUB_PROGRESS_FRAME_FAIL = 0x0C

# A fixed build polls once in http_recv_body and once in tls_recv before
# the abort (twice), or once in tls_recv_encrypted. An unfixed build polls
# ~131,000 times. Anything under this is "stopped at once".
MAX_POLLS_AFTER_FAIL = 8

# --- Scratch (cassette buffer; see test_body_truncation.py for the map) ----
# $0334 harness jsr trampoline, $0339 run_all_tests safety loop.
STUB_ADDR = 0x0380        # 14 B  net_poll replacement (24-bit counter)
DRIVER_ADDR = 0x03A0      # <=16 B
LATCH_ADDR = 0x03B0
COUNTER_ADDR = 0x03B4     # 3 B

POISON = 0xA5
JSR_TIMEOUT = 180.0


def _lohi(addr: int) -> tuple[int, int]:
    return addr & 0xFF, (addr >> 8) & 0xFF


# ---------------------------------------------------------------------------
# Host-side TLS 1.3 record sealing (RFC 8446 §5.2/§5.3)
# ---------------------------------------------------------------------------

def seal(key: bytes, iv: bytes, seq: int, inner_type: int,
         plaintext: bytes) -> bytes:
    """One TLSCiphertext: header || AEAD(plaintext || inner_type)."""
    seq_be = seq.to_bytes(8, "big")
    nonce = iv[:4] + bytes(a ^ b for a, b in zip(iv[4:], seq_be))
    length = len(plaintext) + 1 + 16
    header = bytes([0x17, 0x03, 0x03, length >> 8, length & 0xFF])
    return header + ChaCha20Poly1305(key).encrypt(
        nonce, plaintext + bytes([inner_type]), header)


def flip_tag_bit(record: bytes) -> bytes:
    """Flip one bit in the last byte of the Poly1305 tag."""
    return record[:-1] + bytes([record[-1] ^ 0x01])


# ---------------------------------------------------------------------------
# 6502 plumbing
# ---------------------------------------------------------------------------

def build_poll_counter() -> bytes:
    """net_poll replacement: 24-bit INC of COUNTER_ADDR, RTS."""
    lo, hi = _lohi(COUNTER_ADDR)
    lo1, hi1 = _lohi(COUNTER_ADDR + 1)
    lo2, hi2 = _lohi(COUNTER_ADDR + 2)
    stub = bytes([
        0xEE, lo, hi,       # 0  INC cnt
        0xD0, 0x08,         # 3  BNE -> 13
        0xEE, lo1, hi1,     # 5  INC cnt+1
        0xD0, 0x03,         # 8  BNE -> 13
        0xEE, lo2, hi2,     # 10 INC cnt+2
        0x60,               # 13 RTS
    ])
    assert len(stub) == 14
    return stub


def build_driver(target: int, pre: int | None = None) -> bytes:
    """[JSR pre] / JSR target / latch the carry into LATCH_ADDR / RTS."""
    r_lo, r_hi = _lohi(LATCH_ADDR)
    code = b""
    if pre is not None:
        code += bytes([0x20, *_lohi(pre)])
    code += bytes([
        0x20, *_lohi(target),
        0xA9, 0x00,         # LDA #0
        0x2A,               # ROL A   (carry -> bit 0)
        0x8D, r_lo, r_hi,   # STA latch
        0x60,
    ])
    assert len(code) <= 16
    return code


class Patcher:
    """Write patches, remember the originals, put them all back."""

    def __init__(self, transport):
        self.transport = transport
        self.saved = []

    def patch(self, addr: int, data: bytes, what: str) -> None:
        self.saved.append((addr, read_bytes(self.transport, addr, len(data))))
        write_bytes(self.transport, addr, data)
        back = read_bytes(self.transport, addr, len(data))
        if back != data:
            raise RuntimeError(
                f"{what}: readback mismatch at ${addr:04X} — wrote "
                f"{data.hex()}, read {back.hex()}")

    def restore(self) -> None:
        for addr, original in reversed(self.saved):
            write_bytes(self.transport, addr, original)
        self.saved.clear()


def assert_shadow_ram_readable(transport, labels) -> None:
    """FATAL unless reads under the BASIC ROM shadow return RAM.

    tls_state, tls_last_state, tls_read_seq and the http_* state all live at
    $A000-$BFFF. A ROM read there would make every assertion below a ROM
    byte that happens to look like a verdict.
    """
    for name in ("tls_state", "tls_read_seq", "http_body_total"):
        addr = labels[name]
        original = read_bytes(transport, addr, 1)
        for probe in (0x5A, 0xA5):
            write_bytes(transport, addr, bytes([probe]))
            got = read_bytes(transport, addr, 1)[0]
            if got != probe:
                raise RuntimeError(
                    f"shadow RAM not readable at {name} (${addr:04X}): wrote "
                    f"${probe:02X}, read ${got:02X}; inconclusive")
        write_bytes(transport, addr, original)


def run_receive(transport, labels, *, stream: bytes, state: int,
                keys: tuple[str, str], key: bytes, iv: bytes,
                target: str, pre: str | None = None,
                extra: tuple = (), reads: tuple = ()) -> dict:
    """Put *stream* in the TCP ring, set the TLS read context, JSR *target*.

    *extra* is ((label, bytes), ...) patched after the defaults (so it can
    override them); *reads* is ((label, length), ...) read back into the
    result as raw bytes. Returns what the fail-closed assertions need.
    Everything written is restored afterwards.
    """
    key_label, iv_label = keys
    if len(stream) > TCP_RECV_MASK:
        raise RuntimeError("stream larger than the TCP ring")
    p = Patcher(transport)
    try:
        p.patch(STUB_ADDR, build_poll_counter(), "net_poll counter stub")
        p.patch(labels["net_poll"], bytes([0x4C, *_lohi(STUB_ADDR)]),
                "net_poll JMP")
        p.patch(DRIVER_ADDR, build_driver(
            labels[target], labels[pre] if pre else None), "driver")
        p.patch(LATCH_ADDR, bytes([POISON]), "carry latch")
        p.patch(COUNTER_ADDR, bytes(3), "poll counter")

        # TLS read context: key, IV, sequence 0, state.
        p.patch(labels[key_label], key, key_label)
        p.patch(labels[iv_label], iv, iv_label)
        p.patch(labels["tls_read_seq"], bytes(8), "tls_read_seq")
        p.patch(labels["tls_state"], bytes([state]), "tls_state")
        p.patch(labels["tls_last_state"], bytes([POISON]), "tls_last_state")
        p.patch(labels["tls_recv_sub_progress"], bytes([0]), "sub_progress")
        # Record reader at a record boundary.
        p.patch(labels["tls_recv_state"], bytes([0]), "tls_recv_state")
        p.patch(labels["tls_recv_count"], bytes(2), "tls_recv_count")

        # The ring: stream at offset 0, head = 0, tail = len.
        p.patch(labels["tcp_recv_buf"], stream, "tcp_recv_buf")
        p.patch(labels["tcp_recv_head"], bytes(2), "tcp_recv_head")
        p.patch(labels["tcp_recv_tail"],
                bytes([len(stream) & 0xFF, len(stream) >> 8]), "tcp_recv_tail")
        p.patch(labels["tcp_recv_overflow"], bytes([0]), "tcp_recv_overflow")

        # http state: sink off, framing predicates cleared (see
        # test_body_truncation.py for why predicates are zeroed, not
        # poisoned); outputs poisoned.
        p.patch(labels["http_body_sink"], bytes([0]), "sink off")
        p.patch(labels["http_cl_valid"], bytes([0]), "cl_valid")
        p.patch(labels["http_chunked"], bytes([0]), "chunked")
        p.patch(labels["http_status"], bytes([POISON, POISON]), "status")
        p.patch(labels["http_body_total"], bytes([POISON] * 3), "body_total")
        for name, data in extra:
            p.patch(labels[name], data, name)

        timed_out = False
        try:
            jsr(transport, DRIVER_ADDR, timeout=JSR_TIMEOUT,
                recover_on_timeout=True)
        except Exception as e:  # noqa: BLE001 — a hang is a FAIL, not a crash
            timed_out = True
            print(f"        JSR did not return within {JSR_TIMEOUT:.0f} s: {e}")

        c = read_bytes(transport, COUNTER_ADDR, 3)
        st = read_bytes(transport, labels["http_status"], 2)
        bt = read_bytes(transport, labels["http_body_total"], 3)
        head = read_bytes(transport, labels["tcp_recv_head"], 2)
        return {
            "timed_out": timed_out,
            "carry": read_bytes(transport, LATCH_ADDR, 1)[0],
            "polls": c[0] | (c[1] << 8) | (c[2] << 16),
            "tls_state": read_bytes(transport, labels["tls_state"], 1)[0],
            "last_state": read_bytes(transport, labels["tls_last_state"], 1)[0],
            "sub_progress": read_bytes(
                transport, labels["tls_recv_sub_progress"], 1)[0],
            "read_seq": int.from_bytes(
                read_bytes(transport, labels["tls_read_seq"], 8), "big"),
            "status": st[0] | (st[1] << 8),
            "body_total": bt[0] | (bt[1] << 8) | (bt[2] << 16),
            "ring_head": head[0] | (head[1] << 8),
            **{name: bytes(read_bytes(transport, labels[name], n))
               for name, n in reads},
        }
    finally:
        p.restore()


def find_connect_error_exit(labels) -> tuple[int, bool]:
    """Address of tls_connect's `@error` exit, and whether it is the fixed form.

    Scanned out of the PRG between tls_connect and tls_send (the next
    routine), by its opcode shape, so it follows the code:

        unfixed:  LDA tls_state / STA tls_last_state / ...
        fixed:    LDA tls_state / BMI +8 / STA tls_last_state / ...

    Exactly one match is required; zero or several is FATAL, not a pass.
    """
    with open(PRG_PATH, "rb") as fh:
        prg = fh.read()
    load = prg[0] | (prg[1] << 8)
    img = prg[2:]
    s_lo, s_hi = _lohi(labels["tls_state"])
    l_lo, l_hi = _lohi(labels["tls_last_state"])
    lo, hi = labels["tls_connect"] - load, labels["tls_send"] - load
    unfixed = bytes([0xAD, s_lo, s_hi, 0x8D, l_lo, l_hi])
    fixed = bytes([0xAD, s_lo, s_hi, 0x30, 0x08, 0x8D, l_lo, l_hi])
    hits = []
    for i in range(lo, hi):
        if img[i:i + len(fixed)] == fixed:
            hits.append((load + i, True))
        elif img[i:i + len(unfixed)] == unfixed:
            hits.append((load + i, False))
    if len(hits) != 1:
        raise RuntimeError(
            f"expected exactly one tls_connect error exit in "
            f"${labels['tls_connect']:04X}-${labels['tls_send']:04X}, found "
            f"{len(hits)}: " + ", ".join(f"${a:04X}" for a, _ in hits))
    return hits[0]


def build_tail_setter(labels, tail: int) -> bytes:
    """net_poll replacement for the connect cases: the "server's reply"
    becomes visible on the first poll (tail := *tail*, idempotent), plus
    the usual 24-bit call counter."""
    t_lo, t_hi = _lohi(labels["tcp_recv_tail"])
    t1_lo, t1_hi = _lohi(labels["tcp_recv_tail"] + 1)
    return bytes([
        0xA9, tail & 0xFF, 0x8D, t_lo, t_hi,     # LDA #<tail / STA tail
        0xA9, tail >> 8, 0x8D, t1_lo, t1_hi,     # LDA #>tail / STA tail+1
    ]) + build_poll_counter()


def run_connect_stale(transport, labels, *, stale: bytes, server: bytes,
                      reader: tuple = (0, 0, 0)) -> dict:
    """Run tls_connect with a previous connection's leftovers in place.

    *stale* is unread ring content from the earlier connection and
    *reader* = (tls_recv_state, tls_recv_count, tls_rec_len) the record
    reader it left behind. *server* (a plaintext ServerHello record) sits
    after it in the ring but only becomes visible — tail moves past it — on
    the first net_poll, which tls_connect reaches only after ClientHello,
    as on the wire (TLS 1.3 is client-first). Key generation and the
    ClientHello send are stubbed; tls_parse_server_hello is stubbed to SEC,
    so the run ends in tls_connect's error exit right after the first
    record is handed to ServerHello processing, and tls_recv_progress /
    tls_rec_type say which record that was.
    """
    n1, n2 = len(stale), len(server)
    p = Patcher(transport)
    try:
        p.patch(STUB_ADDR, build_tail_setter(labels, n1 + n2),
                "tail-setter net_poll")
        p.patch(labels["net_poll"], bytes([0x4C, *_lohi(STUB_ADDR)]),
                "net_poll JMP")
        p.patch(labels["drbg_fill_bytes"], bytes([0x60]), "drbg RTS")
        p.patch(labels["tls_ecdh_generate_keypair"], bytes([0x60]),
                "keypair RTS")
        p.patch(labels["tls_send_client_hello"], bytes([0x18, 0x60]),
                "ClientHello CLC/RTS")
        p.patch(labels["tls_parse_server_hello"], bytes([0x38, 0x60]),
                "parse SEC/RTS")
        p.patch(DRIVER_ADDR, build_driver(labels["tls_connect"]), "driver")
        p.patch(LATCH_ADDR, bytes([POISON]), "carry latch")
        p.patch(COUNTER_ADDR, bytes(3), "poll counter")
        p.patch(labels["tls_recv_progress"], bytes([0]), "tls_recv_progress")
        p.patch(labels["tls_rec_type"], bytes([0]), "tls_rec_type")
        rs, rc, rl = reader
        p.patch(labels["tls_recv_state"], bytes([rs]), "tls_recv_state")
        p.patch(labels["tls_recv_count"], bytes([rc & 0xFF, rc >> 8]),
                "tls_recv_count")
        p.patch(labels["tls_rec_len"], bytes([rl & 0xFF, rl >> 8]),
                "tls_rec_len")
        p.patch(labels["tcp_recv_buf"], stale + server, "tcp_recv_buf")
        p.patch(labels["tcp_recv_head"], bytes(2), "tcp_recv_head")
        p.patch(labels["tcp_recv_tail"], bytes([n1 & 0xFF, n1 >> 8]),
                "tcp_recv_tail")
        timed_out = False
        try:
            jsr(transport, DRIVER_ADDR, timeout=JSR_TIMEOUT,
                recover_on_timeout=True)
        except Exception as e:  # noqa: BLE001
            timed_out = True
            print(f"        JSR did not return within {JSR_TIMEOUT:.0f} s: {e}")
        c = read_bytes(transport, COUNTER_ADDR, 3)
        return {
            "timed_out": timed_out,
            "carry": read_bytes(transport, LATCH_ADDR, 1)[0],
            "polls": c[0] | (c[1] << 8) | (c[2] << 16),
            "progress": read_bytes(transport, labels["tls_recv_progress"], 1)[0],
            "rec_type": read_bytes(transport, labels["tls_rec_type"], 1)[0],
            "last_state": read_bytes(transport, labels["tls_last_state"], 1)[0],
        }
    finally:
        p.restore()


def run_connect_error_exit(transport, labels, entry_state: int,
                           recorded: int) -> dict:
    """JSR tls_connect's error exit with tls_state/tls_last_state preset."""
    addr, is_fixed = find_connect_error_exit(labels)
    p = Patcher(transport)
    try:
        p.patch(DRIVER_ADDR, build_driver(addr), "driver")
        p.patch(LATCH_ADDR, bytes([POISON]), "carry latch")
        p.patch(labels["tls_state"], bytes([entry_state]), "tls_state")
        p.patch(labels["tls_last_state"], bytes([recorded]), "tls_last_state")
        jsr(transport, DRIVER_ADDR, timeout=30.0)
        return {
            "addr": addr, "fixed_form": is_fixed,
            "carry": read_bytes(transport, LATCH_ADDR, 1)[0],
            "tls_state": read_bytes(transport, labels["tls_state"], 1)[0],
            "last_state": read_bytes(transport, labels["tls_last_state"], 1)[0],
        }
    finally:
        p.restore()


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

def _report(name, why, r, checks) -> bool:
    ok = all(good for _, good in checks)
    print(f"\n  [{'+' if ok else '-'}] {name}")
    print(f"        {why}")
    print("        " + " ".join(f"{k}={v:#x}" if isinstance(v, int)
                                and not isinstance(v, bool) else f"{k}={v}"
                                for k, v in r.items()))
    for label, good in checks:
        if not good or VERBOSE:
            print(f"        {'ok  ' if good else 'FAIL'} {label}")
    return ok


def _fail_closed_checks(r, *, live_state: int, seq_after: int,
                        sub: int = SUB_PROGRESS_AUTH_FAIL):
    return [
        ("returned (no harness timeout)", not r["timed_out"]),
        ("carry C=1", r["carry"] == 1),
        (f"tls_state = ERROR ($FF)", r["tls_state"] == TLS_STATE_ERROR),
        (f"tls_last_state = ${live_state:02X} (the state the failure hit)",
         r["last_state"] == live_state),
        (f"tls_recv_sub_progress = ${sub:02X}", r["sub_progress"] == sub),
        (f"stopped polling at once (polls <= {MAX_POLLS_AFTER_FAIL})",
         r["polls"] <= MAX_POLLS_AFTER_FAIL),
        (f"tls_read_seq = {seq_after} (failed record not counted)",
         r["read_seq"] == seq_after),
    ]


def run_tests(transport, labels) -> tuple[int, int]:
    if ChaCha20Poly1305 is None:
        # Involuntary: the runner counts a raise as a failure, never a pass.
        raise RuntimeError(
            "python 'cryptography' package missing — cannot seal the TLS "
            "records this suite feeds; nothing was verified")

    passed = failed = 0
    assert_shadow_ram_readable(transport, labels)
    print("  shadow RAM readable (positive control OK)")

    app_key, app_iv = secrets.token_bytes(32), secrets.token_bytes(12)
    hs_key, hs_iv = secrets.token_bytes(32), secrets.token_bytes(12)
    app_keys = ("tls_app_read_key", "tls_app_read_iv")
    hs_keys = ("tls_hs_read_key", "tls_hs_read_iv")

    full = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO"
    good = seal(app_key, app_iv, 0, TLS_CT_APPLICATION, full)

    def tally(ok):
        nonlocal passed, failed
        if ok:
            passed += 1
        else:
            failed += 1

    # --- A: control — a valid record decrypts and completes -------------
    r = run_receive(transport, labels, stream=good, state=TLS_STATE_CONNECTED,
                    keys=app_keys, key=app_key, iv=app_iv,
                    target="http_recv_body")
    tally(_report(
        "control: valid application record (green before AND after)",
        "proves the key/IV/seq plumbing: a failing tag below is the "
        "corruption, not a mis-set key",
        r, [
            ("returned (no harness timeout)", not r["timed_out"]),
            ("carry C=0 (complete)", r["carry"] == 0),
            ("HTTP 200 parsed", r["status"] == 200),
            ("body consumed == 5", r["body_total"] == 5),
            ("tls_read_seq advanced to 1", r["read_seq"] == 1),
            ("tls_state still CONNECTED", r["tls_state"] == TLS_STATE_CONNECTED),
            ("ring fully consumed", r["ring_head"] == len(good)),
        ]))

    # --- B: application record with a corrupted tag ----------------------
    r = run_receive(transport, labels, stream=flip_tag_bit(good),
                    state=TLS_STATE_CONNECTED, keys=app_keys, key=app_key,
                    iv=app_iv, target="http_recv_body")
    tally(_report(
        "application record, one tag bit flipped: http_recv_body fails closed",
        "was: counted as an idle tick, 65,536 of them (~87 min on UCI) with "
        "tls_state still CONNECTED",
        r, _fail_closed_checks(r, live_state=TLS_STATE_CONNECTED, seq_after=0)
        + [("http_status untouched (nothing parsed)",
            r["status"] == (POISON << 8) | POISON)]))

    # --- C: one byte dropped from the stream (the #230(b) shape) ---------
    head = b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n" + b"A" * 10
    rest = b"B" * 30
    r1 = seal(app_key, app_iv, 0, TLS_CT_APPLICATION, head)
    r2 = seal(app_key, app_iv, 1, TLS_CT_APPLICATION, rest)
    r3 = seal(app_key, app_iv, 2, TLS_CT_ALERT, bytes([1, 0]))  # close_notify
    cut = 5 + 12                       # inside record 2's ciphertext
    stream = r1 + r2[:cut] + r2[cut + 1:] + r3
    r = run_receive(transport, labels, stream=stream,
                    state=TLS_STATE_CONNECTED, keys=app_keys, key=app_key,
                    iv=app_iv, target="http_recv_body")
    tally(_report(
        "one byte lost mid-stream: record 2 fails its tag, fetch aborts",
        "record 2 absorbs the first byte of the close_notify behind it; was: "
        "every later record failed silently and the fetch waited out the "
        "budget",
        r, _fail_closed_checks(r, live_state=TLS_STATE_CONNECTED, seq_after=1)
        + [("record 1 parsed: HTTP 200", r["status"] == 200),
           ("record 1 body counted (10 B), nothing after",
            r["body_total"] == 10)]))

    # --- D: handshake path — tls_recv_encrypted ---------------------------
    ee = bytes([8, 0, 0, 2, 0, 0])     # EncryptedExtensions, empty list
    bad_hs = flip_tag_bit(seal(hs_key, hs_iv, 0, TLS_CT_HANDSHAKE, ee))
    pre = "tls_deframe_init" if labels.address("tls_deframe_init") else None
    r = run_receive(transport, labels, stream=bad_hs,
                    state=TLS_STATE_ENCRYPTED_EXT, keys=hs_keys, key=hs_key,
                    iv=hs_iv, target="tls_recv_encrypted", pre=pre)
    tally(_report(
        "handshake record, tag bit flipped: tls_recv_encrypted fails closed"
        + (" (streaming deframer)" if pre else " (ip65 per-record arm)"),
        "was: the same conflation, retried 65,536 times before a generic "
        "timeout",
        r, _fail_closed_checks(r, live_state=TLS_STATE_ENCRYPTED_EXT,
                               seq_after=0)))

    # --- F: malformed header once records are encrypted ------------------
    r1 = seal(app_key, app_iv, 0, TLS_CT_APPLICATION, head)
    bad_hdr = bytes([0x17, 0x03, 0x01, 0x00, 0x13]) + secrets.token_bytes(19)
    r = run_receive(transport, labels, stream=r1 + bad_hdr + r3,
                    state=TLS_STATE_CONNECTED, keys=app_keys, key=app_key,
                    iv=app_iv, target="http_recv_body")
    tally(_report(
        "bad record header (version 0x0301) after keys: fetch aborts",
        "was: reset the reader and resynced a byte at a time through the "
        "ciphertext, silently",
        r, _fail_closed_checks(r, live_state=TLS_STATE_CONNECTED, seq_after=1,
                               sub=SUB_PROGRESS_FRAME_FAIL)
        + [("record 1 parsed: HTTP 200", r["status"] == 200)]))

    # --- G: close_notify before Content-Length is satisfied -------------
    close1 = seal(app_key, app_iv, 1, TLS_CT_ALERT, bytes([1, 0]))
    r = run_receive(transport, labels, stream=r1 + close1,
                    state=TLS_STATE_CONNECTED, keys=app_keys, key=app_key,
                    iv=app_iv, target="http_recv_body")
    tally(_report(
        "close_notify with the body 30 B short of Content-Length",
        "an orderly close, not an integrity error: the framing verdict "
        "fires at once (C=1, short), tls_state is NOT latched to ERROR",
        r, [
            ("returned (no harness timeout)", not r["timed_out"]),
            ("carry C=1 (short body)", r["carry"] == 1),
            ("tls_state still CONNECTED", r["tls_state"] == TLS_STATE_CONNECTED),
            (f"verdict at once (polls <= {MAX_POLLS_AFTER_FAIL})",
             r["polls"] <= MAX_POLLS_AFTER_FAIL),
            ("both records authenticated (tls_read_seq = 2)",
             r["read_seq"] == 2),
            ("body consumed == 10", r["body_total"] == 10),
        ]))

    # --- H: close_notify ending an unframed (Connection: close) body ----
    unframed = seal(app_key, app_iv, 0, TLS_CT_APPLICATION,
                    b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello")
    r = run_receive(transport, labels, stream=unframed + close1,
                    state=TLS_STATE_CONNECTED, keys=app_keys, key=app_key,
                    iv=app_iv, target="http_recv_body")
    tally(_report(
        "close_notify ending an unframed body: complete, at once",
        "close_notify is how an unframed body ends; was: C=0 only after "
        "the whole idle budget",
        r, [
            ("returned (no harness timeout)", not r["timed_out"]),
            ("carry C=0 (complete)", r["carry"] == 0),
            ("HTTP 200 parsed", r["status"] == 200),
            ("body consumed == 5", r["body_total"] == 5),
            ("tls_state still CONNECTED", r["tls_state"] == TLS_STATE_CONNECTED),
            (f"at once (polls <= {MAX_POLLS_AFTER_FAIL})",
             r["polls"] <= MAX_POLLS_AFTER_FAIL),
        ]))

    # --- I: control — a bad byte BEFORE the keys still just resyncs -------
    sh = bytes([0x16, 0x03, 0x03, 0x00, 0x04, 2, 0, 0, 0])
    r = run_receive(transport, labels, stream=b"\x00" + sh,
                    state=TLS_STATE_SERVER_HELLO, keys=app_keys, key=app_key,
                    iv=app_iv, target="tls_record_recv_and_decrypt")
    tally(_report(
        "control: garbage byte in the plaintext (ServerHello) phase",
        "unchanged by the fix: skipped and resynced, not fatal (green both "
        "ways)",
        r, [
            ("returned (no harness timeout)", not r["timed_out"]),
            ("carry C=1 (byte skipped)", r["carry"] == 1),
            ("tls_state still SERVER_HELLO",
             r["tls_state"] == TLS_STATE_SERVER_HELLO),
            ("tls_last_state untouched", r["last_state"] == POISON),
            ("exactly one byte consumed", r["ring_head"] == 1),
        ]))

    # --- J: bad header in the handshake states (3..6) --------------------
    for st in (TLS_STATE_ENCRYPTED_EXT, TLS_STATE_FINISHED):
        r = run_receive(transport, labels, stream=bad_hdr, state=st,
                        keys=hs_keys, key=hs_key, iv=hs_iv,
                        target="tls_recv_encrypted", pre=pre)
        tally(_report(
            f"bad record header during the handshake (tls_state={st}): fatal",
            "the frame check applies from EncryptedExtensions on, not only "
            "once CONNECTED",
            r, _fail_closed_checks(r, live_state=st, seq_after=0,
                                   sub=SUB_PROGRESS_FRAME_FAIL)))

    # --- K: records too short to hold a tag (tls_rec_len - 16 underflow) --
    # tls_record_decrypt's first act is tls_enc_aead_len := tls_rec_len - 16
    # (unchecked). Poisoned beforehand, it witnesses whether the decrypt was
    # entered at all: $FFF5 for a 5-byte record is the underflow itself.
    aead_len_witness = dict(extra=(("tls_enc_aead_len", bytes([POISON] * 2)),),
                            reads=(("tls_enc_aead_len", 2),))

    def not_decrypted(r):
        return ("tls_record_decrypt never entered (tls_enc_aead_len still "
                "poisoned; $FFF5 would be the underflow)",
                r["tls_enc_aead_len"] == bytes([POISON] * 2))

    short_app = bytes([0x17, 3, 3, 0, 5]) + secrets.token_bytes(5)
    r = run_receive(transport, labels, stream=short_app,
                    state=TLS_STATE_CONNECTED, keys=app_keys, key=app_key,
                    iv=app_iv, target="http_recv_body", **aead_len_witness)
    tally(_report(
        "5-byte record after the keys: rejected before the decrypt",
        "was: tls_rec_len-16 underflowed and Poly1305 swept ~64 KB, "
        "$D000-$DFFF I/O included, then the tag failed",
        r, _fail_closed_checks(r, live_state=TLS_STATE_CONNECTED, seq_after=0,
                               sub=SUB_PROGRESS_FRAME_FAIL)
        + [not_decrypted(r)]))
    r = run_receive(transport, labels, stream=short_app,
                    state=TLS_STATE_CERTIFICATE, keys=hs_keys, key=hs_key,
                    iv=hs_iv, target="tls_recv_encrypted", pre=pre,
                    **aead_len_witness)
    tally(_report(
        "5-byte record during the handshake: same guard, same verdict",
        "tls_recv_encrypted reaches the same tls_record_decrypt",
        r, _fail_closed_checks(r, live_state=TLS_STATE_CERTIFICATE,
                               seq_after=0, sub=SUB_PROGRESS_FRAME_FAIL)
        + [not_decrypted(r)]))
    r = run_receive(transport, labels,
                    stream=bytes([0x17, 3, 3, 0, 16]) + secrets.token_bytes(16),
                    state=TLS_STATE_CONNECTED, keys=app_keys, key=app_key,
                    iv=app_iv, target="tls_record_recv_and_decrypt",
                    **aead_len_witness)
    tally(_report(
        "16-byte record (a tag and no inner type): rejected",
        "boundary: ciphertext length 0 would index the inner type at -1",
        r, [("carry C=1", r["carry"] == 1),
            ("tls_state = ERROR", r["tls_state"] == TLS_STATE_ERROR),
            (f"sub_progress = ${SUB_PROGRESS_FRAME_FAIL:02X}",
             r["sub_progress"] == SUB_PROGRESS_FRAME_FAIL),
            not_decrypted(r)]))
    empty = seal(app_key, app_iv, 0, TLS_CT_APPLICATION, b"")
    assert len(empty) == 5 + 17
    r = run_receive(transport, labels, stream=empty,
                    state=TLS_STATE_CONNECTED, keys=app_keys, key=app_key,
                    iv=app_iv, target="tls_record_recv_and_decrypt")
    tally(_report(
        "control: 17-byte record (empty application data) still accepted",
        "boundary, green both ways: the smallest legal record",
        r, [("carry C=0", r["carry"] == 0),
            ("tls_state still CONNECTED", r["tls_state"] == TLS_STATE_CONNECTED),
            ("tls_read_seq = 1", r["read_seq"] == 1)]))

    # --- L: ChangeCipherSpec after the keys is still skipped -------------
    ccs = bytes([0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
    good_ee = seal(hs_key, hs_iv, 0, TLS_CT_HANDSHAKE, ee)
    r = run_receive(transport, labels, stream=ccs + good_ee,
                    state=TLS_STATE_ENCRYPTED_EXT, keys=hs_keys, key=hs_key,
                    iv=hs_iv, target="tls_recv_encrypted", pre=pre)
    tally(_report(
        "control: CCS then a valid EncryptedExtensions (green both ways)",
        "RFC 8446 middlebox CCS: 1 byte, unencrypted - neither the frame "
        "check nor the length guard may reject it",
        r, [("returned (no harness timeout)", not r["timed_out"]),
            ("carry C=0", r["carry"] == 0),
            ("tls_state still ENCRYPTED_EXT",
             r["tls_state"] == TLS_STATE_ENCRYPTED_EXT),
            ("tls_read_seq = 1", r["read_seq"] == 1)]))
    r = run_receive(transport, labels, stream=ccs + good,
                    state=TLS_STATE_CONNECTED, keys=app_keys, key=app_key,
                    iv=app_iv, target="http_recv_body")
    tally(_report(
        "control: CCS then application data (green both ways)",
        "same, on the application path",
        r, [("carry C=0", r["carry"] == 0),
            ("HTTP 200 parsed", r["status"] == 200),
            ("tls_state still CONNECTED", r["tls_state"] == TLS_STATE_CONNECTED)]))

    # --- M: a fatal alert (not close_notify) -----------------------------
    fatal = seal(app_key, app_iv, 1, TLS_CT_ALERT, bytes([2, 50]))  # decode_error
    r = run_receive(transport, labels, stream=r1 + fatal,
                    state=TLS_STATE_CONNECTED, keys=app_keys, key=app_key,
                    iv=app_iv, target="http_recv_body")
    tally(_report(
        "fatal alert (decode_error) after part of the body: C=1 at once",
        "only close_notify is an orderly close",
        r, [("returned (no harness timeout)", not r["timed_out"]),
            ("carry C=1", r["carry"] == 1),
            (f"at once (polls <= {MAX_POLLS_AFTER_FAIL})",
             r["polls"] <= MAX_POLLS_AFTER_FAIL),
            ("both records authenticated (tls_read_seq = 2)",
             r["read_seq"] == 2)]))
    unframed_body = seal(app_key, app_iv, 0, TLS_CT_APPLICATION,
                         b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello")
    r = run_receive(transport, labels, stream=unframed_body + fatal,
                    state=TLS_STATE_CONNECTED, keys=app_keys, key=app_key,
                    iv=app_iv, target="http_recv_body")
    tally(_report(
        "fatal alert ending an unframed body: C=1, not a completed body",
        "a close_notify there is C=0 (case above); decode_error is not",
        r, [("returned (no harness timeout)", not r["timed_out"]),
            ("carry C=1", r["carry"] == 1),
            (f"at once (polls <= {MAX_POLLS_AFTER_FAIL})",
             r["polls"] <= MAX_POLLS_AFTER_FAIL)]))

    # --- N: abort with the REU body sink on (UCI only) -------------------
    if labels.address("sink_reu_setup") is not None:
        r = run_receive(
            transport, labels, stream=r1 + flip_tag_bit(r2),
            state=TLS_STATE_CONNECTED, keys=app_keys, key=app_key, iv=app_iv,
            target="http_recv_body",
            extra=(("http_body_sink", bytes([1])),
                   ("http_reu_body_base", bytes([0, 0, 5])),  # REU bank 5
                   ("http_sink_flushed", bytes([POISON])),
                   ("http_resp_len", bytes([POISON, POISON]))),
            reads=(("http_sink_flushed", 1), ("http_resp_len", 2),
                   ("http_resp_buf", 10)))
        rl = r["http_resp_len"][0] | (r["http_resp_len"][1] << 8)
        tally(_report(
            "abort with the REU sink on: partial body still finalized",
            "the abort path runs http_body_finish, like the verdict: final "
            "blit + first-512 fetch-back",
            r, _fail_closed_checks(r, live_state=TLS_STATE_CONNECTED,
                                   seq_after=1)
            + [("http_sink_flushed = 1", r["http_sink_flushed"] == b"\x01"),
               ("http_resp_len = 10 (min(512, total))", rl == 10),
               ("http_resp_buf = the 10 body bytes, back from the REU",
                r["http_resp_buf"] == b"A" * 10)]))
    else:
        print("\n  [ ] REU-sink abort case: NOT APPLICABLE on this build "
              "(ip65 compiles the sink to a stub) - not counted")

    # --- P: the length guard reads the high byte ------------------------
    rec257 = seal(app_key, app_iv, 0, TLS_CT_APPLICATION, b"z" * 240)
    assert len(rec257) == 5 + 257
    r = run_receive(transport, labels, stream=rec257,
                    state=TLS_STATE_CONNECTED, keys=app_keys, key=app_key,
                    iv=app_iv, target="tls_record_recv_and_decrypt")
    tally(_report(
        "control: 257-byte record (low length byte 1) accepted",
        "the <=16 B guard must test the high byte: 256..272 B records "
        "share a low byte with 0..16",
        r, [("carry C=0", r["carry"] == 0),
            ("tls_state still CONNECTED", r["tls_state"] == TLS_STATE_CONNECTED),
            ("tls_read_seq = 1", r["read_seq"] == 1)]))

    # --- Q: an alert that is not 2 bytes --------------------------------
    # A 0-byte alert leaves tls_rec_buf+1 holding the first tag byte. Pick
    # a key whose tag starts with $00 so a build that reads it as the
    # AlertDescription sees close_notify deterministically (1/256 otherwise).
    for _ in range(4096):
        qk = secrets.token_bytes(32)
        qa = seal(qk, app_iv, 1, TLS_CT_ALERT, b"")
        if qa[6] == 0:
            break
    else:
        raise RuntimeError("no key found with tag[0] == 0 in 4096 tries")
    qb = seal(qk, app_iv, 0, TLS_CT_APPLICATION,
              b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello")
    r = run_receive(transport, labels, stream=qb + qa,
                    state=TLS_STATE_CONNECTED, keys=app_keys, key=qk,
                    iv=app_iv, target="http_recv_body")
    tally(_report(
        "0-byte alert after an unframed body: not a close_notify, C=1",
        "an alert is 2 B; with 0 B the 'description' is a stale tag byte, "
        "here chosen as $00",
        r, [("returned (no harness timeout)", not r["timed_out"]),
            ("carry C=1 (not read as close_notify)", r["carry"] == 1),
            ("both records authenticated (tls_read_seq = 2)",
             r["read_seq"] == 2),
            (f"at once (polls <= {MAX_POLLS_AFTER_FAIL})",
             r["polls"] <= MAX_POLLS_AFTER_FAIL)]))

    # --- O: the next connection after an abort ---------------------------
    sh = bytes([0x16, 0x03, 0x03, 0x00, 0x04, 2, 0, 0, 0])
    residue = seal(app_key, app_iv, 1, TLS_CT_APPLICATION, b"y" * 40)
    r = run_connect_stale(transport, labels, stale=residue, server=sh)
    tally(_report(
        "next tls_connect after an abort: stale ciphertext is not the "
        "ServerHello",
        "was: the aborted connection's unread record came back as the "
        "first record in SERVER_HELLO state, C=0",
        r, [("returned (no harness timeout)", not r["timed_out"]),
            ("the record handed to ServerHello processing is the new "
             "handshake record (type $16)", r["rec_type"] == TLS_CT_HANDSHAKE),
            ("it got as far as the parser (tls_recv_progress = 4)",
             r["progress"] == 4)]))
    r = run_connect_stale(transport, labels, stale=b"", server=sh,
                          reader=(1, 3, 100))
    tally(_report(
        "next tls_connect with the reader left mid-record",
        "a budget-expired fetch can leave tls_recv_state = 1; the new "
        "connection's ServerHello must not be read as that record's payload",
        r, [("returned (no harness timeout)", not r["timed_out"]),
            ("ServerHello record reached the parser (type $16, progress 4)",
             r["rec_type"] == TLS_CT_HANDSHAKE and r["progress"] == 4),
            (f"at once (polls <= {MAX_POLLS_AFTER_FAIL})",
             r["polls"] <= MAX_POLLS_AFTER_FAIL)]))

    # --- E: tls_connect's error exit keeps the record layer's verdict -----
    r = run_connect_error_exit(transport, labels, TLS_STATE_ERROR,
                               TLS_STATE_ENCRYPTED_EXT)
    tally(_report(
        "tls_connect error exit after a record-layer abort",
        "must not overwrite tls_last_state with $FF — the state the tag "
        "failure hit is the diagnostic",
        r, [
            ("carry C=1", r["carry"] == 1),
            ("tls_state = ERROR", r["tls_state"] == TLS_STATE_ERROR),
            ("tls_last_state kept ($03)",
             r["last_state"] == TLS_STATE_ENCRYPTED_EXT),
        ]))

    r = run_connect_error_exit(transport, labels, TLS_STATE_CERT_VERIFY,
                               POISON)
    tally(_report(
        "control: tls_connect error exit from a live state (green both ways)",
        "the ordinary path still records the attempted state and sets ERROR",
        r, [
            ("carry C=1", r["carry"] == 1),
            ("tls_state = ERROR", r["tls_state"] == TLS_STATE_ERROR),
            ("tls_last_state = $05", r["last_state"] == TLS_STATE_CERT_VERIFY),
        ]))

    return passed, failed


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main() -> int:
    global VERBOSE
    os.chdir(PROJECT_ROOT)
    if "--verbose" in sys.argv:
        VERBOSE = True

    if ChaCha20Poly1305 is None:
        return cannot_run(
            "python 'cryptography' package not importable",
            executed=0, total=None,
            certifies="AEAD fail-closed behaviour (#239)")

    if os.environ.get("C64_SKIP_BUILD"):
        print("\n=== Building (skipped: C64_SKIP_BUILD set) ===")
    else:
        print("\n=== Building ===")
        subprocess.run(["make", "clean"], capture_output=True)
        result = subprocess.run(["make"], capture_output=True, text=True)
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

    print("\n=== Labels ===")
    for name in REQUIRED_LABELS:
        print(f"  {name:<24} = ${labels[name]:04X}")

    try:
        menu_wait = float(os.environ.get("C64_INIT_WAIT", "120"))
    except ValueError:
        print(f"FATAL: C64_INIT_WAIT={os.environ['C64_INIT_WAIT']!r} is not "
              f"a number of seconds")
        return 1

    print("\n=== Starting VICE ===")
    config = default_vice_config(prg_path=PRG_PATH, warp=True, ntsc=True,
                                 sound=False)
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"  VICE PID={inst.pid}, port={inst.port}")
        grid = wait_for_text(transport, "Q=QUIT", timeout=menu_wait,
                             verbose=False)
        if grid is None:
            print(f"FATAL: Main menu did not appear within {menu_wait:.0f} s "
                  f"(a comb image's boot precompute needs ~135 s in VICE: "
                  f"set C64_INIT_WAIT)")
            mgr.release(inst)
            return 1
        print("  Main menu ready")

        print("\n=== AEAD tag failure fails closed (issue #239) ===")
        try:
            passed, failed = run_tests(transport, labels)
        finally:
            mgr.release(inst)

    total = passed + failed
    print("\n" + "=" * 60)
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    print(f"\n  [{'+' if failed == 0 else '-'}] AEAD fail-closed: "
          + ("ALL TESTS PASSED" if failed == 0 else f"{failed} FAILED"))
    print("=" * 60)
    return verdict(passed, failed,
                   certifies="AEAD fail-closed decryption (#239)")


if __name__ == "__main__":
    sys.exit(main())
