#!/usr/bin/env python3
"""
Phase 5 LOCAL HTTPS: exercise the real http_get (TLS 1.3) code path through
the UCI backend on a real Ultimate 64 Elite.

Environment variables:
  U64_HOST              — U64E IP address (default 192.168.1.81)
  TURBO_MHZ             — C64 CPU MHz (default 48). TURBO_MHZ=1 runs the test
                          at stock 1 MHz with auto-scaled timeouts; the full
                          handshake + HTTP round-trip takes ~2-3 h wall-clock
                          and has been validated end-to-end on real U64E
                          hardware.
  HTTPS_PORT            — listener port (default 443; falls back to 4433 if
                          the bind fails, e.g. unprivileged)
  SENTINEL_POLL_TIMEOUT — per-test override in seconds for the C64-side
                          sentinel poll (default 600 * _TIMEOUT_SCALE).
  ACCEPT_TIMEOUT        — per-test override in seconds for the server-side
                          accept + handshake slack (default 600 *
                          _TIMEOUT_SCALE).
  DEBUG_CAPTURE         — set to 0 to disable 6510 bus capture (default on).
  KEEP_DEBUG_ON_PASS    — set to 1 to preserve artifacts on PASS runs.
  UCI_DEBUG_DIR         — base directory for run artifacts (default
                          /tmp/uci_https_debug).

Timeouts auto-scale relative to TURBO_MHZ; see env-var docs above.

Debug-stream capture: set DEBUG_CAPTURE=0 in env to disable. Default enabled.
Artifacts land in a per-run timestamped directory under $UCI_DEBUG_DIR
(default /tmp/uci_https_debug/<YYYYMMDD_HHMMSS>/). Each run dir holds:
  summary.txt          — stats + hot PCs + UCI-reg counts
  tail.txt             — last 2000 CPU cycles
  uci_accesses.txt     — every CPU cycle in $DF1B-$DF1F
  trace.bin + .meta.json — packed raw BusCycle trace (4 bytes/cycle)
  server_result.json   — server-side listener state (request, error, ...)
  run_info.txt         — git HEAD, outcome, duration, exit code
The latest 5 run dirs are retained; older ones are pruned on startup.

Flow:
  1. Boot the UCI-built PRG, wait for auto-init (net_init + DHCP).
  2. Start a Python HTTPS server on the dev host's LAN IP with the
     self-signed ECDSA P-256 cert at tools/https_e2e/certs/server.pem.
  3. Quit to BASIC ('Q'), flip to 48 MHz turbo.
  4. DMA-inject a 6502 stub at $4200 that:
       - Banks out BASIC ROM
       - Sets http_host_ptr, http_host_len, http_path_ptr, http_path_len, http_port
       - Calls http_get (the TLS+HTTP code from src/http.s)
       - Writes a sentinel on completion
  5. Trigger with SYS 16896 via keyboard buffer.
  6. Poll sentinel for up to 120 s (handshake is ~13-15 s at 48 MHz).
  7. Assert BOTH sides:
       - C64 side: http_resp_buf holds the complete "HELLO FROM TLS SERVER"
         body (screen RAM is diagnostic only — see _check_c64_result).
       - Server side: the listener completed the handshake, recorded no TLS
         error, and decrypted the GET the C64 was told to send (see
         _check_server_result). Skipped under EXTERNAL_LISTENER=1, which by
         contract has no inline listener.

Offline re-check of an archived run (no hardware):
  ./test_https_local.py --check-artifact <run-dir> [--host IP] [--path P]
re-runs the server-side criteria against that run's server_result.json.
"""
from __future__ import annotations

import base64
import datetime
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

from c64_test_harness.backends.device_lock import DeviceLock, DeviceLockTimeout
from c64_test_harness.backends.ultimate64 import Ultimate64Transport
from c64_test_harness.backends.ultimate64_client import Ultimate64Client
from c64_test_harness.backends.ultimate64_helpers import (
    set_turbo_mhz,
    set_debug_stream_mode,
    runner_health_check,
    Ultimate64RunnerStuckError,
    DEBUG_MODE_6510,
    CAT_U64_SPECIFIC,
    cpu_speed_enum,
)
from c64_test_harness.backends.u64_debug_capture import (
    DebugCapture,
    DEFAULT_DEBUG_PORT,
)
from c64_test_harness.uci_network import enable_uci, disable_uci
from c64_test_harness.keyboard import send_text
from c64_test_harness.labels import Labels

from _memory_policy import (
    build_policy_and_arbiter,
    build_policy_and_arbiter_with_overlay_carveout,
)
from _reu_preflight import ReuPreflightError, preflight_reu


DEBUG_CAPTURE_ENABLED = os.environ.get("DEBUG_CAPTURE", "1") != "0"
UCI_DEBUG_BASE_DIR = Path(
    os.environ.get("UCI_DEBUG_DIR", "/tmp/uci_https_debug")
)
UCI_DEBUG_KEEP = 5
UCI_DEBUG_KEEP_ON_PASS = os.environ.get("KEEP_DEBUG_ON_PASS", "0") != "0"


def _keep_cycle(word: int) -> bool:
    """DebugCapture filter: keep only CPU cycles in regions we care about.

    Keeps a cycle if PHI2=1 (CPU cycle, bit 31 set) AND the 16-bit address
    falls in one of the three interesting ranges:
      - $2000-$3FFF : UCI adapter code/data
      - $6000-$9FFF : crypto + TLS code
      - $DF1B-$DF1F : UCI I/O registers
    """
    if not (word >> 31) & 1:
        return False
    addr = word & 0xFFFF
    return (
        0x2000 <= addr <= 0x3FFF
        or 0x6000 <= addr <= 0x9FFF
        or 0xDF1B <= addr <= 0xDF1F
    )


HOST = os.environ.get("U64_HOST", "192.168.1.81")
REPO_ROOT = Path(__file__).resolve().parents[2]
PRG_PATH = REPO_ROOT / "build" / "c64-https.prg"
LABELS_PATH = REPO_ROOT / "build" / "labels.txt"
CERT_PATH = REPO_ROOT / "tools" / "https_e2e" / "certs" / "server.pem"
KEY_PATH = REPO_ROOT / "tools" / "https_e2e" / "certs" / "server.key"

# The cert/key are gitignored throwaway test material, so a fresh clone has
# none and this script used to die with "cert/key not found" (issue #93).
# They are generated on demand instead — see _ensure_certs_or_fail(), called
# from main() and skipped under EXTERNAL_LISTENER=1, which by contract loads
# no repo certs at all.  CERT_PROFILE is what the P-384 sibling overrides.
CERT_PROFILE = "p256"


def _ensure_certs_or_fail() -> int:
    """Generate the local test cert pair if absent.  0 on success, 2 on failure."""
    global CERT_PATH, KEY_PATH

    if CERT_PATH.is_file() and KEY_PATH.is_file():
        return 0

    https_e2e_dir = str(REPO_ROOT / "tools" / "https_e2e")
    if https_e2e_dir not in sys.path:
        sys.path.insert(0, https_e2e_dir)
    try:
        from ensure_certs import cert_paths, ensure_certs  # noqa: PLC0415
    except ImportError as exc:
        print(f"ERROR: cert/key not found at {CERT_PATH} / {KEY_PATH}, and "
              f"the generator could not be imported ({exc})", file=sys.stderr)
        return 2

    # Only generate into the canonical location.  If someone has pointed
    # CERT_PATH somewhere else, generating the default pair would not help,
    # so say what is actually missing instead.
    canonical = cert_paths(CERT_PROFILE)
    if (CERT_PATH, KEY_PATH) != canonical:
        print(f"ERROR: cert/key not found at {CERT_PATH} / {KEY_PATH}\n"
              f"       (these are not the generated {CERT_PROFILE} paths "
              f"{canonical[0]} / {canonical[1]}, so they must be supplied)",
              file=sys.stderr)
        return 2

    try:
        CERT_PATH, KEY_PATH = ensure_certs(CERT_PROFILE)
    except SystemExit as exc:          # one-line actionable message, no traceback
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0

# NOTE: ROUTINE_ADDR and friends MUST sit in a region that does NOT
# collide with the production CRYPTO_OVERLAY layout.  Under
# USE_X25519_SIBLING=1 the sibling X25519 rodata + bss buffers occupy
# $4200-$50FF (see cfg/c64-https-uci.cfg X25519_RODATA / X25519_BSS).
# Placing the DMA routine at $4200 (the historical value) silently
# clobbered x25_basepoint, fe_p, mul38_lo_tab, etc., producing wrong
# X25519 output during the TLS handshake.
#
# These scratch addresses used to be hardcoded ($4200 originally, then
# $5100 to dodge the X25519 RODATA/BSS span under
# USE_X25519_SIBLING=1).  The hardcoded layout was the antipattern that
# made the X25519 collision possible in the first place — silently
# wrong-but-deterministic crypto output, with no diagnostic until the
# TLS handshake failed half a minute later.
#
# They are now assigned by a :class:`MemoryArbiter` (see
# ``tools/uci/_memory_policy.py``) at runtime, after we have read
# ``build/labels.txt`` and built a :class:`MemoryPolicy` reflecting the
# *current* build's memory map (BACKEND + USE_X25519_SIBLING are
# observed via the segment markers ld65 emits).  The transport's
# memory_policy will then catch any future stray write into a
# c64-https segment before the byte crosses the wire.
#
# Sizes are conservative — the trampoline is ~110 B today; we allow
# 256 B for headroom.  HOST/PATH strings are ASCII-NUL-terminated and
# fit easily inside their 64-byte slots.
ROUTINE_ADDR: int = -1     # arbiter.alloc(256, name="trampoline")
HOST_STR_ADDR: int = -1    # arbiter.alloc(64,  name="host_str")
PATH_STR_ADDR: int = -1    # arbiter.alloc(64,  name="path_str")
SENTINEL_ADDR: int = -1    # arbiter.alloc(1,   name="sentinel")
PROGRESS_ADDR: int = -1    # arbiter.alloc(1,   name="progress")
CARRY_FLAG_ADDR: int = -1  # arbiter.alloc(1,   name="carry_flag")

SENTINEL_VALUE   = 0xAA

# Default HTTPS port; can override via HTTPS_PORT env, else fall back to 4433
# if 443 bind fails (requires root on most systems).
DEFAULT_HTTPS_PORT = int(os.environ.get("HTTPS_PORT", "443"))
FALLBACK_HTTPS_PORT = 4433

# TURBO_MHZ drives a single wall-clock scale factor applied to every
# time-based constant below. At the default 48 MHz the scale is 1.0 and the
# behavior matches the historical hardcoded budgets. TURBO_MHZ=1 (stock C64
# speed) yields a 48x scale across the board; per-test overrides are still
# available via SENTINEL_POLL_TIMEOUT / ACCEPT_TIMEOUT env vars. Timeouts
# auto-scale relative to TURBO_MHZ; see module docstring for details.
TURBO_MHZ       = int(os.environ.get("TURBO_MHZ", "48"))
_TIMEOUT_SCALE  = max(1.0, 48.0 / float(TURBO_MHZ))

SENTINEL_POLL_TIMEOUT = float(
    os.environ.get("SENTINEL_POLL_TIMEOUT", str(600.0 * _TIMEOUT_SCALE))
)
ACCEPT_TIMEOUT        = float(
    os.environ.get("ACCEPT_TIMEOUT", str(600.0 * _TIMEOUT_SCALE))
)

EXPECTED_BODY    = "HELLO FROM TLS SERVER"
HTTP_RESPONSE    = (
    b"HTTP/1.0 200 OK\r\n"
    b"Content-Length: 21\r\n"
    b"\r\n"
    b"HELLO FROM TLS SERVER"
)

# --- External-listener mode ----------------------------------------------
# When EXTERNAL_LISTENER=1 the script does NOT stand up its own inline TLS
# listener and does NOT load the repo cert/key: the server side is provided
# out-of-band (e.g. the packaged dist/c64-https-listener.py listener). The
# C64 client is pointed at EXTERNAL_HOST:EXTERNAL_PORT and the pass criteria
# come purely from C64-side state (http_resp_buf / screen RAM). Default OFF —
# behavior is unchanged unless the var is set.
EXTERNAL_LISTENER = os.environ.get("EXTERNAL_LISTENER", "0") == "1"
# Dev-host IP the C64 should dial. Empty -> auto-detect this machine's LAN IP
# toward the U64E (correct when the external listener runs on this same host
# bound to 0.0.0.0).
EXTERNAL_HOST = os.environ.get("EXTERNAL_HOST", "")
EXTERNAL_PORT = int(os.environ.get("EXTERNAL_PORT", "4433"))


def _detect_local_ip(target: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 80))
        return s.getsockname()[0]
    finally:
        s.close()


def _make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(CERT_PATH), keyfile=str(KEY_PATH))
    # Restrict to TLS 1.3 to match what the C64 client negotiates.
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    except AttributeError:
        pass
    return ctx


def _try_bind(bind_ip: str, port: int) -> socket.socket | None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((bind_ip, port))
    except PermissionError:
        srv.close()
        return None
    except OSError:
        srv.close()
        return None
    return srv


def _run_https_server(srv: socket.socket, ctx: ssl.SSLContext,
                      result: dict) -> None:
    srv.settimeout(ACCEPT_TIMEOUT)
    try:
        srv.listen(1)
        result["listening"] = True
        raw_conn, addr = srv.accept()
        result["client_addr"] = addr
        try:
            tls_conn = ctx.wrap_socket(raw_conn, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            result["error"] = f"TLS handshake failed: {type(exc).__name__}: {exc}"
            try:
                raw_conn.close()
            except Exception:
                pass
            return
        try:
            # Post-handshake request read: C64 still needs to finish Finished
            # MAC + verify server Finished + send client Finished + build HTTP
            # request under the ~2.5 ms UCI fence overhead — give it plenty.
            tls_conn.settimeout(ACCEPT_TIMEOUT)
            try:
                req = tls_conn.recv(1024)
                result["request"] = req
            except socket.timeout:
                result["request"] = b"<timeout>"
            tls_conn.sendall(HTTP_RESPONSE)
            # Keep alive briefly for the C64 to drain before FIN.
            time.sleep(1.0)
        finally:
            try:
                tls_conn.unwrap()
            except Exception:
                pass
            try:
                tls_conn.close()
            except Exception:
                pass
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            srv.close()
        except Exception:
            pass


def _check_c64_result(body_ascii: str, screen_text: str) -> list[str]:
    """C64-side pass criteria. Returns a list of problems; empty ⇒ pass.

    The only accepted criterion is that ``http_resp_buf`` holds the complete
    expected body. Screen RAM is diagnostic, never evidence.

    History (audit finding F5): this used to fall back to passing the run
    whenever the 5 characters ``HELLO`` appeared anywhere in the 1000 bytes
    of screen RAM. That branch was reachable *only* after the body assertion
    had already failed, so it substituted a weaker criterion at exactly the
    moment the strong one did not hold — a truncated body, a mis-decrypted
    body that happened to keep its first word, or a stale ``HELLO`` left on
    screen by an earlier run all passed. The fallback is gone; a screen-RAM
    hit without the body is now reported as a *reason the run failed*.
    """
    problems: list[str] = []
    if EXPECTED_BODY not in body_ascii:
        problems.append(
            f"http_resp_buf does not contain the expected body "
            f"{EXPECTED_BODY!r} (got {body_ascii[:120]!r})"
        )
        if "HELLO" in screen_text.upper():
            problems.append(
                "screen RAM contains 'HELLO' but that is not a pass — only "
                "the complete body in http_resp_buf counts (audit F5)"
            )
    return problems


def _server_request_bytes(server_result: dict) -> bytes | None:
    """Normalize the listener's ``request`` field to bytes, or None if absent.

    Accepts both shapes: the in-process dict (raw ``bytes``) and the
    ``server_result.json`` on-disk form written by
    ``_serialize_server_result`` (``{"__type__": "bytes-b64", ...}``), so the
    same checker runs live and against an archived run directory.
    """
    req = server_result.get("request")
    if req is None:
        return None
    if isinstance(req, (bytes, bytearray)):
        return bytes(req)
    if isinstance(req, dict) and req.get("__type__") == "bytes-b64":
        try:
            return base64.b64decode(req.get("b64", ""))
        except Exception:
            return None
    if isinstance(req, str):
        return req.encode("utf-8", errors="replace")
    return None


def _check_server_result(server_result: dict, *,
                         expect_host: str | None,
                         expect_path: str = "/") -> list[str]:
    """Server-side pass criteria. Returns a list of problems; empty ⇒ pass.

    Audit finding F6: every run already recorded what the listener observed
    into ``server_result.json`` — handshake completion, the decrypted
    request, any TLS error — and the pass criteria never read a byte of it.
    Every assertion was made against C64-side memory and screen RAM, i.e.
    against state the client itself produces. The listener's record is the
    one piece of evidence the client cannot fabricate, so it is now part of
    the verdict.

    Which fields are load-bearing, and why these and not more:

      ``error``       — decisive. Set when the TLS handshake or the socket
                        failed on the server side. A run that reached
                        ``SSLEOFError: UNEXPECTED_EOF_WHILE_READING`` did not
                        complete a TLS session with this listener, whatever
                        the C64's RAM says afterwards.
      ``listening``   — the listener reached ``accept()``. Absent ⇒ there was
                        no server for the C64 to have talked to.
      ``client_addr`` — the listener accepted a connection. Absent ⇒ the C64
                        never reached this listener; anything in http_resp_buf
                        is then stale or fabricated, not this run's evidence.
      ``request``     — the decrypted request must be the one the C64 was
                        configured to send. This is the strongest link
                        between the two sides: the server can only produce
                        these plaintext bytes by having completed the
                        handshake and derived the same application keys.

    All three of ``listening`` / ``client_addr`` / ``request`` are required,
    so the function fails closed: an empty record — listener thread never
    started, crashed before recording anything, artifact absent — is an
    inconclusive check and therefore a failure, never an implicit "no error
    recorded".

    Deliberately NOT asserted, to avoid failing healthy runs:

      - Byte-exact request equality. Only the request line and the ``Host:``
        line are checked — both are values *this script* programmed into the
        C64, so they cannot drift accidentally. Trailing headers
        (``Connection: close``) are src/http.s's business; a future header
        change should not fail the e2e oracle.
      - ``request`` in EXTERNAL_LISTENER mode. There is no inline listener
        then, ``server_result`` is empty by construction, and the documented
        contract is that pass criteria come from C64 state only. The caller
        skips this whole function in that mode and says so out loud.
      - The listener sets ``request`` to ``b"<timeout>"`` when the
        post-handshake ``recv`` times out; that is treated as a failure, not
        as an absent field, because it means the session never carried the
        GET.
    """
    problems: list[str] = []

    err = server_result.get("error")
    if err:
        problems.append(f"listener recorded an error: {err}")

    if not server_result.get("listening"):
        problems.append(
            "listener never reported `listening` — no server side to this run"
        )

    if server_result.get("client_addr") is None:
        problems.append(
            "listener never accepted a connection (`client_addr` absent) — "
            "the C64 did not reach this listener"
        )

    req = _server_request_bytes(server_result)
    if req is None:
        problems.append(
            "listener recorded no decrypted request — the TLS session never "
            "carried the GET"
        )
    elif req == b"<timeout>":
        problems.append(
            "listener timed out waiting for the request after the handshake"
        )
    else:
        want_line = b"GET " + expect_path.encode("ascii") + b" HTTP/1."
        if not req.startswith(want_line):
            problems.append(
                f"decrypted request does not start with {want_line!r} "
                f"(got {req[:40]!r})"
            )
        if expect_host is not None:
            want_host = b"Host: " + expect_host.encode("ascii")
            if want_host not in req:
                problems.append(
                    f"decrypted request lacks {want_host!r} "
                    f"(got {req[:80]!r})"
                )

    return problems


def _load_labels() -> dict[str, int]:
    # c64-test-harness Labels is a Mapping since 0.12.4 (JC-000/c64-test-harness#64)
    # and parses both C: and non-C (REU/bank) label lines since #62.
    return dict(Labels.from_file(LABELS_PATH))


def _build_http_routine(labels: dict[str, int], port: int) -> tuple[bytes, int]:
    """Emit a 6502 routine that calls http_get via the real TLS+HTTP layer."""
    code = bytearray()

    def emit(*bs: int) -> None:
        code.extend(bs)

    def emit_lda_imm(v: int) -> None:
        emit(0xA9, v & 0xFF)

    def emit_sta_abs(addr: int) -> None:
        emit(0x8D, addr & 0xFF, (addr >> 8) & 0xFF)

    def emit_lda_abs(addr: int) -> None:
        emit(0xAD, addr & 0xFF, (addr >> 8) & 0xFF)

    def emit_jsr(addr: int) -> None:
        emit(0x20, addr & 0xFF, (addr >> 8) & 0xFF)

    def emit_jmp(addr: int) -> None:
        emit(0x4C, addr & 0xFF, (addr >> 8) & 0xFF)

    def emit_progress(step: int) -> None:
        emit_lda_imm(step)
        emit_sta_abs(PROGRESS_ADDR)

    # ABI addresses
    http_get       = labels["http_get"]
    http_host_ptr  = labels["http_host_ptr"]
    http_host_len  = labels["http_host_len"]
    http_path_ptr  = labels["http_path_ptr"]
    http_path_len  = labels["http_path_len"]
    http_port      = labels["http_port"]
    net_init       = labels["net_init"]
    tcp_recv_head  = labels["tcp_recv_head"]
    tcp_recv_tail  = labels["tcp_recv_tail"]

    # 0) Bank BASIC ROM OUT so $A000-$BFFF is RAM
    emit_lda_abs(0x0001)
    emit(0x29, 0xFE)          # AND #$FE
    emit_sta_abs(0x0001)

    # Clear markers
    emit_lda_imm(0x00)
    emit_sta_abs(SENTINEL_ADDR)
    emit_sta_abs(PROGRESS_ADDR)
    emit_sta_abs(CARRY_FLAG_ADDR)

    emit_progress(0x01)

    # Re-init UCI (ensure idle state after auto-init)
    emit_jsr(net_init)

    # Zero the TCP ring head/tail to flush any stale boot-poll data
    emit_lda_imm(0x00)
    emit_sta_abs(tcp_recv_head)
    emit_sta_abs(tcp_recv_head + 1)
    emit_sta_abs(tcp_recv_tail)
    emit_sta_abs(tcp_recv_tail + 1)

    emit_progress(0x02)

    # Set http_host_ptr = HOST_STR_ADDR
    emit_lda_imm(HOST_STR_ADDR & 0xFF)
    emit_sta_abs(http_host_ptr)
    emit_lda_imm((HOST_STR_ADDR >> 8) & 0xFF)
    emit_sta_abs(http_host_ptr + 1)

    # Set http_host_len — patched by Python once the IP is known.
    host_len_patch_offset = len(code) + 1
    emit_lda_imm(0x00)
    emit_sta_abs(http_host_len)

    # Set http_path_ptr = PATH_STR_ADDR
    emit_lda_imm(PATH_STR_ADDR & 0xFF)
    emit_sta_abs(http_path_ptr)
    emit_lda_imm((PATH_STR_ADDR >> 8) & 0xFF)
    emit_sta_abs(http_path_ptr + 1)

    # Set http_path_len = 1 (just "/")
    emit_lda_imm(1)
    emit_sta_abs(http_path_len)

    # Set http_port = our test port (16-bit: low then high)
    emit_lda_imm(port & 0xFF)
    emit_sta_abs(http_port)
    emit_lda_imm((port >> 8) & 0xFF)
    emit_sta_abs(http_port + 1)

    emit_progress(0x03)

    # Call http_get — the REAL TLS 1.3 + HTTP code path.
    emit_jsr(http_get)

    # Store carry (success/failure) via PHP/PLA
    emit(0x08)  # PHP
    emit(0x68)  # PLA
    emit_sta_abs(CARRY_FLAG_ADDR)

    emit_progress(0x04)

    # Write sentinel
    emit_lda_imm(SENTINEL_VALUE)
    emit_sta_abs(SENTINEL_ADDR)

    emit_progress(0x05)

    # Park CPU
    park = ROUTINE_ADDR + len(code)
    emit_jmp(park)

    return bytes(code), host_len_patch_offset


def _decode_screen_ram(data: bytes) -> str:
    lines = []
    for row in range(25):
        line = data[row * 40:(row + 1) * 40]
        chars = []
        for b in line:
            if b == 0x20 or b == 0x00:
                chars.append(' ')
            elif 0x01 <= b <= 0x1A:
                chars.append(chr(b + 0x40))
            elif 0x30 <= b <= 0x39:
                chars.append(chr(b))
            elif 0x41 <= b <= 0x5A:
                chars.append(chr(b))
            elif b in (0x2E, 0x2F, 0x3A, 0x2D, 0x28, 0x29):
                chars.append(chr(b))
            else:
                chars.append('.')
        lines.append(''.join(chars).rstrip())
    return '\n'.join(lines)


def _dump_diag(transport: Ultimate64Transport,
               labels: dict[str, int]) -> None:
    def r8(name: str) -> int:
        return transport.read_memory(labels[name], 1)[0]

    def r16(name: str) -> int:
        b = transport.read_memory(labels[name], 2)
        return b[0] | (b[1] << 8)

    print()
    print("--- adapter / TLS state ---")
    for name in ("net_last_error", "net_tcp_state", "uci_socket_id",
                 "net_initialized"):
        if name in labels:
            print(f"  {name:22s} : 0x{r8(name):02X}")
    for name in ("tls_state", "tls_last_state",
                 "tls_recv_progress", "tls_recv_sub_progress"):
        if name in labels:
            print(f"  {name:22s} : 0x{r8(name):02X}")
    for name in ("tcp_recv_head", "tcp_recv_tail",
                 "http_status", "http_resp_len"):
        if name in labels:
            print(f"  {name:22s} : ${r16(name):04X}")


def _dump_tls_state_snapshot(transport: Ultimate64Transport,
                             labels: dict[str, int],
                             run_dir: Path) -> None:
    """DMA-snapshot every TLS state-machine variable we know the label for.

    Written as ``tls_state_dump.json`` in ``run_dir`` to support post-mortem
    decoding of stalls. Byte blobs come out as hex strings; word values are
    unsigned little-endian ints; per-variable entries also carry the label
    address for sanity-checking vs ``build/labels.txt``.

    Silently skips any label that isn't present in ``labels`` (older builds
    may omit some TLS progress counters).
    """
    # Layout: (label_name, byte_count). Anything not present is skipped.
    byte_specs: list[tuple[str, int]] = [
        # --- top-level state / progress ---
        ("tls_state", 1),
        ("tls_last_state", 1),
        ("tls_recv_progress", 1),
        ("tls_recv_sub_progress", 1),
        ("tls_recv_poll_count", 2),
        # --- record-layer framer ---
        ("tls_rec_header", 5),
        ("tls_rec_type", 1),
        ("tls_rec_len", 2),
        ("tls_recv_state", 1),
        ("tls_recv_count", 2),
        # tls_rec_buf holds the decrypted handshake message plaintext
        # (formerly copied into tls_hs_buf; staging buffer removed).
        # 548 B is a bit large for the JSON snapshot but essential for
        # post-mortem cert-parse diagnosis, so capture the full record.
        ("tls_rec_buf", 548),
        # --- app-data plumbing ---
        ("tls_app_ptr", 2),
        ("tls_app_len", 2),
        # --- seq counters / key schedule ---
        ("tls_read_seq", 8),
        ("tls_write_seq", 8),
        ("tls_hs_read_key", 32),
        ("tls_hs_read_iv", 12),
        ("tls_hs_write_key", 32),
        ("tls_hs_write_iv", 12),
        ("tls_app_read_key", 32),
        ("tls_app_read_iv", 12),
        ("tls_app_write_key", 32),
        ("tls_app_write_iv", 12),
        # --- secrets (handshake/master) ---
        ("tls_early_secret", 32),
        ("tls_handshake_secret", 32),
        ("tls_master_secret", 32),
        # --- key-schedule intermediates (for post-mortem verification of
        #     x25519 / HKDF-Extract / HKDF-Expand-Label stages) ---
        ("tls_ecdhe_privkey", 32),      # our X25519 private scalar
        ("tls_ecdhe_pubkey", 32),       # our X25519 public key (= G * priv)
        ("tls_server_pubkey", 32),      # server's X25519 public key (from SH)
        ("tls_shared_secret", 32),      # X25519(priv, server_pub)
        ("tls_client_random", 32),      # CH.random
        ("tls_server_random", 32),      # SH.random
        ("tls_transcript", 32),         # SHA-256(CH||SH), context for derives
        ("tls_c_hs_secret", 32),        # client-handshake-traffic-secret
        ("tls_s_hs_secret", 32),        # server-handshake-traffic-secret
        ("tls_derived_tmp", 32),        # "derived" intermediate
        ("tls_verify_data", 32),        # computed Finished verify_data
        ("tls_finished_key", 32),       # HKDF-Expand-Label(..., "finished", ...)
        # --- ECDSA verification inputs (populated by tls_handle_certificate
        #     and tls_handle_cert_verify — useful for reproducing a failed
        #     signature check offline in python-cryptography) ---
        ("ecdsa_pubkey_x", 32),
        ("ecdsa_pubkey_y", 32),
        ("ecdsa_sig_r", 32),
        ("ecdsa_sig_s", 32),
        ("ecdsa_hash", 32),
        ("ecdsa_hash_len", 1),
        ("ecdsa_sig_len", 1),
        ("ecdsa_curve_id", 1),
        # --- net state ---
        ("net_last_error", 1),
        ("net_tcp_state", 1),
        ("net_initialized", 1),
        ("net_poll_entry_count", 2),
        ("net_poll_return_count", 2),
        # --- http parser ---
        ("http_parse_state", 1),
        ("http_status", 2),
        ("http_resp_len", 2),
    ]

    dump: dict = {"labels_file": str(LABELS_PATH)}
    for name, n in byte_specs:
        if name not in labels:
            continue
        addr = labels[name]
        try:
            raw = bytes(transport.read_memory(addr, n))
        except Exception as exc:
            dump[name] = {"addr": f"${addr:04X}", "error": str(exc)}
            continue
        entry: dict = {"addr": f"${addr:04X}", "hex": raw.hex()}
        if n == 1:
            entry["u8"] = raw[0]
        elif n == 2:
            entry["u16_le"] = raw[0] | (raw[1] << 8)
        elif n == 8:
            entry["u64_le"] = int.from_bytes(raw, "little")
        dump[name] = entry

    # Ring indices, in one struct for easy cross-reference with ring.bin
    ring_head_addr = labels.get("tcp_recv_head")
    ring_tail_addr = labels.get("tcp_recv_tail")
    ring_ovf_addr = labels.get("tcp_recv_overflow")
    ring_entry: dict = {}
    if ring_head_addr is not None:
        try:
            b = transport.read_memory(ring_head_addr, 2)
            ring_entry["head"] = b[0] | (b[1] << 8)
            ring_entry["head_addr"] = f"${ring_head_addr:04X}"
        except Exception as exc:
            ring_entry["head_error"] = str(exc)
    if ring_tail_addr is not None:
        try:
            b = transport.read_memory(ring_tail_addr, 2)
            ring_entry["tail"] = b[0] | (b[1] << 8)
            ring_entry["tail_addr"] = f"${ring_tail_addr:04X}"
        except Exception as exc:
            ring_entry["tail_error"] = str(exc)
    if ring_ovf_addr is not None:
        try:
            b = transport.read_memory(ring_ovf_addr, 1)
            ring_entry["overflow"] = b[0]
        except Exception as exc:
            ring_entry["overflow_error"] = str(exc)
    dump["ring"] = ring_entry

    (run_dir / "tls_state_dump.json").write_text(json.dumps(dump, indent=2))


def _dump_ring(transport: Ultimate64Transport,
               labels: dict[str, int],
               run_dir: Path) -> None:
    """DMA-snapshot the entire TCP receive ring + metadata to ``run_dir``.

    ``ring.bin`` is the raw 4 KB buffer starting at ``tcp_recv_buf`` (no
    reordering — consumers use ``ring_meta.json`` to find head/tail/size).
    ``ring_meta.json`` records base address, size, and current head/tail
    so a post-mortem tool can slice out just the live window.
    """
    base = labels.get("tcp_recv_buf", 0xC000)
    # Match TCP_RECV_MASK = $0FFF from constants.inc — 4 KB ring.
    size = 4096
    try:
        raw = bytes(transport.read_memory(base, size))
    except Exception as exc:
        (run_dir / "ring_meta.json").write_text(json.dumps({
            "error": f"read_memory failed: {exc}",
            "base_addr": f"${base:04X}",
            "size": size,
        }, indent=2))
        return
    (run_dir / "ring.bin").write_bytes(raw)

    meta: dict = {
        "base_addr": f"${base:04X}",
        "size": size,
        "mask": "0x0FFF (TCP_RECV_MASK)",
        "file": "ring.bin",
        "note": "ring.bin is tcp_recv_buf[0..4095] verbatim; head/tail "
                "are masked indices *into* this buffer (not byte offsets "
                "relative to a live window). See net/uci/net.s "
                "net_recv_byte for addressing.",
    }
    try:
        b = transport.read_memory(labels["tcp_recv_head"], 2)
        meta["head"] = b[0] | (b[1] << 8)
    except Exception as exc:
        meta["head_error"] = str(exc)
    try:
        b = transport.read_memory(labels["tcp_recv_tail"], 2)
        meta["tail"] = b[0] | (b[1] << 8)
    except Exception as exc:
        meta["tail_error"] = str(exc)
    try:
        meta["overflow"] = transport.read_memory(
            labels["tcp_recv_overflow"], 1)[0]
    except Exception as exc:
        meta["overflow_error"] = str(exc)

    (run_dir / "ring_meta.json").write_text(json.dumps(meta, indent=2))


def _dump_full(transport: Ultimate64Transport,
               labels: dict[str, int],
               server_result: dict,
               run_dir: Path | None = None) -> None:
    """Dump the full diagnostic set (used on both success and TIMEOUT paths).

    When ``run_dir`` is provided, extra binary/JSON artifacts are written
    alongside the trace files for post-mortem decoding:
      - ``ring.bin`` / ``ring_meta.json`` : full 4 KB tcp_recv_buf + head/tail
      - ``tls_state_dump.json``           : every TLS state-machine variable
    """
    _dump_diag(transport, labels)

    try:
        carry_byte = transport.read_memory(CARRY_FLAG_ADDR, 1)[0]
        carry = carry_byte & 0x01
        print(f"http_get carry  = {carry} (0=success, 1=failure)")
    except Exception as exc:
        print(f"http_get carry  = <read failed: {exc}>")

    try:
        status_raw = transport.read_memory(labels["http_status"], 2)
        http_status = status_raw[0] | (status_raw[1] << 8)
        print(f"http_status     = {http_status}")
    except Exception as exc:
        print(f"http_status     = <read failed: {exc}>")

    resp_len = 0
    try:
        resp_len_raw = transport.read_memory(labels["http_resp_len"], 2)
        resp_len = resp_len_raw[0] | (resp_len_raw[1] << 8)
        print(f"http_resp_len   = {resp_len}")
    except Exception as exc:
        print(f"http_resp_len   = <read failed: {exc}>")

    try:
        read_len = min(resp_len, 200) if resp_len > 0 else 200
        resp_data = bytes(transport.read_memory(labels["http_resp_buf"],
                                                read_len))
        print(f"http_resp_buf   = {resp_data[:80]!r}")
        if read_len > 80:
            print(f"http_resp_buf+  = {resp_data[80:200]!r}")
    except Exception as exc:
        print(f"http_resp_buf   = <read failed: {exc}>")

    try:
        screen = bytes(transport.read_memory(0x0400, 1000))
        screen_text = _decode_screen_ram(screen)
        print("\n--- screen RAM ---")
        for line in screen_text.split('\n'):
            if line.strip():
                print(f"  {line}")
    except Exception as exc:
        print(f"screen RAM read failed: {exc}")

    try:
        ring_data = bytes(transport.read_memory(0xC000, 256))
        print(f"\ntcp_recv_buf[0:128] hex :")
        for off in (0, 64, 128, 192):
            print(f"  +{off:03X} : {ring_data[off:off+64].hex()}")
    except Exception as exc:
        print(f"tcp_recv_buf read failed: {exc}")

    print("\n--- server-side ---")
    print(f"  listening     : {server_result.get('listening', False)}")
    print(f"  client_addr   : {server_result.get('client_addr')}")
    print(f"  request       : {server_result.get('request', b'<none>')!r}")
    print(f"  error         : {server_result.get('error', '<none>')}")

    # --- Persist ring + TLS-state snapshots alongside the trace ---
    if run_dir is not None:
        try:
            _dump_ring(transport, labels, run_dir)
            print(f"  ring.bin            -> {run_dir / 'ring.bin'}")
        except Exception as exc:
            print(f"WARNING: ring dump failed: {exc}")
        try:
            _dump_tls_state_snapshot(transport, labels, run_dir)
            print(f"  tls_state_dump.json -> "
                  f"{run_dir / 'tls_state_dump.json'}")
        except Exception as exc:
            print(f"WARNING: tls_state_dump failed: {exc}")


def _git_head_sha() -> str:
    """Return the short git HEAD SHA, or '<unknown>' if git is unavailable."""
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(REPO_ROOT),
            stderr=subprocess.DEVNULL,
            timeout=3.0,
        )
        return out.decode("ascii", errors="replace").strip() or "<unknown>"
    except Exception:
        return "<unknown>"


def _create_run_dir(base_dir: Path) -> Path:
    """Create and return a timestamped run directory under ``base_dir``."""
    base_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = base_dir / stamp
    # Disambiguate if a same-second run dir already exists
    suffix = 0
    candidate = run_dir
    while candidate.exists():
        suffix += 1
        candidate = base_dir / f"{stamp}_{suffix}"
    candidate.mkdir(parents=True, exist_ok=False)
    return candidate


def _prune_old_run_dirs(base_dir: Path, keep: int) -> list[Path]:
    """Keep the ``keep`` most-recent run directories; remove the rest.

    Orders by mtime (not filename) so DST/timezone oddities don't misorder.
    Returns the list of directories that were removed (for logging).
    """
    if not base_dir.is_dir():
        return []
    entries: list[tuple[float, Path]] = []
    for child in base_dir.iterdir():
        if child.is_dir():
            try:
                entries.append((child.stat().st_mtime, child))
            except OSError:
                pass
    entries.sort(key=lambda t: t[0], reverse=True)
    removed: list[Path] = []
    for _, d in entries[keep:]:
        try:
            shutil.rmtree(d)
            removed.append(d)
        except Exception as exc:
            print(f"WARNING: failed to prune {d}: {exc}")
    return removed


def _serialize_trace_packed(cap_result, trace_path: Path,
                            meta_path: Path) -> dict:
    """Serialize the raw BusCycle trace to a packed 4-byte-per-cycle file.

    Each BusCycle carries only a 32-bit ``raw`` word, so the packed
    little-endian u32 stream is lossless and dramatically more compact
    than pickle. Writes ``trace.bin`` and a ``trace.bin.meta.json``
    sidecar that describes the layout for post-hoc readers.

    Returns a small dict with size/count for logging.
    """
    trace = getattr(cap_result, "trace", None) or []
    count = len(trace)
    # Pre-size buffer and pack in one shot. Fall back to per-cycle pack if
    # the in-tree BusCycle layout ever grows richer.
    try:
        fmt = f"<{count}I"
        buf = struct.pack(fmt, *(int(c.raw) & 0xFFFFFFFF for c in trace))
    except Exception:
        parts = [struct.pack("<I", int(c.raw) & 0xFFFFFFFF) for c in trace]
        buf = b"".join(parts)
    trace_path.write_bytes(buf)

    meta = {
        "format": "packed-u32-le",
        "bytes_per_cycle": 4,
        "cycle_count": count,
        "file": trace_path.name,
        "field_layout": {
            "bit31": "PHI2 (1=CPU, 0=VIC)",
            "bit30": "GAME# (active low)",
            "bit29": "EXROM# (active low)",
            "bit28": "BA (Bus Available)",
            "bit27": "IRQ# (active low)",
            "bit26": "ROM# (active low)",
            "bit25": "NMI# (active low)",
            "bit24": "R/W# (1=read, 0=write)",
            "bits23_16": "Data bus (8-bit)",
            "bits15_0": "Address bus (16-bit)",
        },
        "capture": {
            "packets_received": int(
                getattr(cap_result, "packets_received", 0) or 0),
            "packets_dropped": int(
                getattr(cap_result, "packets_dropped", 0) or 0),
            "duration_seconds": float(
                getattr(cap_result, "duration_seconds", 0.0) or 0.0),
            "total_cycles": int(
                getattr(cap_result, "total_cycles", 0) or 0),
        },
        "first_raw": int(trace[0].raw) & 0xFFFFFFFF if count else None,
        "last_raw": int(trace[-1].raw) & 0xFFFFFFFF if count else None,
    }
    meta_path.write_text(json.dumps(meta, indent=2))
    return {
        "cycle_count": count,
        "bytes_on_disk": len(buf),
    }


def _serialize_server_result(server_result: dict, path: Path) -> None:
    """Dump the HTTPS listener's per-connection dict to JSON.

    Bytes fields are base64-encoded (round-trippable, unlike repr()).
    Non-serializable exception values are captured as type/str/traceback.
    """
    out: dict = {}
    for key, val in server_result.items():
        if isinstance(val, (bytes, bytearray)):
            out[key] = {
                "__type__": "bytes-b64",
                "b64": base64.b64encode(bytes(val)).decode("ascii"),
                "len": len(val),
            }
        elif isinstance(val, BaseException):
            out[key] = {
                "__type__": "exception",
                "class": type(val).__name__,
                "str": str(val),
                "traceback": traceback.format_exception(
                    type(val), val, val.__traceback__),
            }
        elif isinstance(val, tuple):
            # client_addr is (host, port) — JSON has no tuple, keep as list
            out[key] = list(val)
        else:
            try:
                json.dumps(val)
                out[key] = val
            except TypeError:
                out[key] = repr(val)
    path.write_text(json.dumps(out, indent=2, default=str))


def _write_run_info(path: Path, *, outcome: str, duration: float,
                    exit_code: int, extra: dict | None = None) -> None:
    """Write one-line metadata for a run (git SHA, outcome, duration, rc)."""
    sha = _git_head_sha()
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    lines = [
        f"timestamp     = {ts}",
        f"git_head      = {sha}",
        f"outcome       = {outcome}",
        f"duration_s    = {duration:.3f}",
        f"exit_code     = {exit_code}",
    ]
    if extra:
        for k, v in extra.items():
            lines.append(f"{k:<13} = {v}")
    path.write_text("\n".join(lines) + "\n")


def _process_debug_trace(cap_result,
                         summary_path: str,
                         tail_path: str,
                         uci_path: str) -> dict:
    """Post-process the debug-stream BusCycle list into three artifacts.

    Returns a small dict with high-level stats for console logging.
    """
    stats: dict = {}
    trace = getattr(cap_result, "trace", None) or []
    total = len(trace)
    packets = getattr(cap_result, "packets_received", 0)
    dropped = getattr(cap_result, "packets_dropped", 0)
    duration = getattr(cap_result, "duration_seconds", 0.0) or 0.0
    bytes_recv = getattr(cap_result, "bytes_received", 0) or 0
    stats["total"] = total
    stats["packets"] = packets
    stats["dropped"] = dropped
    stats["duration"] = duration

    cpu_count = 0
    vic_count = 0
    cpu_read_hist: dict = {}
    uci_hist: dict = {}
    uci_tail: list = []
    cpu_tail: list = []  # ring of last CPU cycles

    tail_cap = 2000
    huge = total > 2_000_000
    # If huge, still compute PC hotspots but only over the LAST 500k CPU
    # cycles, to bound cost. For small traces use everything.
    scan_window = total
    scan_start = 0
    if huge:
        scan_start = max(0, total - 2_000_000)
        scan_window = total - scan_start

    cpu_idx_for_tail_start = max(0, total - tail_cap * 4)  # oversample — trim later

    for i, c in enumerate(trace):
        is_cpu = bool(getattr(c, "is_cpu", False))
        if is_cpu:
            cpu_count += 1
            if i >= scan_start and bool(getattr(c, "is_read", False)):
                addr = int(getattr(c, "address", 0)) & 0xFFFF
                cpu_read_hist[addr] = cpu_read_hist.get(addr, 0) + 1
            if i >= cpu_idx_for_tail_start:
                cpu_tail.append((i, c))
                if len(cpu_tail) > tail_cap * 2:
                    # keep it bounded while iterating
                    cpu_tail = cpu_tail[-tail_cap:]
            addr = int(getattr(c, "address", 0)) & 0xFFFF
            if 0xDF1B <= addr <= 0xDF1F:
                uci_hist[addr] = uci_hist.get(addr, 0) + 1
                uci_tail.append((i, c))
        else:
            vic_count += 1

    # Trim tail to exactly last tail_cap CPU cycles
    if len(cpu_tail) > tail_cap:
        cpu_tail = cpu_tail[-tail_cap:]

    top_pcs = sorted(cpu_read_hist.items(), key=lambda kv: kv[1],
                     reverse=True)[:20]
    top_uci = sorted(uci_hist.items(), key=lambda kv: kv[1],
                     reverse=True)[:10]

    stats["cpu"] = cpu_count
    stats["vic"] = vic_count
    stats["top_pcs"] = top_pcs
    stats["top_uci"] = top_uci
    stats["uci_tail"] = uci_tail[-10:]
    stats["cpu_tail_sample"] = cpu_tail[-20:]

    # --- Write summary ---
    with open(summary_path, "w") as f:
        f.write(f"DebugCapture summary\n")
        f.write(f"  packets_received   = {packets}\n")
        f.write(f"  packets_dropped    = {dropped}\n")
        f.write(f"  duration_seconds   = {duration:.3f}\n")
        f.write(f"  bytes_received     = {bytes_recv}\n")
        bps = (bytes_recv / duration) if duration > 0 else 0
        f.write(f"  bytes_per_second   = {bps:.0f}\n")
        f.write(f"  total_cycles       = {total}\n")
        f.write(f"  cpu_cycles         = {cpu_count}\n")
        f.write(f"  vic_cycles         = {vic_count}\n")
        if huge:
            f.write(f"  NOTE: trace > 2M cycles; PC histogram computed over "
                    f"last {scan_window} cycles only.\n")
        f.write(f"\nTop 20 CPU-read addresses (approx PC hotspots):\n")
        for addr, count in top_pcs:
            f.write(f"  ${addr:04X}  {count}\n")
        f.write(f"\nTop 10 UCI register accesses ($DF1B-$DF1F):\n")
        for addr, count in top_uci:
            f.write(f"  ${addr:04X}  {count}\n")

    # --- Write tail (last 2000 CPU cycles) ---
    with open(tail_path, "w") as f:
        f.write(f"# last {len(cpu_tail)} CPU cycles (of {cpu_count} total)\n")
        for idx, c in cpu_tail:
            rw = "R" if getattr(c, "is_read", False) else \
                 ("W" if getattr(c, "is_write", False) else "?")
            addr = int(getattr(c, "address", 0)) & 0xFFFF
            data = int(getattr(c, "data", 0)) & 0xFF
            f.write(f"{idx:>9d} {rw} ${addr:04X} = ${data:02X}\n")

    # --- Write UCI-register filter (every CPU access to $DF1B-$DF1F) ---
    with open(uci_path, "w") as f:
        f.write(f"# {len(uci_tail)} CPU cycles in $DF1B-$DF1F\n")
        for run_idx, (idx, c) in enumerate(uci_tail):
            rw = "R" if getattr(c, "is_read", False) else \
                 ("W" if getattr(c, "is_write", False) else "?")
            addr = int(getattr(c, "address", 0)) & 0xFFFF
            data = int(getattr(c, "data", 0)) & 0xFF
            f.write(f"{run_idx:>7d} @{idx:>9d} {rw} ${addr:04X} = ${data:02X}\n")

    stats["uci_total"] = len(uci_tail)
    return stats


def main() -> int:
    if not PRG_PATH.is_file():
        print(f"ERROR: PRG not found at {PRG_PATH}", file=sys.stderr)
        print("Run: make BACKEND=uci", file=sys.stderr)
        return 2
    if not LABELS_PATH.is_file():
        print(f"ERROR: labels.txt not found", file=sys.stderr)
        print("Run: make BACKEND=uci", file=sys.stderr)
        return 2
    # EXTERNAL_LISTENER=1 serves TLS out of band and loads no repo cert, so
    # do not generate one it will never use.
    if not EXTERNAL_LISTENER:
        rc = _ensure_certs_or_fail()
        if rc:
            return rc

    labels = _load_labels()
    required = [
        "http_get", "http_host_ptr", "http_host_len",
        "http_path_ptr", "http_path_len", "http_port",
        "net_init", "net_initialized", "uci_socket_id",
        "tcp_recv_head", "tcp_recv_tail",
        "http_resp_buf", "http_resp_len", "http_status",
        "tls_state", "tls_last_state",
    ]
    missing = [n for n in required if n not in labels]
    if missing:
        print(f"ERROR: missing labels: {missing}", file=sys.stderr)
        return 2

    for n in sorted(required):
        print(f"  {n:22s} = ${labels[n]:04X}")

    # --- Memory policy + arbiter: derive scratch addresses from the
    # current build's segment layout instead of hardcoding them.  The
    # policy reserves every PRG segment found in labels.txt; the
    # arbiter then allocates inside the NET_CODE zero-fill tail
    # ($3xxx-$3FFF), carved out via
    # ``build_policy_and_arbiter_with_overlay_carveout``. Previously this
    # used ``build_policy_and_arbiter`` (CRYPTO_OVERLAY window), but
    # Phase 5's overlay-blob landings fill CRYPTO_OVERLAY end-to-end
    # ($4200-$5FFF) and the arbiter could no longer find a slot. The
    # overlay-carveout helper steals the NET_CODE tail (declared
    # ``fill = yes`` in the cfg, used only up to $3xxx by the adapter
    # and relocated TLS/crypto-aux code) instead, which has ~1.6 KB of
    # safe RAM under both the P-256 and P-384 builds.
    # Transport hookup happens after the transport is constructed
    # inside the try-block below.
    global ROUTINE_ADDR, HOST_STR_ADDR, PATH_STR_ADDR
    global SENTINEL_ADDR, PROGRESS_ADDR, CARRY_FLAG_ADDR
    memory_policy, arbiter = build_policy_and_arbiter_with_overlay_carveout(
        LABELS_PATH, PRG_PATH,
    )
    ROUTINE_ADDR    = arbiter.alloc(256, name="trampoline")
    HOST_STR_ADDR   = arbiter.alloc(64,  name="host_str")
    PATH_STR_ADDR   = arbiter.alloc(64,  name="path_str")
    SENTINEL_ADDR   = arbiter.alloc(1,   name="sentinel")
    PROGRESS_ADDR   = arbiter.alloc(1,   name="progress")
    CARRY_FLAG_ADDR = arbiter.alloc(1,   name="carry_flag")
    print(
        f"\nMemoryPolicy reserved {len(memory_policy.reserved_regions)}"
        f" region(s); arbiter allocations:"
    )
    for base, last, note in arbiter.allocations:
        print(f"  ${base:04X}-${last:04X}  {note}")

    server_result: dict = {}
    server_thread: threading.Thread | None = None

    if EXTERNAL_LISTENER:
        # Server side is provided out-of-band (packaged listener). Don't
        # bind, don't load certs, don't spawn a thread — just point the
        # C64 at the external host:port. Pass criteria come from C64 state.
        test_host_ip = EXTERNAL_HOST or _detect_local_ip(HOST)
        chosen_port = EXTERNAL_PORT
        print(f"\nDev host LAN IP : {test_host_ip}")
        print(f"EXTERNAL_LISTENER=1 — using out-of-band listener at "
              f"{test_host_ip}:{chosen_port} (no inline server, no repo certs)")
        print(f"Expected body   : {EXPECTED_BODY!r}")
    else:
        test_host_ip = _detect_local_ip(HOST)
        print(f"\nDev host LAN IP : {test_host_ip}")
        print(f"Cert / key      : {CERT_PATH} / {KEY_PATH}")

        # --- Bind HTTPS listener (try default port, fall back to 4433) ---
        ctx = _make_ssl_context()
        srv = _try_bind(test_host_ip, DEFAULT_HTTPS_PORT)
        chosen_port = DEFAULT_HTTPS_PORT
        if srv is None:
            if DEFAULT_HTTPS_PORT != FALLBACK_HTTPS_PORT:
                print(f"NOTE: bind {test_host_ip}:{DEFAULT_HTTPS_PORT} failed"
                      f" (need root?), falling back to {FALLBACK_HTTPS_PORT}")
                srv = _try_bind(test_host_ip, FALLBACK_HTTPS_PORT)
                chosen_port = FALLBACK_HTTPS_PORT
            if srv is None:
                print(f"ERROR: could not bind HTTPS listener", file=sys.stderr)
                return 1
        print(f"HTTPS port      : {chosen_port}")
        print(f"Expected body   : {EXPECTED_BODY!r}")

        server_thread = threading.Thread(
            target=_run_https_server,
            args=(srv, ctx, server_result),
            daemon=True,
        )
        server_thread.start()
        for _ in range(60):
            if server_result.get("listening"):
                break
            time.sleep(0.05)
        else:
            print("ERROR: HTTPS server failed to start", file=sys.stderr)
            return 1
        print(f"HTTPS server listening on {test_host_ip}:{chosen_port}")

    # --- Build routine (port patched in at build time) ---
    routine_bytes_raw, host_len_patch = _build_http_routine(labels, chosen_port)
    routine_bytes = bytearray(routine_bytes_raw)
    host_ip_bytes = test_host_ip.encode("ascii")
    routine_bytes[host_len_patch] = len(host_ip_bytes)
    routine_bytes = bytes(routine_bytes)

    print(f"Routine size    : {len(routine_bytes)} bytes @ ${ROUTINE_ADDR:04X}")

    host_str = host_ip_bytes + b"\x00"
    path_str = b"/\x00"

    prg = PRG_PATH.read_bytes()

    lock = DeviceLock(HOST)
    try:
        # acquire_or_raise (c64-test-harness PR #88) replaces the legacy
        # bare-bool acquire+if pattern. On timeout it gathers holder
        # PID/liveness, lockfile age, and a quick REST reachability probe
        # and raises DeviceLockTimeout with a diagnostic message that
        # disambiguates "queued behind healthy holder" from
        # "wedged / stale / unreachable" -- supervisors and humans need
        # this signal to know whether to wait, kill the holder, or call
        # for a recover() (the last requires explicit user authorization,
        # never automated here).
        lock.acquire_or_raise(timeout=120.0)
    except DeviceLockTimeout as exc:
        print(f"[fatal] DeviceLock({HOST}): {exc}", file=sys.stderr)
        return 2
    # Surface queue/holder metadata on kickoff so the supervisor log
    # has the same diagnostic shape as the timeout path. read_info()
    # returns the lockfile JSON dict (or None when the lockfile vanished
    # between acquire and this read, which is harmless).
    info = lock.read_info()
    print(f"Acquired DeviceLock({HOST}); holder info: {info!r}")

    # --- Per-run debug artifact directory + rotation ---
    run_dir: Path | None = None
    if DEBUG_CAPTURE_ENABLED:
        removed = _prune_old_run_dirs(UCI_DEBUG_BASE_DIR, UCI_DEBUG_KEEP)
        for d in removed:
            print(f"Pruning old debug artifacts: {d}")
        run_dir = _create_run_dir(UCI_DEBUG_BASE_DIR)
        print(f"Debug artifacts dir: {run_dir}")

    client: Ultimate64Client | None = None
    uci_enabled = False
    debug_cap: DebugCapture | None = None
    debug_started_on_u64 = False
    outcome: str = "UNKNOWN"
    exit_code: int = 1
    run_start = time.time()
    try:
        client = Ultimate64Client(host=HOST, timeout=15.0)
        transport = Ultimate64Transport(host=HOST, timeout=15.0, client=client)
        # Attach the c64-https-aware MemoryPolicy.  Every subsequent
        # transport.write_memory(...) is checked against the policy
        # *before* the byte crosses the wire — a collision into a
        # reserved segment now raises MemoryPolicyError instead of
        # silently corrupting C64 RAM.
        transport.memory_policy = memory_policy

        print("Enabling UCI...")
        enable_uci(client)
        uci_enabled = True

        # Pre-detect the firmware "Cannot open file" wedged-runner state
        # (c64-test-harness PR #88 / runner_health_check). When the U64E
        # runner subsystem is stuck, every subsequent client.run_prg(...)
        # returns the same 404-ish failure shape, and the test would
        # otherwise blow ~10 minutes timing out at the sentinel poll
        # before surfacing it. The helper sends a tiny no-op PRG and
        # raises Ultimate64RunnerStuckError on the wedge signature; we
        # do NOT call recover() (that's a state-changing action that
        # requires explicit user authorization), just surface and exit.
        try:
            runner_health_check(client)
        except Ultimate64RunnerStuckError as exc:
            print(
                f"[fatal] U64E runner wedged at {HOST}: {exc}",
                file=sys.stderr,
            )
            print(
                "[fatal] supervisor: investigate / authorize recover()",
                file=sys.stderr,
            )
            return 3

        # --- REU preflight (issue #97) ---
        # A REU-profile PRG on a device with the REU disabled does not
        # fail: it derives a wrong X25519 shared secret from silently
        # no-op'd DMA and then spins ~44 minutes on the first encrypted
        # record. Check the one setting that decides it, in one REST call,
        # before committing to the run. On-chip builds need no REU and are
        # not checked at all. This never writes device config — see the
        # module docstring for why.
        try:
            preflight_reu(client, LABELS_PATH)
        except ReuPreflightError as exc:
            print(str(exc), file=sys.stderr)
            return 4

        # --- Set turbo BEFORE booting the PRG ---
        # C64 Ultimate quirk (firmware 1.1.0, core 1.49): a runtime CPU
        # speed change via the REST config API can glitch the UCI bridge
        # so that the next pushed command is silently lost — observed as
        # UCI_ERR_NO_SOCKET on the first TCP_CONNECT after a 1->64 MHz
        # switch (2x reproduced; 1->48 happened to survive). Booting at
        # the target speed avoids the mid-session switch entirely and
        # also makes boot speed deterministic (it used to be whatever
        # the previous run left in the device config).
        # Sharper finding (2026-07-29, C64U): the glitch is caused by the
        # config WRITE itself and SURVIVES the reset below — it is not
        # limited to mid-session switches. It also fires on a REDUNDANT
        # write: 3/3 attempts wrote "64" while the device was already at
        # 64 MHz and every one lost its first TCP_CONNECT
        # (UCI_ERR_NO_SOCKET, no SYN on the wire), while the identical PRG
        # at the identical speed passed via a script that performs no
        # config write before its reset. At 48 MHz the same pattern costs
        # only the first attempt.
        #
        # So: read the current state and skip the write entirely when it
        # already matches, and give a genuine change a wider settle.
        # Shape note: the REST config responses wrap their items in a
        # `<Category>` key and put each value directly under the ITEM name
        # — there is no per-item "value" key (an earlier attempt here read
        # `.get("value")` and silently got None/None on a C64U, which made
        # the skip unreachable). Mirror the harness's own get_reu_config:
        # fetch the category, unwrap, index by item name. One request
        # covers both items. `.get(CAT, cat)` tolerates either shape.
        try:
            cat = client.get_config_category(CAT_U64_SPECIFIC)
            inner = cat.get(CAT_U64_SPECIFIC, cat)
            cur_speed = inner.get("CPU Speed")
            cur_turbo = inner.get("Turbo Control")
        except Exception as exc:                      # probe is best-effort
            print(f"  (turbo state probe failed: {exc}; writing anyway)")
            cur_speed = cur_turbo = None

        # str() both sides: cpu_speed_enum returns a str ("48"), but the
        # REST value's type is the firmware's business, not ours — a silent
        # int/str mismatch here would make the skip never fire and quietly
        # restore the old always-write behaviour.
        want_speed = str(cpu_speed_enum(TURBO_MHZ))
        if str(cur_speed) == want_speed and cur_turbo == "Manual":
            print(
                f"Turbo already {TURBO_MHZ} MHz (Manual) — skipping config "
                "write (avoids the C64U bridge glitch; see comment above)"
            )
        else:
            print(
                f"Setting turbo to {TURBO_MHZ} MHz "
                f"(from {cur_turbo}/{cur_speed})..."
            )
            set_turbo_mhz(client, TURBO_MHZ)
            # Wider settle than the historical 0.5 s: the write is what
            # perturbs the bridge, and the first TCP_CONNECT is what pays
            # for it. Overridable for experiments.
            time.sleep(float(os.environ.get("TURBO_SETTLE", "3.0")))

        print("Resetting machine...")
        client.reset()
        time.sleep(2.5)

        print("run_prg(PRG)...")
        client.run_prg(prg)
        # Wait for auto-init (entropy, REU stash, DHCP). Scales with TURBO_MHZ
        # so stock 1 MHz runs allow enough time for entropy + REU sqtab init.
        # C64_INIT_WAIT overrides the base (comb-profile boots run
        # ec_precompute_256: ~30-50 s at 64 MHz — use 90+).
        time.sleep(float(os.environ.get("C64_INIT_WAIT", "22")) * _TIMEOUT_SCALE)

        init_flag = transport.read_memory(labels["net_initialized"], 1)[0]
        print(f"net_initialized = ${init_flag:02X}")
        if init_flag == 0:
            print("WARNING: net_initialized is 0 — auto-init may have failed")

        # (Turbo was set before boot — see the C64U quirk note above.)

        # --- Start 6510 debug-stream capture (before trigger) ---
        if DEBUG_CAPTURE_ENABLED:
            try:
                set_debug_stream_mode(client, DEBUG_MODE_6510)
                debug_cap = DebugCapture(
                    port=DEFAULT_DEBUG_PORT,
                    recv_buf_size=1024 * 1024,
                    max_bytes=50 * 1024 * 1024,  # ~50 MB rolling filtered window
                    filter=_keep_cycle,
                )
                debug_cap.start()
                debug_dest = f"{test_host_ip}:{DEFAULT_DEBUG_PORT}"
                print(f"Starting U64 6510 debug stream -> {debug_dest}")
                client.stream_debug_start(debug_dest)
                debug_started_on_u64 = True
                time.sleep(0.3)
            except Exception as exc:
                print(f"WARNING: debug capture failed to start: {exc}")
                debug_cap = None
        else:
            print("DEBUG_CAPTURE=0 — 6510 stream disabled")

        # Quit PRG main_loop back to BASIC
        print("Sending 'Q' to exit PRG main_loop...")
        send_text(transport, "q\r")
        # Keyboard-buffer polling scales with CPU speed; grace period scales
        # with TURBO_MHZ to keep BASIC-return reliable at stock 1 MHz.
        time.sleep(2.0 * _TIMEOUT_SCALE)

        # DMA-write the routine + data
        CHUNK = 64
        for i in range(0, len(routine_bytes), CHUNK):
            transport.write_memory(
                ROUTINE_ADDR + i,
                routine_bytes[i:i + CHUNK],
            )
        transport.write_memory(HOST_STR_ADDR, host_str.ljust(32, b"\x00"))
        transport.write_memory(PATH_STR_ADDR, path_str.ljust(8, b"\x00"))

        # Clear sentinel area
        transport.write_memory(SENTINEL_ADDR, bytes(16))

        # Trigger via SYS
        sys_line = f"sys{ROUTINE_ADDR}\r"
        print(f"Triggering: {sys_line.strip()}")
        send_text(transport, sys_line)

        # Poll sentinel
        deadline = time.time() + SENTINEL_POLL_TIMEOUT
        last_progress = -1
        start = time.time()
        while time.time() < deadline:
            time.sleep(0.5)
            blob = transport.read_memory(SENTINEL_ADDR, 2)
            sentinel = blob[0]
            progress = blob[1]
            if progress != last_progress:
                elapsed = time.time() - start
                print(f"  [{elapsed:6.1f}s] progress=0x{progress:02X}")
                last_progress = progress
            if sentinel == SENTINEL_VALUE:
                print("  sentinel set — routine complete")
                break
        else:
            print(f"TIMEOUT: sentinel not set after "
                  f"{SENTINEL_POLL_TIMEOUT:.0f}s "
                  f"(progress=0x{last_progress:02X})", file=sys.stderr)
            if server_thread is not None:
                server_thread.join(timeout=1.0)
            _dump_full(transport, labels, server_result, run_dir=run_dir)
            outcome = "TIMEOUT"
            exit_code = 1
            return exit_code

        # --- Results ---
        # Join server thread briefly so server_result is populated
        if server_thread is not None:
            server_thread.join(timeout=5.0)
        _dump_full(transport, labels, server_result, run_dir=run_dir)

        # Reread resp_data + screen_text for the assertion logic below.
        resp_len_raw = transport.read_memory(labels["http_resp_len"], 2)
        resp_len = resp_len_raw[0] | (resp_len_raw[1] << 8)
        read_len = min(resp_len, 200) if resp_len > 0 else 200
        resp_data = bytes(transport.read_memory(labels["http_resp_buf"],
                                                read_len))
        screen = bytes(transport.read_memory(0x0400, 1000))
        screen_text = _decode_screen_ram(screen)

        # --- Assertions ---
        body_ascii = ""
        try:
            body_ascii = resp_data.decode("ascii", errors="replace")
        except Exception:
            pass

        problems = _check_c64_result(body_ascii, screen_text)

        # Server-side corroboration (audit F6). The listener's record is the
        # only evidence in this test the client cannot produce on its own, so
        # a run passes only when both sides agree. Skipped — loudly — under
        # EXTERNAL_LISTENER=1, where by contract there is no inline listener
        # and no server_result to read.
        if EXTERNAL_LISTENER:
            print("\nNOTE: EXTERNAL_LISTENER=1 — server-side criteria "
                  "skipped (no inline listener); C64-side state only")
        else:
            server_problems = _check_server_result(
                server_result,
                expect_host=test_host_ip,
                expect_path=path_str.rstrip(b"\x00").decode("ascii"),
            )
            problems.extend(server_problems)
            if not server_problems:
                print("\nServer-side check: listener completed the handshake "
                      "and decrypted the expected GET")

        if problems:
            print("\nFAIL: pass criteria not met:", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            outcome = "FAIL"
            exit_code = 1
            return exit_code

        print(f"\nPASS: http_resp_buf contains '{EXPECTED_BODY}'")
        outcome = "PASS"
        exit_code = 0
        return exit_code

    finally:
        # --- Stop 6510 debug stream; post-process + persist trace ---
        if debug_started_on_u64 and client is not None:
            try:
                client.stream_debug_stop()
            except Exception as exc:
                print(f"WARNING: stream_debug_stop failed: {exc}")
        trace_bytes_on_disk = 0
        if debug_cap is not None and run_dir is not None:
            cap_result = None
            try:
                cap_result = debug_cap.stop()
            except Exception as exc:
                print(f"WARNING: debug capture stop failed: {exc}")
            if cap_result is not None:
                try:
                    stats = _process_debug_trace(
                        cap_result,
                        summary_path=str(run_dir / "summary.txt"),
                        tail_path=str(run_dir / "tail.txt"),
                        uci_path=str(run_dir / "uci_accesses.txt"),
                    )
                    print(f"\nDebug capture: {stats.get('packets', 0)} pkts, "
                          f"{stats.get('dropped', 0)} dropped, "
                          f"{stats.get('total', 0)} cycles, "
                          f"{stats.get('duration', 0.0):.1f}s "
                          f"(cpu={stats.get('cpu', 0)} vic={stats.get('vic', 0)}; "
                          f"uci_hits={stats.get('uci_total', 0)})")
                except Exception as exc:
                    print(f"WARNING: debug trace post-process failed: {exc}")

                # Persist the raw trace as packed u32-LE, with a JSON
                # sidecar describing the bit layout.
                try:
                    trace_bin = run_dir / "trace.bin"
                    trace_meta = run_dir / "trace.bin.meta.json"
                    tstats = _serialize_trace_packed(
                        cap_result, trace_bin, trace_meta)
                    trace_bytes_on_disk = tstats["bytes_on_disk"]
                    mb = trace_bytes_on_disk / (1024 * 1024)
                    print(f"  raw trace       : {trace_bin} "
                          f"({tstats['cycle_count']} cycles, {mb:.2f} MB)")
                except Exception as exc:
                    print(f"WARNING: raw trace serialize failed: {exc}")

        # --- Persist server-side listener state ---
        if run_dir is not None:
            try:
                _serialize_server_result(
                    server_result, run_dir / "server_result.json")
            except Exception as exc:
                print(f"WARNING: server_result dump failed: {exc}")

        # --- Write run metadata ---
        if run_dir is not None:
            try:
                _write_run_info(
                    run_dir / "run_info.txt",
                    outcome=outcome,
                    duration=time.time() - run_start,
                    exit_code=exit_code,
                    extra={
                        "trace_bytes": trace_bytes_on_disk,
                        "turbo_mhz": TURBO_MHZ,
                        "host": HOST,
                    },
                )
            except Exception as exc:
                print(f"WARNING: run_info write failed: {exc}")

            # Print run dir prominently for operator / test harness.
            print(f"\nDebug artifacts: {run_dir}")
            # Optional: drop the run dir on PASS unless the operator
            # asked to keep it. 5-dir rotation still applies regardless.
            if outcome == "PASS" and not UCI_DEBUG_KEEP_ON_PASS:
                try:
                    shutil.rmtree(run_dir)
                    print(f"(removed on PASS; set KEEP_DEBUG_ON_PASS=1 to "
                          f"retain)")
                except Exception as exc:
                    print(f"WARNING: failed to remove PASS run dir: {exc}")

        if uci_enabled and client is not None:
            print("\nDisabling UCI...")
            try:
                disable_uci(client)
            except Exception as exc:
                print(f"WARNING: disable_uci failed: {exc}")
        lock.release()
        print(f"Released DeviceLock({HOST})")


def _check_artifact_main(argv: list[str]) -> int:
    """`--check-artifact <run-dir|server_result.json> [--host IP] [--path P]`

    Re-run the server-side pass criteria (audit F6) against an archived run
    without touching hardware. Exists so the criteria are testable — and so a
    stored run can be re-adjudicated after the criteria change.
    """
    if not argv:
        print("usage: test_https_local.py --check-artifact "
              "<run-dir|server_result.json> [--host IP] [--path P]",
              file=sys.stderr)
        return 2
    target = Path(argv[0])
    host: str | None = None
    path = "/"
    rest = argv[1:]
    while rest:
        flag = rest.pop(0)
        if flag == "--host" and rest:
            host = rest.pop(0)
        elif flag == "--path" and rest:
            path = rest.pop(0)
        else:
            print(f"unknown argument: {flag}", file=sys.stderr)
            return 2

    if target.is_dir():
        target = target / "server_result.json"

    # Fail closed: an absent or unreadable record is an inconclusive check,
    # never an implicit "no error recorded". Same defect shape as the F5/F6
    # fallbacks themselves, one layer up.
    if not target.is_file():
        print(f"FAIL: no server_result.json at {target} — the server-side "
              f"record is missing, which is not a pass", file=sys.stderr)
        return 1
    try:
        server_result = json.loads(target.read_text())
    except Exception as exc:
        print(f"FAIL: could not read {target}: {exc}", file=sys.stderr)
        return 1
    if not isinstance(server_result, dict):
        print(f"FAIL: {target} is not a JSON object "
              f"(got {type(server_result).__name__})", file=sys.stderr)
        return 1
    print(f"server_result   : {target}")
    print(f"  listening     : {server_result.get('listening', False)}")
    print(f"  client_addr   : {server_result.get('client_addr')}")
    print(f"  request       : {_server_request_bytes(server_result)!r}")
    print(f"  error         : {server_result.get('error', '<none>')}")
    if host is None:
        print("  (no --host given; the Host-header check is skipped)")

    problems = _check_server_result(
        server_result, expect_host=host, expect_path=path)
    if problems:
        print("\nFAIL: server-side criteria not met:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print("\nPASS: server-side criteria met")
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--check-artifact":
        raise SystemExit(_check_artifact_main(sys.argv[2:]))
    raise SystemExit(main())
