#!/usr/bin/env python3
"""test_https_bad_finished.py — the client must refuse a forged server Finished.

Audit finding F2: the client verifies the server's Finished HMAC and aborts on
mismatch (``tls_verify_finished`` in ``src/tls_keyschedule.s``, ``bcs
@enc_error`` in ``src/tls13.s``), but nothing in the repo ever exercised the
abort. Every listener the suite talks to sends a *correct* Finished, so the
mismatch branch was dead weight as far as the tests were concerned — confirmed
by mutation: inverting it (``sec`` -> ``clc``) left the full hardware e2e
reaching HTTP 200 with the correct body.

This test closes that hole end-to-end on real hardware. It points the C64 at
``tools/https_e2e/evil_listener.py``, a hand-rolled TLS 1.3 server that emits a
completely valid flight — real X25519 ECDHE, real key schedule, real
ChaCha20-Poly1305 records, real P-256 CertificateVerify — with exactly one bit
flipped in the server Finished ``verify_data`` before encryption. The AEAD tag
is correct, so the client cannot bail out at the record layer; it has to reach
the HMAC comparison to notice anything is wrong.

Why not just corrupt the ciphertext: that breaks the Poly1305 tag, the client
rejects at ``aead_decrypt``, and the Finished comparison never runs. That would
pass this test while proving nothing about F2.

Two modes, selected by ``FINISHED_MODE``:

  ``bad``  (default) the server sends the corrupted Finished. PASS requires the
           client to abort *at Finished*.
  ``good`` the identical server sends a correct Finished. PASS requires a
           complete handshake and HTTP 200. This is the control: it proves the
           hand-rolled server is a working TLS 1.3 server, so an abort in
           ``bad`` mode is attributable to the one flipped bit and not to a
           fixture that simply cannot talk to the client.

Run ``good`` before trusting a ``bad`` result.

Oracle
------
Both directions are asserted, from both sides of the wire.

C64 side — ``src/tls13.s:@error`` stashes the state it died in:

    bad  : tls_state == $FF (ERROR) and tls_last_state == 6 (FINISHED)
           and http_status != 200
    good : tls_state != $FF (ERROR) and http_status == 200 and the body

(Not ``tls_state == CONNECTED`` for the good run: ``http_get``'s success path
calls ``tls_close``, which puts the state back to IDLE.)

``tls_last_state`` is what makes this precise rather than merely negative: it
distinguishes "aborted at Finished" from "aborted earlier at Certificate (4) or
CertificateVerify (5)". A test that only checked "handshake failed" would pass
for a fixture that produced a broken certificate.

Server side — evidence the client cannot fabricate, recorded in
``server_result.json``:

    bad  : client_accepted_finished is False (the client never sent its own
           Finished), and finished_corrupted is True
    good : client_accepted_finished is True, client_finished_valid is True,
           response_sent is True

Note the server folds the Finished it actually sent into its own transcript, so
a client that wrongly *accepts* the corrupted Finished stays in lockstep and
sails on to HTTP 200. A broken client therefore fails fast and unambiguously
instead of hanging until the sentinel timeout.

Environment
-----------
  U64_HOST              U64E / C64U address (default 192.168.1.81)
  FINISHED_MODE         bad (default) | good
  TURBO_MHZ             C64 CPU MHz (default 48); timeouts auto-scale
  HTTPS_PORT            listener port (default 4433)
  SENTINEL_POLL_TIMEOUT / ACCEPT_TIMEOUT   per-test overrides, seconds
  C64_INIT_WAIT         boot/auto-init wait before triggering (default 22 s,
                        scaled); comb-profile builds need 90+
  UCI_DEBUG_DIR         artifact base dir (default /tmp/uci_bad_finished)

Exit codes: 0 pass, 1 fail, 2 setup error, 3 device wedged.
"""
from __future__ import annotations

import datetime
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

from c64_test_harness.backends.device_lock import DeviceLock, DeviceLockTimeout
from c64_test_harness.backends.ultimate64 import Ultimate64Transport
from c64_test_harness.backends.ultimate64_client import Ultimate64Client
from c64_test_harness.backends.ultimate64_helpers import (
    set_turbo_mhz,
    runner_health_check,
    Ultimate64RunnerStuckError,
    CAT_U64_SPECIFIC,
    cpu_speed_enum,
)
from c64_test_harness.uci_network import enable_uci, disable_uci
from c64_test_harness.keyboard import send_text
from c64_test_harness.labels import Labels

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _memory_policy import (  # noqa: E402
    build_policy_and_arbiter_with_overlay_carveout,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools" / "https_e2e"))
from evil_listener import (  # noqa: E402
    DEFAULT_BODY,
    serve_one_connection,
)
from https_listener import _ensure_certs_p256  # noqa: E402

HOST = os.environ.get("U64_HOST", "192.168.1.81")
PRG_PATH = REPO_ROOT / "build" / "c64-https.prg"
LABELS_PATH = REPO_ROOT / "build" / "labels.txt"

MODE_ENV = os.environ.get("FINISHED_MODE", "bad").lower()
if MODE_ENV not in ("bad", "good"):
    print(f"ERROR: FINISHED_MODE must be 'bad' or 'good', got {MODE_ENV!r}",
          file=sys.stderr)
    sys.exit(2)
SERVER_MODE = "bad_finished" if MODE_ENV == "bad" else "good"

TURBO_MHZ = int(os.environ.get("TURBO_MHZ", "48"))
_TIMEOUT_SCALE = max(1.0, 48.0 / float(TURBO_MHZ))
SENTINEL_POLL_TIMEOUT = float(
    os.environ.get("SENTINEL_POLL_TIMEOUT", str(600.0 * _TIMEOUT_SCALE))
)
ACCEPT_TIMEOUT = float(
    os.environ.get("ACCEPT_TIMEOUT", str(600.0 * _TIMEOUT_SCALE))
)
HTTPS_PORT = int(os.environ.get("HTTPS_PORT", "4433"))
ARTIFACT_BASE = Path(os.environ.get("UCI_DEBUG_DIR", "/tmp/uci_bad_finished"))

SENTINEL_VALUE = 0xAA

# TLS_STATE_* from src/constants.inc
TLS_STATE_CERTIFICATE = 4
TLS_STATE_CERT_VERIFY = 5
TLS_STATE_FINISHED = 6
TLS_STATE_CONNECTED = 7
TLS_STATE_ERROR = 0xFF

_STATE_NAMES = {
    0: "IDLE", 1: "CLIENT_HELLO", 2: "SERVER_HELLO", 3: "ENCRYPTED_EXT",
    4: "CERTIFICATE", 5: "CERT_VERIFY", 6: "FINISHED", 7: "CONNECTED",
    0xFF: "ERROR",
}


def _state_name(v: int) -> str:
    return f"{_STATE_NAMES.get(v, '?')} (${v:02X})"


# Arbiter-assigned; see the long note in test_https_local.py about why these
# must never be hardcoded.
ROUTINE_ADDR = HOST_STR_ADDR = PATH_STR_ADDR = -1
SENTINEL_ADDR = PROGRESS_ADDR = CARRY_FLAG_ADDR = -1


def _detect_local_ip(target: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 80))
        return s.getsockname()[0]
    finally:
        s.close()


def _try_bind(bind_ip: str, port: int) -> socket.socket | None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((bind_ip, port))
    except OSError:
        srv.close()
        return None
    return srv


def _build_http_routine(labels: dict[str, int], port: int) -> tuple[bytes, int]:
    """6502 stub: set up http_get's inputs, call it, latch carry, signal done.

    Mirrors tools/uci/test_https_local.py's routine — same real code path
    (``http_get`` -> ``tls_connect``), so the only thing this test changes
    relative to the passing e2e is what the server puts on the wire.
    """
    code = bytearray()

    def emit(*bs: int) -> None:
        code.extend(bs)

    def emit_lda_imm(v: int) -> None:
        emit(0xA9, v & 0xFF)

    def emit_sta_abs(a: int) -> None:
        emit(0x8D, a & 0xFF, (a >> 8) & 0xFF)

    def emit_lda_abs(a: int) -> None:
        emit(0xAD, a & 0xFF, (a >> 8) & 0xFF)

    def emit_jsr(a: int) -> None:
        emit(0x20, a & 0xFF, (a >> 8) & 0xFF)

    def emit_progress(step: int) -> None:
        emit_lda_imm(step)
        emit_sta_abs(PROGRESS_ADDR)

    # Bank BASIC ROM out so $A000-$BFFF reads as RAM (crypto/TLS BSS lives
    # there; without this the later DMA reads would return ROM bytes).
    emit_lda_abs(0x0001)
    emit(0x29, 0xFE)
    emit_sta_abs(0x0001)

    emit_lda_imm(0x00)
    emit_sta_abs(SENTINEL_ADDR)
    emit_sta_abs(PROGRESS_ADDR)
    emit_sta_abs(CARRY_FLAG_ADDR)

    emit_progress(0x01)
    emit_jsr(labels["net_init"])

    emit_lda_imm(0x00)
    emit_sta_abs(labels["tcp_recv_head"])
    emit_sta_abs(labels["tcp_recv_head"] + 1)
    emit_sta_abs(labels["tcp_recv_tail"])
    emit_sta_abs(labels["tcp_recv_tail"] + 1)

    emit_progress(0x02)

    emit_lda_imm(HOST_STR_ADDR & 0xFF)
    emit_sta_abs(labels["http_host_ptr"])
    emit_lda_imm((HOST_STR_ADDR >> 8) & 0xFF)
    emit_sta_abs(labels["http_host_ptr"] + 1)

    host_len_patch_offset = len(code) + 1
    emit_lda_imm(0x00)
    emit_sta_abs(labels["http_host_len"])

    emit_lda_imm(PATH_STR_ADDR & 0xFF)
    emit_sta_abs(labels["http_path_ptr"])
    emit_lda_imm((PATH_STR_ADDR >> 8) & 0xFF)
    emit_sta_abs(labels["http_path_ptr"] + 1)
    emit_lda_imm(1)
    emit_sta_abs(labels["http_path_len"])

    emit_lda_imm(port & 0xFF)
    emit_sta_abs(labels["http_port"])
    emit_lda_imm((port >> 8) & 0xFF)
    emit_sta_abs(labels["http_port"] + 1)

    emit_progress(0x03)
    emit_jsr(labels["http_get"])

    # Latch the carry into RAM rather than reading the CPU status register
    # over the wire. PHP/PLA puts the whole P register in A; bit 0 is C.
    emit(0x08)                       # PHP
    emit(0x68)                       # PLA
    emit_sta_abs(CARRY_FLAG_ADDR)

    emit_progress(0x04)
    emit_lda_imm(SENTINEL_VALUE)
    emit_sta_abs(SENTINEL_ADDR)
    emit_progress(0x05)

    park = ROUTINE_ADDR + len(code)
    emit(0x4C, park & 0xFF, (park >> 8) & 0xFF)
    return bytes(code), host_len_patch_offset


def _decode_screen_ram(data: bytes) -> str:
    """Screen codes -> ASCII, 40 columns."""
    out = []
    for row in range(min(25, len(data) // 40)):
        line = []
        for col in range(40):
            c = data[row * 40 + col]
            if c == 0x20 or c == 0x00:
                line.append(" ")
            elif 0x01 <= c <= 0x1A:
                line.append(chr(ord("A") + c - 1))
            elif 0x30 <= c <= 0x39:
                line.append(chr(c))
            elif c == 0x2E:
                line.append(".")
            elif c == 0x2D:
                line.append("-")
            elif c == 0x3A:
                line.append(":")
            elif c == 0x2F:
                line.append("/")
            else:
                line.append(".")
        out.append("".join(line).rstrip())
    return "\n".join(out)


def _read_c64_state(transport, labels) -> dict:
    def rd(name: str, n: int = 1) -> bytes:
        return bytes(transport.read_memory(labels[name], n))

    resp_len_raw = rd("http_resp_len", 2)
    resp_len = resp_len_raw[0] | (resp_len_raw[1] << 8)
    status_raw = rd("http_status", 2)
    read_len = min(resp_len, 200) if resp_len > 0 else 64
    return {
        "tls_state": rd("tls_state")[0],
        "tls_last_state": rd("tls_last_state")[0],
        "http_status": status_raw[0] | (status_raw[1] << 8),
        "http_resp_len": resp_len,
        "http_resp_buf": bytes(
            transport.read_memory(labels["http_resp_buf"], read_len)
        ),
        "net_last_error": (
            rd("net_last_error")[0] if "net_last_error" in labels else None
        ),
    }


def _write_artifacts(run_dir: Path, *, server_result: dict, c64: dict,
                     screen_text: str, mode: str, outcome: str,
                     reasons: list[str]) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    serialisable = dict(server_result)
    for k, v in list(serialisable.items()):
        if isinstance(v, (bytes, bytearray)):
            serialisable[k] = v.decode("latin-1")
        elif isinstance(v, tuple):
            serialisable[k] = list(v)
    (run_dir / "server_result.json").write_text(
        json.dumps(serialisable, indent=2, default=str)
    )
    c64_json = dict(c64)
    if isinstance(c64_json.get("http_resp_buf"), (bytes, bytearray)):
        c64_json["http_resp_buf"] = c64_json["http_resp_buf"].decode(
            "ascii", errors="replace"
        )
    (run_dir / "c64_state.json").write_text(json.dumps(c64_json, indent=2))
    (run_dir / "screen.txt").write_text(screen_text)
    (run_dir / "run_info.txt").write_text(
        f"mode      : {mode}\n"
        f"outcome   : {outcome}\n"
        f"host      : {HOST}\n"
        f"turbo_mhz : {TURBO_MHZ}\n"
        f"reasons   :\n" + "".join(f"  - {r}\n" for r in reasons)
    )


def _evaluate(mode: str, server_result: dict, c64: dict,
              screen_text: str) -> tuple[bool, list[str]]:
    """Return (passed, reasons). Every criterion is reported, pass or fail."""
    reasons: list[str] = []
    ok = True

    def check(cond: bool, msg: str) -> None:
        nonlocal ok
        reasons.append(("OK   " if cond else "FAIL ") + msg)
        if not cond:
            ok = False

    err = server_result.get("error")
    check(not err, f"server reported no error (error={err!r})")
    check(bool(server_result.get("client_hello_seen")),
          "server received a ClientHello")
    check(bool(server_result.get("server_flight_sent")),
          "server sent its full handshake flight")

    body = c64.get("http_resp_buf", b"").decode("ascii", errors="replace")

    if mode == "bad":
        check(bool(server_result.get("finished_corrupted")),
              "server actually corrupted the Finished verify_data")
        check(server_result.get("client_accepted_finished") is False,
              "client did NOT send its own Finished "
              f"(reaction: {server_result.get('client_reaction')!r})")
        check(c64["tls_state"] == TLS_STATE_ERROR,
              f"tls_state is ERROR (got {_state_name(c64['tls_state'])})")
        check(c64["tls_last_state"] == TLS_STATE_FINISHED,
              "abort happened AT Finished, not earlier "
              f"(tls_last_state = {_state_name(c64['tls_last_state'])})")
        check(c64["http_status"] != 200,
              f"no HTTP 200 was parsed (http_status={c64['http_status']})")
        check(DEFAULT_BODY not in body,
              "response body was not received")
        check(DEFAULT_BODY.upper() not in screen_text.upper(),
              "response body did not reach the screen either")
    else:
        check(server_result.get("client_accepted_finished") is True,
              "client sent its own Finished")
        check(server_result.get("client_finished_valid") is True,
              "client Finished verified against the server's expectation")
        check(bool(server_result.get("response_sent")),
              "server sent the HTTP response")
        req = server_result.get("request") or b""
        if isinstance(req, str):
            req = req.encode("latin-1")
        check(req.startswith(b"GET "),
              f"server decrypted a GET request ({req[:40]!r})")
        # NOT `== CONNECTED`: on the success path http_get calls tls_close,
        # which sets tls_state back to IDLE (src/tls13.s:tls_close). CONNECTED
        # is only observable mid-flight. What matters here is that the
        # handshake never took the error path — measured on hardware, where
        # the naive CONNECTED assertion failed a genuinely passing run.
        check(c64["tls_state"] != TLS_STATE_ERROR,
              f"tls_state is not ERROR (got {_state_name(c64['tls_state'])})")
        check(c64["http_status"] == 200,
              f"http_status is 200 (got {c64['http_status']})")
        check(DEFAULT_BODY in body,
              f"http_resp_buf holds the expected body ({body[:40]!r})")

    return ok, reasons


def main() -> int:
    if not PRG_PATH.is_file() or not LABELS_PATH.is_file():
        print(f"ERROR: build artifacts missing; run `make BACKEND=uci` first",
              file=sys.stderr)
        return 2

    labels = dict(Labels.from_file(LABELS_PATH))
    required = [
        "http_get", "http_host_ptr", "http_host_len",
        "http_path_ptr", "http_path_len", "http_port",
        "net_init", "net_initialized",
        "tcp_recv_head", "tcp_recv_tail",
        "http_resp_buf", "http_resp_len", "http_status",
        "tls_state", "tls_last_state",
    ]
    missing = [n for n in required if n not in labels]
    if missing:
        # A missing label is a broken test, not a skippable one (finding F3).
        print(f"ERROR: missing labels: {missing}", file=sys.stderr)
        return 2

    print(f"=== HTTPS bad-Finished e2e ({MODE_ENV.upper()} mode) ===")
    print(f"Device       : {HOST} @ {TURBO_MHZ} MHz")
    print(f"Server mode  : {SERVER_MODE}")
    print(f"PRG          : {PRG_PATH}")

    global ROUTINE_ADDR, HOST_STR_ADDR, PATH_STR_ADDR
    global SENTINEL_ADDR, PROGRESS_ADDR, CARRY_FLAG_ADDR
    memory_policy, arbiter = build_policy_and_arbiter_with_overlay_carveout(
        LABELS_PATH, PRG_PATH,
    )
    ROUTINE_ADDR = arbiter.alloc(256, name="trampoline")
    HOST_STR_ADDR = arbiter.alloc(64, name="host_str")
    PATH_STR_ADDR = arbiter.alloc(64, name="path_str")
    SENTINEL_ADDR = arbiter.alloc(1, name="sentinel")
    PROGRESS_ADDR = arbiter.alloc(1, name="progress")
    CARRY_FLAG_ADDR = arbiter.alloc(1, name="carry_flag")
    for base, last, note in arbiter.allocations:
        print(f"  ${base:04X}-${last:04X}  {note}")

    cert_path, key_path = _ensure_certs_p256()
    test_host_ip = _detect_local_ip(HOST)
    srv = _try_bind(test_host_ip, HTTPS_PORT)
    if srv is None:
        print(f"ERROR: could not bind {test_host_ip}:{HTTPS_PORT}",
              file=sys.stderr)
        return 2
    print(f"Listener     : {test_host_ip}:{HTTPS_PORT} (cert {cert_path})")

    server_result: dict = {}
    server_thread = threading.Thread(
        target=serve_one_connection,
        args=(srv, cert_path, key_path),
        kwargs=dict(mode=SERVER_MODE, body=DEFAULT_BODY,
                    timeout=ACCEPT_TIMEOUT, result=server_result),
        daemon=True,
    )
    server_thread.start()
    for _ in range(100):
        if server_result.get("listening"):
            break
        time.sleep(0.05)
    else:
        print("ERROR: listener failed to come up", file=sys.stderr)
        return 2

    routine_raw, host_len_patch = _build_http_routine(labels, HTTPS_PORT)
    routine = bytearray(routine_raw)
    host_bytes = test_host_ip.encode("ascii")
    routine[host_len_patch] = len(host_bytes)
    routine = bytes(routine)

    prg = PRG_PATH.read_bytes()
    run_dir = ARTIFACT_BASE / datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    lock = DeviceLock(HOST)
    try:
        lock.acquire_or_raise(timeout=300.0)
    except DeviceLockTimeout as exc:
        print(f"[fatal] DeviceLock({HOST}): {exc}", file=sys.stderr)
        return 2
    print(f"Acquired DeviceLock({HOST})")

    client: Ultimate64Client | None = None
    uci_enabled = False
    try:
        client = Ultimate64Client(host=HOST, timeout=15.0)
        transport = Ultimate64Transport(host=HOST, timeout=15.0, client=client)
        transport.memory_policy = memory_policy

        print("Enabling UCI...")
        enable_uci(client)
        uci_enabled = True

        try:
            runner_health_check(client)
        except Ultimate64RunnerStuckError as exc:
            print(f"[fatal] runner wedged at {HOST}: {exc}", file=sys.stderr)
            return 3

        # Set turbo BEFORE boot, and skip a redundant write — the config write
        # itself is what glitches the UCI bridge on a C64U (see the long note
        # in test_https_local.py and the c64u_starlight_device memory).
        try:
            cat = client.get_config_category(CAT_U64_SPECIFIC)
            inner = cat.get(CAT_U64_SPECIFIC, cat)
            cur_speed, cur_turbo = inner.get("CPU Speed"), inner.get("Turbo Control")
        except Exception as exc:
            print(f"  (turbo probe failed: {exc}; writing anyway)")
            cur_speed = cur_turbo = None
        if str(cur_speed) == str(cpu_speed_enum(TURBO_MHZ)) and cur_turbo == "Manual":
            print(f"Turbo already {TURBO_MHZ} MHz — skipping config write")
        else:
            print(f"Setting turbo {cur_turbo}/{cur_speed} -> {TURBO_MHZ} MHz")
            set_turbo_mhz(client, TURBO_MHZ)
            time.sleep(float(os.environ.get("TURBO_SETTLE", "3.0")))

        print("Resetting machine...")
        client.reset()
        time.sleep(2.5)

        print("run_prg(PRG)...")
        client.run_prg(prg)
        time.sleep(float(os.environ.get("C64_INIT_WAIT", "22")) * _TIMEOUT_SCALE)

        init_flag = transport.read_memory(labels["net_initialized"], 1)[0]
        print(f"net_initialized = ${init_flag:02X}")
        if init_flag == 0:
            print("WARNING: net_initialized is 0 — auto-init may have failed")

        print("Sending 'Q' to exit main_loop...")
        send_text(transport, "q\r")
        time.sleep(2.0 * _TIMEOUT_SCALE)

        for i in range(0, len(routine), 64):
            transport.write_memory(ROUTINE_ADDR + i, routine[i:i + 64])
        transport.write_memory(HOST_STR_ADDR, (host_bytes + b"\x00").ljust(32, b"\x00"))
        transport.write_memory(PATH_STR_ADDR, b"/\x00".ljust(8, b"\x00"))
        transport.write_memory(SENTINEL_ADDR, bytes(16))

        print(f"Triggering: sys{ROUTINE_ADDR}")
        send_text(transport, f"sys{ROUTINE_ADDR}\r")

        deadline = time.time() + SENTINEL_POLL_TIMEOUT
        start = time.time()
        last_progress = -1
        completed = False
        while time.time() < deadline:
            time.sleep(0.5)
            blob = transport.read_memory(SENTINEL_ADDR, 2)
            if blob[1] != last_progress:
                print(f"  [{time.time() - start:6.1f}s] progress=0x{blob[1]:02X}")
                last_progress = blob[1]
            if blob[0] == SENTINEL_VALUE:
                completed = True
                print(f"  sentinel set after {time.time() - start:.1f}s")
                break

        server_thread.join(timeout=10.0)

        c64 = _read_c64_state(transport, labels)
        screen_text = _decode_screen_ram(
            bytes(transport.read_memory(0x0400, 1000))
        )

        print("\n--- C64 state ---")
        print(f"  tls_state       = {_state_name(c64['tls_state'])}")
        print(f"  tls_last_state  = {_state_name(c64['tls_last_state'])}")
        print(f"  http_status     = {c64['http_status']}")
        print(f"  http_resp_len   = {c64['http_resp_len']}")
        print(f"  http_resp_buf   = "
              f"{c64['http_resp_buf'][:48].decode('ascii', 'replace')!r}")
        print("\n--- server saw ---")
        for k, v in server_result.items():
            print(f"  {k:26s} = {v!r}")
        print("\n--- screen ---")
        print(screen_text)

        if not completed:
            # The 6502 stub never signalled completion, so http_get is still
            # running or wedged. We cannot say what the client decided —
            # inconclusive is a failure, never a pass.
            reasons = [f"FAIL  routine did not complete within "
                       f"{SENTINEL_POLL_TIMEOUT:.0f}s "
                       f"(progress=0x{last_progress:02X}) — inconclusive"]
            passed = False
        else:
            passed, reasons = _evaluate(MODE_ENV, server_result, c64, screen_text)

        outcome = "PASS" if passed else "FAIL"
        print(f"\n--- criteria ({MODE_ENV} mode) ---")
        for r in reasons:
            print(f"  {r}")
        _write_artifacts(run_dir, server_result=server_result, c64=c64,
                         screen_text=screen_text, mode=MODE_ENV,
                         outcome=outcome, reasons=reasons)
        print(f"\nArtifacts: {run_dir}")
        print(f"\n{outcome}: "
              + ("client rejected the forged server Finished"
                 if passed and MODE_ENV == "bad" else
                 "handshake completed against the control listener"
                 if passed else
                 "see failed criteria above"))
        return 0 if passed else 1

    finally:
        if uci_enabled and client is not None:
            try:
                disable_uci(client)
            except Exception as exc:
                print(f"WARNING: disable_uci failed: {exc}")
        try:
            lock.release()
        except Exception:
            pass
        try:
            srv.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
