#!/usr/bin/env python3
"""test_tls_connected_latch.py - the CONNECTED high-water latch (issue #204).

Why this exists
---------------
``tls_state`` holds ``TLS_STATE_CONNECTED`` only between the store at the end
of ``tls_connect`` and ``tls_close``, which writes IDLE back over it. At 48 MHz
that window fits inside one rig poll, so the RR-Net rig's CONNECTED oracle was
outrun on a run that had in fact connected (#204). ``tls_reached_connected``
is a one-byte latch that records the fact durably:

  * cleared by ``do_https_get`` before DNS, and by ``tls_connect`` at entry,
    so each attempt starts from 0;
  * set to ``TLS_STATE_CONNECTED`` at tls_connect's CONNECTED store, and
    nowhere else;
  * never written by ``tls_close`` or by tls_connect's error path.

What this drives
----------------
No network. Every routine ``tls_connect`` calls is patched in RAM to
``CLC/RTS`` (or ``SEC/RTS`` for the step chosen to fail), so what runs is
``tls_connect``'s own state machine -- the code that carries the latch
stores -- and the real ``tls_close``. Patches are restored after each case.

Cases, run in this order in one VICE session so the attempt-to-attempt
sequencing is the real one:

  success               C=0, tls_state=CONNECTED, latch=CONNECTED
  after tls_close       tls_state=IDLE (moved on), latch still CONNECTED
  fail at last step     starts from the latch the success left set;
                        tls_derive_traffic_keys fails -> C=1, tls_state=ERROR,
                        tls_last_state=FINISHED (the walk reached the step
                        right before CONNECTED), latch=0
  fail at first step    latch poisoned -> ClientHello send fails -> latch=0
  success after failure latch 0 -> CONNECTED (not stuck)
  mid-attempt probe     latch starts CONNECTED; tls_send_client_hello is
                        replaced by a probe that records the latch -> 0
                        (the clear is at entry, not only on the error path)
  do_https_get, DNS fails   latch set to CONNECTED as a previous attempt
                        would leave it; tls_connect replaced by a tripwire
                        that would overwrite tls_state; afterwards tls_state
                        is untouched (tls_connect never ran) and latch=0 --
                        the pre-DNS clear is what separates the attempts

On a tree without the latch the label is missing and the suite FAILS (exit
1); a missing label is never a skip.

Usage:
    python3 tools/test_tls_connected_latch.py [--verbose]

Env:
    C64_SKIP_BUILD=1   reuse the already-built PRG (either backend)

Requires: Python 3.10+, c64_test_harness, VICE x64sc
"""

from __future__ import annotations

import os
import subprocess
import sys

from c64_test_harness import (
    Labels, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _vice_helpers import default_vice_config  # noqa: E402
from _skip_policy import verdict  # noqa: E402

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

# src/constants.inc
TLS_STATE_IDLE = 0x00
TLS_STATE_CLIENT_HELLO = 0x01
TLS_STATE_FINISHED = 0x06
TLS_STATE_CONNECTED = 0x07
TLS_STATE_ERROR = 0xFF

# Every routine tls_connect JSRs, in call order. tls_deframe_init exists
# only on TLS_STREAM_DEFRAME (uci) builds and is patched when present.
TLS_CONNECT_CALLEES = [
    "drbg_fill_bytes",
    "tls_ecdh_generate_keypair",
    "tls_send_client_hello",
    "tls_recv_server_hello",
    "tls_transcript_hash",
    "tls_derive_handshake_keys",
    "tls_recv_encrypted",
    "tls_send_finished",
    "tls_derive_traffic_keys",
]
OPTIONAL_CALLEES = ["tls_deframe_init"]

REQUIRED_LABELS = [
    "tls_reached_connected",
    "tls_state",
    "tls_last_state",
    "tls_connect",
    "tls_close",
    "do_https_get",
    "net_initialized",
    "net_dns_resolve",
] + TLS_CONNECT_CALLEES

# Cassette buffer. Harness jsr() trampoline $0334, run_all_tests.py's loop
# $0339, run_subroutine's U64 trampoline $0360-$036D and flags $03F0/$03F1,
# test_finished_verify.py $0340-$0350, test_body_truncation.py $0380-$03B1.
# $03C0-$03CB collides with none of them.
DRIVER_ADDR = 0x03C0      # 10 B -> $03C9
CARRY_ADDR = 0x03CA
PROBE_ADDR = 0x03CB       # latch value seen mid-attempt (probe case)

POISON = 0xA5
CLC_RTS = bytes([0x18, 0x60])
SEC_RTS = bytes([0x38, 0x60])


def _lohi(addr: int) -> tuple[int, int]:
    return addr & 0xFF, (addr >> 8) & 0xFF


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
                f"{what}: readback mismatch at ${addr:04X} - wrote "
                f"{data.hex()}, read {back.hex()}")

    def restore(self) -> None:
        for addr, original in reversed(self.saved):
            write_bytes(self.transport, addr, original)
        self.saved.clear()


def assert_shadow_ram_readable(transport, labels) -> None:
    """FATAL unless the latch's address reads back as RAM, not BASIC ROM.

    The latch lives in $A000-$BFFF. If the monitor reads ROM there, every
    value below is a ROM byte -- a result measuring nothing.
    """
    addr = labels["tls_reached_connected"]
    original = read_bytes(transport, addr, 1)
    for probe in (0x5A, 0xA5):
        write_bytes(transport, addr, bytes([probe]))
        got = read_bytes(transport, addr, 1)[0]
        if got != probe:
            raise RuntimeError(
                f"shadow RAM not readable at tls_reached_connected "
                f"(${addr:04X}): wrote ${probe:02X}, read ${got:02X}. "
                f"Inconclusive, not a pass.")
    write_bytes(transport, addr, original)


def poke(transport, labels, name: str, value: int) -> None:
    write_bytes(transport, labels[name], bytes([value]))


def peek(transport, labels, name: str) -> int:
    return read_bytes(transport, labels[name], 1)[0]


def call(transport, p: Patcher, target: int) -> int:
    """JSR *target* via a driver that latches the carry; return it."""
    t_lo, t_hi = _lohi(target)
    c_lo, c_hi = _lohi(CARRY_ADDR)
    p.patch(DRIVER_ADDR, bytes([
        0x20, t_lo, t_hi,       # JSR target
        0xA9, 0x00,             # LDA #0
        0x2A,                   # ROL A   (carry -> bit 0)
        0x8D, c_lo, c_hi,       # STA carry
        0x60,                   # RTS
    ]), "driver")
    p.patch(CARRY_ADDR, bytes([POISON]), "carry latch")
    jsr(transport, DRIVER_ADDR, timeout=60.0)
    carry = read_bytes(transport, CARRY_ADDR, 1)[0]
    if carry not in (0, 1):
        raise RuntimeError(
            f"carry latch never written (read ${carry:02X}) - the driver did "
            f"not complete; inconclusive, not a pass")
    return carry


def stub_callees(p: Patcher, labels, fail_at: str | None) -> None:
    names = TLS_CONNECT_CALLEES + [n for n in OPTIONAL_CALLEES
                                   if labels.address(n) is not None]
    for name in names:
        p.patch(labels[name], SEC_RTS if name == fail_at else CLC_RTS,
                f"{name} stub")


def run_tls_connect(transport, labels, fail_at: str | None,
                    latch_before: int, probe: bool = False) -> dict:
    p = Patcher(transport)
    try:
        stub_callees(p, labels, fail_at)
        if probe:
            # tls_send_client_hello -> LDA latch / STA probe / CLC / RTS:
            # records the latch as the attempt sees it, before any outcome.
            l_lo, l_hi = _lohi(labels["tls_reached_connected"])
            s_lo, s_hi = _lohi(PROBE_ADDR)
            p.patch(labels["tls_send_client_hello"],
                    bytes([0xAD, l_lo, l_hi, 0x8D, s_lo, s_hi, 0x18, 0x60]),
                    "mid-attempt latch probe")
            p.patch(PROBE_ADDR, bytes([POISON]), "probe byte")
        poke(transport, labels, "tls_reached_connected", latch_before)
        poke(transport, labels, "tls_state", 0x42)
        poke(transport, labels, "tls_last_state", 0x42)
        carry = call(transport, p, labels["tls_connect"])
        r = {
            "carry": carry,
            "state": peek(transport, labels, "tls_state"),
            "last": peek(transport, labels, "tls_last_state"),
            "latch": peek(transport, labels, "tls_reached_connected"),
        }
        if probe:
            r["mid"] = read_bytes(transport, PROBE_ADDR, 1)[0]
        return r
    finally:
        p.restore()


def run_tls_close(transport, labels) -> dict:
    p = Patcher(transport)
    try:
        call(transport, p, labels["tls_close"])
        return {
            "state": peek(transport, labels, "tls_state"),
            "latch": peek(transport, labels, "tls_reached_connected"),
        }
    finally:
        p.restore()


def run_https_get_dns_fail(transport, labels) -> dict:
    """do_https_get with the network 'up' and DNS failing."""
    p = Patcher(transport)
    try:
        p.patch(labels["net_dns_resolve"], SEC_RTS, "net_dns_resolve stub")
        p.patch(labels["net_initialized"], b"\x01", "net_initialized")
        # tls_connect replaced by LDA #$EE / STA tls_state / SEC / RTS: if
        # do_https_get ever reached it, tls_state would read $EE, not $42.
        s_lo, s_hi = _lohi(labels["tls_state"])
        p.patch(labels["tls_connect"],
                bytes([0xA9, 0xEE, 0x8D, s_lo, s_hi, 0x38, 0x60]),
                "tls_connect tripwire")
        poke(transport, labels, "tls_state", 0x42)
        poke(transport, labels, "tls_reached_connected", TLS_STATE_CONNECTED)
        call(transport, p, labels["do_https_get"])
        return {
            "state": peek(transport, labels, "tls_state"),
            "latch": peek(transport, labels, "tls_reached_connected"),
        }
    finally:
        p.restore()


def run_tests(transport, labels) -> tuple[int, int]:
    passed = failed = 0

    assert_shadow_ram_readable(transport, labels)
    print("  shadow RAM readable at the latch (positive control OK)")

    def report(name, why, checks, detail):
        nonlocal passed, failed
        ok = all(good for _, good in checks)
        print(f"\n  [{'+' if ok else '-'}] {name}")
        print(f"        {why}")
        print(f"        {detail}")
        for label, good in checks:
            if not good or VERBOSE:
                print(f"        {'ok  ' if good else 'FAIL'} {label}")
        if ok:
            passed += 1
        else:
            failed += 1

    def fmt(r):
        return "  ".join(f"{k}=${v:02X}" for k, v in r.items())

    C = TLS_STATE_CONNECTED

    r = run_tls_connect(transport, labels, fail_at=None, latch_before=0x00)
    report("successful handshake sets the latch",
           "the only set site is the CONNECTED store",
           [("C=0", r["carry"] == 0),
            ("tls_state == CONNECTED", r["state"] == C),
            ("latch == CONNECTED", r["latch"] == C)], fmt(r))

    r = run_tls_close(transport, labels)
    report("latch survives tls_close while tls_state moves on",
           "the whole point of #204: the CONNECTED window closes, the "
           "latch does not",
           [("tls_state == IDLE", r["state"] == TLS_STATE_IDLE),
            ("latch still CONNECTED", r["latch"] == C)], fmt(r))

    # Deliberately NOT re-poked to 0: this attempt starts from the latch the
    # previous (successful, closed) attempt left behind.
    r = run_tls_connect(transport, labels,
                        fail_at="tls_derive_traffic_keys", latch_before=C)
    report("failed handshake after a success reads 0 (last step fails)",
           "a failed attempt does not inherit the last success; failing "
           "the step just before CONNECTED catches a latch set too early",
           [("C=1", r["carry"] == 1),
            ("tls_state == ERROR", r["state"] == TLS_STATE_ERROR),
            ("tls_last_state == FINISHED (walk reached the end)",
             r["last"] == TLS_STATE_FINISHED),
            ("latch == 0", r["latch"] == 0)], fmt(r))

    r = run_tls_connect(transport, labels,
                        fail_at="tls_send_client_hello", latch_before=POISON)
    report("failed handshake at the first step reads 0",
           "the error path never sets the latch",
           [("C=1", r["carry"] == 1),
            ("tls_state == ERROR", r["state"] == TLS_STATE_ERROR),
            ("tls_last_state == CLIENT_HELLO",
             r["last"] == TLS_STATE_CLIENT_HELLO),
            ("latch == 0", r["latch"] == 0)], fmt(r))

    r = run_tls_connect(transport, labels, fail_at=None, latch_before=0x00)
    report("success after a failure sets it again",
           "the latch is per attempt, not stuck at 0",
           [("C=0", r["carry"] == 0),
            ("tls_state == CONNECTED", r["state"] == C),
            ("latch == CONNECTED", r["latch"] == C)], fmt(r))

    # Every case above reads the latch after tls_connect returns, so a
    # clear moved from tls_connect's entry to its @error path would pass
    # them all. This one reads it DURING the attempt.
    r = run_tls_connect(transport, labels, fail_at=None, latch_before=C,
                        probe=True)
    report("latch is already 0 mid-attempt (cleared at entry)",
           "a rig polling during the handshake must not see the previous "
           "attempt's CONNECTED; an error-path-only clear fails this",
           [("mid-attempt latch == 0 (seen from tls_send_client_hello)",
             r["mid"] == 0),
            ("C=0", r["carry"] == 0),
            ("latch == CONNECTED at the end", r["latch"] == C)], fmt(r))

    r = run_https_get_dns_fail(transport, labels)
    report("do_https_get clears the latch before DNS",
           "an attempt that dies before tls_connect must not inherit the "
           "previous attempt's CONNECTED",
           [("tls_connect never ran (tls_state still $42)",
             r["state"] == 0x42),
            ("latch == 0", r["latch"] == 0)], fmt(r))

    return passed, failed


def main() -> int:
    global VERBOSE
    os.chdir(PROJECT_ROOT)

    if "--verbose" in sys.argv:
        VERBOSE = True

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
        # The latch (or a routine this suite drives) is absent: a failure,
        # never a skip.
        print(f"FATAL: required label(s) not found: {', '.join(missing)}")
        return 1

    print("\n=== Labels ===")
    for name in REQUIRED_LABELS:
        print(f"  {name:<26} = ${labels[name]:04X}")

    print("\n=== Starting VICE ===")
    config = default_vice_config(prg_path=PRG_PATH, warp=True, ntsc=True,
                                sound=False)

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"  VICE PID={inst.pid}, port={inst.port}")

        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=120.0, verbose=False)
        if grid is None:
            print("FATAL: Main menu did not appear")
            mgr.release(inst)
            return 1
        print("  Main menu ready")

        print("\n=== tls_reached_connected latch (issue #204) ===")
        try:
            passed, failed = run_tests(transport, labels)
        finally:
            mgr.release(inst)

    total = passed + failed
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    if failed == 0:
        print(f"\n  [+] CONNECTED latch: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] CONNECTED latch: {failed} TEST(S) FAILED")
    print("=" * 60)

    return verdict(passed, failed,
                   certifies="the tls_connected latch (#204)")


if __name__ == "__main__":
    sys.exit(main())
