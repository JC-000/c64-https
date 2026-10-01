#!/usr/bin/env python3
"""#243 on hardware: net_tcp_close must close the socket even when its entry
wait finds the command interface busy.

The failure this pins: net_tcp_close's entry `uci_wait_idle` expires (a
reply somebody left open), the routine aborts the transaction, and used to
return WITHOUT ever pushing SOCKET_CLOSE — the firmware socket stayed live
while net_tcp_state said CLOSED, which a later C64 reset turns into lease
poisoning (CLAUDE.md "Device gotchas"). After #243 it retries the close
once when the abort's reset lands.

The model covers this (tools/test_uci_abort_recovery.py); this rig forces
the same path on the device. A DMA'd 6502 routine, run from BASIC via SYS:

  1. net_init; net_dns_resolve(RETRY_TARGET_HOST); net_tcp_connect(:443)
     — TCP only, nothing is sent over the socket;
  2. FORCED arm only: hand-push SOCKET_READ(sock, 16) with the adapter's
     own uci_begin_cmd / uci_put_byte / uci_push_wait and never read or
     accept the reply, so the interface is left in its data phase;
  3. set net_last_error = $86 (a stand-in for the error a caller brings
     in), then net_tcp_close, timed on CIA1 TOD;
  4. put net_tcp_state back to CONNECTED and run ONE net_poll: a
     SOCKET_READ on the same handle. On a closed handle the firmware
     answers errno 9 (EBADF) and net_poll marks the socket ERROR; on a
     socket still open it answers "02,NO DATA: 11" and it stays CONNECTED;
  5. an unconditional net_tcp_close, so no live socket survives the run
     whatever the steps above did.

The CONTROL arm runs the same routine without step 2, in the same boot.

PASS needs, per arm:
  forced : $DF1C busy before the close; the close took >= 3 s (the entry
           wait expired — the only 5 s wait on that path); C=0; the $86
           preserved; net_tcp_state CLOSED; the follow-up read says the
           handle is gone (net_poll -> ERROR, errno not 11).
  control: $DF1C idle before the close; the close took < 3 s; the same
           C=0 / $86 / CLOSED / handle-gone results.

The forced arm FAILS on the pre-#243 adapter: the close returns C=1 with
$89. The handle-gone check reads net_poll's errno verdict (#253), so on an
adapter older than that the control arm fails too — there, read the close's
carry and error, not the verdict line.

Environment: U64_HOST, TURBO_MHZ (default 48), RETRY_TARGET_HOST (default
lwn.net; any host accepting TCP on 443), C64_INIT_WAIT, UCI_DEBUG_DIR.
Needs a BACKEND=uci build in build/ (any profile; the comb build's boot
precompute is waited out like the other rigs do).

Exit: 0 pass, 1 fail, 2 fatal (build/labels/stub), 3 DeviceLock timeout,
4 device prep / REU preflight / PRG load verify (#199).

    U64_HOST=10.43.23.81 tools/uci/rig_close_retry.py
    tools/uci/rig_close_retry.py --selfcheck      # offline, no device
"""
from __future__ import annotations

import hashlib
import os
import sys
import time
from pathlib import Path

from c64_test_harness.backends.device_lock import DeviceLock, DeviceLockTimeout
from c64_test_harness.backends.ultimate64 import Ultimate64Transport
from c64_test_harness.backends.ultimate64_client import Ultimate64Client
from c64_test_harness.uci_network import enable_uci, disable_uci
from c64_test_harness.keyboard import send_text
from c64_test_harness.labels import Labels

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _device_lock_helper import (  # noqa: E402
    LockTimeoutConfigError, acquire_device_lock,
)
from _rig_lifecycle import guard_socket_teardown  # noqa: E402
from _prg_load import PrgLoadError, load_verified_and_run  # noqa: E402
from _memory_policy import (  # noqa: E402
    LOW_RAM_SCRATCH, build_policy_and_low_ram_arbiter,
)
from _device_prep import DevicePrepError, prepare_device  # noqa: E402
from _reu_preflight import ReuPreflightError, preflight_reu  # noqa: E402
from _temp_gc import gc_temp  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _skip_policy import verdict  # noqa: E402
from rig_https_local import (  # noqa: E402
    _create_run_dir, _prune_old_run_dirs, _write_run_info,
)

HOST = os.environ.get("U64_HOST", "192.168.1.81")
REPO_ROOT = Path(__file__).resolve().parents[2]
PRG_PATH = REPO_ROOT / "build" / "c64-https.prg"
LABELS_PATH = REPO_ROOT / "build" / "labels.txt"
TARGET_HOST = os.environ.get("RETRY_TARGET_HOST", "lwn.net")
TARGET_PORT = 443
TURBO_MHZ = int(os.environ.get("TURBO_MHZ", "48"))
_SCALE = max(1.0, 48.0 / float(TURBO_MHZ))
DEBUG_BASE_DIR = Path(os.environ.get("UCI_DEBUG_DIR",
                                     "/tmp/uci_close_retry_debug"))

SENTINEL_VALUE = 0xC4
# Page 3 is the only low-RAM window the routine fits in whole (#209); the
# stale push is a subroutine so the rest of the scratch can go to page 2.
ROUTINE_MAX = LOW_RAM_SCRATCH[1] - LOW_RAM_SCRATCH[0] + 1
ARM_FORCED, ARM_CONTROL = 1, 0
# The entry wait is a 5 s CIA1 TOD bound; a close that took this long spent
# it. The clean close is a few firmware round trips.
ENTRY_WAIT_SECONDS = 3.0

REQUIRED_LABELS = (
    "net_init", "net_dns_resolve", "net_tcp_connect", "net_tcp_close",
    "net_poll", "uci_begin_cmd", "uci_put_byte", "uci_push_wait",
    "uci_socket_id", "net_last_error", "net_tcp_state", "net_initialized",
    "uci_status_len", "uci_status_force", "uci_status_buf",
    "tcp_recv_head", "tcp_recv_tail",
)

# Results block layout (offsets).
R_CONN_P, R_CONN_ERR, R_SOCK = 0, 1, 2
R_CLOSE_P, R_CLOSE_ERR, R_CLOSE_STATE = 3, 4, 5
R_POLL_STATE, R_STATUS_LEN, R_FINAL_P = 6, 7, 8
R_BUSY = 9                                   # $DF1C just before the close
R_TOD0 = 10                                  # sec, tenths before the close
R_TOD1 = 12                                  # sec, tenths after
RESULTS_LEN = 16

UCI_STATUS_REG = 0xDF1C
UCI_BUSY_MASK = 0x35       # uci_wait_idle's mask: STATE | ABORT_PENDING | BUSY
CIA_TOD_TENTHS, CIA_TOD_SEC, CIA_TOD_HOUR = 0xDC08, 0xDC09, 0xDC0B
UCI_TARGET_NETWORK, UCI_CMD_SOCKET_READ = 0x03, 0x10
NET_TCP_CLOSED, NET_TCP_CONNECTED, NET_TCP_ERROR = 0x00, 0x01, 0x02
PRIOR_ERROR = 0x86         # what the caller brings in; the retry keeps it


def _load_labels() -> dict[str, int]:
    return dict(Labels.from_file(LABELS_PATH))


def default_init_wait(labels: dict[str, int]) -> float:
    """75 s for a comb build (boot precompute), 22 s otherwise."""
    banks = labels.get("LIB_NISTCURVES_REU_BANKS_USED")
    if banks is not None and banks & 0x04:
        return 75.0
    if any(name.startswith("ec_precompute") for name in labels):
        return 75.0
    return 22.0


def build_stale_push(labels: dict[str, int]) -> bytes:
    """The FORCED arm's step 2, as a subroutine: SOCKET_READ(sock, 16) pushed
    and never read, so the interface is left in its data phase. RTS."""
    L = labels
    c = bytearray()

    def e(*bs): c.extend(bs)
    def lda(v): e(0xA9, v & 0xFF)
    def ldaa(a): e(0xAD, a & 0xFF, a >> 8)
    def jsr(a): e(0x20, a & 0xFF, a >> 8)

    lda(UCI_TARGET_NETWORK); jsr(L["uci_begin_cmd"])
    lda(UCI_CMD_SOCKET_READ); jsr(L["uci_put_byte"])
    ldaa(L["uci_socket_id"]); jsr(L["uci_put_byte"])
    lda(16); jsr(L["uci_put_byte"])
    lda(0); jsr(L["uci_put_byte"])
    jsr(L["uci_push_wait"])                       # reply staged, never read
    e(0x60)                                       # RTS
    return bytes(c)


def build_routine(labels: dict[str, int], *, routine_addr: int,
                  push_addr: int, host_addr: int, results: int,
                  sentinel: int, progress: int, arm_addr: int,
                  save01: int) -> bytes:
    """The SYS-able routine. Reads its arm from `arm_addr`; returns to BASIC.

    The host zeroes `results`, `sentinel` and `progress` before every SYS
    (_run_arm), so the routine does not: that, INC for each progress step
    and the stale push as a subroutine at `push_addr` are what fit it in
    page 3 (#209).
    """
    L = labels
    c = bytearray()

    def e(*bs): c.extend(bs)
    def lda(v): e(0xA9, v & 0xFF)
    def ldx(v): e(0xA2, v & 0xFF)
    def sta(a): e(0x8D, a & 0xFF, a >> 8)
    def ldaa(a): e(0xAD, a & 0xFF, a >> 8)
    def jsr(a): e(0x20, a & 0xFF, a >> 8)
    def carry_to(a): e(0x08, 0x68); sta(a)        # PHP; PLA; STA
    def prog(): e(0xEE, progress & 0xFF, progress >> 8)   # INC: 1, 2, ... 7

    def tod_to(off):
        ldaa(CIA_TOD_HOUR)                        # latch
        ldaa(CIA_TOD_SEC); sta(results + off)
        ldaa(CIA_TOD_TENTHS); sta(results + off + 1)   # unlatch

    e(0xA5, 0x01); sta(save01); e(0x29, 0xFE); e(0x85, 0x01)   # BASIC out
    prog()
    jsr(L["net_init"])
    lda(0)
    for name in ("tcp_recv_head", "tcp_recv_tail"):
        sta(L[name]); sta(L[name] + 1)
    lda(host_addr & 0xFF); ldx(host_addr >> 8); jsr(L["net_dns_resolve"])
    prog()
    lda(TARGET_PORT & 0xFF); ldx(TARGET_PORT >> 8); jsr(L["net_tcp_connect"])
    carry_to(results + R_CONN_P)
    ldaa(L["net_last_error"]); sta(results + R_CONN_ERR)
    ldaa(L["uci_socket_id"]); sta(results + R_SOCK)
    prog()
    ldaa(arm_addr)
    e(0xF0, 0x03)                                 # BEQ over the JSR
    jsr(push_addr)
    ldaa(UCI_STATUS_REG); sta(results + R_BUSY)
    lda(PRIOR_ERROR); sta(L["net_last_error"])
    prog()
    tod_to(R_TOD0)
    jsr(L["net_tcp_close"])
    carry_to(results + R_CLOSE_P)
    tod_to(R_TOD1)
    ldaa(L["net_last_error"]); sta(results + R_CLOSE_ERR)
    ldaa(L["net_tcp_state"]); sta(results + R_CLOSE_STATE)
    prog()
    lda(0)
    sta(L["uci_status_len"]); sta(L["uci_status_force"])
    sta(L["net_last_error"])
    lda(NET_TCP_CONNECTED); sta(L["net_tcp_state"])
    jsr(L["net_poll"])
    ldaa(L["net_tcp_state"]); sta(results + R_POLL_STATE)
    ldaa(L["uci_status_len"]); sta(results + R_STATUS_LEN)
    prog()
    jsr(L["net_tcp_close"])                       # no live socket survives
    carry_to(results + R_FINAL_P)
    prog()
    lda(SENTINEL_VALUE); sta(sentinel)
    ldaa(save01); e(0x85, 0x01)
    e(0x60)                                       # RTS to BASIC
    return bytes(c)


def _bcd(b: int) -> int:
    return (b >> 4) * 10 + (b & 0x0F)


def tod_delta(sec0: int, ten0: int, sec1: int, ten1: int) -> float:
    """Seconds between two CIA TOD (sec, tenths) BCD samples, mod 60 s."""
    t0 = _bcd(sec0 & 0x7F) + (ten0 & 0x0F) / 10.0
    t1 = _bcd(sec1 & 0x7F) + (ten1 & 0x0F) / 10.0
    return (t1 - t0) % 60.0


def judge(arm: int, r: bytes, status: bytes) -> list[str]:
    """Problems for one arm; empty means PASS."""
    p = []
    busy = r[R_BUSY] & UCI_BUSY_MASK
    took = tod_delta(r[R_TOD0], r[R_TOD0 + 1], r[R_TOD1], r[R_TOD1 + 1])
    if r[R_CONN_P] & 1 or r[R_SOCK] == 0:
        p.append(f"connect failed (C=1 or no socket; net_last_error "
                 f"${r[R_CONN_ERR]:02X}) — the arm tested nothing")
    if arm == ARM_FORCED:
        if not busy:
            p.append(f"$DF1C=${r[R_BUSY]:02X} before the close: the stale "
                     "reply did not leave the interface busy, so the entry "
                     "wait was never exercised")
        if took < ENTRY_WAIT_SECONDS:
            p.append(f"the close took {took:.1f}s: the entry wait did not "
                     "expire")
    else:
        if busy:
            p.append(f"$DF1C=${r[R_BUSY]:02X} before the control close: "
                     "not idle")
        if took >= ENTRY_WAIT_SECONDS:
            p.append(f"the control close took {took:.1f}s")
    if r[R_CLOSE_P] & 1:
        p.append(f"net_tcp_close returned C=1 (net_last_error "
                 f"${r[R_CLOSE_ERR]:02X})")
    if r[R_CLOSE_ERR] != PRIOR_ERROR:
        p.append(f"net_last_error=${r[R_CLOSE_ERR]:02X} after the close, "
                 f"expected the caller's ${PRIOR_ERROR:02X}")
    if r[R_CLOSE_STATE] != NET_TCP_CLOSED:
        p.append(f"net_tcp_state=${r[R_CLOSE_STATE]:02X} after the close")
    if r[R_POLL_STATE] != NET_TCP_ERROR or status == b"02,NO DATA: 11":
        p.append(f"the follow-up read on the same handle left state "
                 f"${r[R_POLL_STATE]:02X}, status {status!r}: the socket is "
                 "still open — the close did not reach the firmware")
    return p


def _selfcheck() -> int:
    """Offline: labels present, routine assembles and fits, judge is sane."""
    fails = []
    if not LABELS_PATH.is_file():
        print("selfcheck: no build/labels.txt (build BACKEND=uci first)")
        return 2
    labels = _load_labels()
    missing = [n for n in REQUIRED_LABELS if n not in labels]
    if missing:
        print(f"selfcheck: missing labels {missing} — not a BACKEND=uci build")
        return 2
    code = build_routine(labels, routine_addr=0x5900, push_addr=0x5A00,
                         host_addr=0x5A40, results=0x5A80, sentinel=0x5A90,
                         progress=0x5A91, arm_addr=0x5A92, save01=0x5A93)
    if len(code) > ROUTINE_MAX:
        fails.append(f"routine {len(code)} B > {ROUTINE_MAX}")
    good = bytearray(RESULTS_LEN)
    good[R_SOCK], good[R_CLOSE_ERR] = 1, PRIOR_ERROR
    good[R_POLL_STATE] = NET_TCP_ERROR
    ctl = bytes(good)
    frc = bytearray(good); frc[R_BUSY] = 0x20; frc[R_TOD1] = 0x05
    if judge(ARM_CONTROL, ctl, b"02,NO DATA: 9"):
        fails.append("judge rejects a good control arm")
    if judge(ARM_FORCED, bytes(frc), b"02,NO DATA: 9"):
        fails.append("judge rejects a good forced arm")
    old = bytearray(frc); old[R_CLOSE_P] = 1; old[R_CLOSE_ERR] = 0x89
    old[R_POLL_STATE] = NET_TCP_CONNECTED
    if not judge(ARM_FORCED, bytes(old), b"02,NO DATA: 11"):
        fails.append("judge passes the pre-#243 outcome")
    checks = 4                       # fits, good control, good forced, old
    for f in fails:
        print(f"  FAIL {f}")
    print(f"selfcheck: routine {len(code)} B, {checks - len(fails)}/{checks}")
    return verdict(checks - len(fails), len(fails),
                   certifies="rig_close_retry's routine and verdict (offline)")


def _run_arm(tr, arm, a, code, host, results, sentinel, progress, arm_addr,
             labels) -> tuple[list[str], str]:
    tr.write_memory(arm_addr, bytes([arm]))
    tr.write_memory(results, bytes(RESULTS_LEN))
    tr.write_memory(sentinel, bytes(2))     # sentinel + progress: the routine
                                            # INCs progress from 0
    send_text(tr, f"sys{a}\r")
    name = "FORCED" if arm == ARM_FORCED else "CONTROL"
    deadline = time.time() + 60 * _SCALE
    last = -1
    while time.time() < deadline:
        pg = tr.read_memory(progress, 1)[0]
        if pg != last:
            print(f"  [{name}] progress={pg}")
            last = pg
        if tr.read_memory(sentinel, 1)[0] == SENTINEL_VALUE:
            break
        time.sleep(0.25)
    else:
        return ([f"{name}: routine did not finish (progress={last}); the "
                 "machine is left as-is — do NOT reset it, a socket may be "
                 "live"], "HUNG")
    r = bytes(tr.read_memory(results, RESULTS_LEN))
    n = r[R_STATUS_LEN]
    status = bytes(tr.read_memory(labels["uci_status_buf"], min(n, 32))) \
        if n else b""
    took = tod_delta(r[R_TOD0], r[R_TOD0 + 1], r[R_TOD1], r[R_TOD1 + 1])
    print(f"  [{name}] connect C={r[R_CONN_P] & 1} err=${r[R_CONN_ERR]:02X} "
          f"sock={r[R_SOCK]}; $DF1C=${r[R_BUSY]:02X}; close C="
          f"{r[R_CLOSE_P] & 1} err=${r[R_CLOSE_ERR]:02X} state="
          f"${r[R_CLOSE_STATE]:02X} in {took:.1f}s; follow-up read state="
          f"${r[R_POLL_STATE]:02X} status={status!r}; final close C="
          f"{r[R_FINAL_P] & 1}")
    problems = [f"{name}: {x}" for x in judge(arm, r, status)]
    return problems, ("PASS" if not problems else "FAIL")


def main() -> int:
    if not PRG_PATH.is_file() or not LABELS_PATH.is_file():
        print("ERROR: build/c64-https.prg or labels.txt missing — build "
              "BACKEND=uci first", file=sys.stderr)
        return 2
    labels = _load_labels()
    missing = [n for n in REQUIRED_LABELS if n not in labels]
    if missing:
        print(f"ERROR: missing labels {missing} — not a BACKEND=uci build",
              file=sys.stderr)
        return 2
    init_wait = float(os.environ.get("C64_INIT_WAIT",
                                     str(default_init_wait(labels))))
    # Low-RAM scratch, sized to what is written (#209): the routine takes
    # page 3, first fit puts the rest in page 2. Every linked tail this used
    # to carve has been spent at one time or another (comb's CRYPTO_OVERLAY).
    policy, arbiter = build_policy_and_low_ram_arbiter(
        LABELS_PATH, PRG_PATH, page2=True)
    push = build_stale_push(labels)
    host_str = TARGET_HOST.encode() + b"\0"
    a = arbiter.alloc(len(build_routine(
        labels, routine_addr=0, push_addr=0, host_addr=0, results=0,
        sentinel=0, progress=0, arm_addr=0, save01=0)), name="routine")
    push_addr = arbiter.alloc(len(push), name="stale_push")
    host = arbiter.alloc(len(host_str), name="host_str")
    results = arbiter.alloc(RESULTS_LEN, name="results")
    # sentinel + progress are cleared together by _run_arm.
    markers = arbiter.alloc(4, name="sentinel+progress+arm+save01")
    sentinel, progress, arm_addr, save01 = range(markers, markers + 4)
    code = build_routine(labels, routine_addr=a, push_addr=push_addr,
                         host_addr=host, results=results, sentinel=sentinel,
                         progress=progress, arm_addr=arm_addr, save01=save01)
    if len(code) > ROUTINE_MAX:
        print(f"ERROR: routine {len(code)} B > {ROUTINE_MAX}", file=sys.stderr)
        return 2
    prg = PRG_PATH.read_bytes()
    print(f"PRG {hashlib.sha256(prg).hexdigest()}")
    print(f"routine {len(code)} B @ ${a:04X}; target {TARGET_HOST}:"
          f"{TARGET_PORT}; {TURBO_MHZ} MHz")

    lock = DeviceLock(HOST)
    try:
        acquire_device_lock(lock)
    except LockTimeoutConfigError as exc:
        print(f"[fatal] {exc}", file=sys.stderr)
        return 2
    except DeviceLockTimeout as exc:
        print(f"[fatal] DeviceLock({HOST}): {exc}", file=sys.stderr)
        return 3
    print(f"Acquired DeviceLock({HOST})")
    for d in _prune_old_run_dirs(DEBUG_BASE_DIR, 5):
        print(f"Pruning old debug artifacts: {d}")
    run_dir = _create_run_dir(DEBUG_BASE_DIR)
    client = None
    tr = None
    uci_enabled = False
    fetch_in_flight = False
    outcome, exit_code = "UNKNOWN", 1
    start = time.time()
    try:
        client = Ultimate64Client(host=HOST, timeout=15.0)
        tr = Ultimate64Transport(host=HOST, timeout=15.0, client=client)
        tr.memory_policy = policy
        enable_uci(client)
        uci_enabled = True
        gc_temp(HOST)
        try:
            prepare_device(client, LABELS_PATH, turbo_mhz=TURBO_MHZ,
                           artifact_dir=run_dir)
        except DevicePrepError as exc:
            print(str(exc), file=sys.stderr)
            outcome, exit_code = "PREP", 4
            return exit_code
        try:
            preflight_reu(client, LABELS_PATH)
        except ReuPreflightError as exc:
            print(str(exc), file=sys.stderr)
            outcome, exit_code = "PREFLIGHT", 4
            return exit_code
        client.reset()
        time.sleep(2.5)
        try:
            load_verified_and_run(client, prg)
        except PrgLoadError as exc:
            print(f"[fatal] {exc}", file=sys.stderr)
            outcome, exit_code = "PRG_LOAD", 4
            return exit_code
        time.sleep(init_wait * _SCALE)
        if tr.read_memory(labels["net_initialized"], 1)[0] == 0:
            print("WARNING: net_initialized is 0 — auto-init may have failed")
        send_text(tr, "q\r")
        time.sleep(2.0 * _SCALE)
        for i in range(0, len(code), 64):
            tr.write_memory(a + i, code[i:i + 64])
        tr.write_memory(push_addr, push)
        tr.write_memory(host, host_str)
        if (bytes(tr.read_memory(a, len(code))) != code
                or bytes(tr.read_memory(push_addr, len(push))) != push):
            print("ERROR: routine read back wrong", file=sys.stderr)
            outcome, exit_code = "STUB", 2
            return exit_code
        problems = []
        verdicts = {}
        fetch_in_flight = True      # #234: from here a socket may be live
        for arm in (ARM_FORCED, ARM_CONTROL):
            p, v = _run_arm(tr, arm, a, code, host, results, sentinel,
                            progress, arm_addr, labels)
            verdicts["FORCED" if arm else "CONTROL"] = v
            problems += p
            if v == "HUNG":
                break
            time.sleep(1.0)
        else:
            fetch_in_flight = False     # both routines returned
        print(f"\nverdicts: {verdicts}")
        if problems:
            for x in problems:
                print(f"  - {x}")
            print("FAIL")
            outcome, exit_code = "FAIL", 1
            return exit_code
        print("PASS: the close lands after an entry-wait abort (#243), and "
              "the clean close is unchanged")
        outcome, exit_code = "PASS", 0
        return exit_code
    finally:
        try:
            _write_run_info(run_dir / "run_info.txt", outcome=outcome,
                            duration=time.time() - start,
                            exit_code=exit_code,
                            extra={"target": f"{TARGET_HOST}:{TARGET_PORT}",
                                   "turbo_mhz": TURBO_MHZ, "host": HOST})
        except Exception as exc:
            print(f"WARNING: run_info write failed: {exc}")
        # #234: before disable_uci — the C64 needs the command interface
        # to issue the SOCKET_CLOSE this waits for.
        if fetch_in_flight and tr is not None:
            guard_socket_teardown(tr.read_memory,
                                  labels.get("net_tcp_state"))
        if uci_enabled and client is not None:
            try:
                disable_uci(client)
            except Exception as exc:
                print(f"WARNING: disable_uci failed: {exc}")
        lock.release()
        print(f"Released DeviceLock({HOST})")


if __name__ == "__main__":
    if "--selfcheck" in sys.argv[1:]:
        sys.exit(_selfcheck())
    sys.exit(main())
