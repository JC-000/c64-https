#!/usr/bin/env python3
"""tests/rig_ip65_rrnet_hw.py — HTTPS over a REAL RR-Net cartridge.

THE COVERAGE GAP THIS CLOSES
============================
`c64-https-ip65-onchip.prg` is one of the three products `make package`
ships, and until this rig no ip65 build had ever run on real CS8900a
silicon. Every prior ip65 result — including the 36-minute stock-clock
end-to-end in CLAUDE.md — came from `tests/rig_vice_https_macos.py`, which
drives the same PRG inside a pcap-patched VICE against a feth pair. VICE's
CS8900a is a model of the chip; this is the chip.

    [ RR-Net in the U64E's cartridge port ] <--cable, no switch--> [ Mac en4 ]

The PRG is loaded over the U64's REST interface the usual way (DeviceLock,
write + SYS), but NOTHING about the network path goes through the Ultimate:
the C64 talks to the world through the cartridge, and the Mac is the only
other station on the cable. It is DHCP server, DNS server and HTTPS origin
at once (tools/rig-up-rrnet-macos.sh, tools/https_e2e).

WHAT DECIDES, AND WHAT ONLY OBSERVES
====================================
This file supplies the pcap and the DMA reads. It decides nothing:
every verdict comes from `tools/ip65_hw_checks.py`, and every one of those
has a red case in `tools/test_ip65_hw_checks_unit.py` proving it alarms on
a known-bad input off-device. That split exists because a first-ever
hardware result is the one nobody re-reads, and this repo has three
recorded instances of a suite passing for the wrong reason (#158, #161,
#176).

The library selftest below runs BEFORE the device is touched: it feeds the
imported checker a capture that must fail and one that must pass. If the
checker has been broken, the run stops without disturbing a shared bench.

WHY THIS RIG DOES NOT CALL enable_uci()
=======================================
Every other hardware rig in this repo does, because the UCI bridge is how
they reach the network. This one reaches the network through a physical
cartridge on the same expansion bus, and `Command Interface` lives in the
same config category as `Cartridge Preference`. Turning on a second
consumer of that bus is not something this run needs, and "reset to
baseline, then set what this run needs" says do not. The item's value is
READ and reported so a reader can see what it was; it is never written.

TIMING — BUDGET HONESTLY
========================
This is a stock-clock 1 MHz run, because `c64-https-ip65-onchip.prg` is
the stock-C64 product: no turbo, no REU. The same profile took 2,159.7 s
(36.0 min) in VICE at honest 1 MHz, of which ~1,417 s is the P-256 verify
and ~326 s each is an X25519. Real silicon is the same clock, and
c64-wireguard measured cartridge-port I/O on this bench as only ~1.7x
faster from 1 MHz to 48 MHz, so nothing here is quick. The default budget
is 80 minutes and a timeout is REPORTED AS A TIMEOUT, never as a defect.

The clock is not raised because nobody has measured whether the U64 times
CS8900a register cycles correctly at 48 MHz, and a run that answered "does
our shipped stock-C64 image work" at a clock that image never uses would
be answering a different question.

USAGE
=====
    # once per session, by hand (both need sudo):
    sudo bash tools/rig-up-rrnet-macos.sh en4
    sudo tcpdump -i en4 -n -s0 -U -w /tmp/rrnet-https.pcap

    # then:
    U64_HOST=10.43.23.81 python3 tests/rig_ip65_rrnet_hw.py

Environment:
    U64_HOST            the Ultimate (default 10.43.23.81)
    RRNET_IFACE         the Mac's NIC on the segment (default en4)
    RRNET_PCAP          capture path (default /tmp/rrnet-https.pcap)
    C64_SKIP_BUILD=1    reuse build/c64-https.prg instead of building
    E2E_TIMEOUT         fetch budget in seconds (default 4800)
    HTTPS_PORT          listener + PRG port (default 4433)

Exit codes: 0 PASS / 1 FAIL / 2 COULD NOT RUN / 78 INCONCLUSIVE.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "tools"))
for _p in ("/Users/someone/Documents/c64-test-harness/src",):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

import ip65_hw_checks as hw                                        # noqa: E402
from _skip_policy import cannot_run, not_applicable                # noqa: E402
from https_e2e import (                                            # noqa: E402
    press_key, get_screen_text, wait_for_screen_text,
    start_https_listener, stop_https_listener,
)
from c64_test_harness import (                                     # noqa: E402
    CARTRIDGE_PREFERENCE_ITEM, CARTRIDGE_SETTINGS_CATEGORY,
    DeviceLock, DeviceLockTimeout, Labels, dump_screen, probe_u64,
    read_bytes, send_text, wait_for_text, write_bytes,
)
from c64_test_harness.execute import parse_basic_sys_address       # noqa: E402
from c64_test_harness.backends.ultimate64 import Ultimate64Transport   # noqa: E402
from c64_test_harness.backends.ultimate64_client import (          # noqa: E402
    Ultimate64Client, Ultimate64RunnerStuckError,
)
from c64_test_harness.backends.ultimate64_helpers import (         # noqa: E402
    get_turbo_mhz, recover, runner_health_check, set_reu, set_turbo_mhz,
)

CERTIFIES = ("the TLS 1.3 handshake + GET over a PHYSICAL RR-Net cartridge "
             "on real CS8900a silicon")

RIG_SCRIPT = PROJECT_ROOT / "tools" / "rig-up-rrnet-macos.sh"
PRG_PATH = PROJECT_ROOT / "build" / "c64-https.prg"
LABELS_PATH = PROJECT_ROOT / "build" / "labels.txt"
ERRORS_INC = PROJECT_ROOT / "src" / "net" / "ip65" / "ip65_errors.inc"

IFACE = os.environ.get("RRNET_IFACE", "en4")
PCAP_PATH = os.environ.get("RRNET_PCAP", "/tmp/rrnet-https.pcap")
U64_HOST = os.environ.get("U64_HOST", "10.43.23.81")
HTTPS_PORT = int(os.environ.get("HTTPS_PORT", "4433"))
FETCH_BUDGET_S = float(os.environ.get("E2E_TIMEOUT", "4800"))
LOCK_TIMEOUT_S = 120.0

RESPONSE_BODY = "TLS13 OK OVER REAL RRNET"
MENU_NEEDLE = "Q=QUIT"
DHCP_OK_NEEDLE = "DHCP OK"
SUCCESS_NEEDLE = "CONNECTION CLOSED"
FAIL_NEEDLES = ("DNS RESOLVE FAILED", "TCP CONNECT FAILED",
                "TLS HANDSHAKE FAILED", "TLS SEND FAILED", "DHCP FAILED")
PROGRESS_NEEDLES = ("HTTPS GET", "DNS OK", "TCP CONNECTED", "CH", "SH", "KEYS",
                    "ENC1", "RX", "GOT", "DEC", "PROC", "EE", "CERT", "CV",
                    "FIN", "CFIN", "TLS HANDSHAKE OK", "REQUEST SENT",
                    "CONNECTION CLOSED")

EXIT_INCONCLUSIVE = 78

# The segment's addressing is READ from the rig script, never copied here.
HOST_IP = hw.rig_const("HOST_IP", RIG_SCRIPT)
C64_IP = hw.rig_const("C64_IP", RIG_SCRIPT)
C64_MAC = hw.parse_mac(hw.rig_const("C64_MAC", RIG_SCRIPT))
TEST_HOST = hw.rig_const("TEST_HOST", RIG_SCRIPT)
SUBNET = HOST_IP.rsplit(".", 1)[0] + ".0"

RUN: dict = {}


# ===========================================================================
# Bookkeeping
# ===========================================================================
class Results:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.inconclusive = 0
        self.names: list = []
        self.rows: list = []

    def check(self, ok: bool, label: str, detail: str = "",
              status: str | None = None) -> bool:
        status = status or ("PASS" if ok else "FAIL")
        if status == "PASS":
            self.passed += 1
        elif status == "INCONCLUSIVE":
            self.inconclusive += 1
        else:
            self.failed += 1
        self.names.append(label)
        self.rows.append({"label": label, "status": status, "detail": detail})
        print(f"  [{status:12s}] {label}" + (f"\n                 {detail}"
                                             if detail else ""))
        return ok

    def verdict(self, v, label: str) -> bool:
        status = {"pass": "PASS", "fail": "FAIL",
                  "inconclusive": "INCONCLUSIVE"}[v.status]
        self.check(v.ok, label, v.reason, status=status)
        RUN.setdefault("evidence", {})[label] = v.evidence
        return v.ok


RES = Results()


# ===========================================================================
# 0. The checker itself must be capable of failing
# ===========================================================================
def selftest_library() -> bool:
    """Feed the IMPORTED checker a known-bad capture and require a FAIL.

    tools/test_ip65_hw_checks_unit.py proves this at length off-device;
    this is the abbreviated version that runs in THIS process, against the
    module this run actually imported, before a shared bench is touched. A
    mutated or half-installed checker stops the run here.
    """
    print("=== 0. checker selftest (no device) ===")
    host_mac = bytes.fromhex("c05627b11638")
    # A capture holding ONLY the Mac's frames: the shape a run with the
    # cartridge unplugged produces, and the one that must never pass.
    eth = (bytes(C64_MAC) + host_mac + b"\x08\x00"
           + b"\x45\x00\x00\x28" + bytes(5) + b"\x06" + bytes(2)
           + hw.ip4_bytes(HOST_IP) + hw.ip4_bytes(C64_IP)
           + b"\x11\x51\x04\x01" + bytes(12))
    import struct
    pcap = (struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
            + struct.pack("<IIII", int(time.time()), 0, len(eth), len(eth))
            + eth)
    frames = hw.parse_pcap(pcap)
    ok = True
    ok &= RES.check(not hw.check_c64_originated(frames, C64_MAC, host_mac).ok,
                    "checker rejects a capture with no C64 frames",
                    "a powered-off cartridge must not pass")
    ok &= RES.check(not hw.check_dhcp_lease(bytes(hw.IP65_DEFAULT_CFG_IP),
                                            subnet=SUBNET).ok,
                    "checker rejects ip65's build-time cfg_ip default",
                    "192.168.1.64 is what a machine that never ran DHCP reads")
    ok &= RES.check(hw.check_body_not_on_wire(frames, b"SECRET", b"nope")
                    .inconclusive,
                    "checker refuses an absence claim with no positive control",
                    "no control hit => INCONCLUSIVE, which fails closed")
    ok &= RES.check(not hw.check_shadow_ram_readable(
                        hw.BASIC_ROM_A000_PREFIX + b"CBMBASIC" + bytes(4)).ok,
                    "checker rejects a $A000 read that returned the BASIC ROM")
    return bool(ok)


# ===========================================================================
# 1. Preflight — the rig, before the device
# ===========================================================================
def rig_problems() -> list:
    problems: list = []
    r = subprocess.run(["ifconfig", IFACE], capture_output=True, text=True)
    if r.returncode != 0 or f"inet {HOST_IP} " not in r.stdout:
        problems.append(f"{IFACE} missing or not at {HOST_IP} -- run "
                        f"`sudo bash {RIG_SCRIPT.relative_to(PROJECT_ROOT)} {IFACE}`")
    elif "status: active" not in r.stdout:
        problems.append(f"{IFACE} link is down -- a CS8900a only lights the "
                        "link when the cartridge has power")
    # DNS. The client resolves HTTPS_HOST before it connects, so a DHCP-only
    # segment stops at DNS RESOLVE FAILED and every later check is about a
    # machine that never opened a socket. Asked over the wire, not by
    # inspecting a config file.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3.0)
        q = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             + b"".join(bytes([len(l)]) + l.encode()
                        for l in TEST_HOST.split(".")) + b"\x00\x00\x01\x00\x01")
        s.sendto(q, (HOST_IP, 53))
        reply = s.recv(512)
        s.close()
        if len(reply) < 12 or not (reply[3] & 0x0F) == 0 or \
                int.from_bytes(reply[6:8], "big") < 1:
            problems.append(f"{HOST_IP} answered no A record for {TEST_HOST}")
        else:
            RUN["dns_probe"] = "answered"
    except OSError as exc:
        problems.append(f"no DNS on {HOST_IP}:53 for {TEST_HOST} ({exc}) -- the "
                        "segment needs a resolver, see the rig script")
    if not PRG_PATH.exists():
        problems.append(f"{PRG_PATH} missing")
    if not LABELS_PATH.exists():
        problems.append(f"{LABELS_PATH} missing")
    try:
        st = os.stat(PCAP_PATH)
        with open(PCAP_PATH, "rb") as fh:
            magic = fh.read(4)
        if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                         b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            problems.append(f"{PCAP_PATH} is not a classic pcap (magic "
                            f"{magic.hex()}) -- tcpdump -w, not pcapng")
        RUN["pcap_size_before"] = st.st_size
        RUN["pcap_mtime_before"] = time.strftime("%Y-%m-%dT%H:%M:%S",
                                                 time.localtime(st.st_mtime))
    except OSError as exc:
        problems.append(
            f"{PCAP_PATH} unreadable ({exc}). Start the capture first:\n"
            f"        sudo tcpdump -i {IFACE} -n -s0 -U -w {PCAP_PATH}\n"
            "        (-s0 and -U are both load-bearing: a snaplen-clipped "
            "capture is refused, and without -U the file does not grow "
            "while the run is in flight)")
    return problems


def build_prg() -> bool:
    args = ["make", "BACKEND=ip65", "USE_NISTCURVES_ONCHIP=1",
            f"HTTPS_PORT={HTTPS_PORT}"]
    print(f"=== building: {' '.join(args)} ===")
    subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
    r = subprocess.run(args, capture_output=True, text=True, cwd=PROJECT_ROOT)
    if r.returncode != 0:
        print(r.stdout[-2000:])
        print(r.stderr[-2000:])
        return False
    return True


def _config_item(payload) -> dict:
    """The `{current, values, default}` map, whichever shape came back.

    `get_config_item` has returned BOTH shapes in living memory: the whole
    REST envelope (`{category: {item: {...}}, "errors": []}`) before
    c64-test-harness#226, and the unwrapped item map after it. The harness
    is an EDITABLE install from a sibling working tree, so their merges are
    our regressions — c64-wireguard lost a teardown restore to exactly this
    change, reading None and therefore having nothing to write back. Both
    shapes are accepted; anything else yields {} and the caller refuses to
    write a value it could not read.
    """
    if not isinstance(payload, dict):
        return {}
    if "current" in payload:
        return payload
    for value in payload.values():
        if isinstance(value, dict):
            for inner in value.values():
                if isinstance(inner, dict) and "current" in inner:
                    return inner
    return {}


def load_labels() -> dict:
    labels = Labels.from_file(str(LABELS_PATH))
    return {name: addr for name, addr in labels.items()}


# ===========================================================================
# 2. Loading the PRG — verified before SYS
# ===========================================================================
def load_prg_verified(tr, prg: bytes) -> bool:
    """Write the image, PROVE it landed, then type SYS.

    NOT `client.run_prg`: the firmware's runner load path leaves an external
    cartridge deselected (c64-test-harness#217), so the program then reads
    the whole $DE00 window as zeros while `Cartridge Preference` still says
    External. ip65's EISA probe fails, the screen says the driver did not
    initialise, and it looks exactly like a dead RR-Net — a wrong conclusion
    manufactured by our own loader, about the very thing this run exists to
    test.

    And not `run_prg_via_sys` unmodified either: it writes through
    `write_bytes` without reading anything back. A ~47 kB image torn by one
    dropped REST write gets SYS'd anyway and fails later as a network fault,
    which is the same wrong conclusion by a different route.

    The two-byte head is rewritten AFTER the body and re-checked past a
    settle window: c64-wireguard measured a single event on this device that
    zeroes $0801/$0802 between ~2 s and ~5 s after READY. is drawn,
    independently of any write. Those bytes are the BASIC next-line pointer,
    which SYS does not use, so the program runs either way — but a verifier
    taught to tolerate two wrong bytes tolerates them being wrong for some
    other reason too.
    """
    load_addr = prg[0] | (prg[1] << 8)
    body = prg[2:]
    sys_addr = parse_basic_sys_address(prg)
    if sys_addr is None:
        RES.check(False, "the PRG carries a SYS entry point")
        return False

    tr.reset()
    if wait_for_text(tr, "READY.", timeout=40.0, poll_interval=0.3,
                     verbose=False) is None:
        RES.check(False, "the machine reached READY. after reset")
        return False
    t_ready = time.monotonic()

    # VERIFY ONLY BELOW $A000, AND SAY SO. The ip65 image runs to $BFFF, but
    # everything from $A000 up is CRYPTO_COLD_SHADOW: 8,192 bytes of zero fill
    # for BSS that boot.s zeroes again anyway. A host read of that span comes
    # back as the BASIC ROM until the program banks it out, so comparing it
    # before SYS would fail on every healthy run. What is verified is every
    # byte of code and rodata the link emitted -- $0801 through $9FD7, the end
    # of LIB_NISTCURVES_MUL_CODE. The unverified tail is checked for the one
    # property that IS decidable from the file: that it is all zeros.
    verify_len = min(len(body), 0xA000 - load_addr)
    tail = body[verify_len:]
    if not RES.check(set(tail) <= {0},
                     "the image's $A000+ tail is zero fill, not code",
                     f"{len(tail)} bytes; if this ever holds code, the "
                     "verification below stops covering the whole image and "
                     "this rig must bank the ROM out to read it"):
        return False

    attempts: list = []
    verdict = None
    for attempt in (1, 2):
        # CHUNKED, not one big write_memory. MEASURED on this device
        # (2026-09-05, U64E fw v3.15-78-g71480a9d, n=2): a single 47,103-byte
        # `write_memory` lands in 0.22 s and reads back with EXACTLY ONE wrong
        # byte, at a different offset each time -- offset 2715 ($12BC) on one
        # attempt, 3181 ($146E, $C8 read back as $AB) on the next. Not
        # truncation and not a size cap; a sporadic single-byte corruption in
        # the bulk path. The 84-byte chunked path takes ~33 s and came back
        # byte-exact. A one-byte flip inside 6502 code is precisely the fault
        # that surfaces 40 minutes later as a crash or a failed handshake and
        # gets written up as "ip65 does not work on real silicon", so the
        # slower path is the right one and the verify is not optional.
        t0 = time.monotonic()
        write_bytes(tr, load_addr, body)
        # THE HEAD GOES LAST, AND IS RE-CHECKED PAST A SETTLE WINDOW.
        # c64-wireguard measured, and this rig reproduced independently
        # (2026-09-05): a single event zeroes $0801/$0802 between ~2 s and
        # ~5 s after READY. is drawn, with no write involved. Those two bytes
        # are the BASIC next-line pointer, which SYS does not use, so the
        # program runs either way -- but a verifier taught to tolerate two
        # wrong bytes tolerates them being wrong for some other reason too.
        tr.write_memory(load_addr, body[:2])
        load_s = time.monotonic() - t0
        settle = 7.0 - (time.monotonic() - t_ready)
        if settle > 0:
            time.sleep(settle)
        for _ in range(3):
            if bytes(tr.read_memory(load_addr, 2)) == body[:2]:
                break
            tr.write_memory(load_addr, body[:2])
            time.sleep(1.0)

        back = bytes(tr.read_memory(load_addr, verify_len))
        verdict = hw.check_image_readback(body[:verify_len], back)
        attempts.append({"attempt": attempt, "seconds": round(load_s, 1),
                         "ok": verdict.ok,
                         "first_difference":
                             verdict.evidence.get("first_difference")})
        if verdict.ok:
            break
        print(f"  load attempt {attempt} did not verify "
              f"({verdict.reason}); rewriting")

    RUN["load"] = {"load_addr": f"${load_addr:04X}", "bytes": len(body),
                   "verified_bytes": verify_len,
                   "unverified_tail_bytes": len(tail),
                   "unverified_tail_all_zero": set(tail) <= {0},
                   "sys": sys_addr, "path": "write_bytes",
                   "attempts": attempts}
    if not RES.verdict(verdict, f"the PRG's {verify_len} code/rodata bytes "
                                "loaded into RAM byte-exact"):
        return False
    send_text(tr, f"SYS{sys_addr}\r")
    return True


# ===========================================================================
# 3. The run
# ===========================================================================
def last_progress(screen: str) -> str:
    upper = screen.upper()
    best, best_idx = "(none)", -1
    for needle in PROGRESS_NEEDLES:
        idx = upper.rfind(needle)
        if idx > best_idx:
            best, best_idx = needle, idx
    return best


def read_u16(tr, addr: int) -> int:
    b = bytes(tr.read_memory(addr, 2))
    return b[0] | (b[1] << 8)


def stage_boot_and_dhcp(tr, labels: dict) -> bool:
    print("=== 2. boot + DHCP over the cartridge ===")
    try:
        wait_for_screen_text(tr, MENU_NEEDLE, timeout=240.0)
    except TimeoutError as exc:
        RES.check(False, "the boot menu appeared", str(exc)[:400])
        dump_screen(tr, label="rrnet-boot")
        return False
    RES.check(True, "the boot menu appeared")

    # $A000 must read RAM before any shadow read below is worth anything.
    RES.verdict(hw.check_shadow_ram_readable(bytes(tr.read_memory(0xA000, 16))),
                "a DMA read of $A000 returns RAM, not the BASIC ROM")

    screen = get_screen_text(tr)
    tries = 0
    while DHCP_OK_NEEDLE not in screen.upper():
        if tries >= 3:
            RES.check(False, "DHCP completed over the RR-Net",
                      f"three attempts; last screen: {screen[:300]!r}")
            dump_screen(tr, label="rrnet-dhcp")
            return False
        tries += 1
        print(f"  DHCP attempt {tries} (pressing 'I')")
        press_key(tr, "I")
        try:
            wait_for_screen_text(tr, DHCP_OK_NEEDLE, timeout=150.0)
        except TimeoutError:
            pass
        screen = get_screen_text(tr)
    RUN["dhcp_attempts"] = tries
    RES.check(True, "DHCP completed over the RR-Net",
              f"{tries} explicit attempt(s) after the auto attempt")

    local_ip = bytes(tr.read_memory(labels["net_local_ip"], 4))
    RUN["c64_ip"] = hw.fmt_ip(local_ip)
    return RES.verdict(
        hw.check_dhcp_lease(local_ip, subnet=SUBNET, host_ip=HOST_IP,
                            expect_ip=C64_IP),
        f"the C64 holds the pinned lease {C64_IP} (read from its own memory)")


def stage_fetch(tr, labels: dict) -> str:
    """Press G and watch. Returns "pass", "fail" or "timeout"."""
    print(f"=== 3. HTTPS GET (budget {FETCH_BUDGET_S / 60:.0f} min at 1 MHz) ===")
    press_key(tr, "G")
    t0 = time.monotonic()
    deadline = t0 + FETCH_BUDGET_S
    heartbeat = t0 + 60.0
    phase = last_progress(get_screen_text(tr))
    phases: list = []
    tls_max = 0
    tls_addr = labels["tls_state"]
    result = "timeout"
    while time.monotonic() < deadline:
        time.sleep(5.0)
        try:
            screen = get_screen_text(tr)
            state = tr.read_memory(tls_addr, 1)[0]
        except Exception:                                        # noqa: BLE001
            continue
        # $FF is ERROR, which is not "higher than CONNECTED" -- track the
        # furthest NORMAL state, and latch ERROR separately.
        if state == hw.TLS_STATE_ERROR:
            tls_max = state
        elif tls_max != hw.TLS_STATE_ERROR and state > tls_max:
            tls_max = state
        upper = screen.upper()
        now_phase = last_progress(screen)
        if now_phase != phase:
            phase = now_phase
            phases.append((phase, round(time.monotonic() - t0, 1)))
            print(f"  phase +{phases[-1][1]:7.1f}s  {phase}  "
                  f"(tls_state={state})")
        if SUCCESS_NEEDLE in upper:
            result = "pass"
            break
        if any(n in upper for n in FAIL_NEEDLES):
            result = "fail"
            RUN["fail_needle"] = next(n for n in FAIL_NEEDLES if n in upper)
            break
        if time.monotonic() > heartbeat:
            heartbeat = time.monotonic() + 60.0
            print(f"  ... +{time.monotonic() - t0:6.0f}s  {phase}  "
                  f"tls_state={state} (max {tls_max})")
    RUN["fetch_seconds"] = round(time.monotonic() - t0, 1)
    RUN["phases"] = phases
    RUN["tls_state_max"] = tls_max
    RUN["final_screen"] = get_screen_text(tr)
    print(f"  fetch ended after {RUN['fetch_seconds']:.0f}s: {result}")

    last_state = tr.read_memory(labels["tls_last_state"], 1)[0]
    RUN["tls_last_state"] = last_state
    RES.verdict(hw.check_tls_connected(tls_max, last_state),
                "the C64's TLS state machine reached CONNECTED")

    status = read_u16(tr, labels["http_status"])
    resp_len = read_u16(tr, labels["http_resp_len"])
    buf = bytes(tr.read_memory(labels["http_resp_buf"],
                               max(1, min(resp_len + 16, 512))))
    RUN["http_status"] = status
    RUN["http_resp_len"] = resp_len
    RES.verdict(hw.check_http_response(status, resp_len, buf,
                                       RESPONSE_BODY.encode()),
                "HTTP 200 and the exact response body, out of the C64's buffer")

    err = tr.read_memory(labels["net_last_error"], 1)[0]
    RUN["net_last_error"] = err
    RES.verdict(hw.check_net_last_error(
        err, hw.net_error_table(ERRORS_INC.read_text())),
        "net_last_error is clean")
    if result == "timeout":
        RES.check(False, "the fetch completed inside its budget",
                  f"no terminal screen after {FETCH_BUDGET_S:.0f}s; last phase "
                  f"{phase}. This is a TIMEOUT, not a defect: read the phase "
                  "timeline before concluding anything about the client.")
    return result


# ===========================================================================
# 4. The wire
# ===========================================================================
def stage_wire(started_at: float, ended_at: float) -> None:
    print("=== 4. the wire ===")
    try:
        st = os.stat(PCAP_PATH)
        RUN["pcap_size_after"] = st.st_size
        RUN["pcap_mtime_after"] = time.strftime("%Y-%m-%dT%H:%M:%S",
                                                time.localtime(st.st_mtime))
        data = Path(PCAP_PATH).read_bytes()
    except OSError as exc:
        RES.check(False, "the capture could be read", str(exc),
                  status="INCONCLUSIVE")
        return
    RES.verdict(hw.check_capture_grew(RUN.get("pcap_size_before"),
                                      RUN.get("pcap_size_after"),
                                      path=PCAP_PATH),
                "the capture grew across the run")
    try:
        frames = hw.parse_pcap(data)
    except hw.PcapError as exc:
        RES.check(False, "the capture decodes", str(exc), status="INCONCLUSIVE")
        return
    RUN["pcap_frames_total"] = len(frames)
    if not RES.verdict(hw.check_capture_bracket(frames, started_at, ended_at,
                                                path=PCAP_PATH),
                       "the capture covers this run's window"):
        return
    corpus = hw.frames_in_window(frames, started_at, ended_at)
    RUN["pcap_frames_in_window"] = len(corpus)
    host_macs = sorted({bytes(f.eth_src) for f in corpus} - {bytes(C64_MAC)})
    if not host_macs:
        RES.check(False, "the capture holds frames from both stations",
                  "no frame from anything but the C64's MAC")
        return
    host_mac = host_macs[0]
    RUN["host_mac"] = hw.fmt_mac(host_mac)
    RUN["c64_mac"] = hw.fmt_mac(C64_MAC)

    RES.verdict(hw.check_c64_originated(corpus, C64_MAC, host_mac, min_frames=4),
                "frames on the cable came FROM the RR-Net, not only the Mac")
    RES.verdict(hw.check_mac_on_wire(corpus, C64_MAC, host_mac, min_frames=4),
                f"the RR-Net's MAC {hw.fmt_mac(C64_MAC)} is an Ethernet SOURCE "
                "on the cable")
    RES.verdict(hw.check_dns_query_on_wire(corpus, C64_MAC, TEST_HOST),
                f"the C64 resolved {TEST_HOST} over the cartridge")
    RES.verdict(hw.check_client_hello_on_wire(corpus, C64_MAC, port=HTTPS_PORT,
                                              expect_sni=TEST_HOST),
                "the C64 put a TLS ClientHello on the wire")
    RES.verdict(hw.check_tls_traffic_both_ways(corpus, C64_MAC, host_mac,
                                               port=HTTPS_PORT),
                "encrypted application data crossed the cable both ways")
    RES.verdict(hw.check_body_not_on_wire(corpus, RESPONSE_BODY.encode(),
                                          TEST_HOST.encode()),
                "the response body never appears in cleartext on the wire")


# ===========================================================================
# main
# ===========================================================================
def main() -> int:
    if sys.platform != "darwin":
        return not_applicable(
            f"this rig is macOS-only (the segment is brought up by "
            f"tools/rig-up-rrnet-macos.sh); this host is {sys.platform}",
            certifies=CERTIFIES)

    for line in hw.format_provenance(hw.provenance(
            [Path(__file__), PROJECT_ROOT / "tools" / "ip65_hw_checks.py",
             PRG_PATH], repo=PROJECT_ROOT)):
        print(line)

    if not selftest_library():
        return cannot_run(
            "the checker library failed its own selftest -- it cannot be "
            "relied on to fail, so nothing it says about the hardware would "
            "mean anything",
            executed=0, total=1, certifies=CERTIFIES, opt_out_env=None)

    if os.environ.get("C64_SKIP_BUILD") != "1" and not build_prg():
        return cannot_run("the PRG could not be built -- `make` failed",
                          executed=0, total=1, certifies=CERTIFIES,
                          opt_out_env=None)

    problems = rig_problems()
    if problems:
        return cannot_run("rig not ready:\n    - " + "\n    - ".join(problems),
                          executed=0, total=1, certifies=CERTIFIES,
                          opt_out_env="C64_ALLOW_SKIP")

    prg = PRG_PATH.read_bytes()
    labels = load_labels()
    if not RES.verdict(hw.resolve_symbols(labels), "this build exports every "
                                                   "symbol the rig reads"):
        return cannot_run("the build does not export the diagnostic symbols",
                          executed=0, total=1, certifies=CERTIFIES,
                          opt_out_env=None)

    probe = probe_u64(U64_HOST)
    if not getattr(probe, "reachable", bool(probe)):
        return cannot_run(f"{U64_HOST} is not reachable: {probe}",
                          executed=0, total=1, certifies=CERTIFIES,
                          opt_out_env="C64_ALLOW_SKIP")

    lock = DeviceLock(U64_HOST)
    try:
        lock.acquire_or_raise(timeout=LOCK_TIMEOUT_S)
    except DeviceLockTimeout as exc:
        return cannot_run(f"another lane holds {U64_HOST}: {exc}",
                          executed=0, total=1, certifies=CERTIFIES,
                          opt_out_env=None)

    client = None
    cart_prev = None
    started_at = time.time()
    try:
        client = Ultimate64Client(host=U64_HOST, timeout=60.0)
        tr = Ultimate64Transport(host=U64_HOST, timeout=60.0, client=client)
        try:
            runner_health_check(client)
        except Ultimate64RunnerStuckError as exc:
            print(f"  runner wedged ({exc}); recovering")
            recover(client)
            runner_health_check(client)

        # --- baseline, then only what this run needs ---------------------
        # REU off: this is a no-REU product and inheriting another lane's
        # attachment is exactly the state that makes a failure look like ours.
        set_reu(client, False)
        set_turbo_mhz(client, 1)
        time.sleep(1.0)
        RUN["turbo_mhz"] = get_turbo_mhz(client)
        # Command Interface (UCI) is READ, never written -- see the module
        # docstring. A second consumer of the expansion bus is not something
        # an RR-Net run needs.
        try:
            RUN["command_interface"] = str(client.get_config_item(
                CARTRIDGE_SETTINGS_CATEGORY, "Command Interface"))[:200]
        except Exception as exc:                                 # noqa: BLE001
            RUN["command_interface"] = f"unreadable: {exc}"

        item = _config_item(client.get_config_item(
            CARTRIDGE_SETTINGS_CATEGORY, CARTRIDGE_PREFERENCE_ITEM))
        cart_now = item.get("current")
        allowed = item.get("values") or []
        default = item.get("default")
        RUN["cartridge_preference_before"] = cart_now
        if not allowed or cart_now not in allowed:
            # Refuse to set what we could not read back: a run that cannot
            # restore a shared bench must not disturb it.
            raise RuntimeError(
                f"could not read {CARTRIDGE_PREFERENCE_ITEM!r} as one of "
                f"{allowed} (got {cart_now!r}); NOT setting it")
        # Already-External is indistinguishable from an earlier run leaking
        # it, so restore the device's own declared default in that case.
        cart_prev = (default if cart_now == "External" and default
                     and default != "External" else cart_now)
        client.set_config_item(CARTRIDGE_SETTINGS_CATEGORY,
                               CARTRIDGE_PREFERENCE_ITEM, "External")
        time.sleep(1.0)
        RES.check(True, "Cartridge Preference set to External",
                  f"was {cart_now!r}, will restore to {cart_prev!r}. NOT proof "
                  "the cartridge is visible -- only the 6510 can establish "
                  "that, which is what DHCP over the cable does below.")

        print(f"=== 1. HTTPS listener on {HOST_IP}:{HTTPS_PORT} ===")
        listener = start_https_listener(host=HOST_IP, port=HTTPS_PORT,
                                        response_body=RESPONSE_BODY)
        RUN["cert"] = {"path": listener.cert_path,
                       "profile": listener.cert_profile}
        try:
            probe_sock = socket.create_connection((HOST_IP, HTTPS_PORT),
                                                  timeout=5)
            probe_sock.close()
            RES.check(True, "the listener is reachable from this host")
        except OSError as exc:
            stop_https_listener(listener)
            raise RuntimeError(
                f"the listener is not reachable at {HOST_IP}:{HTTPS_PORT} "
                f"({exc}); macOS Local Network privacy can silently block it")

        try:
            started_at = time.time()
            if load_prg_verified(tr, prg) and stage_boot_and_dhcp(tr, labels):
                stage_fetch(tr, labels)
            # Let the fetch finish before anything resets: resetting the C64
            # with a live socket poisons the DHCP lease until a wall power
            # cycle.
            time.sleep(3.0)
        finally:
            ended_at = time.time()
            stop_https_listener(listener)
    except Exception as exc:                                     # noqa: BLE001
        ended_at = time.time()
        RES.check(False, "the run completed without aborting",
                  f"{type(exc).__name__}: {exc}")
    finally:
        if client is not None:
            try:
                set_turbo_mhz(client, 1)
                set_reu(client, False)
            except Exception as exc:                             # noqa: BLE001
                print(f"  clock/REU restore FAILED: {exc}")
            try:
                if cart_prev:
                    client.set_config_item(CARTRIDGE_SETTINGS_CATEGORY,
                                           CARTRIDGE_PREFERENCE_ITEM, cart_prev)
                    print(f"  restored Cartridge Preference to {cart_prev!r}")
            except Exception as exc:                             # noqa: BLE001
                print(f"  could not restore Cartridge Preference: {exc}")
            try:
                client.reset()
            except Exception as exc:                             # noqa: BLE001
                print(f"  reset FAILED: {exc}")
        lock.release()
        print("  device lock released")

    stage_wire(started_at, ended_at)

    RUN["results"] = RES.rows
    print("\n=== RUN ===")
    print(json.dumps(RUN, indent=2, default=str))
    total = RES.passed + RES.failed + RES.inconclusive
    print(f"\n{RES.passed}/{total} checks passed, {RES.failed} failed, "
          f"{RES.inconclusive} inconclusive")
    if total == 0:
        print("NOTHING RAN -- a run with no checks is not a pass")
        return EXIT_INCONCLUSIVE
    if RES.failed:
        return 1
    if RES.inconclusive:
        return EXIT_INCONCLUSIVE
    return 0


if __name__ == "__main__":
    sys.exit(main())
