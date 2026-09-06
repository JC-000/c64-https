#!/usr/bin/env python3
"""macOS hardware-free HTTPS e2e: ip65 PRG in ethernet-VICE vs local TLS 1.3 listener.

The macOS counterpart to tests/rig_phase3_https.py (which is Linux-only:
sysfs TAP checks + sudo dnsmasq). This variant expects the feth/pcap rig
from tools/rig-up-macos.sh to be up already (one sudo command per boot)
and runs everything else unprivileged:

  - VICE: the ethernet-capable build at ~/opt/vice-eth/bin/x64sc (stock
    macOS VICE binaries gate the pcap rawnet driver on euid==0 — see
    c64-test-harness#144). Launched directly with pcap on feth0; the
    host owns 10.0.65.1 on feth1 (the feth peer IS the L2 link).
  - DHCP/DNS: the rig's externally-managed dnsmasq (never touched here).
  - TLS listener: tools/https_e2e machinery bound to 10.0.65.1:4433
    (unprivileged port — the PRG must be built with HTTPS_PORT=4433).

Timing model: DHCP runs at 1x speed (warp compresses ip65's retry budget
below dnsmasq's OFFER latency and DHCP FAILED is guaranteed); after
DHCP OK the TLS phase runs under warp via the binary monitor's
WarpMode resource unless E2E_NO_WARP=1 (set that for honest stock-clock
wall-time; budget hours for the REU-less onchip profile).

DO NOT REMOVE THE 1x DHCP ASSIST ON THE STRENGTH OF THE U64E TIMER
MEASUREMENT. On 2026-09-06 the CIA2 timers were measured on hardware and
found to run at real NTSC phi2 at every CPU clock — ratio 1.000 from
1 MHz to 48 MHz — so ip65's ~15 s DHCP budget survives turbo there and
`tests/rig_ip65_rrnet_hw.py` needs no assist (`docs/engineering-notes.md`,
`tools/probe_cia_timer_rate.py`). **That result does not transfer to this
file, because the mechanism is different.** A turbo CPU leaves the CIAs on
the 1 MHz bus, so emulated time and wall time still agree. Warp
accelerates the whole emulated machine, CIAs included, so ip65's budget
still burns in a second or two of wall clock while dnsmasq answers on wall
clock — the retry budget is measured in emulated ticks and the OFFER
arrives in real ones. "The timers are realtime, the assist is
unnecessary" is true of hardware turbo and false of warp; deleting this
guarantees DHCP FAILED in the emulator.

Environment knobs:
  C64_SKIP_BUILD=1     reuse build/c64-https.prg (default: rebuild)
  E2E_PROFILE          onchip (default) | reu — build flags + -reu for VICE
  HTTPS_PORT           listener + PRG port (default 4433)
  E2E_TIMEOUT          TLS-phase budget in seconds (default 2400)
  E2E_NO_WARP=1        keep 1x speed for the TLS phase
  VICE_ETH_BIN         override the ethernet-VICE binary path

First-run rig prerequisite beyond tools/rig-up-macos.sh: macOS prompts
once for "Local Network" access for the python interpreter — until
approved, the OS silently blocks the TLS listener from the feth network
and the C64 dies at TCP CONNECT with nothing on the wire. The listener
self-probe below detects this and says so.

Exit codes (tools/_skip_policy.py, issue #178):
    0 PASS, or NOT APPLICABLE on a non-macOS host (tests/rig_phase3_https.py
      owns that coverage on Linux) -- a named verdict, never a bare skip.
    1 FAIL (a check ran and failed)
    2 COULD NOT RUN -- the rig is not up, or it is contended, so nothing was
      verified.  C64_ALLOW_SKIP=1 accepts a rig-NOT-READY run as exit 0; it
      does NOT cover contention, and does not cover a failed build.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import time

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_TOOLS = os.path.join(_REPO_ROOT, "tools")
for p in (_TOOLS, "/Users/someone/Documents/c64-test-harness/src"):
    if p not in sys.path:
        sys.path.insert(0, p)

# needs _TOOLS on sys.path, hence the placement below the block above
from _skip_policy import cannot_run, not_applicable  # noqa: E402

_CERTIFIES = "the TLS 1.3 handshake + GET over emulated RR-Net on macOS"
from c64_test_harness.backends.vice_binary import BinaryViceTransport  # noqa: E402
from c64_test_harness import Labels, read_bytes  # noqa: E402
from https_e2e import (  # noqa: E402
    press_key,
    wait_for_screen_text,
    get_screen_text,
    start_https_listener,
    stop_https_listener,
)

PRG_PATH = os.path.join(_REPO_ROOT, "build", "c64-https.prg")
HOST_IP = "10.0.65.1"
VICE_BIN = os.environ.get(
    "VICE_ETH_BIN", os.path.expanduser("~/opt/vice-eth/bin/x64sc"))
HTTPS_PORT = int(os.environ.get("HTTPS_PORT", "4433"))
PROFILE = os.environ.get("E2E_PROFILE", "onchip")
TLS_TIMEOUT = float(os.environ.get("E2E_TIMEOUT", "2400"))
NO_WARP = os.environ.get("E2E_NO_WARP") == "1"
MONITOR_PORT = int(os.environ.get("E2E_MONITOR_PORT", "6544"))

RESPONSE_BODY = "TLS13 OK FROM C64 TEST"
MENU_NEEDLE = "Q=QUIT"
DHCP_OK_NEEDLE = "DHCP OK"
SUCCESS_NEEDLE = "CONNECTION CLOSED"
FAIL_NEEDLES = (
    "DNS RESOLVE FAILED",
    "TCP CONNECT FAILED",
    "TLS HANDSHAKE FAILED",
    "TLS SEND FAILED",
)
PROGRESS_NEEDLES = (
    "HTTPS GET", "DNS OK", "TCP CONNECTED", "CH", "SH", "KEYS", "ENC1",
    "RX", "GOT", "DEC", "PROC", "EE", "CERT", "CV", "FIN", "CFIN",
    "TLS HANDSHAKE OK", "REQUEST SENT", "CONNECTION CLOSED",
)


def _platform_supported() -> bool:
    """True if this host can run the feth/pcap rig at all.

    Module-level and parameterless on purpose: a test can replace THIS to
    exercise both branches, instead of patching `sys.platform` globally.
    """
    return sys.platform == "darwin"


def _rig_check() -> "tuple[list[str], list[str]]":
    """Return (problems, contention) for a macOS host.  Both empty = rig OK.

    Two lists because the remedies differ in kind, and issue #178's rule is
    that the remedy decides the verdict:

      problems   -- something is not installed or not set up.  Remedy: run
                    `sudo bash tools/rig-up-macos.sh`, build the VICE.  An
                    involuntary skip, exit 2, opt-out-able by a lane that
                    knowingly has no rig.
      contention -- the rig exists but another process holds it.  Remedy:
                    wait, or kill YOUR stale instance.  Also exit 2, but
                    deliberately NOT opt-out-able: a lane that silences
                    contention goes green every time it collides, which is
                    the exact vacuous-pass this policy exists to stop, and
                    unlike a missing tool it is transient, so silencing it
                    hides a condition that would have cleared on its own.

    The platform question is asked by the CALLER, before this runs -- a
    non-Darwin host is a voluntary skip owned by tests/rig_phase3_https.py,
    not a problem with this rig.
    """
    problems: list[str] = []
    contention: list[str] = []
    if not os.path.exists(VICE_BIN):
        problems.append(
            f"{VICE_BIN} missing — build it per c64-test-harness#144 "
            "(stock VICE cannot do unprivileged ethernet on macOS)")
    try:
        mode = os.stat("/dev/bpf0").st_mode
        if not (mode & stat.S_IROTH and mode & stat.S_IWOTH):
            problems.append("/dev/bpf0 not world-rw (perms reset on reboot)")
    except FileNotFoundError:
        problems.append("/dev/bpf0 missing")
    r = subprocess.run(["ifconfig", "feth1"], capture_output=True, text=True)
    if r.returncode != 0 or f"inet {HOST_IP} " not in r.stdout:
        problems.append(f"feth1 missing or not at {HOST_IP}")
    # Another VICE already attached to feth0 is a hard conflict: every
    # ip65 instance uses the same default MAC (00:0e:3a:64:64:64), so a
    # leftover instance is a live duplicate-MAC node on the same L2 that
    # eats/garbles ARP and TCP meant for this run. Other x64sc processes
    # NOT on feth0 (other projects' fleets on this shared bench) are
    # fine — never kill those.
    # Match the BINARY first, then that process's argv.  `pgrep -fl
    # "ethernetioif feth0"` matched the full command line of EVERY process
    # against an unanchored pattern, so anything merely containing that text
    # matched too: a grep for it, an editor opened on this file, a driver
    # script passing it as an argument.  A false positive is unrecoverable
    # here, because contention is deliberately not opt-out-able -- so the
    # detector has to be narrow.  `pgrep -x x64sc` matches only processes
    # whose executable name is exactly x64sc; the argv check then confirms it
    # is the one on feth0.
    attached: list[str] = []
    r = subprocess.run(["pgrep", "-x", "x64sc"], capture_output=True, text=True)
    for pid in r.stdout.split():
        if not pid.isdigit():
            continue
        ps = subprocess.run(["ps", "-o", "command=", "-p", pid],
                            capture_output=True, text=True)
        cmd = " ".join(ps.stdout.split())
        if "ethernetioif" in cmd and "feth0" in cmd:
            attached.append(f"pid {pid}: {cmd}")
    if attached:
        contention.append(
            "another VICE is already attached to feth0 (duplicate-MAC "
            "conflict):\n    " + "\n    ".join(attached)
            + "\n    kill YOUR stale instance (do not touch other projects' "
              "x64sc processes)")
    try:
        pid = int(open("/tmp/c64-rig-dnsmasq.pid").read().strip())
        os.kill(pid, 0)
    except PermissionError:
        pass  # EPERM = process exists (it's root-owned) — rig is up
    except (OSError, ValueError):
        problems.append("rig dnsmasq not running (pid file stale/absent)")
    return problems, contention


def _build_prg() -> None:
    make_args = ["make", "BACKEND=ip65", f"HTTPS_PORT={HTTPS_PORT}"]
    if PROFILE == "onchip":
        make_args.append("USE_NISTCURVES_ONCHIP=1")
    print(f"=== Building: {' '.join(make_args)} ===")
    subprocess.run(["make", "clean"], capture_output=True, cwd=_REPO_ROOT)
    r = subprocess.run(make_args, capture_output=True, text=True,
                       cwd=_REPO_ROOT)
    if r.returncode != 0:
        print(r.stdout[-2000:])
        print(r.stderr[-2000:])
        # A failed build is exit 2 (could not run), not exit 1 (a check ran
        # and failed) -- the same verdict the other four rigs give, and never
        # opted out of.  SystemExit("build failed") used to exit 1 here, which
        # made a broken build indistinguishable from a real handshake failure.
        raise SystemExit(cannot_run(
            "the PRG could not be built -- `make` failed; this is a broken "
            "build, not a missing prerequisite",
            executed=0,
            total=1,
            certifies=_CERTIFIES,
            opt_out_env=None,
        ))


def _launch_vice() -> subprocess.Popen:
    # -minimized: the SDL2 window must never take keyboard focus — a
    # stray host keystroke lands in the emulated C64 and can break the
    # autostart LOAD/RUN sequence or corrupt the menu state mid-run
    # (observed: user typing leaked into attempt 3 and killed autostart).
    args = [VICE_BIN, "+sound", "-minimized",
            "-ethernetiodriver", "pcap", "-ethernetioif", "feth0",
            "-ethernetcartmode", "1", "-ethernetcart",
            "-binarymonitor",
            "-binarymonitoraddress", f"127.0.0.1:{MONITOR_PORT}",
            "-autostart", PRG_PATH]
    if PROFILE == "reu":
        args += ["-reu", "-reusize", "512"]
    print(f"=== Launching VICE ({os.path.basename(VICE_BIN)}, "
          f"profile={PROFILE}, reu={'yes' if PROFILE == 'reu' else 'NO'}) ===")
    return subprocess.Popen(args, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


def _connect(timeout: float = 30.0) -> BinaryViceTransport:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return BinaryViceTransport(port=MONITOR_PORT)
        except Exception:  # noqa: BLE001 — harness raises its own hierarchy
            time.sleep(0.5)
    raise TimeoutError("binary monitor never came up")


def _last_progress(screen: str) -> str:
    upper = screen.upper()
    best, best_idx = "(none)", -1
    for needle in PROGRESS_NEEDLES:
        idx = upper.rfind(needle)
        if idx > best_idx:
            best, best_idx = needle, idx
    return best


_DIAG_SYMBOLS = (
    # (label, byte count) — read on failure, before teardown kills VICE.
    ("tls_state", 1), ("tls_recv_progress", 1), ("tls_recv_sub_progress", 1),
    ("tls_read_seq", 8), ("tls_rec_type", 1), ("tls_rec_len", 2),
    ("net_last_error", 1), ("net_tcp_state", 1),
    ("tcp_recv_head", 2), ("tcp_recv_tail", 2), ("tcp_recv_overflow", 1),
    ("http_status", 2),
)


def _dump_c64_state(transport: BinaryViceTransport) -> None:
    """Read TLS/net state via labels at failure time (VICE still alive)."""
    try:
        labels = Labels.from_file(os.path.join(_REPO_ROOT, "build", "labels.txt"))
    except Exception as e:  # noqa: BLE001
        print(f"  (state dump unavailable — labels: {e})")
        return
    print("=== C64 state at failure ===")
    for name, count in _DIAG_SYMBOLS:
        addr = labels.address(name)
        if addr is None:
            continue
        try:
            data = read_bytes(transport, addr, count)
            print(f"  {name:22s} = {data.hex()}")
        except Exception as e:  # noqa: BLE001
            print(f"  {name:22s} unreadable ({e})")


def main() -> int:
    # SIGTERM must run the finally-block teardown (kill VICE, stop the
    # listener) — an orphaned VICE stays attached to feth0 as a
    # duplicate-MAC node and poisons every subsequent run.
    import signal

    def _sigterm(_sig, _frame):
        raise SystemExit(143)

    signal.signal(signal.SIGTERM, _sigterm)

    # Platform FIRST, and it is a VOLUNTARY skip: a Linux host can never run
    # the feth/pcap rig, and tests/rig_phase3_https.py owns that coverage
    # there.  Exit 2 would be a red nobody on that platform could clear
    # (issue #178).
    if not _platform_supported():
        return not_applicable(
            f"this rig is macOS-only (feth pair + /dev/bpf pcap); this host "
            f"is {sys.platform} -- tests/rig_phase3_https.py owns this "
            f"coverage on Linux",
            certifies=_CERTIFIES,
        )

    problems, contention = _rig_check()

    # PROBLEMS FIRST.  Contention on a rig that does not exist is a
    # meaningless statement: with no VICE binary, no feth1 and no dnsmasq,
    # "another VICE holds feth0" is the wrong headline and demotes the real
    # cause to a parenthetical.  Worse, contention is deliberately not
    # opt-out-able, so evaluating it first left a CI lane that legitimately
    # has no rig -- and correctly set C64_ALLOW_SKIP=1 -- red with no
    # recourse.  An involuntary skip is a FAILURE, but this one is the kind
    # an operator can opt out of (issue #178).
    if problems:
        return cannot_run(
            "rig not ready:\n    - " + "\n    - ".join(problems)
            + "\n    fix: (re)run `sudo bash tools/rig-up-macos.sh`",
            executed=0,
            total=1,
            certifies=_CERTIFIES,
            opt_out_env="C64_ALLOW_SKIP",
        )

    # Only once the rig is otherwise complete does contention mean anything.
    # Its own category: the rig is here, someone else has it.  Exit 2 like any
    # could-not-run, but with NO opt-out -- see _rig_check().
    if contention:
        return cannot_run(
            "rig is contended:\n    - " + "\n    - ".join(contention)
            + "\n    fix: wait for the other run, or kill YOUR stale "
              "instance",
            executed=0,
            total=1,
            certifies=_CERTIFIES,
            opt_out_env=None,
        )

    if os.environ.get("C64_SKIP_BUILD") != "1":
        _build_prg()
    assert os.path.exists(PRG_PATH), f"{PRG_PATH} missing"

    print(f"=== Starting HTTPS listener on {HOST_IP}:{HTTPS_PORT} ===")
    listener = start_https_listener(
        host=HOST_IP, port=HTTPS_PORT, response_body=RESPONSE_BODY)
    print(f"  cert: {listener.cert_path} ({listener.cert_profile})")

    # Self-probe: macOS "Local Network" privacy gating can silently block
    # the python interpreter's sockets on the feth network until the user
    # approves a one-time prompt — the C64 then sees dead air at TCP
    # CONNECT and the failure looks like a client bug. A plain TCP
    # connect to our own listener catches that class before VICE starts.
    import socket
    try:
        probe = socket.create_connection((HOST_IP, HTTPS_PORT), timeout=5)
        probe.close()
        print("  listener self-probe OK")
    except OSError as e:
        stop_https_listener(listener)
        print(f"FAIL: listener unreachable at {HOST_IP}:{HTTPS_PORT} ({e}).")
        print("  Likely cause: macOS Local Network permission for python is")
        print("  unapproved (System Settings > Privacy & Security > Local")
        print("  Network) — approve it and rerun.")
        return 1

    proc = _launch_vice()
    transport = None
    t0 = time.monotonic()
    try:
        transport = _connect()

        print("=== Waiting for boot menu ===")
        try:
            wait_for_screen_text(transport, MENU_NEEDLE, timeout=90.0)
        except TimeoutError:
            # VICE's autostart occasionally injects LOAD but the RUN
            # keystroke gets lost; if the program is loaded and BASIC is
            # sitting at READY., type RUN ourselves.
            screen = get_screen_text(transport).upper()
            if "LOADING" in screen and "READY." in screen:
                print("  autostart stalled at READY. — typing RUN")
                for ch in "RUN":
                    press_key(transport, ch)
                press_key(transport, 13)  # Return
                wait_for_screen_text(transport, MENU_NEEDLE, timeout=120.0)
            else:
                raise
        t_menu = time.monotonic() - t0
        print(f"  menu OK (+{t_menu:.0f}s)")

        # Boot auto-runs DHCP; retry via 'I' if the auto attempt lost the
        # race against dnsmasq's OFFER latency.
        screen = get_screen_text(transport)
        tries = 0
        while DHCP_OK_NEEDLE not in screen.upper():
            if tries >= 3:
                print("FAIL: DHCP not acquired after 3 attempts")
                print(screen)
                return 1
            tries += 1
            print(f"=== DHCP attempt {tries} (pressing 'I') ===")
            press_key(transport, "I")
            try:
                wait_for_screen_text(transport, DHCP_OK_NEEDLE, timeout=90.0)
            except TimeoutError:
                pass
            screen = get_screen_text(transport)
        t_dhcp = time.monotonic() - t0
        print(f"  DHCP OK (+{t_dhcp:.0f}s)")

        if not NO_WARP:
            # VICE 3.10 has no runtime warp control: no "WarpMode"
            # resource ("InitialWarpMode" is launch-only), and on this
            # SDL2 build the "Speed" percent resource yields only ~1.2x
            # measured (frame pacing dominates). Set it anyway — a
            # future VICE may honor it — but budget timeouts for ~1x.
            # True warp (-warp at launch) is unusable because DHCP dies
            # under it (see module docstring timing model).
            try:
                transport.resource_set("Speed", 100000)
                print("  Speed=100000 requested (measured ~1.2x on "
                      "SDL2 3.10 — plan wall-clock for ~1x)")
            except Exception as e:  # noqa: BLE001
                print(f"  speed boost unavailable ({e}) — continuing at 1x")

        print("=== Pressing 'G' for HTTPS GET ===")
        press_key(transport, "G")

        # Per-phase timeline: record the first wall-clock time the
        # "current phase" (latest progress needle in screen reading
        # order) CHANGES to each value after 'G'. Change-detection
        # rather than substring-presence so banner text that embeds a
        # short needle (e.g. "CH" inside "CHACHA20-POLY1305") doesn't
        # fake a phase entry: a phase is only logged when it becomes
        # the latest needle on screen, which banner text (top of
        # screen) stops being as soon as real progress prints below it.
        t_g = time.monotonic()
        phase_log: list[tuple[str, float]] = []
        cur_phase = _last_progress(get_screen_text(transport))

        deadline = time.monotonic() + TLS_TIMEOUT
        heartbeat = time.monotonic() + 30.0
        result, reason = None, ""
        while time.monotonic() < deadline:
            # Binary-monitor reads leave the CPU PAUSED — resume every
            # iteration or the emulation only runs between polls (seen
            # as 14 s of CPU in 38 min, "CH" forever). Mirrors
            # wait_for_screen_text / tests/rig_phase3_https.py.
            try:
                transport.resume()
            except Exception:  # noqa: BLE001
                pass
            time.sleep(3.0)
            try:
                screen = get_screen_text(transport)
            except Exception:  # noqa: BLE001
                continue
            upper = screen.upper()
            phase = _last_progress(screen)
            if phase != cur_phase:
                cur_phase = phase
                phase_log.append((phase, time.monotonic() - t_g))
                print(f"  phase +{phase_log[-1][1]:7.1f}s  {phase}")
            if SUCCESS_NEEDLE in upper:
                result = "pass"
                break
            hit = [n for n in FAIL_NEEDLES if n in upper]
            if hit:
                result, reason = "fail", hit[0]
                break
            if time.monotonic() > heartbeat:
                heartbeat = time.monotonic() + 30.0
                print(f"  ... +{time.monotonic() - t0:.0f}s "
                      f"progress: {phase}")

        t_end = time.monotonic() - t0
        final = get_screen_text(transport)
        print("=== Final screen ===")
        print(final)
        if phase_log:
            print("=== Phase timeline (seconds after 'G') ===")
            prev = 0.0
            for phase, ts in phase_log:
                print(f"  {ts:8.1f}  (+{ts - prev:7.1f})  {phase}")
                prev = ts
        if result == "pass":
            # Verify the response from C64 memory, not the screen — the
            # 22-byte body scrolls off the 25-line display behind the
            # HTTP headers. http_get only completes (-> CONNECTION
            # CLOSED) once http_resp_len == Content-Length, so memory
            # holds the ground truth.
            # Semantics (post issue #72 fix): the demo now routes through
            # the shared http_recv_body, so http_status holds the parsed
            # status code and http_resp_buf/http_resp_len hold the BODY
            # (Content-Length-terminated) — the same contract as the
            # http_get path the UCI tests drive. Assert the full contract.
            ok_body = False
            detail = "labels unavailable"
            try:
                labels = Labels.from_file(
                    os.path.join(_REPO_ROOT, "build", "labels.txt"))
                status = read_bytes(transport, labels["http_status"], 2)
                status_val = status[0] | (status[1] << 8)
                rlen = read_bytes(transport, labels["http_resp_len"], 2)
                n = rlen[0] | (rlen[1] << 8)
                raw = read_bytes(transport, labels["http_resp_buf"],
                                 min(n, 512) or 1)
                text = raw.decode("ascii", errors="replace")
                ok_status = status_val == 200
                ok_len = n == len(RESPONSE_BODY)
                ok_payload = text.startswith(RESPONSE_BODY)
                ok_body = ok_status and ok_len and ok_payload
                detail = (f"http_status={status_val} resp_len={n} "
                          f"(expect {len(RESPONSE_BODY)}) "
                          f"body={'match' if ok_payload else text[:40]!r}")
            except Exception as e:  # noqa: BLE001
                detail = f"memory check failed: {e}"
                ok_body = RESPONSE_BODY.split()[0] in final.upper()
            print(f"PASS: handshake+GET complete in {t_end:.0f}s wall "
                  f"(warp={'off' if NO_WARP else 'on'}); {detail}")
            return 0 if ok_body else 1
        if result == "fail":
            print(f"FAIL at stage {reason} (+{t_end:.0f}s); "
                  f"last progress: {_last_progress(final)}")
            _dump_c64_state(transport)
            return 1
        print(f"FAIL: timeout after {TLS_TIMEOUT:.0f}s; "
              f"last progress: {_last_progress(final)}")
        return 1
    finally:
        if transport is not None:
            try:
                transport.resource_set("Speed", 100)
            except Exception:  # noqa: BLE001
                pass
            try:
                transport.close()
            except Exception:  # noqa: BLE001
                pass
        proc.terminate()
        time.sleep(1)
        proc.kill()
        stop_https_listener(listener)


if __name__ == "__main__":
    sys.exit(main())
