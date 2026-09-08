#!/usr/bin/env python3
"""Issue #128: prove on real hardware that the HTTPS banner names the
ACTUAL build target, not the hardcoded `WWW.FOO.BAR` literal it used to.

Why this rig exists at all: `rig_https_wiki.py` and `rig_https_local.py`
both drive `http_get` through a DMA'd trampoline, so neither one ever
executes `do_https_get` — which is where the banner lives. The wikipedia
run can PASS with a banner that says anything. This rig walks the MENU
instead, the way a human does: 'I' to init, 'G' to start the GET, then
reads screen RAM at $0400 and looks at the line.

It deliberately lets the whole fetch finish and then sends 'Q' to leave
the viewer, because `do_https_get` only reaches its `tls_close` /
`net_tcp_close` after the viewer returns. Resetting a machine with a live
firmware socket poisons the UCI lease path (GET_IPADDR returns 0.0.0.0 on
every interface afterwards) and ONLY a wall power cycle clears it — see
CLAUDE.md "U64E lease-poisoning". So the clean exit is not politeness, it
is the difference between finishing and bricking the device for the day.

Issue #210: it also asserts that the BODY IS COMPLETE, which it could not
do before. The old check was `total >= 125_000` — a stale literal about a
user-editable Wikipedia article (measured at 125,703 B on 2026-09-07) —
and the `ok` it computed was assigned and then never consulted by the
verdict. A run reaching 73,720 B printed `WARNING: body stalled` and
`PASS`, exit 0. Being the only rig on the `do_https_get` path, that is why
#211's silent truncation went unnoticed.

Completeness is now derived from the RESPONSE'S OWN FRAMING —
`Content-Length` versus consumed bytes, or the arrival of the terminal
chunk — by `tools/http_body_checks.py`, which mirrors `src/http.s`'s
`http_recv_timeout_verdict` branch for branch. That oracle has a
hardware-free red case per branch (`tools/test_http_body_checks_unit.py`)
and a mutation runner (`tools/mutate_http_body_checks.py`).

Exit: 0 pass, 1 fail, 78 inconclusive (framing that says nothing about
length, or a poll budget that expired mid-body — never promoted to a
pass), 2 fatal, 3 DeviceLock timeout. The codes come from
`http_body_checks.decide_exit`, which also decides which one applies; this
file does not compute an exit code of its own.

    U64_HOST=10.43.23.81 tools/uci/rig_https_banner.py
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from c64_test_harness.backends.device_lock import (
    DeviceLock, DeviceLockTimeout,
)
from c64_test_harness.backends.ultimate64_client import Ultimate64Client
from c64_test_harness.backends.ultimate64_helpers import (
    CAT_U64_SPECIFIC, cpu_speed_enum, set_turbo_mhz,
)
from c64_test_harness.uci_network import disable_uci, enable_uci

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _device_lock_helper import (  # noqa: E402
    LockTimeoutConfigError, acquire_device_lock,
)
from boot_check import decode_screen, screen_text  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from http_body_checks import (  # noqa: E402
    EXIT_FAIL, EXIT_INCONCLUSIVE, EXIT_PASS, SYMBOLS, check_body_complete,
    check_fetch_settled, check_http_status, decide_exit, decode_body_state,
)
from ip65_hw_checks import check_shadow_ram_readable  # noqa: E402

HOST = os.environ.get("U64_HOST", "192.168.1.81")
PRG_PATH = Path(__file__).resolve().parents[2] / "build" / "c64-https.prg"
EXPECT_HOST = os.environ.get("HTTPS_HOST", "en.wikipedia.org").upper()
#: The rig used to inherit whatever CPU speed the previous lane left in the
#: device config, and got away with it because its only verdict was the
#: banner, which is clock-independent. A COMPLETENESS verdict is not: a
#: 1 MHz U64E needs ~35 min to reach the first body byte, so an inherited
#: 1 MHz would report a truncated fetch that is merely a slow one. Measured
#: 2026-09-07: the device was at ' 1' and the first run of this rig timed
#: out at "tcp connected". So the clock is now set, not assumed, and the
#: budgets below scale with it. NOT every literal in this file does: the
#: 40 s banner-capture window after 'G' is a screen-scrape race against
#: scrolling, not a work budget, and is deliberately left alone.
TURBO_MHZ = int(os.environ.get("TURBO_MHZ", "48"))
_SCALE = max(1.0, 48.0 / float(TURBO_MHZ))

INIT_WAIT = float(os.environ.get("C64_INIT_WAIT", str(75 * _SCALE)))
DHCP_TIMEOUT = float(os.environ.get("DHCP_TIMEOUT", str(90 * _SCALE)))
FETCH_TIMEOUT = float(os.environ.get("FETCH_TIMEOUT", str(300 * _SCALE)))


def label_addr(name: str) -> int:
    """Read a symbol address out of build/labels.txt (VICE `al C:XXXX .name`)."""
    labels = PRG_PATH.parent / "labels.txt"
    for line in labels.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == "." + name:
            return int(parts[1].split(":")[1], 16)
    raise KeyError(f"{name} not in {labels}")


def screen(client) -> tuple[list[str], str]:
    lines = decode_screen(bytes(client.read_mem(0x0400, 1000)))
    return lines, screen_text(lines)


def wait_for(client, marker: str, budget: float, label: str) -> tuple[bool, list[str]]:
    deadline = time.monotonic() + budget
    while True:
        lines, text = screen(client)
        if marker in text:
            print(f"  [{label}] '{marker}' reached")
            return True, lines
        if time.monotonic() >= deadline:
            print(f"  [{label}] '{marker}' NOT seen within {budget:.0f}s")
            return False, lines
        time.sleep(2.0)


def dump(lines: list[str], title: str) -> None:
    print(f"\n--- {title} ---")
    for i, line in enumerate(lines):
        if line.strip():
            print(f"{i:02d}: {line}")
    print("--- end ---\n")


def main() -> int:
    if not PRG_PATH.is_file():
        print(f"ERROR: no PRG at {PRG_PATH}", file=sys.stderr)
        return 2
    prg = PRG_PATH.read_bytes()
    print(f"Loaded {len(prg)} B from {PRG_PATH}")
    print(f"Expecting the banner to name: {EXPECT_HOST}")

    lock = DeviceLock(HOST)
    try:
        # Budget: C64_DEVICE_LOCK_TIMEOUT, else 30 min. The old
        # bare-bool acquire() discarded every diagnostic the
        # harness had gathered and reported only False.
        acquire_device_lock(lock)
    except LockTimeoutConfigError as exc:
        print(f"[fatal] {exc}", file=sys.stderr)
        return 2
    except DeviceLockTimeout as exc:
        print(f"[fatal] DeviceLock({HOST}): {exc}", file=sys.stderr)
        return 3
    print(f"Acquired DeviceLock({HOST})")

    client = None
    uci_on = False
    try:
        client = Ultimate64Client(host=HOST, timeout=20.0)
        enable_uci(client)
        uci_on = True

        # fw <= 3.14d leaks one /Temp file per REST body; run_prg is a big
        # writemem, and a session's worth of them wedges REST and the UCI
        # bridge together (CLAUDE.md "writemem exhaustion wedge"). Cheap
        # insurance, same as the live/wiki rigs.
        if os.environ.get("C64_SKIP_TEMP_GC") != "1":
            try:
                from _temp_gc import gc_temp
                removed = gc_temp(HOST)
                print(f"/Temp GC: removed {removed} stale file(s)")
            except Exception as exc:
                print(f"WARNING: /Temp GC skipped: {exc}")

        # Set turbo BEFORE the reset, and skip a redundant write. The
        # config WRITE itself perturbs the UCI bridge and the next pushed
        # command is silently lost (UCI_ERR_NO_SOCKET) — it fires on a
        # write that changes nothing, and it survives the reset. Same
        # reasoning and same shape as rig_https_local.py; read its comment
        # for the 3/3 C64U reproduction behind it.
        try:
            cat = client.get_config_category(CAT_U64_SPECIFIC)
            inner = cat.get(CAT_U64_SPECIFIC, cat)
            cur_speed, cur_turbo = inner.get("CPU Speed"), inner.get("Turbo Control")
        except Exception as exc:                      # probe is best-effort
            print(f"  (turbo state probe failed: {exc}; writing anyway)")
            cur_speed = cur_turbo = None
        # str() and strip() BOTH sides of both comparisons: the REST
        # value's type and padding are the firmware's business ('CPU Speed'
        # comes back as ' 1'), and an asymmetric compare here fails safe but
        # silently — it would just always write, restoring the bridge glitch
        # this skip exists to avoid.
        if str(cur_speed).strip() == str(cpu_speed_enum(TURBO_MHZ)).strip() \
                and str(cur_turbo).strip() == "Manual":
            print(f"Turbo already {TURBO_MHZ} MHz (Manual) — skipping the write")
        else:
            print(f"Setting turbo to {TURBO_MHZ} MHz (from {cur_turbo}/{cur_speed})...")
            try:
                set_turbo_mhz(client, TURBO_MHZ)
            except ValueError as exc:
                # An unsupported TURBO_MHZ is an operator error, and the
                # rig's own code for that is 2 (fatal), not 1 (a check
                # failed) and not a traceback.
                print(f"[fatal] TURBO_MHZ={TURBO_MHZ}: {exc}", file=sys.stderr)
                return 2
            time.sleep(float(os.environ.get("TURBO_SETTLE", "3.0")))

        client.reset()
        time.sleep(2.5)
        client.run_prg(prg)

        print(f"Waiting up to {INIT_WAIT:.0f}s for the menu (comb boot precompute)...")
        ok, lines = wait_for(client, "Q=QUIT", INIT_WAIT + 30, "boot")
        if not ok:
            dump(lines, "screen at boot timeout")
            return 1

        print("Pressing 'I' (init network)...")
        client.send_text("I", finish_with_return=False)
        ok, lines = wait_for(client, "DHCP OK", DHCP_TIMEOUT, "dhcp")
        if not ok:
            dump(lines, "screen at DHCP timeout")
            return 1

        print("Pressing 'G' (HTTPS GET) — reading the banner...")
        client.send_text("G", finish_with_return=False)

        # decode_screen() returns LOWERCASE letters — only screen_text()
        # uppercases, when it joins the rows. Comparing a raw row against
        # "HTTPS GET" therefore never matches, which is exactly how the first
        # version of this rig reported "no banner appeared" against a screen
        # that very likely had one. Uppercase the row before testing it.
        #
        # No sleep on the first pass either: at 48 MHz the handshake prints
        # ~24 progress markers (sh/hk1/keys/enc1/rx/got2...) and scrolls the
        # banner off the 25-row screen, so the read has to start immediately
        # and stay tight.
        banner = None
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            lines, _ = screen(client)
            for line in lines:
                up = line.strip().upper()
                if up.startswith("HTTPS GET"):
                    banner = up
                    break
            if banner:
                break

        if banner is None:
            dump(lines, "screen with no HTTPS GET line")
            print("FAIL: no 'HTTPS GET' banner appeared", file=sys.stderr)
            return 1

        print(f"\n  BANNER: {banner!r}\n")
        names_target = EXPECT_HOST in banner
        says_foobar = "FOO.BAR" in banner
        print(f"  names {EXPECT_HOST}: {names_target}")
        print(f"  says FOO.BAR       : {says_foobar}")
        banner_ok = names_target and not says_foobar

        # Let the fetch finish so do_https_get reaches tls_close/net_tcp_close.
        #
        # Poll http_body_total over DMA rather than scraping for a viewer
        # marker: the viewer's status row ends in "Q=QUIT" and so does the
        # main menu, so the obvious screen marker cannot tell them apart.
        # The byte counter is unambiguous and is what rig_https_wiki.py
        # uses as its progress signal too.
        print("Letting the fetch run to completion (socket must close cleanly)...")
        addrs = {name: label_addr(name) for name in SYMBOLS}

        # ONE DMA read per poll, not seven. The symbols are scattered across
        # a few hundred bytes of CRYPTO_COLD_SHADOW, and this loop runs every
        # 2 s for up to FETCH_TIMEOUT — seven REST round-trips a tick is
        # traffic the shared device does not need. Span, then slice; the
        # bounds come from labels.txt, so they follow the build.
        span_lo = min(addrs.values())
        span_hi = max(addrs[n] + w for n, w in SYMBOLS.items())
        assert span_hi - span_lo <= 8192, (
            f"the http parser state now spans {span_hi - span_lo} B "
            f"(${span_lo:04X}-${span_hi:04X}); read it per symbol instead")

        def read_state():
            blob = bytes(client.read_mem(span_lo, span_hi - span_lo))
            raw = {}
            for name, width in SYMBOLS.items():
                off = addrs[name] - span_lo
                raw[name] = blob[off:off + width]
            return decode_body_state(raw)

        # Everything above lives in CRYPTO_COLD_SHADOW, RAM under the BASIC
        # ROM, and a host DMA read of $A000+ follows the machine's banking.
        # With BASIC banked IN every value below is a ROM byte: plausible,
        # consistently wrong, and a completeness verdict computed from ROM
        # is worse than no verdict at all. boot.s banks it out for runtime
        # operation; this is how we know it did.
        shadow = check_shadow_ram_readable(bytes(client.read_mem(0xA000, 16)))
        print(f"  shadow RAM: {shadow.reason}")

        started = time.monotonic()
        deadline = started + FETCH_TIMEOUT
        last_print = 0.0
        state = None
        body = None
        # A body still growing when the budget expires is a budget problem,
        # not a truncation. Track when the consumed count last moved.
        last_total, last_moved = None, started
        settled = check_fetch_settled(False, 0.0, FETCH_TIMEOUT)
        while time.monotonic() < deadline:
            state = read_state()
            body = check_body_complete(state)
            if body.ok:
                print(f"  {body.reason}")
                break
            now = time.monotonic()
            if state.body_total != last_total:
                last_total, last_moved = state.body_total, now
            if now - last_print > 15:
                print(f"  {state.summary()}")
                last_print = now
            time.sleep(2.0)
        else:
            print(f"  fetch did not complete within {FETCH_TIMEOUT:.0f}s")
            # STALL_GRACE: two poll ticks plus slack. Shorter and a slow
            # server reads as a stall; longer and a real stall reads as
            # progress.
            grace = float(os.environ.get("STALL_GRACE", "10"))
            settled = check_fetch_settled(
                time.monotonic() - last_moved < grace,
                time.monotonic() - started, FETCH_TIMEOUT)

        print("Sending 'Q' to leave the viewer so the socket closes...")
        client.send_text("Q", finish_with_return=False)
        ok, lines = wait_for(client, "CONNECTION CLOSED", 120 * _SCALE,
                             "close")
        dump(lines, "final screen")
        if not ok:
            print("WARNING: never saw CONNECTION CLOSED — leaving the machine "
                  "as-is rather than resetting it (a reset with a live socket "
                  "poisons the UCI lease; power cycle only).", file=sys.stderr)

        # THE VERDICT IS COMPUTED FROM THE STATE CAPTURED WHILE THE
        # TRANSPORT WAS LIVE, above, and deliberately NOT re-read here.
        # #211's first method trap: a post-hoc read of these symbols came
        # back all zeros — including http_status — on a run the rig itself
        # had read as 200. A verdict recomputed after 'Q' would be a
        # verdict about the wrong moment.
        status = check_http_status(state) if state is not None else None

        # The decision itself is decide_exit(), in tools/http_body_checks.py,
        # so that it is EXECUTED by the unit suite rather than inspected. It
        # used to be five lines here, and an adversarial review found five
        # one-token mutations of those lines that no AST guard could see —
        # two of which restored #210 (exit 0 on a body just reported as
        # truncated). Keep this a call; do not re-grow the logic in the rig.
        # BY KEYWORD, and that is not a style preference. Transposing
        # `settled` and `status` positionally survives every guard there
        # is — the names are all still present — and hands the
        # still-growing gate a status verdict that is never inconclusive,
        # so the gate silently dies and the cry-wolf failure returns. A
        # plausible signature-refactor slip; keywords remove it.
        code, report = decide_exit(banner_ok=banner_ok, shadow=shadow,
                                   settled=settled, status=status, body=body)
        print()
        for line in report[:-1]:
            print(line)
        print(report[-1], file=sys.stderr if code else sys.stdout)
        return code
    finally:
        if uci_on and client is not None:
            try:
                disable_uci(client)
            except Exception as exc:
                print(f"WARNING: disable_uci failed: {exc}")
        lock.release()
        print(f"Released DeviceLock({HOST})")


if __name__ == "__main__":
    sys.exit(main())
