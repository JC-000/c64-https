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

Issue #226: the poll loop may stop before FETCH_TIMEOUT, but only once
`http_body_checks.should_stop_early` says the budget-expiry verdict is
already fixed (a framed body failing its check, `net_tcp_state` ERROR or
CLOSED, frozen for STALL_ABORT). It prints "STOPPED EARLY, budget not
exhausted", still sends 'Q', and changes no verdict — only when the loop
ends.

Device state is `_device_prep.prepare_device` (48 MHz, plus the REU when
the build needs one), with `preflight_reu` behind it — the same two steps,
in the same order, as the other five crypto-path rigs.

Exit: 0 pass, 1 fail, 78 inconclusive (framing that says nothing about
length, or a poll budget that expired mid-body — never promoted to a
pass), 2 fatal, 3 DeviceLock timeout, 4 device prep / REU preflight. The codes come from
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
from c64_test_harness.uci_network import disable_uci, enable_uci

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _device_lock_helper import (  # noqa: E402
    LockTimeoutConfigError, acquire_device_lock,
)
from _device_prep import DevicePrepError, prepare_device  # noqa: E402
from _reu_preflight import ReuPreflightError, preflight_reu  # noqa: E402
from boot_check import decode_screen, screen_text  # noqa: E402
# Run-dir helpers, imported rather than copied: `rig_https_wiki.py` already
# takes them from here, and a third copy of "make a timestamped directory"
# is a third thing to drift.
from rig_https_local import (  # noqa: E402
    _create_run_dir, _prune_old_run_dirs,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from http_body_checks import (  # noqa: E402
    EXIT_FAIL, EXIT_INCONCLUSIVE, EXIT_PASS, NET_TCP_CLOSED, STALL_ABORT,
    STALL_ABORT_MIN, STALL_GRACE, SYMBOLS, check_body_complete,
    check_fetch_settled, check_http_status, decide_exit, decode_body_state,
    should_stop_early,
)
from ip65_hw_checks import check_shadow_ram_readable  # noqa: E402

HOST = os.environ.get("U64_HOST", "192.168.1.81")
PRG_PATH = Path(__file__).resolve().parents[2] / "build" / "c64-https.prg"
LABELS_PATH = PRG_PATH.parent / "labels.txt"
EXPECT_HOST = os.environ.get("HTTPS_HOST", "en.wikipedia.org").upper()

#: This rig runs no bus capture, so unlike `rig_https_local` it has no run
#: directory of its own to put `device_state.json` in — it always creates
#: one, which is `bench_ecdsa_u64e.py`'s capture-off branch without the
#: branch. Same base directory as the local/wiki rigs so a session's
#: artifacts stay together, same 5-deep rotation.
DEBUG_BASE_DIR = Path(os.environ.get("UCI_DEBUG_DIR", "/tmp/uci_https_debug"))
DEBUG_KEEP = 5
#: The rig used to inherit whatever CPU speed the previous lane left in the
#: device config, and got away with it because its only verdict was the
#: banner, which is clock-independent. A COMPLETENESS verdict is not: a
#: 1 MHz U64E needs ~35 min to reach the first body byte, so an inherited
#: 1 MHz would report a truncated fetch that is merely a slow one. Measured
#: 2026-09-07: the device was at ' 1' and the first run of this rig timed
#: out at "tcp connected". So the clock is now set, not assumed — through
#: `_device_prep.prepare_device`, not inline — and the budgets below scale
#: with it. NOT every literal in this file does: the 40 s banner-capture
#: window after 'G' is a screen-scrape race against scrolling, not a work
#: budget, and is deliberately left alone.
TURBO_MHZ = int(os.environ.get("TURBO_MHZ", "48"))
_SCALE = max(1.0, 48.0 / float(TURBO_MHZ))

INIT_WAIT = float(os.environ.get("C64_INIT_WAIT", str(75 * _SCALE)))
DHCP_TIMEOUT = float(os.environ.get("DHCP_TIMEOUT", str(90 * _SCALE)))
FETCH_TIMEOUT = float(os.environ.get("FETCH_TIMEOUT", str(300 * _SCALE)))
#: #226: how long a decided truncation must sit frozen, on a socket that can
#: deliver nothing more, before the loop stops ahead of FETCH_TIMEOUT. The
#: conditions are `http_body_checks.should_stop_early`'s; this is only the
#: time margin, and that function refuses one below STALL_ABORT_MIN.
STALL_ABORT_S = float(os.environ.get("STALL_ABORT", str(STALL_ABORT * _SCALE)))


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


def wait_for(client, marker: str, budget: float, label: str,
             also=None) -> tuple[bool, list[str]]:
    """Poll the screen for `marker`; `also()` returning a string is an
    equivalent positive signal (it names what was seen)."""
    deadline = time.monotonic() + budget
    while True:
        lines, text = screen(client)
        if marker in text:
            print(f"  [{label}] '{marker}' reached")
            return True, lines
        seen = also() if also is not None else None
        if seen:
            print(f"  [{label}] {seen}")
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
    # #226: refuse a too-small STALL_ABORT HERE, before the device is
    # touched. should_stop_early raises on one, and a raise inside the poll
    # loop would skip the 'Q' below with a live socket.
    if STALL_ABORT_S < STALL_ABORT_MIN:
        print(f"[fatal] STALL_ABORT={STALL_ABORT_S:.0f}s is below the "
              f"{STALL_ABORT_MIN:.0f}s floor", file=sys.stderr)
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

        # --- Device prep: reset-then-configure (#197, #187, #212) -------
        # This rig used to probe `CPU Speed` / `Turbo Control` inline and,
        # when the read failed, perform the write regardless — the #187
        # degrade, reintroduced by composition: the turbo handling arrived
        # in #227 while #225's KNOWN_UNPREPPED still exempted this file on
        # the grounds that it had no device-state handling at all. It does
        # now, so it goes through the one home for that policy like the
        # other five crypto-path rigs. An unreadable turbo state ABORTS here
        # (C64_FORCE_TURBO_WRITE=1 to override); an unreadable REU state
        # degrades toward the write, which is the safe direction there.
        #
        # 48 MHz, asserted rather than inherited. The clock is load-bearing
        # for this rig specifically: its completeness verdict is what a
        # 1 MHz device turns into a false TRUNCATED, and a comb boot at
        # 1 MHz needs ~36 min against C64_INIT_WAIT — #212's own failure.
        prep_dir = _create_run_dir(DEBUG_BASE_DIR)
        _prune_old_run_dirs(DEBUG_BASE_DIR, keep=DEBUG_KEEP)
        print(f"Device-state record dir: {prep_dir} (device_state.json)")
        try:
            prepare_device(client, LABELS_PATH, turbo_mhz=TURBO_MHZ,
                           artifact_dir=prep_dir)
        except DevicePrepError as exc:
            print(str(exc), file=sys.stderr)
            return 4
        except ValueError as exc:
            # NOT a second copy of the turbo policy: prepare_device calls
            # the harness's set_turbo_mhz uncaught, and an unsupported
            # speed raises ValueError rather than DevicePrepError. That is
            # an operator typo in TURBO_MHZ, and this rig's code for that
            # is 2 (fatal), not a traceback at exit 1. Worth pushing into
            # _device_prep so all six call sites agree; owned by another
            # lane, so it is reported rather than edited from here.
            print(f"[fatal] TURBO_MHZ={TURBO_MHZ}: {exc}", file=sys.stderr)
            return 2

        # The #97 preflight stays as the backstop BEHIND the prep, and it
        # matters more here than it used to: this rig is now a completeness
        # oracle with a 900 s default budget, so a comb PRG on a
        # REU-disabled device (the documented factory default) would spin
        # far longer before failing than it did when the rig only read a
        # banner.
        try:
            preflight_reu(client, LABELS_PATH)
        except ReuPreflightError as exc:
            print(str(exc), file=sys.stderr)
            return 4

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

        # #226: the UCI adapter's socket state, read only once the other
        # early-stop conditions already hold. A missing label means the
        # loop never stops early (should_stop_early treats None as "may
        # still deliver"), which is the pre-#226 behaviour.
        try:
            tcp_addr = label_addr("net_tcp_state")
        except KeyError:
            tcp_addr = None

        def read_tcp_state():
            if tcp_addr is None:
                return None
            return bytes(client.read_mem(tcp_addr, 1))[0]

        started = time.monotonic()
        deadline = started + FETCH_TIMEOUT
        last_print = 0.0
        state = None
        body = None
        # A body still growing when the budget expires is a budget problem,
        # not a truncation. Track when the consumed count last moved.
        last_total, last_moved = None, started
        settled = check_fetch_settled(False, 0.0, FETCH_TIMEOUT)
        stopped_early = False
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
            # #226: a verdict that can no longer change need not wait out
            # FETCH_TIMEOUT. The socket byte is read only past the time
            # margin, so a healthy fetch costs no extra REST traffic.
            if now - last_moved >= STALL_ABORT_S:
                stop, why = should_stop_early(
                    state, read_tcp_state(), now - last_moved,
                    stall_abort=STALL_ABORT_S, shadow_ok=shadow.ok)
                if stop:
                    print(f"  {state.summary()}")
                    print(f"  {why}")
                    stopped_early = True
                    settled = check_fetch_settled(
                        False, now - started, FETCH_TIMEOUT)
                    break
            time.sleep(2.0)
        else:
            print(f"  fetch did not complete within {FETCH_TIMEOUT:.0f}s")
            # STALL_GRACE: two poll ticks plus slack. Shorter and a slow
            # server reads as a stall; longer and a real stall reads as
            # progress.
            grace = float(os.environ.get("STALL_GRACE", str(STALL_GRACE)))
            settled = check_fetch_settled(
                time.monotonic() - last_moved < grace,
                time.monotonic() - started, FETCH_TIMEOUT)

        print("Sending 'Q' to leave the viewer so the socket closes...")
        client.send_text("Q", finish_with_return=False)

        # #226: after an early stop the marker may never be printed (or has
        # scrolled away), and waiting the full window was pure cost. The
        # wait still ends only on POSITIVE evidence: net_tcp_state reading
        # NET_TCP_CLOSED means net_tcp_close has run — it is the store
        # just before do_https_get prints the marker. Same window, same
        # "never reset" rule if neither signal arrives.
        def client_closed():
            if stopped_early and read_tcp_state() == NET_TCP_CLOSED:
                return "net_tcp_state=CLOSED (net_tcp_close has run)"
            return None

        ok, lines = wait_for(client, "CONNECTION CLOSED", 120 * _SCALE,
                             "close", also=client_closed)
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
