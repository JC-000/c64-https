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

    U64_HOST=10.43.23.81 tools/uci/rig_https_banner.py
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from c64_test_harness.backends.device_lock import DeviceLock
from c64_test_harness.backends.ultimate64_client import Ultimate64Client
from c64_test_harness.uci_network import disable_uci, enable_uci

sys.path.insert(0, str(Path(__file__).resolve().parent))
from boot_check import decode_screen, screen_text  # noqa: E402

HOST = os.environ.get("U64_HOST", "192.168.1.81")
PRG_PATH = Path(__file__).resolve().parents[2] / "build" / "c64-https.prg"
EXPECT_HOST = os.environ.get("HTTPS_HOST", "en.wikipedia.org").upper()
INIT_WAIT = float(os.environ.get("C64_INIT_WAIT", "75"))
DHCP_TIMEOUT = float(os.environ.get("DHCP_TIMEOUT", "90"))
FETCH_TIMEOUT = float(os.environ.get("FETCH_TIMEOUT", "300"))


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
    if not lock.acquire(timeout=120.0):
        print(f"ERROR: could not acquire DeviceLock({HOST})", file=sys.stderr)
        return 3
    print(f"Acquired DeviceLock({HOST})")

    client = None
    uci_on = False
    verdict = 1
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
        verdict = 0 if (names_target and not says_foobar) else 1

        # Let the fetch finish so do_https_get reaches tls_close/net_tcp_close.
        #
        # Poll http_body_total over DMA rather than scraping for a viewer
        # marker: the viewer's status row ends in "Q=QUIT" and so does the
        # main menu, so the obvious screen marker cannot tell them apart.
        # The byte counter is unambiguous and is what rig_https_wiki.py
        # uses as its progress signal too.
        print("Letting the fetch run to completion (socket must close cleanly)...")
        body_addr = label_addr("http_body_total")
        deadline = time.monotonic() + FETCH_TIMEOUT
        total = 0
        last_print = 0.0
        while time.monotonic() < deadline:
            raw = bytes(client.read_mem(body_addr, 3))
            total = raw[0] | (raw[1] << 8) | (raw[2] << 16)
            if total >= 125_000:
                print(f"  body complete: {total:,} B")
                break
            if time.monotonic() - last_print > 15:
                print(f"  http_body_total={total:,} B")
                last_print = time.monotonic()
            time.sleep(2.0)
        else:
            print(f"  WARNING: body stalled at {total:,} B")
        ok = total >= 125_000
        print("Sending 'Q' to leave the viewer so the socket closes...")
        client.send_text("Q", finish_with_return=False)
        ok, lines = wait_for(client, "CONNECTION CLOSED", 120, "close")
        dump(lines, "final screen")
        if not ok:
            print("WARNING: never saw CONNECTION CLOSED — leaving the machine "
                  "as-is rather than resetting it (a reset with a live socket "
                  "poisons the UCI lease; power cycle only).", file=sys.stderr)

        print("PASS: banner names the real target" if verdict == 0
              else "FAIL: banner did not name the real target", file=sys.stderr if verdict else sys.stdout)
        return verdict
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
