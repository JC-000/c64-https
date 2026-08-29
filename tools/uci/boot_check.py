#!/usr/bin/env python3
"""
Phase 1b boot check for the UCI backend.

Uploads build/c64-https.prg (assumed to have been built with
`make BACKEND=uci`) to the U64E (default 192.168.1.81, overridable via
U64_HOST), waits for the PRG to reach its main menu, reads screen RAM at
$0400 (40x25 = 1000 bytes), decodes the Commodore screen-code bytes to
ASCII, and asserts the boot actually succeeded.

Pass criteria (all must hold):

  1. The PRG image on disk carries the *expected backend's* banner string
     (checked before the device is touched — catches a stale
     `build/c64-https.prg` from a different BACKEND=).
  2. The screen shows the common banner `C64-HTTPS CLIENT V0.1`.
  3. The screen shows the expected backend's network line, and not the
     other backend's.
  4. No `FAILED` anywhere on the screen (`NETWORK INIT FAILED`,
     `DHCP FAILED`, ...).
  5. The main menu (`Q=QUIT`) was reached, i.e. boot ran to completion.
  6. (uci only) CIA1's TOD is ticking. The CIA's TOD is halted out of
     reset and starts only when TENTHS is written; every bounded wait in
     `src/net/uci/uci_cmd.s` measures wall-clock by watching TENTHS
     advance, so a halted TOD makes all of them infinite (#145).
     `net_init` calls `uci_tod_start`; this is the regression guard, and
     it has to live in a hardware rig because VICE's CIA runs the TOD
     from reset and cannot reproduce the bug.

The old criterion — "screen has some text and >= 3 distinct byte values" —
only distinguished a booted machine from a blank screen. An ip65/RR-Net
PRG booted on a U64E draws its banner and then `NETWORK INIT FAILED`, and
that criterion returned PASS (audit finding F4).

Usage:
    python3 tools/uci/boot_check.py

Environment:
    U64_HOST     — U64E address (default 192.168.1.81)
    BACKEND      — expected backend, `uci` (default) or `ip65`. The banner
                   is backend-aware, so the assertion has to know which
                   build it is checking.
    C64_PRG      — override the PRG path (default build/c64-https.prg)
    BOOT_TIMEOUT — seconds to wait for the main menu (default 60)
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from c64_test_harness.backends.device_lock import DeviceLock
from c64_test_harness.backends.ultimate64_client import Ultimate64Client
from c64_test_harness.uci_network import disable_uci, enable_uci

HOST = os.environ.get("U64_HOST", "192.168.1.81")
BACKEND = os.environ.get("BACKEND", "uci").strip().lower()
BOOT_TIMEOUT = float(os.environ.get("BOOT_TIMEOUT", "60"))
PRG_PATH = Path(
    os.environ.get(
        "C64_PRG",
        str(Path(__file__).resolve().parents[2] / "build" / "c64-https.prg"),
    )
)

# Backend-specific banner line printed by boot.s between the common
# front-matter and the menu (`net_banner_str`):
#   src/net/ip65/net_banner.s  -> "RR-NET (CS8900A) ETHERNET"
#   src/net/uci/net.s          -> "UCI NETWORKING"
BACKEND_BANNERS = {
    "uci": "UCI NETWORKING",
    "ip65": "RR-NET (CS8900A) ETHERNET",
}

COMMON_BANNER = "C64-HTTPS CLIENT V0.1"
MENU_MARKER = "Q=QUIT"

# CIA1 time-of-day tenths-of-a-second register, and how long to watch it
# before calling it halted. TOD ticks at 10 Hz, so ~1.5 s of sampling is
# many ticks' worth of margin over any plausible REST round-trip jitter.
CIA_TOD_TENTHS = 0xDC08
TOD_SAMPLE_WINDOW = 1.5


# Commodore screen-code -> ASCII (uppercase/graphics mode, codes $00-$3F
# cover the visible uppercase charset we care about for the banner).
def screen_code_to_ascii(b: int) -> str:
    b &= 0x7F  # mask off reverse-video bit
    if b == 0x00:
        return "@"
    if 0x01 <= b <= 0x1A:
        return chr(ord("a") + (b - 0x01))  # $01..$1A -> a..z
    if 0x1B <= b <= 0x1F:
        return "[\\]^_"[b - 0x1B]
    if b == 0x20:
        return " "
    if 0x21 <= b <= 0x3F:
        # $21..$3F maps to ASCII $21..$3F (punctuation + digits)
        return chr(b)
    return "."  # non-printable / graphics


def decode_screen(mem: bytes) -> list[str]:
    lines: list[str] = []
    for row in range(25):
        start = row * 40
        end = start + 40
        text = "".join(screen_code_to_ascii(b) for b in mem[start:end])
        lines.append(text.rstrip())
    return lines


def screen_text(lines: list[str]) -> str:
    """Join the decoded rows into one uppercase haystack.

    Rows are joined with a space rather than concatenated so a string can
    never be manufactured across a row boundary.
    """
    return " ".join(lines).upper()


def evaluate_screen(lines: list[str], backend: str) -> list[tuple[str, bool, str]]:
    """Return [(check name, ok, detail)] for a decoded screen.

    Pure function — no device access — so it can be exercised against a
    captured screen dump.
    """
    text = screen_text(lines)
    expected = BACKEND_BANNERS[backend]
    others = [v for k, v in BACKEND_BANNERS.items() if k != backend]

    results: list[tuple[str, bool, str]] = []

    results.append(
        (
            "common banner",
            COMMON_BANNER in text,
            f"expected {COMMON_BANNER!r}",
        )
    )
    results.append(
        (
            f"{backend} backend banner",
            expected in text,
            f"expected {expected!r}",
        )
    )
    wrong = [o for o in others if o in text]
    results.append(
        (
            "no foreign backend banner",
            not wrong,
            f"found {wrong!r} — wrong-backend PRG?" if wrong else "none present",
        )
    )
    results.append(
        (
            "no FAILED on screen",
            "FAILED" not in text,
            "screen reports a failure"
            if "FAILED" in text
            else "no failure message",
        )
    )
    results.append(
        (
            "main menu reached",
            MENU_MARKER in text,
            f"expected {MENU_MARKER!r}",
        )
    )
    return results


def check_prg_image(prg: bytes, backend: str) -> list[tuple[str, bool, str]]:
    """Verify the PRG on disk was built for the expected backend.

    `net_banner_str` sits in RODATA as plain ASCII, so the built image is
    self-identifying. This runs before the device is touched: a stale
    artifact from a different `BACKEND=` is caught without burning a
    hardware slot.
    """
    expected = BACKEND_BANNERS[backend].encode("ascii")
    others = [
        (k, v.encode("ascii")) for k, v in BACKEND_BANNERS.items() if k != backend
    ]
    results = [
        (
            f"image carries {backend} banner",
            expected in prg,
            f"expected bytes {BACKEND_BANNERS[backend]!r} in the PRG",
        )
    ]
    found = [k for k, v in others if v in prg]
    results.append(
        (
            "image free of foreign banner",
            not found,
            f"image looks like a {found!r} build" if found else "none present",
        )
    )
    return results


def check_tod_running(client) -> tuple[str, bool, str]:
    """Assert CIA1's TOD is actually running — issue #145.

    Reads only TENTHS. Reading the HOUR register would latch the TOD
    until TENTHS is read, and we have no reason to disturb the latch
    state of a machine the adapter is sharing.
    """
    first = client.read_mem(CIA_TOD_TENTHS, 1)[0] & 0x0F
    samples = 1
    deadline = time.monotonic() + TOD_SAMPLE_WINDOW
    while time.monotonic() < deadline:
        time.sleep(0.2)
        now = client.read_mem(CIA_TOD_TENTHS, 1)[0] & 0x0F
        samples += 1
        if now != first:
            return (
                "CIA1 TOD is running",
                True,
                f"TENTHS advanced {first} -> {now} within {samples} samples",
            )
    return (
        "CIA1 TOD is running",
        False,
        f"TENTHS frozen at {first} across {samples} samples over "
        f"{TOD_SAMPLE_WINDOW:.1f}s — every TOD-bounded wait in the UCI "
        f"adapter is therefore unbounded (#145). Is uci_tod_start still "
        f"called from net_init?",
    )


def report(results: list[tuple[str, bool, str]]) -> bool:
    ok = True
    for name, passed, detail in results:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}: {detail}")
        ok = ok and passed
    return ok


def main() -> int:
    if BACKEND not in BACKEND_BANNERS:
        print(
            f"ERROR: BACKEND={BACKEND!r} unknown; expected one of "
            f"{sorted(BACKEND_BANNERS)}",
            file=sys.stderr,
        )
        return 2
    if not PRG_PATH.is_file():
        print(f"ERROR: PRG not found at {PRG_PATH}", file=sys.stderr)
        print("Run: make BACKEND=uci clean && make BACKEND=uci", file=sys.stderr)
        return 2

    prg = PRG_PATH.read_bytes()
    print(f"Loaded {len(prg)} bytes from {PRG_PATH}")
    print(f"Expected backend: {BACKEND} ({BACKEND_BANNERS[BACKEND]!r})")

    print("\n--- PRG image checks ---")
    image_ok = report(check_prg_image(prg, BACKEND))
    if not image_ok:
        print(
            "WARNING: the PRG does not look like a "
            f"{BACKEND} build — running it anyway so the on-device "
            "verdict is recorded too.",
            file=sys.stderr,
        )

    lock = DeviceLock(HOST)
    if not lock.acquire(timeout=60.0):
        print(f"ERROR: could not acquire DeviceLock({HOST})", file=sys.stderr)
        return 3
    print(f"\nAcquired DeviceLock({HOST})")

    client: Ultimate64Client | None = None
    uci_enabled = False
    try:
        client = Ultimate64Client(host=HOST, timeout=15.0)

        if BACKEND == "uci":
            # Without enable_uci the $DF1D identifier register never
            # answers $C9, so net_init reports UCI_ERR_NOT_PRESENT and the
            # banner ends in NETWORK INIT FAILED.
            print("Enabling UCI (Command Interface)...")
            enable_uci(client)
            uci_enabled = True

        print("Resetting machine...")
        client.reset()
        time.sleep(2.5)  # let KERNAL boot

        print("run_prg(PRG)...")
        client.run_prg(prg)

        # Boot does entropy + sqtab + reu_mul_init (~15-18 s on the U64E)
        # before do_net_init and the menu, so poll for the menu rather
        # than guessing a sleep.
        print(f"Waiting up to {BOOT_TIMEOUT:.0f}s for the main menu...")
        deadline = time.monotonic() + BOOT_TIMEOUT
        mem = b""
        lines: list[str] = []
        while True:
            mem = bytes(client.read_mem(0x0400, 1000))
            lines = decode_screen(mem)
            if MENU_MARKER in screen_text(lines):
                print("  main menu reached")
                break
            if time.monotonic() >= deadline:
                print("  main menu never appeared within the budget")
                break
            time.sleep(2.0)

        if len(mem) != 1000:
            print(
                f"WARNING: read_mem returned {len(mem)} bytes, expected 1000",
                file=sys.stderr,
            )

        print("\n--- screen RAM decoded (non-empty lines) ---")
        for i, line in enumerate(lines):
            if line.strip():
                print(f"{i:02d}: {line}")
        print("--- end screen ---\n")

        print("--- boot checks ---")
        screen_ok = report(evaluate_screen(lines, BACKEND))

        # The UCI adapter is the only backend with TOD-bounded waits.
        tod_ok = True
        if BACKEND == "uci":
            print("\n--- CIA1 TOD check (#145) ---")
            tod_ok = report([check_tod_running(client)])

        if image_ok and screen_ok and tod_ok:
            print(f"\nPASS: {BACKEND} PRG booted cleanly to the menu")
            return 0
        print(f"\nFAIL: boot check failed for expected backend {BACKEND}",
              file=sys.stderr)
        return 1

    finally:
        if uci_enabled and client is not None:
            print("Disabling UCI...")
            try:
                disable_uci(client)
            except Exception as exc:  # pragma: no cover - diagnostics only
                print(f"WARNING: disable_uci failed: {exc}")
        lock.release()
        print(f"Released DeviceLock({HOST})")


if __name__ == "__main__":
    raise SystemExit(main())
