#!/usr/bin/env python3
"""Phase 1 e2e test: boot c64-https.prg in VICE, press I, see DHCP OK.

This test runs the real c64-https binary in VICE on a Linux bridge with
RR-Net ethernet and a host-side dnsmasq. It exercises ip65's net_dhcp
end-to-end. It touches NO TLS/HTTP logic -- it only asserts that the
boot menu appears and that pressing 'I' produces the 'DHCP OK' banner.

Run:
    PYTHONPATH=tools python3 tests/test_phase1_dhcp.py

Exit codes:
    0 -- PASS
    0 -- SKIP (clearly printed)
    1 -- FAIL
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_TOOLS = os.path.join(_REPO_ROOT, "tools")
if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)

PRG_PATH = os.path.join(_REPO_ROOT, "build", "c64-https.prg")

# Exact literal from src/boot.asm (menu_msg @ line 424-426).
MENU_NEEDLE = "Q=QUIT"
# dhcp_ok_msg @ boot.asm:448 is "DHCP OK - IP: ". Match the load-bearing prefix.
DHCP_OK_NEEDLE = "DHCP OK"

MENU_TIMEOUT = 90.0
DHCP_TIMEOUT = 90.0


def _skip(reason: str) -> int:
    print(f"SKIP: {reason}")
    return 0


def _ensure_built() -> bool:
    if os.path.isfile(PRG_PATH):
        return True
    print("[build] c64-https.prg missing, running make...")
    r = subprocess.run(["make"], cwd=_REPO_ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  make failed (exit {r.returncode}):\n{r.stderr}")
        return False
    return os.path.isfile(PRG_PATH)


def main() -> int:
    # ---- Prerequisite / skip gating ----------------------------------------
    from https_e2e import (
        BridgeEnv,
        check_prerequisites,
        launch_vice_on_bridge,
        shutdown_vice,
        press_key,
        wait_for_screen_text,
        get_screen_text,
    )

    missing = check_prerequisites()
    if missing:
        return _skip("missing prerequisites: " + "; ".join(missing))

    if not _ensure_built():
        return _skip("c64-https.prg could not be built")

    # ---- Run the test ------------------------------------------------------
    handle = None
    try:
        with BridgeEnv() as env:
            try:
                print(f"\n=== Launching VICE on {env.tap0} with {PRG_PATH} ===")
                handle = launch_vice_on_bridge(
                    prg_path=PRG_PATH,
                    tap=env.tap0,
                    ready_timeout=90.0,
                )
                transport = handle.transport

                print(f"\n=== Waiting for boot menu ({MENU_NEEDLE!r}) ===")
                try:
                    wait_for_screen_text(
                        transport, MENU_NEEDLE, timeout=MENU_TIMEOUT
                    )
                except TimeoutError as e:
                    print(f"FAIL: boot menu did not appear\n{e}")
                    return 1
                print("  boot menu OK")

                print("\n=== Pressing 'I' for DHCP init ===")
                press_key(transport, "I")

                print(f"\n=== Waiting up to {DHCP_TIMEOUT:.0f}s for {DHCP_OK_NEEDLE!r} ===")
                try:
                    final = wait_for_screen_text(
                        transport, DHCP_OK_NEEDLE, timeout=DHCP_TIMEOUT
                    )
                except TimeoutError as e:
                    print(f"FAIL: DHCP did not complete\n{e}")
                    dnsmasq_log = "/tmp/c64-https-dnsmasq.log"
                    if os.path.isfile(dnsmasq_log):
                        print(f"\n--- tail of {dnsmasq_log} ---")
                        with open(dnsmasq_log, "rb") as f:
                            data = f.read()[-4000:]
                        print(data.decode("utf-8", errors="replace"))
                    return 1

                print("\n=== PASS: DHCP OK seen on screen ===")
                snippet = "\n".join(final.splitlines()[:25])
                print(f"--- final screen (first 25 lines) ---\n{snippet}")
                return 0
            finally:
                # Shut VICE down BEFORE BridgeEnv tears down the TAPs.
                if handle is not None:
                    try:
                        shutdown_vice(handle)
                    except Exception as e:  # noqa: BLE001
                        print(f"  shutdown_vice: {e}")
                    handle = None
    except Exception as e:
        print(f"FAIL: unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
