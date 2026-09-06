#!/usr/bin/env python3
"""Phase 1 e2e test: boot c64-https.prg in VICE, press I, see DHCP OK.

This test runs the real c64-https binary in VICE on a Linux bridge with
RR-Net ethernet and a host-side dnsmasq. It exercises ip65's net_dhcp_acquire
end-to-end. It touches NO TLS/HTTP logic -- it only asserts that the
boot menu appears and that pressing 'I' produces the 'DHCP OK' banner.

Run:
    PYTHONPATH=tools python3 tests/rig_phase1_dhcp.py

Exit codes (tools/_skip_policy.py, issue #178):
    0 -- PASS
    1 -- FAIL (a check ran and failed)
    0 -- NOT APPLICABLE: this rig is Linux-only, and on any other host
         tests/rig_vice_https_macos.py owns the coverage.  A named verdict,
         never a bare skip.
    2 -- COULD NOT RUN (a prerequisite is missing ON LINUX, or the build is
         broken -- nothing was verified).  Set C64_ALLOW_SKIP=1 to accept a
         prerequisite-missing run as exit 0; a FAILED BUILD is never opted
         out of.
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

# needs _TOOLS on sys.path, hence the placement below the block above
from _skip_policy import cannot_run, not_applicable  # noqa: E402

PRG_PATH = os.path.join(_REPO_ROOT, "build", "c64-https.prg")

# Exact literal from src/boot.asm (menu_msg @ line 424-426).
MENU_NEEDLE = "Q=QUIT"
# dhcp_ok_msg @ boot.asm:448 is "DHCP OK - IP: ". Match the load-bearing prefix.
DHCP_OK_NEEDLE = "DHCP OK"

MENU_TIMEOUT = 90.0
DHCP_TIMEOUT = 90.0


_CERTIFIES = "ip65 net_dhcp_acquire end-to-end in VICE"


def _cannot_run(reason: str, *, opt_out: bool = True) -> int:
    """An involuntary skip is a FAILURE -- nothing was verified (issue #178).

    `opt_out=False` for a broken build: a failed `make` is never laundered
    into a pass, not even by C64_ALLOW_SKIP.
    """
    return cannot_run(
        reason,
        executed=0,
        total=1,
        certifies=_CERTIFIES,
        opt_out_env="C64_ALLOW_SKIP" if opt_out else None,
    )


_COUNTERPART = (
    "tests/rig_vice_https_macos.py owns this coverage on macOS -- its handshake begins with the same ip65 DHCP acquisition"
)


def _wrong_platform() -> int:
    """A VOLUNTARY skip: this host can never run this rig (issue #178).

    The load-bearing question is what the remedy is.  "install iproute2" is
    an involuntary skip and stays exit 2 -- but on a non-Linux host there is
    no remedy at all, and another rig owns the coverage, so nothing is lost
    and exit 2 would be a red nobody can ever clear.
    """
    return not_applicable(
        f"this rig is Linux-only (br-c64 bridge + netfilter + /proc/net/udp); "
        f"this host is {sys.platform} -- {_COUNTERPART}",
        certifies=_CERTIFIES,
    )


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
        platform_supported,
        launch_vice_on_bridge,
        shutdown_vice,
        press_key,
        wait_for_screen_text,
        get_screen_text,
    )

    # Platform FIRST: check_prerequisites() cannot answer this, because the
    # same string ("ip not on PATH") means "installable" on Linux and "wrong
    # OS" everywhere else (issue #178).
    if not platform_supported():
        return _wrong_platform()

    missing = check_prerequisites()
    if missing:
        return _cannot_run("missing prerequisites: " + "; ".join(missing))

    if not _ensure_built():
        return _cannot_run("c64-https.prg could not be built -- `make` "
                           "failed; this is a broken build, not a "
                           "missing prerequisite", opt_out=False)

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
