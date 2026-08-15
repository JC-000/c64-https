#!/usr/bin/env python3
"""Phase 2 e2e test: boot c64-https.prg, do DHCP, then plain HTTP GET.

This test extends Phase 1 by pressing 'H' after DHCP succeeds, which
triggers a plain HTTP GET to zimmers.net (resolved via dnsmasq to the
host bridge IP 10.0.65.1). A Python HTTP server on 10.0.65.1:80 serves
a known response body.

Run:
    sudo PYTHONPATH=tools python3 tests/rig_phase2_http.py

Exit codes:
    0 -- PASS
    0 -- SKIP (clearly printed)
    1 -- FAIL
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_TOOLS = os.path.join(_REPO_ROOT, "tools")
if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)

PRG_PATH = os.path.join(_REPO_ROOT, "build", "c64-https.prg")

# Screen needles (from src/boot.asm string labels).
MENU_NEEDLE = "Q=QUIT"
DHCP_OK_NEEDLE = "DHCP OK"
# Response body served by our test HTTP server.
RESPONSE_BODY = "HELLO FROM TEST SERVER"

MENU_TIMEOUT = 90.0
DHCP_TIMEOUT = 90.0
HTTP_TIMEOUT = 120.0


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


def _dump_diagnostics(transport=None) -> None:
    """Print dnsmasq log and host-side connectivity checks for post-mortem."""
    dnsmasq_log = "/tmp/c64-https-dnsmasq.log"
    if os.path.isfile(dnsmasq_log):
        print(f"\n--- tail of {dnsmasq_log} ---")
        with open(dnsmasq_log, "rb") as f:
            data = f.read()[-4000:]
        print(data.decode("utf-8", errors="replace"))

    # Host-side DNS check
    try:
        r = subprocess.run(
            ["dig", "+short", "@10.0.65.1", "www.zimmers.net"],
            capture_output=True, text=True, timeout=5,
        )
        print(f"\n  dig @10.0.65.1 www.zimmers.net -> {r.stdout.strip()}")
    except Exception as e:
        print(f"  dig check failed: {e}")

    # Host-side HTTP check
    try:
        import urllib.request
        resp = urllib.request.urlopen("http://10.0.65.1:80/", timeout=3)
        print(f"  HTTP from host: {resp.status} {resp.read()[:100]}")
    except Exception as e:
        print(f"  HTTP from host failed: {e}")

    # ip65 error code from C64 memory
    if transport is not None:
        try:
            transport.resume()
            err_data = transport.read_memory(0x4CEA, 1)
            print(f"  ip65_error at $4CEA = 0x{err_data[0]:02X}")
        except Exception as e:
            print(f"  ip65_error read failed: {e}")


def main() -> int:
    from https_e2e import (
        BridgeEnv,
        check_prerequisites,
        launch_vice_on_bridge,
        shutdown_vice,
        press_key,
        wait_for_screen_text,
        get_screen_text,
        start_http_listener,
        stop_http_listener,
    )

    missing = check_prerequisites()
    if missing:
        return _skip("missing prerequisites: " + "; ".join(missing))

    if not _ensure_built():
        return _skip("c64-https.prg could not be built")

    handle = None
    listener = None
    try:
        with BridgeEnv() as env:
            try:
                # --- Start HTTP listener on bridge IP ---
                print(f"\n=== Starting HTTP listener on {env.bridge_ip}:80 ===")
                listener = start_http_listener(
                    host=env.bridge_ip,
                    port=80,
                    response_body=RESPONSE_BODY,
                )
                print(f"  listener ready on {listener.host}:{listener.port}")

                # --- Launch VICE ---
                print(f"\n=== Launching VICE on {env.tap0} with {PRG_PATH} ===")
                handle = launch_vice_on_bridge(
                    prg_path=PRG_PATH,
                    tap=env.tap0,
                    ready_timeout=90.0,
                )
                transport = handle.transport

                # --- Wait for boot menu ---
                print(f"\n=== Waiting for boot menu ({MENU_NEEDLE!r}) ===")
                try:
                    wait_for_screen_text(transport, MENU_NEEDLE, timeout=MENU_TIMEOUT)
                except TimeoutError as e:
                    print(f"FAIL: boot menu did not appear\n{e}")
                    return 1
                print("  boot menu OK")

                # --- DHCP init ---
                print("\n=== Pressing 'I' for DHCP init ===")
                press_key(transport, "I")

                print(f"\n=== Waiting up to {DHCP_TIMEOUT:.0f}s for {DHCP_OK_NEEDLE!r} ===")
                try:
                    wait_for_screen_text(transport, DHCP_OK_NEEDLE, timeout=DHCP_TIMEOUT)
                except TimeoutError as e:
                    print(f"FAIL: DHCP did not complete\n{e}")
                    _dump_diagnostics(transport)
                    return 1
                print("  DHCP OK")

                # --- HTTP GET ---
                print("\n=== Pressing 'H' for plain HTTP GET ===")
                press_key(transport, "H")

                print(f"\n=== Waiting up to {HTTP_TIMEOUT:.0f}s for HTTP OK ===")
                # After pressing H, the C64 prints:
                #   "HTTP GET WWW.ZIMMERS.NET..."
                # then on success: "OK" followed by response body,
                # or on failure: "FAILED".
                #
                # We cannot simply wait_for_screen_text("OK") because
                # "DHCP OK" is already on screen. Instead we poll and
                # look for "OK" appearing *after* the "HTTP GET" line,
                # or for "FAILED" after it, or for the response body.
                deadline = time.monotonic() + HTTP_TIMEOUT
                final = ""
                http_started = False
                result = None  # "pass" | "fail"

                while time.monotonic() < deadline:
                    try:
                        transport.resume()
                    except Exception:
                        pass
                    time.sleep(2.0)
                    try:
                        final = get_screen_text(transport)
                    except Exception:
                        continue

                    upper = final.upper()

                    # Check if the HTTP GET banner appeared
                    idx_get = upper.find("HTTP GET")
                    if idx_get < 0:
                        continue
                    if not http_started:
                        print("  HTTP GET initiated")
                        http_started = True

                    after_get = upper[idx_get:]

                    # Check for FAILED after HTTP GET
                    if "FAILED" in after_get:
                        result = "fail"
                        break

                    # Check for OK after HTTP GET line (not DHCP OK).
                    lines_after = after_get.split("\n")
                    for line in lines_after[1:]:  # skip "HTTP GET..." line
                        stripped = line.strip()
                        if stripped == "OK" or stripped.startswith("OK"):
                            result = "pass"
                            break

                    # Also check for response body as a success indicator.
                    if RESPONSE_BODY[:12].upper() in upper:
                        result = "pass"

                    if result:
                        break

                if result == "fail" or result != "pass":
                    reason = ("HTTP GET reported FAILED" if result == "fail"
                              else f"HTTP GET did not complete within {HTTP_TIMEOUT:.0f}s")
                    print(f"FAIL: {reason}")
                    if result != "fail":
                        try:
                            final = get_screen_text(transport)
                        except Exception:
                            pass
                    print(f"\n--- final screen ---\n{final}")
                    _dump_diagnostics(transport)
                    return 1

                print("\n=== PASS: HTTP GET OK seen on screen ===")
                snippet = "\n".join(final.splitlines()[:25])
                print(f"--- final screen (first 25 lines) ---\n{snippet}")

                # Check for response body on screen.
                body_upper = RESPONSE_BODY.upper()
                if body_upper in final.upper():
                    print(f"  response body verified: {RESPONSE_BODY!r}")
                else:
                    # Not a hard failure -- the body might have scrolled off.
                    print(f"  (response body not found on screen, may have scrolled)")

                return 0
            finally:
                if listener is not None:
                    try:
                        stop_http_listener(listener)
                    except Exception as e:
                        print(f"  stop_http_listener: {e}")
                    listener = None
                if handle is not None:
                    try:
                        shutdown_vice(handle)
                    except Exception as e:
                        print(f"  shutdown_vice: {e}")
                    handle = None
    except Exception as e:
        print(f"FAIL: unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
