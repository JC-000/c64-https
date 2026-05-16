#!/usr/bin/env python3
"""
Phase 5 LOCAL HTTPS (P-384): exercise the real http_get (TLS 1.3) code
path through the UCI backend on a real Ultimate 64 Elite, against a
local listener serving an ECDSA secp384r1 certificate.

This is the P-384 sibling of tools/uci/test_https_local.py.  Differences:

  - Uses the P-384 cert/key bundle at tools/https_e2e/certs/
    (server-p384.pem / server-p384.key).  Equivalent to setting
    HTTPS_LISTENER_CERT_PROFILE=p384 against the high-level
    tools/https_e2e/https_listener.py API; this file inlines its own
    listener (matches the parent file's pattern) and points it at the
    P-384 certs directly.

  - Default SENTINEL_POLL_TIMEOUT scaled up.  ECDSA-P384 verify under
    the dual-overlay swap dance is the dominant cost of the handshake;
    expect 4-7 minutes per handshake at U64E 48 MHz turbo (the SHA-384
    overlay swaps in for the SHA hash, then the curve overlay swaps in
    for the verify; each swap is two REU DMAs ~16 ms wallclock).

Usage:
    /Users/someone/.local/share/c64-test-harness/venv/bin/python \\
        tools/uci/test_https_local_p384.py

Environment variables (same as test_https_local.py):
  U64_HOST              - U64E IP (default 192.168.1.81)
  TURBO_MHZ             - C64 CPU MHz (default 48)
  HTTPS_PORT            - listener port (default 443; falls back to 4433)
  SENTINEL_POLL_TIMEOUT - C64-side sentinel poll budget (default
                          1800 * _TIMEOUT_SCALE = 30 min at 48 MHz; the
                          ECDSA-P384 verify can take 4-7 min and the
                          handshake includes one verify so this gives
                          ample slack against handshake stalls)
  ACCEPT_TIMEOUT        - server-side accept + handshake budget (same
                          default as SENTINEL_POLL_TIMEOUT)
  DEBUG_CAPTURE         - 0 to disable 6510 bus capture (default on)
  KEEP_DEBUG_ON_PASS    - 1 to preserve artifacts on PASS (default 0)
  UCI_DEBUG_DIR         - artifact dir base (default /tmp/uci_https_debug)

Flow mirrors test_https_local.py exactly; see that file's docstring
for the per-step description.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# --------------------------------------------------------------------------
# Patch the parent module's CERT_PATH / KEY_PATH and timeouts BEFORE
# importing it as a module.  The parent module reads these at import time
# (top-of-file constants) so we monkey-patch via env vars where possible
# and via attribute injection for the cert paths.
#
# Set the timeout defaults BEFORE the import so the module's
# `os.environ.get(...)` calls pick them up.
# --------------------------------------------------------------------------

# Default to a 30 min budget if the user hasn't overridden it.  The
# P-384 verify (one per handshake) dominates wall-clock; pre-Phase-C.4
# numbers for P-256 measured ~85 s for ecdsa_verify alone, and the
# P-384 cost is ~5x for the scalar mult (larger field, same primitives).
# Conservative 30 min covers stalls and gives the operator clear room
# above the expected 4-7 min handshake.
os.environ.setdefault("SENTINEL_POLL_TIMEOUT", "1800")
os.environ.setdefault("ACCEPT_TIMEOUT", "1800")

# Now import the parent module — it will pick up the timeout env vars
# above, and we patch CERT_PATH / KEY_PATH below before main() runs.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_https_local  # type: ignore

# --------------------------------------------------------------------------
# Swap to the P-384 cert/key.  These live in the same dir as the P-256
# bundle; the listener wraps the socket with whatever ssl.SSLContext we
# load.
# --------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[2]
test_https_local.CERT_PATH = _REPO_ROOT / "tools" / "https_e2e" / "certs" / "server-p384.pem"
test_https_local.KEY_PATH  = _REPO_ROOT / "tools" / "https_e2e" / "certs" / "server-p384.key"


# --------------------------------------------------------------------------
# Memory arbiter override for the P-384 build.
#
# Under the production P-384 UCI build CRYPTO_OVERLAY ($4200-$5FFF) is
# fully occupied at PRG-load time (OVERLAY_BLOB_SHA384) and is the
# active overlay swap slot at runtime, so the default
# CRYPTO_OVERLAY-scoped arbiter window finds no free range and raises
# MemoryArbiterError. The parent test_https_local.py now defaults to
# ``build_policy_and_arbiter_with_overlay_carveout`` (which carves
# harness scratch from the NET_CODE zero-fill tail $3xxx-$3FFF), so
# the P-384 sibling inherits the correct arbiter window automatically —
# no override needed here. The inline ``_p384_build_policy_and_arbiter``
# monkey-patch that previously lived in this file was factored into
# ``_memory_policy.build_policy_and_arbiter_with_overlay_carveout`` and
# adopted as the default in PR #...
# --------------------------------------------------------------------------

# Sanity check that the certs exist before delegating to main().
if not test_https_local.CERT_PATH.is_file():
    print(
        f"ERROR: P-384 cert not found at {test_https_local.CERT_PATH}",
        file=sys.stderr,
    )
    sys.exit(2)
if not test_https_local.KEY_PATH.is_file():
    print(
        f"ERROR: P-384 key not found at {test_https_local.KEY_PATH}",
        file=sys.stderr,
    )
    sys.exit(2)


def main() -> int:
    print("=" * 60)
    print("Phase 5 LOCAL HTTPS (P-384)")
    print("=" * 60)
    print(f"P-384 cert : {test_https_local.CERT_PATH}")
    print(f"P-384 key  : {test_https_local.KEY_PATH}")
    print()
    print("NOTE: ECDSA-P384 verify dominates handshake wall-clock;")
    print("      expect 4-7 minutes per handshake at U64E 48 MHz turbo.")
    print()

    return test_https_local.main()


if __name__ == "__main__":
    raise SystemExit(main())
