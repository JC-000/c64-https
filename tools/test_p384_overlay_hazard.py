#!/usr/bin/env python3
"""Does a P-384 certificate corrupt the shipped image?

`ecdsa_verify` branches on `ecdsa_curve_id`; a P-384 leaf sets it to 1
(src/tls_cert.s:422) and the dispatcher jumps to `ecdsa_verify_384_tls`
(src/crypto/ecdsa_verify.s:110-114), which calls `crypto_swap_to_p384_sha384`.
That swap DMAs OVERLAY_SIZE ($1E00) bytes from REU into
`__CRYPTO_OVERLAY_START__` with no check that anything was ever staged there —
and in a shipped build `reu_p384_overlay_init` is `.ifdef USE_OVERLAY_P384_EMBED`,
i.e. an empty RTS, so those REU banks are never written.

The region it writes into is not spare. Under ip65 it is TLS_CODE +
CRYPTO_AUX_CODE + HTTP_AUX_CODE; under UCI it is HTTP_SINK_CODE +
TLS_DEFRAME_CODE + CERT_BUF_BSS + VIEWER_CODE + HTTPS_TARGET_RODATA.

This test snapshots that span, calls `ecdsa_verify` with curve_id=1, and
snapshots again. It asserts the SAFE behaviour — region unchanged and a clean
C=1 reject — so it FAILS if the hazard is real. Read a failure as the finding.

    make && C64_SKIP_BUILD=1 python3 tools/test_p384_overlay_hazard.py
"""
from __future__ import annotations

import os
import sys
import time

from c64_test_harness import (
    Labels, ViceInstanceManager, read_bytes, write_bytes, goto, wait_for_text,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _vice_helpers import default_vice_config  # noqa: E402

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

OVERLAY_SIZE = 0x1E00

# Trampoline constants and jsr_with_carry copied verbatim from
# tools/test_ecdsa_kat_oracle.py (which took them from tools/test_x509.py).
# Deliberately NOT reimplemented: a second carry-latch of my own would put
# the test's own correctness in question exactly when it reports a failure.
CARRY_TRAMPOLINE = 0x033C
CARRY_RESULT_ADDR = 0x0352
CARRY_FLAG_ADDR = 0x0353


def jsr_with_carry(transport, addr, timeout=300.0, poll_interval=5.0):
    """Returns 0/1, or None if the routine never came back (a hang IS a result)."""
    lo, hi = addr & 0xFF, (addr >> 8) & 0xFF
    result_lo, result_hi = CARRY_RESULT_ADDR & 0xFF, (CARRY_RESULT_ADDR >> 8) & 0xFF
    flag_lo, flag_hi = CARRY_FLAG_ADDR & 0xFF, (CARRY_FLAG_ADDR >> 8) & 0xFF
    loop_addr = CARRY_TRAMPOLINE + 19
    trampoline = bytes([
        0xA9, 0x00,
        0x8D, flag_lo, flag_hi,
        0x20, lo, hi,
        0xA9, 0x00,
        0x2A,
        0x8D, result_lo, result_hi,
        0xA9, 0xFF,
        0x8D, flag_lo, flag_hi,
        0x4C, loop_addr & 0xFF, loop_addr >> 8,
    ])
    write_bytes(transport, CARRY_TRAMPOLINE, trampoline)
    write_bytes(transport, CARRY_FLAG_ADDR, bytes([0x00]))
    goto(transport, CARRY_TRAMPOLINE)

    deadline = time.monotonic() + timeout
    while True:
        time.sleep(poll_interval)
        if time.monotonic() >= deadline:
            return None
        try:
            if read_bytes(transport, CARRY_FLAG_ADDR, 1)[0] == 0xFF:
                break
            transport.resume()
        except Exception:
            continue
    return read_bytes(transport, CARRY_RESULT_ADDR, 1)[0]


def main() -> int:
    os.chdir(PROJECT_ROOT)
    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} missing — run make first", file=sys.stderr)
        return 2
    labels = Labels.from_file(LABELS_PATH)

    start = labels.address("__CRYPTO_OVERLAY_START__")
    if start is None:
        print("FATAL: __CRYPTO_OVERLAY_START__ not in labels.txt", file=sys.stderr)
        return 2
    print(f"  overlay slot start : ${start:04X}")
    print(f"  swap writes        : {OVERLAY_SIZE} B  -> ${start:04X}-${start+OVERLAY_SIZE-1:04X}")

    for n in ("ecdsa_verify", "ecdsa_curve_id", "ecdsa_hash", "ecdsa_sig_r",
              "ecdsa_sig_s", "ecdsa_pubkey_x", "ecdsa_pubkey_y"):
        if labels.address(n) is None:
            print(f"FATAL: label {n} missing", file=sys.stderr)
            return 2

    config = default_vice_config(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        t = inst.transport
        print(f"  VICE PID={inst.pid} port={inst.port}")
        if wait_for_text(t, "Q=QUIT", timeout=float(os.environ.get("C64_INIT_TIMEOUT", "90")),
                         verbose=False) is None:
            print("FATAL: menu never appeared", file=sys.stderr)
            return 2
        print("  menu ready")

        before = bytes(read_bytes(t, start, OVERLAY_SIZE))
        print(f"  snapshot before: {len(before)} B, sha={hash(before) & 0xffffffff:08x}")

        # A P-384 leaf sets curve_id=1.
        write_bytes(t, labels["ecdsa_curve_id"], bytes([1]))
        write_bytes(t, labels["ecdsa_pubkey_x"], bytes(range(1, 49)))
        write_bytes(t, labels["ecdsa_pubkey_y"], bytes(range(1, 49)))

        # THE SIGNATURE MUST BE WELL-FORMED DER, and this is the whole
        # difficulty of the test. ecdsa_verify_384_tls step 1 parses the
        # signature out of tls_rec_buf+8 and does `sec; rts` on malformed DER
        # (src/crypto/ecdsa_verify_384.s:205-207) — BEFORE the overlay swap at
        # :268. A first version of this test wrote garbage into ecdsa_sig_r/s,
        # never populated tls_rec_buf, and got a clean C=1 with zero bytes
        # changed: a PASS that proved only that the DER parser rejects garbage.
        # Steps 2 and 3 are straight-line copies with no further early-out, so
        # a parseable signature is the only gate on reaching the swap.
        #
        # SEQUENCE { INTEGER r[48], INTEGER s[48] } — leading byte 0x01 keeps
        # both INTEGERs positive so no 0x00 pad byte is needed.
        r = bytes(range(1, 49))
        sig_der = bytes([0x30, 0x64, 0x02, 0x30]) + r + bytes([0x02, 0x30]) + r
        rec_buf = labels.address("tls_rec_buf")
        if rec_buf is None:
            print("FATAL: tls_rec_buf not in labels.txt", file=sys.stderr)
            return 2
        write_bytes(t, rec_buf + 8, sig_der)
        print(f"  DER sig ({len(sig_der)} B) written at tls_rec_buf+8 = ${rec_buf + 8:04X}")

        print("  calling ecdsa_verify with curve_id=1 ...")
        carry = jsr_with_carry(t, labels["ecdsa_verify"],
                               timeout=float(os.environ.get("P384_TIMEOUT", "180")))
        after = bytes(read_bytes(t, start, OVERLAY_SIZE))

        changed = sum(1 for a, b in zip(before, after) if a != b)
        print()
        print(f"  returned           : {'C=%d' % carry if carry is not None else 'DID NOT RETURN (hung)'}")
        print(f"  bytes changed in the live overlay slot: {changed} / {OVERLAY_SIZE}")

        ok_mem = (changed == 0)
        ok_ret = (carry == 1)
        print()
        print(f"  [{'PASS' if ok_mem else 'FAIL'}] resident code left intact")
        print(f"  [{'PASS' if ok_ret else 'FAIL'}] clean reject (C=1) on an unsupported curve")
        if ok_mem and ok_ret:
            print("\nPASS: a P-384 certificate is handled safely")
            return 0
        print("\nFAIL: the P-384 path is NOT safe on this build — see the counts above",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
