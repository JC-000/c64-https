#!/usr/bin/env python3
"""test_quit_basic_exit.py -- 'Q' must leave a working BASIC and no secrets.

The bug: 'Q' used to bank BASIC ROM back in and RTS into the SYS that
started the image. BASIC resumes by running CHRGET ($73-$8A) off TXTPTR
($7A/$7B), but the crypto time-shares that ZP: X25519's fe_wide is $40-$7F,
nistcurves' fp_mul_i/j are CURLIN ($39/$3A), the TLS/ECDSA slots cover
BASIC's pointers at $2B-$38. After a handshake the 6510 executed a leftover
field element as CHRGET and BASIC printed "?SYNTAX ERROR IN <garbage>"
(rig_https_banner.py ended every run that way). And the session's keys sat
in RAM after the quit, readable by anything that ran next.

What this suite does, all hardware-free in VICE:

  1. Runs the real crypto that does the clobbering, through the entry
     points a handshake uses: ``tls_ecdh_compute_shared`` on the RFC 7748
     vector (checked, so the run is known to be real) and ``ecdsa_verify``
     on a CAVP P-256 record. It then checks that CHRGET really is
     clobbered -- the precondition that makes the rest non-vacuous.
  2. Plants a distinct pattern in every session-secret buffer (a handshake
     would leave keys there; this does not run one).
  3. Presses 'Q'. At ``quit_scrubbed`` -- the instant before BASIC ROM is
     mapped back in -- it reads ZP $02-$7F and $FB-$FF, the stack page and
     every planted buffer: all zero, the DRBG re-seeded rather than zeroed.
  4. At READY.: no error on screen, the menu still on screen, CHRGET equal
     to the ROM's copy, the program NEWed, BASIC capped at the empty
     program (MEMSIZ = FRETOP = VARTAB) and actually evaluating
     ``PRINT 6*7``. A variable, a DIM, a string concatenation and a typed
     program line each give ?OUT OF MEMORY, and $0803-$9FFF -- the image
     the rigs SYS back into -- is byte-identical afterwards.
  5. Re-enters the image the way the tools/uci rigs do after 'Q' (bank
     BASIC out, call in): X25519 and ECDSA verify both still give the right
     answers, so the scrub broke nothing the rigs rely on.

On the old quit path step 3 fails by name (no ``quit_scrubbed`` label) and
step 4 fails on the syntax error and the clobbered CHRGET.

Not dispatched by tools/run_all_tests.py (see UNDISPATCHED_SUITES there):
it ends the program, so it cannot share that runner's VICE instance.

Usage:
    python3 tools/test_quit_basic_exit.py

Environment: BACKEND (default ip65) and MAKE_ARGS select the build, as in
test_x25519.py; C64_SKIP_BUILD=1 reuses build/. ~3-4 min under VICE warp.
"""

import os
import subprocess
import sys
import time

from c64_test_harness import (
    Labels, ScreenGrid, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text, send_text, send_key,
    set_breakpoint, delete_breakpoint, wait_for_pc,
)

from _vice_helpers import default_vice_config, menu_wait
from _skip_policy import verdict, cannot_run  # noqa: E402
from test_x25519 import SCALAR_1, U_1, EXPECTED_1
from test_ecdsa_kat_oracle import KAT_VECTORS, setup_ecdsa_verify

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

# CHRGET as INITCZ copies it: ROM $E3A2.. -> $73.. ($7A/$7B is TXTPTR,
# which BASIC moves, so it is compared separately).
CHRGET_ROM = 0xE3A2
CHRGET_ZP = 0x73
CHRGET_LEN = 0x18               # $73-$8A

# Page-3 stubs for re-entry, as the rigs do it. $0334-$0338 is jsr()'s own
# trampoline, so these start past it.
STUB_BANK_OUT = 0x0340          # lda $01 / and #$FE / sta $01 / rts
STUB_BANK_IN = 0x0348           # lda $01 / ora #$01 / sta $01 / rts

# Every buffer that holds a session secret after a handshake: (label, size).
# Must read zero at quit_scrubbed.
ZEROED = [
    ("tls_ecdhe_privkey", 32), ("tls_shared_secret", 32),
    ("tls_hs_write_key", 32), ("tls_hs_write_iv", 12),
    ("tls_hs_read_key", 32), ("tls_hs_read_iv", 12),
    ("tls_app_write_key", 32), ("tls_app_write_iv", 12),
    ("tls_app_read_key", 32), ("tls_app_read_iv", 12),
    ("tls_nonce", 12),
    ("hkdf_prk", 32), ("hkdf_okm", 32),
    ("tls_early_secret", 32), ("tls_handshake_secret", 32),
    ("tls_master_secret", 32),
    ("tls_c_hs_secret", 32), ("tls_s_hs_secret", 32),
    ("tls_derived_tmp", 32), ("tls_finished_key", 32),
    ("cc20_state", 64), ("cc20_work", 64), ("cc20_keystream", 64),
    ("cc20_key", 32),
    ("poly_h", 17), ("poly_r", 16), ("poly_s", 16),
    ("aead_key", 32), ("aead_nonce", 12),
    ("drbg_output", 32),
    ("tls_rec_buf", 548),
    ("x25_scalar", 32), ("x25_result", 32),
    ("zp_save_buf", 26),
    ("poly_prod_lo", 2),          # poly_prod_hi follows (asserted in the span)
    ("mul_dma_lo", 256), ("mul_dma_hi", 256),
]
# The DRBG state: re-seeded on quit, not left zero (a zero K/V would hand a
# rig that SYSes back in all-zero "random" bytes). Must hold neither the
# planted pattern nor all zeros.
RESEEDED = [("hmac_key", 32), ("hmac_val", 32)]

# The image BASIC must not be able to allocate over once 'Q' NEWs it.
IMAGE_LO = 0x0803
IMAGE_HI = 0xA000

VERBOSE = False


def hx(b):
    return " ".join(f"{x:02X}" for x in b)


def pattern(i, size):
    return bytes(((0xA5 + 7 * i + j) & 0xFF) or 0x5A for j in range(size))


class Tally:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def check(self, ok, what, detail=""):
        if ok:
            self.passed += 1
            print(f"  PASS  {what}")
        else:
            self.failed += 1
            print(f"  FAIL  {what}" + (f": {detail}" if detail else ""))
        return ok


# Budgets: ~31 s and ~84 s under VICE warp. Generous, but bounded so a
# machine the old quit path left executing garbage fails here instead of
# sitting out a 40-minute verify timeout.
X25519_BUDGET = 600.0
ECDSA_BUDGET = 1200.0


def run_crypto(transport, labels, t, tag):
    """X25519 via the handshake's own entry point, then one P-256 verify."""
    try:
        _run_crypto(transport, labels, t, tag)
    except Exception as e:  # a hung routine is a result here, not a crash
        t.check(False, f"{tag}: crypto returned", f"{type(e).__name__}: {e}")


def _run_crypto(transport, labels, t, tag):
    write_bytes(transport, labels["tls_ecdhe_privkey"], SCALAR_1)
    write_bytes(transport, labels["tls_server_pubkey"], U_1)
    t0 = time.monotonic()
    jsr(transport, labels["tls_ecdh_compute_shared"], timeout=X25519_BUDGET)
    ss = read_bytes(transport, labels["tls_shared_secret"], 32)
    t.check(ss == EXPECTED_1,
            f"{tag}: tls_ecdh_compute_shared = RFC 7748 vector 1 "
            f"({time.monotonic() - t0:.0f} s)", f"got {ss.hex()}")

    v = KAT_VECTORS[0]
    setup_ecdsa_verify(transport, labels, v["hash"], v["r"], v["s"],
                       v["qx"], v["qy"])
    t0 = time.monotonic()
    regs = jsr(transport, labels["ecdsa_verify"], timeout=ECDSA_BUDGET)
    carry = regs.get("FL", 0xFF) & 1
    t.check(carry == v["expect_carry"],
            f"{tag}: ecdsa_verify({v['tag']}) C={carry} "
            f"({time.monotonic() - t0:.0f} s)")


def typed(transport, cmd, needle, timeout=15.0):
    """Clear the screen, type *cmd* at READY., wait for *needle*."""
    send_key(transport, 0x93)
    send_text(transport, cmd + "\r")
    return wait_for_text(transport, needle, timeout=timeout,
                         verbose=False) is not None


def run_tests(transport, labels, seed=None):
    t = Tally()

    print("\n[1] real crypto clobbers BASIC's zero page")
    run_crypto(transport, labels, t, "before Q")
    zp = read_bytes(transport, 0, 256)
    rom = read_bytes(transport, CHRGET_ROM, CHRGET_LEN)
    print(f"      CHRGET $73-$8A: {hx(zp[0x73:0x8B])}")
    print(f"      ROM    $E3A2.:  {hx(rom)}")
    print(f"      TXTPTR=${zp[0x7B]:02X}{zp[0x7A]:02X} "
          f"CURLIN=${zp[0x3A]:02X}{zp[0x39]:02X} "
          f"TXTTAB=${zp[0x2C]:02X}{zp[0x2B]:02X}")
    # Without this the remaining checks could pass on a machine whose ZP
    # the crypto never touched, i.e. prove nothing.
    t.check(zp[CHRGET_ZP:CHRGET_ZP + 7] != rom[:7],
            "precondition: CHRGET $73-$79 no longer matches ROM")

    print("\n[2] plant a pattern in every session-secret buffer")
    for i, (name, size) in enumerate(ZEROED + RESEEDED):
        write_bytes(transport, labels[name], pattern(i, size))
    # tls_rec_buf's pattern overwrote x25_scalar/x25_result (the cfg
    # overlays the X25519 scratch on it); re-plant them distinctly.
    for i, (name, size) in enumerate(ZEROED + RESEEDED):
        if name.startswith("x25_"):
            write_bytes(transport, labels[name], pattern(i, size))
    # A session leaves drbg_buf_idx < 32 most of the time; only the re-seed
    # puts it back to 32, so start it at 0 or the check below is vacuous.
    write_bytes(transport, labels["drbg_buf_idx"], b"\x00")

    print("\n[3] 'Q': state at quit_scrubbed, before BASIC ROM returns")
    scrub_pc = labels.address("quit_scrubbed")
    if t.check(scrub_pc is not None, "quit_scrubbed exists",
               "no such label: this is the old RTS quit path"):
        bp = set_breakpoint(transport, scrub_pc)
        send_key(transport, "Q")
        transport.resume()
        try:
            wait_for_pc(transport, scrub_pc, timeout=60.0)
        finally:
            delete_breakpoint(transport, bp)
        zp = read_bytes(transport, 0, 256)
        nz = [f"${a:02X}" for a in list(range(0x02, 0x80)) + list(range(0xFB, 0x100))
              if zp[a]]
        t.check(not nz, "ZP $02-$7F and $FB-$FF zero", " ".join(nz[:24]))
        stack = read_bytes(transport, 0x0100, 256)
        t.check(not any(stack), "stack page $0100-$01FF zero",
                f"{sum(1 for b in stack if b)} non-zero bytes")
        for name, size in ZEROED:
            got = read_bytes(transport, labels[name], size)
            t.check(not any(got), f"{name} zero", hx(got[:16]))
        for i, (name, size) in enumerate(RESEEDED, start=len(ZEROED)):
            got = read_bytes(transport, labels[name], size)
            t.check(any(got) and got != pattern(i, size),
                    f"{name} re-seeded (neither zero nor the session's)",
                    hx(got[:16]))
        idx = read_bytes(transport, labels["drbg_buf_idx"], 1)[0]
        t.check(idx == 32, "drbg_buf_idx = 32 (next byte forces a generate)",
                f"${idx:02X}")
        transport.resume()
    else:
        send_key(transport, "Q")
        transport.resume()

    print("\n[4] READY. and a working BASIC")
    grid = wait_for_text(transport, "READY.", timeout=30.0, verbose=False)
    t.check(grid is not None, "READY. on screen")
    time.sleep(1.0)             # let a late error message land, if any
    body = ScreenGrid.from_transport(transport).text().upper()
    if VERBOSE or "ERROR" in body:
        print(body)
    t.check("ERROR" not in body, "no BASIC error on screen",
            next((ln.strip() for ln in body.splitlines() if "ERROR" in ln), ""))
    t.check("Q=QUIT" in body, "screen kept (menu still visible)")

    zp = read_bytes(transport, 0, 256)
    rom = read_bytes(transport, CHRGET_ROM, CHRGET_LEN)
    ok = (zp[0x73:0x7A] == rom[:7]) and (zp[0x7C:0x8B] == rom[9:])
    t.check(ok, "CHRGET $73-$79/$7C-$8A equal ROM $E3A2", hx(zp[0x73:0x8B]))
    word = lambda a: zp[a] | (zp[a + 1] << 8)  # noqa: E731
    t.check(word(0x2B) == 0x0801, "TXTTAB = $0801", f"${word(0x2B):04X}")
    t.check(word(0x2D) == 0x0803, "VARTAB = $0803 (program NEWed)",
            f"${word(0x2D):04X}")
    t.check(word(0x37) == 0x0803 and word(0x33) == 0x0803,
            "MEMSIZ = FRETOP = $0803 (BASIC capped below the image)",
            f"MEMSIZ=${word(0x37):04X} FRETOP=${word(0x33):04X}")
    link = read_bytes(transport, 0x0801, 2)
    t.check(link == b"\x00\x00", "program link at $0801 = 0 (NEW)", hx(link))
    t.check(zp[0x01] & 0x07 == 0x07, "$01 has BASIC ROM back in",
            f"${zp[0x01]:02X}")

    image = read_bytes(transport, IMAGE_LO, IMAGE_HI - IMAGE_LO)
    t.check(typed(transport, "print 6*7", " 42"), "PRINT 6*7 -> 42")
    for cmd in ("a=1:b=2:c=3", "dim x(600)", 'print "ab"+"cd"',
                "10 print"):
        t.check(typed(transport, cmd, "OUT OF MEMORY"),
                f"{cmd.upper()} -> ?OUT OF MEMORY")
    after = read_bytes(transport, IMAGE_LO, IMAGE_HI - IMAGE_LO)
    diff = [IMAGE_LO + i for i, (a, b) in enumerate(zip(image, after)) if a != b]
    t.check(not diff, "image $0803-$9FFF unchanged by those commands",
            f"{len(diff)} bytes, first ${diff[0]:04X}" if diff else "")

    print("\n[5] re-entry after 'Q', as the tools/uci rigs do it")
    write_bytes(transport, STUB_BANK_OUT, bytes([0xA5, 0x01, 0x29, 0xFE, 0x85, 0x01, 0x60]))
    write_bytes(transport, STUB_BANK_IN, bytes([0xA5, 0x01, 0x09, 0x01, 0x85, 0x01, 0x60]))
    jsr(transport, STUB_BANK_OUT)
    try:
        run_crypto(transport, labels, t, "after Q")
    finally:
        jsr(transport, STUB_BANK_IN)

    return t.passed, t.failed


def main():
    global VERBOSE
    os.chdir(PROJECT_ROOT)
    VERBOSE = "--verbose" in sys.argv[1:]

    backend = os.environ.get("BACKEND", "ip65")
    make_args = [f"BACKEND={backend}"] + os.environ.get("MAKE_ARGS", "").split()
    print(f"=== Building ({' '.join(make_args)}) ===")
    if os.environ.get("C64_SKIP_BUILD") != "1":
        subprocess.run(["make", "clean"] + make_args,
                       capture_output=True, cwd=PROJECT_ROOT)
        r = subprocess.run(["make"] + make_args, capture_output=True,
                           text=True, cwd=PROJECT_ROOT)
        if r.returncode != 0:
            print(f"Build failed:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}")
            sys.exit(1)
    else:
        print("  C64_SKIP_BUILD=1 — reusing existing build artifacts")
    if not os.path.exists(PRG_PATH):
        sys.exit(cannot_run(f"{PRG_PATH} not found"))

    labels = Labels.from_file(LABELS_PATH)
    required = (["tls_ecdh_compute_shared", "tls_server_pubkey",
                 "ecdsa_verify", "drbg_buf_idx"]
                + [n for n, _ in ZEROED + RESEEDED])
    missing = [n for n in required if labels.address(n) is None]
    if missing:
        # uci-m3 links no 6510 crypto; this suite has nothing to run there.
        sys.exit(cannot_run(f"labels missing from {LABELS_PATH}: "
                            + ", ".join(missing)))

    config = default_vice_config(prg_path=PRG_PATH, warp=True, ntsc=True,
                                 sound=False)
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        if wait_for_text(transport, "Q=QUIT", timeout=menu_wait(60),
                         verbose=False) is None:
            print("FATAL: program menu did not appear")
            sys.exit(1)
        passed, failed = run_tests(transport, labels)
        mgr.release(inst)

    total = passed + failed
    print(f"\n{'=' * 60}\nRESULTS: {passed}/{total} passed, "
          f"{failed}/{total} failed\n{'=' * 60}")
    sys.exit(verdict(passed, failed, certifies="the 'Q' exit to BASIC"))


if __name__ == "__main__":
    main()
