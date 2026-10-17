#!/usr/bin/env python3
"""test_mlkem_linked.py -- the PQ_HYBRID image, run: copy, vectors, KeyGen, Decaps.

tools/test_mlkem_placement.py proves where libs/mlkem LINKS. This proves it
is THERE and works, in a VICE boot of the linked PQ_HYBRID uci-onchip PRG:

  [1] build-time shape: the PRG carries the ML-KEM image at its load
      address $A000 and ends below $D000.
  [2] boot copy: after the menu appears, $E000.. holds exactly the bytes the
      PRG carries at $A000.. (the image is compared span by span from the
      linker's own LOAD/RUN/SIZE symbols), and the $FFFA/$FFFC/$FFFE RAM
      vectors point at an RTI.
  [3] end to end through pq_mlkem_call, the library's only entry:
        X25519 (rebuilds the window the ML-KEM tables live in), then
        mlkem_keygen on fixed seeds == the reference's ek and dk byte for
        byte, then X25519 again, then mlkem_decaps_seed on the reference's
        ciphertext == the reference's K. That is placement + banking + zero
        page + the shared sqtab + the "arith_init before every call group"
        rule, all at once. (The reference is libs/mlkem/tools/mlkem_ref.py,
        the one the library's ACVP runs are checked against.)
  [4] mutants, each must go red: (a) boot.s without the copy call (image
      comparison fails), (b) the copy call moved after the zeroing (the
      assembler assert fires), (c) the call wrapper without mlkem_arith_init
      (KeyGen after X25519 is wrong).

The onchip image needs no REU: set C64_VICE_NO_REU=1 to prove it (the
default config adds -reu). ~6 min (X25519 x2 + KeyGen + Decaps under warp).

    python3 tools/test_mlkem_linked.py            # [1]-[4]
    python3 tools/test_mlkem_linked.py --no-mutants
"""

import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "libs" / "mlkem" / "tools"))

from c64_test_harness import (  # noqa: E402
    Labels, ViceInstanceManager, jsr, read_bytes, write_bytes, wait_for_text,
)
from _vice_helpers import default_vice_config, menu_wait  # noqa: E402
from _skip_policy import cannot_run, verdict  # noqa: E402
from test_x25519 import SCALAR_1, U_1, EXPECTED_1  # noqa: E402

PRG = REPO / "build" / "c64-https.prg"
LABELS = REPO / "build" / "labels.txt"
MAKE_ARGS = ["BACKEND=uci", "USE_NISTCURVES_ONCHIP=1", "PQ_HYBRID=1"]

# Page-3 scratch (jsr()'s trampoline is $0334-$0338), all free in the menu.
SEED = 0x0340           # d (32) then z (32), contiguous: decaps_seed's d||z
SEED_Z = SEED + 32
KEY = 0x0380
STUB = 0x03C0
EK_AT = 0x4200          # cert_buf: idle in the menu, 2 KB
DK_AT = 0xC000          # the TCP ring: where the real dk will live
CT_AT = 0xC960          # past the 2,400 B dk, inside the ring

D = bytes(range(1, 33))
Z = bytes(range(101, 133))
M = bytes(range(201, 233))


class Tally:
    def __init__(self):
        self.passed = self.failed = 0

    def check(self, ok, what, detail=""):
        if ok:
            self.passed += 1
            print(f"  PASS  {what}")
        else:
            self.failed += 1
            print(f"  FAIL  {what}" + (f": {detail}" if detail else ""))
        return ok


def make(extra=()):
    subprocess.run(["make", "clean"], cwd=REPO, capture_output=True)
    r = subprocess.run(["make"] + MAKE_ARGS + list(extra), cwd=REPO,
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def prg_bytes_at(prg, addr, n):
    off = addr - 0x0801 + 2
    return prg[off:off + n]


def image_spans(labels):
    """[(name, load, run, size)] straight from the linker's symbols."""
    out = []
    for seg in ("LIB_MLKEM_CODE", "LIB_MLKEM_RODATA"):
        out.append((seg, labels[f"__{seg}_LOAD__"], labels[f"__{seg}_RUN__"],
                    labels[f"__{seg}_SIZE__"]))
    return out


def shape_checks(t, labels):
    print("\n[1] the PRG carries the image at $A000")
    prg = PRG.read_bytes()
    t.check(len(prg) - 2 + 0x0801 - 1 < 0xD000,
            "the PRG ends below $D000", f"{len(prg)} B")
    first = prg_bytes_at(prg, 0xA000, 1)
    t.check(first and first != b"\x00",
            "the first image byte is nonzero (mlkem_boot_init's 'fresh' test"
            " relies on it)", first.hex())
    for name, load, run, size in image_spans(labels):
        t.check(load == 0xA000 or name.endswith("RODATA"),
                f"{name} loads at ${load:04X}, runs at ${run:04X}, {size} B")


def ram_read(transport, addr, n):
    """RAM at *addr* (the KERNAL ROM covers $E000+ in the CPU view): read
    with $01 = $34, then put $01 back."""
    old = read_bytes(transport, 1, 1)
    write_bytes(transport, 1, b"\x34")
    try:
        return read_bytes(transport, addr, n)
    finally:
        write_bytes(transport, 1, old)


def image_checks(t, transport, labels, tag):
    print(f"\n[2] {tag}: the boot copy")
    prg = PRG.read_bytes()
    ok_all = True
    for name, load, run, size in image_spans(labels):
        want = prg_bytes_at(prg, load, size)
        got = ram_read(transport, run, size)
        ok = t.check(got == want and len(want) == size,
                     f"{name}: ${run:04X}..${run + size - 1:04X} == the PRG's "
                     f"${load:04X}.. ({size} B)",
                     f"first diff at +{next((i for i in range(size) if got[i] != want[i]), -1)}")
        ok_all = ok_all and ok
    vec = ram_read(transport, 0xFFFA, 6)
    rti = labels["mlkem_rti"]
    t.check(vec == bytes([rti & 255, rti >> 8]) * 3 and
            read_bytes(transport, rti, 1) == b"\x40",
            f"$FFFA/$FFFC/$FFFE -> an RTI at ${rti:04X}", vec.hex())
    return ok_all


def x25519_ok(t, transport, labels, tag):
    write_bytes(transport, labels["tls_ecdhe_privkey"], SCALAR_1)
    write_bytes(transport, labels["tls_server_pubkey"], U_1)
    jsr(transport, labels["tls_ecdh_compute_shared"], timeout=600.0)
    ss = read_bytes(transport, labels["tls_shared_secret"], 32)
    return t.check(ss == EXPECTED_1, f"{tag}: X25519 = RFC 7748 vector 1",
                   ss.hex())


def set_args(transport, labels, **ptrs):
    for name, addr in ptrs.items():
        write_bytes(transport, labels[f"mlkem_arg_{name}"],
                    bytes([addr & 255, addr >> 8]))


RES = 0x03B0            # +0 A, +1 P as the stub saw them after the call


def call(transport, labels, entry):
    """Call a named wrapper (pq_mlkem_keygen / pq_mlkem_decaps_seed) through
    a page-3 stub that records A and P after the call."""
    w = labels["pq_" + entry]
    stub = bytes([0x20, w & 255, w >> 8,                  # jsr wrapper
                  0x8D, RES & 255, RES >> 8,              # sta RES
                  0x08, 0x68,                             # php / pla
                  0x8D, (RES + 1) & 255, RES >> 8,        # sta RES+1
                  0x60])
    write_bytes(transport, STUB, stub)
    t0 = time.monotonic()
    jsr(transport, STUB, timeout=900.0)
    a, p = read_bytes(transport, RES, 2)
    return {"A": a, "P": p}, time.monotonic() - t0


def iflag_checks(t, transport, labels):
    """The caller's I flag comes back as it went in (mutant d: no php/plp)."""
    print("  [3a] the I flag is restored")
    e, c = labels["mlkem_arith_init"], labels["pq_mlkem_call"]
    for name, op, want in (("clear (cli)", 0x58, 0), ("set (sei)", 0x78, 4)):
        stub = bytes([op, 0xA9, e & 255, 0xA2, e >> 8, 0x20, c & 255, c >> 8,
                      0x08, 0x68, 0x8D, RES & 255, RES >> 8, 0x60])
        write_bytes(transport, STUB, stub)
        jsr(transport, STUB, timeout=60.0)
        p = read_bytes(transport, RES, 1)[0]
        t.check(p & 4 == want, f"I flag {name} on entry -> unchanged on return",
                f"P=${p:02X}")


def kat(t, transport, labels):
    import mlkem_ref as R
    print("\n[3] KeyGen and Decaps through pq_mlkem_call")
    ek_ref, dk_ref = R.mlkem_keygen(D, Z)
    K_ref, ct_ref = R.mlkem_encaps(ek_ref, M)

    # Re-running the boot copy (SYS re-entry) must not erase the code: the
    # flag says "done", and with the flag cleared the stage is zero, which
    # reads as "not fresh". Only a fresh LOAD (flag 0 AND a nonzero stage)
    # copies.
    prg = PRG.read_bytes()
    img = lambda: ram_read(transport, labels["__LIB_MLKEM_CODE_RUN__"], 0x1900)  # noqa: E731
    want = prg_bytes_at(prg, 0xA000, 0x1900)
    jsr(transport, labels["mlkem_boot_init"], timeout=30.0)
    t.check(img() == want, "re-running mlkem_boot_init leaves the image intact")
    # The PRG-data flag clobbered (BASIC after 'Q'): the stage is zero, so the
    # tail marker is absent at $A000, but it IS at $E000: resident, flag set
    # again, image untouched.
    write_bytes(transport, labels["mlkem_copied"], b"\x00")
    jsr(transport, labels["mlkem_boot_init"], timeout=30.0)
    t.check(img() == want and read_bytes(transport, labels["mlkem_copied"], 1) == b"\x01",
            "flag cleared, stage gone: the marker at $E000 re-arms it, no copy")
    iflag_checks(t, transport, labels)

    x25519_ok(t, transport, labels, "before")     # rebuilds the ML-KEM window

    write_bytes(transport, SEED, D + Z)
    write_bytes(transport, EK_AT, bytes([0xEE]) * 1184)
    write_bytes(transport, DK_AT, bytes([0xEE]) * 2400)
    set_args(transport, labels, seed=SEED, z=SEED_Z, ek=EK_AT, dk=DK_AT)
    regs, dt = call(transport, labels, "mlkem_keygen")
    ek = read_bytes(transport, EK_AT, 1184)
    dk = read_bytes(transport, DK_AT, 2400)
    t.check(regs["A"] == 0, f"mlkem_keygen returned A=0 ({dt:.0f} s)",
            f"A={regs['A']:02X}")
    t.check(ek == ek_ref, "mlkem_keygen ek == the reference's",
            f"first diff at +{next((i for i in range(1184) if ek[i] != ek_ref[i]), -1)}")
    t.check(dk == dk_ref, "mlkem_keygen dk == the reference's",
            f"first diff at +{next((i for i in range(2400) if dk[i] != dk_ref[i]), -1)}")

    x25519_ok(t, transport, labels, "after")      # rebuilds the tables again

    write_bytes(transport, CT_AT, ct_ref)
    write_bytes(transport, KEY, bytes(32))
    set_args(transport, labels, seed=SEED, ct=CT_AT, key=KEY)
    regs, dt = call(transport, labels, "mlkem_decaps_seed")
    K = read_bytes(transport, KEY, 32)
    t.check(K == K_ref, f"mlkem_decaps_seed K == the reference's ({dt:.0f} s)",
            K.hex())
    # Implicit rejection through the same path: a flipped ct bit must NOT
    # give K (and must still return A=0).
    bad = bytearray(ct_ref)
    bad[7] ^= 1
    write_bytes(transport, CT_AT, bytes(bad))
    call(transport, labels, "mlkem_decaps_seed")
    K2 = read_bytes(transport, KEY, 32)
    t.check(K2 != K_ref and K2 != bytes(32),
            "a flipped ciphertext bit gives a different (rejection) key")
    # $01 is back where the boot left it (BASIC out, KERNAL and I/O in).
    port = read_bytes(transport, 1, 1)[0]
    t.check(port & 7 == 6, "$01 restored by pq_mlkem_call", f"${port:02X}")


def boot_and_run(t, labels, tag, do_kat):
    config = default_vice_config(prg_path=str(PRG), warp=True, ntsc=True,
                                 sound=False)
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        tr = inst.transport
        if wait_for_text(tr, "Q=QUIT", timeout=menu_wait(60),
                         verbose=False) is None:
            t.check(False, f"{tag}: the menu appeared")
            mgr.release(inst)
            return False
        ok = image_checks(t, tr, labels, tag)
        if do_kat and ok:
            kat(t, tr, labels)
        mgr.release(inst)
        return ok


def refusal_phase(t, labels):
    """A LOAD cut short before the tail marker is REFUSED, not half-copied."""
    import tempfile
    print("\n[2b] a PRG without the tail marker (a LOAD cut short)")
    prg = bytearray(PRG.read_bytes())
    off = labels["__LIB_MLKEM_MARK_LOAD__"] - 0x0801 + 2
    assert prg[off] == 0x5C, "the marker is not where the labels say"
    prg[off] = 0
    tmp = Path(tempfile.mkdtemp(prefix="mlkem_cut_")) / "cut.prg"
    tmp.write_bytes(bytes(prg))
    config = default_vice_config(prg_path=str(tmp), warp=True, ntsc=True, sound=False)
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        tr = inst.transport
        if wait_for_text(tr, "Q=QUIT", timeout=menu_wait(60), verbose=False) is None:
            t.check(False, "the cut-short image still reached the menu")
            mgr.release(inst)
            return
        t.check(read_bytes(tr, labels["mlkem_copied"], 1) == b"\x00",
                "mlkem_copied stays 0 (no copy, no silent skip)")
        t.check(read_bytes(tr, 0xD020, 1)[0] & 15 == 2, "the border is red")
        want = prg_bytes_at(bytes(prg), labels["__LIB_MLKEM_CODE_LOAD__"], 64)
        t.check(ram_read(tr, labels["__LIB_MLKEM_CODE_RUN__"], 64) != want,
                "nothing was copied to $E000")
        r, _ = call(tr, labels, "mlkem_keygen")
        t.check(r["A"] == 0xFF and r["P"] & 1 == 1,
                "pq_mlkem_keygen refuses: A=$FF, C=1, nothing ran",
                f"A={r['A']:02X} P={r['P']:02X}")
        mgr.release(inst)


def mutant(t, label, path, old, new, expect, labels_tag):
    """Build with *old* -> *new* in *path*; return (rc, output)."""
    p = REPO / path
    orig = p.read_text()
    assert old in orig, (path, old)
    try:
        p.write_text(orig.replace(old, new, 1))
        rc, out = make()
    finally:
        p.write_text(orig)
    return rc, out


def main():
    t = Tally()
    if shutil.which("ca65") is None:
        return cannot_run("cc65 not found", certifies="the linked ML-KEM image")
    rc, out = make()
    if rc != 0:
        print(out[-1500:])
        return cannot_run("the PQ_HYBRID build failed", certifies="the linked ML-KEM image")
    labels = Labels.from_file(str(LABELS))
    shape_checks(t, labels)
    ok = boot_and_run(t, labels, "green", True)
    refusal_phase(t, labels)

    if "--no-mutants" not in sys.argv[1:]:
        print("\n[4] mutants")
        # (a) no copy call at all: the image never reaches $E000
        rc, out = mutant(t, "no copy", "src/boot.s",
                         "        jsr mlkem_boot_init\n", "        nop\n        nop\n        nop\n", None, "")
        if t.check(rc == 0, "mutant (a) no copy call: still links", out[-300:]):
            lab = Labels.from_file(str(LABELS))
            t2 = Tally()
            boot_and_run(t2, lab, "mutant (a)", False)
            t.check(t2.failed > 0, "mutant (a) is RED: the $E000 image differs "
                    f"({t2.failed} image check(s) failed)")
        # (b) copy moved after the zeroing: the assembler assert fires
        # moving the call: put it after the zeroing loop's first label instead
        p = REPO / "src/boot.s"
        orig = p.read_text()
        try:
            late = orig.replace("mlkem_copy_site:\n        jsr mlkem_boot_init\n",
                                "mlkem_copy_site:\n", 1)
            late = late.replace("boot_zbss_first:\n",
                                "boot_zbss_first:\n        jsr mlkem_boot_init\n", 1)
            p.write_text(late)
            rc, out = make()
        finally:
            p.write_text(orig)
        t.check(rc != 0 and "the ML-KEM boot copy must run BEFORE" in out,
                "mutant (b) copy after the zeroing: the assembler assert fires",
                out[-300:])
        # (c) the wrapper without arith_init
        rc, out = mutant(t, "no arith_init", "src/crypto/mlkem_link.s",
                         "        jsr mlkem_arith_init\n@go:",
                         "        nop\n        nop\n        nop\n@go:", None, "")
        if t.check(rc == 0, "mutant (c) no arith_init: still links", out[-300:]):
            lab = Labels.from_file(str(LABELS))
            t3 = Tally()
            config = default_vice_config(prg_path=str(PRG), warp=True,
                                         ntsc=True, sound=False)
            with ViceInstanceManager(config=config) as mgr:
                inst = mgr.acquire()
                if wait_for_text(inst.transport, "Q=QUIT",
                                 timeout=menu_wait(60), verbose=False):
                    kat(t3, inst.transport, lab)
                mgr.release(inst)
            t.check(t3.failed > 0, "mutant (c) is RED: KeyGen after X25519 is "
                    f"wrong without arith_init ({t3.failed} check(s) failed)")
        # (d) pq_mlkem_call without php/plp: the caller's I flag is not restored
        p = REPO / "src/crypto/mlkem_link.s"
        orig = p.read_text()
        try:
            m = orig.replace("@run:   sta @go+1\n        stx @go+2\n        php\n",
                             "@run:   sta @go+1\n        stx @go+2\n        nop\n", 1)
            m = m.replace("        sta $01\n        plp\n@ra:", "        sta $01\n        nop\n@ra:", 1)
            assert m != orig
            p.write_text(m)
            rc, out = make()
        finally:
            p.write_text(orig)
        if t.check(rc == 0, "mutant (d) no php/plp: still links", out[-300:]):
            lab = Labels.from_file(str(LABELS))
            t4 = Tally()
            config = default_vice_config(prg_path=str(PRG), warp=True,
                                         ntsc=True, sound=False)
            with ViceInstanceManager(config=config) as mgr:
                inst = mgr.acquire()
                if wait_for_text(inst.transport, "Q=QUIT",
                                 timeout=menu_wait(60), verbose=False):
                    iflag_checks(t4, inst.transport, lab)
                mgr.release(inst)
            t.check(t4.failed > 0, "mutant (d) is RED: the I flag is not "
                    f"restored ({t4.failed} check(s) failed)")
        make()      # restore the green build

    print(f"\nRESULTS: {t.passed}/{t.passed + t.failed} passed, {t.failed} failed")
    return verdict(t.passed, t.failed, certifies="the linked ML-KEM image")


if __name__ == "__main__":
    sys.exit(main())
