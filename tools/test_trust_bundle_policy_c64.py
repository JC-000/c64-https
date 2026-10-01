#!/usr/bin/env python3
"""test_trust_bundle_policy_c64.py — the SHIPPED bundle check, real ECDSA (#155, L3).

tools/test_trust_bundle_c64.py proved the format needs no conversion, with
a trampoline of its own. This runs the code the PRG actually ships,
src/net/uci/trust_bundle.s's `trust_bundle`, in VICE, with the real 6502
SHA-256 and the real `ecdsa_verify` (libs/nistcurves P-256), against the
key and floor compiled into the image (the TEST-ONLY key):

  * the bundle file is written to the TCP ring at $C000, where trust_pre's
    read leaves it, with dos_cnt = its length, tb_loaded = 1 and ts_key =
    the host key of the host being fetched — exactly trust_pre's hand-off;
  * a trampoline JSRs trust_bundle and flags completion.

Cases (signed with tools/trust_bundle.py; the expected verdict comes from
the host-side verifier, never from the C64):

  good              gen = floor, a pin for the host   verdict GOOD, pin found
  again             the same file, second call        GOOD from the cache: no
                                                      verify (wall-clock), found
  record            one record byte flipped           BAD, no pin
  wrong key         signed by another P-256 key       BAD, no pin
  replay            validly signed, gen = floor - 1   signature GOOD, no pin

Usage:
    python3 tools/test_trust_bundle_policy_c64.py   # builds onchip + bundle
    C64_SKIP_BUILD=1 python3 tools/test_trust_bundle_policy_c64.py

Exit 0 pass, 1 fail, 2 could not run.
"""

import hashlib
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from c64_test_harness import (  # noqa: E402
    Labels, ViceInstanceManager, goto, read_bytes, wait_for_text, write_bytes)
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

import trust_bundle as tb  # noqa: E402
import trust_store as ts  # noqa: E402
from _skip_policy import cannot_run, verdict  # noqa: E402
from _vice_helpers import (  # noqa: E402
    default_vice_config, menu_wait, require_menu_wait_env)

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG = os.path.join(ROOT, "build", "c64-https.prg")
LABELS = os.path.join(ROOT, "build", "labels.txt")
MAKE = ["BACKEND=uci", "USE_NISTCURVES_ONCHIP=1", "TRUST_STORE=1", "TRUST_BUNDLE=1"]
CERTIFIES = "the shipped trust-bundle check with the real ECDSA (#155, L3)"
RING = 0xC000
TRAMPOLINE, FLAG = 0x033C, 0x03E1
HOST = "en.wikipedia.org"
NAMES = ["trust_bundle", "tb_loaded", "tb_found", "tb_spki", "tb_verdict",
         "tb_digest", "ts_key", "dos_cnt", "sqtab_init"]
V_GOOD, V_BAD = 1, 2


def floor():
    text = open(os.path.join(ROOT, "tools", "trust_bundle_TEST_ONLY_pubkey.inc")).read()
    return int(re.search(r"TRUST_BUNDLE_GEN_FLOOR\s*=\s*\$([0-9A-Fa-f]+)", text).group(1), 16)


def call(transport, lab, blob, timeout):
    write_bytes(transport, RING, blob)
    if read_bytes(transport, RING, len(blob)) != blob:
        raise RuntimeError("ring read-back mismatch")
    write_bytes(transport, lab["dos_cnt"], bytes([len(blob) & 0xFF, len(blob) >> 8]))
    write_bytes(transport, lab["ts_key"], ts.host_key(HOST))
    write_bytes(transport, lab["tb_loaded"], b"\x01")
    write_bytes(transport, lab["tb_found"], b"\x00")
    t = lab["trust_bundle"]
    code = bytes([0x20, t & 0xFF, t >> 8,                    # jsr trust_bundle
                  0xA9, 0xFF, 0x8D, FLAG & 0xFF, FLAG >> 8,  # lda #$FF / sta FLAG
                  0x4C, (TRAMPOLINE + 8) & 0xFF, (TRAMPOLINE + 8) >> 8])
    write_bytes(transport, TRAMPOLINE, code)
    write_bytes(transport, FLAG, b"\x00")
    t0 = time.monotonic()
    goto(transport, TRAMPOLINE)
    while True:
        time.sleep(2)
        if time.monotonic() - t0 > timeout:
            raise TimeoutError(f"no result after {timeout:.0f}s")
        try:
            if read_bytes(transport, FLAG, 1)[0] == 0xFF:
                break
            transport.resume()
        except Exception:               # noqa: BLE001 — monitor hiccup, retry
            continue
    found = read_bytes(transport, lab["tb_found"], 1)[0]
    spki = read_bytes(transport, lab["tb_spki"], 32)
    v = read_bytes(transport, lab["tb_verdict"], 1)[0]
    return found, spki, v, time.monotonic() - t0


def main():
    require_menu_wait_env()
    os.chdir(ROOT)
    if not os.environ.get("C64_SKIP_BUILD"):
        subprocess.run(["make", "clean"], capture_output=True)
        r = subprocess.run(["make"] + MAKE, capture_output=True, text=True)
        if r.returncode:
            return cannot_run(f"make {' '.join(MAKE)} failed:\n{r.stdout[-800:]}{r.stderr[-800:]}",
                              certifies=CERTIFIES)
    labels = Labels.from_file(LABELS)
    missing = [n for n in NAMES if labels.address(n) is None]
    if missing:
        return cannot_run(f"not a TRUST_BUNDLE=1 image (labels missing: {missing})",
                          certifies=CERTIFIES)
    lab = {n: labels.address(n) for n in NAMES}
    print(f"  PRG sha256 {hashlib.sha256(open(PRG, 'rb').read()).hexdigest()}")

    key = tb.load_private_key(tb.TEST_KEY_PATH)
    pin = hashlib.sha256(b"a leaf SPKI").digest()
    recs = [tb.leaf_record(HOST, pin), tb.leaf_record("github.com", bytes(32))]
    good = tb.sign(key, floor(), recs)
    flipped = bytearray(good)
    flipped[8 + 70] ^= 0x01
    cases = [
        ("good", good, V_GOOD, True),
        ("again (cached)", good, V_GOOD, True),
        ("record byte flipped", bytes(flipped), V_BAD, False),
        ("wrong key", tb.sign(ec.generate_private_key(ec.SECP256R1()), floor(), recs),
         V_BAD, False),
    ]
    if floor() > 0:
        cases.append(("replay: gen = floor - 1", tb.sign(key, floor() - 1, recs), V_GOOD, False))
    for name, blob, want_v, _ in cases:     # the host verifier agrees
        try:
            tb.verify(blob, key.public_key(), 0)
            host_v = V_GOOD
        except tb.BundleError:
            host_v = V_BAD
        assert host_v == want_v, name

    passed = failed = 0
    first_dt = None
    config = default_vice_config(prg_path=PRG, warp=True, ntsc=True, sound=False)
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        tr = inst.transport
        if wait_for_text(tr, "Q=QUIT", timeout=menu_wait(60), verbose=False) is None:
            mgr.release(inst)
            return cannot_run("main menu never appeared", certifies=CERTIFIES)
        for name, blob, want_v, want_found in cases:
            try:
                found, spki, v, dt = call(tr, lab, blob,
                                          float(os.environ.get("C64_CASE_TIMEOUT", "2400")))
            except Exception as e:      # noqa: BLE001
                failed += 1
                print(f"  FAIL {name}: {e}")
                continue
            ok = v == want_v and bool(found) == want_found and (not want_found or spki == pin)
            if name == "good":
                first_dt = dt
            if name.startswith("again"):
                ok = ok and first_dt is not None and dt < first_dt / 4
            passed += ok
            failed += not ok
            print(f"  {'PASS' if ok else 'FAIL'} {name}: verdict={v} (want {want_v}) "
                  f"found={found} (want {int(want_found)}) [{dt:.0f}s]")
        mgr.release(inst)
    return verdict(passed, failed, certifies=CERTIFIES)


if __name__ == "__main__":
    sys.exit(main())
