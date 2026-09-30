#!/usr/bin/env python3
"""test_trust_bundle_c64.py — the C64 verifies a signed trust bundle (#155 phase 2).

Proves the format in tools/trust_bundle.py needs no byte conversion on the
C64: the raw bundle file is written into C64 RAM, and a 6502 trampoline does
exactly what the on-C64 loader will do —

  1. SHA-256 over header||records with the in-tree streaming hash
     (tls_transcript_init / _update / _hash) — the C64 hashes the file
     itself; the host supplies no digest;
  2. copies that digest to ecdsa_hash and the 64-byte trailer, verbatim, to
     ecdsa_sig_r (r then s — the buffers are contiguous);
  3. lda #<ecdsa_sig_r / ldx #>ecdsa_sig_r / jsr ecdsa_verify_256.

Qx/Qy are written to ecdsa_pubkey_x/_y from the test key, standing in for
the TRUST_BUNDLE_PUBKEY_BYTES the PRG will carry.

Cases (expected carry from the host-side verifier, never from the C64):

  good      tools/trust_bundle_sample_TEST_ONLY.bin as committed   C=0
  record    one bit flipped in record 0's SPKI hash                 C=1
  gen       one bit flipped in the generation field (a replay that
            tries to lift an old bundle over the floor)             C=1
  sig       one bit flipped in s                                    C=1

Each case also compares the C64's own SHA-256 with the host's for the same
bytes, so a mismatch in the hashing half cannot hide behind a verify result.

The bundle sits in cert_buf (idle outside a handshake). On ip65 that buffer
is unioned with the nistcurves BSS, which is why the trampoline hashes and
copies everything out BEFORE the verify runs.

Usage (builds with C64_MAKE_ARGS, like test_ecdsa_kat_oracle.py):

    C64_MAKE_ARGS="BACKEND=uci USE_NISTCURVES_ONCHIP=1" \\
        python3 tools/test_trust_bundle_c64.py
    C64_SKIP_BUILD=1 python3 tools/test_trust_bundle_c64.py   # reuse build/
"""

import hashlib
import os
import re
import shlex
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from c64_test_harness import (  # noqa: E402
    Labels, ViceInstanceManager, goto, jsr, read_bytes, wait_for_text,
    write_bytes)

import trust_bundle as tb  # noqa: E402
from _skip_policy import cannot_run, verdict  # noqa: E402
from _vice_helpers import default_vice_config  # noqa: E402

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")
CONSTANTS = os.path.join(PROJECT_ROOT, "src", "constants.inc")

TRAMPOLINE = 0x033C                     # page 3, same as the KAT oracle
HASH_OUT = 0x03C0                       # 32 B: the C64's digest, copied out
RESULT = 0x03E0                         # carry after ecdsa_verify_256
FLAG = 0x03E1                           # $FF when the trampoline finished

LABELS = ["tls_transcript_init", "tls_transcript_update", "tls_transcript_hash",
          "tls_transcript", "ecdsa_hash", "ecdsa_sig_r", "ecdsa_pubkey_x",
          "ecdsa_pubkey_y", "ecdsa_verify_256", "sqtab_init", "cert_buf",
          "cert_buf_size"]


def zp_equates():
    """zp_ptr / zp_count from src/constants.inc (zp_count is not a label)."""
    text = open(CONSTANTS).read()
    out = {}
    for name in ("zp_ptr", "zp_count"):
        m = re.search(rf"^{name}\s*=\s*\$([0-9a-fA-F]+)", text, re.M)
        out[name] = int(m.group(1), 16)
    return out


def trampoline(lab, zp, buf, body_len):
    lo = lambda v: v & 0xFF             # noqa: E731
    hi = lambda v: v >> 8               # noqa: E731

    def abs_(op, v):
        return [op, lo(v), hi(v)]

    code = []
    code += abs_(0x20, lab["tls_transcript_init"])
    code += [0xA9, lo(buf), 0x85, zp["zp_ptr"], 0xA9, hi(buf), 0x85, zp["zp_ptr"] + 1]
    code += [0xA9, lo(body_len), 0x85, zp["zp_count"],
             0xA9, hi(body_len), 0x85, zp["zp_count"] + 1]
    code += abs_(0x20, lab["tls_transcript_update"])
    code += abs_(0x20, lab["tls_transcript_hash"])
    # ldx #31 / lda tls_transcript,x / sta ecdsa_hash,x / sta HASH_OUT,x / dex / bpl
    code += [0xA2, 31] + abs_(0xBD, lab["tls_transcript"]) \
        + abs_(0x9D, lab["ecdsa_hash"]) + abs_(0x9D, HASH_OUT) + [0xCA, 0x10, 0xF4]
    # ldx #63 / lda trailer,x / sta ecdsa_sig_r,x / dex / bpl
    code += [0xA2, 63] + abs_(0xBD, buf + body_len) \
        + abs_(0x9D, lab["ecdsa_sig_r"]) + [0xCA, 0x10, 0xF7]
    code += [0xA9, lo(lab["ecdsa_sig_r"]), 0xA2, hi(lab["ecdsa_sig_r"])]
    code += abs_(0x20, lab["ecdsa_verify_256"])
    code += [0xA9, 0x00, 0x2A] + abs_(0x8D, RESULT)      # lda #0 / rol / sta
    code += [0xA9, 0xFF] + abs_(0x8D, FLAG)
    here = TRAMPOLINE + len(code)
    code += abs_(0x4C, here)                             # jmp *
    assert TRAMPOLINE + len(code) <= HASH_OUT, "trampoline overruns HASH_OUT"
    return bytes(code)


def run_case(transport, lab, zp, blob, qxy, timeout):
    buf = lab["cert_buf"]
    assert len(blob) <= lab["cert_buf_size"]
    body_len = len(blob) - tb.SIG_LEN
    write_bytes(transport, buf, blob)
    if read_bytes(transport, buf, len(blob)) != blob:
        raise RuntimeError("bundle read-back mismatch")
    write_bytes(transport, lab["ecdsa_pubkey_x"], qxy[:32])
    write_bytes(transport, lab["ecdsa_pubkey_y"], qxy[32:])
    write_bytes(transport, TRAMPOLINE, trampoline(lab, zp, buf, body_len))
    write_bytes(transport, FLAG, b"\x00")
    t0 = time.monotonic()
    goto(transport, TRAMPOLINE)
    while True:
        time.sleep(10)
        if time.monotonic() - t0 > timeout:
            raise TimeoutError(f"no result after {timeout:.0f}s")
        try:
            if read_bytes(transport, FLAG, 1)[0] == 0xFF:
                break
            transport.resume()
        except Exception:               # noqa: BLE001 — monitor hiccup, retry
            continue
    carry = read_bytes(transport, RESULT, 1)[0]
    digest = read_bytes(transport, HASH_OUT, 32)
    return carry, digest, time.monotonic() - t0


def cases():
    blob = open(tb.SAMPLE_BUNDLE_PATH, "rb").read()

    def flip(i, bit):
        t = bytearray(blob)
        t[i] ^= 1 << bit
        return bytes(t)

    end = len(blob) - tb.SIG_LEN
    return [
        ("good (committed sample bundle)", blob),
        ("record: bit 0 of record 0 SPKI byte 0", flip(tb.HEADER_LEN + 16, 0)),
        ("gen: bit 1 of generation (1 -> 3)", flip(5, 1)),
        ("sig: bit 0 of the last byte of s", flip(end + 63, 0)),
    ]


def main():
    os.chdir(PROJECT_ROOT)
    make_args = shlex.split(os.environ.get("C64_MAKE_ARGS", ""))
    profile = " ".join(make_args) or "(bare make: ip65, REU profile)"
    if os.environ.get("C64_SKIP_BUILD"):
        print(f"=== build skipped (C64_SKIP_BUILD); C64_MAKE_ARGS={profile!r} "
              "NOT applied — read build/flags.stamp ===")
    else:
        print(f"=== make {profile} ===")
        subprocess.run(["make", "clean"] + make_args, capture_output=True)
        res = subprocess.run(["make"] + make_args, capture_output=True, text=True)
        if res.returncode != 0:
            print(res.stderr[-2000:])
            return cannot_run("build failed", executed=0, total=4,
                              certifies="on-C64 trust-bundle verify")
    if not os.path.exists(PRG_PATH):
        return cannot_run(f"{PRG_PATH} missing", executed=0, total=4,
                          certifies="on-C64 trust-bundle verify")
    prg = open(PRG_PATH, "rb").read()
    print(f"  PRG sha256 {hashlib.sha256(prg).hexdigest()}")

    labels = Labels.from_file(LABELS_PATH)
    missing = [n for n in LABELS if labels.address(n) is None]
    if missing:
        return cannot_run(f"labels missing: {missing}", executed=0, total=4,
                          certifies="on-C64 trust-bundle verify")
    lab = {n: labels.address(n) for n in LABELS}
    zp = zp_equates()
    qxy = tb.pubkey_xy(tb.load_public_key(tb.TEST_KEY_PATH))

    passed = failed = 0
    config = default_vice_config(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        menu_to = float(os.environ.get("C64_INIT_TIMEOUT", "60"))
        if wait_for_text(transport, "Q=QUIT", timeout=menu_to, verbose=False) is None:
            mgr.release(inst)
            return cannot_run("main menu never appeared", executed=0, total=4,
                              certifies="on-C64 trust-bundle verify")
        jsr(transport, lab["sqtab_init"], timeout=60.0)

        for name, blob in cases():
            try:
                tb.verify(blob, tb.load_public_key(tb.TEST_KEY_PATH), 0)
                want = 0
            except tb.BundleError:
                want = 1
            host_digest = hashlib.sha256(blob[:-tb.SIG_LEN]).digest()
            try:
                carry, digest, dt = run_case(transport, lab, zp, blob, qxy,
                                             float(os.environ.get(
                                                 "C64_CASE_TIMEOUT", "2400")))
            except Exception as e:      # noqa: BLE001
                failed += 1
                print(f"  FAIL {name}: {e}")
                continue
            ok_hash = digest == host_digest
            ok = carry == want and ok_hash
            passed += ok
            failed += not ok
            print(f"  {'PASS' if ok else 'FAIL'} {name}: C64 carry={carry} "
                  f"(want {want}), C64 SHA-256 {'==' if ok_hash else '!='} host "
                  f"{digest.hex()[:16]}... [{dt:.0f}s]")
        mgr.release(inst)

    return verdict(passed, failed, certifies="on-C64 trust-bundle verify "
                   f"({profile})")


if __name__ == "__main__":
    sys.exit(main())
