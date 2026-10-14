#!/usr/bin/env python3
"""test_curve_refusal.py - only P-256 is verified; everything else is refused.

P-384 was retired: the client verifies ECDSA P-256 only. This suite pins that
every other key or scheme a server can present is turned away cleanly, by the
image's own code (VICE, jsr into the real routines):

  [1a] the ClientHello's signature_algorithms offers 0x0403 and nothing else
  [1b] tls_handle_cert_verify's scheme gate: 0x0503, 0x0603, 0x0804 and
       0x0003 (wrong high byte) and 0x0401, 0x0402, 0x04FF (wrong low byte)
       stop AT the gate (tls_recv_sub_progress $21, C=1, ecdsa_curve_id
       untouched); 0x0403 gets past it ($22)
  [1c] a plain P-384 leaf through x509_extract_pubkey: C=1, ecdsa_curve_id
       and the P-256 key slots untouched
  [1d] CHARACTERISATION, not a guarantee: a P-384 leaf that ALSO carries a
       P-256 SPKI byte pattern after its real key (an unknown extension)
       gets THAT P-256 key extracted (C=0) -- the extractor scans for the
       first supported curve OID, it does not parse. RSA leaves behave the
       same way. CertificateVerify is then checked against the extracted key,
       one the server chose; nothing here validates a chain, and a pin binds
       to the extracted key (src/cert_pin.s).
  [1e] an RSA leaf: C=1, slots untouched
  [1f] an Ed25519 leaf: C=1, slots untouched

Every leaf carries a SAN naming tls_hostname, so on UCI the name check would
pass it: only the key type can refuse it. On TRUST_STORE builds (both shipped
UCI products) the extractor tail-calls the trust hook, which refuses unless
trust_pre set tp_mode; every extraction here first sets TP_M_FIRST, as a
first-use trust_pre would, so a refusal is the extractor's, not the hook's.
Run it on both shipped store builds, not only on plain images. Ported from the retired
test_tls_p384_negotiation.py ([1a]-[1d]) with the armed-build branches removed.

Usage:
    python3 tools/test_curve_refusal.py [--seed S]     # builds bare `make`
    C64_SKIP_BUILD=1 python3 tools/test_curve_refusal.py   # whatever build/ holds

Requires VICE x64sc. Exit 0 pass, 1 fail.
"""

import os
import random
import struct
import subprocess
import sys
import time

from c64_test_harness import (
    Labels,
    ViceInstanceManager,
    read_bytes,
    write_bytes,
    jsr,
    wait_for_text,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _vice_helpers import default_vice_config, menu_wait  # noqa: E402
from _skip_policy import verdict  # noqa: E402

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

CARRY_TRAMPOLINE = 0x033C
CARRY_RESULT_ADDR = 0x0352
CARRY_FLAG_ADDR = 0x0353

HOST = "www.foo.invalid"
EXPECTED_CHECKS = 6               # [1a] [1b] [1c] [1d] [1e] [1f]
CANARY = bytes([0xA5] * 32)


def _tp_mode_first():
    """TP_M_FIRST from src/trust_policy.inc (never a copied number)."""
    import re
    inc = os.path.join(PROJECT_ROOT, "src", "trust_policy.inc")
    m = re.search(r"^TP_M_FIRST\s*=\s*(\$?[0-9A-Fa-f]+)", open(inc).read(), re.M)
    v = m.group(1)
    return int(v[1:], 16) if v.startswith("$") else int(v)


def _arm_trust_hook(transport, labels):
    """TRUST_STORE builds (both shipped UCI products): x509_extract_pubkey
    tail-calls the trust hook (cert_pin_check), which refuses while tp_mode
    is TP_M_NONE ("trust_pre never ran"). Set first use, as trust_pre would,
    so a refusal seen here is the extractor's, never the hook's."""
    if labels.address("tp_mode") is not None:
        write_bytes(transport, labels["tp_mode"], bytes([_tp_mode_first()]))


def jsr_with_carry(transport, addr, timeout=120.0, poll_interval=0.5):
    """Call subroutine; return the carry after it (0/1) via a trampoline."""
    lo, hi = addr & 0xFF, (addr >> 8) & 0xFF
    trampoline = bytes([
        0xA9, 0x00,                                         # LDA #$00
        0x8D, CARRY_FLAG_ADDR & 0xFF, CARRY_FLAG_ADDR >> 8,  # STA flag
        0x20, lo, hi,                                       # JSR target
        0xA9, 0x00, 0x2A, 0x29, 0x01,                       # A = C
        0x8D, CARRY_RESULT_ADDR & 0xFF, CARRY_RESULT_ADDR >> 8,
        0xA9, 0xFF,
        0x8D, CARRY_FLAG_ADDR & 0xFF, CARRY_FLAG_ADDR >> 8,  # flag = $FF
        0x60,                                               # RTS
    ])
    write_bytes(transport, CARRY_TRAMPOLINE, trampoline)
    write_bytes(transport, CARRY_FLAG_ADDR, bytes([0x00]))
    jsr(transport, CARRY_TRAMPOLINE, timeout=timeout)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if read_bytes(transport, CARRY_FLAG_ADDR, 1)[0] == 0xFF:
            return read_bytes(transport, CARRY_RESULT_ADDR, 1)[0]
        time.sleep(poll_interval)
    raise TimeoutError(f"jsr_with_carry timed out after {timeout}s")


# ---------------------------------------------------------------------------
# [1a] ClientHello: 0x0403 only
# ---------------------------------------------------------------------------

def test_client_hello_sig_algs(transport, labels, rng):
    print("\n  [1a] ClientHello signature_algorithms: 0x0403 only")
    need = ["tls_build_client_hello", "tls_rec_buf", "tls_rec_len",
            "tls_client_random", "tls_ecdhe_pubkey"]
    missing = [n for n in need if labels.address(n) is None]
    if missing:
        print(f"       FAIL: missing labels {missing}")
        return 0, 1
    write_bytes(transport, labels["tls_client_random"],
                bytes(rng.getrandbits(8) for _ in range(32)))
    write_bytes(transport, labels["tls_ecdhe_pubkey"],
                bytes(rng.getrandbits(8) for _ in range(32)))
    try:
        jsr(transport, labels["tls_build_client_hello"], timeout=60.0)
    except Exception as e:
        print(f"       FAIL: tls_build_client_hello raised {e}")
        return 0, 1
    lb = read_bytes(transport, labels["tls_rec_len"], 2)
    msg_len = lb[0] | (lb[1] << 8)
    msg = read_bytes(transport, labels["tls_rec_buf"], min(msg_len, 320))
    if len(msg) < 49:
        print(f"       FAIL: ClientHello too short ({len(msg)} B)")
        return 0, 1
    # [4-5] version, [6-37] random, [38] sid len 0, [39-42] one suite,
    # [43-44] compression, [45-46] extensions length, [47..] extensions.
    pos, end = 47, min(47 + ((msg[45] << 8) | msg[46]), len(msg))
    payload = None
    while pos + 4 <= end:
        etype = (msg[pos] << 8) | msg[pos + 1]
        elen = (msg[pos + 2] << 8) | msg[pos + 3]
        if etype == 0x000D:
            payload = msg[pos + 4:pos + 4 + elen]
            break
        pos += 4 + elen
    if payload is None or len(payload) < 2:
        print("       FAIL: no signature_algorithms extension")
        return 0, 1
    inner = payload[2:2 + ((payload[0] << 8) | payload[1])]
    schemes = sorted((inner[i] << 8) | inner[i + 1] for i in range(0, len(inner) - 1, 2))
    shown = ", ".join(f"0x{s:04x}" for s in schemes) or "(none)"
    if schemes != [0x0403]:
        print(f"       FAIL: advertised {shown}, want exactly 0x0403")
        return 0, 1
    print(f"       PASS: advertised {shown}")
    return 1, 0


# ---------------------------------------------------------------------------
# [1b] CertificateVerify 0x0503 refused in the handler
# ---------------------------------------------------------------------------

def test_cert_verify_scheme_gate(transport, labels):
    """tls_handle_cert_verify accepts signature_scheme 0x0403 and nothing else.

    Judged by tls_recv_sub_progress, which the handler sets to $21 after the
    handshake-type check and to $22 only once the scheme gate has passed --
    so the assertion is about the GATE, not about what fails later. (The
    first version of this check sent 48 zero bytes and asserted only C=1:
    ecdsa_parse_der_sig rejects those regardless, so a handler with no
    scheme gate at all still passed. Review finding on the retirement.)

    Refused schemes must stop at $21 with C=1 and ecdsa_curve_id untouched;
    the 0x0403 control must get past the gate (>= $22). The signature bytes
    are zeros, so even the control fails the DER parse right after the gate
    and no verify runs.
    """
    print("\n  [1b] CertificateVerify scheme gate: 0x0403 only")
    need = ["tls_handle_cert_verify", "tls_hs_ptr_reset", "tls_rec_buf",
            "ecdsa_curve_id", "tls_recv_sub_progress"]
    missing = [n for n in need if labels.address(n) is None]
    if missing:
        print(f"       FAIL: missing labels {missing}")
        return 0, 1
    prog = labels["tls_recv_sub_progress"]
    sig = bytes(48)
    ok_all = True
    for scheme, accept in ((0x0503, False), (0x0603, False), (0x0804, False),
                           (0x0003, False),
                           # high byte $04: only the LOW-byte check refuses
                           # these (0x0401 = rsa_pkcs1_sha256)
                           (0x0401, False), (0x0402, False), (0x04FF, False),
                           (0x0403, True)):
        msg = (bytes([0x0F]) + b"\x00\x00\x00" + struct.pack(">H", scheme)
               + struct.pack(">H", len(sig)) + sig)
        write_bytes(transport, labels["tls_rec_buf"], msg)
        write_bytes(transport, labels["ecdsa_curve_id"], bytes([0xFF]))
        write_bytes(transport, prog, bytes([0x00]))
        try:
            # Under TLS_STREAM_DEFRAME (UCI) the handler does not reset
            # tls_hs_ptr itself; tls_hs_ptr_reset does, on either backend.
            jsr(transport, labels["tls_hs_ptr_reset"], timeout=30.0)
            carry = jsr_with_carry(transport, labels["tls_handle_cert_verify"],
                                   timeout=60.0)
        except Exception as e:
            print(f"       FAIL 0x{scheme:04x}: raised {e}")
            ok_all = False
            continue
        p = read_bytes(transport, prog, 1)[0]
        curve = read_bytes(transport, labels["ecdsa_curve_id"], 1)[0]
        if accept:
            ok = p >= 0x22
            what = f"progress ${p:02X} (want >= $22: past the gate)"
        else:
            ok = p == 0x21 and carry == 1 and curve == 0xFF
            what = (f"progress ${p:02X} (want $21: stopped at the gate), C={carry}, "
                    f"curve_id={curve:#x}")
        print(f"       {'PASS' if ok else 'FAIL'} 0x{scheme:04x}: {what}")
        ok_all = ok_all and ok
    return (1, 0) if ok_all else (0, 1)


# ---------------------------------------------------------------------------
# [1c]-[1f] leaves through the live extractor
# ---------------------------------------------------------------------------

def _p384_leaf_with_trailing_p256(spki384, spki256, host):
    """A P-384 leaf whose real SPKI comes first, plus a P-256 SPKI's bytes
    inside an unknown, non-critical extension (OID 1.3.6.1.4.1.99999.1)
    AFTER it. Unsigned: nothing on the C64 checks a certificate signature."""
    from test_cert_pin import tlv
    tbs = (tlv(0xA0, tlv(0x02, b"\x02")) + tlv(0x02, b"\x01")
           + tlv(0x30, tlv(0x06, bytes.fromhex("2a8648ce3d040303")))
           + tlv(0x30, b"") + tlv(0x30, b"") + tlv(0x30, b"") + spki384)
    san = tlv(0x30, tlv(0x06, b"\x55\x1d\x11")
              + tlv(0x04, tlv(0x30, tlv(0x82, host.encode()))))
    unknown = tlv(0x30, tlv(0x06, bytes.fromhex("2b06010401868d1f01"))
                  + tlv(0x04, spki256))
    tbs += tlv(0xA3, tlv(0x30, san + unknown))
    return tlv(0x30, tlv(0x30, tbs) + tlv(0x30, b"") + tlv(0x03, b"\x00"))


def _extract(transport, labels, leaf):
    """Stage `leaf` in cert_buf and run x509_extract_pubkey.
    Returns (carry, curve_id, 64 B of ecdsa_pubkey_x||y)."""
    cb = labels["cert_buf"]
    write_bytes(transport, cb, leaf)
    write_bytes(transport, labels["cert_data_ptr"], bytes([cb & 0xFF, cb >> 8]))
    write_bytes(transport, labels["cert_data_len_lo"], bytes([len(leaf) & 0xFF]))
    write_bytes(transport, labels["cert_data_len_hi"], bytes([len(leaf) >> 8]))
    if labels.address("tls_hostname") is not None:
        write_bytes(transport, labels["tls_hostname"], HOST.encode() + b"\x00")
        write_bytes(transport, labels["tls_hostname_len"], bytes([len(HOST)]))
    write_bytes(transport, labels["ecdsa_pubkey_x"], CANARY)
    write_bytes(transport, labels["ecdsa_pubkey_y"], CANARY)
    write_bytes(transport, labels["ecdsa_curve_id"], bytes([0xFF]))
    _arm_trust_hook(transport, labels)
    carry = jsr_with_carry(transport, labels["x509_extract_pubkey"], timeout=60.0)
    curve = read_bytes(transport, labels["ecdsa_curve_id"], 1)[0]
    q = (read_bytes(transport, labels["ecdsa_pubkey_x"], 32)
         + read_bytes(transport, labels["ecdsa_pubkey_y"], 32))
    return carry, curve, q


def test_leaves(transport, labels):
    need = ["x509_extract_pubkey", "cert_buf", "cert_data_ptr",
            "cert_data_len_lo", "cert_data_len_hi", "ecdsa_curve_id",
            "ecdsa_pubkey_x", "ecdsa_pubkey_y"]
    missing = [n for n in need if labels.address(n) is None]
    if missing:
        print(f"\n  [1c-1f] FAIL: missing labels {missing}")
        return 0, 4
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    from test_cert_pin import make_cert, point, spki

    k384 = ec.derive_private_key(0x384, ec.SECP384R1())
    k256 = ec.derive_private_key(0x256, ec.SECP256R1())
    krsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ked = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))

    refused = [
        ("1c", "a plain P-384 leaf", make_cert(spki(k384), [HOST])),
        ("1e", "an RSA-2048 leaf", make_cert(spki(krsa), [HOST])),
        ("1f", "an Ed25519 leaf", make_cert(spki(ked), [HOST])),
    ]
    passed = failed = 0
    for tag, what, leaf in refused:
        print(f"\n  [{tag}] {what} through x509_extract_pubkey")
        try:
            c, curve, q = _extract(transport, labels, leaf)
        except Exception as e:
            print(f"       FAIL: raised {e} (a hang is a failure)")
            failed += 1
            continue
        ok = c == 1 and curve == 0xFF and q == CANARY * 2
        print(f"       {'PASS' if ok else 'FAIL'}: C={c} (want 1), "
              f"curve_id={curve:#x} (want 0xff), key slots "
              f"{'untouched' if q == CANARY * 2 else 'WRITTEN'}")
        passed += ok
        failed += not ok

    print("\n  [1d] P-384 leaf + a trailing P-256 SPKI pattern (characterisation)")
    leaf = _p384_leaf_with_trailing_p256(spki(k384), spki(k256), HOST)
    try:
        c, curve, q = _extract(transport, labels, leaf)
        ok = c == 0 and curve == 0 and q == point(k256)
        print(f"       {'PASS' if ok else 'FAIL'}: C={c} (want 0), curve_id={curve:#x} "
              f"(want 0), extracted key "
              f"{'= the trailing P-256 one' if q == point(k256) else 'UNEXPECTED'}")
    except Exception as e:
        print(f"       FAIL: raised {e}")
        ok = False
    passed += ok
    failed += not ok
    return passed, failed


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def run_tests(transport, labels, seed=None):
    """Runner entry point (tools/run_all_tests.py): returns (passed, failed).

    Assumes a booted machine at the menu. A check that produced no verdict
    counts as a failure, so the tally always covers EXPECTED_CHECKS."""
    rng = random.Random(seed)
    passed = failed = 0
    for fn in (lambda: test_client_hello_sig_algs(transport, labels, rng),
               lambda: test_cert_verify_scheme_gate(transport, labels),
               lambda: test_leaves(transport, labels)):
        p, f = fn()
        passed += p
        failed += f
    if passed + failed != EXPECTED_CHECKS:
        print(f"  [-] curve refusal: only {passed + failed} of "
              f"{EXPECTED_CHECKS} checks produced a verdict")
        failed += EXPECTED_CHECKS - (passed + failed)
    return passed, failed


def main():
    os.chdir(PROJECT_ROOT)
    seed = random.randint(0, 2**32 - 1)
    if "--seed" in sys.argv:
        seed = int(sys.argv[sys.argv.index("--seed") + 1])
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

    if os.environ.get("C64_SKIP_BUILD"):
        print("\n=== Building (skipped: C64_SKIP_BUILD set) ===")
    else:
        print("\n=== Building: make ===")
        subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
        r = subprocess.run(["make"], capture_output=True, text=True, cwd=PROJECT_ROOT)
        if r.returncode != 0:
            print(f"Build failed:\n{r.stderr}")
            sys.exit(1)
    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found")
        sys.exit(1)
    labels = Labels.from_file(LABELS_PATH)

    config = default_vice_config(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    passed = failed = 0
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        t = inst.transport
        if wait_for_text(t, "Q=QUIT", timeout=menu_wait(60), verbose=False) is None:
            print("FATAL: main menu did not appear")
            sys.exit(1)
        passed, failed = run_tests(t, labels, seed)
        mgr.release(inst)

    print(f"\n{'=' * 60}\n  Passed: {passed}/{passed + failed}")
    print(f"  [{'+' if failed == 0 else '-'}] curve refusal: "
          f"{'PASS' if failed == 0 else 'FAIL'} ({passed}/{EXPECTED_CHECKS})")
    sys.exit(verdict(passed, failed,
                     certifies="only P-256 is accepted: P-384 / RSA / Ed25519 "
                               "leaves and a 0x0503 CertificateVerify are refused"))


if __name__ == "__main__":
    main()
