#!/usr/bin/env python3
"""test_cert_pin.py — build-time leaf SPKI pin (issue #155, phase 1).

Builds its own images, because the pin is a build input: an ENFORCE image and
a WARN image, both pinned to key A, generated here. Then drives the real entry
point, ``x509_extract_pubkey`` (whose success exit tail-calls
``cert_pin_check``), over DMA exactly as ``test_x509_name.py`` drives the name
check: stage a DER leaf in cert_buf, set tls_hostname, JSR, read the carry,
``cert_pin_status`` and the screen.

What each group proves
----------------------
* match / mismatch — the compare, the status byte, and the on-screen
  "PIN FAIL EXP <4 bytes> GOT <4 bytes>" diagnostic.
* displaced key — the extractor SCANS for the first ecPublicKey OID rather
  than parsing the DER, so a leaf can carry a second SPKI earlier (planted in
  the subject here). The pin must bind to the key the extractor actually
  copied into ecdsa_pubkey_x/y, i.e. the key CertificateVerify is checked
  against — not to the structurally-correct SPKI. Pinning the structural SPKI
  (the design as first written in #155) ACCEPTS "real SPKI = A, planted SPKI
  = B" while CertificateVerify then runs against B. Both directions are here.
* curve gate — a non-P-256 extraction leaves ecdsa_pubkey_x/y holding an
  EARLIER connection's key, so the check refuses ecdsa_curve_id != 0 even when
  the window hashes right. Driven directly, since no real P-384 leaf can make
  that window hash to a P-256 pin.
* name chaining — a pinned key with the wrong SAN still fails (the pin runs
  first, then tail-calls #135's name check).
* interlock — ``cert_pin_require`` (what tls_connect calls before deriving
  traffic keys) refuses status $00, i.e. "no Certificate was ever checked";
  the map must show tls13.o importing it. The full-handshake version of this
  (a flight with no Certificate) is a hardware rig run, see the PR.
* banner — "SPKI PIN <4 bytes>" at boot.
* helper — tools/spki_pin.py agrees with the openssl pipeline byte for byte.

Usage:
    python3 tools/test_cert_pin.py            # builds BACKEND=uci onchip twice
    C64_PIN_PROFILE=uci|ip65-onchip|ip65 python3 tools/test_cert_pin.py

Leaves build/ holding the WARN image. Exit 0 pass, 1 fail, 2 could not run.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from c64_test_harness import (
    Labels, ScreenGrid, ViceInstanceManager, goto, read_bytes, wait_for_text,
    write_bytes,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _vice_helpers import default_vice_config  # noqa: E402
from _skip_policy import verdict as exit_verdict  # noqa: E402
import spki_pin  # noqa: E402

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")
MAP_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.map")

PROFILES = {
    "onchip": ["BACKEND=uci", "USE_NISTCURVES_ONCHIP=1"],
    "uci": ["BACKEND=uci"],
    "ip65-onchip": ["BACKEND=ip65", "USE_NISTCURVES_ONCHIP=1"],
    "ip65": ["BACKEND=ip65"],
}

CARRY_TRAMPOLINE = 0x033C
CARRY_RESULT_ADDR = 0x0352
CARRY_FLAG_ADDR = 0x0353
ZP_PTR = 0xFB

HOST = "www.foo.invalid"
ST_NONE, ST_MATCH, ST_BAD = 0x00, 0x01, 0x80


# --- keys and DER ------------------------------------------------------------

def key(n: int) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(n, ec.SECP256R1())


def spki(k) -> bytes:
    return k.public_key().public_bytes(serialization.Encoding.DER,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)


def point(k) -> bytes:
    return k.public_key().public_bytes(serialization.Encoding.X962,
                                       serialization.PublicFormat.UncompressedPoint)[1:]


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])


def tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _len(len(payload)) + payload


def make_cert(spki_der: bytes, sans, planted: bytes = b"") -> bytes:
    """A leaf carrying a real SPKI, a SAN, and optionally a second SPKI's
    bytes planted in the subject CN (before the real one, so the extractor's
    scan finds the planted one first). Unsigned: nothing here checks it."""
    subject = b""
    if planted:
        subject = tlv(0x31, tlv(0x30, tlv(0x06, b"\x55\x04\x03") + tlv(0x0C, planted)))
    tbs = (tlv(0xA0, tlv(0x02, b"\x02")) + tlv(0x02, b"\x01")
           + tlv(0x30, tlv(0x06, bytes.fromhex("2a8648ce3d040302")))
           + tlv(0x30, b"") + tlv(0x30, b"") + tlv(0x30, subject) + spki_der)
    names = b"".join(tlv(0x82, n.encode()) for n in sans)
    ext = tlv(0x06, b"\x55\x1d\x11") + tlv(0x04, tlv(0x30, names))
    tbs += tlv(0xA3, tlv(0x30, tlv(0x30, ext)))
    return tlv(0x30, tlv(0x30, tbs) + tlv(0x30, b"") + tlv(0x03, b"\x00"))


# --- build ---------------------------------------------------------------------

def build(pin: str, warn: bool, profile: list[str]) -> str | None:
    args = ["make"] + profile + [f"HTTPS_PIN_SPKI_SHA256={pin}"]
    if warn:
        args.append("HTTPS_PIN_WARN=1")
    subprocess.run(["make", "clean"], cwd=PROJECT_ROOT, capture_output=True)
    r = subprocess.run(args, cwd=PROJECT_ROOT, capture_output=True, text=True)
    if r.returncode != 0 or not os.path.exists(PRG_PATH):
        print(r.stdout[-2000:] + r.stderr[-2000:], file=sys.stderr)
        return None
    with open(PRG_PATH, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def imports_of(symbol: str) -> list[str]:
    """Modules the ld65 map lists as importing *symbol*."""
    txt = open(MAP_PATH).read()
    sect = txt[txt.index("Imports list:"):]
    m = re.search(rf"^{re.escape(symbol)} \(.*?\):\n((?:    .*\n)+)", sect, re.M)
    return re.findall(r"^\s+(\S+?\.o)", m.group(1), re.M) if m else []


# --- 6502 driving ---------------------------------------------------------------

def jsr_with_carry(t, addr, timeout=60.0, poll=0.5):
    lo, hi = addr & 0xFF, (addr >> 8) & 0xFF
    rl, rh = CARRY_RESULT_ADDR & 0xFF, CARRY_RESULT_ADDR >> 8
    fl, fh = CARRY_FLAG_ADDR & 0xFF, CARRY_FLAG_ADDR >> 8
    loop = CARRY_TRAMPOLINE + 19
    write_bytes(t, CARRY_TRAMPOLINE, bytes([
        0xA9, 0x00, 0x8D, fl, fh, 0x20, lo, hi, 0xA9, 0x00, 0x2A,
        0x8D, rl, rh, 0xA9, 0xFF, 0x8D, fl, fh, 0x4C, loop & 0xFF, loop >> 8]))
    write_bytes(t, CARRY_FLAG_ADDR, b"\x00")
    goto(t, CARRY_TRAMPOLINE)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(poll)
        try:
            if read_bytes(t, CARRY_FLAG_ADDR, 1)[0] == 0xFF:
                return read_bytes(t, CARRY_RESULT_ADDR, 1)[0]
            t.resume()
        except Exception:
            continue
    return None


class Run:
    def __init__(self, t, labels):
        self.t, self.L = t, labels
        self.passed = self.failed = 0

    def check(self, name, ok, detail=""):
        self.passed += bool(ok)
        self.failed += not ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' — ' + detail) if detail else ''}")

    def blank_screen(self):
        write_bytes(self.t, 0x0400, b"\x20" * 1000)

    def screen(self) -> str:
        return ScreenGrid.from_transport(self.t).continuous_text().upper()

    def status(self) -> int:
        return read_bytes(self.t, self.L["cert_pin_status"], 1)[0]

    def stage(self, der: bytes, host: str = HOST):
        L, t = self.L, self.t
        write_bytes(t, L["cert_buf"], der)
        write_bytes(t, L["cert_data_ptr"], bytes([L["cert_buf"] & 0xFF, L["cert_buf"] >> 8]))
        n = len(der)
        write_bytes(t, L["cert_data_len_lo"], bytes([n & 0xFF]))
        write_bytes(t, L["cert_data_len_hi"], bytes([n >> 8]))
        write_bytes(t, L["tls_hostname"], host.encode() + b"\x00")
        write_bytes(t, L["tls_hostname_len"], bytes([len(host)]))
        write_bytes(t, L["cert_pin_status"], bytes([ST_NONE]))
        self.blank_screen()

    def extract(self, der: bytes, host: str = HOST):
        self.stage(der, host)
        c = jsr_with_carry(self.t, self.L["x509_extract_pubkey"])
        return c, self.status(), read_bytes(self.t, self.L["ecdsa_pubkey_x"], 32) + \
            read_bytes(self.t, self.L["ecdsa_pubkey_y"], 32), self.screen()

    def require(self, st: int):
        write_bytes(self.t, self.L["cert_pin_status"], bytes([st]))
        return jsr_with_carry(self.t, self.L["cert_pin_require"])


def h4(b: bytes) -> str:
    return b[:4].hex().upper()


def run_image(r: Run, warn: bool, A, B, name_check: bool):
    pin_a = hashlib.sha256(spki(A)).digest()
    pin_b = hashlib.sha256(spki(B)).digest()
    word = "WARN" if warn else "FAIL"
    good = make_cert(spki(A), [HOST])
    bad = make_cert(spki(B), [HOST])

    c, st, pk, scr = r.extract(good)
    r.check("pinned key accepted", c == 0 and st == ST_MATCH and pk == point(A),
            f"C={c} status=${st:02X}")
    r.check("no diagnostic on a match", "PIN " not in scr)

    c, st, pk, scr = r.extract(bad)
    want_c = 0 if warn else 1
    r.check(f"other key: C={want_c} ({'continue' if warn else 'abort'}), status $80",
            c == want_c and st == ST_BAD, f"C={c} status=${st:02X}")
    needle = f"PIN {word} EXP {h4(pin_a)} GOT {h4(pin_b)}"
    r.check(f"diagnostic '{needle}' on screen", needle in scr)

    # Displaced key, the attack: structural SPKI = A (pinned), planted SPKI = B
    # earlier in the TBS. The extractor copies B; the pin must see B.
    der = make_cert(spki(A), [HOST], planted=spki(B))
    c, st, pk, scr = r.extract(der)
    r.check("displaced key: extractor took the planted key (fixture sanity)",
            pk == point(B))
    r.check("displaced key: pin judges the key that will be VERIFIED (B), not the "
            "structural SPKI (A)", st == ST_BAD and c == want_c, f"C={c} status=${st:02X}")

    # Reverse: structural = B, planted = A. The verified key is A, the pinned
    # one — accepting is correct, and proves the binding is to the used key.
    der = make_cert(spki(B), [HOST], planted=spki(A))
    c, st, pk, _ = r.extract(der)
    r.check("reverse displacement: verified key is A, so the pin accepts",
            c == 0 and st == ST_MATCH and pk == point(A), f"C={c} status=${st:02X}")

    # Pin passes, name fails: the chain still rejects — where there IS a name
    # check (#135, UCI only). On ip65 the pin is the whole certificate check.
    c, st, _, _ = r.extract(make_cert(spki(A), ["other.example"]))
    if name_check:
        r.check("pinned key, wrong SAN: pin passes, name check still rejects",
                c == 1 and st == ST_MATCH, f"C={c} status=${st:02X}")
    else:
        r.check("pinned key, wrong SAN: accepted (ip65 has no name check)",
                c == 0 and st == ST_MATCH, f"C={c} status=${st:02X}")

    # Curve gate, driven directly: a window that hashes to the pin, with
    # ecdsa_curve_id = 1 as a P-384 extraction leaves it.
    L, t = r.L, r.t
    r.stage(good)
    qy = L["cert_buf"] + good.index(spki(A)) + 59
    for curve, want_st, want_carry in ((1, ST_BAD, want_c), (0, ST_MATCH, 0)):
        write_bytes(t, L["cert_pin_status"], bytes([ST_NONE]))
        write_bytes(t, L["ecdsa_curve_id"], bytes([curve]))
        write_bytes(t, ZP_PTR, bytes([qy & 0xFF, qy >> 8]))
        c = jsr_with_carry(t, L["cert_pin_check"])
        st = r.status()
        r.check(f"curve gate: ecdsa_curve_id={curve} -> status ${want_st:02X}",
                st == want_st and c == want_carry, f"C={c} status=${st:02X}")

    # Interlock.
    want = {ST_NONE: 1, ST_MATCH: 0, ST_BAD: 0 if warn else 1}
    for st, w in want.items():
        c = r.require(st)
        what = {ST_NONE: "never ran (no Certificate)", ST_MATCH: "matched",
                ST_BAD: "mismatched"}[st]
        r.check(f"cert_pin_require, check {what}: C={w}", c == w, f"C={c}")


def main() -> int:
    os.chdir(PROJECT_ROOT)
    prof_name = os.environ.get("C64_PIN_PROFILE", "onchip")
    if prof_name not in PROFILES:
        print(f"C64_PIN_PROFILE must be one of {sorted(PROFILES)}", file=sys.stderr)
        return 2
    profile = PROFILES[prof_name]
    A, B = key(0xA11CE), key(0xB0B)
    pin_a = hashlib.sha256(spki(A)).hexdigest()
    passed = failed = 0

    # Helper vs openssl on a real PEM.
    pem = os.path.join(PROJECT_ROOT, "build", "pin_test_leaf.pem")
    if shutil.which("openssl"):
        os.makedirs(os.path.dirname(pem), exist_ok=True)
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import NameOID
        import datetime
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(A.public_key()).serial_number(1)
                .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
                .sign(A, hashes.SHA256()))
        with open(pem, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        ossl = subprocess.run(
            f"openssl x509 -in '{pem}' -pubkey -noout | openssl pkey -pubin -outform DER"
            " | openssl dgst -sha256 -r", shell=True, capture_output=True, text=True
        ).stdout.split()[0]
        helper = spki_pin.pin_of(cert)
        ok = helper == ossl == pin_a
        print(f"  [{'PASS' if ok else 'FAIL'}] tools/spki_pin.py == openssl pipeline ({helper[:16]}…)")
        passed += ok
        failed += not ok
        p384_rejected = False
        try:
            from cryptography.hazmat.primitives.asymmetric import ec as _ec
            p384 = _ec.generate_private_key(_ec.SECP384R1())
            c384 = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(p384.public_key()).serial_number(1)
                    .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
                    .sign(p384, hashes.SHA384()))
            spki_pin.pin_of(c384)
        except spki_pin.NotP256:
            p384_rejected = True
        print(f"  [{'PASS' if p384_rejected else 'FAIL'}] tools/spki_pin.py refuses a P-384 leaf")
        passed += p384_rejected
        failed += not p384_rejected
    else:
        print("  [FAIL] openssl not on PATH: the helper cross-check could not run")
        failed += 1

    for warn in (False, True):
        mode = "WARN" if warn else "ENFORCE"
        print(f"\n=== {mode} image: make {' '.join(profile)} HTTPS_PIN_SPKI_SHA256={pin_a[:16]}…"
              f"{' HTTPS_PIN_WARN=1' if warn else ''}")
        h = build(pin_a, warn, profile)
        if h is None:
            print(f"CANNOT RUN: the {mode} image did not build", file=sys.stderr)
            return 2
        print(f"  PRG sha256 {h}")
        labels = Labels.from_file(LABELS_PATH)
        need = ["x509_extract_pubkey", "cert_pin_check", "cert_pin_require",
                "cert_pin_status", "cert_buf", "cert_data_ptr", "cert_data_len_lo",
                "cert_data_len_hi", "tls_hostname", "tls_hostname_len",
                "ecdsa_pubkey_x", "ecdsa_pubkey_y", "ecdsa_curve_id"]
        missing = [n for n in need if labels.address(n) is None]
        if missing:
            print(f"CANNOT RUN: labels missing from the {mode} image: {missing}", file=sys.stderr)
            return 2

        wired = "tls13.o" in " ".join(imports_of("cert_pin_require")) and \
                "tls13.o" in " ".join(imports_of("cert_pin_status"))
        print(f"  [{'PASS' if wired else 'FAIL'}] map: tls13.o imports cert_pin_require"
              " and cert_pin_status (the interlock is linked into tls_connect)")
        passed += wired
        failed += not wired

        config = default_vice_config(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
        with ViceInstanceManager(config=config) as mgr:
            t = mgr.acquire().transport
            grid = wait_for_text(t, "Q=QUIT", timeout=float(os.environ.get("C64_INIT_TIMEOUT", "120")),
                                 verbose=False)
            if grid is None:
                print("CANNOT RUN: menu never appeared", file=sys.stderr)
                return 2
            want_banner = f"SPKI PIN {h4(bytes.fromhex(pin_a))}" + (" WARN" if warn else "")
            scr = grid.continuous_text().upper()
            ok = want_banner in scr and (warn or f"{want_banner} WARN" not in scr)
            print(f"  [{'PASS' if ok else 'FAIL'}] boot banner shows '{want_banner}'")
            passed += ok
            failed += not ok
            r = Run(t, labels)
            run_image(r, warn, A, B, name_check="BACKEND=uci" in profile)
            passed += r.passed
            failed += r.failed

    print(f"\nRESULTS: {passed}/{passed + failed} passed")
    return exit_verdict(passed, failed, certifies="SPKI pin (#155): compare, "
                        "diagnostic, key binding, curve gate, interlock, banner")


if __name__ == "__main__":
    sys.exit(main())
