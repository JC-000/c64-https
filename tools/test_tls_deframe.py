#!/usr/bin/env python3
"""test_tls_deframe.py - W1 streaming handshake-message deframer coverage.

Drives ``tls_deframe_init`` / ``tls_deframe_new_record`` /
``tls_deframe_pump`` (src/tls_deframe.s) directly over DMA in VICE,
feeding synthetic handshake plaintext "records" into tls_rec_buf at
record/message alignments a real server produces but the local listener
never does:

  - several messages sharing one record
  - a message body split across records (carry-buffer path)
  - a message HEADER split across records
  - a split server Finished, positive and negative — proves the
    per-MESSAGE transcript discipline: tls_verify_finished must see the
    running hash EXCLUDING the Finished message itself, even when that
    message arrived in two records
  - a spanning non-Certificate message larger than the carry buffer
    (explicit error, never an overflow)
  - W2: a Certificate spanning records — leaf streamed into cert_buf,
    remaining chain entries discarded, pubkey extracted; and the
    explicit "certificate too large" error path

The deframer is UCI-only (TLS_STREAM_DEFRAME — see the Makefile), so
this test builds ``BACKEND=uci``. The UCI build boots to the menu in
VICE (net_init fails non-fatally without UCI hardware) exactly like
tools/test_x25519.py's BACKEND=uci mode.

After each successful scenario the running transcript is finalized
(tls_transcript_hash) and compared against a Python SHA-256 of every
handshake byte fed — the deframer must fold exactly the message bytes,
once each, in order, whatever the record framing was.

Env:
    C64_SKIP_BUILD=1   reuse the already-built PRG (must be BACKEND=uci)

Requires: Python 3.10+, c64_test_harness, VICE x64sc
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import os
import struct
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from c64_test_harness import (
    Labels,
    ViceInstanceManager,
    read_bytes,
    write_bytes,
    jsr,
    wait_for_text,
)

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _vice_helpers import default_vice_config  # noqa: E402

PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

REQUIRED_LABELS = [
    "tls_deframe_init", "tls_deframe_new_record", "tls_deframe_pump",
    "df_last_err", "df_carry_buf",
    "tls_rec_buf", "tls_rec_len",
    "tls_transcript_init", "tls_transcript_hash", "tls_transcript",
    "tls_s_hs_secret",
    "cert_buf", "cert_buf_len",
    "ecdsa_pubkey_x", "ecdsa_pubkey_y", "ecdsa_curve_id",
]

# Handshake message types
HS_EE = 8
HS_CERT = 11
HS_CV = 15
HS_FIN = 20

# deframer error codes (src/tls_deframe.s DF_ERR_*)
ERR_HDR_LEN = 1
ERR_TOO_BIG = 2
ERR_DISPATCH = 3
ERR_TYPE = 4
ERR_CERT_FMT = 5
ERR_CERT_TOO_BIG = 6

TLS_HS_PTR = 0x3E               # ZP base pointer (src/constants.inc)

# Cassette buffer (see test_finished_verify.py for the layout rationale).
# The stub is 13 bytes ($0340-$034C), so the latches sit at $0355/$0356 —
# clear of the stub and of the harness trampolines at $0334 and $0360.
STUB_ADDR = 0x0340
C_LATCH = 0x0355
A_LATCH = 0x0356


# ---------------------------------------------------------------------------
# Python reference crypto (same helpers as test_finished_verify.py)
# ---------------------------------------------------------------------------

def hkdf_expand_label(secret: bytes, label: bytes, context: bytes,
                      length: int) -> bytes:
    assert length <= 32
    info = struct.pack(">H", length)
    info += bytes([6 + len(label)]) + b"tls13 " + label
    info += bytes([len(context)]) + context
    return hmac.new(secret, info + b"\x01", hashlib.sha256).digest()[:length]


def finished_verify_data(traffic_secret: bytes, transcript: bytes) -> bytes:
    finished_key = hkdf_expand_label(traffic_secret, b"finished", b"", 32)
    return hmac.new(finished_key, transcript, hashlib.sha256).digest()


def hs_msg(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + len(body).to_bytes(3, "big") + body


def cert_msg(entries, ctx: bytes = b"") -> bytes:
    """RFC 8446 §4.4.2 Certificate message. entries = [(der, ext_bytes)]."""
    lst = b""
    for der, ext in entries:
        lst += len(der).to_bytes(3, "big") + der
        lst += len(ext).to_bytes(2, "big") + ext
    body = bytes([len(ctx)]) + ctx + len(lst).to_bytes(3, "big") + lst
    return hs_msg(HS_CERT, body)


def chunks(data: bytes, n: int):
    return [data[i:i + n] for i in range(0, len(data), n)]


def generate_p256_cert():
    """Self-signed ECDSA P-256 cert (same recipe as test_x509.py)."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(datetime.datetime.now(datetime.UTC)
                             + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    nums = key.public_key().public_numbers()
    return der, nums.x.to_bytes(32, "big"), nums.y.to_bytes(32, "big")


SECRET = hashlib.sha256(b"c64-https lane A deframe secret").digest()


# ---------------------------------------------------------------------------
# C64 plumbing
# ---------------------------------------------------------------------------

def install_stub(transport, pump_addr: int) -> None:
    """jsr pump; latch A (sta abs leaves flags alone), then latch carry."""
    stub = bytes([
        0x20, pump_addr & 0xFF, pump_addr >> 8,      # jsr tls_deframe_pump
        0x8D, A_LATCH & 0xFF, A_LATCH >> 8,          # sta A_LATCH
        0xA9, 0x00,                                  # lda #0
        0x2A,                                        # rol a  (carry -> bit 0)
        0x8D, C_LATCH & 0xFF, C_LATCH >> 8,          # sta C_LATCH
        0x60,                                        # rts
    ])
    write_bytes(transport, STUB_ADDR, stub)
    if read_bytes(transport, STUB_ADDR, len(stub)) != stub:
        raise RuntimeError("pump stub readback mismatch")


class Rig:
    def __init__(self, transport, labels):
        self.t = transport
        self.l = labels

    def reset(self):
        """Fresh transcript + deframer state (record marked consumed)."""
        write_bytes(self.t, self.l["tls_rec_len"], b"\x00\x00")
        jsr(self.t, self.l["tls_transcript_init"], timeout=30.0)
        jsr(self.t, self.l["tls_deframe_init"], timeout=30.0)

    def feed_record(self, data: bytes):
        write_bytes(self.t, self.l["tls_rec_buf"], data)
        write_bytes(self.t, self.l["tls_rec_len"],
                    struct.pack("<H", len(data)))
        jsr(self.t, self.l["tls_deframe_new_record"], timeout=30.0)

    def pump(self, timeout=60.0):
        """Return (carry, a)."""
        write_bytes(self.t, C_LATCH, b"\xa5")
        write_bytes(self.t, A_LATCH, b"\xa5")
        jsr(self.t, STUB_ADDR, timeout=timeout)
        carry = read_bytes(self.t, C_LATCH, 1)[0]
        a = read_bytes(self.t, A_LATCH, 1)[0]
        if carry == 0xA5:
            raise RuntimeError("carry latch never written — stub did not run")
        return carry, a

    def drive(self, records, max_pumps=64):
        """Feed records, pumping each dry. Returns event list:
        'msg' per dispatched message, ('err', code) on error,
        implicit 'need-data' consumes the next record."""
        events = []
        for rec in records:
            self.feed_record(rec)
            for _ in range(max_pumps):
                carry, a = self.pump()
                if carry == 0:
                    events.append("msg")
                    continue
                if a == 0:
                    break               # record exhausted -> next record
                events.append(("err", a))
                return events
            else:
                raise RuntimeError("pump livelock (no progress)")
        return events

    def transcript(self) -> bytes:
        jsr(self.t, self.l["tls_transcript_hash"], timeout=60.0)
        return read_bytes(self.t, self.l["tls_transcript"], 32)

    def hs_ptr(self) -> int:
        p = read_bytes(self.t, TLS_HS_PTR, 2)
        return p[0] | (p[1] << 8)


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

def run_cases(transport, labels):
    rig = Rig(transport, labels)
    passed = failed = 0
    fed_ok = []                 # messages whose bytes should be in transcript

    def check(name, cond, detail=""):
        nonlocal passed, failed
        if cond:
            print(f"  PASS  {name}")
            passed += 1
        else:
            print(f"  FAIL  {name}  {detail}")
            failed += 1

    def check_transcript(name, *msgs):
        expect = hashlib.sha256(b"".join(msgs)).digest()
        got = rig.transcript()
        check(name + " (transcript)", got == expect,
              f"got {got.hex()} want {expect.hex()}")

    # --- 1. single message, wholly in one record (in-place, zero copy) ---
    m1 = hs_msg(HS_EE, b"\x00\x00")
    rig.reset()
    ev = rig.drive([m1])
    check("in-place single EE", ev == ["msg"], f"events={ev}")
    check("in-place dispatch pointer = tls_rec_buf",
          rig.hs_ptr() == labels["tls_rec_buf"],
          f"ptr=${rig.hs_ptr():04X}")
    check_transcript("in-place single EE", m1)

    # --- 2. two messages sharing one record ---
    m2 = hs_msg(HS_EE, b"\x00\x0b\x00\x01\x02")
    rig.reset()
    ev = rig.drive([m1 + m2])
    check("two messages, one record", ev == ["msg", "msg"], f"events={ev}")
    check_transcript("two messages, one record", m1, m2)

    # --- 3. body split across two records (carry path) ---
    m3 = hs_msg(HS_EE, bytes(range(40)))
    rig.reset()
    ev = rig.drive([m3[:14], m3[14:]])
    check("body split across records", ev == ["msg"], f"events={ev}")
    check("carry dispatch pointer = df_carry_buf",
          rig.hs_ptr() == labels["df_carry_buf"],
          f"ptr=${rig.hs_ptr():04X}")
    check_transcript("body split across records", m3)

    # --- 4. header split across two records ---
    rig.reset()
    ev = rig.drive([m3[:2], m3[2:]])
    check("header split across records", ev == ["msg"], f"events={ev}")
    check_transcript("header split across records", m3)

    # --- 5. record boundary exactly after the header ---
    rig.reset()
    ev = rig.drive([m3[:4], m3[4:]])
    check("boundary at header end", ev == ["msg"], f"events={ev}")
    check_transcript("boundary at header end", m3)

    # --- 6. split server Finished, correct verify_data ---
    # The pre-Finished transcript is sha256(m1): the deframer snapshots
    # it when the Finished header completes, so tls_verify_finished must
    # accept a verify_data computed over exactly that.
    write_bytes(transport, labels["tls_s_hs_secret"], SECRET)
    pre = hashlib.sha256(m1).digest()
    fin_good = hs_msg(HS_FIN, finished_verify_data(SECRET, pre))
    rig.reset()
    ev = rig.drive([m1, fin_good[:20], fin_good[20:]])
    check("split Finished accepted (per-message transcript)",
          ev == ["msg", "msg"], f"events={ev}")
    check_transcript("split Finished accepted", m1, fin_good)

    # --- 6b. same Finished sharing one record with EE (in-place) ---
    rig.reset()
    ev = rig.drive([m1 + fin_good])
    check("EE+Finished sharing one record", ev == ["msg", "msg"],
          f"events={ev}")

    # --- 7. split server Finished, corrupted verify_data ---
    bad_vd = bytearray(finished_verify_data(SECRET, pre))
    bad_vd[7] ^= 0x40
    fin_bad = hs_msg(HS_FIN, bytes(bad_vd))
    rig.reset()
    ev = rig.drive([m1, fin_bad[:20], fin_bad[20:]])
    check("split Finished REJECTED on bad verify_data",
          ev == ["msg", ("err", ERR_DISPATCH)], f"events={ev}")

    # --- 8. unknown handshake type ---
    rig.reset()
    ev = rig.drive([hs_msg(0x63, b"\x00" * 5)])
    check("unknown handshake type rejected",
          ev == [("err", ERR_TYPE)], f"events={ev}")

    # --- 9. spanning non-Certificate message beyond the carry cap ---
    big = hs_msg(HS_EE, bytes(300))
    rig.reset()
    ev = rig.drive([big[:100], big[100:]])
    check("oversize spanning non-Certificate rejected",
          ev == [("err", ERR_TOO_BIG)], f"events={ev}")

    # =======================================================================
    # W2: streaming Certificate consumer
    # =======================================================================
    leaf_der, pub_x, pub_y = generate_p256_cert()

    def check_pubkey(name):
        got_x = read_bytes(transport, labels["ecdsa_pubkey_x"], 32)
        got_y = read_bytes(transport, labels["ecdsa_pubkey_y"], 32)
        curve = read_bytes(transport, labels["ecdsa_curve_id"], 1)[0]
        check(name + " (pubkey X)", got_x == pub_x,
              f"got {got_x.hex()[:16]}.. want {pub_x.hex()[:16]}..")
        check(name + " (pubkey Y)", got_y == pub_y, "")
        check(name + " (curve id P-256)", curve == 0, f"curve={curve}")

    def clear_pubkey():
        write_bytes(transport, labels["ecdsa_pubkey_x"], b"\xa5" * 32)
        write_bytes(transport, labels["ecdsa_pubkey_y"], b"\xa5" * 32)
        write_bytes(transport, labels["ecdsa_curve_id"], b"\xff")

    # --- 10. Certificate wholly in one record: in-place path unchanged ---
    cm = cert_msg([(leaf_der, b"")])
    if len(cm) <= 548:
        rig.reset()
        clear_pubkey()
        ev = rig.drive([cm])
        check("in-place Certificate", ev == ["msg"], f"events={ev}")
        check("in-place Certificate pointer = tls_rec_buf",
              rig.hs_ptr() == labels["tls_rec_buf"],
              f"ptr=${rig.hs_ptr():04X}")
        check_pubkey("in-place Certificate")
        check_transcript("in-place Certificate", cm)
    else:
        check("in-place Certificate", False,
              f"generated cert msg too large for one record ({len(cm)} B)")

    # --- 11. Certificate chain spanning records (streamed leaf) ---
    # Leaf with real extensions bytes, plus a second (discarded) chain
    # entry — split into 529-byte-ish record chunks like a real MFL=512
    # server, but at a deliberately awkward 150 B to hit more edges.
    chain = cert_msg([(leaf_der, b"\x00\x0b\x00\x01\x04"),
                      (b"\xaa" * 600, b"\x01\x02\x03")])
    rig.reset()
    clear_pubkey()
    write_bytes(transport, labels["cert_buf"], b"\x5a" * 16)  # stale marker
    ev = rig.drive(chunks(chain, 150))
    check("streamed Certificate chain", ev == ["msg"], f"events={ev}")
    check_pubkey("streamed Certificate chain")
    got_leaf = read_bytes(transport, labels["cert_buf"], len(leaf_der))
    check("streamed Certificate leaf staged in cert_buf",
          got_leaf == leaf_der, "cert_buf contents differ")
    got_len = read_bytes(transport, labels["cert_buf_len"], 2)
    check("cert_buf_len set to leaf length",
          struct.unpack("<H", got_len)[0] == len(leaf_der),
          f"len={struct.unpack('<H', got_len)[0]} want {len(leaf_der)}")
    check_transcript("streamed Certificate chain", chain)

    # --- 12. streamed Certificate followed by more messages ---
    # Real tail pattern: ...Certificate spans records, and the record
    # carrying its end also carries the next message (here an EE stand-in).
    combo = chain + m1
    rig.reset()
    clear_pubkey()
    ev = rig.drive(chunks(combo, 200))
    check("streamed Certificate + trailing message",
          ev == ["msg", "msg"], f"events={ev}")
    check_pubkey("streamed Certificate + trailing message")
    check_transcript("streamed Certificate + trailing message", chain, m1)

    # --- 13. leaf larger than cert_buf: explicit error, before any copy ---
    # The cap check fires when the entry length completes, i.e. BEFORE a
    # single cert_data byte is copied — cert_buf must remain untouched.
    # (A sentinel at cert_buf+1536 cannot test this: that address is
    # tls_rec_buf[0] under both cfgs, which the record layer writes
    # legitimately. Watching cert_buf itself is collision-free.)
    big_cert = cert_msg([(b"\xbb" * 1600, b"")])   # wikipedia-sized leaf
    rig.reset()
    write_bytes(transport, labels["cert_buf"], b"\x5a" * 64)
    ev = rig.drive(chunks(big_cert, 300))
    check("oversize leaf rejected (certificate too large)",
          ev == [("err", ERR_CERT_TOO_BIG)], f"events={ev}")
    check("oversize leaf: cert_buf untouched (guard before copy)",
          read_bytes(transport, labels["cert_buf"], 64) == b"\x5a" * 64, "")

    # --- 13b. leaf of exactly 1536 B is still accepted by the cap ---
    # (no EC key inside, so it must fail LATER with CERT_FMT — proving
    # the boundary itself is not rejected)
    edge_cert = cert_msg([(b"\xcc" * 1536, b"")])
    rig.reset()
    ev = rig.drive(chunks(edge_cert, 300))
    check("1536 B leaf passes the cap (fails later on extraction)",
          ev == [("err", ERR_CERT_FMT)], f"events={ev}")

    # --- 14. non-zero certificate_request_context ---
    bad_ctx = bytearray(cert_msg([(leaf_der, b"")]))
    bad_ctx[4] = 0x05             # ctx length byte inside the body
    rig.reset()
    ev = rig.drive(chunks(bytes(bad_ctx), 150))
    check("non-zero request context rejected (streamed)",
          ev == [("err", ERR_CERT_FMT)], f"events={ev}")

    # --- 15. leaf with no EC public key ---
    junk_cert = cert_msg([(b"\xdd" * 200, b"")])
    rig.reset()
    ev = rig.drive(chunks(junk_cert, 80))
    check("junk leaf rejected (no usable key)",
          ev == [("err", ERR_CERT_FMT)], f"events={ev}")

    return passed, failed


def main() -> int:
    os.chdir(PROJECT_ROOT)

    if os.environ.get("C64_SKIP_BUILD"):
        print("\n=== Building (skipped: C64_SKIP_BUILD set) ===")
    else:
        print("\n=== Building (BACKEND=uci — deframer is UCI-only) ===")
        subprocess.run(["make", "clean"], capture_output=True)
        result = subprocess.run(["make", "BACKEND=uci"],
                                capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            return 1
        print("  Build OK")

    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found")
        return 1

    labels = Labels.from_file(LABELS_PATH)
    missing = [n for n in REQUIRED_LABELS if labels.address(n) is None]
    if missing:
        print(f"FATAL: required label(s) not found: {', '.join(missing)}")
        print("(is this an ip65 build? the deframer needs BACKEND=uci)")
        return 1

    print("\n=== Labels ===")
    for name in REQUIRED_LABELS:
        print(f"  {name:<24} = ${labels[name]:04X}")

    print("\n=== Starting VICE ===")
    config = default_vice_config(
        prg_path=PRG_PATH,
        warp=True,
        ntsc=True,
        sound=False,
    )

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"  VICE PID={inst.pid}, port={inst.port}")

        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=180.0, verbose=False)
        if grid is None:
            print("FATAL: Main menu did not appear")
            mgr.release(inst)
            return 1
        print("  Main menu ready")

        install_stub(transport, labels["tls_deframe_pump"])

        print("\n=== tls_deframe ===")
        try:
            passed, failed = run_cases(transport, labels)
        finally:
            mgr.release(inst)

    total = passed + failed
    print("\n" + "=" * 60)
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    if failed == 0:
        print(f"\n  [+] TLS deframe: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] TLS deframe: {failed} TEST(S) FAILED")
    print("=" * 60)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
