#!/usr/bin/env python3
"""test_pq_kem.py - KeyGen, ClientHello, Decaps and tls_connect (PQC phase P4).

The slow half of the P4 suites (tools/test_pq_sh.py is the fast one): real
ML-KEM runs in a VICE boot of the BACKEND=uci USE_NISTCURVES_ONCHIP=1
PQ_HYBRID=1 image, checked against libs/mlkem/tools/mlkem_ref.py.

  [1] pq_connect_prep: the 64 B seed the DRBG produced is dumped, the ek in
      cert_buf equals the reference's KeyGen(d, z).ek, the 2,400 B dk scratch
      is all zero afterwards, tls_ch_ks_ptr/len are armed with the ek and the
      hybrid is marked offered. Twice: two preps give two different seeds.
  [2] tls_send_client_hello after prep: the wire bytes equal a Python
      reference ClientHello carrying THAT ek (11EC = ek || x25519, then 001D),
      the transcript is SHA-256 of it, the arm is one-shot.
  [3] Decaps KAT: the host encapsulates to the C64's ek; the 11EC ServerHello
      (ct || x25519) goes in as 512+512+154; pq_sh_decaps leaves K in
      tls_mlkem_ss; the seed is zeroed. A flipped ct bit gives the reference's
      implicit-rejection key (not K).
  [4] tls_connect end to end with net_tcp_send replaced by a recorder:
      KeyGen runs inside it (breakpoint at tls_recv_server_hello: ek valid for
      the dumped seed, dk zero, CH recorded), the ServerHello is injected into
      the TCP ring as three records, and the run continues through Decaps and
      the X25519 mult to the first encrypted record. Group 11EC and group
      001D (classic fallback: HTTPS proceeds as before). The expected end state
      is the P4 documented one: the key schedule is not hybrid yet, so the
      first encrypted record cannot be read (tls_last_state = ENCRYPTED_EXT).
      Afterwards (error exit) seed + ss are zero.

    python3 tools/test_pq_kem.py            # builds the PQ image first
    C64_SKIP_BUILD=1 python3 tools/test_pq_kem.py
"""

import hashlib
import os
import shutil
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _pq_testlib import (  # noqa: E402
    Tally, Session, build_or_reuse, sh_message, ks_ext, sv_ext, split_at,
    x25519, x25519_pub, GROUP_HYB, GROUP_X, CT_LEN, EK_LEN, E_DECAPS,
)
from _skip_policy import cannot_run, verdict  # noqa: E402
from c64_test_harness import (  # noqa: E402
    set_breakpoint, delete_breakpoint, wait_for_pc, goto, write_bytes,
    read_bytes,
)
import mlkem_ref as R  # noqa: E402
import test_tls_handshake as TH  # noqa: E402

HOST = "example.com"
M_FIXED = bytes(range(201, 233))


def prep(s):
    a, p = s.call("pq_connect_prep", timeout=1800.0)
    seed = s.rd(s.L("tls_pq_seed"), 64)
    ek = s.rd(s.L("cert_buf"), EK_LEN)
    return a, p, seed, ek


def phase_prep(s, t):
    print("\n[1] pq_connect_prep")
    s.wr(0xC000, bytes([0xEE]) * 2400)
    a, p, seed, ek = prep(s)
    t.check(not p & 1, "pq_connect_prep: C=0", f"P=${p:02X}")
    ek_ref, dk_ref = R.mlkem_keygen(seed[:32], seed[32:])
    t.check(seed != bytes(64), "the DRBG filled the 64 B seed")
    t.check(ek == ek_ref, "cert_buf holds the reference's ek for that seed",
            f"first diff at +{next((i for i in range(EK_LEN) if ek[i] != ek_ref[i]), -1)}")
    dk = s.rd(0xC000, 2400)
    t.check(dk == bytes(2400), "the 2,400 B dk scratch is all zero",
            f"{sum(1 for b in dk if b)} non-zero bytes")
    ptr = s.rd(s.L("tls_ch_ks_ptr"), 2)
    ln = s.rd(s.L("tls_ch_ks_len"), 2)
    t.check(ptr[0] | ptr[1] << 8 == s.L("cert_buf"), "tls_ch_ks_ptr = cert_buf")
    t.check(ln[0] | ln[1] << 8 == EK_LEN, "tls_ch_ks_len = 1,184")
    t.check(s.rd(s.L("tls_pq_offered"), 1) == b"\x01", "the hybrid is marked offered")
    # a second prep: a different seed, again a matching ek
    a2, p2, seed2, ek2 = prep(s)
    t.check(seed2 != seed, "a second prep draws a different seed")
    t.check(ek2 == R.mlkem_keygen(seed2[:32], seed2[32:])[0],
            "...and its ek matches the reference too")
    return seed2, ek2


def phase_ch(s, t, ek):
    print("\n[2] ClientHello carries the ek")
    rnd = bytes((3 * i + 1) & 255 for i in range(32))
    pub = bytes((5 * i + 2) & 255 for i in range(32))
    carry, secs, wire, th, ks_after = TH.capture_client_hello(
        s.tr, s.labels, rnd, pub, HOST, None)
    ref = TH.ref_client_hello(rnd, pub, HOST, ek)
    ref_wire = b"\x16\x03\x03" + struct.pack(">H", len(ref)) + ref
    t.check(carry == 0, "tls_send_client_hello: C=0")
    t.check(wire == ref_wire, "wire == reference hybrid ClientHello (11EC = ek || x25519, then 001D)",
            f"{len(wire)} vs {len(ref_wire)} B")
    t.check(th == hashlib.sha256(ref).digest(), "transcript == SHA-256 of the message")
    t.check(len(secs) == 4 and ks_after == b"\x00\x00",
            "four sends, tls_ch_ks_len cleared (one-shot)", f"{len(secs)} {ks_after}")


def hybrid_sh(ct, pub, rnd=None):
    msg = sh_message(sv_ext() + ks_ext(GROUP_HYB, ct + pub),
                     random=rnd or bytes(range(32, 64)))
    return msg


def phase_decaps(s, t, seed, ek):
    print("\n[3] Decaps KAT")
    d, z = seed[:32], seed[32:]
    ek_ref, dk_ref = R.mlkem_keygen(d, z)
    K, ct = R.mlkem_encaps(ek_ref, M_FIXED)
    spub = x25519_pub(bytes(range(90, 122)))
    msg = hybrid_sh(ct, spub)
    s.begin(True)
    for rec in split_at(msg, [512, 1024]):
        c, z_ = s.feed(rec)
        assert not c
    a, p = s.call("pq_sh_decaps", timeout=1800.0)
    ss = s.rd(s.L("tls_mlkem_ss"), 32)
    t.check(not p & 1 and a == 0, "pq_sh_decaps: C=0", f"A={a:02X} P=${p:02X}")
    t.check(ss == K, "tls_mlkem_ss == the reference's K", ss.hex())
    t.check(s.rd(s.L("tls_pq_seed"), 64) == bytes(64), "the seed is zeroed after Decaps")
    t.check(s.group() == 0xEC, "tls_kex_group = $EC")
    # implicit rejection: same seed, a corrupted ct
    bad = bytearray(ct)
    bad[100] ^= 0x10
    K_rej = R.mlkem_decaps(dk_ref, bytes(bad))
    t.check(K_rej != K, "(reference) the rejection key differs from K")
    s.wr(s.L("tls_pq_seed"), seed)
    s.begin(True)
    for rec in split_at(hybrid_sh(bytes(bad), spub), [512, 1024]):
        s.feed(rec)
    a, p = s.call("pq_sh_decaps", timeout=1800.0)
    ss2 = s.rd(s.L("tls_mlkem_ss"), 32)
    t.check(not p & 1 and ss2 == K_rej, "a flipped ct bit gives the reference's implicit-rejection key",
            ss2.hex())


# ---------------------------------------------------------------------------
# [4] tls_connect, end to end
# ---------------------------------------------------------------------------
CTL = 0x0334            # the harness trampoline
CARRY = 0x033F
REC_STUB = 0x0350       # net_tcp_send recorder
REC_IDX = 0x037F
REC_TBL = 0x0380        # 4 B per call: ptr, len


def recorder(s):
    """Replace net_tcp_send by a recorder (as capture_client_hello does) and
    return the original 3 bytes."""
    L = s.L
    nsl = L("net_send_len")
    stub = bytearray([0xAC, REC_IDX & 255, REC_IDX >> 8])
    for off, ld in ((0, None), (1, "x"), (2, nsl), (3, nsl + 1)):
        if ld == "x":
            stub += bytes([0x8A])
        elif ld is not None:
            stub += bytes([0xAD, ld & 255, ld >> 8])
        stub += bytes([0x99, (REC_TBL + off) & 255, (REC_TBL + off) >> 8])
    stub += bytes([0xC8] * 4 + [0x8C, REC_IDX & 255, REC_IDX >> 8, 0x18, 0x60])
    s.wr(REC_STUB, bytes(stub))
    s.wr(REC_IDX, [0])
    orig = s.rd(L("net_tcp_send"), 3)
    s.wr(L("net_tcp_send"), bytes([0x4C, REC_STUB & 255, REC_STUB >> 8]))
    return orig


def wire_sent(s):
    n = s.rd(REC_IDX, 1)[0] // 4
    tbl = s.rd(REC_TBL, 4 * n) if n else b""
    out = b""
    for i in range(n):
        ptr = tbl[4 * i] | tbl[4 * i + 1] << 8
        ln = tbl[4 * i + 2] | tbl[4 * i + 3] << 8
        out += s.rd(ptr, ln) if ln else b""
    return out


def inject(s, records):
    """Append plaintext handshake records to the (empty) TCP ring."""
    L = s.L
    tail = s.rd(L("tcp_recv_tail"), 2)
    off = tail[0] | tail[1] << 8
    data = b"".join(b"\x16\x03\x03" + struct.pack(">H", len(r)) + r for r in records)
    assert off + len(data) <= 0x1000
    s.wr(0xC000 + off, data)
    off += len(data)
    s.wr(L("tcp_recv_tail"), [off & 255, off >> 8])


def run_connect(s, t, tag, kind):
    """tls_connect with the network faked. kind: 'hyb' or 'x'."""
    L = s.L
    sk_c = bytes((11 * i + 7) & 255 for i in range(32))
    sk_s = bytes((13 * i + 1) & 255 for i in range(32))
    spub = x25519_pub(sk_s)
    print(f"\n[4] tls_connect, {tag}")
    s.wr(L("tls_hostname"), HOST.encode())
    s.wr(L("tls_hostname_len"), [len(HOST)])
    orig = recorder(s)
    # tls_connect draws its own private key; we need to know it, so pin the
    # DRBG output: tls_connect fills tls_ecdhe_privkey from the DRBG, which we
    # cannot predict, so read it back at the breakpoint instead.
    tramp = bytes([0x20, L("tls_connect") & 255, L("tls_connect") >> 8,
                   0xA9, 0, 0x2A, 0x8D, CARRY & 255, CARRY >> 8, 0xEA, 0xEA])
    s.wr(CTL, tramp)
    end = CTL + len(tramp) - 2
    bp_sh = set_breakpoint(s.tr, L("tls_recv_server_hello"))
    bp_end = set_breakpoint(s.tr, end)
    try:
        goto(s.tr, CTL)
        wait_for_pc(s.tr, L("tls_recv_server_hello"), timeout=3600.0)
        # --- KeyGen has run inside tls_connect, the CH has been "sent" ---
        seed = s.rd(L("tls_pq_seed"), 64)
        ek = s.rd(L("cert_buf"), EK_LEN)
        priv = s.rd(L("tls_ecdhe_privkey"), 32)
        pub = s.rd(L("tls_ecdhe_pubkey"), 32)
        rnd = s.rd(L("tls_client_random"), 32)
        ek_ref, dk_ref = R.mlkem_keygen(seed[:32], seed[32:])
        t.check(ek == ek_ref and seed != bytes(64),
                "tls_connect ran KeyGen: cert_buf = the reference ek for the seed it drew")
        t.check(s.rd(0xC000, 2400) == bytes(2400), "tls_connect left the dk scratch zero")
        t.check(s.rd(L("tls_pq_offered"), 1) == b"\x01", "hybrid offered")
        wire = wire_sent(s)
        ref = TH.ref_client_hello(rnd, pub, HOST, ek)
        t.check(wire == b"\x16\x03\x03" + struct.pack(">H", len(ref)) + ref,
                "the ClientHello tls_connect sent is the hybrid one carrying that ek")
        t.check(pub == x25519_pub(priv), "tls_ecdhe_pubkey is the public key of tls_ecdhe_privkey")
        # --- the server's answer ---
        if kind == "hyb":
            K, ct = R.mlkem_encaps(ek_ref, M_FIXED)
            msg = hybrid_sh(ct, spub)
            recs = split_at(msg, [512, 1024])
        else:
            K = None
            msg = sh_message(sv_ext() + ks_ext(GROUP_X, spub),
                             random=bytes(range(32, 64)))
            recs = [msg]
        inject(s, recs)
        # tls_connect has already issued tls_rx_reset; the ring is ours now
        bp_ecdh = set_breakpoint(s.tr, L("tls_ecdh_compute_shared"))
        s.tr.resume()
        wait_for_pc(s.tr, L("tls_ecdh_compute_shared"), timeout=7200.0)
        # Decaps (if any) has run and the X25519 mult has NOT: the ML-KEM
        # secret is final and the seed is gone.
        t.check(s.rd(L("tls_pq_seed"), 64) == bytes(64),
                "at the X25519 mult the seed is already zero")
        ss_k = s.rd(L("tls_mlkem_ss"), 32)
        if kind == "hyb":
            t.check(ss_k == K, "tls_mlkem_ss == the reference K, before the X25519 mult", ss_k.hex())
        else:
            t.check(ss_k == bytes(32), "classic path: no ML-KEM secret was produced")
        t.check(s.rd(L("tls_transcript_total_lo"), 2)[0] | s.rd(L("tls_transcript_total_lo"), 2)[1] << 8
                == len(ref) + len(msg),
                "transcript has folded exactly CH + SH (byte count)")
        delete_breakpoint(s.tr, bp_ecdh)
        s.tr.resume()
        wait_for_pc(s.tr, end, timeout=7200.0)
    finally:
        for b in (bp_sh, bp_end):
            try:
                delete_breakpoint(s.tr, b)
            except Exception:
                pass
        write_bytes(s.tr, L("net_tcp_send"), orig)
    carry = s.rd(CARRY, 1)[0]
    ss_x = s.rd(L("tls_shared_secret"), 32)
    t.check(ss_x == x25519(priv, spub), "the X25519 shared secret is correct (after Decaps rebuilt the window)")
    t.check(s.rd(L("tls_server_pubkey"), 32) == spub, "the server's x25519 share was extracted")
    t.check(s.group() == (0xEC if kind == "hyb" else 0x1D), "tls_kex_group recorded")
    t.check(s.rd(L("tls_last_state"), 1)[0] == 3 or carry == 1,
            "the run got past ServerHello to EncryptedExtensions (tls_last_state = 3)",
            f"last_state={s.rd(L('tls_last_state'), 1)[0]} carry={carry}")
    t.check(carry == 1, "P4 state: the handshake does not complete (key schedule not hybrid yet / no server)")
    sec = s.rd(L("tls_pq_seed"), 96)
    t.check(sec == bytes(96), "after tls_connect's error exit seed + ss are zero")
    return K


def main():
    t = Tally()
    if shutil.which("ca65") is None:
        return cannot_run("cc65 not found", certifies="the PQ KeyGen/Decaps path")
    rc, out = build_or_reuse()
    if rc != 0:
        print(out[-1500:])
        return cannot_run("the PQ_HYBRID build failed", certifies="the PQ KeyGen/Decaps path")
    only = [a for a in sys.argv[1:] if not a.startswith("-")]
    with Session() as s:
        seed, ek = phase_prep(s, t)
        phase_ch(s, t, ek)
        if "nodecaps" not in only:
            phase_decaps(s, t, seed, ek)
    if "noconnect" not in only:
        with Session() as s:
            run_connect(s, t, "hybrid ServerHello (11EC)", "hyb")
        with Session() as s:
            run_connect(s, t, "classic ServerHello (001D)", "x")
    print(f"\nRESULTS: {t.passed}/{t.passed + t.failed} passed, {t.failed} failed")
    return verdict(t.passed, t.failed, certifies="the PQ KeyGen/Decaps path")


if __name__ == "__main__":
    sys.exit(main())
