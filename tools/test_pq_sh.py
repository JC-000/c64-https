#!/usr/bin/env python3
"""test_pq_sh.py - the PQ_HYBRID streaming ServerHello reader (PQC phase P4).

Fast: no ML-KEM and no X25519 run (the slow half is tools/test_pq_kem.py).
A VICE boot of the BACKEND=uci USE_NISTCURVES_ONCHIP=1 PQ_HYBRID=1 image; each
case writes records straight into the record buffer and runs pq_sh_feed (the
routine tls_recv_server_hello calls once per plaintext record), so the
fragmentation is exactly the test's and nothing depends on the TCP ring.

  [1] accepted: hybrid 11EC in 512+512+154, with the key_share first, in
      1-byte and 1-2-3-byte fragments, split at every offset of the header and
      extension area and around both ct boundaries; classic 001D in one
      record and byte by byte; unknown extensions skipped. For each: the ct
      lands in cert_buf exactly (and not one byte past it), the x25519 share
      in tls_server_pubkey, the random in tls_server_random, tls_kex_group,
      tls_sh_err = 0, and the transcript hash == SHA-256 of the whole message
      (every byte folded once, in order).
  [2] refused, each with its own tls_sh_err and C=1 (see src/constants.inc).
  [3] glue: pq_sh_decaps on the classic path zeroes the seed without running
      ML-KEM; pq_sh_decaps / pq_connect_prep with the ML-KEM image refused
      return C=1 with SH_ERR_PQ_DECAPS / SH_ERR_PQ_KEYGEN and the dk scratch
      zero; pq_secrets_zero.

    python3 tools/test_pq_sh.py            # builds the PQ image first
    C64_SKIP_BUILD=1 python3 tools/test_pq_sh.py
"""

import hashlib
import os
import random
import shutil
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _pq_testlib import (  # noqa: E402
    Tally, Session, build_or_reuse, require_pq_image, sh_message, ks_ext, sv_ext, ext, split_at,
    chunks, HRR_MAGIC, GROUP_HYB, GROUP_X, CT_LEN,
    E_HRR, E_RECTYPE, E_HDR, E_FIXED, E_EXTLEN, E_VERSION, E_GROUP, E_KSLEN,
    E_TRAIL, E_MISSING, E_DECAPS, E_KEYGEN, E_EXT,
)
from _skip_policy import cannot_run, verdict  # noqa: E402

RNG = random.Random(0x50514832)
SENT = 0xA5


def rb(n):
    return bytes(RNG.getrandbits(8) for _ in range(n))


CT = rb(CT_LEN)
PUB = rb(32)
SRND = bytes(RNG.getrandbits(8) for _ in range(32))
HYB_KEY = CT + PUB


def hybrid_msg(**kw):
    exts = kw.pop("exts", None)
    if exts is None:
        exts = sv_ext() + ks_ext(GROUP_HYB, HYB_KEY)
    return sh_message(exts, random=SRND, **kw)


def classic_msg(exts=None, **kw):
    if exts is None:
        exts = sv_ext() + ks_ext(GROUP_X, PUB)
    return sh_message(exts, random=SRND, **kw)


def run_ok(s, t, tag, msg, records, kind, offered=True, unknown_exts=False):
    """Feed *records*, expect acceptance after the last one and not before."""
    s.begin(offered)
    s.wr(s.L("cert_buf"), bytes([SENT]) * 2048)
    ok = True
    for i, rec in enumerate(records):
        c, z = s.feed(rec)
        last = i == len(records) - 1
        if c or z != (1 if last else 0):
            t.check(False, f"{tag}: record {i}/{len(records)} C={c} Z={z} "
                    f"err={s.err()}")
            return False
    th = s.transcript()
    ct = s.rd(s.L("cert_buf"), 2048)
    pub = s.rd(s.L("tls_server_pubkey"), 32)
    srnd = s.rd(s.L("tls_server_random"), 32)
    probs = []
    if s.err() != 0:
        probs.append(f"tls_sh_err={s.err()}")
    if th != hashlib.sha256(msg).digest():
        probs.append("transcript != sha256(message)")
    if srnd != SRND:
        probs.append("server_random")
    if kind == "hyb":
        if s.group() != 0xEC:
            probs.append(f"group ${s.group():02X}")
        if ct[:CT_LEN] != CT:
            probs.append("ct bytes")
        if ct[CT_LEN:] != bytes([SENT]) * (2048 - CT_LEN):
            probs.append("cert_buf written past the ct")
    else:
        if s.group() != 0x1D:
            probs.append(f"group ${s.group():02X}")
        if ct != bytes([SENT]) * 2048:
            probs.append("cert_buf touched by a classic share")
    if pub != PUB:
        probs.append("x25519 share")
    return t.check(not probs, tag, "; ".join(probs))


def run_err(s, t, tag, records, code, offered=True, rtypes=None):
    """Feed records until one is refused; the refusal must carry *code*."""
    s.begin(offered)
    for i, rec in enumerate(records):
        rt = rtypes[i] if rtypes else 0x16
        c, z = s.feed(rec, rt)
        if c:
            return t.check(s.err() == code,
                           f"{tag} -> refused at record {i} with ${s.err():02X}"
                           f" (want ${code:02X})")
        if z:
            break
    return t.check(False, f"{tag}: not refused (want ${code:02X})",
                   f"err=${s.err():02X}")


def accepted(s, t):
    print("\n[1] accepted shapes")
    msg = hybrid_msg()
    assert len(msg) == 1178, len(msg)
    run_ok(s, t, "11EC, 512+512+154", msg, split_at(msg, [512, 1024]), "hyb")
    msg2 = hybrid_msg(exts=ks_ext(GROUP_HYB, HYB_KEY) + sv_ext())
    run_ok(s, t, "11EC, key_share before supported_versions", msg2,
           split_at(msg2, [512, 1024]), "hyb")
    # pathological: 1-byte records over the whole header/extension prefix and
    # into the ct, then 1-2-3-5-8 growth, then big records
    recs = chunks(msg[:140], [1]) + chunks(msg[140:300], [2, 3, 5, 8]) \
        + split_at(msg[300:], [])
    run_ok(s, t, "11EC, 1-byte records over the first 140 bytes", msg,
           recs, "hyb")
    # every cut inside the fixed prefix + extension headers (offsets 1..60)
    for c in range(1, 61):
        run_ok(s, t, f"11EC, cut at {c}", msg, split_at(msg, [c, 512]), "hyb")
    ct_start = msg.index(CT)
    ct_end = ct_start + CT_LEN
    for c in (ct_start - 2, ct_start - 1, ct_start, ct_start + 1,
              ct_end - 1, ct_end, ct_end + 1, ct_end + 31, len(msg) - 1):
        run_ok(s, t, f"11EC, cut at {c} (ct ${ct_start}..{ct_end})", msg,
               split_at(msg, [c]), "hyb")
    # the boundary between records falling exactly on the key_share header
    for w in (4, 5, 6, 7, 8, 9, 10):
        run_ok(s, t, f"11EC, three cuts {w} bytes either side of the ks header",
               msg, split_at(msg, [ct_start - w, ct_start - w + 3, ct_start + w]),
               "hyb")
    cm = classic_msg()
    run_ok(s, t, "001D, one record", cm, [cm], "x")
    run_ok(s, t, "001D, byte by byte", cm, chunks(cm, [1]), "x")
    run_ok(s, t, "001D with the hybrid NOT offered", cm, [cm], "x", offered=False)
    for v in (b"\x03\x02", b"\x03\x04", b"\x00\x00"):
        cv = classic_msg(version=v)
        run_ok(s, t, f"001D with legacy_version {v.hex()} (ignored, RFC 8446 4.2.1)", cv, [cv], "x")
    hv = hybrid_msg(version=b"\x03\x01")
    run_ok(s, t, "11EC with legacy_version 0301", hv, split_at(hv, [512, 1024]), "hyb")


def refused(s, t):
    print("\n[2] refusals")
    big = hybrid_msg()
    run_err(s, t, "HRR random", [sh_message(sv_ext() + ks_ext(GROUP_X, PUB),
                                            random=HRR_MAGIC)], E_HRR)
    # a HelloRetryRequest-shaped body: selected_group only, 2-byte key_share
    hrr = sh_message(sv_ext() + ext(0x33, struct.pack(">H", GROUP_X)),
                     random=HRR_MAGIC)
    run_err(s, t, "HRR (real shape)", [hrr], E_HRR)
    # key_share lengths
    for n in (1119, 1121, 0, 1088, 1152, 864, 1376):
        key = (CT + PUB + bytes(300))[:n]
        run_err(s, t, f"11EC key_exchange of {n} B",
                split_at(sh_message(sv_ext() + ks_ext(GROUP_HYB, key),
                                    random=SRND), [512, 1024]), E_KSLEN)
    run_err(s, t, "11EC when the hybrid was NOT offered",
            split_at(big, [512, 1024]), E_GROUP, offered=False)
    run_err(s, t, "unknown group 0x0017 (secp256r1, 65 B)",
            [sh_message(sv_ext() + ks_ext(0x0017, rb(65)), random=SRND)], E_GROUP)
    run_err(s, t, "unknown group 0x6399", [classic_msg(
        exts=sv_ext() + ks_ext(0x6399, PUB))], E_GROUP)
    run_err(s, t, "group 0x021D (hi byte set)", [classic_msg(
        exts=sv_ext() + ks_ext(0x021D, PUB))], E_GROUP)
    run_err(s, t, "group 0x11ED (hybrid look-alike, low byte)", split_at(classic_msg(
        exts=sv_ext() + ks_ext(0x11ED, HYB_KEY)), [512, 1024]), E_GROUP)
    run_err(s, t, "group 0x12EC (hybrid look-alike)", split_at(classic_msg(
        exts=sv_ext() + ks_ext(0x12EC, HYB_KEY)), [512, 1024]), E_GROUP)
    for n in (31, 33, 64, 0, 288):
        run_err(s, t, f"001D with a {n} B share", [classic_msg(
            exts=sv_ext() + ks_ext(GROUP_X, rb(n)))], E_KSLEN)
    # key_share whose own key length disagrees with its extension length
    bad = ext(0x33, struct.pack(">HH", GROUP_X, 32) + rb(33))
    run_err(s, t, "key_share: key length + 4 != extension length",
            [classic_msg(exts=sv_ext() + bad)], E_KSLEN)
    bad = ext(0x33, struct.pack(">HH", GROUP_X, 33) + rb(32))
    run_err(s, t, "key_share: key length claims more than the extension holds",
            [classic_msg(exts=sv_ext() + bad)], E_KSLEN)
    run_err(s, t, "key_share extension shorter than its 4-byte header",
            [classic_msg(exts=sv_ext() + ext(0x33, b"\x00\x1d\x00"))], E_KSLEN)
    # fixed fields
    run_err(s, t, "cipher suite 0x1301", [classic_msg(suite=b"\x13\x01")], E_FIXED)
    run_err(s, t, "cipher suite 0x1302", [classic_msg(suite=b"\x13\x02")], E_FIXED)
    run_err(s, t, "cipher suite 0x0303 (low byte right, high byte wrong)",
            [classic_msg(suite=b"\x03\x03")], E_FIXED)
    run_err(s, t, "cipher suite 0x1203", [classic_msg(suite=b"\x12\x03")], E_FIXED)
    # a 3-byte session id crafted so the bytes after it parse as a valid
    # suite/compression/extensions_length: only the session-id length check
    # itself can refuse it
    ex = sv_ext() + ks_ext(GROUP_X, PUB)
    crafted = sh_message(ex, random=SRND, sid=b"\x13\x03\x00", suite=struct.pack(">H", 3 + len(ex)))
    run_err(s, t, "session id echo of 3 B that mimics the fixed fields", [crafted], E_FIXED)
    # extensions we did not request (RFC 8446 4.2): every type but the two
    for typ, data, name in ((0x1234, b"\x01" * 7, "unknown 0x1234"),
                            (0x0029, b"\x00\x00", "pre_shared_key 0x0029"),
                            (0x002C, b"\x00\x01\x02", "cookie 0x002C"),
                            (0x000A, b"", "supported_groups, empty"),
                            (0xFF01, b"\x00", "renegotiation_info"),
                            (0x0000, b"", "server_name, empty")):
        for order, ex in (("before", ext(typ, data) + sv_ext() + ks_ext(GROUP_X, PUB)),
                          ("between", sv_ext() + ext(typ, data) + ks_ext(GROUP_X, PUB)),
                          ("after", sv_ext() + ks_ext(GROUP_X, PUB) + ext(typ, data))):
            run_err(s, t, f"{name} {order} the required extensions", [classic_msg(exts=ex)], E_EXT)
    run_err(s, t, "unsolicited extension after a fragmented hybrid key_share",
            split_at(hybrid_msg(exts=sv_ext() + ks_ext(GROUP_HYB, HYB_KEY) + ext(0x0029, b"\x00\x00")),
                     [512, 1024]), E_EXT)
    run_err(s, t, "session id echo of 32 B", [classic_msg(sid=bytes(32))], E_FIXED)
    run_err(s, t, "compression method 1", [classic_msg(comp=b"\x01")], E_FIXED)
    # required extensions
    run_err(s, t, "no supported_versions", [classic_msg(
        exts=ks_ext(GROUP_X, PUB))], E_MISSING)
    run_err(s, t, "no key_share", [classic_msg(exts=sv_ext())], E_MISSING)
    run_err(s, t, "no extensions at all", [classic_msg(exts=b"")], E_MISSING)
    run_err(s, t, "key_share look-alike 0x0133 is an unsolicited extension, not a key_share", [classic_msg(
        exts=sv_ext() + ext(0x0133, struct.pack(">HH", GROUP_X, 32) + PUB))],
        E_EXT)
    run_err(s, t, "supported_versions look-alike 0x012B is unsolicited", [classic_msg(
        exts=ext(0x012B, b"\x03\x04") + ks_ext(GROUP_X, PUB))], E_EXT)
    run_err(s, t, "duplicate key_share", [classic_msg(
        exts=sv_ext() + ks_ext(GROUP_X, PUB) + ks_ext(GROUP_X, PUB))], E_KSLEN)
    run_err(s, t, "duplicate supported_versions", [classic_msg(
        exts=sv_ext() + sv_ext() + ks_ext(GROUP_X, PUB))], E_VERSION)
    run_err(s, t, "supported_versions 0x0303", [classic_msg(
        exts=sv_ext(b"\x03\x03") + ks_ext(GROUP_X, PUB))], E_VERSION)
    run_err(s, t, "supported_versions of 3 B", [classic_msg(
        exts=ext(0x2B, b"\x03\x04\x00") + ks_ext(GROUP_X, PUB))], E_VERSION)
    run_err(s, t, "supported_versions of 0 B", [classic_msg(
        exts=ext(0x2B, b"") + ks_ext(GROUP_X, PUB))], E_VERSION)
    # message header
    cm = classic_msg()
    run_err(s, t, "handshake type 8 (EncryptedExtensions) first",
            [classic_msg(hdr_type=8)], E_HDR)
    run_err(s, t, "handshake type 1", [classic_msg(hdr_type=1)], E_HDR)
    run_err(s, t, "24-bit length with a non-zero top byte",
            [classic_msg(len_top=1)], E_HDR)
    run_err(s, t, "message length 0x0600 (past the cap)",
            [classic_msg(msg_len=0x0600)], E_HDR)
    run_err(s, t, "message length 39 (shorter than the fixed fields)",
            [classic_msg(msg_len=39)], E_HDR)
    run_err(s, t, "message length 0", [classic_msg(msg_len=0)], E_HDR)
    # extension framing
    run_err(s, t, "extensions_length one too long",
            [classic_msg(ext_len=len(sv_ext() + ks_ext(GROUP_X, PUB)) + 1)], E_EXTLEN)
    run_err(s, t, "extensions_length one too short",
            [classic_msg(ext_len=len(sv_ext() + ks_ext(GROUP_X, PUB)) - 1)], E_EXTLEN)
    run_err(s, t, "extension data longer than what is left", [classic_msg(
        exts=sv_ext() + ks_ext(GROUP_X, PUB) + struct.pack(">HH", 0x1234, 100)
        + b"\x00" * 3)], E_EXTLEN)
    run_err(s, t, "2 stray bytes where an extension header should be",
            [classic_msg(exts=sv_ext() + ks_ext(GROUP_X, PUB) + b"\x00\x00")],
            E_EXTLEN)
    run_err(s, t, "key_share ext length one more than the bytes present",
            [classic_msg(exts=sv_ext() + struct.pack(">HH", 0x33, 37)
                         + struct.pack(">HH", GROUP_X, 32) + PUB)], E_EXTLEN)
    # bytes after the message
    run_err(s, t, "one trailing byte in the last record", [cm + b"\x00"], E_TRAIL)
    run_err(s, t, "a whole EncryptedExtensions header after the SH, same record",
            [cm + bytes([8, 0, 0, 2, 0, 0])], E_TRAIL)
    hm = hybrid_msg()
    run_err(s, t, "trailing byte after a fragmented hybrid SH",
            split_at(hm + b"\x16", [512, 1024]), E_TRAIL)
    # a further record after completion
    s.begin(True)
    c, z = s.feed(cm)
    c2, _ = s.feed(b"\x00")
    t.check(c == 0 and z == 1 and c2 == 1 and s.err() == E_TRAIL,
            "a record after the message is complete is refused (TRAIL)")
    # record layer
    run_err(s, t, "first record is application data (23)", [cm], E_RECTYPE,
            rtypes=[23])
    run_err(s, t, "first record is an alert (21)", [cm], E_RECTYPE, rtypes=[21])
    run_err(s, t, "alert record in the middle of the message",
            split_at(hm, [300, 700]), E_RECTYPE, rtypes=[0x16, 21, 0x16])
    run_err(s, t, "handshake type after a CCS-typed record (20) mid-message",
            split_at(hm, [300]), E_RECTYPE, rtypes=[0x16, 20])
    s.begin(True)
    s.wr(s.L("tls_rec_len"), [0, 0])
    s.wr(s.L("tls_rec_type"), [0x16])
    a, p = s.call("pq_sh_feed")
    t.check((p & 1) == 1 and s.err() == E_RECTYPE,
            "a zero-length handshake record is refused")
    s.begin(True)
    s.feed(hm[:100])
    s.wr(s.L("tls_rec_len"), [0, 0])
    a, p = s.call("pq_sh_feed")
    t.check((p & 1) == 1 and s.err() == E_RECTYPE,
            "a zero-length record mid-message is refused")


def glue(s, t):
    print("\n[3] glue")
    L = s.L
    # pq_sh_init resets the recorded group: a refusal after a success leaves none
    cm0 = classic_msg()
    run_ok(s, t, "(setup) 001D accepted, group recorded", cm0, [cm0], "x")
    s.begin(True)
    c, z = s.feed(sh_message(sv_ext() + ks_ext(0x0017, rb(65)), random=SRND))
    t.check(c == 1 and s.group() == 0, "a refusal after a success leaves tls_kex_group reset",
            f"group=${s.group():02X}")
    # classic path: no ML-KEM, seed scrubbed, ss untouched
    s.wr(L("tls_pq_seed"), bytes([0x77]) * 64)
    s.wr(L("tls_mlkem_ss"), bytes([0x66]) * 32)
    s.wr(L("tls_kex_group"), [0x1D])
    a, p = s.call("pq_sh_decaps")
    t.check(not p & 1 and a is not None, "classic path: C=0")
    t.check(s.rd(L("tls_pq_seed"), 64) == bytes(64),
            "classic path: the seed is zeroed")
    t.check(s.rd(L("tls_mlkem_ss"), 32) == bytes([0x66]) * 32,
            "classic path: the ML-KEM secret is not touched")
    # Decaps refused (image not resident): C=1, SH_ERR_PQ_DECAPS, nothing ran
    s.wr(L("tls_pq_seed"), bytes([0x77]) * 64)
    s.wr(L("tls_kex_group"), [0xEC])
    saved = s.rd(L("mlkem_copied"), 1)
    s.wr(L("mlkem_copied"), [0])
    a, p = s.call("pq_sh_decaps")
    t.check(p & 1 and s.err() == E_DECAPS,
            "Decaps refused by the wrapper: C=1, SH_ERR_PQ_DECAPS",
            f"P=${p:02X} err={s.err()}")
    t.check(s.rd(L("tls_pq_seed"), 64) == bytes([0x77]) * 64,
            "refused Decaps leaves the seed for tls_connect's error exit")
    # pq_secrets_zero clears seed + ss
    s.wr(L("tls_mlkem_ss"), bytes([0x66]) * 32)
    s.call("pq_secrets_zero")
    t.check(s.rd(L("tls_pq_seed"), 96) == bytes(96),
            "pq_secrets_zero zeroes the seed and the ML-KEM secret")
    # KeyGen refused: C=1, SH_ERR_PQ_KEYGEN, dk scratch zero, nothing armed
    dk = 0xC000                      # mlkem_dk_scratch = tcp_recv_buf
    s.wr(L("tls_mlkem_ss"), bytes([0x66]) * 32)
    s.wr(L("tls_pq_seed"), bytes([0x77]) * 64)
    s.wr(dk, bytes([0xEE]) * 2400)
    s.wr(dk + 2400, bytes([0xEE]) * 16)
    s.wr(L("tls_ch_ks_len"), [0, 0])
    s.wr(L("tls_pq_offered"), [1])
    a, p = s.call("pq_connect_prep")
    t.check(p & 1 and s.err() == E_KEYGEN,
            "KeyGen refused by the wrapper: C=1, SH_ERR_PQ_KEYGEN",
            f"P=${p:02X} err={s.err()}")
    t.check(s.rd(dk, 2400) == bytes(2400),
            "the 2,400 B dk scratch is zero even when KeyGen was refused")
    t.check(s.rd(dk + 2400, 16) == bytes([0xEE]) * 16,
            "...and the zeroing stops at 2,400 B")
    t.check(s.rd(L("tls_mlkem_ss"), 32) == bytes(32),
            "the next connection's prep scrubs the previous tls_mlkem_ss")
    t.check(s.rd(L("tls_pq_seed"), 64) != bytes([0x77]) * 64,
            "...and replaces the previous seed")
    t.check(s.rd(L("tls_ch_ks_len"), 2) == b"\x00\x00",
            "a refused KeyGen arms nothing")
    t.check(s.rd(L("tls_pq_offered"), 1) == b"\x00",
            "a refused KeyGen leaves the hybrid not offered")
    s.wr(L("mlkem_copied"), saved)


def scrub(s, t):
    print("\n[4] 'Q' scrub (session_scrub) covers the PQ secrets")
    L = s.L
    s.wr(L("tls_pq_seed"), bytes([0x5A]) * 64)
    s.wr(L("tls_mlkem_ss"), bytes([0x5B]) * 32)
    s.call("session_scrub", timeout=300.0)
    t.check(s.rd(L("tls_pq_seed"), 96) == bytes(96),
            "session_scrub zeroes tls_pq_seed and tls_mlkem_ss")


def scrub_wrapper(s, t):
    print("\n[5] pq_mlkem_scrub")
    L = s.L
    win = L("mul38_lo_tab")
    assert win == 0xB100
    s.ram_wr(0xD000, bytes([0xEE]) * 4096)
    s.wr(win - 1, b"\xEE")
    s.wr(win, bytes([0xEE]) * 0xB00)
    s.wr(0xBC00, b"\xEE")
    for iflag in (1, 0):        # sei first: a leaked $01 with I clear would livelock the next IRQ
        a, p, port = s.call_port("pq_mlkem_scrub", iflag, timeout=60.0)
        ok = t.check(port & 7 == 6, f"$01 restored (BASIC out, KERNAL and I/O in) after a scrub entered with I={iflag}",
                     f"$01=${port:02X}")
        t.check((p >> 2) & 1 == iflag, f"the I flag is restored: entered with I={iflag}",
                f"P=${p:02X}")
        if not ok:
            break
    t.check(s.ram_rd(0xD000, 4096) == bytes(4096), "the 4 KB polynomial area ($D000) is zero")
    t.check(s.rd(win, 0xB00) == bytes(0xB00), "the ML-KEM rest-BSS window ($B100-$BBFF) is zero")
    t.check(s.rd(win - 1, 1) == b"\xEE" and s.rd(0xBC00, 1) == b"\xEE",
            "...and the bytes either side of the window are not touched (sqtab at $BC00)")
    t.check(s.ram_rd(0xD000, 1) == bytes(1) and s.rd(1, 1)[0] & 7 == 6,
            "$01 is back where it was (BASIC out, KERNAL and I/O in)", f"${s.rd(1, 1)[0]:02X}")


def main():
    t = Tally()
    if shutil.which("ca65") is None:
        return cannot_run("cc65 not found", certifies="the PQ ServerHello reader")
    rc, out = build_or_reuse()
    if rc != 0:
        print(out[-1500:])
        return cannot_run("the PQ_HYBRID build failed",
                          certifies="the PQ ServerHello reader")
    why = require_pq_image()
    if why:
        return cannot_run(why, certifies="the PQ ServerHello reader")
    only = [a for a in sys.argv[1:] if not a.startswith("-")]
    with Session() as s:
        if not only or "1" in only:
            accepted(s, t)
        if not only or "2" in only:
            refused(s, t)
        if not only or "3" in only:
            glue(s, t)
        if not only or "4" in only:
            scrub(s, t)
        if not only or "5" in only:
            scrub_wrapper(s, t)
    print(f"\nRESULTS: {t.passed}/{t.passed + t.failed} passed, {t.failed} failed")
    return verdict(t.passed, t.failed, certifies="the PQ ServerHello reader")


if __name__ == "__main__":
    sys.exit(main())
