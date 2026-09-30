#!/usr/bin/env python3
"""Unit tests for the trust-store format mirror, tools/trust_store.py (#155).

Pure logic: no build, no VICE, no hardware. What runs on the C64 is
src/net/uci/trust_store.s; tools/test_trust_store_6502.py drives THAT
against this mirror. This file pins the mirror itself: the checksum, the
generation compare, torn-slot selection and every fail-closed case of
S3 §4.3, plus constant parity with src/trust_store.inc.

Runs under pytest, or standalone: python3 tools/test_trust_store_format.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import trust_store as ts  # noqa: E402
from _skip_policy import verdict  # noqa: E402

SPKI_A = bytes(range(32))
SPKI_B = bytes(range(100, 132))


def rec(host, spki=SPKI_A, **kw):
    return ts.Record.for_host(host, spki, **kw)


def store(gen, *hosts):
    return ts.encode(gen, [rec(h) for h in hosts])


# --- constants --------------------------------------------------------------

def test_constants_match_the_inc():
    inc = ts.parse_inc()
    for py, asm in ts.INC_NAMES.items():
        assert asm in inc, f"{asm} missing from src/trust_store.inc"
        assert getattr(ts, py) == inc[asm], f"{py}={getattr(ts, py)} but {asm}={inc[asm]}"
    assert bytes(inc[f"TS_MAGIC_{i}"] for i in range(4)) == ts.MAGIC
    assert inc["TS_FILE_MAX"] == ts.FILE_MAX == 2064
    offs = (inc["TS_REC_KEY"], inc["TS_REC_SPKI"], inc["TS_REC_MODE"],
            inc["TS_REC_FLAGS"], inc["TS_REC_USES"], inc["TS_REC_DISPLAY"])
    assert offs == (0, 16, 48, 49, 50, 52)


# --- host key ---------------------------------------------------------------

def test_host_key_is_truncated_sha256_of_the_lowercased_host():
    import hashlib
    assert ts.host_key("GitHub.COM") == hashlib.sha256(b"github.com").digest()[:16]
    assert ts.host_key("github.com") == ts.host_key("GITHUB.COM")
    assert ts.host_key("github.com") != ts.host_key("github.co")


def test_host_key_lowers_only_ascii_letters():
    # '@' (0x40) and '[' (0x5B) sit either side of A-Z; OR-ing 0x20 into
    # them would be a bug the 6502's range check exists to avoid.
    assert ts.lower_ascii(b"@AZ[") == b"@az["


# --- records and files ------------------------------------------------------

def test_record_roundtrip_and_layout():
    r = rec("example.com", SPKI_B, mode=ts.MODE_ACCEPTED, flags=5, uses=0x1234)
    raw = r.pack()
    assert len(raw) == 64
    assert raw[48] == ts.MODE_ACCEPTED and raw[49] == 5
    assert raw[50:52] == b"\x34\x12"
    assert raw[52:64] == b"example.com\x00"
    assert ts.Record.unpack(raw).pack() == raw


def test_file_roundtrip():
    data = store(7, "a.example", "b.example")
    assert len(data) == 8 + 2 * 64 + 8
    assert data[:4] == b"C6TS" and data[4] == 1 and data[5:7] == b"\x07\x00"
    gen, recs = ts.decode(data)
    assert gen == 7 and [r.key for r in recs] == [ts.host_key("a.example"),
                                                  ts.host_key("b.example")]


def test_empty_record_list_is_a_valid_store():
    assert ts.decode(ts.encode(3, [])) == (3, [])


def test_checksum_catches_any_single_byte_flip():
    data = store(1, "a.example")
    for i in range(len(data)):
        bad = bytearray(data)
        bad[i] ^= 0x01
        try:
            ts.decode(bytes(bad))
        except ts.StoreError:
            continue
        raise AssertionError(f"flip at {i} accepted")


def test_checksum_failure_code():
    bad = bytearray(store(1, "a.example"))
    bad[20] ^= 0xFF                        # inside the record
    assert ts.slot_result(bytes(bad)) == ts.R_CHECKSUM


def test_format_failures():
    good = store(1, "a.example")
    assert ts.slot_result(b"") == ts.R_FORMAT                   # torn to 0 B
    assert ts.slot_result(good[:15]) == ts.R_FORMAT            # < header+trailer
    assert ts.slot_result(good[:-1]) == ts.R_FORMAT            # size != N
    assert ts.slot_result(good + b"\x00") == ts.R_FORMAT
    assert ts.slot_result(b"XXXX" + good[4:]) == ts.R_FORMAT   # magic
    big = bytearray(ts.encode(1, []))
    big[7] = 255                                               # N lies
    assert ts.slot_result(bytes(big)) == ts.R_FORMAT


def test_unknown_version_fails_closed_before_the_checksum():
    bad = bytearray(store(1, "a.example"))
    bad[4] = 2
    assert ts.slot_result(bytes(bad)) == ts.R_VERSION


def test_oversize_file_is_format_as_on_the_c64():
    data = ts.encode(1, [rec(f"h{i}.example") for i in range(32)])
    assert len(data) == ts.FILE_MAX and ts.slot_result(data) == ts.SLOT_OK
    assert ts.slot_result(data + bytes(100)) == ts.R_FORMAT


# --- generation compare -----------------------------------------------------

def test_serial_newer():
    assert ts.serial_newer(1, 2) is True
    assert ts.serial_newer(2, 1) is False
    assert ts.serial_newer(0xFFFF, 0) is True          # the wrap
    assert ts.serial_newer(0, 0xFFFF) is False
    assert ts.serial_newer(0xFFFE, 0x0003) is True
    assert ts.serial_newer(5, 5) is None
    assert ts.serial_newer(0, 0x8000) is None          # undefined in RFC 1982
    assert ts.serial_newer(0x8000, 0) is None
    assert ts.serial_newer(0, 0x7FFF) is True


# --- selection: torn slots and fail-closed ----------------------------------

def test_both_absent_is_empty():
    sel = ts.select(None, None)
    assert sel.state == ts.ST_EMPTY and sel.slot == 1 and sel.gen == 0


def test_newer_valid_slot_wins_either_way_round():
    a, b = store(4, "old.example"), store(5, "new.example")
    assert (ts.select(a, b).slot, ts.select(a, b).gen) == (1, 5)
    assert (ts.select(b, a).slot, ts.select(b, a).gen) == (0, 5)


def test_generation_wrap_selects_the_wrapped_slot():
    sel = ts.select(store(0xFFFF, "x.example"), store(0, "x.example"))
    assert sel.state == ts.ST_VALID and sel.slot == 1 and sel.gen == 0


def test_generation_tie_fails_closed():
    sel = ts.select(store(9, "a.example"), store(9, "b.example"))
    assert (sel.state, sel.reason) == (ts.ST_FAIL, ts.R_TIE)
    sel = ts.select(store(0, "a.example"), store(0x8000, "b.example"))
    assert (sel.state, sel.reason) == (ts.ST_FAIL, ts.R_TIE)


def test_torn_write_falls_back_to_the_older_slot():
    # A save opens the target for write, which empties it; a reset before
    # close leaves it empty or partial. The other slot is untouched.
    older = store(6, "a.example")
    for torn in (b"", store(7, "a.example", "b.example")[:40]):
        for sel, slot in ((ts.select(older, torn), 0), (ts.select(torn, older), 1)):
            assert sel.state == ts.ST_VALID and sel.slot == slot and sel.gen == 6
            assert sel.slot_st[slot ^ 1] == ts.R_FORMAT


def test_one_valid_slot_beside_an_open_failure_is_valid():
    good = store(2, "a.example")
    for code in (ts.R_DOS, ts.R_IO, ts.R_NOPATH):
        assert ts.select(good, code).state == ts.ST_VALID


def test_fail_closed_cases():
    corrupt = bytearray(store(1, "a.example"))
    corrupt[-1] ^= 1
    corrupt = bytes(corrupt)
    cases = {
        (corrupt, corrupt): ts.R_CHECKSUM,          # checksum on both slots
        (corrupt, None): ts.R_CHECKSUM,             # S3 §4.3: only 62+62 is EMPTY
        (None, corrupt): ts.R_CHECKSUM,
        (ts.R_NOPATH, ts.R_NOPATH): ts.R_NOPATH,    # no medium
        (None, ts.R_DOS): ts.R_DOS,                 # a DOS error other than 62
        (ts.R_IO, None): ts.R_IO,
    }
    vers = bytearray(store(1, "a.example"))
    vers[4] = 9
    cases[(bytes(vers), None)] = ts.R_VERSION       # unknown version
    for (a, b), reason in cases.items():
        sel = ts.select(a, b)
        assert (sel.state, sel.reason) == (ts.ST_FAIL, reason), (a, b, sel)


# --- lookup and save --------------------------------------------------------

def test_lookup_only_in_a_valid_store():
    sel = ts.select(store(1, "a.example"), None)
    assert ts.lookup(sel, "A.EXAMPLE").key == ts.host_key("a.example")
    assert ts.lookup(sel, "b.example") is None
    assert ts.lookup(ts.select(None, None), "a.example") is None


def test_save_to_an_empty_store_writes_slot_a_generation_1():
    target, data = ts.save(None, None, "a.example", rec("ignored", SPKI_B))
    assert target == 0
    gen, recs = ts.decode(data)
    assert gen == 1 and recs[0].key == ts.host_key("a.example")
    assert recs[0].spki == SPKI_B


def test_save_ping_pongs_and_replaces_in_place():
    a = store(1, "a.example", "b.example")
    target, b = ts.save(a, None, "b.example", rec("b.example", SPKI_B))
    assert target == 1
    gen, recs = ts.decode(b)
    assert gen == 2 and len(recs) == 2 and recs[1].spki == SPKI_B
    target, a2 = ts.save(a, b, "c.example", rec("c.example"))
    assert target == 0 and ts.decode(a2)[0] == 3 and len(ts.decode(a2)[1]) == 3


def test_save_wraps_the_generation():
    target, data = ts.save(store(0xFFFF, "a.example"), None, "a.example", rec("a.example"))
    assert ts.decode(data)[0] == 0
    assert ts.select(store(0xFFFF, "a.example"), data).slot == 1


def test_save_refuses_a_full_store_and_a_failed_load():
    full = ts.encode(1, [rec(f"h{i}.example") for i in range(32)])
    try:
        ts.save(full, None, "new.example", rec("new.example"))
        raise AssertionError("33rd record accepted")
    except ts.StoreError as e:
        assert e.code == ts.R_FULL
    ts.save(full, None, "h3.example", rec("h3.example", SPKI_B))   # replace: fine
    try:
        ts.save(ts.R_NOPATH, None, "a.example", rec("a.example"))
        raise AssertionError("saved over a FAIL store")
    except ts.StoreError as e:
        assert e.code == ts.R_NOTREADY


def _main():
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL {name}: {e!r}")
    return verdict(len(tests) - failed, failed,
                   certifies="the trust-store format mirror (tools/trust_store.py)")


if __name__ == "__main__":
    sys.exit(_main())
