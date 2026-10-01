#!/usr/bin/env python3
"""Pin the UCI rigs' post-load image verify (#199).

``tools/uci/_prg_load.load_verified_and_run`` is RUN against a faked
Ultimate64Client whose ``load_prg`` can flip a byte, zero the BASIC head the
way the U64E has been measured doing, or answer $A000+ with the BASIC ROM.
No hardware, no build: the PRG is synthetic, shaped like the real UCI image
(a BASIC SYS stub at $0801, code below $A000, a zero tail to $FDFF).

The property that matters most is the negative one: on an image that does
not verify, nothing is started — ``send_text`` is never called.

    python3 tools/test_prg_load.py
"""

from __future__ import annotations

import ast
import io
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
UCI = REPO / "tools" / "uci"
for p in (str(UCI), str(REPO / "tools")):
    if p not in sys.path:
        sys.path.insert(0, p)

import _prg_load as pl  # noqa: E402

ROM = bytes.fromhex("94e37be3") + b"CBMBASIC" * 4


def make_prg(code_end=0x9FD8, image_end=0xFE00, tail_byte=0):
    """$0801: 10 SYS2061 ; then code bytes to code_end, zeros to image_end."""
    stub = bytes([0x0B, 0x08, 0x0A, 0x00, 0x9E]) + b"2061" + bytes([0, 0, 0])
    code = bytes((i * 7 + 3) & 0xFF or 1 for i in range(code_end - 0x080D))
    tail = bytes(image_end - code_end)
    if tail_byte:
        tail = tail[:-1] + bytes([tail_byte])
    return bytes([0x01, 0x08]) + stub + code + tail


class FakeClient:
    def __init__(self, *, flips=(), zero_head_once=False):
        self.mem = bytearray(0x10000)
        self.mem[0xA000:0xA000 + len(ROM)] = ROM       # BASIC banked in
        self.flips = list(flips)       # per load: offset to flip, or None
        self.zero_head_once = zero_head_once
        self.loads = 0
        self.typed = []
        self.writes = []

    def load_prg(self, prg):
        la = prg[0] | (prg[1] << 8)
        body = prg[2:]
        end = min(la + len(body), 0xA000)          # $A000+ reads as ROM
        self.mem[la:end] = body[:end - la]
        if self.loads < len(self.flips) and self.flips[self.loads] is not None:
            self.mem[la + self.flips[self.loads]] ^= 0x5A
        self.loads += 1
        if self.zero_head_once:
            self.mem[la:la + 2] = b"\0\0"
            self.zero_head_once = False

    def read_mem(self, addr, n):
        return bytes(self.mem[addr:addr + n])

    def write_mem(self, addr, data):
        self.writes.append((addr, bytes(data)))
        self.mem[addr:addr + len(data)] = data

    def send_text(self, text, finish_with_return=True):
        self.typed.append(text)


def run(client, prg, **k):
    return pl.load_verified_and_run(client, prg, clock=lambda: 0.0,
                                    sleep=lambda s: None, out=io.StringIO(),
                                    **k)


def test_clean_load_verifies_and_starts_by_sys() -> None:
    c = FakeClient()
    rep = run(c, make_prg())
    assert c.typed == ["SYS2061"], c.typed
    assert c.loads == 1
    assert rep["verified"] == "$0801-$9FFF", rep
    assert rep["attempts"] == [{"attempt": 1, "ok": True,
                                "first_difference": None}]


def test_a_flipped_byte_is_reloaded_once() -> None:
    c = FakeClient(flips=[0x1234, None])
    rep = run(c, make_prg())
    assert c.loads == 2 and c.typed == ["SYS2061"]
    assert rep["attempts"][0]["first_difference"] == f"${0x0801 + 0x1234:04X}"


def test_a_persistent_flip_starts_nothing() -> None:
    c = FakeClient(flips=[0x2000, 0x2000])
    try:
        run(c, make_prg())
    except pl.PrgLoadError as exc:
        assert f"${0x0801 + 0x2000:04X}" in str(exc), exc
    else:
        raise AssertionError("a corrupt image was accepted")
    assert c.typed == [], "a run was started on an image known to be wrong"
    assert c.loads == 2, "exactly one retry"


def test_a_flip_in_the_last_verified_byte_is_seen() -> None:
    prg = make_prg()
    c = FakeClient(flips=[0x9FFF - 0x0801] * 2)
    try:
        run(c, prg)
    except pl.PrgLoadError:
        pass
    else:
        raise AssertionError("$9FFF is inside the verified span")


def test_the_rom_shadow_is_not_compared() -> None:
    """$A000+ reads as ROM before the program banks it out; a verify that
    compared it would fail every healthy load."""
    c = FakeClient()
    run(c, make_prg())
    assert bytes(c.mem[0xA000:0xA004]) == ROM[:4]
    assert c.typed == ["SYS2061"]


def test_a_non_zero_tail_refuses_the_image() -> None:
    try:
        pl.image_span(make_prg(tail_byte=0xEA))
    except pl.PrgLoadError as exc:
        assert "$FDFF" in str(exc), exc
    else:
        raise AssertionError("code past $A000 would go unverified silently")


def test_a_zeroed_head_is_rewritten_then_verified() -> None:
    c = FakeClient(zero_head_once=True)
    run(c, make_prg())
    assert (0x0801, bytes([0x0B, 0x08])) in c.writes, c.writes
    assert c.typed == ["SYS2061"] and c.loads == 1


def test_no_sys_stub_is_refused() -> None:
    prg = bytes([0x00, 0xC0]) + bytes(64)
    c = FakeClient()
    try:
        run(c, prg)
    except pl.PrgLoadError:
        pass
    else:
        raise AssertionError("a PRG with no SYS stub was started")
    assert c.loads == 0 and c.typed == []


def test_no_uci_rig_starts_a_prg_unverified() -> None:
    """Every tools/uci script that boots the image goes through the verify:
    no bare run_prg (load-and-run, nothing read back) remains."""
    bad = []
    for p in sorted(UCI.glob("*.py")):
        if p.name == "_prg_load.py":
            continue
        for n in ast.walk(ast.parse(p.read_text())):
            if (isinstance(n, ast.Call)
                    and getattr(n.func, "attr", "") in ("run_prg",
                                                        "run_prg_file")):
                bad.append(f"{p.name}:{n.lineno}")
    assert not bad, f"#199: unverified PRG starts remain: {bad}"


def main() -> int:
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failed += 1
            print(f"  FAIL  {name}: {exc}")
        except Exception as exc:                              # noqa: BLE001
            failed += 1
            print(f"  ERROR {name}: {type(exc).__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    from _skip_policy import verdict
    return verdict(len(tests) - failed, failed,
                   certifies="the UCI rigs' post-load verify (#199)")


if __name__ == "__main__":
    sys.exit(main())
