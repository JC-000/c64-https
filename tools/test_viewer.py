#!/usr/bin/env python3
"""test_viewer.py - REU text viewer render tests (Lane G stretch goal).

Exercises the non-interactive `viewer_render_at` entry of src/viewer.s
against a known multi-KB ASCII document blitted into the REU, asserting
the exact 40x25 screen-code content for vectors covering LF handling,
long-line hard wrap (including the wrap-then-LF consume), lowercase
folding, TAB/CR handling, EOF clamping, mid-document offsets, the
total=0 EMPTY screen, and the status line. Also drives the exported
`viewer_scroll_up` helper to verify the backward row-start scan against
a forward-rendered row-start list.

The interactive key loop of `viewer_enter` is a thin dispatch over these
tested primitives and is deliberately NOT driven from VICE.

Build (done automatically unless C64_SKIP_BUILD=1):

    make clean && make BACKEND=uci HTTP_REU_BODY_BASE=196608 \
        VIEWER_TEST_HELPERS=1

(196608 = $03:0000 — inside the 512 KB VICE REU; the production default
base is $10:0000, outside it.)

Usage:
    python3 tools/test_viewer.py [--verbose]

Requires: Python 3.10+, c64_test_harness, VICE x64sc.
"""

import os
import subprocess
import sys

from c64_test_harness import (
    Labels,
    ViceInstanceManager,
    read_bytes,
    write_bytes,
    jsr,
    wait_for_text,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _vice_helpers import default_vice_config

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

REU_BASE = 196608  # $03:0000 — must match the make line above

SCREEN = 0x0400
COLS = 40
CONTENT_ROWS = 24
BLIT_BUF = 0xC000
BLIT_CHUNK = 4096

REQUIRED_LABELS = [
    "viewer_render_at",
    "viewer_offset",
    "viewer_test_blit",
    "viewer_blit_off",
    "viewer_scroll_up",
    "http_body_total",
]

VERBOSE = False


# ---------------------------------------------------------------------------
# Python model of the renderer (must mirror src/viewer.s exactly)
# ---------------------------------------------------------------------------

def conv(b):
    """ASCII byte -> screen code, mirroring conv_ascii."""
    if b < 0x20:
        return 0x20
    if b < 0x40:
        return b
    if b < 0x60:
        return b - 0x40
    if b == 0x60:
        return 0x20
    if 0x61 <= b <= 0x7A:
        return b - 0x60
    return 0x20


def txt_codes(s):
    """Uppercase-glyph screen codes for an ASCII string (A-Z -> 1-26)."""
    out = []
    for ch in s:
        o = ord(ch)
        if 0x41 <= o <= 0x5A:
            out.append(o - 0x40)
        else:
            out.append(o)
    return out


def render_model(doc, total, off):
    """Render 24 content rows from offset. Returns (rows, row_starts).

    row_starts has 25 entries: the 24 row starts plus the next-screen top.
    """
    rows = []
    starts = []
    cur = off
    for _ in range(CONTENT_ROWS):
        starts.append(cur)
        row = []
        while True:
            if cur >= total:
                row += [0x20] * (COLS - len(row))
                break
            b = doc[cur]
            if b == 0x0A:
                cur += 1
                row += [0x20] * (COLS - len(row))
                break
            if b == 0x0D:
                cur += 1
                continue
            row.append(0x20 if b == 0x09 else conv(b))
            cur += 1
            if len(row) == COLS:
                # hard wrap: consume a single immediately-following LF
                if cur < total and doc[cur] == 0x0A:
                    cur += 1
                break
        rows.append(row)
    starts.append(cur)
    return rows, starts


def hexdig(d):
    return 0x30 + d if d < 10 else d - 9  # screen '0'-'9' / A-F ($01-$06)


def hex24(v):
    out = []
    for byte in ((v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF):
        out.append(hexdig(byte >> 4))
        out.append(hexdig(byte & 0x0F))
    return out


def status_model(off, total):
    row = hex24(off) + [0x2F] + hex24(total) + txt_codes("  Q=QUIT")
    row += [0x20] * (COLS - len(row))
    return row


def expected_screen(doc, total, off):
    """Full 25x40 expected screen-code grid."""
    if total == 0:
        grid = [txt_codes("EMPTY") + [0x20] * (COLS - 5)]
        grid += [[0x20] * COLS for _ in range(CONTENT_ROWS)]
        return grid
    rows, _ = render_model(doc, total, off)
    return [status_model(off, total)] + rows


def forward_row_starts(doc, total):
    """Every display-row start offset from document start to EOF."""
    starts = []
    cur = 0
    while cur < total:
        starts.append(cur)
        col = 0
        while True:
            if cur >= total:
                break
            b = doc[cur]
            if b == 0x0A:
                cur += 1
                break
            if b == 0x0D:
                cur += 1
                continue
            cur += 1
            col += 1
            if col == COLS:
                if cur < total and doc[cur] == 0x0A:
                    cur += 1
                break
    return starts


# ---------------------------------------------------------------------------
# Test document
# ---------------------------------------------------------------------------

def build_doc():
    parts = []
    parts.append(b"Hello, C64 viewer!\n")                       # folding + punct
    parts.append(b"lowercase line with words\n")                # folding
    parts.append(b"\n")                                          # empty line
    parts.append(b"A" * 40 + b"\n")                              # exactly 40 + LF (consumed)
    parts.append(b"B" * 41 + b"\n")                              # wraps to 2 rows
    parts.append(b"tab\there and CR\r ignored\n")                # TAB, CR
    parts.append(b"odd bytes: `{|}~ \x7f\x80\xff end\n")         # -> spaces
    parts.append(b"digits 0123456789 and SYMBOLS @[]^_\n")
    # a long run of numbered lines to give mid-document offsets substance
    for i in range(120):
        parts.append(("line %04d: the quick brown fox jumps over the lazy dog\n" % i).encode())
    parts.append(b"C" * 100 + b"\n")                             # 3-row wrap
    parts.append(b"last line without trailing newline")
    return b"".join(parts)


# ---------------------------------------------------------------------------
# Harness plumbing
# ---------------------------------------------------------------------------

def write24(transport, addr, value):
    write_bytes(transport, addr, bytes([value & 0xFF, (value >> 8) & 0xFF,
                                        (value >> 16) & 0xFF]))


def upload_doc(transport, labels, doc):
    for off in range(0, len(doc), BLIT_CHUNK):
        chunk = doc[off:off + BLIT_CHUNK]
        chunk += b"\x00" * (BLIT_CHUNK - len(chunk))
        write_bytes(transport, BLIT_BUF, chunk)
        write24(transport, labels["viewer_blit_off"], off)
        jsr(transport, labels["viewer_test_blit"], timeout=30.0)


def read_screen(transport):
    data = read_bytes(transport, SCREEN, 1000)
    return [list(data[r * COLS:(r + 1) * COLS]) for r in range(25)]


def dump_row(row):
    return " ".join("%02x" % b for b in row)


def check_screen(name, transport, labels, doc, total, off):
    print(f"\n--- {name} (offset {off}, total {total}) ---")
    write24(transport, labels["http_body_total"], total)
    write24(transport, labels["viewer_offset"], off)
    jsr(transport, labels["viewer_render_at"], timeout=60.0)
    got = read_screen(transport)
    want = expected_screen(doc, total, off)
    for r in range(25):
        if got[r] != want[r]:
            print(f"  FAIL: row {r} mismatch")
            print(f"    want: {dump_row(want[r])}")
            print(f"    got:  {dump_row(got[r])}")
            return False
    print("  PASS: all 25 rows match")
    return True


def check_scroll_up(name, transport, labels, expect_from_to):
    """expect_from_to: list of (top, expected_new_top)."""
    print(f"\n--- {name} ---")
    ok = True
    for top, want in expect_from_to:
        write24(transport, labels["viewer_offset"], top)
        jsr(transport, labels["viewer_scroll_up"], timeout=30.0)
        got_b = read_bytes(transport, labels["viewer_offset"], 3)
        got = got_b[0] | (got_b[1] << 8) | (got_b[2] << 16)
        if got == want:
            print(f"  PASS: scroll_up({top}) -> {got}")
        else:
            print(f"  FAIL: scroll_up({top}) -> {got}, expected {want}")
            ok = False
    return ok


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global VERBOSE
    VERBOSE = "--verbose" in sys.argv
    os.chdir(PROJECT_ROOT)

    if os.environ.get("C64_SKIP_BUILD"):
        print("=== Building (skipped: C64_SKIP_BUILD set) ===")
    else:
        print("=== Building (BACKEND=uci, test REU base, viewer helpers) ===")
        subprocess.run(["make", "clean"], capture_output=True)
        result = subprocess.run(
            ["make", "BACKEND=uci", f"HTTP_REU_BODY_BASE={REU_BASE}",
             "VIEWER_TEST_HELPERS=1"],
            capture_output=True, text=True)
        if result.returncode != 0:
            print(f"  Build failed:\n{result.stderr[-2000:]}")
            sys.exit(1)
        print("  Build OK")

    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found")
        sys.exit(1)

    labels = Labels.from_file(LABELS_PATH)
    for name in REQUIRED_LABELS:
        if labels.address(name) is None:
            print(f"FATAL: required label '{name}' not found "
                  f"(build with VIEWER_TEST_HELPERS=1)")
            sys.exit(1)

    doc = build_doc()
    total = len(doc)
    print(f"  Document: {total} bytes")
    starts = forward_row_starts(doc, total)

    config = default_vice_config(
        prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    passed = failed = 0

    def tally(ok):
        nonlocal passed, failed
        if ok:
            passed += 1
        else:
            failed += 1

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"  VICE PID={inst.pid}, port={inst.port}")

        print("  Waiting for main menu...")
        if wait_for_text(transport, "Q=QUIT", timeout=120.0, verbose=False) is None:
            print("FATAL: main menu did not appear")
            sys.exit(1)

        print("  Uploading document to REU...")
        upload_doc(transport, labels, doc)

        # 1: document start — LF handling, empty line, lowercase folding,
        #    TAB, CR, odd-byte squashing, exact-40 wrap + LF consume
        tally(check_screen("Test 1: top of document", transport, labels,
                           doc, total, 0))

        # 2: mid-document offset (a genuine forward row start)
        mid = starts[len(starts) // 2]
        tally(check_screen("Test 2: mid-document row start", transport,
                           labels, doc, total, mid))

        # 3: arbitrary (non-row-start) offset — render_at takes any offset
        tally(check_screen("Test 3: arbitrary offset", transport, labels,
                           doc, total, 1234))

        # 4: EOF clamp — fewer than 24 rows remain, rest blank-filled
        tally(check_screen("Test 4: EOF clamp", transport, labels,
                           doc, total, starts[-3]))

        # 5: offset exactly at total — fully blank content
        tally(check_screen("Test 5: offset == total", transport, labels,
                           doc, total, total))

        # 6: empty document
        tally(check_screen("Test 6: EMPTY document", transport, labels,
                           doc, 0, 0))

        # restore total for the scroll tests
        write24(transport, labels["http_body_total"], total)

        # 7: scroll-up — for a sample of forward row starts, one step up
        #    must land on the preceding forward row start; top 0 stays.
        sample_idx = [1, 2, 3, 4, 5, 8, len(starts) // 2, len(starts) - 1]
        vectors = [(0, 0)]
        for i in sample_idx:
            vectors.append((starts[i], starts[i - 1]))
        tally(check_scroll_up("Test 7: scroll-up row-start scan",
                              transport, labels, vectors))

        mgr.release(inst)

    total_t = passed + failed
    print("\n" + "=" * 60)
    print(f"  Passed: {passed}/{total_t}")
    print(f"  Failed: {failed}/{total_t}")
    if failed == 0:
        print(f"\n  [+] viewer: ALL {total_t} TESTS PASSED")
    else:
        print(f"\n  [-] viewer: {failed} TEST(S) FAILED")
    print("=" * 60)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
