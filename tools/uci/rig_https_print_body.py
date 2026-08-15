#!/usr/bin/env python3
"""
Issue #28 verification harness: runs the standard HTTPS GET flow but the
injected 6502 stub also calls `print_resp_body` after `http_get`, so the
decrypted response body actually lands on the C64 screen.

Unlike the all-uppercase body used by rig_https_local.py (which could
not detect the ASCII-vs-PETSCII rendering bug of issue #28), this harness
serves a mixed-case body:

    Hello from TLS server v1.

and then asserts the expected screen-code sequence produced by the
ASCII->PETSCII translator path in print_resp_body (strategy B in
src/boot.s: lowercase a-z is uppercase-folded to PETSCII A-Z before
CHROUT, so in the default uppercase/graphics character set the entire
body renders as uppercase letters and punctuation).

The harness also asserts the buggy "graphics-range" screen codes that a
missing translator would produce (screen codes $41..$5A for lowercase
e,l,o,f,... which render as hearts/spades/etc.) do NOT appear at the
body's row.

Reads all environment variables the same way as rig_https_local.py
(U64_HOST, TURBO_MHZ, HTTPS_PORT, ACCEPT_TIMEOUT, SENTINEL_POLL_TIMEOUT,
UCI_DEBUG_DIR, etc.).

Exit code 0 = PASS (http_resp_buf matches ASCII body AND the translated
screen-code sequence is present at the expected row).  Exit 1 = FAIL.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

# Reuse the existing harness's helpers by importing the module as-is.
# We override a narrow slice: the stub-building function and the body.
from tools.uci import rig_https_local as base


# -----------------------------------------------------------------------------
# Mixed-case response body + expected screen-code sequence.
# -----------------------------------------------------------------------------
# Body contains UPPERCASE (H, T, L, S), lowercase (ello, from, erver, v),
# space, digits (1), and punctuation (.) — every band touched by the
# translator's case-fold table.  A pre-fix build (no translator) renders
# lowercase letters as graphics characters; with the translator in place
# all letters land as uppercase screen codes.
BODY_STR = "Hello from TLS server v1."
BODY_BYTES = BODY_STR.encode("ascii")


def _ascii_to_screen_code(b: int) -> int:
    """Mirror src/boot.s ascii_chrout + CHROUT PETSCII->screen-code bias.

    Returns the screen-code byte that the translator+CHROUT would write
    to screen RAM for ASCII byte `b`.  Anything the translator drops is
    represented here as a sentinel (returned as None); dropped bytes are
    not expected to appear in the screen sequence.
    """
    # ascii_chrout behaviour
    if b < 0x20:
        if b == 0x0D or b == 0x0A:
            # CR -> CHROUT($0D); no glyph emitted
            return None
        return None
    if b == 0x7F:
        return None
    if b >= 0x80:
        return None
    if 0x61 <= b <= 0x7A:
        petscii = b - 0x20  # uppercase fold
    elif 0x7B <= b <= 0x7E:
        return None
    else:
        petscii = b         # pass-through ($20-$60)
    # CHROUT PETSCII -> screen-code bias
    if 0x20 <= petscii <= 0x3F:
        return petscii
    if 0x40 <= petscii <= 0x5F:
        return petscii - 0x40
    # (Other bands unreached for our body.)
    return None


EXPECTED_SC = bytes(
    c for c in (_ascii_to_screen_code(b) for b in BODY_BYTES) if c is not None
)


def _build_routine(labels, port):
    """Same as base._build_http_routine but adds a jsr to print_resp_body
    after http_get, so the body actually renders to screen RAM."""
    code = bytearray()

    def emit(*bs):
        code.extend(bs)

    def emit_lda_imm(v):
        emit(0xA9, v & 0xFF)

    def emit_sta_abs(addr):
        emit(0x8D, addr & 0xFF, (addr >> 8) & 0xFF)

    def emit_lda_abs(addr):
        emit(0xAD, addr & 0xFF, (addr >> 8) & 0xFF)

    def emit_jsr(addr):
        emit(0x20, addr & 0xFF, (addr >> 8) & 0xFF)

    def emit_jmp(addr):
        emit(0x4C, addr & 0xFF, (addr >> 8) & 0xFF)

    def emit_progress(step):
        emit_lda_imm(step)
        emit_sta_abs(base.PROGRESS_ADDR)

    http_get         = labels["http_get"]
    http_host_ptr    = labels["http_host_ptr"]
    http_host_len    = labels["http_host_len"]
    http_path_ptr    = labels["http_path_ptr"]
    http_path_len    = labels["http_path_len"]
    http_port        = labels["http_port"]
    net_init         = labels["net_init"]
    tcp_recv_head    = labels["tcp_recv_head"]
    tcp_recv_tail    = labels["tcp_recv_tail"]
    print_resp_body  = labels["print_resp_body"]

    emit_lda_abs(0x0001)
    emit(0x29, 0xFE)
    emit_sta_abs(0x0001)

    emit_lda_imm(0x00)
    emit_sta_abs(base.SENTINEL_ADDR)
    emit_sta_abs(base.PROGRESS_ADDR)
    emit_sta_abs(base.CARRY_FLAG_ADDR)

    emit_progress(0x01)
    emit_jsr(net_init)

    emit_lda_imm(0x00)
    emit_sta_abs(tcp_recv_head)
    emit_sta_abs(tcp_recv_head + 1)
    emit_sta_abs(tcp_recv_tail)
    emit_sta_abs(tcp_recv_tail + 1)

    emit_progress(0x02)

    emit_lda_imm(base.HOST_STR_ADDR & 0xFF)
    emit_sta_abs(http_host_ptr)
    emit_lda_imm((base.HOST_STR_ADDR >> 8) & 0xFF)
    emit_sta_abs(http_host_ptr + 1)

    host_len_patch_offset = len(code) + 1
    emit_lda_imm(0x00)
    emit_sta_abs(http_host_len)

    emit_lda_imm(base.PATH_STR_ADDR & 0xFF)
    emit_sta_abs(http_path_ptr)
    emit_lda_imm((base.PATH_STR_ADDR >> 8) & 0xFF)
    emit_sta_abs(http_path_ptr + 1)

    emit_lda_imm(1)
    emit_sta_abs(http_path_len)

    emit_lda_imm(port & 0xFF)
    emit_sta_abs(http_port)
    emit_lda_imm((port >> 8) & 0xFF)
    emit_sta_abs(http_port + 1)

    emit_progress(0x03)
    emit_jsr(http_get)

    emit(0x08)
    emit(0x68)
    emit_sta_abs(base.CARRY_FLAG_ADDR)

    emit_progress(0x04)

    # Render body on screen so we can observe rendering correctness.
    emit_jsr(print_resp_body)

    emit_lda_imm(base.SENTINEL_VALUE)
    emit_sta_abs(base.SENTINEL_ADDR)

    emit_progress(0x05)

    park = base.ROUTINE_ADDR + len(code)
    emit_jmp(park)

    return bytes(code), host_len_patch_offset


def _scan_screen(data, needle):
    """Return (offset, row, col) or None."""
    idx = data.find(needle)
    if idx < 0:
        return None
    return (idx, idx // 40, idx % 40)


def _has_graphics_range(data: bytes, row_lo: int, row_hi: int) -> list[int]:
    """Return list of (offset, byte) where screen RAM in rows [row_lo, row_hi]
    contains a code in $40-$5E — the graphics / shifted-symbol band that a
    broken (translator-missing) path would write for ASCII lowercase a..z.
    Row is 40 cols wide.  We skip $5F and below-$40 which are legit
    punctuation/uppercase.
    """
    hits = []
    start = row_lo * 40
    end   = min((row_hi + 1) * 40, len(data))
    for off in range(start, end):
        b = data[off]
        if 0x40 <= b <= 0x5E:
            hits.append((off, b))
    return hits


def main():
    # Patch the test body BEFORE anything reads it.
    body_len = len(BODY_BYTES)
    base.EXPECTED_BODY = BODY_STR
    base.HTTP_RESPONSE = (
        b"HTTP/1.0 200 OK\r\n"
        + f"Content-Length: {body_len}\r\n".encode("ascii")
        + b"\r\n"
        + BODY_BYTES
    )

    # Patch the stub builder to also call print_resp_body on success.
    base._build_http_routine = _build_routine

    # Hook into base._decode_screen_ram so we capture the screen bytes
    # DMA'd out by the base test, without rewriting its full main().
    original_decode = base._decode_screen_ram
    captured = {"sc_bytes": None, "hit": None, "screen_text": None}

    def decode_and_capture(data):
        text = original_decode(data)
        captured["screen_text"] = text
        captured["sc_bytes"] = data
        captured["hit"] = _scan_screen(data, EXPECTED_SC)
        return text

    base._decode_screen_ram = decode_and_capture

    rc = base.main()

    print()
    print("=" * 64)
    print("ISSUE #28 — mixed-case body rendering verification")
    print("=" * 64)
    print(f"Body (ASCII)    : {BODY_STR!r}")
    print(f"Body length     : {body_len}")
    print(f"Expected screen-code sequence ({len(EXPECTED_SC)} B):")
    hx = EXPECTED_SC.hex(" ")
    for i in range(0, len(hx), 60):
        print(f"  {hx[i:i+60]}")

    if captured["sc_bytes"] is None:
        print("FAIL: screen RAM never dumped (base test skipped its DMA read)")
        return max(rc, 1)

    sc = captured["sc_bytes"]
    hit = captured["hit"]
    if hit is None:
        print("FAIL: expected screen-code sequence NOT found in $0400-$07E7")
        # Dump the first 200 bytes of screen RAM for diagnostics.
        print("\nscreen RAM $0400-$04C7 (first 200 B), hex by row:")
        for i in range(0, min(200, len(sc)), 40):
            print(f"  row {i // 40:02d}: {sc[i:i + 40].hex()}")
        return 1

    offset, row, col = hit
    print(f"\nPASS: translated screen-code sequence found at offset "
          f"+{offset:04X} (row {row}, col {col})")

    # Additional guard: on the ROW containing the body (and one preceding +
    # trailing row), there must be no PRE-FIX lowercase artefacts.  Pre-fix,
    # lowercase 'e' would write screen code $45 (a graphic char) instead of
    # $05.  After the fix only legit uppercase screen codes $01..$1A and
    # spaces/punctuation appear.  The assertion below fails loudly if any
    # $40-$5E byte shows up near our hit — that range is ONLY reached by
    # a broken path for our body (we have no raw graphics chars by design).
    row_lo = max(0, row - 1)
    row_hi = min(24, row + 1)
    stray = _has_graphics_range(sc, row_lo, row_hi)
    if stray:
        print(f"FAIL: {len(stray)} stray graphics-range byte(s) within rows "
              f"{row_lo}..{row_hi} — translator path appears bypassed")
        for off, b in stray[:20]:
            print(f"  +{off:04X} (row {off // 40}, col {off % 40}): ${b:02X}")
        return 1
    print(f"OK: no graphics-range bytes ($40-$5E) near rows "
          f"{row_lo}..{row_hi}")

    return rc


if __name__ == "__main__":
    sys.exit(main())
