#!/usr/bin/env python3
"""test_http.py — HTTP layer unit tests for c64-https.

Tests http_build_get output format and http_recv_response parser
with canned HTTP response data pre-loaded in the ring buffer.

Usage:
    python3 tools/test_http.py [--seed S] [--verbose]
"""

import os
import random
import struct
import subprocess
import sys
from c64_test_harness import (
    Labels, ViceConfig, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)
from _vice_helpers import default_vice_config

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")


def test_build_get_labels(labels):
    """Verify all required HTTP labels exist."""
    passed = 0
    failed = 0

    required = [
        "http_build_get", "http_recv_response", "http_get_plain",
        "http_host_ptr", "http_host_len", "http_path_ptr", "http_path_len",
        "http_req_buf", "http_req_len", "http_resp_buf", "http_resp_len",
        "http_status", "http_parse_state", "http_hdr_match",
        "http_line_idx", "http_line_buf",
    ]
    for name in required:
        addr = labels.address(name)
        if addr is not None:
            passed += 1
        else:
            print(f"  FAIL: label '{name}' not found")
            failed += 1

    return passed, failed


def test_build_get_basic(transport, labels):
    """Test http_build_get with a known hostname and path."""
    passed = 0
    failed = 0

    build_get = labels.address("http_build_get")
    host_ptr = labels.address("http_host_ptr")
    host_len = labels.address("http_host_len")
    path_ptr = labels.address("http_path_ptr")
    path_len = labels.address("http_path_len")
    req_buf = labels.address("http_req_buf")
    req_len = labels.address("http_req_len")

    if None in (build_get, host_ptr, host_len, path_ptr, path_len, req_buf, req_len):
        print("  FAIL: required labels not found")
        return 0, 1

    # Write test hostname at $C000 and path at $C100
    hostname = b"example.com"
    path = b"/test"
    write_bytes(transport, 0xC000, hostname)
    write_bytes(transport, 0xC100, path)

    # Set host pointer/length
    write_bytes(transport, host_ptr, [0x00, 0xC0])  # $C000 little-endian
    write_bytes(transport, host_len, [len(hostname)])

    # Set path pointer/length
    write_bytes(transport, path_ptr, [0x00, 0xC1])  # $C100 little-endian
    write_bytes(transport, path_len, [len(path)])

    # Call http_build_get
    jsr(transport, build_get)

    # Read the resulting request length
    req_len_bytes = read_bytes(transport, req_len, 2)
    actual_len = req_len_bytes[0] | (req_len_bytes[1] << 8)

    # Read the string constants that ACME actually emitted to know what
    # byte values we should expect (PETSCII vs ASCII depends on ACME config).
    get_verb_addr = labels.address("http_get_verb")
    version_addr = labels.address("http_version")
    host_hdr_addr = labels.address("http_host_hdr")
    conn_hdr_addr = labels.address("http_conn_hdr")
    ua_hdr_addr = labels.address("http_ua_hdr")
    crlf_addr = labels.address("http_crlf")

    # Build expected output by reading the actual constant bytes from VICE
    # This avoids any PETSCII/ASCII confusion — we compare against what
    # the assembler actually produced.
    verb_bytes = read_bytes(transport, get_verb_addr, 4)       # "GET "
    ver_bytes = read_bytes(transport, version_addr, 11)        # " HTTP/1.1\r\n"
    hosthdr_bytes = read_bytes(transport, host_hdr_addr, 6)    # "Host: "
    conn_bytes = read_bytes(transport, conn_hdr_addr, 19)      # "Connection: close\r\n"
    ua_bytes = read_bytes(transport, ua_hdr_addr, 27)          # "User-Agent: ...\r\n"
    crlf_bytes = read_bytes(transport, crlf_addr, 2)           # \r\n

    # The hostname and path are written by us in raw bytes, so they stay as-is.
    expected = (
        verb_bytes +              # "GET "           (4)
        path +                    # "/test"          (5)
        ver_bytes +               # " HTTP/1.1\r\n" (11)
        hosthdr_bytes +           # "Host: "         (6)
        hostname +                # "example.com"    (11)
        crlf_bytes +              # "\r\n"           (2)
        ua_bytes +                # "User-Agent: c64-https/0.1\r\n" (27)
        conn_bytes +              # "Connection: close\r\n" (19)
        crlf_bytes                # "\r\n"           (2)
    )

    expected_len = len(expected)  # should be 87

    # The UA header exists because Wikipedia 403s UA-less requests: assert
    # the emitted line is exactly the honest short UA (raw ASCII).
    if ua_bytes == b"User-Agent: c64-https/0.1\r\n":
        print("  PASS: User-Agent header line emitted as expected")
        passed += 1
    else:
        print(f"  FAIL: User-Agent line = {bytes(ua_bytes)!r}")
        failed += 1

    # Check length
    if actual_len == expected_len:
        print(f"  PASS: request length = {actual_len} (expected {expected_len})")
        passed += 1
    else:
        print(f"  FAIL: request length = {actual_len}, expected {expected_len}")
        failed += 1

    # Read the request buffer and compare byte-by-byte
    actual_data = read_bytes(transport, req_buf, actual_len)
    if actual_data == expected:
        print(f"  PASS: request content matches expected bytes")
        passed += 1
    else:
        print(f"  FAIL: request content mismatch")
        # Show first divergence
        for i in range(min(len(actual_data), len(expected))):
            if actual_data[i] != expected[i]:
                print(f"    First diff at offset {i}: got ${actual_data[i]:02X}, expected ${expected[i]:02X}")
                break
        failed += 1

    return passed, failed


def _load_ring_buffer(transport, labels, data):
    """Load canned data into the TCP receive ring buffer.

    Writes data into tcp_recv_buf starting at offset 0,
    sets tcp_recv_head=0 and tcp_recv_tail=len(data).
    Data must be <= 256 bytes.
    """
    recv_buf = labels.address("tcp_recv_buf")
    recv_head = labels.address("tcp_recv_head")
    recv_tail = labels.address("tcp_recv_tail")
    write_bytes(transport, recv_buf, data)
    write_bytes(transport, recv_head, [0])
    write_bytes(transport, recv_tail, [len(data) & 0xFF])


def _reset_parser(transport, labels):
    """Reset HTTP response parser state to initial values."""
    parse_state = labels.address("http_parse_state")
    line_idx = labels.address("http_line_idx")
    hdr_match = labels.address("http_hdr_match")
    resp_len = labels.address("http_resp_len")
    write_bytes(transport, parse_state, [0])
    write_bytes(transport, line_idx, [0])
    write_bytes(transport, hdr_match, [0])
    write_bytes(transport, resp_len, [0, 0])
    # Ring input mode by default (span tests flip to 1 per span).
    write_bytes(transport, labels.address("http_in_mode"), [0])


# --- span-mode input (the TLS path's input mode) -------------------------
# The TLS path hands each decrypted record to http_recv_response as a
# linear span (http_in_mode=1).  These helpers drive the parser exactly
# that way, one call per "record", which is what lets the tests cover
# headers/chunks spanning many TLS records.

SPAN_SCRATCH = 0xC800   # inside TCP_BUF, above the test scratch at $C000-$C3xx
CARRY_STUB = 0xC300     # carry-latching JSR stub
CARRY_LATCH = 0xC2F0


def _feed_span(transport, labels, data, timeout=30.0):
    """Feed one span to http_recv_response.

    Returns the carry flag after the call: 1 = parser needs more data,
    0 = response complete.
    """
    assert len(data) <= 0x700, "span too large for scratch area"
    write_bytes(transport, SPAN_SCRATCH, data)
    write_bytes(transport, labels.address("http_in_mode"), [1])
    write_bytes(transport, labels.address("http_in_ptr"),
                [SPAN_SCRATCH & 0xFF, SPAN_SCRATCH >> 8])
    write_bytes(transport, labels.address("http_in_len"),
                [len(data) & 0xFF, len(data) >> 8])
    recv = labels.address("http_recv_response")
    stub = bytes([
        0x20, recv & 0xFF, recv >> 8,        # JSR http_recv_response
        0xA9, 0x00,                          # LDA #0
        0x69, 0x00,                          # ADC #0  (A = carry)
        0x8D, CARRY_LATCH & 0xFF, CARRY_LATCH >> 8,  # STA latch
        0x60,                                # RTS
    ])
    write_bytes(transport, CARRY_LATCH, [0xEE])  # poison the latch
    write_bytes(transport, CARRY_STUB, stub)
    jsr(transport, CARRY_STUB, timeout=timeout)
    return read_bytes(transport, CARRY_LATCH, 1)[0]


def _run_span_response(transport, labels, spans):
    """Reset the parser and feed a list of spans.

    Asserts carry=1 after every span except the last.  Returns the carry
    after the final span (0 expected for a cleanly terminated response).
    """
    _reset_parser(transport, labels)
    carry = None
    for i, span in enumerate(spans):
        carry = _feed_span(transport, labels, span)
        if i < len(spans) - 1 and carry != 1:
            return ("early", i, carry)
    return carry


def _check_response(transport, labels, want_status, want_body, prefix=None):
    """Common assertions: status, resp_len, body bytes.

    If prefix is not None, expect resp_len == len(prefix) and the buffer
    to hold prefix (the truncate-at-capacity case); otherwise expect the
    full want_body.
    """
    passed = 0
    failed = 0
    expect = prefix if prefix is not None else want_body

    status_bytes = read_bytes(transport, labels.address("http_status"), 2)
    status = status_bytes[0] | (status_bytes[1] << 8)
    if status == want_status:
        print(f"  PASS: http_status = {status}")
        passed += 1
    else:
        print(f"  FAIL: http_status = {status}, expected {want_status}")
        failed += 1

    resp_len_bytes = read_bytes(transport, labels.address("http_resp_len"), 2)
    resp_len = resp_len_bytes[0] | (resp_len_bytes[1] << 8)
    if resp_len == len(expect):
        print(f"  PASS: http_resp_len = {resp_len}")
        passed += 1
    else:
        print(f"  FAIL: http_resp_len = {resp_len}, expected {len(expect)}")
        failed += 1

    body = read_bytes(transport, labels.address("http_resp_buf"),
                      min(resp_len, 512))
    if body == expect[:512]:
        print(f"  PASS: body matches ({len(expect[:512])} bytes)")
        passed += 1
    else:
        mism = [(i, body[i], expect[i])
                for i in range(min(len(body), len(expect)))
                if body[i] != expect[i]]
        print(f"  FAIL: body mismatch — {len(mism)} byte(s) differ, "
              f"len got {len(body)} vs {len(expect[:512])}")
        for idx, got, exp in mism[:5]:
            print(f"    offset {idx}: got ${got:02X}, expected ${exp:02X}")
        failed += 1
    return passed, failed


def _read_u16(transport, labels, name):
    b = read_bytes(transport, labels.address(name), 2)
    return b[0] | (b[1] << 8)


def _read_u24(transport, labels, name):
    b = read_bytes(transport, labels.address(name), 3)
    return b[0] | (b[1] << 8) | (b[2] << 16)


def _chunked(body, sizes, ext=b""):
    """Encode body as chunked with the given chunk sizes."""
    out = b""
    pos = 0
    for n in sizes:
        out += format(n, "x").encode() + ext + b"\r\n" + body[pos:pos+n] + b"\r\n"
        pos += n
    assert pos == len(body)
    out += b"0\r\n\r\n"
    return out


def test_chunked_basic(transport, labels):
    """Chunked response, everything in one span, lowercase hex sizes."""
    body = b"Hello!!!"
    resp = (b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"5\r\nHello\r\n3\r\n!!!\r\n0\r\n\r\n")
    carry = _run_span_response(transport, labels, [resp])
    if carry != 0:
        print(f"  FAIL: parser did not complete (carry={carry})")
        return 0, 1
    print("  PASS: parser completed on terminal chunk")
    p, f = _check_response(transport, labels, 200, body)
    chunked = read_bytes(transport, labels.address("http_chunked"), 1)[0]
    if chunked == 1:
        print("  PASS: http_chunked flag set")
        p += 1
    else:
        print(f"  FAIL: http_chunked = {chunked}, expected 1")
        f += 1
    return p + 1, f


def test_chunked_multi_record(transport, labels):
    """Chunks + headers split across spans: header name split mid-word,
    chunk data split mid-chunk, uppercase hex size, chunk extension,
    terminal-chunk CRLF split between spans."""
    body = b"0123456789" + bytes(range(0x41, 0x51))   # 10 + 16 = 26 bytes
    wire = (b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Enco")
    wire2 = (b"ding: chunked\r\n"
             b"X-Other: yes\r\n"
             b"\r\n"
             b"A\r\n" + body[:4])
    wire3 = body[4:10] + b"\r\n" + b"10;ext=1\r\n" + body[10:18]
    wire4 = body[18:26] + b"\r\n" + b"0\r\n"
    wire5 = b"\r\n"
    carry = _run_span_response(transport, labels,
                               [wire, wire2, wire3, wire4, wire5])
    if carry != 0:
        print(f"  FAIL: parser did not complete cleanly (result={carry})")
        return 0, 1
    print("  PASS: 5-span chunked response completed on terminal chunk")
    p, f = _check_response(transport, labels, 200, body)
    return p + 1, f


def test_chunked_truncation(transport, labels):
    """Chunked body larger than the 512 B http_resp_buf: the parser must
    fill the buffer, keep consuming/discarding, and still terminate
    cleanly on the terminal chunk with http_resp_len = 512."""
    body = bytes((i * 7 + 3) & 0xFF for i in range(700))
    wire = (b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n" + _chunked(body, [100] * 7))
    # split into ~400-byte spans (multi-record chunks)
    spans = [wire[i:i+400] for i in range(0, len(wire), 400)]
    carry = _run_span_response(transport, labels, spans)
    if carry != 0:
        print(f"  FAIL: parser did not complete cleanly (result={carry})")
        return 0, 1
    print(f"  PASS: {len(spans)}-span oversized chunked response completed")
    p, f = _check_response(transport, labels, 200, body, prefix=body[:512])
    # W4: http_body_total counts every de-chunked payload byte CONSUMED,
    # including the 188 past the 512 B stored cap — never framing.
    total = _read_u24(transport, labels, "http_body_total")
    if total == 700:
        print(f"  PASS: http_body_total = {total} (payload only)")
        p += 1
    else:
        print(f"  FAIL: http_body_total = {total}, expected 700")
        f += 1
    return p + 1, f


def _big_headers(count=24):
    """A >1.5 KB header block: filler headers, several lines longer than
    the 32-byte line buffer, Content-Length-lookalike prefixes, mixed
    case."""
    hdrs = b"HTTP/1.1 200 OK\r\n"
    hdrs += b"Server: test-rig/1.0\r\n"
    # a CSP-style monster line (~200 bytes)
    hdrs += (b"Content-Security-Policy: default-src 'none'; "
             + b"script-src " + b"https://example.invalid " * 6
             + b"; style-src 'unsafe-inline'\r\n")
    # a header whose 31-byte truncated prefix must NOT match Content-Length
    hdrs += b"Content-Length-Hint: not-a-real-header-9999\r\n"
    for i in range(count):
        hdrs += (f"X-Filler-Header-{i:02d}: ".encode()
                 + b"v" * 40 + b"\r\n")
    return hdrs


def test_large_headers_content_length(transport, labels):
    """Header block far larger than http_resp_buf, split across many
    spans, with Content-Length buried mid-block."""
    body = b"Hello"
    hdrs = _big_headers()
    hdrs += b"Content-Length: 5\r\n"
    hdrs += _big_headers(8)[len(b"HTTP/1.1 200 OK\r\n"):]  # more filler after
    wire = hdrs + b"\r\n" + body
    assert len(hdrs) > 1500, f"header block only {len(hdrs)} bytes"
    spans = [wire[i:i+200] for i in range(0, len(wire), 200)]
    carry = _run_span_response(transport, labels, spans)
    if carry != 0:
        print(f"  FAIL: parser did not complete cleanly (result={carry})")
        return 0, 1
    print(f"  PASS: {len(spans)}-span large-header response completed "
          f"({len(hdrs)} header bytes)")
    p, f = _check_response(transport, labels, 200, body)
    return p + 1, f


def test_chunked_large_headers(transport, labels):
    """Chunked + large headers combined — the realistic github.com shape."""
    body = b"<html>chunked page</html>"
    hdrs = _big_headers(16)
    hdrs += b"Transfer-Encoding: chunked\r\n"
    wire = hdrs + b"\r\n" + _chunked(body, [16, 9])
    spans = [wire[i:i+250] for i in range(0, len(wire), 250)]
    carry = _run_span_response(transport, labels, spans)
    if carry != 0:
        print(f"  FAIL: parser did not complete cleanly (result={carry})")
        return 0, 1
    print(f"  PASS: {len(spans)}-span chunked+large-header response completed")
    p, f = _check_response(transport, labels, 200, body)
    return p + 1, f


# --- W4 lane-E vectors: consumed-count termination, 24-bit CL, REU sink ---

def test_identity_oversize_cl(transport, labels):
    """W4 regression (browserleaks.com): identity body > 512 B with
    Content-Length must terminate by CONSUMED count, not stored count.

    Before the fix, http_resp_len froze at the 512 B cap, the
    Content-Length match could never fire, and only connection-close /
    poll-timeout ended the read — a server that holds the connection
    open left http_get never returning."""
    body = bytes((i * 7 + (i >> 8)) & 0xFF for i in range(700))
    wire = b"HTTP/1.1 200 OK\r\nContent-Length: 700\r\n\r\n" + body
    spans = [wire[i:i+400] for i in range(0, len(wire), 400)]
    carry = _run_span_response(transport, labels, spans)
    if carry != 0:
        print(f"  FAIL: parser did not complete (result={carry}) — the "
              "consumed-count Content-Length termination did not fire")
        return 0, 1
    print(f"  PASS: {len(spans)}-span oversized identity/CL response "
          "terminated on consumed-count match")
    p, f = _check_response(transport, labels, 200, body, prefix=body[:512])

    total = _read_u24(transport, labels, "http_body_total")
    if total == 700:
        print(f"  PASS: http_body_total = {total}")
        p += 1
    else:
        print(f"  FAIL: http_body_total = {total}, expected 700")
        f += 1

    in_len = _read_u16(transport, labels, "http_in_len")
    if in_len == 0:
        print("  PASS: span fully consumed (bytes past the cap drained)")
        p += 1
    else:
        print(f"  FAIL: http_in_len = {in_len}, expected 0")
        f += 1
    return p + 1, f


def test_content_length_24bit(transport, labels):
    """Content-Length parses to 24 bits (real bodies exceed 64 KB) with
    the http_cl_valid flag replacing the old $FFFF magic sentinel."""
    passed = 0
    failed = 0

    # Headers + a token 5 bytes of a (claimed) 100000-byte body.  One
    # span; the parser must consume it and stay in the body state.
    wire = b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\nABCDE"
    _reset_parser(transport, labels)
    carry = _feed_span(transport, labels, wire)
    if carry != 1:
        print(f"  FAIL: parser terminated early (carry={carry})")
        return 0, 1
    print("  PASS: parser still waiting for the rest of the 100000 B body")
    passed += 1

    cl_valid = read_bytes(transport, labels.address("http_cl_valid"), 1)[0]
    cl = _read_u24(transport, labels, "http_content_length")
    if cl_valid == 1 and cl == 100000:
        print(f"  PASS: http_cl_valid = 1, http_content_length = {cl}")
        passed += 1
    else:
        print(f"  FAIL: http_cl_valid = {cl_valid} (exp 1), "
              f"http_content_length = {cl} (exp 100000)")
        failed += 1

    total = _read_u24(transport, labels, "http_body_total")
    state = read_bytes(transport, labels.address("http_parse_state"), 1)[0]
    if total == 5 and state == 2:
        print(f"  PASS: body_total = {total}, still in body state")
        passed += 1
    else:
        print(f"  FAIL: body_total = {total} (exp 5), parse_state = {state} "
              "(exp 2)")
        failed += 1
    return passed, failed


def test_body_no_content_length(transport, labels):
    """Content-Length absent: legacy behaviour preserved — bytes store into
    http_resp_buf, no premature termination, body_total still counts."""
    passed = 0
    failed = 0

    body = b"NO-CL BODY BYTES HERE"          # 21 bytes
    wire = b"HTTP/1.1 200 OK\r\nX-Info: none\r\n\r\n" + body
    _reset_parser(transport, labels)
    carry = _feed_span(transport, labels, wire)
    if carry != 1:
        print(f"  FAIL: parser terminated early (carry={carry})")
        return 0, 1

    resp_len = _read_u16(transport, labels, "http_resp_len")
    stored = read_bytes(transport, labels.address("http_resp_buf"), len(body))
    total = _read_u24(transport, labels, "http_body_total")
    if resp_len == len(body) and stored == body:
        print(f"  PASS: body stored intact, http_resp_len = {resp_len}")
        passed += 1
    else:
        print(f"  FAIL: resp_len = {resp_len} (exp {len(body)}), "
              f"stored = {stored!r}")
        failed += 1
    if total == len(body):
        print(f"  PASS: http_body_total = {total}")
        passed += 1
    else:
        print(f"  FAIL: http_body_total = {total}, expected {len(body)}")
        failed += 1
    return passed, failed


# --- W4 REU body sink -----------------------------------------------------
# VICE runs with a 512 KB REU (-reusize 512), which cannot hold the
# shipped default base of bank 16 ($10:0000, 16 MB REU).  The sink reads
# its base from the runtime variable http_reu_body_base (3 bytes LE,
# file-backed RAM), so the test retargets it to bank 3 ($03:0000) by
# DMA, no rebuild needed.  Hardware rigs with a 16 MB REU use the
# shipped default (or `make HTTP_REU_BODY_BASE=<decimal>`).
SINK_TEST_BASE = (0x00, 0x00, 0x03)      # $03:0000 — inside a 512 KB REU
SINK_FETCH_STUB = 0xC380                 # after the carry stub at $C300
SINK_FETCH_DEST = 0xC000                 # ring area; free between tests


def _reu_fetch_to_ram(transport, labels, length, c64_addr=SINK_FETCH_DEST,
                      reu_base=SINK_TEST_BASE, stub_addr=SINK_FETCH_STUB):
    """Drive a C64-side REU FETCH so the host can read REU contents back.

    Writes a small 6502 stub that programs the $DF00 REC registers for a
    REU->C64 transfer of `length` bytes from `reu_base` to `c64_addr`,
    executes it via jsr(), and returns the fetched bytes.
    """
    lo, hi = length & 0xFF, (length >> 8) & 0xFF
    stub = bytes([
        0xA9, c64_addr & 0xFF,        0x8D, 0x02, 0xDF,   # c64 addr lo
        0xA9, (c64_addr >> 8) & 0xFF, 0x8D, 0x03, 0xDF,   # c64 addr hi
        0xA9, reu_base[0],            0x8D, 0x04, 0xDF,   # reu addr lo
        0xA9, reu_base[1],            0x8D, 0x05, 0xDF,   # reu addr hi
        0xA9, reu_base[2],            0x8D, 0x06, 0xDF,   # reu bank
        0xA9, lo,                     0x8D, 0x07, 0xDF,   # len lo
        0xA9, hi,                     0x8D, 0x08, 0xDF,   # len hi
        0xA9, 0x00,                   0x8D, 0x0A, 0xDF,   # addr ctrl
        0xA9, 0xB1,                   0x8D, 0x01, 0xDF,   # execute FETCH
        0x60,                                             # rts
    ])
    write_bytes(transport, stub_addr, stub)
    jsr(transport, stub_addr)
    return read_bytes(transport, c64_addr, length)


def test_reu_body_sink(transport, labels):
    """W4 REU body sink: >512 B bodies streamed to the REU through the
    512 B bounce buffer; verifies http_body_total, the first-512
    http_resp_buf restore contract, and the REU contents read back by
    DMA.  Covers both the chunked (Wikipedia shape) and identity/CL
    paths."""
    passed = 0
    failed = 0

    sink_blit = labels.address("http_sink_blit")
    base_var = labels.address("http_reu_body_base")
    sink_flag = labels.address("http_body_sink")
    if sink_blit is None or base_var is None:
        # The REU sink is BACKEND=uci-only (ip65 cannot fit it).  Do not
        # let this read as coverage: say loudly what was not run.
        print("  !! SINK VECTORS NOT RUN: this PRG has no REU sink "
              "(BACKEND=uci-only).")
        print("  !! To cover them: make clean && make BACKEND=uci && "
              "C64_SKIP_BUILD=1 python3 tools/test_http.py")
        if os.environ.get("C64_EXPECT_SINK"):
            print("  FAIL: C64_EXPECT_SINK=1 but the sink is absent")
            return 0, 1
        return 0, 0

    # Retarget the sink base into the 512 KB VICE REU (bank 3) and
    # enable sink mode.
    write_bytes(transport, base_var, list(SINK_TEST_BASE))
    write_bytes(transport, sink_flag, [1])

    # --- vector 1: chunked 700 B (the Wikipedia shape) ---
    part1 = bytes((i * 13 + 5) & 0xFF for i in range(400))
    part2 = bytes((i * 17 + 9) & 0xFF for i in range(300))
    body = part1 + part2
    wire = (b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n" + _chunked(body, [400, 300]))
    carry = _run_span_response(transport, labels, [wire])
    if carry != 0:
        print(f"  FAIL: sink parse (chunked) did not complete "
              f"(result={carry})")
        write_bytes(transport, sink_flag, [0])
        return passed, failed + 1
    print("  PASS: chunked sink parse complete")
    passed += 1

    total = _read_u24(transport, labels, "http_body_total")
    resp_len = _read_u16(transport, labels, "http_resp_len")
    if total == 700 and resp_len == 512:
        print(f"  PASS: body_total = {total}, resp_len = {resp_len}")
        passed += 1
    else:
        print(f"  FAIL: body_total = {total} (exp 700), resp_len = "
              f"{resp_len} (exp 512)")
        failed += 1

    stored = read_bytes(transport, labels.address("http_resp_buf"), 512)
    if stored == body[:512]:
        print("  PASS: http_resp_buf restored to the FIRST 512 body bytes")
        passed += 1
    else:
        print("  FAIL: http_resp_buf does not hold the first 512 body bytes")
        failed += 1

    reu = _reu_fetch_to_ram(transport, labels, 700)
    if bytes(reu) == body:
        print("  PASS: REU holds all 700 de-chunked body bytes")
        passed += 1
    else:
        diff = next((i for i in range(700) if reu[i] != body[i]), None)
        print(f"  FAIL: REU contents mismatch (first diff at {diff})")
        failed += 1

    # --- vector 2: identity 600 B with Content-Length ---
    body2 = bytes((i * 31 + 7) & 0xFF for i in range(600))
    wire2 = b"HTTP/1.1 200 OK\r\nContent-Length: 600\r\n\r\n" + body2
    carry = _run_span_response(transport, labels, [wire2])
    if carry != 0:
        print(f"  FAIL: sink parse (identity/CL) did not complete "
              f"(result={carry})")
        write_bytes(transport, sink_flag, [0])
        return passed, failed + 1

    total = _read_u24(transport, labels, "http_body_total")
    resp_len = _read_u16(transport, labels, "http_resp_len")
    stored = read_bytes(transport, labels.address("http_resp_buf"), 512)
    reu = _reu_fetch_to_ram(transport, labels, 600)
    if (total == 600 and resp_len == 512 and stored == body2[:512]
            and bytes(reu) == body2):
        print("  PASS: identity/CL sink: body_total = 600, first-512 "
              "restored, REU contents match")
        passed += 1
    else:
        print(f"  FAIL: identity/CL sink: total={total}, resp_len={resp_len}, "
              f"prefix_ok={stored == body2[:512]}, "
              f"reu_ok={bytes(reu) == body2}")
        failed += 1

    # Cleanup: buffer mode, shipped default base (bank 16), ring input.
    write_bytes(transport, sink_flag, [0])
    write_bytes(transport, base_var, [0x00, 0x00, 0x10])
    write_bytes(transport, labels.address("http_in_mode"), [0])
    return passed, failed


def _run_parser_loop(transport, labels, timeout=30.0):
    """Run http_recv_response in a loop until complete (C=0).

    Writes a 6502 trampoline at $C200 that calls http_recv_response
    in a loop (JSR recv / BCS loop / RTS), then executes it with a
    single jsr() call. The entire parser loop runs on the C64 side.

    Returns True if parser completed, False on timeout.
    """
    recv_response = labels.address("http_recv_response")
    lo = recv_response & 0xFF
    hi = (recv_response >> 8) & 0xFF
    # @loop: JSR http_recv_response (3) / BCS @loop (2) / RTS (1)
    trampoline = bytes([
        0x20, lo, hi,   # JSR http_recv_response
        0xB0, 0xFB,     # BCS @loop (-5, back to offset 0)
        0x60,           # RTS
    ])
    write_bytes(transport, 0xC200, trampoline)
    try:
        jsr(transport, 0xC200, timeout=timeout)
        return True
    except TimeoutError:
        return False


def test_recv_response_basic(transport, labels):
    """Test HTTP response parser with a simple 200 OK response."""
    passed = 0
    failed = 0

    # Check required labels
    required = [
        "http_recv_response", "tcp_recv_buf", "tcp_recv_head", "tcp_recv_tail",
        "http_parse_state", "http_line_idx", "http_hdr_match",
        "http_resp_len", "http_resp_buf", "http_status",
    ]
    for name in required:
        if labels.address(name) is None:
            print(f"  FAIL: required label '{name}' not found")
            return 0, 1

    # Craft a simple HTTP response
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello"

    # Load into ring buffer and reset parser
    _load_ring_buffer(transport, labels, response)
    _reset_parser(transport, labels)

    # Run parser loop
    complete = _run_parser_loop(transport, labels)
    if not complete:
        print("  FAIL: parser did not complete within max iterations")
        return 0, 1

    # Diagnostics: check parser state and ring buffer
    parse_st = read_bytes(transport, labels.address("http_parse_state"), 1)[0]
    head_val = read_bytes(transport, labels.address("tcp_recv_head"), 1)[0]
    tail_val = read_bytes(transport, labels.address("tcp_recv_tail"), 1)[0]
    print(f"  DEBUG: parse_state={parse_st}, head={head_val}, tail={tail_val}")

    # Check http_status = 200 ($C8, $00 in little-endian)
    status_bytes = read_bytes(transport, labels.address("http_status"), 2)
    status = status_bytes[0] | (status_bytes[1] << 8)
    if status == 200:
        print(f"  PASS: http_status = {status}")
        passed += 1
    else:
        print(f"  FAIL: http_status = {status}, expected 200 (bytes: ${status_bytes[0]:02X} ${status_bytes[1]:02X})")
        failed += 1

    # Check response body
    resp_len_bytes = read_bytes(transport, labels.address("http_resp_len"), 2)
    resp_len = resp_len_bytes[0] | (resp_len_bytes[1] << 8)
    if resp_len == 5:
        print(f"  PASS: http_resp_len = {resp_len}")
        passed += 1
    else:
        print(f"  FAIL: http_resp_len = {resp_len}, expected 5")
        failed += 1

    resp_body = read_bytes(transport, labels.address("http_resp_buf"), resp_len)
    if resp_body == b"Hello":
        print(f"  PASS: response body = 'Hello'")
        passed += 1
    else:
        print(f"  FAIL: response body = {resp_body!r}, expected b'Hello'")
        failed += 1

    return passed, failed


def test_recv_response_404(transport, labels):
    """Test HTTP response parser with a 404 Not Found response."""
    passed = 0
    failed = 0

    # Craft a 404 response with a header and empty body
    response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"

    _load_ring_buffer(transport, labels, response)
    _reset_parser(transport, labels)

    complete = _run_parser_loop(transport, labels)
    if not complete:
        print("  FAIL: parser did not complete within max iterations")
        return 0, 1

    # Check http_status = 404 ($94, $01 in little-endian)
    status_bytes = read_bytes(transport, labels.address("http_status"), 2)
    status = status_bytes[0] | (status_bytes[1] << 8)
    if status == 404:
        print(f"  PASS: http_status = {status}")
        passed += 1
    else:
        print(f"  FAIL: http_status = {status}, expected 404 (bytes: ${status_bytes[0]:02X} ${status_bytes[1]:02X})")
        failed += 1

    # Body length should be 0 (parser completes when ring buffer empty)
    resp_len_bytes = read_bytes(transport, labels.address("http_resp_len"), 2)
    resp_len = resp_len_bytes[0] | (resp_len_bytes[1] << 8)
    if resp_len == 0:
        print(f"  PASS: http_resp_len = 0 (empty body)")
        passed += 1
    else:
        print(f"  FAIL: http_resp_len = {resp_len}, expected 0")
        failed += 1

    return passed, failed


def test_recv_response_with_body(transport, labels):
    """Test HTTP response parser with a larger body (100+ bytes)."""
    passed = 0
    failed = 0

    # Build a body of 120 bytes of known content
    body = bytes(range(120))  # 0x00..0x77
    headers = b"HTTP/1.1 200 OK\r\nContent-Length: 120\r\n\r\n"
    response = headers + body

    if len(response) > 256:
        print(f"  SKIP: response ({len(response)} bytes) exceeds 256-byte ring buffer")
        return 0, 0

    _load_ring_buffer(transport, labels, response)
    _reset_parser(transport, labels)

    complete = _run_parser_loop(transport, labels, timeout=60.0)
    if not complete:
        print("  FAIL: parser did not complete within max iterations")
        return 0, 1

    # Check status
    status_bytes = read_bytes(transport, labels.address("http_status"), 2)
    status = status_bytes[0] | (status_bytes[1] << 8)
    if status == 200:
        print(f"  PASS: http_status = {status}")
        passed += 1
    else:
        print(f"  FAIL: http_status = {status}, expected 200")
        failed += 1

    # Check body length
    resp_len_bytes = read_bytes(transport, labels.address("http_resp_len"), 2)
    resp_len = resp_len_bytes[0] | (resp_len_bytes[1] << 8)
    if resp_len == 120:
        print(f"  PASS: http_resp_len = {resp_len}")
        passed += 1
    else:
        print(f"  FAIL: http_resp_len = {resp_len}, expected 120")
        failed += 1

    # Verify body content byte-by-byte
    resp_body = read_bytes(transport, labels.address("http_resp_buf"), resp_len)
    if resp_body == body:
        print(f"  PASS: response body matches all {len(body)} bytes")
        passed += 1
    else:
        mismatches = [(i, resp_body[i], body[i])
                      for i in range(min(len(resp_body), len(body)))
                      if resp_body[i] != body[i]]
        print(f"  FAIL: body mismatch — {len(mismatches)} byte(s) differ")
        for idx, got, exp in mismatches[:5]:
            print(f"    offset {idx}: got ${got:02X}, expected ${exp:02X}")
        failed += 1

    return passed, failed


def run_tests(transport, labels, verbose=False):
    total_passed = 0
    total_failed = 0

    print("\n--- HTTP Label Integrity ---")
    p, f = test_build_get_labels(labels)
    total_passed += p
    total_failed += f
    print(f"  {p} labels verified")

    # Verify VICE is still alive
    print("\n--- Connectivity Check ---")
    try:
        probe = read_bytes(transport, 0x0400, 1)
        print(f"  VICE alive (screen byte: ${probe[0]:02X})")
    except Exception as e:
        print(f"  FATAL: VICE connection lost: {e}")
        return total_passed, total_failed + 1

    # jsr() smoke test.  net_save_zp is ip65-only; http_body_finish
    # exists under both backends and is a no-op while http_body_sink=0.
    print("\n--- jsr() Smoke Test ---")
    try:
        target = labels.address("net_save_zp")
        name = "net_save_zp"
        if target is None:
            target = labels.address("http_body_finish")
            name = "http_body_finish"
        jsr(transport, target)
        print(f"  PASS: jsr({name}) returned OK")
        total_passed += 1
    except Exception as e:
        print(f"  FAIL: jsr() crashed VICE: {e}")
        total_failed += 1
        return total_passed, total_failed

    print("\n--- http_build_get Basic ---")
    p, f = test_build_get_basic(transport, labels)
    total_passed += p
    total_failed += f

    print("\n--- http_recv_response Basic (200 OK) ---")
    p, f = test_recv_response_basic(transport, labels)
    total_passed += p
    total_failed += f

    print("\n--- http_recv_response 404 ---")
    p, f = test_recv_response_404(transport, labels)
    total_passed += p
    total_failed += f

    print("\n--- http_recv_response Large Body ---")
    p, f = test_recv_response_with_body(transport, labels)
    total_passed += p
    total_failed += f

    print("\n--- Chunked: basic (single span) ---")
    p, f = test_chunked_basic(transport, labels)
    total_passed += p
    total_failed += f

    print("\n--- Chunked: multi-record spans ---")
    p, f = test_chunked_multi_record(transport, labels)
    total_passed += p
    total_failed += f

    print("\n--- Chunked: >512 B truncation ---")
    p, f = test_chunked_truncation(transport, labels)
    total_passed += p
    total_failed += f

    print("\n--- Large headers + Content-Length ---")
    p, f = test_large_headers_content_length(transport, labels)
    total_passed += p
    total_failed += f

    print("\n--- Chunked + large headers ---")
    p, f = test_chunked_large_headers(transport, labels)
    total_passed += p
    total_failed += f

    print("\n--- W4: identity body > 512 with Content-Length "
          "(browserleaks regression) ---")
    p, f = test_identity_oversize_cl(transport, labels)
    total_passed += p
    total_failed += f

    print("\n--- W4: 24-bit Content-Length ---")
    p, f = test_content_length_24bit(transport, labels)
    total_passed += p
    total_failed += f

    print("\n--- W4: Content-Length absent (legacy path) ---")
    p, f = test_body_no_content_length(transport, labels)
    total_passed += p
    total_failed += f

    print("\n--- W4: REU body sink (BACKEND=uci builds only) ---")
    p, f = test_reu_body_sink(transport, labels)
    total_passed += p
    total_failed += f

    return total_passed, total_failed


def main():
    os.chdir(PROJECT_ROOT)

    seed = random.randint(0, 2**32 - 1)
    verbose = False
    for arg in sys.argv[1:]:
        if arg == "--verbose":
            verbose = True
        elif arg == "--seed":
            pass
        elif sys.argv[sys.argv.index(arg) - 1] == "--seed":
            seed = int(arg)
    random.seed(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

    # Build (skippable via C64_SKIP_BUILD=1 when a caller has already built)
    if os.environ.get("C64_SKIP_BUILD"):
        print("\n=== Building (skipped: C64_SKIP_BUILD set) ===")
    else:
        print("\n=== Building ===")
        result = subprocess.run(["make", "clean"], capture_output=True)
        result = subprocess.run(["make"], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"  Build failed:\n{result.stderr}")
            sys.exit(1)
        print("  Build OK")

    labels = Labels.from_file(LABELS_PATH)
    print(f"  Labels loaded, {len(labels)} symbols")

    # Verify key labels
    for name in ["http_build_get", "http_recv_response", "http_req_buf", "http_status"]:
        if labels.address(name) is None:
            print(f"  FATAL: required label '{name}' not found")
            sys.exit(1)

    # default_vice_config pre-applies the mandatory -reu -reusize 512
    # (see "VICE harness gotcha" in CLAUDE.md) — the REU body-sink
    # vectors DMA through the emulated REU.
    config = default_vice_config(prg_path=PRG_PATH, warp=True, ntsc=True,
                                 sound=False)
    print("\n=== Starting VICE ===")

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"  VICE PID={inst.pid}, port={inst.port}")

        # Wait for menu to appear
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0, verbose=False)
        if grid is None:
            print("  FATAL: Program menu did not appear")
            sys.exit(1)
        print("  Program started OK")

        passed, failed = run_tests(transport, labels, verbose)

        mgr.release(inst)

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"RESULTS: {passed}/{total} passed, {failed}/{total} failed")
    print(f"{'='*60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
