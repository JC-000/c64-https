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
    crlf_addr = labels.address("http_crlf")

    # Build expected output by reading the actual constant bytes from VICE
    # This avoids any PETSCII/ASCII confusion — we compare against what
    # the assembler actually produced.
    verb_bytes = read_bytes(transport, get_verb_addr, 4)       # "GET "
    ver_bytes = read_bytes(transport, version_addr, 11)        # " HTTP/1.1\r\n"
    hosthdr_bytes = read_bytes(transport, host_hdr_addr, 6)    # "Host: "
    conn_bytes = read_bytes(transport, conn_hdr_addr, 19)      # "Connection: close\r\n"
    crlf_bytes = read_bytes(transport, crlf_addr, 2)           # \r\n

    # The hostname and path are written by us in raw bytes, so they stay as-is.
    expected = (
        verb_bytes +              # "GET "           (4)
        path +                    # "/test"          (5)
        ver_bytes +               # " HTTP/1.1\r\n" (11)
        hosthdr_bytes +           # "Host: "         (6)
        hostname +                # "example.com"    (11)
        crlf_bytes +              # "\r\n"           (2)
        conn_bytes +              # "Connection: close\r\n" (19)
        crlf_bytes                # "\r\n"           (2)
    )

    expected_len = len(expected)  # should be 60

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


def _load_span(transport, labels, data, addr=0xC400):
    """Feed canned data to the parser as a linear span (http_in_mode=1).

    This is the TLS-path input mode (issue #72): the parser reads from
    http_in_ptr/http_in_len instead of the TCP ring, which also lifts the
    ring helper's 256-byte limit — needed for the >512 B body vectors.
    """
    write_bytes(transport, addr, data)
    write_bytes(transport, labels.address("http_in_mode"), [1])
    write_bytes(transport, labels.address("http_in_ptr"),
                [addr & 0xFF, (addr >> 8) & 0xFF])
    write_bytes(transport, labels.address("http_in_len"),
                [len(data) & 0xFF, (len(data) >> 8) & 0xFF])


def _read_u16(transport, labels, name):
    b = read_bytes(transport, labels.address(name), 2)
    return b[0] | (b[1] << 8)


def _read_u24(transport, labels, name):
    b = read_bytes(transport, labels.address(name), 3)
    return b[0] | (b[1] << 8) | (b[2] << 16)


def test_body_larger_than_buffer(transport, labels):
    """W4 regression (browserleaks.com): identity body > 512 B with
    Content-Length must terminate by CONSUMED count, not stored count.

    Before the fix, http_resp_len froze at the 512 B cap, the
    Content-Length match could never fire, and only connection-close /
    poll-timeout ended the read."""
    passed = 0
    failed = 0

    body = bytes((i * 7 + (i >> 8)) & 0xFF for i in range(700))
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 700\r\n\r\n" + body

    _load_span(transport, labels, response)
    _reset_parser(transport, labels)

    complete = _run_parser_loop(transport, labels, timeout=60.0)
    if not complete:
        print("  FAIL: parser did not complete (Content-Length termination "
              "did not fire on truncated body — the W4 regression)")
        return 0, 1
    print("  PASS: parser terminated on consumed-count match")
    passed += 1

    total = _read_u24(transport, labels, "http_body_total")
    if total == 700:
        print(f"  PASS: http_body_total = {total}")
        passed += 1
    else:
        print(f"  FAIL: http_body_total = {total}, expected 700")
        failed += 1

    resp_len = _read_u16(transport, labels, "http_resp_len")
    if resp_len == 512:
        print(f"  PASS: http_resp_len = {resp_len} (min(512, total))")
        passed += 1
    else:
        print(f"  FAIL: http_resp_len = {resp_len}, expected 512")
        failed += 1

    stored = read_bytes(transport, labels.address("http_resp_buf"), 512)
    if stored == body[:512]:
        print("  PASS: http_resp_buf holds the first 512 body bytes")
        passed += 1
    else:
        print("  FAIL: http_resp_buf does not match first 512 body bytes")
        failed += 1

    in_len = _read_u16(transport, labels, "http_in_len")
    if in_len == 0:
        print("  PASS: span fully consumed (bytes past the cap were drained)")
        passed += 1
    else:
        print(f"  FAIL: http_in_len = {in_len}, expected 0 "
              "(bytes past the 512 cap were not consumed)")
        failed += 1

    return passed, failed


def test_content_length_24bit(transport, labels):
    """Content-Length parses to 24 bits (real bodies exceed 64 KB) with
    the valid-flag replacing the old $FFFF magic sentinel."""
    passed = 0
    failed = 0

    # Headers + a token 5 bytes of a (claimed) 100000-byte body.  A single
    # dispatch consumes the span and returns not-done; we then inspect the
    # parsed header state.
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\nABCDE"
    _load_span(transport, labels, response)
    _reset_parser(transport, labels)

    jsr(transport, labels.address("http_recv_response"))

    cl_valid = read_bytes(transport, labels.address("http_cl_valid"), 1)[0]
    if cl_valid == 1:
        print("  PASS: http_cl_valid = 1")
        passed += 1
    else:
        print(f"  FAIL: http_cl_valid = {cl_valid}, expected 1")
        failed += 1

    cl = _read_u24(transport, labels, "http_content_length")
    if cl == 100000:
        print(f"  PASS: http_content_length = {cl} (24-bit)")
        passed += 1
    else:
        print(f"  FAIL: http_content_length = {cl}, expected 100000")
        failed += 1

    total = _read_u24(transport, labels, "http_body_total")
    state = read_bytes(transport, labels.address("http_parse_state"), 1)[0]
    if total == 5 and state == 2:
        print(f"  PASS: body_total = {total}, still in body state "
              "(not terminated early)")
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
    response = b"HTTP/1.1 200 OK\r\nX-Info: none\r\n\r\n" + body
    _load_span(transport, labels, response)
    _reset_parser(transport, labels)

    # Single dispatch: consumes the whole span, returns not-done (C=1)
    # because with no Content-Length the parser keeps polling.
    jsr(transport, labels.address("http_recv_response"))

    resp_len = _read_u16(transport, labels, "http_resp_len")
    if resp_len == len(body):
        print(f"  PASS: http_resp_len = {resp_len}")
        passed += 1
    else:
        print(f"  FAIL: http_resp_len = {resp_len}, expected {len(body)}")
        failed += 1

    stored = read_bytes(transport, labels.address("http_resp_buf"), len(body))
    if stored == body:
        print("  PASS: body stored intact")
        passed += 1
    else:
        print(f"  FAIL: body mismatch: {stored!r}")
        failed += 1

    total = _read_u24(transport, labels, "http_body_total")
    if total == len(body):
        print(f"  PASS: http_body_total = {total}")
        passed += 1
    else:
        print(f"  FAIL: http_body_total = {total}, expected {len(body)}")
        failed += 1

    # Restore ring input mode for any later ring-driven vectors.
    write_bytes(transport, labels.address("http_in_mode"), [0])
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

    # jsr() smoke test
    print("\n--- jsr() Smoke Test ---")
    try:
        save_zp = labels.address("net_save_zp")
        jsr(transport, save_zp)
        print("  PASS: jsr(net_save_zp) returned OK")
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

    print("\n--- W4: body > 512 with Content-Length (browserleaks regression) ---")
    p, f = test_body_larger_than_buffer(transport, labels)
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

    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
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
