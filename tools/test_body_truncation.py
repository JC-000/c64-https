#!/usr/bin/env python3
"""test_body_truncation.py — issue #211: http_recv_body reports success on a
truncated body.

WHAT THIS PINS
--------------
``http_recv_body`` (src/http.s) polls the transport, hands each decrypted
TLS record to the parser, and counts *consecutive* no-data ticks in a
16-bit counter.  When that counter wraps, control **falls through into the
success path**::

    @recv_no_data:
            inc @recv_timeout           ; src/http.s:258
            bne @recv_loop
            inc @recv_timeout+1
            bne @recv_loop
            ; Timeout — accept whatever we have     <-- no compare, no sec
    @recv_complete:
            jsr http_body_finish
            clc                         ; src/http.s:270
            rts

``http_cl_valid``, the 24-bit ``http_body_total`` and ``http_content_length``
are all in scope at that point, and ``http_body_done_check``
(src/http.s:700) already implements exactly the comparison that nobody
calls there.  ``http_get`` then discards the carry unconditionally
(src/http.s:174-178), so a caller has two independent reasons it cannot
learn the body was short.

Observed in the field as *two* failure modes — a fast false success and a
"hang".  Those are ONE defect at two costs, not two cases here.  The
budget is 65,536 consecutive ticks; against a socket ``net_poll`` has
flagged ``NET_TCP_ERROR`` that is ~0.1 s, because a non-CONNECTED socket
makes the UCI ``net_poll`` a 6-cycle RTS (src/net/uci/net.s:151-155),
while against a healthy but silent socket each tick is two real ~40 ms
``net_poll`` round-trips (src/net/uci/net_tuning.inc) and the budget takes
~87 minutes, which a 900 s rig budget reads as a hang.

**The socket's state changes the COST of a tick, never the OUTCOME.**
``@recv_timeout`` increments on any ``tls_recv`` C=1 regardless of why,
and the carry is decided entirely by ``http_parse_state`` / ``cl_valid`` /
``chunked`` / ``body_total`` vs ``content_length``.  An earlier draft of
this suite had separate ERRORed-socket and CONNECTED-socket cases; they
were the same test twice, because ``net_tcp_state``'s only reader is
inside ``net_poll``, which this suite stubs out.  Verified empirically:
poking garbage there gives byte-identical output.

When the deferred abort lands (``http_recv_body`` gaining its own
``lda net_tcp_state`` so a dead socket fails immediately instead of after
65,536 ticks), that byte acquires a second reader outside ``net_poll`` and
the two cases become genuinely distinct with no stubbing — split them back
out then, and assert elapsed time, which is the thing that actually
differs.

HOW IT DRIVES THE C64
---------------------
No network, no listener, no device.  Host-installed patches, all of them
saved and restored around each case (see ``Patcher``) so the suite leaves
the machine as it found it:

  * ``net_poll`` -> ``RTS``.  A tick then costs tens of cycles instead of
    tens of milliseconds, which is what makes the silent-socket case a
    three-second test rather than an 87-minute one.  It also keeps the
    suite backend-agnostic: ip65's ``net_poll`` ignores ``net_tcp_state``
    entirely and always calls ``ip65_process``.
  * ``tls_recv`` -> ``JMP`` to a stub that yields one canned application
    record (C=0) and then reports no-data (C=1) forever.

The carry-propagation case additionally stubs ``http_recv_body`` to
``SEC``/``RTS`` and both closes to ``RTS``, then JSRs straight at the
``jsr http_recv_body`` instruction inside ``http_get`` — located by
scanning the PRG image for the opcode, not hardcoded — so it measures
exactly what ``http_get`` does with a failing receive.

``http_recv_body`` is entered through a carry-latching stub: reading the P
register back over the monitor is unreliable across backends, latching it
into RAM from 6502 code is not (technique from
tools/test_finished_verify.py:202).

SHADOW-RAM TRAP
---------------
``http_*`` state and ``net_tcp_state`` live under the BASIC ROM shadow at
$A000-$BFFF (and at *different* addresses per backend — ``net_tcp_state``
is $B3BF on uci and $B9BF on ip65, which is why every address here comes
from ``build/labels.txt`` and none is written down).  Writes land in RAM,
but a *read* returns ROM unless
$01 has the ROM banked out at the moment of the read.  A run that reads
ROM and reports a plausible-looking number is exactly the failure class
this issue is about, so ``assert_shadow_ram_readable()`` runs first and is
FATAL, never a skip.

Backend-agnostic: the transport is stubbed out entirely, so the suite is
red on an unfixed build and green on a fixed one under both BACKEND=ip65
and BACKEND=uci (measured both ways).  That is why it is dispatched from
tools/run_all_tests.py, which builds ip65.

Usage:
    C64_SKIP_BUILD=1 python3 tools/test_body_truncation.py
"""

import os
import subprocess
import sys

from c64_test_harness import (
    Labels, ViceInstanceManager,
    read_bytes, write_bytes, jsr, wait_for_text,
)
from _vice_helpers import default_vice_config

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

REQUIRED_LABELS = [
    "http_recv_body",
    "net_poll",
    "tls_recv",
    "tls_app_ptr",
    "tls_app_len",
    "net_tcp_state",
    "http_status",
    "http_cl_valid",
    "http_content_length",
    "http_body_total",
    "http_body_sink",
    "http_parse_state",
    "http_chunked",
    "http_get",
    "tls_close",
    "net_tcp_close",
]

# src/net/net_states.inc — normative, defined there and nowhere else.
NET_TCP_CONNECTED = 0x01
NET_TCP_ERROR = 0x02

# --- Scratch layout ---------------------------------------------------------
# $02A7-$02FF is the 89-byte free block below the cassette buffer; the
# canned response is 75 B at most and both ends are readback-verified.
CANNED_ADDR = 0x02A7
CANNED_MAX = 0x0300 - CANNED_ADDR

# Cassette buffer.  The harness's own jsr() trampoline is at $0334 (5 B),
# run_all_tests.py's safety loop at $0339 (3 B), run_subroutine's U64
# trampoline at $0360 (14 B) with flags at $03F0/$03F1, and
# test_finished_verify.py's stub at $0340/$0350.  $0380 upward collides
# with none of them.
STUB_ADDR = 0x0380        # 32 B -> $039F   (tls_recv replacement)
DRIVER_ADDR = 0x03A0      # 15 B -> $03AE   (reset counter, call, latch carry)
LATCH_ADDR = 0x03B0
COUNTER_ADDR = 0x03B1

POISON = 0xA5


# ---------------------------------------------------------------------------
# 6502 plumbing
# ---------------------------------------------------------------------------

def _lohi(addr: int) -> tuple[int, int]:
    return addr & 0xFF, (addr >> 8) & 0xFF


def build_recv_stub(labels, canned_addr: int, canned_len: int) -> bytes:
    """Assemble the ``tls_recv`` replacement.

    First call: publish the canned record and return C=0.  Every later
    call: C=1 ("no data right now"), which is what drives http_recv_body
    into its @recv_no_data tick budget.

        LDA counter
        BNE  fail
        INC  counter
        LDA #<canned  / STA tls_app_ptr
        LDA #>canned  / STA tls_app_ptr+1
        LDA #<len     / STA tls_app_len
        LDA #>len     / STA tls_app_len+1
        CLC / RTS
    fail:
        SEC / RTS
    """
    c_lo, c_hi = _lohi(COUNTER_ADDR)
    d_lo, d_hi = _lohi(canned_addr)
    p_lo, p_hi = _lohi(labels["tls_app_ptr"])
    p1_lo, p1_hi = _lohi(labels["tls_app_ptr"] + 1)
    l_lo, l_hi = _lohi(labels["tls_app_len"])
    l1_lo, l1_hi = _lohi(labels["tls_app_len"] + 1)
    n_lo, n_hi = _lohi(canned_len)

    stub = bytes([
        0xAD, c_lo, c_hi,           # 0  LDA counter
        0xD0, 0x19,                 # 3  BNE +25 -> offset 30
        0xEE, c_lo, c_hi,           # 5  INC counter
        0xA9, d_lo,                 # 8  LDA #<canned
        0x8D, p_lo, p_hi,           # 10 STA tls_app_ptr
        0xA9, d_hi,                 # 13 LDA #>canned
        0x8D, p1_lo, p1_hi,         # 15 STA tls_app_ptr+1
        0xA9, n_lo,                 # 18 LDA #<len
        0x8D, l_lo, l_hi,           # 20 STA tls_app_len
        0xA9, n_hi,                 # 23 LDA #>len
        0x8D, l1_lo, l1_hi,         # 25 STA tls_app_len+1
        0x18,                       # 28 CLC
        0x60,                       # 29 RTS
        0x38,                       # 30 SEC
        0x60,                       # 31 RTS
    ])
    assert len(stub) == 32 and stub[30] == 0x38, "stub branch target moved"
    return stub


def build_driver(labels) -> bytes:
    """Reset the stub counter, call http_recv_body, latch the carry."""
    c_lo, c_hi = _lohi(COUNTER_ADDR)
    t_lo, t_hi = _lohi(labels["http_recv_body"])
    r_lo, r_hi = _lohi(LATCH_ADDR)
    return bytes([
        0xA9, 0x00,                 # LDA #0
        0x8D, c_lo, c_hi,           # STA counter
        0x20, t_lo, t_hi,           # JSR http_recv_body
        0xA9, 0x00,                 # LDA #0
        0x2A,                       # ROL A        (carry -> bit 0)
        0x8D, r_lo, r_hi,           # STA latch
        0x60,                       # RTS
    ])


def write_verified(transport, addr: int, data: bytes, what: str) -> None:
    write_bytes(transport, addr, data)
    back = read_bytes(transport, addr, len(data))
    if back != data:
        raise RuntimeError(
            f"{what}: readback mismatch at ${addr:04X} — wrote "
            f"{data.hex()}, read {back.hex()}"
        )


def assert_shadow_ram_readable(transport, labels) -> None:
    """FATAL unless reads of the $A000-$BFFF shadow return RAM, not ROM.

    ``http_body_total`` and friends live under the BASIC ROM.  If the
    monitor reads ROM there, every counter this suite prints is a BASIC
    ROM byte that happens to look like a number — a passing-shaped result
    measuring nothing.  Probe both a $A8xx and a $B3xx address, since the
    two are in different ROM images' territory.
    """
    for name in ("http_body_total", "net_tcp_state"):
        addr = labels[name]
        original = read_bytes(transport, addr, 1)
        for probe in (0x5A, 0xA5):
            write_bytes(transport, addr, bytes([probe]))
            got = read_bytes(transport, addr, 1)[0]
            if got != probe:
                raise RuntimeError(
                    f"shadow RAM not readable at {name} (${addr:04X}): wrote "
                    f"${probe:02X}, read ${got:02X}. The BASIC/KERNAL ROM is "
                    f"banked in for reads ($01), so every counter below "
                    f"would be a ROM byte. Treat this run as inconclusive."
                )
        write_bytes(transport, addr, original)


# ---------------------------------------------------------------------------
# Patching with restore
# ---------------------------------------------------------------------------

class Patcher:
    """Write patches, remember the originals, put them all back.

    Without this the suite would leave ``net_poll`` and ``tls_recv``
    stubbed and the ``http_*`` state poisoned, which is safe only for as
    long as it happens to run last in ``SUITE_ORDER``.

    It **reduces** the suite's footprint; it does not retire it. The
    Patcher restores writes, not effects: running the code under test also
    moves state nobody patched. Measured, 6 of 19 watched locations are
    left changed -- ``http_parse_state`` at 2 and ``http_resp_len`` at
    $0220 among them -- because the parser wrote them itself. Every stub,
    every scratch byte and every value this suite pokes is restored, which
    is what makes the suite safe to reorder; a consumer that depends on
    ``http_parse_state`` being 0 at entry would still need its own reset,
    exactly as ``http_recv_body`` performs one.
    """

    def __init__(self, transport):
        self.transport = transport
        self.saved = []

    def patch(self, addr: int, data: bytes, what: str) -> None:
        self.saved.append((addr, read_bytes(self.transport, addr, len(data))))
        write_bytes(self.transport, addr, data)
        back = read_bytes(self.transport, addr, len(data))
        if back != data:
            raise RuntimeError(
                f"{what}: readback mismatch at ${addr:04X} — wrote "
                f"{data.hex()}, read {back.hex()}"
            )

    def restore(self) -> None:
        for addr, original in reversed(self.saved):
            write_bytes(self.transport, addr, original)
        self.saved.clear()


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

def canned_response(content_length, body_len: int, chunked: bool = False):
    """Build a canned HTTP/1.1 response.

    ``content_length=None`` + ``chunked=True`` produces a chunked response
    whose terminal ``0\r\n\r\n`` chunk never arrives.
    """
    if chunked:
        head = ("HTTP/1.1 200 OK\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n").encode("ascii")
        payload = bytes((0x41 + (i % 26)) for i in range(body_len))
        blob = head + f"{body_len:x}\r\n".encode("ascii") + payload + b"\r\n"
    else:
        head = (f"HTTP/1.1 200 OK\r\n"
                f"Content-Length: {content_length}\r\n"
                f"\r\n").encode("ascii")
        blob = head + bytes((0x41 + (i % 26)) for i in range(body_len))
    if len(blob) > CANNED_MAX:
        raise RuntimeError(
            f"canned response {len(blob)} B exceeds the {CANNED_MAX} B "
            f"scratch block at ${CANNED_ADDR:04X}"
        )
    return blob


def find_http_get_recv_site(labels) -> int:
    """Address of the ``jsr http_recv_body`` instruction inside http_get.

    Scanned out of the PRG image rather than hardcoded, so it follows the
    code if it moves. The instruction after it is reported by the caller
    as a self-check: $20 (another JSR) on an unfixed build, $08 (PHP) on a
    fixed one — if that byte is neither, the scan found the wrong site and
    the case is inconclusive rather than passing.
    """
    with open(PRG_PATH, "rb") as fh:
        prg = fh.read()
    load = prg[0] | (prg[1] << 8)
    img = prg[2:]
    rb = labels["http_recv_body"]
    pat = bytes([0x20, rb & 0xFF, (rb >> 8) & 0xFF])
    sites = [load + i for i in range(len(img) - 2) if img[i:i + 3] == pat]
    after = [a for a in sites if a >= labels["http_get"]]
    if not after:
        raise RuntimeError(
            f"no `jsr http_recv_body` at or above http_get "
            f"(${labels['http_get']:04X}); sites found: "
            + ", ".join(f"${a:04X}" for a in sites)
        )
    site = min(after)
    return site, img[site - load + 3]


def run_case(transport, labels, content_length, body_len, chunked=False,
             blob=None, timeout: float = 180.0) -> dict:
    """Drive http_recv_body once over a canned response, return the outcome.

    ``blob=b""`` is the "nothing ever arrived" case: the stub publishes a
    zero-length record, so the parser never leaves the status-line state.
    """
    if blob is None:
        blob = canned_response(content_length, body_len, chunked)
    p = Patcher(transport)
    try:
        if blob:
            p.patch(CANNED_ADDR, blob, "canned response")
        p.patch(STUB_ADDR, build_recv_stub(labels, CANNED_ADDR, len(blob)),
                "tls_recv stub")
        p.patch(DRIVER_ADDR, build_driver(labels), "driver")

        # Transport patches. net_poll -> RTS keeps a tick in the tens of
        # cycles; without it the silent-socket case is a ~87 minute test.
        p.patch(labels["net_poll"], bytes([0x60]), "net_poll RTS patch")
        lo, hi = _lohi(STUB_ADDR)
        p.patch(labels["tls_recv"], bytes([0x4C, lo, hi]), "tls_recv JMP")

        p.patch(labels["http_body_sink"], bytes([0x00]), "sink off")

        # PREDICATES vs OUTPUTS, and the distinction is load-bearing.
        #
        # http_cl_valid and http_chunked are bytes the verdict BRANCHES
        # on, not values it reports. Poison is the wrong tool for those:
        # a non-zero poison byte is indistinguishable from a real flag, so
        # a poisoned predicate silently steers the routine down an arm the
        # case was not written to test. Both are therefore set to ZERO --
        # the state boot leaves and the state http_hdr_init writes -- so
        # every case starts from "no framing seen" and only the parser can
        # turn a flag on.
        #
        # This is not hypothetical. Reviewed against an earlier draft that
        # poisoned them, the "nothing ever arrived" case was red by two
        # contaminants cancelling: chunked=1 inherited from the previous
        # case would have sent the guard-less path to sec (masking the
        # mutant), while cl_valid=$A5 sent it to http_body_done_check
        # first, where two equal poisoned 24-bit values compared equal and
        # returned clc (restoring the red). A reorder, a different poison
        # byte, or a case inserted before it would have flipped that
        # silently -- in a suite whose entire subject is silent false
        # success.
        #
        # http_status, http_body_total and http_content_length ARE outputs:
        # they stay poisoned, so a routine that never ran cannot be
        # mistaken for one that ran and agreed with us.
        p.patch(LATCH_ADDR, bytes([POISON]), "carry latch")
        p.patch(labels["http_status"], bytes([POISON, POISON]), "status")
        p.patch(labels["http_body_total"], bytes([POISON] * 3), "body_total")
        p.patch(labels["http_content_length"], bytes([POISON] * 3), "cl")
        p.patch(labels["http_cl_valid"], bytes([0x00]), "cl_valid predicate")
        p.patch(labels["http_chunked"], bytes([0x00]), "chunked predicate")

        jsr(transport, DRIVER_ADDR, timeout=timeout)

        carry = read_bytes(transport, LATCH_ADDR, 1)[0]
        if carry not in (0, 1):
            raise RuntimeError(
                f"carry latch never written (read ${carry:02X}) — the driver "
                f"did not complete; inconclusive, not a pass"
            )

        def u24(name):
            b = read_bytes(transport, labels[name], 3)
            return b[0] | (b[1] << 8) | (b[2] << 16)

        st = read_bytes(transport, labels["http_status"], 2)
        result = {
            "carry": carry,
            "body_total": u24("http_body_total"),
            "content_length": u24("http_content_length"),
            "cl_valid": read_bytes(transport, labels["http_cl_valid"], 1)[0],
            "chunked": read_bytes(transport, labels["http_chunked"], 1)[0],
            "parse_state": read_bytes(transport,
                                      labels["http_parse_state"], 1)[0],
            "status": st[0] | (st[1] << 8),
        }

        # The span the parser read from must be unchanged; if this scratch
        # block is not free, the case measured something else.
        back = read_bytes(transport, CANNED_ADDR, len(blob)) if blob else b""
        if back != blob:
            raise RuntimeError(
                f"canned response at ${CANNED_ADDR:04X} was modified during "
                f"the run — that scratch block is not free; inconclusive"
            )
        return result
    finally:
        p.restore()


def run_carry_propagation_case(transport, labels) -> dict:
    """Does http_get let a failing http_recv_body reach its caller?

    Stub http_recv_body -> SEC/RTS and both closes -> RTS, then JSR at the
    `jsr http_recv_body` instruction inside http_get and latch the carry
    that arrives at http_get's own RTS. Unfixed (unconditional `clc`)
    latches 0; fixed (php/plp) latches 1.
    """
    site, next_byte = find_http_get_recv_site(labels)
    p = Patcher(transport)
    try:
        p.patch(labels["http_recv_body"], bytes([0x38, 0x60]), "recv_body SEC")
        p.patch(labels["tls_close"], bytes([0x60]), "tls_close RTS")
        p.patch(labels["net_tcp_close"], bytes([0x60]), "net_tcp_close RTS")
        r_lo, r_hi = _lohi(LATCH_ADDR)
        p.patch(DRIVER_ADDR, bytes([
            0x20, site & 0xFF, (site >> 8) & 0xFF,
            0xA9, 0x00, 0x2A,
            0x8D, r_lo, r_hi,
            0x60,
        ]), "carry-propagation driver")
        p.patch(LATCH_ADDR, bytes([POISON]), "carry latch")

        jsr(transport, DRIVER_ADDR, timeout=60.0)
        carry = read_bytes(transport, LATCH_ADDR, 1)[0]
        if carry not in (0, 1):
            raise RuntimeError(
                f"carry latch never written (read ${carry:02X}) — "
                f"inconclusive, not a pass"
            )
        return {"carry": carry, "site": site, "next_byte": next_byte}
    finally:
        p.restore()


def run_tests(transport, labels) -> tuple[int, int]:
    passed = failed = 0

    assert_shadow_ram_readable(transport, labels)
    print("  shadow RAM readable (positive control OK)")

    # (name, content_length, body_len, chunked, expect_carry, why)
    cases = [
        (
            "short body — Content-Length seen, consumed count below it",
            160000, 32, False, 1,
            "the tick budget expiring is not evidence the body ended; "
            "159,968 B short must not read as a complete HTTP 200",
        ),
        (
            "chunked body — terminal chunk never arrived",
            None, 32, True, 1,
            "the other framing arm: chunked termination is the 0-length "
            "chunk, and the budget expiring is not one",
        ),
        (
            "nothing ever arrived — no status line, no headers, no body",
            None, 0, False, 1,
            "returned C=0 with http_status=0 through the unframed arm "
            "until the parse-state guard; found by adversarial review",
        ),
        (
            "complete body (control — green before AND after the fix)",
            32, 32, False, 0,
            "proves the rig actually drives the parser: a suite that "
            "measures nothing would report every case as it pleases",
        ),
    ]

    for name, clen, blen, chunked, expect_carry, why in cases:
        # blob=b"" is the "nothing arrived" case: an empty span, not a
        # response with an empty body -- the latter is just another short
        # body and would not reach the unframed arm at all.
        nothing = name.startswith("nothing")
        blob = b"" if nothing else None
        r = run_case(transport, labels, clen, blen, chunked, blob=blob)

        checks = []
        if nothing:
            # Nothing was received at all: the parser never left state 0,
            # and the framing bytes are still the zeros we set -- so the
            # verdict reached its unframed arm and only the parse-state
            # guard can have produced C=1.
            checks.append(("parser never reached the body",
                           r["parse_state"] < 2))
            checks.append(("reached the unframed arm (no framing seen)",
                           r["cl_valid"] == 0 and r["chunked"] == 0))
            # Outputs still poisoned: nothing wrote them, so the C=1 came
            # from the parse-state guard and from nothing else.
            checks.append(("outputs untouched (body_total, Content-Length)",
                           r["body_total"] == 0xA5A5A5
                           and r["content_length"] == 0xA5A5A5))
        elif chunked:
            checks.append(("status parsed as 200", r["status"] == 200))
            checks.append(("chunked framing seen", r["chunked"] == 1))
            checks.append((f"body consumed == {blen}",
                           r["body_total"] == blen))
        else:
            checks.append(("status parsed as 200", r["status"] == 200))
            checks.append(("Content-Length seen", r["cl_valid"] == 1))
            checks.append((f"Content-Length == {clen}",
                           r["content_length"] == clen))
            checks.append((f"body consumed == {blen}",
                           r["body_total"] == blen))
        want = "C=1 (short/failed)" if expect_carry else "C=0 (complete)"
        checks.append((f"carry {want}", r["carry"] == expect_carry))
        if name.startswith("nothing"):
            # http_status keeps its poison: the parser never wrote it, so
            # nothing was parsed at all. (Pre-guard this case returned C=0
            # with a status the caller had no reason to trust.)
            checks.append(("http_status untouched (nothing was parsed)",
                           r["status"] == (POISON << 8) | POISON))

        ok = all(good for _, good in checks)
        print(f"\n  [{'+' if ok else '-'}] {name}")
        print(f"        {why}")
        print(f"        parse_state={r['parse_state']} status={r['status']} "
              f"cl_valid={r['cl_valid']} chunked={r['chunked']} "
              f"content_length={r['content_length']} "
              f"body_total={r['body_total']} "
              f"carry=C={r['carry']}")
        for label, good in checks:
            if not good or VERBOSE:
                print(f"        {'ok  ' if good else 'FAIL'} {label}")
        passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)

    # --- hunk 3: http_get must not discard the verdict ---------------------
    r = run_carry_propagation_case(transport, labels)
    # $20 = the next instruction is still a JSR (unfixed: jsr tls_close);
    # $08 = PHP (fixed). Anything else means the image scan found the
    # wrong call site and this case measured nothing.
    site_ok = r["next_byte"] in (0x20, 0x08)
    carry_ok = r["carry"] == 1
    ok = site_ok and carry_ok
    print(f"\n  [{'+' if ok else '-'}] http_get propagates a failing receive "
          f"to its caller")
    print("        a caller that cannot fail cannot be trusted; this is the "
          "shipped entry point the rigs drive")
    print(f"        site=${r['site']:04X} next_byte=${r['next_byte']:02X} "
          f"carry=C={r['carry']}")
    if not site_ok:
        print("        FAIL call-site scan landed on ${:02X}, expected $20 "
              "(unfixed) or $08 (PHP) — inconclusive"
              .format(r["next_byte"]))
    if not carry_ok:
        print("        FAIL carry C=1 (http_recv_body reported failure)")
    passed, failed = (passed + 1, failed) if ok else (passed, failed + 1)

    return passed, failed


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main() -> int:
    global VERBOSE
    os.chdir(PROJECT_ROOT)

    if "--verbose" in sys.argv:
        VERBOSE = True

    if os.environ.get("C64_SKIP_BUILD"):
        print("\n=== Building (skipped: C64_SKIP_BUILD set) ===")
    else:
        print("\n=== Building ===")
        subprocess.run(["make", "clean"], capture_output=True)
        result = subprocess.run(["make"], capture_output=True, text=True)
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
        # A missing label means the routine under test moved or was
        # renamed. That is a failure, never a silent skip (audit F3).
        print(f"FATAL: required label(s) not found: {', '.join(missing)}")
        return 1

    print("\n=== Labels ===")
    for name in REQUIRED_LABELS:
        print(f"  {name:<22} = ${labels[name]:04X}")

    print("\n=== Starting VICE ===")
    config = default_vice_config(prg_path=PRG_PATH, warp=True, ntsc=True,
                                sound=False)

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"  VICE PID={inst.pid}, port={inst.port}")

        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=120.0, verbose=False)
        if grid is None:
            print("FATAL: Main menu did not appear")
            mgr.release(inst)
            return 1
        print("  Main menu ready")

        print("\n=== http_recv_body body-termination (issue #211) ===")
        try:
            passed, failed = run_tests(transport, labels)
        finally:
            mgr.release(inst)

    total = passed + failed
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    if failed == 0:
        print(f"\n  [+] Body truncation: ALL {total} TESTS PASSED")
    else:
        print(f"\n  [-] Body truncation: {failed} TEST(S) FAILED")
    print("=" * 60)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
