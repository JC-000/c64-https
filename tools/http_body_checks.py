#!/usr/bin/env python3
"""tools/http_body_checks.py — is the fetched HTTP body COMPLETE?

Why this module exists
======================
`tools/uci/rig_https_banner.py` is the only rig that executes
`do_https_get` — the menu path a human drives — and until now its body
check was a hardcoded literal that could not fail the run (issue #210)::

    if total >= 125_000: ...          # "body complete"
    ...
    ok = total >= 125_000             # computed, then never used
    verdict = 0 if (names_target and not says_foobar) else 1

Two defects with one cause. The threshold was a stale figure about
*someone else's user-editable content* (125,703 B measured on 2026-09-07,
so a complete fetch printed "body stalled"), and the `ok` it computed was
discarded before the verdict. A run reaching 73,720 B of ~125,703 B
printed `WARNING: body stalled` and `PASS`, exit 0. That is why the
silent-truncation defect (#211) went unnoticed for as long as it did: the
one rig on the path could not go red on it.

The fix is not a better literal. Any literal about a remote document is a
stale figure with a delayed fuse. **The response frames its own length**,
and the C64 has already parsed that framing — so the oracle asks the same
question the client asks, off the same parser state, over DMA:

    Content-Length seen -> complete exactly when the 24-bit consumed
        count `http_body_total` equals the 24-bit `http_content_length`.
    chunked             -> complete exactly when the TERMINAL (zero-size)
        chunk was seen, i.e. `http_chunk_state` reached 4.
    neither             -> INCONCLUSIVE. A `Connection: close` stream with
        no length and no chunking carries no completeness signal at all;
        saying "pass" there would be inventing one.

RELATION TO `http_recv_timeout_verdict` (`src/http.s`) — TWO OF FOUR ARMS
MATCH, AND THE OTHER TWO DIVERGE ON PURPOSE. An earlier draft of this file
claimed the two "mirror branch for branch". They do not, and the claim was
wrong in a way that reads as reassuring, so it is spelled out instead:

  parse_state < 2   MATCHES. 6502: `cmp #2 / bcc @to_short` -> `sec`.
  Content-Length    MATCHES, including the PRECEDENCE: both test
                    `http_cl_valid` before `http_chunked`, and both then
                    compare the 24-bit consumed count against the 24-bit
                    length (the 6502 by tail-calling `http_body_done_check`).
                    `test_the_6502_verdict_keeps_the_shape_this_mirrors`
                    pins that order against `src/http.s`; without it,
                    reversing the two arms in the 6502 leaves every
                    host-side test green (measured).
  chunked           DIVERGES. 6502: `lda http_chunked / bne @to_short` —
                    an UNCONDITIONAL reject that never reads
                    `http_chunk_state`. Correct there, because that code
                    only runs when the tick budget expired, and a chunked
                    response that reached the budget is short by
                    construction. This module is read at an ARBITRARY
                    moment, including after the parser's own success exit,
                    so it needs a positive completeness signal rather than
                    the absence of one: `http_chunk_state == 4`.
  neither framing   DIVERGES. 6502: `clc` — the PRG must return something
                    and "accept whatever we have" is right for a
                    Connection: close stream. A rig is under no such
                    obligation, so this reports INCONCLUSIVE.

The two artefacts answer different questions at different moments: the
6502 answers "the budget just expired — what carry do I hand my caller",
this answers "looking at the machine now, is the body complete". Where
that difference does not apply the answers must agree, and the
Content-Length precedence is pinned so that it keeps agreeing.

What this can and cannot support
================================
Every input here is C64-side parser state read over DMA. It observes what
the client CONSUMED and what framing the client BELIEVES it was given. It
does not observe what the server sent. So:

  * `check_body_complete` failing is strong: the client parsed a
    `Content-Length` (or a chunked stream) and then stopped short of it.
    Nothing about the server's behaviour is needed to call that a defect —
    #211 is exactly this, and it stays open for the CAUSE.
  * `check_body_complete` passing is a statement about framing agreement,
    not about byte-for-byte fidelity. It does not prove the bytes are the
    ones the server sent; only a wire capture or a content compare does
    (`tools/ip65_hw_checks.py::check_http_response` is that, for a
    fixture-sized body).

Reads of `$A000-$BFFF` follow the machine's banking
===================================================
Every symbol here lives in `CRYPTO_COLD_SHADOW` (RAM under the BASIC ROM;
`http_body_total` is at `$A858` on the uci-onchip build). A host DMA read
of that span returns ROM bytes whenever `$01` bit 0 is set — plausible
values, consistently wrong. `boot.s` banks the ROM out for runtime
operation. Callers must prove it did: use
`ip65_hw_checks.check_shadow_ram_readable` on a read of `$A000` before
trusting anything below, which is why the rig reads it and this module
does not silently assume it.

Pure functions over bytes; `tools/test_http_body_checks_unit.py` feeds
each one a known-bad input and requires it to fail, and
`tools/mutate_http_body_checks.py` breaks each verdict in turn to prove
that suite can go red.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ip65_hw_checks import Verdict  # noqa: E402  (re-used, not re-invented)

__all__ = [
    "BodyState",
    "CHUNK_STATE_TERMINAL",
    "PARSE_STATE_BODY",
    "SYMBOLS",
    "EXIT_FAIL",
    "EXIT_INCONCLUSIVE",
    "EXIT_PASS",
    "check_body_complete",
    "check_fetch_settled",
    "check_http_status",
    "decide_exit",
    "decode_body_state",
    "expected_body_size",
]

#: `http_recv_response`'s state machine (src/http.s): 0 = status line,
#: 1 = headers, 2 = body. Anything below 2 means the response never
#: reached a body at all.
PARSE_STATE_BODY = 2

#: `http_state_body_chunked`'s sub-state 4: the terminal zero-size chunk
#: has been seen and the parser is skipping trailer lines. It is the last
#: state the machine enters and it does not leave it, so "reached 4" is
#: the durable, DMA-observable form of "the server said the body ended".
CHUNK_STATE_TERMINAL = 4

#: name -> width in bytes, as laid out by src/http.s. Callers resolve the
#: addresses through build/labels.txt; the widths are a property of the
#: source and belong with the decoder that reads them.
SYMBOLS = {
    "http_parse_state": 1,
    "http_status": 2,
    "http_cl_valid": 1,
    "http_content_length": 3,   # 24-bit, W4 (bodies exceed 64 KB)
    "http_body_total": 3,       # 24-bit CONSUMED count
    "http_chunked": 1,
    "http_chunk_state": 1,
}


@dataclass
class BodyState:
    """The C64-side HTTP parser state, as read over DMA."""
    parse_state: int
    status: int
    cl_valid: int
    content_length: int
    body_total: int
    chunked: int
    chunk_state: int

    def summary(self) -> str:
        framing = ("Content-Length" if self.cl_valid
                   else "chunked" if self.chunked else "unframed")
        return (f"parse_state={self.parse_state} status={self.status} "
                f"framing={framing} content_length={self.content_length:,} "
                f"body_total={self.body_total:,} "
                f"chunk_state={self.chunk_state}")


def _le(raw: bytes) -> int:
    return int.from_bytes(bytes(raw), "little")


def decode_body_state(raw: dict) -> BodyState:
    """Build a `BodyState` from {symbol name: bytes read over DMA}.

    Refuses a short read rather than padding it: a read that returned
    fewer bytes than the symbol is wide is a transport problem, and
    silently zero-extending it would turn one into a plausible verdict.
    """
    missing = sorted(set(SYMBOLS) - set(raw))
    if missing:
        raise KeyError(f"no DMA read supplied for {missing}")
    for name, width in SYMBOLS.items():
        if len(bytes(raw[name])) != width:
            raise ValueError(
                f"{name}: read {len(bytes(raw[name]))} bytes, expected {width}")
    return BodyState(
        parse_state=_le(raw["http_parse_state"]),
        status=_le(raw["http_status"]),
        cl_valid=_le(raw["http_cl_valid"]),
        content_length=_le(raw["http_content_length"]),
        body_total=_le(raw["http_body_total"]),
        chunked=_le(raw["http_chunked"]),
        chunk_state=_le(raw["http_chunk_state"]),
    )


def expected_body_size(state: BodyState):
    """The body size the RESPONSE ITSELF declares, or None.

    #210's "derive expected size from the response's own framing rather
    than a literal". `None` is the honest answer for a chunked or unframed
    response: chunked never declares a total, so its completeness question
    is "did the terminal chunk arrive", not "how many bytes".
    """
    if state.cl_valid:
        return state.content_length
    return None


def check_http_status(state: BodyState, expect: int = 200) -> Verdict:
    """The response carried the status the caller expected.

    Separate from completeness on purpose: a 404 whose short body is
    complete is a different failure from a 200 whose body is truncated,
    and a rig that folds them together cannot report which it saw.
    """
    ev = {"status": state.status, "expected": expect}
    if state.parse_state < PARSE_STATE_BODY:
        return Verdict(False, f"the parser never reached the body "
                              f"(parse_state={state.parse_state}); there is no "
                              "status line to believe", ev)
    if state.status != expect:
        return Verdict(False, f"HTTP {state.status}, expected {expect}", ev)
    return Verdict(True, f"HTTP {state.status}", ev)


def check_body_complete(state: BodyState) -> Verdict:
    """The body is complete BY THE RESPONSE'S OWN FRAMING.

    Two of its four arms match `http_recv_timeout_verdict` (src/http.s)
    and two diverge deliberately — the module docstring has the table, and
    is the authority. Do not restore the "same branches, same order" line
    that used to stand here: it was wrong about half of them, it is what a
    hover or `help()` shows, and it contradicted the file it sits in.
    """
    ev = {
        "parse_state": state.parse_state,
        "status": state.status,
        "cl_valid": state.cl_valid,
        "content_length": state.content_length,
        "body_total": state.body_total,
        "chunked": state.chunked,
        "chunk_state": state.chunk_state,
        "expected": expected_body_size(state),
    }

    if state.parse_state < PARSE_STATE_BODY:
        return Verdict(False,
                       f"the response never reached the body "
                       f"(parse_state={state.parse_state}): the status line or "
                       "header block was cut short, so there is no body that "
                       "could be complete", ev)

    if state.cl_valid:
        if state.body_total == state.content_length:
            return Verdict(True, f"body complete: {state.body_total:,} B "
                                 "consumed == Content-Length", ev)
        if state.body_total < state.content_length:
            short = state.content_length - state.body_total
            return Verdict(False,
                           f"TRUNCATED: {state.body_total:,} B consumed of a "
                           f"declared Content-Length of "
                           f"{state.content_length:,} B — {short:,} B short "
                           "(issue #211)", ev)
        return Verdict(False,
                       f"OVER-READ: {state.body_total:,} B consumed against a "
                       f"declared Content-Length of {state.content_length:,} B. "
                       "The parser consumed past the framing it was given; "
                       "that is a framing bug, not a short body", ev)

    if state.chunked:
        if state.chunk_state == CHUNK_STATE_TERMINAL:
            return Verdict(True, f"body complete: terminal chunk seen after "
                                 f"{state.body_total:,} B", ev)
        return Verdict(False,
                       f"TRUNCATED: chunked response stopped in chunk_state="
                       f"{state.chunk_state} after {state.body_total:,} B; the "
                       "terminal zero-size chunk never arrived (issue #211)",
                       ev)

    return Verdict(False,
                   f"INCONCLUSIVE: the response declared neither "
                   f"Content-Length nor chunked framing, so nothing in it says "
                   f"how long the body should be. {state.body_total:,} B were "
                   "consumed and that may be all of it — but this run cannot "
                   "tell, and a threshold invented here would be exactly the "
                   "stale literal #210 removed", ev, status="inconclusive")


def check_fetch_settled(progressing: bool, elapsed: float,
                        budget: float) -> Verdict:
    """The fetch had STOPPED advancing when the state above was read.

    Without this, a poll budget that is merely too short reports a
    TRUNCATED body, and the rig goes red for a reason that has nothing to
    do with the client. Measured on the first hardware run of the new
    oracle (2026-09-07, U64E @ 48 MHz): en.wikipedia.org served a
    754,413 B identity body and the 300 s budget expired at 591,417 B while
    `http_body_total` was still climbing. RATE, corrected: the loop polls
    every 2 s but PRINTS every 15 s, so the ~38.4 KB between printed lines
    is ~2.56 KB/s, not the ~19 KB/s an earlier version of this docstring
    read off them; 591,417 B in 300 s is ~2.0 KB/s and agrees. An operator
    sizing FETCH_TIMEOUT off the wrong figure sets it ~7x too small and
    gets 78 every time. The completeness verdict was correct about the
    bytes and wrong about the meaning.

    WHAT THIS DOES AND DOES NOT COVER. `settled` is deliberately NOT in
    the caller's `checks` list: it can only turn a FAIL into a 78, never
    turn anything into a PASS, so it cannot hide a truncation. Its blind
    spot is a truncation whose last byte lands inside STALL_GRACE of the
    deadline, which would be reported inconclusive instead of failed —
    bounded by STALL_GRACE / FETCH_TIMEOUT (~3% at the defaults, if
    stalls were uniform in time). They are not: both observed #211 stalls
    were ABRUPT, the counter freezing and staying frozen for hundreds of
    seconds, which is what #219's fast-expiry path predicts.

    So a still-growing body at the deadline is INCONCLUSIVE, never a
    failure — and never a pass either: nothing was established. A body
    that has stopped advancing is a settled observation, and #211's
    verdict is then about the client.
    """
    ev = {"progressing": progressing, "elapsed": elapsed, "budget": budget}
    if progressing:
        return Verdict(False,
                       f"INCONCLUSIVE: the {budget:.0f}s poll budget expired "
                       "while the body was still growing. That is a budget, "
                       "not a defect — re-run with a larger FETCH_TIMEOUT "
                       "before reading anything into the byte count",
                       ev, status="inconclusive")
    return Verdict(True, "the fetch had stopped advancing when the state was "
                         "read, so the completeness verdict is about the "
                         "client, not the clock", ev)


# ===========================================================================
# The exit-code decision
# ===========================================================================
#: `tests/rig_ip65_rrnet_hw.py` uses 78 for "we could not look". It is
#: sysexits' EX_CONFIG; the number is borrowed for its established meaning
#: in this repo, not for its POSIX name. What matters is that an
#: inconclusive verdict shares an exit code with neither a pass nor a fail.
EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_INCONCLUSIVE = 78


def decide_exit(banner_ok: bool, shadow: Verdict, settled: Verdict,
                status, body):
    """Turn the verdicts into (exit code, report lines).

    THIS LIVES HERE, NOT IN THE RIG, AND THAT PLACEMENT IS THE POINT.
    While it was five lines at the bottom of `rig_https_banner.py` the only
    thing testing it was an AST guard, and an adversarial review found five
    one-token mutants that kept the guard green — `any(` -> `all(`,
    `return EXIT_FAIL` -> `EXIT_PASS`, `[shadow, status, body][:2]`, and two
    dead conjuncts. Two of those restore #210 exactly: exit 0 on a body the
    rig has just reported as truncated. A guard that proves a name reaches
    the test of an `if` cannot see any of that, because none of them move
    the name.

    Here it is a pure function of five verdicts, so it is EXECUTED against
    known-bad inputs like every other check in this module, and the mutants
    above are ordinary module-side mutants that the suite reddens on.

    Ordering, and why `settled` is not in `checks`:

      1. banner wrong                      -> FAIL. The rig's original job.
      2. the fetch was still growing       -> INCONCLUSIVE, ahead of the
         fail arm: `body` then says TRUNCATED while describing the poll
         budget, and reporting that as a failure is how a rig cries wolf.
      3. any verdict failed, or is missing -> FAIL. A verdict that was
         never evaluated is a failure, never a skip.
      4. any verdict inconclusive          -> INCONCLUSIVE.
      5. otherwise                         -> PASS.

    `settled` can therefore only turn a FAIL into an INCONCLUSIVE. It can
    never turn anything into a PASS, so it cannot hide a truncation.
    """
    checks = [shadow, status, body]
    lines = [
        "=== VERDICT ===",
        f"  banner names the build target    : {'PASS' if banner_ok else 'FAIL'}",
    ]
    for label, v in (("shadow RAM readable ($A000)", shadow),
                     ("fetch settled (not still growing)", settled),
                     ("HTTP status", status),
                     ("body complete (own framing)", body)):
        lines.append(f"  {label:<33}: "
                     + ("FAIL (never evaluated)" if v is None
                        else f"{v.status.upper()} — {v.reason}"))

    if not banner_ok:
        return EXIT_FAIL, lines + [
            "FAIL: banner did not name the real target"]
    if settled is None:
        return EXIT_FAIL, lines + [
            "FAIL: the still-growing check was never evaluated"]
    if settled.inconclusive:
        return EXIT_INCONCLUSIVE, lines + [
            "INCONCLUSIVE: the poll budget expired mid-body — raise "
            "FETCH_TIMEOUT and re-run; nothing here is a verdict on the "
            "client"]
    if any(v is None or v.status == "fail" for v in checks):
        return EXIT_FAIL, lines + [
            "FAIL: the banner is right but the fetch is not — see the "
            "verdict block above"]
    if any(v.inconclusive for v in checks):
        return EXIT_INCONCLUSIVE, lines + [
            "INCONCLUSIVE: nothing failed, but completeness could not be "
            "established — this is NOT a pass"]
    return EXIT_PASS, lines + [
        "PASS: banner names the real target and the body is complete by "
        "its own framing"]
