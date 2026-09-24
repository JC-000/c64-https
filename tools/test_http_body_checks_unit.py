#!/usr/bin/env python3
"""tools/test_http_body_checks_unit.py — prove the #210 oracle can go RED.

`tools/http_body_checks.py` is the completeness verdict that
`tools/uci/rig_https_banner.py` now gates on. The thing it replaced —
`total >= 125_000`, computed into an `ok` that was then discarded — is the
canonical shape of a check that cannot fail, so a replacement asserted
only by "it passed on hardware once" would prove nothing at all.

Every verdict here is therefore fed a KNOWN-BAD input off-device and
required to fail, and `test_every_check_has_a_red_case` enforces by
introspection that no `check_*` can be added to the module without one.
`tools/mutate_http_body_checks.py` goes one step further and breaks each
branch in the running module to show this suite reddens.

No VICE, no hardware, no build, no network; milliseconds.

    pytest tools/test_http_body_checks_unit.py
    python3 tools/test_http_body_checks_unit.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))

import http_body_checks as hbc  # noqa: E402

#: Every `check_*` in the module must appear here, mapped to the test that
#: feeds it a known-bad input. test_every_check_has_a_red_case() enforces it.
RED_CASES = {
    "check_body_complete": "test_body_complete_red_green",
    "check_http_status": "test_http_status_red_green",
    "check_fetch_settled": "test_fetch_settled_red_green",
}

#: `decide_exit` is not a `check_*` and so is outside RED_CASES, but it is
#: the function that turns four verdicts into the number CI reads. Its red
#: cases are test_decide_exit_red_green.


def state(**kw) -> hbc.BodyState:
    """A BodyState with a COMPLETE Content-Length response as the base.

    Defaults matter here: each red case below overrides exactly one field,
    so what it proves is that *that* field is what the verdict turned on.
    A red case that changes three things at once cannot distinguish a
    working check from one that alarms on any of them.
    """
    base = dict(parse_state=2, status=200, cl_valid=1,
                content_length=125_703, body_total=125_703,
                chunked=0, chunk_state=0)
    base.update(kw)
    return hbc.BodyState(**base)


# ===========================================================================
# The verdicts
# ===========================================================================
def test_body_complete_red_green() -> None:
    """Every branch of the completeness verdict, green and red."""
    # --- Content-Length framing -------------------------------------------
    v = hbc.check_body_complete(state())
    assert v.ok and v.status == "pass", v.reason

    # THE #210 CASE, verbatim: the run the issue quotes reached 73,720 B of
    # ~125,703 B, printed "WARNING: body stalled" and "PASS", exit 0.
    v = hbc.check_body_complete(state(body_total=73_720))
    assert not v.ok, "a 51,983 B shortfall must not read as a complete body"
    assert v.status == "fail"
    assert "51,983 B short" in v.reason, v.reason

    # And the trap the old literal had: a COMPLETE body below the stale
    # threshold. `>= 125_000` would have called 124,000/124,000 a stall.
    v = hbc.check_body_complete(state(content_length=124_000,
                                      body_total=124_000))
    assert v.ok, "a complete body must pass regardless of its size"

    # ...while a body that is one byte short is not complete, however big.
    v = hbc.check_body_complete(state(body_total=125_702))
    assert not v.ok, "one byte short is still short"

    # Consuming PAST the declared length is a framing bug, not a pass.
    v = hbc.check_body_complete(state(body_total=125_704))
    assert not v.ok and "OVER-READ" in v.reason, v.reason

    # --- chunked framing ---------------------------------------------------
    chunked = dict(cl_valid=0, content_length=0, chunked=1)
    v = hbc.check_body_complete(state(**chunked,
                                      chunk_state=hbc.CHUNK_STATE_TERMINAL))
    assert v.ok, v.reason
    # SYNTHETIC, and worth saying so: both hardware runs of this rig saw
    # `framing=Content-Length` (identity, 754,413 B) from en.wikipedia.org,
    # not chunked. #211's live captures were chunked. The wire shape is the
    # server's choice and both are reachable, so both arms are covered
    # here; no run on this branch has exercised the chunked arm on
    # hardware. Stopped mid-payload (sub-state 2) => no terminal chunk.
    for stalled in (0, 1, 2, 3):
        v = hbc.check_body_complete(state(**chunked, chunk_state=stalled))
        assert not v.ok, f"chunk_state={stalled} is not a terminal chunk"
        assert v.status == "fail"

    # A chunked body is NOT judged by byte count: no size, no threshold.
    assert hbc.expected_body_size(
        state(**chunked, chunk_state=hbc.CHUNK_STATE_TERMINAL)) is None

    # --- the response never reached a body ---------------------------------
    for ps in (0, 1):
        v = hbc.check_body_complete(state(parse_state=ps))
        assert not v.ok, f"parse_state={ps} never reached the body"
    # Zero bytes received, with the header state's zeroed framing: the
    # shape that returned C=0 with http_status=0 before PR #219.
    v = hbc.check_body_complete(
        hbc.BodyState(parse_state=0, status=0, cl_valid=0, content_length=0,
                      body_total=0, chunked=0, chunk_state=0))
    assert not v.ok, "a fetch that received nothing is not a complete body"

    # --- neither framing: INCONCLUSIVE, and it fails closed ----------------
    v = hbc.check_body_complete(state(cl_valid=0, content_length=0, chunked=0,
                                      body_total=40_000))
    assert v.status == "inconclusive", v.reason
    assert not v.ok, ("an inconclusive verdict must fail closed for a caller "
                      "that branches on .ok — that is the whole point of the "
                      "three-state Verdict")

    # --- the PRG's own precedence is mirrored, not re-invented -------------
    # src/http.s tests http_cl_valid BEFORE http_chunked. A response with
    # both set is judged by Content-Length in the PRG, so it is judged by
    # Content-Length here; a rig that answered "chunked, terminal chunk
    # missing" would report a failure the client does not believe in.
    v = hbc.check_body_complete(state(chunked=1, chunk_state=0))
    assert v.ok, ("cl_valid must take precedence over chunked, as it does in "
                  "http_recv_timeout_verdict")


def test_http_status_red_green() -> None:
    assert hbc.check_http_status(state()).ok
    v = hbc.check_http_status(state(status=404))
    assert not v.ok and "404" in v.reason, v.reason
    v = hbc.check_http_status(state(status=301), expect=301)
    assert v.ok
    # A status read out of a parser that never got past the headers is not
    # a status at all.
    v = hbc.check_http_status(state(parse_state=1, status=200))
    assert not v.ok, "parse_state=1 has no status line to believe"


def test_fetch_settled_red_green() -> None:
    """A body still growing at the deadline is inconclusive, not a failure.

    The case that forced this check to exist: 2026-09-07, U64E @ 48 MHz,
    en.wikipedia.org served 754,413 B identity and the 300 s budget expired
    at 591,417 B with `http_body_total` climbing ~39 KB per tick. The
    completeness verdict said TRUNCATED and was describing the rig's own
    budget.
    """
    v = hbc.check_fetch_settled(False, 300.0, 300.0)
    assert v.ok and v.status == "pass", v.reason
    v = hbc.check_fetch_settled(True, 300.0, 300.0)
    assert v.status == "inconclusive", v.reason
    assert not v.ok, ("a still-growing fetch is not a pass either -- nothing "
                      "was established")
    assert "FETCH_TIMEOUT" in v.reason, (
        "the message must tell the operator what to change; a bare "
        "INCONCLUSIVE gets re-run identically")


# ===========================================================================
# When the poll loop may stop early (#226)
# ===========================================================================
def test_should_stop_early_red_green() -> None:
    """Stop only when the budget-expiry verdict is already fixed.

    #226's measured run: 299,123 B of a declared 754,413 B, frozen, polled
    for ~700 s. Each red case below removes exactly one condition from
    that shape and requires the loop to KEEP polling, because each is a
    way an early stop could turn a slow-but-healthy fetch into a FAIL.
    """
    stop = hbc.should_stop_early
    ab = hbc.STALL_ABORT
    frozen = state(content_length=754_413, body_total=299_123)

    # GREEN: the #226 shape, on a dead socket, past the threshold.
    for sock in (hbc.NET_TCP_ERROR, hbc.NET_TCP_CLOSED):
        ok, why = stop(frozen, sock, ab)
        assert ok, why
        assert "budget not exhausted" in why, (
            "an early stop must say so, or a reader cannot tell it from a "
            "budget that ran out")
        assert "299,123" in why, why
    # Chunked with no terminal chunk is a definite expectation too.
    ok, _ = stop(state(cl_valid=0, content_length=0, chunked=1,
                       chunk_state=2), hbc.NET_TCP_ERROR, ab)
    assert ok

    # RED: a healthy-but-silent socket is still CONNECTED. That is the
    # slow fetch that must run to the budget, however long it is frozen.
    ok, _ = stop(frozen, hbc.NET_TCP_CONNECTED, 10 * ab)
    assert not ok, "a CONNECTED socket may still deliver the rest"
    # ...and a socket state that could not be read, or is not one we know.
    for sock in (None, 0x03, 0xFF):
        ok, _ = stop(frozen, sock, 10 * ab)
        assert not ok, f"net_tcp_state={sock!r} must not stop the loop"

    # RED: frozen, but not for long enough.
    ok, _ = stop(frozen, hbc.NET_TCP_ERROR, ab - 1)
    assert not ok, "below STALL_ABORT the loop keeps polling"

    # RED: the verdict is not a failure -- a complete body is not "stopped
    # early", it is done, and the loop's own body.ok exit owns that.
    ok, _ = stop(state(), hbc.NET_TCP_CLOSED, 10 * ab)
    assert not ok
    chunk_done = state(cl_valid=0, content_length=0, chunked=1,
                       chunk_state=hbc.CHUNK_STATE_TERMINAL)
    ok, _ = stop(chunk_done, hbc.NET_TCP_CLOSED, 10 * ab)
    assert not ok

    # RED: unframed. Its verdict is INCONCLUSIVE; out of scope for #226.
    ok, _ = stop(state(cl_valid=0, content_length=0, chunked=0),
                 hbc.NET_TCP_CLOSED, 10 * ab)
    assert not ok, "an unframed response has no definite expectation"

    # RED: no body yet. body_total sits at 0 through the whole handshake
    # (minutes; ~35 at 1 MHz). The socket is CONNECTED then, so the socket
    # gate alone would hold -- but it is CLOSED (net_init's zero) in the
    # window before net_tcp_connect, and this gate must not lean on that.
    for ps in (0, 1):
        ok, _ = stop(hbc.BodyState(parse_state=ps, status=0, cl_valid=0,
                                   content_length=0, body_total=0, chunked=0,
                                   chunk_state=0), hbc.NET_TCP_CLOSED, 10 * ab)
        assert not ok, f"parse_state={ps}: the handshake is not a stall"
    # ...even if stale framing bytes claim a length.
    ok, _ = stop(state(parse_state=1, body_total=0), hbc.NET_TCP_CLOSED,
                 10 * ab)
    assert not ok

    # RED: DMA reads of $A000+ were not proven to be RAM.
    ok, _ = stop(frozen, hbc.NET_TCP_ERROR, 10 * ab, shadow_ok=False)
    assert not ok, "ROM bytes are frozen by construction"

    # The margin is far above the grace, and cannot be configured below
    # the floor: an operator typo must not reduce it to the grace's order.
    assert hbc.STALL_ABORT >= hbc.STALL_ABORT_MIN >= 6 * hbc.STALL_GRACE
    for bad in (hbc.STALL_GRACE, hbc.STALL_ABORT_MIN - 1):
        try:
            stop(frozen, hbc.NET_TCP_ERROR, 10 * ab, stall_abort=bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"stall_abort={bad} was accepted")


def test_an_early_stop_decides_what_the_budget_would() -> None:
    """Stopping early changes WHEN, never WHAT: same exit code as expiry.

    The rig sets `settled` from check_fetch_settled(False, ...) on an early
    stop -- the value the deadline path computes for a counter that is
    still frozen -- so decide_exit sees the same five verdicts either way.
    """
    frozen = state(content_length=754_413, body_total=299_123)
    ok, _ = hbc.should_stop_early(frozen, hbc.NET_TCP_ERROR, hbc.STALL_ABORT)
    assert ok
    body = hbc.check_body_complete(frozen)
    shadow = hbc.Verdict(True, "RAM")
    early = hbc.decide_exit(
        banner_ok=True, shadow=shadow, body=body,
        status=hbc.check_http_status(frozen),
        settled=hbc.check_fetch_settled(False, hbc.STALL_ABORT, 900.0))
    expiry = hbc.decide_exit(
        banner_ok=True, shadow=shadow, body=body,
        status=hbc.check_http_status(frozen),
        settled=hbc.check_fetch_settled(False, 900.0, 900.0))
    assert early[0] == expiry[0] == hbc.EXIT_FAIL


def test_net_tcp_states_match_the_source() -> None:
    """The socket-state values should_stop_early trusts are the 6502's."""
    import re
    src = (REPO / "src" / "net" / "net_states.inc").read_text()
    found = {m.group(1): int(m.group(2), 16) for m in re.finditer(
        r"^(NET_TCP_\w+)\s*=\s*\$([0-9A-Fa-f]+)", src, re.M)}
    for name in ("NET_TCP_CLOSED", "NET_TCP_CONNECTED", "NET_TCP_ERROR"):
        assert found.get(name) == getattr(hbc, name), (
            f"{name}: src/net/net_states.inc says {found.get(name)!r}, "
            f"http_body_checks says {getattr(hbc, name)!r}")


def test_stall_tracker_and_early_stop_step() -> None:
    """The loop step, executed: progress tracking, the lazy socket read,
    and the margin passed through.

    These used to be locals in the rig, where dropping the update, or
    measuring from `started`, survived every guard (PR #232 review).
    """
    frozen = state(content_length=754_413, body_total=299_123)
    ab = hbc.STALL_ABORT

    # StallTracker measures from the LAST CHANGE, not from the start.
    t = hbc.StallTracker(100.0)
    assert t.frozen_for(100.0) == 0.0
    t.observe(10, 150.0)
    assert t.frozen_for(400.0) == 250.0, "measured from the last change"
    t.observe(10, 300.0)            # no change -> no reset
    assert t.frozen_for(400.0) == 250.0
    t.observe(11, 390.0)
    assert t.frozen_for(400.0) == 10.0

    # early_stop_step: a counter that moved THIS poll is not frozen, however
    # long ago the run started.
    reads = []

    def dead():
        reads.append(1)
        return hbc.NET_TCP_ERROR

    t = hbc.StallTracker(0.0)
    t.observe(1_000, 0.0)
    stop, _ = hbc.early_stop_step(t, frozen, 10 * ab, dead,
                                  stall_abort=ab, shadow_ok=True)
    assert not stop, "the body moved this poll; it is not frozen"
    assert not reads, "the socket byte is read only past the margin"

    # Frozen since 0, but only ab-1 s: still polling, still no socket read.
    t = hbc.StallTracker(0.0)
    stop, _ = hbc.early_stop_step(t, frozen, 0.0, dead,
                                  stall_abort=ab, shadow_ok=True)
    stop, _ = hbc.early_stop_step(t, frozen, ab - 1, dead,
                                  stall_abort=ab, shadow_ok=True)
    assert not stop and not reads
    # ...and at the margin: one socket read, and the stop.
    stop, why = hbc.early_stop_step(t, frozen, ab, dead,
                                    stall_abort=ab, shadow_ok=True)
    assert stop and reads == [1], why
    # The reported freeze is the MEASURED one, not the threshold: at 3*ab
    # the report must say 3*ab, or the operator reads the margin as data.
    stop, why = hbc.early_stop_step(t, frozen, 3 * ab, dead,
                                    stall_abort=ab, shadow_ok=True)
    assert stop and f"for {3 * ab:.0f}s" in why, why

    # The margin actually passed is the one used (the rig passes the
    # _SCALE'd value): at 4*ab, a 3*ab freeze keeps polling.
    t = hbc.StallTracker(0.0)
    hbc.early_stop_step(t, frozen, 0.0, dead, stall_abort=4 * ab,
                        shadow_ok=True)
    stop, _ = hbc.early_stop_step(t, frozen, 3 * ab, dead,
                                  stall_abort=4 * ab, shadow_ok=True)
    assert not stop, "stall_abort is not honoured"

    # The socket value read is the one decided on, and shadow_ok reaches it.
    for sock, shadow_ok in ((hbc.NET_TCP_CONNECTED, True),
                            (hbc.NET_TCP_ERROR, False)):
        t = hbc.StallTracker(0.0)
        hbc.early_stop_step(t, frozen, 0.0, lambda: sock,
                            stall_abort=ab, shadow_ok=shadow_ok)
        stop, _ = hbc.early_stop_step(t, frozen, 10 * ab, lambda: sock,
                                      stall_abort=ab, shadow_ok=shadow_ok)
        assert not stop, (sock, shadow_ok)


def test_close_confirmed_red_green() -> None:
    """The close wait ends early only on positive, RAM-proven evidence."""
    calls = []

    def sock(v):
        def read():
            calls.append("tcp")
            return v
        return read

    # GREEN: after an early stop, RAM readable, CLOSED.
    assert hbc.close_confirmed(True, lambda: True, sock(hbc.NET_TCP_CLOSED))
    # RED: not an early stop -- the screen marker alone decides, and the
    # byte is not even read.
    calls.clear()
    assert hbc.close_confirmed(False, lambda: True,
                               sock(hbc.NET_TCP_CLOSED)) is None
    assert not calls
    # RED: still ERROR / CONNECTED -- net_tcp_close has not run.
    for v in (hbc.NET_TCP_ERROR, hbc.NET_TCP_CONNECTED):
        assert hbc.close_confirmed(True, lambda: True, sock(v)) is None, v
    # RED: 'Q' at the menu banked BASIC in; $B3BF is ROM. Even a ROM byte
    # that happens to equal CLOSED must not be believed.
    calls.clear()
    assert hbc.close_confirmed(True, lambda: False,
                               sock(hbc.NET_TCP_CLOSED)) is None
    assert not calls, "the socket byte is read only once RAM is proven"


def test_stall_config_error_red_green() -> None:
    """Refused before the lock: a sub-floor STALL_ABORT, or a grace >= it."""
    assert hbc.stall_config_error(hbc.STALL_ABORT, hbc.STALL_GRACE) is None
    assert hbc.stall_config_error(hbc.STALL_ABORT_MIN, hbc.STALL_GRACE) is None
    assert "floor" in hbc.stall_config_error(hbc.STALL_ABORT_MIN - 1,
                                             hbc.STALL_GRACE)
    # A grace at or above the margin: the early stop records "settled"
    # while the deadline path would say "still growing" -- FAIL vs 78.
    for grace in (hbc.STALL_ABORT, hbc.STALL_ABORT + 1):
        msg = hbc.stall_config_error(hbc.STALL_ABORT, grace)
        assert msg and "STALL_GRACE" in msg, grace
    assert hbc.stall_config_error(hbc.STALL_ABORT,
                                  hbc.STALL_ABORT - 1) is None
    # Non-finite: NaN compares False against everything, so it would pass
    # both tests above and stop the loop at 0 s frozen.
    nan, inf = float("nan"), float("inf")
    for abort, grace in ((nan, hbc.STALL_GRACE), (inf, hbc.STALL_GRACE),
                         (hbc.STALL_ABORT, nan), (hbc.STALL_ABORT, -inf)):
        msg = hbc.stall_config_error(abort, grace)
        assert msg and "finite" in msg, (abort, grace)
    try:
        hbc.should_stop_early(state(body_total=1), hbc.NET_TCP_ERROR, 0.0,
                              stall_abort=nan)
    except ValueError:
        pass
    else:
        raise AssertionError("should_stop_early accepted stall_abort=nan")


def test_poll_until_red_green() -> None:
    """The rig's screen wait, executed with a fake clock.

    RED is the lease-poisoning shape: a close wait that ends on its first
    poll while the socket is still CONNECTED releases the lock, and the
    next lane's reset lands on a live firmware socket.
    """
    def run(texts, also=None, budget=10.0):
        t = [0.0]
        polls = []

        def read():
            polls.append(1)
            txt = texts[min(len(polls) - 1, len(texts) - 1)]
            return [txt], txt

        def sleep(dt):
            t[0] += dt
        seen, _ = hbc.poll_until(read, "CONNECTION CLOSED", budget, also,
                                 clock=lambda: t[0], sleep=sleep)
        return seen, len(polls), t[0]

    # GREEN: the marker ends the wait, on the poll that sees it.
    seen, n, _ = run(["...", "...", "CONNECTION CLOSED"])
    assert seen == "'CONNECTION CLOSED' reached" and n == 3, (seen, n)
    # GREEN: close_confirmed's evidence string ends it too.
    seen, n, _ = run(["..."], also=lambda: "net_tcp_state=CLOSED")
    assert seen == "net_tcp_state=CLOSED" and n == 1, (seen, n)

    # RED: no signal -> the wait runs the WHOLE budget, then says None.
    for also in (None, lambda: None, lambda: "", lambda: True,
                 lambda: 1, lambda: ["x"]):
        seen, n, t = run(["..."], also=also, budget=10.0)
        assert seen is None, (also, seen)
        assert t >= 10.0 and n > 1, (
            f"the wait ended after {n} poll(s) / {t}s with no signal")

    # The budget passed is the budget used: not clamped, not a default.
    # (Every case above uses 10 s, so a `min(budget, 10.0)` walked past.)
    seen, n, t = run(["..."], also=lambda: None, budget=37.0)
    assert seen is None and 37.0 <= t < 37.0 + 2.0 + 1e-9, (
        f"a 37 s wait ended at {t}s")

    # A real close_confirmed over a CONNECTED socket is "no signal".
    seen, _, t = run(["..."], also=lambda: hbc.close_confirmed(
        True, lambda: True, lambda: hbc.NET_TCP_CONNECTED))
    assert seen is None and t >= 10.0


def _call_named(tree, name):
    import ast
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call)
            and getattr(n.func, "id", "") == name]


def _src(node) -> str:
    import ast
    return ast.unparse(node)


def test_the_banner_rig_uses_the_early_stop_decision() -> None:
    """Source inspection (the rig needs a U64E), of VALUES, not keywords.

    The logic is executed above; what is left in the rig is wiring, and
    each argument is pinned to the exact expression it must be. A keyword
    check let `shadow_ok=True`, a constant socket state, the unscaled
    STALL_ABORT and a vacuous close predicate through (PR #232 review).
    """
    import ast
    src = (REPO / "tools" / "uci" / "rig_https_banner.py").read_text()
    tree = ast.parse(src)

    steps = _call_named(tree, "early_stop_step")
    assert len(steps) == 1, "the loop must call early_stop_step exactly once"
    step = steps[0]
    assert [_src(a) for a in step.args] == [
        "tracker", "state", "now", "read_tcp_state"], (
        "early_stop_step must get the tracker, this poll's state and time, "
        "and the socket READER itself (not a value or a stand-in): "
        + str([_src(a) for a in step.args]))
    kws = {k.arg: _src(k.value) for k in step.keywords}
    assert kws == {"stall_abort": "STALL_ABORT_S",
                   "shadow_ok": "shadow.ok"}, kws

    # read_tcp_state really reads net_tcp_state's label.
    rts = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
               and n.name == "read_tcp_state")
    assert "tcp_addr" in _src(rts) and "read_mem" in _src(rts)
    assert "label_addr('net_tcp_state')" in src.replace('"', "'")

    # The tracker starts at `started`, and the deadline path measures the
    # grace off the same tracker.
    assert [_src(a) for c in _call_named(tree, "StallTracker")
            for a in c.args] == ["started"]
    assert "tracker.frozen_for(now) < STALL_GRACE_S" in src

    # The close predicate: exactly these three, in this order.
    cc = _call_named(tree, "close_confirmed")
    assert len(cc) == 1 and [_src(a) for a in cc[0].args] == [
        "stopped_early", "read_shadow_ok", "read_tcp_state"], (
        [_src(a) for a in cc[0].args] if cc else "no close_confirmed call")
    rso = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
               and n.name == "read_shadow_ok")
    assert "check_shadow_ram_readable" in _src(rso) and any(
        isinstance(n, ast.Constant) and n.value == 0xA000
        for n in ast.walk(rso)), "read_shadow_ok must re-read $A000"

    # Pre-lock: the stall knobs are checked before DeviceLock is taken.
    lock_line = min(n.lineno for n in _call_named(tree, "DeviceLock"))
    cfg = [c for c in _call_named(tree, "stall_config_error")
           if c.lineno < lock_line]
    assert cfg and [_src(a) for a in cfg[0].args] == [
        "STALL_ABORT_S", "STALL_GRACE_S"], "stall knobs not checked pre-lock"
    # ...and the check's verdict is acted on (return before the lock).
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
              and n.name == "main")
    guard = next(n for n in ast.walk(fn) if isinstance(n, ast.If)
                 and _src(n.test) == "bad_stall")
    assert any(isinstance(x, ast.Return) and _src(x.value) == "2"
               for x in guard.body), "a bad stall config must exit 2"

    # ---- Exact expressions, by AST (round-2 review: substring greps passed
    # on a comment, and one-token edits walked through) -------------------
    def assigns(name):
        return [n for n in ast.walk(fn) if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name
                        for tg in n.targets
                        for t in (tg.elts if isinstance(tg, ast.Tuple)
                                  else [tg]))]

    def fdef(name):
        return next(n for n in ast.walk(fn)
                    if isinstance(n, ast.FunctionDef) and n.name == name)

    # net_tcp_state's address comes from labels.txt and nowhere else, and
    # the read is exactly one byte AT it (tcp_addr + 1 is net_send_len,
    # which could stop the loop on a live socket).
    assert sorted(_src(a.value) for a in assigns("tcp_addr")) == [
        "None", "label_addr('net_tcp_state')"], [
        _src(a) for a in assigns("tcp_addr")]
    assert _src(fdef("read_tcp_state")) == (
        "def read_tcp_state():\n"
        "    if tcp_addr is None:\n"
        "        return None\n"
        "    return bytes(client.read_mem(tcp_addr, 1))[0]"), _src(
        fdef("read_tcp_state"))
    assert _src(fdef("read_shadow_ok")) == (
        "def read_shadow_ok():\n"
        "    return check_shadow_ram_readable(bytes(client.read_mem(40960, "
        "16))).ok"), _src(fdef("read_shadow_ok"))

    # The close wait's extra exit is exactly close_confirmed's answer.
    # `... or 'x'` would end the wait on its first poll over a CONNECTED
    # socket, release the lock, and let the next lane reset over it.
    also = [k.value for c in _call_named(tree, "wait_for")
            for k in c.keywords if k.arg == "also"]
    assert [_src(a) for a in also] == [
        "lambda: close_confirmed(stopped_early, read_shadow_ok, "
        "read_tcp_state)"], [_src(a) for a in also]

    # `stop` and `stopped_early` have exactly the bindings the feature needs:
    # stop only from early_stop_step; stopped_early False before the loop
    # and True inside the stop branch -- nothing that silently disables it.
    assert [_src(a) for a in assigns("stop")] == [
        "stop, why = " + _src(step)], [_src(a) for a in assigns("stop")]
    assert sorted(_src(a) for a in assigns("stopped_early")) == [
        "stopped_early = False", "stopped_early = True"]
    assert [_src(a) for a in assigns("bad_stall")] == [
        "bad_stall = stall_config_error(STALL_ABORT_S, STALL_GRACE_S)"]
    # Only early_stop_step feeds the tracker.
    assert not [c for c in ast.walk(fn) if isinstance(c, ast.Call)
                and getattr(c.func, "attr", "") == "observe"], (
        "the rig calls tracker.observe itself; early_stop_step owns that")

    # The 'Q' that lets do_https_get reach net_tcp_close must follow the
    # loop unconditionally -- an early stop may not skip it (lease
    # poisoning if the next lane resets over a live socket).
    loop = next(n for n in ast.walk(tree) if isinstance(n, ast.While)
                and step in list(ast.walk(n)))
    # The stop branch: exactly `if stop:` directly in the loop body, and it
    # is what sets stopped_early and breaks.
    ifs = [s for s in loop.body if isinstance(s, ast.If)
           and any(isinstance(x, ast.Break) for x in s.body)
           and any(_src(x) == "stopped_early = True" for x in s.body)]
    assert len(ifs) == 1 and _src(ifs[0].test) == "stop", [
        _src(s.test) for s in ifs]
    # The deadline path (the while's else): `settled` is computed from the
    # tracker against the grace. A constant there turns every still-growing
    # expiry into FAIL instead of 78 -- #210's cry-wolf.
    dl = [s for s in loop.orelse if isinstance(s, ast.Assign)
          and _src(s.targets[0]) == "settled"]
    assert [_src(s.value) for s in dl] == [
        "check_fetch_settled(tracker.frozen_for(now) < STALL_GRACE_S, "
        "now - started, FETCH_TIMEOUT)"], [_src(s.value) for s in dl]
    assert "now = time.monotonic()" in [_src(s) for s in loop.orelse]
    parent = next(p for p in ast.walk(tree)
                  if isinstance(getattr(p, "body", None), list)
                  and loop in p.body)
    after = parent.body[parent.body.index(loop) + 1:]
    # DIRECT statements only: ast.walk would accept a `send_text("Q")`
    # nested under `if not stopped_early:`, which skips the 'Q' exactly
    # when the early stop fired (round-3 review).
    assert [_src(s) for s in after[:2]] == [
        "print(\"Sending 'Q' to leave the viewer so the socket closes...\")",
        "client.send_text('Q', finish_with_return=False)"], [
        _src(s) for s in after[:2]]

    # The close wait itself, argument for argument (a 0 s window, or a
    # different predicate, ends it before the socket can close).
    closes = [c for c in _call_named(tree, "wait_for")
              if any(k.arg == "also" for k in c.keywords)]
    assert [_src(c) for c in closes] == [
        "wait_for(client, 'CONNECTION CLOSED', 120 * _SCALE, 'close', "
        "also=lambda: close_confirmed(stopped_early, read_shadow_ok, "
        "read_tcp_state))"], [_src(c) for c in closes]

    # wait_for (module level, outside main) is a thin shell over the
    # executed poll_until; pinned whole.
    wf = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
              and n.name == "wait_for")
    body = [s for s in wf.body
            if not (isinstance(s, ast.Expr)
                    and isinstance(s.value, ast.Constant))]   # docstring
    assert "\n".join(_src(s) for s in body) == (
        "seen, lines = poll_until(lambda: screen(client), marker, budget, "
        "also, clock=time.monotonic, sleep=time.sleep)\n"
        "if seen is None:\n"
        "    print(f\"  [{label}] '{marker}' NOT seen within {budget:.0f}s\")\n"
        "    return (False, lines)\n"
        "print(f'  [{label}] {seen}')\n"
        "return (True, lines)"), "\n".join(_src(s) for s in body)

    # The knobs: STALL_ABORT_S scales with the clock (120 s at 48 MHz,
    # 5,760 s at 1 MHz); dropping _SCALE cuts the 1 MHz margin 48x.
    knobs = {t.id: _src(n.value) for n in tree.body
             if isinstance(n, ast.Assign) for t in n.targets
             if isinstance(t, ast.Name)}
    assert knobs.get("STALL_ABORT_S") == (
        "float(os.environ.get('STALL_ABORT', str(STALL_ABORT * _SCALE)))"), \
        knobs.get("STALL_ABORT_S")
    assert knobs.get("STALL_GRACE_S") == (
        "float(os.environ.get('STALL_GRACE', str(STALL_GRACE)))"), \
        knobs.get("STALL_GRACE_S")
    assert knobs.get("_SCALE") == "max(1.0, 48.0 / float(TURBO_MHZ))", \
        knobs.get("_SCALE")
    # `started` is bound once, by the clock.
    assert [_src(a) for a in assigns("started")] == [
        "started = time.monotonic()"], [_src(a) for a in assigns("started")]
    assert not any(isinstance(n, (ast.Return, ast.Raise))
                   for n in ast.walk(loop)), (
        "the poll loop must not return or raise past the 'Q'")
    # An early stop records the fetch as SETTLED (not progressing), which
    # is what the deadline path computes for a frozen counter. Anything
    # else would move a FAIL to 78 purely because the loop stopped early.
    # (loop.body only: the while's `else:` is the deadline path.)
    in_loop = [c for stmt in loop.body for c in ast.walk(stmt)
               if isinstance(c, ast.Call)
               and getattr(c.func, "id", "") == "check_fetch_settled"]
    assert in_loop, "the early stop does not record `settled`"
    for c in in_loop:
        assert (c.args and isinstance(c.args[0], ast.Constant)
                and c.args[0].value is False), (
            "the early stop must record progressing=False")
    assert [_src(c) for c in in_loop] == [
        "check_fetch_settled(False, now - started, FETCH_TIMEOUT)"], [
        _src(c) for c in in_loop]


# ===========================================================================
# The decoder
# ===========================================================================
def _raw(parse_state=2, status=200, cl_valid=1, content_length=125_703,
         body_total=125_703, chunked=0, chunk_state=0) -> dict:
    return {
        "http_parse_state": bytes([parse_state]),
        "http_status": status.to_bytes(2, "little"),
        "http_cl_valid": bytes([cl_valid]),
        "http_content_length": content_length.to_bytes(3, "little"),
        "http_body_total": body_total.to_bytes(3, "little"),
        "http_chunked": bytes([chunked]),
        "http_chunk_state": bytes([chunk_state]),
    }


def test_decode_body_state_is_little_endian_and_24_bit() -> None:
    """The counts are 24-bit LE (W4). A 16-bit read would wrap at 65,536."""
    st = hbc.decode_body_state(_raw(body_total=125_703,
                                    content_length=125_703))
    assert st.body_total == 125_703 and st.content_length == 125_703
    assert st.status == 200
    # 125,703 = 0x01EAC7 — the low two bytes alone are 60,103, so a decoder
    # that dropped the third byte would report a 65 KB shortfall on a
    # COMPLETE body and the rig would go red for the wrong reason.
    assert int.from_bytes(_raw()["http_body_total"][:2], "little") == 60_167


def test_decode_refuses_a_short_or_missing_read() -> None:
    raw = _raw()
    raw["http_body_total"] = b"\x00\x00"      # 2 bytes, not 3
    try:
        hbc.decode_body_state(raw)
    except ValueError:
        pass
    else:
        raise AssertionError("a short DMA read must not be zero-extended into "
                             "a plausible verdict")
    raw = _raw()
    del raw["http_chunk_state"]
    try:
        hbc.decode_body_state(raw)
    except KeyError:
        pass
    else:
        raise AssertionError("a missing symbol must not decode")


def test_symbols_are_declared_where_this_module_thinks_they_are() -> None:
    """SYMBOLS names real labels, at the widths the SOURCE reserves.

    The earlier version of this grepped `src/http.s` for name substrings,
    which was close to worthless: FIVE of the seven symbols are DECLARED in
    `src/data.s` (http.s only `.import`s them), so a rename or a width
    change there would have sailed through. Read the `.res` directives.
    """
    decls = {}
    for rel in ("src/data.s", "src/http.s"):
        for line in (REPO / rel).read_text().splitlines():
            head, _, rest = line.partition(":")
            name = head.strip()
            if name in hbc.SYMBOLS and ".res" in rest:
                width = int(rest.split(".res")[1].split(";")[0].strip())
                decls[name] = (rel, width)
    missing = sorted(set(hbc.SYMBOLS) - set(decls))
    assert not missing, (
        f"{missing} have no `.res` declaration in src/data.s or src/http.s; "
        "the rig would read a stale address")
    for name, width in hbc.SYMBOLS.items():
        rel, got = decls[name]
        assert got == width, (
            f"{name} is `.res {got}` in {rel} but this module reads {width} "
            "bytes -- a 24-bit count read as 16-bit wraps at 65,536 and "
            "reports a 65 KB shortfall on a complete body")


def test_the_6502_verdict_keeps_the_shape_this_mirrors() -> None:
    """Pin the ONE property the Python and the 6502 must share.

    `check_body_complete` deliberately diverges from
    `http_recv_timeout_verdict` on two arms (see the module docstring), but
    the Content-Length-before-chunked PRECEDENCE is not a divergence -- it
    is a property this module copies, and one of the shipped mutants tests
    that the Python side keeps it. Nothing tested the 6502 side: an
    adversarial review reversed those two arms in `src/http.s` and every
    host-side test stayed green, 8/8.

    Source shape, not behaviour, and weaker evidence than the link-time
    asserts this repo uses elsewhere (`src/net_abi_asserts.s`) -- but those
    cannot reach a fact about a Python module, and this catches the
    mutation that was actually demonstrated.
    """
    src = (REPO / "src" / "http.s").read_text()
    start = src.index("http_recv_timeout_verdict:")
    body = src[start:src.index('.segment "CODE"', start)]
    order = [ln.split()[1] for ln in body.splitlines()
             if ln.strip().startswith("lda http_")]
    assert order[:3] == ["http_parse_state", "http_cl_valid", "http_chunked"], (
        f"http_recv_timeout_verdict now tests {order[:3]}; this module "
        "mirrors parse_state -> cl_valid -> chunked and its "
        "cl_valid-before-chunked precedence would no longer match the PRG")
    # And the documented divergence is still the divergence we documented:
    # the 6502 chunked arm rejects unconditionally and never reads
    # http_chunk_state, which is why this module needs its own positive
    # completeness signal rather than copying that arm.
    assert "http_chunk_state" not in body, (
        "the 6502 verdict now reads http_chunk_state -- the chunked "
        "divergence documented in http_body_checks.py is stale; re-read "
        "both and update the prose before trusting either")


# ===========================================================================
# The rig actually consumes the verdict (the OTHER half of #210)
# ===========================================================================
def test_decide_exit_red_green() -> None:
    """The exit-code decision, executed. Every arm, and the mutants.

    This function used to be five lines at the bottom of the rig, tested
    only by an AST guard. An adversarial review found five one-token
    mutations that kept that guard green, two of which restored #210
    outright. They are ordinary assertions now.
    """
    ok = hbc.Verdict(True, "fine")
    bad = hbc.Verdict(False, "broken")
    unk = hbc.Verdict(False, "cannot say", status="inconclusive")
    settled_ok = hbc.check_fetch_settled(False, 1.0, 300.0)
    growing = hbc.check_fetch_settled(True, 300.0, 300.0)

    def code(**kw) -> int:
        base = dict(banner_ok=True, shadow=ok, settled=settled_ok,
                    status=ok, body=ok)
        base.update(kw)
        return hbc.decide_exit(**base)[0]

    assert code() == hbc.EXIT_PASS

    # M15 / M16, the two that restore #210: a body verdict of FAIL must
    # not exit 0, whatever else passed.
    assert code(body=bad) == hbc.EXIT_FAIL
    # M18: dropping ONE element of the checks list. Each of the three must
    # be able to fail the run on its own, or one of them is decorative.
    assert code(shadow=bad) == hbc.EXIT_FAIL
    assert code(status=bad) == hbc.EXIT_FAIL
    # ...and `any`, not `all`: one failure is enough, two are not required.
    assert code(body=bad, status=ok, shadow=ok) == hbc.EXIT_FAIL

    # A verdict that was never evaluated is a failure, never a skip.
    for missing in ("shadow", "status", "body", "settled"):
        assert code(**{missing: None}) == hbc.EXIT_FAIL, missing

    # Inconclusive is its own code, and never a pass.
    assert code(body=unk) == hbc.EXIT_INCONCLUSIVE
    assert hbc.EXIT_INCONCLUSIVE not in (hbc.EXIT_PASS, hbc.EXIT_FAIL)

    # The still-growing arm outranks the fail arm -- and ONLY in that
    # direction. It can turn a FAIL into a 78; it must never reach PASS.
    assert code(settled=growing, body=bad) == hbc.EXIT_INCONCLUSIVE
    assert code(settled=growing) == hbc.EXIT_INCONCLUSIVE

    # The banner is still the rig's original job and still fails first.
    assert code(banner_ok=False) == hbc.EXIT_FAIL
    assert code(banner_ok=False, body=bad) == hbc.EXIT_FAIL

    # The report names the failing check, or an operator cannot act on it.
    rc, lines = hbc.decide_exit(True, ok, settled_ok, ok, bad)
    assert rc == hbc.EXIT_FAIL and any("broken" in ln for ln in lines)


def test_the_banner_rig_delegates_its_exit_code() -> None:
    """The rig must hold no exit-code logic of its own.

    The previous guard here tried to prove, by name-taint over the AST,
    that each verdict reached the test of an `if` that returned. That is
    unprovable in the useful direction: taint says nothing about polarity,
    about `any` vs `all`, about WHICH code is returned, or about a name
    that is tainted but sliced out of the list. Five demonstrated mutants
    walked through it.

    So the logic moved into `decide_exit`, where it is executed, and this
    guard now asserts only the two things that keep it there: the rig calls
    `decide_exit`, passing every verdict BY KEYWORD, and returns what it
    returns.

    IT DOES NOT ASSERT that the rig computes no exit code of its own. An
    earlier version of this docstring claimed it did; the clause was never
    implemented, and adding lines after the call — an extra `return
    EXIT_PASS`, or `code = 0 if code == 1 else code` — walks through. That
    is a weaker class of mutation than the one-token edits that made the
    old guard useless, since it requires adding code rather than
    weakening it, but the honest statement is that the guard does not
    reach it.

    Source inspection, and labelled as such: the rig needs a U64E, so its
    runtime behaviour is not reachable from here.
    """
    import ast
    src = (REPO / "tools" / "uci" / "rig_https_banner.py").read_text()
    tree = ast.parse(src)

    # The module docstring QUOTES the retired literal, on purpose, so the
    # next reader knows what was removed and why. Strip it before looking:
    # a guard that could not tell a code constant from the prose describing
    # it would force that history out of the file to stay green.
    if (tree.body and isinstance(tree.body[0], ast.Expr)
            and isinstance(tree.body[0].value, ast.Constant)):
        del tree.body[0]
    # The delegation assertion comes FIRST, deliberately. When the stale
    # `125_000` literal check led, running this suite against the pre-fix
    # rig reddened on the literal and never reached the substantive
    # assertion -- so that evidence did not demonstrate the guard worked,
    # which is part of why the old AST guard's weakness went unnoticed.
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call)
             and getattr(n.value.func, "id", "") == "decide_exit"]
    assert calls, "the rig never calls decide_exit"
    bound = {t.id for n in calls for t in n.targets
             for t in (t.elts if isinstance(t, ast.Tuple) else [t])
             if isinstance(t, ast.Name)}
    returned = {n.value.id for n in ast.walk(tree)
                if isinstance(n, ast.Return) and isinstance(n.value, ast.Name)}
    assert bound & returned, (
        f"decide_exit's result {sorted(bound)} is never returned; the rig is "
        "deciding its own exit code again, which is where the mutants lived")

    assert "125000" not in ast.unparse(tree), (
        "the hardcoded completeness threshold is back in the rig's CODE; any "
        "literal about a user-editable remote document is a stale figure "
        "with a delayed fuse")

    # Every verdict decide_exit needs is passed to it, BY KEYWORD. The
    # earlier version of this loop looked for the five names anywhere in
    # the call's positional args, so transposing `settled` and `status`
    # walked straight through it — the still-growing gate would then be
    # handed a status verdict, never be inconclusive, and cry wolf again.
    for call in calls:
        assert not call.value.args, (
            "decide_exit is called with positional arguments; pass every "
            "verdict by keyword, or a transposition is invisible here and "
            "on the bench")
        given = {kw.arg for kw in call.value.keywords}
        missing = {"banner_ok", "shadow", "settled", "status", "body"} - given
        assert not missing, f"decide_exit is not given {sorted(missing)}"


# ===========================================================================
# The backstop
# ===========================================================================
def test_every_check_has_a_red_case() -> None:
    """No verdict may exist without a test that feeds it a known-bad input."""
    module_checks = {n for n in dir(hbc)
                     if n.startswith("check_")
                     and callable(getattr(hbc, n))
                     and getattr(getattr(hbc, n), "__module__", "")
                     == hbc.__name__}
    missing = sorted(module_checks - set(RED_CASES))
    assert not missing, (
        f"{missing} have no entry in RED_CASES -- every verdict needs a test "
        "that shows it failing on a known-bad input")
    stale = sorted(set(RED_CASES) - module_checks)
    assert not stale, f"RED_CASES names checks that no longer exist: {stale}"
    for check, testname in RED_CASES.items():
        assert testname in globals(), f"{check} points at missing test {testname}"


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
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
