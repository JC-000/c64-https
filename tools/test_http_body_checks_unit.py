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
    from _skip_policy import verdict
    return verdict(len(tests) - failed, failed,
                   certifies="the #210 body-completeness oracle")


if __name__ == "__main__":
    sys.exit(main())
