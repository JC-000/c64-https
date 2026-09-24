#!/usr/bin/env python3
"""tools/mutate_http_body_checks.py — break the #210 oracle on purpose.

`tools/test_http_body_checks_unit.py` claims that every branch of the body
completeness verdict alarms on a known-bad input, and that the banner rig
cannot go back to computing a verdict it drops. This is the thing that
CHECKS those claims: it copies the module, the suite and the rig into a
scratch mirror, applies one textual mutation at a time, and requires the
suite to go red.

Why it matters more here than usual: the check being replaced —
`ok = total >= 125_000`, assigned and never read — passed every run it was
ever part of. "It went green on hardware" is precisely the evidence that
cannot distinguish a working oracle from that one. A mutant that SURVIVES
means the same thing has happened again.

Modelled on `tools/mutate_ip65_hw_checks.py`, including its methodology
trap: Python caches bytecode on (mtime, size), and a harness that rewrites
the same path many times in one second will silently run a previous
mutant's bytecode when two files happen to be the same length. The
subprocess therefore runs with PYTHONDONTWRITEBYTECODE=1.

    python3 tools/mutate_http_body_checks.py [--keep]
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

MODULE = "tools/http_body_checks.py"
RIG = "tools/uci/rig_https_banner.py"
SRC = "src/http.s"

FAIL_ARM = '    if any(v is None or v.status == "fail" for v in checks):'

#: (description, file to mutate, text to find, text to replace it with).
#: Each mutation is a plausible weaker implementation, not a random edit.
MUTANTS = [
    ("check_body_complete accepts a body short of its Content-Length",
     MODULE,
     "        if state.body_total == state.content_length:",
     "        if state.body_total <= state.content_length:"),
    ("check_body_complete keeps the retired >= 125_000 threshold",
     MODULE,
     "        if state.body_total == state.content_length:",
     "        if state.body_total >= 125_000:"),
    ("check_body_complete ignores an over-read past the declared length",
     MODULE,
     "        return Verdict(False,\n"
     "                       f\"OVER-READ: {state.body_total:,} B consumed against a \"",
     "        return Verdict(True,\n"
     "                       f\"OVER-READ: {state.body_total:,} B consumed against a \""),
    ("check_body_complete accepts a chunked body with no terminal chunk",
     MODULE,
     "        if state.chunk_state == CHUNK_STATE_TERMINAL:",
     "        if state.chunk_state >= 0:"),
    ("check_body_complete believes a parser that never reached the body",
     MODULE,
     "    if state.parse_state < PARSE_STATE_BODY:\n"
     "        return Verdict(False,\n"
     "                       f\"the response never reached the body \"",
     "    if False and state.parse_state < PARSE_STATE_BODY:\n"
     "        return Verdict(False,\n"
     "                       f\"the response never reached the body \""),
    ("an unframed response is promoted from inconclusive to a pass",
     MODULE,
     "                   \"stale literal #210 removed\", ev, status=\"inconclusive\")",
     "                   \"stale literal #210 removed\", ev)"),
    ("check_body_complete prefers chunked over Content-Length "
     "(the PRG's order reversed)",
     MODULE,
     "    if state.cl_valid:\n        if state.body_total == state.content_length:",
     "    if state.cl_valid and not state.chunked:\n"
     "        if state.body_total == state.content_length:"),
    ("check_http_status accepts any status",
     MODULE,
     "    if state.status != expect:",
     "    if False and state.status != expect:"),
    ("decode_body_state reads the 24-bit counts as 16-bit",
     MODULE,
     '    "http_body_total": 3,       # 24-bit CONSUMED count',
     '    "http_body_total": 2,       # 24-bit CONSUMED count'),
    ("decode_body_state zero-extends a short DMA read",
     MODULE,
     "        if len(bytes(raw[name])) != width:",
     "        if False and len(bytes(raw[name])) != width:"),
    # --- the exit-code decision. All five of these were found by an
    # --- adversarial review of the AST guard that used to be the only
    # --- thing testing this logic; every one of them kept that guard
    # --- green. They are module-side mutants now because the logic
    # --- moved into decide_exit, where the suite EXECUTES it.
    ("M15: decide_exit's fail arm uses all() instead of any() "
     "(exit 0 on a truncated body - #210 restored)",
     MODULE,
     FAIL_ARM,
     FAIL_ARM.replace("if any(", "if all(")),
    ("M16: decide_exit's fail arm returns EXIT_PASS (#210 restored)",
     MODULE,
     FAIL_ARM + "\n        return EXIT_FAIL, lines + [",
     FAIL_ARM + "\n        return EXIT_PASS, lines + ["),
    ("M17: decide_exit's fail arm is dead",
     MODULE,
     FAIL_ARM,
     FAIL_ARM.replace("if any(", "if False and any(")),
    ("M18: the body verdict is sliced out of decide_exit's checks list",
     MODULE,
     "    checks = [shadow, status, body]",
     "    checks = [shadow, status, body][:2]"),
    ("M23: decide_exit's still-growing gate is dead "
     "(cry-wolf restored)",
     MODULE,
     "    if settled.inconclusive:",
     "    if settled.inconclusive and False:"),
    ("the rig decides its own exit code again instead of delegating",
     RIG,
     "        code, report = decide_exit(banner_ok=banner_ok, shadow=shadow,\n"
     "                                   settled=settled, status=status, body=body)",
     "        code, report = (0, ['PASS'])"),
    # --- Round-2 review wrote these six against decide_exit WITHOUT
    # --- looking at this list, and all six were caught. Folded in so
    # --- they stay caught: an independent set that lands is worth more
    # --- than the same set re-run, and it only stays worth something
    # --- if it is here.
    ("R2-a: decide_exit stops treating a never-evaluated verdict as a failure",
     MODULE,
     FAIL_ARM,
     '    if any(v.status == "fail" for v in checks if v is not None):'),
    ("R2-b: decide_exit widens the fail test to != \"pass\" (inconclusive becomes FAIL)",
     MODULE,
     FAIL_ARM,
     FAIL_ARM.replace('== "fail"', '!= "pass"')),
    ("R2-c: decide_exit's inconclusive arm returns EXIT_PASS",
     MODULE,
     "    if any(v.inconclusive for v in checks):\n        return EXIT_INCONCLUSIVE, lines + [",
     "    if any(v.inconclusive for v in checks):\n        return EXIT_PASS, lines + ["),
    ("R2-d: decide_exit's still-growing arm stays live but is ranked behind the fail arm",
     MODULE,
     "    if settled.inconclusive:",
     "    if settled.inconclusive and not any(v is None or v.status == 'fail'\n                                    for v in checks):"),
    ("R2-e: decide_exit drops the `settled is None` guard",
     MODULE,
     "    if settled is None:",
     "    if False:"),
    ("R2-f: decide_exit's banner arm returns EXIT_INCONCLUSIVE instead of failing",
     MODULE,
     "    if not banner_ok:\n        return EXIT_FAIL, lines + [",
     "    if not banner_ok:\n        return EXIT_INCONCLUSIVE, lines + ["),
    ("the rig passes decide_exit's verdicts positionally, so a "
     "settled/status transposition is invisible to every guard",
     RIG,
     "        code, report = decide_exit(banner_ok=banner_ok, shadow=shadow,\n                                   settled=settled, status=status, body=body)",
     "        code, report = decide_exit(banner_ok, shadow, status, settled, body)"),
    # --- the 6502 side. The reviewer reversed these two arms in
    # --- src/http.s and every host-side test stayed green, 8/8.
    ("the 6502 verdict tests http_chunked before http_cl_valid "
     "(the precedence this module copies)",
     SRC,
     "        lda http_cl_valid\n        beq @to_unframed",
     "        lda http_chunked\n        beq @to_unframed"),
    ("the 6502 chunked arm starts reading http_chunk_state "
     "(the documented divergence goes stale)",
     SRC,
     "@to_unframed:\n        lda http_chunked",
     "@to_unframed:\n        lda http_chunk_state\n        lda http_chunked"),
    ("check_fetch_settled calls a still-growing fetch settled",
     MODULE,
     "    if progressing:",
     "    if False and progressing:"),
    # --- #226: when the poll loop may stop before FETCH_TIMEOUT. Each is a
    # --- way an early stop could cut a slow-but-healthy fetch short.
    ("#226: should_stop_early ignores the socket state",
     MODULE,
     "    if tcp_state not in (NET_TCP_ERROR, NET_TCP_CLOSED):",
     "    if False and tcp_state not in (NET_TCP_ERROR, NET_TCP_CLOSED):"),
    ("#226: should_stop_early treats a CONNECTED socket as dead",
     MODULE,
     "    if tcp_state not in (NET_TCP_ERROR, NET_TCP_CLOSED):",
     "    if tcp_state not in (NET_TCP_ERROR, NET_TCP_CLOSED, "
     "NET_TCP_CONNECTED):"),
    ("#226: should_stop_early ignores how long the counter was frozen",
     MODULE,
     "    if frozen_for < stall_abort:",
     "    if False and frozen_for < stall_abort:"),
    ("#226: should_stop_early uses STALL_GRACE as its margin",
     MODULE,
     "    if frozen_for < stall_abort:",
     "    if frozen_for < STALL_GRACE:"),
    ("#226: should_stop_early stops during the handshake (parse_state < 2)",
     MODULE,
     "    if state.parse_state < PARSE_STATE_BODY:\n"
     "        return False, \"the response has not reached its body\"",
     "    if False and state.parse_state < PARSE_STATE_BODY:\n"
     "        return False, \"the response has not reached its body\""),
    ("#226: should_stop_early stops on an unframed (INCONCLUSIVE) response",
     MODULE,
     "    if check_body_complete(state).status != \"fail\":",
     "    if check_body_complete(state).status == \"pass\":"),
    ("#226: should_stop_early stops on a body that is not a failure",
     MODULE,
     "    if check_body_complete(state).status != \"fail\":",
     "    if False and check_body_complete(state).status != \"fail\":"),
    ("#226: should_stop_early trusts an unproven shadow-RAM read",
     MODULE,
     "    if not shadow_ok:",
     "    if False and not shadow_ok:"),
    ("#226: should_stop_early accepts a threshold below its floor",
     MODULE,
     "    if stall_abort < STALL_ABORT_MIN:",
     "    if False and stall_abort < STALL_ABORT_MIN:"),
    ("#226: NET_TCP_ERROR drifts from src/net/net_states.inc",
     MODULE,
     "NET_TCP_ERROR = 0x02",
     "NET_TCP_ERROR = 0x03"),
    ("#226: the rig returns out of the poll loop, skipping the 'Q'",
     RIG,
     "                stopped_early = True\n",
     "                stopped_early = True\n"
     "                return EXIT_FAIL\n"),
    ("#226: the rig records an early stop as still growing (FAIL -> 78)",
     RIG,
     "                settled = check_fetch_settled(\n"
     "                    False, now - started, FETCH_TIMEOUT)",
     "                settled = check_fetch_settled(\n"
     "                    True, now - started, FETCH_TIMEOUT)"),
    ("#226: the rig ignores a bad stall config (a sub-floor STALL_ABORT "
     "would raise inside the loop, past the 'Q')",
     RIG,
     "    if bad_stall:",
     "    if False:"),
    ("#226 R1: the rig checks STALL_ABORT but not STALL_GRACE against it",
     RIG,
     "stall_config_error(STALL_ABORT_S, STALL_GRACE_S)",
     "stall_config_error(STALL_ABORT_S, 0.0)"),
    ("#226 R1: the rig hardcodes shadow_ok=True in the early-stop step",
     RIG,
     "stall_abort=STALL_ABORT_S, shadow_ok=shadow.ok)",
     "stall_abort=STALL_ABORT_S, shadow_ok=True)"),
    ("#226 R1: the rig hands the step a constant socket state",
     RIG,
     "tracker, state, now, read_tcp_state,",
     "tracker, state, now, lambda: 2,"),
    ("#226 R1: the rig passes the unscaled STALL_ABORT (drops _SCALE)",
     RIG,
     "stall_abort=STALL_ABORT_S, shadow_ok=shadow.ok)",
     "stall_abort=STALL_ABORT, shadow_ok=shadow.ok)"),
    ("#226 R1: the rig's tracker does not start at `started`",
     RIG,
     "tracker = StallTracker(started)",
     "tracker = StallTracker(0.0)"),
    ("#226 R1: the deadline path measures the grace from `started`",
     RIG,
     "tracker.frozen_for(now) < STALL_GRACE_S",
     "now - started < STALL_GRACE_S"),
    ("#226 R1: the rig's close predicate ignores stopped_early",
     RIG,
     "close_confirmed(stopped_early, read_shadow_ok,",
     "close_confirmed(True, read_shadow_ok,"),
    ("#226 R1: the rig's close predicate skips the post-'Q' shadow re-read",
     RIG,
     "close_confirmed(stopped_early, read_shadow_ok,",
     "close_confirmed(stopped_early, lambda: True,"),
    ("#226 R1: StallTracker never records a change (last_moved update dropped)",
     MODULE,
     "            self.last_total, self.last_moved = total, now",
     "            self.last_total = total"),
    ("#226 R1: StallTracker measures from `started`, not the last change",
     MODULE,
     "        return now - self.last_moved",
     "        return now - self.started"),
    ("#226 R1: early_stop_step decides on a constant socket state",
     MODULE,
     "    return should_stop_early(state, read_tcp_state(), frozen,",
     "    return should_stop_early(state, NET_TCP_ERROR, frozen,"),
    ("#226 R1: early_stop_step drops shadow_ok",
     MODULE,
     "                             stall_abort=stall_abort, shadow_ok=shadow_ok)",
     "                             stall_abort=stall_abort, shadow_ok=True)"),
    ("#226 R1: early_stop_step reads the socket on every poll",
     MODULE,
     "    tracker.observe(state.body_total, now)\n    frozen",
     "    read_tcp_state()\n    tracker.observe(state.body_total, now)\n    frozen"),
    ("#226 R1: close_confirmed accepts any state but CLOSED",
     MODULE,
     "    if read_tcp_state() == NET_TCP_CLOSED:",
     "    if read_tcp_state() != NET_TCP_CLOSED:"),
    ("#226 R1: close_confirmed fires without an early stop",
     MODULE,
     "    if not stopped_early:\n        return None",
     "    if False:\n        return None"),
    ("#226 R1: close_confirmed trusts a ROM read after 'Q'",
     MODULE,
     "    if not read_shadow_ok():",
     "    if False:"),
    ("#226 R1: stall_config_error lets STALL_GRACE reach STALL_ABORT",
     MODULE,
     "    if stall_grace >= stall_abort:",
     "    if False:"),
    ("#226 R1: stall_config_error drops the STALL_ABORT floor",
     MODULE,
     "    if stall_abort < STALL_ABORT_MIN:\n        return (",
     "    if False:\n        return ("),
    # --- #226 round 2: the twelve that survived commit eeb5fd1's suite
    # --- (substring greps passed on a comment) plus the NaN knob.
    ("#226 R2: the rig's stop branch is dead (`if False:`)",
     RIG,
     "            if stop:\n                print(f\"  {state.summary()}\")",
     "            if False:\n                print(f\"  {state.summary()}\")"),
    ("#226 R2: the rig overwrites the step's answer (`stop = False`)",
     RIG,
     "            if stop:\n                print(f\"  {state.summary()}\")",
     "            stop = False\n            if stop:\n"
     "                print(f\"  {state.summary()}\")"),
    ("#226 R2: the rig never marks the stop (`stopped_early = False`)",
     RIG,
     "                stopped_early = True\n",
     "                stopped_early = False\n"),
    ("#226 R2: read_tcp_state reads net_send_len (tcp_addr + 1)",
     RIG,
     "return bytes(client.read_mem(tcp_addr, 1))[0]",
     "return bytes(client.read_mem(tcp_addr + 1, 1))[0]"),
    ("#226 R2: tcp_addr hardcoded, the label only in a comment",
     RIG,
     "tcp_addr = label_addr(\"net_tcp_state\")",
     "tcp_addr = 0xB3BF  # label_addr('net_tcp_state')"),
    ("#226 R2: the post-'Q' shadow re-check is `... .ok or True`",
     RIG,
     "bytes(client.read_mem(0xA000, 16))).ok",
     "bytes(client.read_mem(0xA000, 16))).ok or True"),
    ("#226 R2: the deadline path's settled is a constant, the expression "
     "left in a comment (78 -> FAIL, #210 cry-wolf)",
     RIG,
     "            now = time.monotonic()\n            settled = check_fetch_settled(\n"
     "                tracker.frozen_for(now) < STALL_GRACE_S,",
     "            now = time.monotonic()\n"
     "            # tracker.frozen_for(now) < STALL_GRACE_S\n"
     "            settled = check_fetch_settled(\n                False,"),
    ("#226 R2: the rig feeds the tracker itself as well",
     RIG,
     "            stop, why = early_stop_step(",
     "            tracker.observe(state.body_total, now)\n"
     "            stop, why = early_stop_step("),
    ("#226 R2: the pre-lock verdict is discarded after it is printed",
     RIG,
     "    if bad_stall:\n        print(f\"[fatal] {bad_stall}\", file=sys.stderr)\n"
     "        return 2",
     "    if bad_stall:\n        print(f\"[fatal] {bad_stall}\", file=sys.stderr)\n"
     "        return 2\n    bad_stall = None"),
    ("#226 R2: the close wait's extra exit always fires (`... or 'x'`: "
     "lock released over a CONNECTED socket)",
     RIG,
     "also=lambda: close_confirmed(stopped_early, read_shadow_ok,\n"
     "                                         read_tcp_state))",
     "also=lambda: close_confirmed(stopped_early, read_shadow_ok,\n"
     "                                         read_tcp_state) or 'x')"),
    ("#226 R2: early_stop_step reports the threshold as the freeze",
     MODULE,
     "    return should_stop_early(state, read_tcp_state(), frozen,",
     "    return should_stop_early(state, read_tcp_state(), stall_abort,"),
    ("#226 R2: stall_config_error accepts a non-finite knob (NaN stops "
     "the loop at 0 s)",
     MODULE,
     "        if not math.isfinite(v):",
     "        if False and not math.isfinite(v):"),
    ("#226 R2: should_stop_early accepts stall_abort=nan",
     MODULE,
     "    if not math.isfinite(stall_abort) or stall_abort < STALL_ABORT_MIN:",
     "    if stall_abort < STALL_ABORT_MIN:"),
    # --- #226 round 3: the close wait and the knobs (lease-poisoning and
    # --- 1 MHz-margin paths that survived d2d2b5f).
    ("#226 R3: poll_until accepts any also() result (`also() or 'x'`)",
     MODULE,
     "            seen = also()\n",
     "            seen = also() or 'x'\n"),
    ("#226 R3: poll_until ends on any also, signal or not",
     MODULE,
     "            if isinstance(seen, str) and seen:",
     "            if seen is not None or also is not None:"),
    ("#226 R3: poll_until never waits out its budget",
     MODULE,
     "        if clock() >= deadline:\n            return None, lines",
     "        if True:\n            return None, lines"),
    ("#226 R3: the rig's wait_for reports success on no signal",
     RIG,
     "    if seen is None:\n",
     "    if False:\n"),
    ("#226 R3: the 'Q' is skipped after an early stop",
     RIG,
     "        client.send_text(\"Q\", finish_with_return=False)",
     "        if not stopped_early:\n"
     "            client.send_text(\"Q\", finish_with_return=False)"),
    ("#226 R3: the close wait has a 0 s window",
     RIG,
     "            client, \"CONNECTION CLOSED\", 120 * _SCALE, \"close\",",
     "            client, \"CONNECTION CLOSED\", 0, \"close\","),
    ("#226 R3: STALL_ABORT_S drops _SCALE (120 s, not 5,760 s, at 1 MHz)",
     RIG,
     "str(STALL_ABORT * _SCALE)))",
     "str(STALL_ABORT)))"),
    ("#226 R3: STALL_ABORT_S is a constant 60 s",
     RIG,
     "str(STALL_ABORT * _SCALE)))",
     "str(60.0)))"),
    ("#226 R3: STALL_GRACE_S default inflated 20x",
     RIG,
     "STALL_GRACE_S = float(os.environ.get(\"STALL_GRACE\", str(STALL_GRACE)))",
     "STALL_GRACE_S = float(os.environ.get(\"STALL_GRACE\", str(STALL_GRACE * 20)))"),
    ("#226 R3: the early stop records 0 s elapsed",
     RIG,
     "                settled = check_fetch_settled(\n"
     "                    False, now - started, FETCH_TIMEOUT)",
     "                settled = check_fetch_settled(\n"
     "                    False, 0.0, FETCH_TIMEOUT)"),
    ("#226 R3: `started` is rebound after the deadline is set",
     RIG,
     "        deadline = started + FETCH_TIMEOUT\n",
     "        deadline = started + FETCH_TIMEOUT\n        started = 0.0\n"),
    ("a check_* is renamed away (the RED_CASES registry goes stale)",
     MODULE,
     "def check_http_status(", "def renamed_check_http_status("),
]

#: Mutants that CANNOT be detected, with the reason. Reported, never hidden.
KNOWN_EQUIVALENT: dict = {}

#: HOW THE RIG-SIDE GAP WAS CLOSED, since the shape of it is the lesson.
#: The exit-code decision used to live in `rig_https_banner.py` and was
#: tested only by an AST guard. An adversarial review found FIVE
#: one-token mutants that kept that guard green -- `any(` -> `all(`,
#: `return EXIT_FAIL` -> `EXIT_PASS`, a `[:2]` slice, and two dead
#: conjuncts -- two of which restore #210 exactly. Name-taint over an
#: AST cannot see polarity, list membership, or which constant is
#: returned, and no strengthening of it would have. The logic moved to
#: `decide_exit` in the module instead, so those five are ordinary
#: mutants the suite EXECUTES. What remains in the rig is a call, and
#: the guard now checks only that it is still a call, by keyword.
#:
#: NAME THE TRADE RATHER THAN CALLING THE SEAM CLOSED. It is smaller in
#: CONSEQUENCE and marginally larger in SURFACE: the highest-consequence
#: part -- the decision itself -- left the seam and is executed now, and
#: five untestable decision mutants were traded for one untestable
#: BINDING mutant (transposing decide_exit's arguments), which passing by
#: keyword removes. What is unchanged and still untested is the rest of
#: the rig between the DMA read and the call: `read_state`'s slicing, the
#: `span_lo`/`span_hi` arithmetic, the `last_moved` tracking and the
#: `grace` computation. `tools/uci/` rigs need hardware and this one is
#: not importable without the sibling harness -- the same restructure
#: `tools/test_rig_skip_contract.py` records as owed for the macOS
#: bridge rig.


def stage(root: Path) -> None:
    (root / "tools" / "uci").mkdir(parents=True)
    (root / "src").mkdir(parents=True)
    for rel in (MODULE, RIG,
                "tools/test_http_body_checks_unit.py",
                "tools/ip65_hw_checks.py"):
        shutil.copy(REPO / rel, root / rel)
    # The suite reads the real 6502 source: src/http.s for the verdict
    # shape, src/data.s for the symbol widths. src/http.s is MUTATED
    # below, so the mirror copy is what the suite must see.
    for rel in (SRC, "src/data.s"):
        shutil.copy(REPO / rel, root / rel)
    # #226: the NET_TCP_* values should_stop_early trusts.
    (root / "src" / "net").mkdir()
    shutil.copy(REPO / "src/net/net_states.inc",
                root / "src/net/net_states.inc")


def run_suite(root: Path):
    """The suite, against the mirror. Bytecode caching OFF — see the docstring."""
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    r = subprocess.run(
        [sys.executable, str(root / "tools" / "test_http_body_checks_unit.py")],
        capture_output=True, text=True, env=env)
    failed = [ln.strip() for ln in r.stdout.splitlines()
              if ln.strip().startswith(("FAIL", "ERROR"))]
    return r.returncode, failed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true",
                    help="leave the scratch mirror in place for inspection")
    args = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="httpbody-mutate-"))
    try:
        stage(tmp)
        rc, failed = run_suite(tmp)
        if rc != 0:
            print(f"BASELINE IS ALREADY RED ({len(failed)} failures) — fix that "
                  "first; mutation results mean nothing against a red baseline")
            print("\n".join(failed))
            return 2
        print(f"baseline: {len(MUTANTS)} mutations to apply, suite green")

        pristine = {rel: (tmp / rel).read_text()
                    for rel in (MODULE, RIG, SRC)}
        survived, unexpected = [], []
        for name, rel, old, new in MUTANTS:
            target = tmp / rel
            if old not in pristine[rel]:
                print(f"  !! NOT APPLICABLE  {name}\n     (the anchor text is "
                      "gone — the mutation no longer describes the code, so "
                      "this proves nothing; update it)")
                unexpected.append(name)
                continue
            target.write_text(pristine[rel].replace(old, new, 1))
            rc, failed = run_suite(tmp)
            target.write_text(pristine[rel])
            if rc == 0:
                if name in KNOWN_EQUIVALENT:
                    print(f"  equivalent  {name}\n              "
                          f"{KNOWN_EQUIVALENT[name]}")
                else:
                    print(f"  SURVIVED    {name}")
                    survived.append(name)
                continue
            who = ", ".join(sorted({f.split(":")[0].split()[-1]
                                    for f in failed}))
            print(f"  caught      {name}\n              by {who}")

        detectable = [m for m in MUTANTS if m[0] not in KNOWN_EQUIVALENT]
        caught = len(detectable) - len(survived) - len(unexpected)
        print(f"\n{caught}/{len(detectable)} detectable mutants caught, "
              f"{len(KNOWN_EQUIVALENT)} known-equivalent")
        if survived or unexpected:
            print("A surviving mutant means the suite passes whether or not "
                  "the checker works.")
            return 1
        return 0
    finally:
        if args.keep:
            print(f"mirror kept at {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
