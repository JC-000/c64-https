#!/usr/bin/env python3
"""tools/mutate_trust_policy.py — break the trust policy on purpose (#155, L3).

tools/test_trust_policy_6502.py claims to catch each way the policy could
quietly stop protecting anyone. This checks that claim: it applies one
plausible weakening at a time to the 6502 source, rebuilds, runs the
scenarios that should notice, and requires them to go RED. A mutant that
survives is a guarantee the suite does not actually make.

The source is edited in place in this checkout and restored afterwards
(also on error or Ctrl-C), so run it on a clean tree you own:

    python3 tools/mutate_trust_policy.py            # every mutant
    python3 tools/mutate_trust_policy.py 3 7        # just these (1-based)

Exit 0 every mutant killed (and the unmutated baseline passed), 1 otherwise.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TEST = "tools/test_trust_policy_6502.py"
IMAGE = os.environ.get("C64_MUT_IMAGE", "onchip-pinned")  # pin + bundle + store
HOOK = "src/cert_pin.s"
POLICY = "src/net/uci/trust_policy.s"
BUNDLE = "src/net/uci/trust_bundle.s"

#: (what the weaker policy does, scenarios that must go red,
#:  [(file, find, replace)][, image -- default IMAGE])
MUTANTS = [
    ("RUN after Q keeps an armed accept", "sc_restart",
     [("src/boot.s", "        jsr trust_state_init    ; RUN after 'Q' must not inherit an accept\n", "")]),
    ("a cold-bank refusal of trust_post leaves the accept armed", "sc_bank_refuses_post",
     [(POLICY, "        lda #TP_M_NONE\n        sta tp_mode\n        sta tp_ovr_armed\n@stop:",
               "        lda #TP_M_NONE\n        nop\n        nop\n        nop\n        nop\n        nop\n        nop\n@stop:")],
     "comb"),
    ("a resident stub calls into the cold TRUST group (the prompt)", "sc_bank_refuses_post",
     [(POLICY, "        sta tp_ovr_armed\n@stop:  sec",
               "        sta tp_ovr_armed\n        jsr tp_unpinned_banner\n@stop:  sec")],
     "comb"),
    ("a bundle mismatch is flagged with A, which may be $00", "sc_bundle",
     [(HOOK, "        lda #1                          ; NOT A: on a mismatch tp_cmp_got\n",
             "        nop\n        nop\n")]),
    ("an armed accept takes ANY key, not the armed hash", "sc_accept_exact",
     [(HOOK, "        jsr tp_cmp_got\n        bne @changed\n",
             "        jsr tp_cmp_got\n        nop\n        nop\n")]),
    ("hash compares check only the first 4 bytes", "sc_near_collision",
     [(HOOK, "        ldy #TP_HASH_LEN-1\n@c:", "        ldy #3\n@c:")]),
    ("hash compares stop after the last 4 bytes", "sc_near_collision",
     [(HOOK, "        dey\n        bpl @c\n        lda #0                          ; Z=1",
             "        dey\n        cpy #28\n        bcs @c\n        lda #0                          ; Z=1")]),
    ("cert_pin_require lets a refused verdict send Finished", "sc_interlock",
     [(HOOK, "        bmi :+                          ; refused (TP_ST_CHANGED/_REFUSED)\n",
             "        nop\n        nop\n")]),
    ("the hook accepts a connection trust_pre never prepared", "sc_no_trust_pre",
     [(HOOK, "@refuse:                                ; TP_M_NONE, or not a P-256 window\n"
             "        lda #TP_ST_REFUSED",
             "@refuse:\n        lda #TP_ST_FIRST")]),
    ("a changed key is recorded anyway", "sc_changed_refused",
     [(POLICY, "        jsr tp_changed          ; shows, asks, arms",
               "        lda #TS_MODE_TOFU\n        jsr tp_record\n        jsr tp_changed")]),
    ("an accept armed for one host survives a GET for another", "sc_accept_other_host",
     [(POLICY, "        cmp tp_ovr_key,x\n        bne @disarm",
               "        cmp tp_ovr_key,x\n        nop\n        nop")]),
    ("an UNPINNED fetch records the key", "sc_store_fail,sc_changed_unpinned",
     [(POLICY, "        cmp #TP_M_UNPINNED\n        bne @not_unpinned",
               "        cmp #$FF\n        bne @not_unpinned"),
      (POLICY, "        cmp #TP_ST_FIRST\n        bne @done",
               "        cmp #TP_ST_UNPINNED+1\n        bcs @done")]),
    ("a key typed ahead answers the question", "sc_type_ahead",
     [(POLICY, "        sta NDX                 ; only", "        bit NDX                 ; only")]),
    ("the build pin's host goes to the store", "sc_build_pin",
     [(POLICY, "        jsr tp_is_build_host\n        bne @store",
               "        jsr tp_is_build_host\n        jmp @store")]),
    ("a failed name check still records", "sc_name_fail",
     [(POLICY, "        lda tls_reached_connected\n        beq @refused",
               "        lda #1\n        beq @refused")]),
    ("a store failure dials without the operator's Y", "sc_store_fail",
     [(POLICY, "        jsr tp_ask_unpinned\n        bcc @ret",
               "        jsr tp_ask_unpinned\n        clc\n        bcc @ret")]),
    ("a bundle mismatch at first use is recorded without asking", "sc_bundle",
     [(POLICY, "        lda tp_bwarn\n        beq @tofu", "        lda #0\n        beq @tofu")]),
    ("a bundle whose signature fails is used", "sc_bundle",
     [(BUNDLE, "        bcc :+\n        lda #TB_V_BAD", "        bcc :+\n        lda #TB_V_GOOD")]),
    ("the generation floor is not checked", "sc_bundle",
     [(BUNDLE, "        sbc #>TRUST_BUNDLE_GEN_FLOOR\n        bcs @lookup",
               "        sbc #>TRUST_BUNDLE_GEN_FLOOR\n        jmp @lookup")]),
    ("the bundle's exact size is not checked", "sc_bundle",
     [(BUNDLE, "        cpx dos_cnt             ; exactly: no slack either way\n        bne @bad_format",
               "        cpx dos_cnt\n        nop\n        nop")]),
    ("the bundle's keys need not ascend", "sc_bundle",
     [(BUNDLE, "        bcc @bad_format         ; descending", "        bcc @next")]),
    ("a cached verdict is reused for a different file", "sc_bundle",
     [(BUNDLE, "        cmp tb_digest,x\n        bne @fresh", "        cmp tb_digest,x\n        nop\n        nop")]),
]


def run_test(scenarios: str, image: str = IMAGE) -> int:
    env = dict(os.environ, C64_TP_IMAGES=image, C64_TP_SCENARIOS=scenarios,
               PYTHONDONTWRITEBYTECODE="1")
    p = subprocess.run([sys.executable, TEST], cwd=REPO, env=env,
                       capture_output=True, text=True)
    return p.returncode


def main(argv) -> int:
    picks = [int(a) for a in argv] or list(range(1, len(MUTANTS) + 1))
    files = {f for m in MUTANTS for f, _, _ in m[2]}
    original = {f: (REPO / f).read_text() for f in files}
    every = ",".join(sorted({s for m in MUTANTS for s in m[1].split(",")}))
    rc = max(run_test(every, im) for im in sorted({IMAGE} | {m[3] for m in MUTANTS if len(m) > 3}))
    print(f"baseline (unmutated, {every}): exit {rc}")
    if rc != 0:
        print("baseline is not green: nothing below would mean anything")
        return 1
    survived = []
    try:
        for i in picks:
            what, scen, edits = MUTANTS[i - 1][:3]
            image = MUTANTS[i - 1][3] if len(MUTANTS[i - 1]) > 3 else IMAGE
            for f in files:
                (REPO / f).write_text(original[f])
            for f, find, repl in edits:
                text = (REPO / f).read_text()
                if text.count(find) != 1:
                    print(f"  [{i}] STALE: {find!r} found {text.count(find)}x in {f}")
                    survived.append(i)
                    break
                (REPO / f).write_text(text.replace(find, repl))
            else:
                rc = run_test(scen, image)
                verdict = {1: "killed", 0: "SURVIVED", 2: "DID NOT BUILD"}.get(rc, f"exit {rc}")
                print(f"  [{i}] {verdict:13} {what}  ({scen})")
                if rc != 1:
                    survived.append(i)
    finally:
        for f in files:
            (REPO / f).write_text(original[f])
    print(f"{len(picks) - len(survived)}/{len(picks)} mutants killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
