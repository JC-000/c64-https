#!/usr/bin/env python3
"""Mutation runner for tools/check_m3_client.py (BACKEND=uci-m3).

Each mutant breaks ONE M3-SPEC rule in the SOURCE, the image is rebuilt with
the exact ca65/ld65 command lines of the current build (build/flags.stamp)
in a scratch directory, and the test that pins the rule must go RED. The
unmutated rebuild must reproduce build/c64-https.prg byte for byte first,
so a mutant's verdict is about the mutation and nothing else.

    make BACKEND=uci-m3 && python3 tools/mutate_m3_client.py

Exit 0 only if the control reproduces the PRG, its tests pass, and every
mutant is killed.
"""

from __future__ import annotations

import hashlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_m3_client as t                               # noqa: E402

NET = "src/net/uci-m3/net.s"
CMD = "src/net/uci-m3/m3_cmd.s"
INC = "src/net/uci-m3/m3.inc"
HTTP = "src/http.s"
UI = "src/net/uci-m3/m3_https_get.inc"

# (name, rule, file, old, new, tests that must go red)
#
# Not listed, because it is EQUIVALENT (verified, not assumed): deleting the
# startup sweep's own `cmp #M3_EXEC_WEDGED / beq @init_fail` exit. After a
# wedge, the sweep's next m3_begin refuses (m3_wedged) and net_init fails
# there instead, having written nothing: the same observable outcome. The
# guard that carries the rule is that refusal, and "begin-ignores-wedge"
# below shows it is load-bearing (test_wedge_writes_nothing_more goes red).
MUTANTS = [
    ("abort-not-0c", "ER-2 $0C at startup", NET,
     "ldy #(UCI_CTRL_ABORT | UCI_CTRL_CLR_ERR)", "ldy #UCI_CTRL_ABORT",
     ["test_startup_sequence"]),
    ("sweep-0..14", "ER-2/ER-9 CLOSE sweep 0..15", NET,
     "cmp #M3_SWEEP_HANDLES", "cmp #15", ["test_startup_sequence"]),
    ("no-presence-check", "ER-2 presence check", NET,
     "        cmp #(UCI_ID_VALUE & $7F)\n        beq @present",
     "        jmp @present", ["test_no_uci_writes_nothing"]),
    ("info-trailing-00", "ER-4 INFO exactly 3 bytes", NET,
     "        lda #M3_INFO_CAPS\n        jsr m3_put\n",
     "        lda #M3_INFO_CAPS\n        jsr m3_put\n        lda #0\n        jsr m3_put\n",
     ["test_startup_sequence"]),
    ("handle-0-is-none", "ER-9 handle 0 is legal", NET,
     "        lda m3_open_reply+0\n        sta m3_handle",
     "        lda m3_open_reply+0\n        beq @tc_malformed\n        sta m3_handle",
     ["test_handle_zero_is_legal"]),
    ("open-bound-12s", "ER-1 OPEN bound 45 s", NET,
     "        lda #<M3_B_OPEN\n        ldx #>M3_B_OPEN\n        jsr m3_exec",
     "        lda #<M3_B_TLS\n        ldx #>M3_B_TLS\n        jsr m3_exec",
     ["test_open_waits_45s_not_12"]),
    ("no-release", "S 1.8 `03 25` after an ABORTed Open", NET,
     "        jsr m3_release              ; ABORTed Open: `03 25` next\n", "",
     ["test_open_timeout_aborts_then_releases"]),
    ("post-abort-1s", "ER-1 post-ABORT wait to ABORT + 12 s", INC,
     "M3_B_POST_ABORT     = 1200", "M3_B_POST_ABORT     = 100",
     ["test_open_timeout_aborts_then_releases"]),
    ("abort-with-push", "Appendix A: never ABORT with PUSH", CMD,
     "m3_abort_wait:\n        ldy #UCI_CTRL_ABORT",
     "m3_abort_wait:\n        ldy #(UCI_CTRL_ABORT | UCI_CTRL_PUSH_CMD)",
     ["test_open_timeout_aborts_then_releases"]),
    ("wedge-not-latched", "ER-11 write nothing once wedged", CMD,
     "        lda #$80\n        sta m3_wedged", "        lda #$80\n        bit m3_wedged",
     ["test_wedge_writes_nothing_more"]),
    ("status-16-bytes", "ER-8 40-byte status line", INC,
     "M3_STATUS_MAX       = 40", "M3_STATUS_MAX       = 16",
     ["test_refusal_line_is_kept_whole"]),
    ("no-ready-poll", "ER-10 ready bits before OPEN", NET,
     "        jsr m3_wait_ready\n        bcc :+\n        jmp @tc_fail\n:\n", "",
     ["test_ready_bits_polled_before_open"]),
    ("close-after-gone", "S 1.6 M10: never CLOSE a GONE handle", NET,
     "net_tcp_close:\n        lda m3_owned\n        beq @c_ok\n", "net_tcp_close:\n",
     ["test_read_end_01_is_gone"]),
    ("sticky-as-gone", "S 1.6: 12/14/16/17 are still ours, CLOSE", NET,
     "        cmp #5\n        bne @p_dead_read            ; any status but 1/5 (seen: 12/14/16/17): dead, still ours\n",
     "        cmp #5\n", ["test_read_end_14_is_closed"]),
    ("ffff-9-as-idle", "ER-7 `02,NO DATA: 9` = stop", NET,
     "        lda #0\n        sta m3_owned\n        lda #NET_TCP_ERROR\n        sta net_tcp_state\n        rts\n\n@p_0000:",
     "        lda #M3_POLL_IDLE\n        sta m3_poll_result\n        rts\n\n@p_0000:",
     ["test_read_not_ours_stops"]),
    ("empty-reply-as-eof", "ER-12 bit 7 before the header", NET,
     "        jsr m3_finish\n        jmp @p_dead_hdr             ; no header at all (81/82)\n",
     "        jsr m3_finish\n        lda #1\n        jmp @p_gone\n",
     ["test_empty_read_reply_is_not_eof"]),
    ("accept-data-more", "ER-5 no accept over a hole", NET,
     "        cmp #UCI_STAT_STATE         ; \"11\": Data More\n        bne @p_last",
     "        cmp #UCI_STAT_STATE         ; \"11\": Data More\n        jmp @p_last",
     ["test_data_more_is_never_accepted"]),
    ("aborted-read-kept", "S 1.1 M-2 CLOSE after an ABORTed READ", NET,
     ":       jmp @p_dead_owned           ; ABORTed READ: data lost, CLOSE it",
     ":       rts", ["test_read_timeout_aborts_and_closes"]),
    ("write-before-read", "ER-21 READ before WRITE", NET,
     "@s_drain:\n        lda net_tcp_state", "@s_drain:\n        jmp @s_chunk\n        lda net_tcp_state",
     ["test_read_before_write"]),
    ("write-result-ignored", "S 1.6 WRITE $FFFF = failed", NET,
     "        lda m3_rd_count\n        cmp #2\n        bne @s_short\n        lda m3_code\n        bne @s_short                ; $FFFF + 12/14/16/17: sticky\n        lda m3_wresp\n        cmp m3_piece\n        bne @s_short\n        lda m3_wresp+1\n        cmp m3_piece+1\n        bne @s_short\n",
     "", ["test_write_failure_is_reported"]),
    ("write-max-1024", "S 1.5 WRITE <= 892 B", INC,
     "M3_WRITE_MAX        = 892", "M3_WRITE_MAX        = 1024",
     ["test_long_write_is_split_at_892"]),
    ("read-max-1472", "S 1.5 one block: READ <= 893 B", INC,
     "M3_READ_MAX         = 893", "M3_READ_MAX         = 1472",
     ["test_http_content_length_end_to_end"]),
    ("05-unframed-trusted", "S 1.6 05: trust only framed data", HTTP,
     "        lda m3_eof_code\n        cmp #5\n        bne @m3_framed",
     "        jmp @m3_framed", ["test_http_05_unframed_is_short"]),
    ("sink-refusal-ignored", "a body the REU sink refused stops, C=1", HTTP,
     "        lda http_sink_full      ; the body outgrew its REU region: stop\n"
     "        bne @m3_dead            ;  now, C=1\n", "",
     ["test_http_sink_refusal_stops"]),
    ("sink-refusal-complete", "a body the REU sink refused is never C=0", HTTP,
     "@m3_complete:\n        jsr http_body_finish\n"
     "        lda http_sink_full      ; C=1 iff the sink refused a write\n"
     "        cmp #1\n",
     "@m3_complete:\n        jsr http_body_finish\n        clc\n",
     ["test_http_sink_refusal_stops"]),
    ("refused-not-8d", "$8D UCI_ERR_OPEN_REFUSED on a named refusal", NET,
     "        lda #UCI_ERR_OPEN_REFUSED   ; named in m3_status (e.g. 94,...)",
     "        lda #UCI_ERR_CONNECT_FAIL", ["test_refusal_line_is_kept_whole",
                                         "test_refusal_reaches_the_user"]),
    ("unknown-not-8e", "$8E UCI_ERR_CMD_UNKNOWN on 21", NET,
     "        lda #UCI_ERR_CMD_UNKNOWN\n        bne @ic_set",
     "        lda #UCI_ERR_NOT_PRESENT\n        bne @ic_set",
     ["test_no_tls_firmware", "test_no_tls_firmware_reaches_the_user"]),
    ("status-not-shown", "the refusal's status line reaches the user", UI,
     "m3_report_fail:\n        jsr m3_print_status",
     "m3_report_fail:\n        nop", ["test_refusal_reaches_the_user",
                                       "test_no_tls_firmware_reaches_the_user"]),
    # adv-271 round 1: the finding, and the mutants the suite could not see
    # The stall arm now relies on the shared verdict's unframed arm (the
    # 6510 TLS backends share it), so the mutant breaks that arm.
    ("stall-unframed-trusted", "an unframed body is whole only on 01", HTTP,
     "        rts                     ; unframed: complete only on a clean end\n",
     "        clc\n        rts\n", ["test_http_unframed_stall_is_short"]),
    ("05-as-owned", "S 1.6: 05 is GONE, never CLOSEd", NET,
     "        cmp #5\n        bne @p_dead_read", "        cmp #$FF\n        bne @p_dead_read",
     ["test_read_end_05_is_gone"]),
    ("bad-gate-removed", "ER-5: a short / over-long block is a hole", NET,
     "        lda m3_bad\n        bne @p_dead_code\n", "",
     ["test_short_block_is_dead", "test_block_tail_is_dead",
      "test_overclaimed_header_is_dead"]),
    ("rejected-as-reply", "a rejected PUSH never ran", CMD,
     "        lda #M3_EXEC_REJECTED\n        sec", "        lda #M3_EXEC_REPLY\n        clc",
     ["test_rejected_push_is_not_a_reply"]),
    ("ok-without-handle", "S 1.1: never assume a session; `03 25`", NET,
     "        lda m3_rd_count\n        cmp #M3_OPEN_REPLY_LEN\n        bne @tc_malformed\n", "",
     ["test_ok_without_handle_is_released"]),
    ("no-entry-wait", "write nothing into a busy interface", CMD,
     "        lda #(UCI_STAT_STATE | UCI_STAT_ABORT_PENDING | UCI_STAT_CMD_BUSY)\n"
     "        jsr m3_wait_clear\n        bcc @b_idle", "        jmp @b_idle",
     ["test_entry_waits_for_idle"]),
    ("idle-11-unchecked", "ER-7: only `: 11` is idle", NET,
     "        lda m3_status+12\n        cmp #'1'\n        bne @p_not_ours\n"
     "        lda m3_status+13\n        cmp #'1'\n        bne @p_not_ours\n", "",
     ["test_ffff_other_errno_stops"]),
    ("halt-is-rts", "ER-11: halt on a wedge", UI,
     "@cw_halt:\n        jmp @cw_halt", "@cw_halt:\n        rts",
     ["test_wedge_halts_the_ui"]),
    ("begin-ignores-wedge", "ER-11: nothing is written once wedged", CMD,
     "        bit m3_wedged\n        bmi @b_wedged\n", "",
     ["test_sweep_stops_at_a_wedge", "test_wedge_writes_nothing_more"]),
    ("no-release-retry", "Appendix A: resend an ABORTed `03 25`", NET,
     "        dec m3_tries\n        bne @rl_again\n", "",
     ["test_release_is_retried_once"]),
    # code review round (fix/uci-m3-client-review)
    ("close-rejected-drops-owned", "a refused CLOSE push never ran", NET,
     "        cmp #M3_EXEC_REJECTED\n        bne @c_fail                 ; wedged\n"
     "        dec m3_tries\n        bne @c_again\n"
     "        beq @c_fail                 ; rejected twice: still owned\n",
     "        jmp @c_gone_fail\n",
     ["test_rejected_close_is_retried", "test_unclosed_handle_stays_owned"]),
    ("close-no-retry", "a refused CLOSE push is pushed again", NET,
     "        dec m3_tries\n        bne @c_again\n        beq @c_fail ",
     "        jmp @c_fail\n        beq @c_fail ", ["test_rejected_close_is_retried"]),
    ("connect-stomps-unclosed", "no Open over a handle not yet closed", NET,
     "        jsr net_tcp_close           ; one session at a time\n        lda m3_owned\n        beq :+\n",
     "        jsr net_tcp_close           ; one session at a time\n        jmp :+\n",
     ["test_unclosed_handle_stays_owned"]),
    ("open-reply-any-length", "S 1.1: an Open reply is exactly 8 bytes", NET,
     "        lda m3_rd_count\n        cmp #M3_OPEN_REPLY_LEN\n        bne @tc_malformed\n",
     "        lda m3_rd_count\n        beq @tc_malformed\n",
     ["test_short_open_reply_is_released"]),
    ("version-unchecked", "REQUIRE_TLS13: refuse a non-1.3 session", NET,
     "        lda m3_open_reply+1\n        cmp #$04\n        bne @tc_not_tls13\n",
     "", ["test_non_tls13_session_is_refused"]),
    ("alert14-ignored", "REQUIRE_TLS13: any 14 = no TLS 1.3", NET,
     "        cmp #14\n        bne @tc_refused_code", "        cmp #99\n        bne @tc_refused_code",
     ["test_alert14_reads_as_no_tls13"]),
    ("dead-read-no-code", "$90 on a dead session", NET,
     "@p_dead_read:\n        lda #UCI_ERR_STREAM_LOST", "@p_dead_read:\n        lda #0",
     ["test_read_end_14_is_closed"]),
    ("not-ours-no-code", "$90 on a number no longer ours", NET,
     "        lda #UCI_ERR_STREAM_LOST\n        sta net_last_error\n        lda #0\n        sta m3_owned",
     "        lda #0\n        sta m3_owned", ["test_read_not_ours_stops"]),
    ("dead-read-is-86", "$86 keeps its one meaning", NET,
     "@p_dead_read:\n        lda #UCI_ERR_STREAM_LOST", "@p_dead_read:\n        lda #UCI_ERR_READ_FAIL",
     ["test_read_end_14_is_closed"]),
    ("dead-hdr-no-code", "finding 7: $8B on a READ reply of no shape", NET,
     "        bne @p_dead_code            ; the reason the block was refused\n        lda #UCI_ERR_BAD_READ_HDR",
     "        bne @p_dead_code            ; the reason the block was refused\n        lda #0",
     ["test_empty_read_reply_is_not_eof"]),
    ("short-not-8f", "finding 7: $8F on a block short of its header", NET,
     "        lda #UCI_ERR_SHORT_READ     ; the block ended short of its header",
     "        lda #UCI_ERR_BAD_READ_HDR   ; the block ended short of its header",
     ["test_short_block_is_dead"]),
    ("tail-no-code", "finding 7: $8B on bytes past the header", NET,
     "        lda #UCI_ERR_BAD_READ_HDR   ; bytes past the header: dropped\n        sta m3_bad",
     "        lda #1                      ; bytes past the header: dropped\n        sta m3_bad",
     ["test_block_tail_is_dead"]),
    # adv-276
    ("no-discard-check", "S 1.1: more than 8 reply bytes is malformed", NET,
     "        lda m3_discarded\n        bne @tc_malformed\n", "",
     ["test_long_open_reply_is_released"]),
    ("no-major-check", "REQUIRE_TLS13: both version bytes", NET,
     "        lda m3_open_reply+2\n        cmp #$03\n        bne @tc_not_tls13\n", "",
     ["test_reply_version_major_checked"]),
    ("not-tls13-code-0", "$84 on a refused non-1.3 session", NET,
     "        lda #UCI_ERR_CONNECT_FAIL   ; the client refused the session",
     "        lda #0                      ; the client refused the session",
     ["test_non_tls13_session_is_refused"]),
    ("hints-2-3-swapped", "each client reason prints its own text", UI,
     "m3_hint_lo:     .byte <m3_hint_1, <m3_hint_2, <m3_hint_3\nm3_hint_hi:     .byte >m3_hint_1, >m3_hint_2, >m3_hint_3",
     "m3_hint_lo:     .byte <m3_hint_1, <m3_hint_3, <m3_hint_2\nm3_hint_hi:     .byte >m3_hint_1, >m3_hint_3, >m3_hint_2",
     ["test_hint_texts_reach_the_user"]),
    ("wedge-89-overwritten", "a wedged Data More ABORT keeps $89", NET,
     "        jsr m3_abort_wait\n        bcc :+\n        jmp @p_dead_owned           ; wedged: keep the abort's $89\n:       jmp @p_dead_hdr",
     "        jsr m3_abort_wait\n        jmp @p_dead_hdr",
     ["test_data_more_wedge_keeps_89"]),
    ("held-session-stale", "an unclosed earlier session is reported", NET,
     "        lda #M3_HINT_HELD\n        sta m3_open_hint\n", "",
     ["test_held_session_message"]),
    ("any-14-is-no-tls13", "only alerts 40/70/71 mean no TLS 1.3", NET,
     "        cmp #71\n        bne @tc_refused_code\n", "",
     ["test_only_version_alerts_read_as_no_tls13"]),
    ("refusal-data-kept", "a refusal with reply bytes is released", NET,
     "        lda m3_rd_count\n        bne @tc_malformed\n        lda m3_code\n        bne @tc_refused             ; always\n",
     "        lda m3_code\n        jmp @tc_refused\n",
     ["test_refusal_with_data_is_released"]),
    ("held-session-code-0", "$84 on an Open refused over a held session", NET,
     "        lda #M3_HINT_HELD\n        sta m3_open_hint\n        lda #UCI_ERR_CONNECT_FAIL",
     "        lda #M3_HINT_HELD\n        sta m3_open_hint\n        lda #0",
     ["test_held_session_message"]),
    ("tls12-offered", "S 1.1/1.7 flags: TLS 1.3 only by default", NET,
     "M3_FLAGS = M3_FLAG_TLS13_ONLY", "M3_FLAGS = 0", ["test_open_layout"]),
]


def _stamp():
    text = (REPO / "build" / "flags.stamp").read_text().splitlines()
    vals = {}
    for line in text:
        if "=" in line:
            k, v = line.split("=", 1)
            vals[k] = v
    if vals.get("BACKEND") != "uci-m3":
        raise SystemExit("build/ is not a BACKEND=uci-m3 build (flags.stamp "
                         "says %r): run `make BACKEND=uci-m3` first"
                         % vals.get("BACKEND"))
    return vals


def _sources():
    mk = (REPO / "Makefile").read_text()
    block = mk.split("else ifeq ($(BACKEND),uci-m3)\n# The M3 variant's whole link", 1)[1]
    def grab(name):
        m = re.search(name + r" := (.*?)\n(?!    )", block, re.S)
        return m.group(1).replace("\\\n", " ").split()
    return grab("TOP_SRCS") + grab("NET_SRCS")


def build(workdir: Path, mutate=None) -> Path:
    """Copy src/ + cfg/ + the generated header, mutate, assemble, link."""
    if workdir.exists():
        shutil.rmtree(workdir)
    shutil.copytree(REPO / "src", workdir / "src")
    shutil.copytree(REPO / "cfg", workdir / "cfg")
    (workdir / "build").mkdir()
    shutil.copy(REPO / "build" / "https_host.inc", workdir / "build")
    if mutate:
        path, old, new = mutate
        f = workdir / path
        text = f.read_text()
        if text.count(old) != 1:
            raise SystemExit("mutant text matches %d times in %s:\n%s"
                             % (text.count(old), path, old))
        f.write_text(text.replace(old, new))
    st = _stamp()
    ca65 = shlex.split(st["CA65"]) + shlex.split(st["CA65FLAGS"])
    objs = []
    for src in _sources():
        obj = workdir / "build" / (src[len("src/"):-2] + ".o")
        obj.parent.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(ca65 + ["-o", str(obj), src], cwd=workdir,
                           capture_output=True, text=True)
        if r.returncode:
            raise RuntimeError("ca65 %s: %s" % (src, r.stderr.strip()))
        objs.append(str(obj.relative_to(workdir)))
    ld = shlex.split(st["LD65"]) + shlex.split(st["LD65FLAGS"])
    r = subprocess.run(ld + ["-o", "build/c64-https.prg"] + objs, cwd=workdir,
                       capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError("ld65: %s" % r.stderr.strip())
    labels = workdir / "build" / "labels.txt"
    labels.write_text(re.sub(r"^al 00([0-9a-fA-F]{4}) ", r"al C:\1 ",
                             labels.read_text(), flags=re.M))
    return workdir / "build" / "c64-https.prg"


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="m3mut-"))
    try:
        ctl = build(tmp / "control")
        want = sha(REPO / "build" / "c64-https.prg")
        if sha(ctl) != want:
            print("CONTROL FAIL: the runner's rebuild %s != build/ %s"
                  % (sha(ctl)[:16], want[:16]))
            return 1
        print("control: rebuild reproduces build/c64-https.prg (%s)" % want[:16])
        needed = sorted({n for m in MUTANTS for n in m[5]})
        res = t.run(ctl, ctl.parent / "labels.txt", only=needed, quiet=True)
        bad = [n for n, e in res.items() if e]
        if bad:
            print("CONTROL FAIL: tests red on the unmutated image: %s" % bad)
            return 1
        print("control: %d targeted tests pass on the unmutated image\n" % len(res))
        survivors = 0
        for name, rule, path, old, new, tests in MUTANTS:
            try:
                prg = build(tmp / name, (path, old, new))
            except RuntimeError as exc:
                # A mutant that does not build proves nothing about a test.
                survivors += 1
                print("BROKEN  %-22s %-40s does not build: %s"
                      % (name, rule, str(exc).splitlines()[0][:60]))
                continue
            res = t.run(prg, prg.parent / "labels.txt", only=tests, quiet=True)
            red = {n: e for n, e in res.items() if e}
            if red:
                first = next(iter(red.values())).splitlines()[0]
                print("KILLED  %-22s %-40s %s" % (name, rule, first[:90]))
            else:
                survivors += 1
                print("SURVIVED %-21s %-40s %s all pass" % (name, rule, tests))
            shutil.rmtree(tmp / name, ignore_errors=True)
        print("\n%d mutants, %d killed, %d survived or broken"
              % (len(MUTANTS), len(MUTANTS) - survivors, survivors))
        return 1 if survivors else 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
