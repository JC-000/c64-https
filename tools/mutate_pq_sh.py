#!/usr/bin/env python3
"""mutate_pq_sh.py - break each check of the PQ_HYBRID P4 code, prove a test notices.

For every mutant: the source file is edited in place (the edit must match
exactly once), the PQ image is rebuilt from clean, and the named suite runs
with C64_FAIL_FAST=1. The mutant is KILLED if the suite exits non-zero; a
mutant that builds and passes is a hole in the tests (SURVIVED) and a mutant
that does not build is reported BUILD-FAIL (not a kill: the check was not
what stopped it). Every edited file is restored in a finally block and the
control is rebuilt and re-run at the end.

    python3 tools/mutate_pq_sh.py                  # all mutants
    python3 tools/mutate_pq_sh.py M03 M11          # some
    python3 tools/mutate_pq_sh.py --list
    python3 tools/mutate_pq_sh.py --no-control ...   # skip the green control runs

Needs a toolchain and VICE; ~2-4 min per mutant (the kem suites are slow).
Builds in THIS checkout (overwrites build/): run it in a scratch worktree.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PQ_ARGS = ["BACKEND=uci", "USE_NISTCURVES_ONCHIP=1", "PQ_HYBRID=1"]

H = "src/crypto/pq_hybrid.s"
T13 = "src/tls13.s"
SCR = "src/session_scrub.s"

# (id, what it breaks, file, old, new, suite command)
SH = ["tools/test_pq_sh.py"]
SH1 = ["tools/test_pq_sh.py", "1"]
SH2 = ["tools/test_pq_sh.py", "2"]
SH3 = ["tools/test_pq_sh.py", "3"]
SH4 = ["tools/test_pq_sh.py", "4"]
KEM = ["tools/test_pq_kem.py"]
KS = ["tools/test_pq_keyschedule.py"]
KSF = "src/tls_keyschedule.s"


SCRUB_BODY = """pq_mlkem_scrub:
        php
        sei
        lda $01
        pha
        lda #$34
        sta $01
        lda #>__MLKEM_POLY_RAM_START__
        ldx #>__MLKEM_POLY_RAM_SIZE__
        jsr @zero
        lda #>__MLKEM_BSS_RAM_START__
        ldx #>__MLKEM_BSS_RAM_SIZE__
        jsr @zero
        pla
        sta $01
        plp
        rts
@zero:"""


def nop(n):
    return "        nop\n" * n


MUTANTS = [
    ("M01", "key_exchange length: the low byte of 1,120 is not checked", H,
     "        lda shs_f+3\n        cmp #<MLKEM_HYB_SH_KEY\n        bne @kslen\n",
     "        lda shs_f+3\n        cmp #<MLKEM_HYB_SH_KEY\n" + nop(2), SH2),
    ("M02", "key_exchange length: the high byte of 1,120 is not checked", H,
     "        cmp #>MLKEM_HYB_SH_KEY\n        bne @kslen\n",
     "        cmp #>MLKEM_HYB_SH_KEY\n" + nop(2), SH2),
    ("M03", "group: the 11EC low byte is not checked", H,
     "        lda shs_f+1\n        cmp #$ec\n        bne @grp\n",
     "        lda shs_f+1\n        cmp #$ec\n" + nop(2), SH2),
    ("M04", "group: the 11EC high byte is not checked", H,
     "        cmp #$11\n        bne @grp\n", "        cmp #$11\n" + nop(2), SH2),
    ("M05", "group: the 001D low byte is not checked", H,
     "@g00:   lda shs_f+1\n        cmp #$1d\n        bne @grp\n",
     "@g00:   lda shs_f+1\n        cmp #$1d\n" + nop(2), SH2),
    ("M06", "group: 11EC accepted although it was not offered", H,
     "        lda tls_pq_offered              ; 11EC only if this hello offered it\n        beq @grp\n",
     "        lda tls_pq_offered\n" + nop(2), SH2),
    ("M07", "001D share length: the low byte is not checked", H,
     "        lda shs_f+3\n        cmp #32\n        bne @kslen\n",
     "        lda shs_f+3\n        cmp #32\n" + nop(2), SH2),
    ("M08", "ct copy bound: one byte too many", H,
     "tab_cl: .byte 4, 2, 32, 6, 4, 2, 4, <MLKEM_CT_SIZE,",
     "tab_cl: .byte 4, 2, 32, 6, 4, 2, 4, <(MLKEM_CT_SIZE+1),", SH1),
    ("M09", "ct copy bound: one byte too few", H,
     "tab_cl: .byte 4, 2, 32, 6, 4, 2, 4, <MLKEM_CT_SIZE,",
     "tab_cl: .byte 4, 2, 32, 6, 4, 2, 4, <(MLKEM_CT_SIZE-1),", SH1),
    ("M10", "ct destination: the pointer's page does not advance", H,
     "        bne shs_nost\n        inc shs_st+2\n", "        bne shs_nost\n" + nop(2), SH1),
    ("M11", "transcript: the record is never folded", H,
     "        jsr tls_transcript_update\n        clc\n        lda shs_state\n",
     "        clc\n        lda shs_state\n", SH1),
    ("M12", "transcript: the record is folded twice", H,
     "        jsr tls_transcript_update\n        clc\n        lda shs_state\n",
     "        jsr tls_transcript_update\n        lda #<tls_rec_buf\n        sta zp_ptr\n        lda #>tls_rec_buf\n        sta zp_ptr+1\n        lda tls_rec_len\n        sta zp_count\n        lda tls_rec_len+1\n        sta zp_count+1\n        jsr tls_transcript_update\n        clc\n        lda shs_state\n", SH1),
    ("M13", "transcript: the fold stops one byte short", H,
     "        lda tls_rec_len\n        sta zp_count\n        lda tls_rec_len+1\n        sta zp_count+1\n        jsr tls_transcript_update",
     "        lda tls_rec_len\n        sec\n        sbc #1\n        sta zp_count\n        lda tls_rec_len+1\n        sta zp_count+1\n        jsr tls_transcript_update", SH1),
    ("M14", "fragmenting: the field counter does not borrow across 256", H,
     "        bne :+\n        dec shs_cnt+1\n:       dec shs_cnt\n",
     "        bne :+\n" + nop(2) + ":       dec shs_cnt\n", SH1),
    ("M15", "fragmenting: the record byte count does not borrow across 256", H,
     "        bne :+\n        dec zp_count+1\n:       dec zp_count\n",
     "        bne :+\n" + nop(2) + ":       dec zp_count\n", SH1),
    ("M16", "fragmenting: the message-left counter does not borrow", H,
     "        bne :+\n        dec shs_rem+1\n:       dec shs_rem\n",
     "        bne :+\n" + nop(2) + ":       dec shs_rem\n", SH1),
    ("M17", "Decaps outcome ignored (refusal and status)", H,
     "        bcs @fail\n        cmp #0\n        bne @fail\n@done:  jsr pq_seed_zero\n",
     nop(5) + "@done:  jsr pq_seed_zero\n", SH3),
    ("M18", "dk scratch: the tail loop bound is wrong", H,
     "        cpy #<MLKEM_DK_SIZE\n", "        cpy #0\n", SH3),
    ("M19", "dk scratch: one page short", H,
     "        ldx #>MLKEM_DK_SIZE\n", "        ldx #(>MLKEM_DK_SIZE)-1\n", SH3),
    ("M20", "dk scratch: not zeroed on a KeyGen that was refused", H,
     "        jsr pq_mlkem_keygen             ; C=1/A=$FF refused; C=0: A = status\n        pha\n        jsr pq_dk_zero                  ; BEFORE anything else, success or not\n",
     "        jsr pq_mlkem_keygen\n        cmp #0\n        bne @fail\n        pha\n        jsr pq_dk_zero\n", SH3),
    ("M21", "KeyGen status ignored: a refused KeyGen still arms", H,
     "        pla\n        bne @fail                       ; refusal ($FF) or a non-zero status\n",
     "        pla\n" + nop(2), SH3),
    ("M22", "the ek length armed is off by one", H,
     "        lda #<MLKEM_EK_SIZE\n        sta tls_ch_ks_len\n",
     "        lda #<(MLKEM_EK_SIZE+1)\n        sta tls_ch_ks_len\n", KEM + ["prep"]),
    ("M23", "seed not zeroed after a successful Decaps", H,
     "@done:  jsr pq_seed_zero\n        clc\n", "@done:  nop\n        nop\n        nop\n        clc\n", KEM + ["decaps"]),
    ("M24", "the seed span is missing from the 'Q' scrub", SCR,
     "        SPAN tls_pq_seed,       tls_mlkem_ss + 32,      96\n", "", SH4),
    ("M25", "the ML-KEM secret is outside the scrub span", SCR,
     "        SPAN tls_pq_seed,       tls_mlkem_ss + 32,      96\n",
     "        SPAN tls_pq_seed,       tls_pq_seed + 64,       64\n", SH4),
    ("M26", "HelloRetryRequest is not recognised", H,
     "h_rnd:  jsr tls_sh_chk_hrr              ; C=1: tls_sh_err = SH_ERR_HRR\n        bcs @hrr\n",
     "h_rnd:  clc\n        bcs @hrr\n", SH2),
    ("M27", "bytes after the message are accepted", H,
     "        cpx #SS_DONE\n        bne shs_live\n        lda #SH_ERR_TRAIL\n        bne shs_fail\n",
     "        cpx #SS_DONE\n        bne shs_live\n        clc\n        rts\n", SH2),
    ("M28", "a second key_share is accepted", H,
     "@ks:    lda shs_seen\n        and #2\n        bne @kslen\n", "@ks:    lda shs_seen\n" + nop(3), SH2),
    ("M29", "a second supported_versions is accepted", H,
     "@sv:    lda shs_seen\n        and #1\n        bne @ver\n", "@sv:    lda shs_seen\n" + nop(3), SH2),
    ("M30", "extensions_length need not fill the message", H,
     "        lda shs_f+5\n        cmp shs_rem\n        bne @ext\n", "        lda shs_f+5\n" + nop(3), SH2),
    ("M31", "extension data may overrun the message", H,
     "        sbc shs_d+1\n        bcc @ext\n", "        sbc shs_d+1\n" + nop(2), SH2),
    ("M32", "a missing key_share/supported_versions is accepted", H,
     "        cmp #3\n        bne @missing\n        lda #SS_DONE\n", "        cmp #3\n" + nop(2) + "        lda #SS_DONE\n", SH2),
    ("M33", "cipher suite is not checked", H,
     "        lda shs_f+1                     ; suite 1303\n        cmp #$13\n        bne @bad\n",
     "        lda shs_f+1\n        cmp #$13\n" + nop(2), SH2),
    ("M34", "the session id echo is not checked", H,
     "h_fix:  lda shs_f                       ; session id echo length 0\n        bne @bad\n",
     "h_fix:  lda shs_f\n" + nop(2), SH2),
    ("M35", "the handshake type is not checked", H,
     "        cmp #TLS_HS_SERVER_HELLO\n        bne @bad\n", "        cmp #TLS_HS_SERVER_HELLO\n" + nop(2), SH2),
    ("M36", "the message length cap is gone", H,
     "        cmp #SHS_MAX_HI\n        bcs @bad\n", "        cmp #SHS_MAX_HI\n" + nop(2), SH2),
    ("M37", "a non-handshake record is parsed", H,
     "        lda tls_rec_type\n        cmp #TLS_CT_HANDSHAKE\n        bne @bad_rec\n",
     "        lda tls_rec_type\n        cmp #TLS_CT_HANDSHAKE\n" + nop(2), SH2),
    ("M38", "an extension type's high byte is ignored (0x0133 read as key_share)", H,
     "        lda shs_f                       ; type\n        bne @other\n",
     "        lda shs_f                       ; type\n" + nop(2), SH2),
    ("M39", "tls_connect never calls pq_connect_prep", T13,
     "        jsr pq_connect_prep     ; KeyGen + arm the hybrid key share (C=1: refused)\n        bcc :+\n        jmp @error\n:\n",
     "", KEM + ["connect"]),
    ("M40", "tls_connect ignores a refused KeyGen", T13,
     "        jsr pq_connect_prep     ; KeyGen + arm the hybrid key share (C=1: refused)\n        bcc :+\n        jmp @error\n:\n",
     "        jsr pq_connect_prep\n", KEM + ["refused"]),
    ("M41", "tls_recv_server_hello ignores a refusal of the reader", T13,
     "        jsr pq_sh_feed\n        bcs @sh_error\n", "        jsr pq_sh_feed\n        clc\n", KEM + ["bad"]),
    ("M42", "Decaps runs after the X25519 mult instead of before", T13,
     "        jsr pq_sh_decaps\n        bcs @sh_error\n.endif\n        jsr tls_ecdh_compute_shared\n        bcs @sh_error\n",
     ".endif\n        jsr tls_ecdh_compute_shared\n        bcs @sh_error\n.ifdef PQ_HYBRID\n        jsr pq_sh_decaps\n        bcs @sh_error\n.endif\n", KEM + ["connect"]),
    ("M43", "tls_connect's error exit does not scrub the seed", T13,
     "        jsr pq_seed_zero        ;", "        nop\n        nop\n        nop        ;", KEM + ["bad"]),
    ("M44", "Decaps is skipped for an 11EC server", H,
     "        lda tls_kex_group\n        cmp #$EC\n        bne @done\n", "        lda tls_kex_group\n        cmp #$EC\n        bne @done\n        jmp @done\n", KEM + ["decaps"]),
    ("M45", "the next prep does not scrub the previous ss/seed", H,
     "        jsr pq_secrets_zero             ; no earlier session's ss survives\n", nop(3), SH3),
    ("M46", "the SH timeout budget is re-armed per record", T13,
     "        bne @sh_wait                    ; Z=0: more records; ONE timeout budget for the whole SH\n",
     "        lda #0\n        sta sh_timeout\n        sta sh_timeout+1\n        beq @sh_wait\n", KEM + ["timeout"]),
    ("M47", "an unsolicited extension is accepted", H,
     "@other: lda #SH_ERR_EXT                 ; we requested only these two (RFC 8446 4.2)\n        jmp shs_fail\n",
     "@other: jmp ext_next\n", SH2),
    ("M48", "pq_sh_init does not reset tls_kex_group", H,
     "        sta shs_seen\n        sta tls_kex_group\n", "        sta shs_seen\n" + nop(3), SH3),
    ("M49", "Decaps leaves y/e1/e2 and m'/K'/r' behind", H,
     "        jsr pq_mlkem_scrub              ; y/e1/e2 in $D000, m'/K'/r' in the window, any outcome (preserves C)\n", nop(3), KEM + ["decaps"]),
    ("M50", "KeyGen leaves s_hat behind", H,
     "        jsr pq_mlkem_scrub              ; s_hat in $D000 and the sponge/ring residue in the window\n", nop(3), KEM + ["prep"]),
    ("M51", "the scrub misses the last polynomial page", "src/crypto/mlkem_link.s",
     "        ldx #>__MLKEM_POLY_RAM_SIZE__\n", "        ldx #(>__MLKEM_POLY_RAM_SIZE__)-1\n", SH + ["5"]),
    ("M52", "the scrub misses the last window page", "src/crypto/mlkem_link.s",
     "        ldx #>__MLKEM_BSS_RAM_SIZE__\n", "        ldx #(>__MLKEM_BSS_RAM_SIZE__)-1\n", SH + ["5"]),
    ("M53", "a malformed record header while waiting for the SH is not fatal", "src/tls_record_io.s",
     "        cmp #TLS_STATE_SERVER_HELLO     ; a hybrid SH is read record by record: a bad\n",
     "        cmp #TLS_STATE_ENCRYPTED_EXT\n", KEM + ["oversize"]),
    ("M54", "the oversize-record refusal sets no tls_sh_err", T13,
     "        sta tls_sh_err                  ;  not fit tls_rec_buf): fail now, do not\n", nop(3), KEM + ["oversize"]),
    ("M55", "001D key length: the high byte is not checked", H,
     "        lda shs_f+2                     ; exactly 32\n        bne @kslen\n", "        lda shs_f+2\n" + nop(2), SH2),
    ("Y3", "pq_mlkem_scrub does not restore $01", "src/crypto/mlkem_link.s",
     "        jsr @zero\n        pla\n        sta $01\n        plp\n        rts\n@zero:",
     "        jsr @zero\n        pla\n" + nop(2) + "        plp\n        rts\n@zero:", SH + ["5"]),
    ("Y4", "pq_mlkem_scrub does not save/restore the I flag", "src/crypto/mlkem_link.s",
     SCRUB_BODY,
     SCRUB_BODY.replace("pq_mlkem_scrub:\n        php\n", "pq_mlkem_scrub:\n        nop\n")
                .replace("        sta $01\n        plp\n        rts\n@zero:", "        sta $01\n        nop\n        rts\n@zero:"), SH + ["5"]),
    ("Y3p", "$01 leaks out of the post-KeyGen scrub", "src/crypto/mlkem_link.s",
     "        jsr @zero\n        pla\n        sta $01\n        plp\n        rts\n@zero:",
     "        jsr @zero\n        pla\n" + nop(2) + "        plp\n        rts\n@zero:", KEM + ["prep"]),
    ("Y4d", "the I flag leaks out of the post-Decaps scrub", "src/crypto/mlkem_link.s",
     SCRUB_BODY,
     SCRUB_BODY.replace("pq_mlkem_scrub:\n        php\n", "pq_mlkem_scrub:\n        nop\n")
                .replace("        sta $01\n        plp\n        rts\n@zero:", "        sta $01\n        nop\n        rts\n@zero:"), KEM + ["decaps"]),
    ("M56", "the SH loop ignores the ERROR latch", T13,
     "        bpl :+                          ;  record header while waiting for the SH\n",
     "        jmp :+\n", KEM + ["oversize"]),
    # --- P5: the hybrid key schedule (suite: tools/test_pq_keyschedule.py) ---
    ("K01", "wrong IKM order: x25519_ss || mlkem_ss", KSF,
     "        lda tls_mlkem_ss,x\n        sta input_buffer,x\n        lda tls_shared_secret,x\n        sta input_buffer+32,x\n",
     "        lda tls_mlkem_ss,x\n        sta input_buffer+32,x\n        lda tls_shared_secret,x\n        sta input_buffer,x\n", KS),
    ("K02", "IKM length 32 instead of 64", KSF,
     "        lda #64\n        sta hkdf_ikm_len\n", "        lda #32\n        sta hkdf_ikm_len\n", KS),
    ("K03", "group test inverted (hybrid only for a non-11EC group)", KSF,
     "        cmp #$EC\n        bne @dhk_ikm_ready\n", "        cmp #$EC\n        beq @dhk_ikm_ready\n", KS),
    ("K04", "group test compares 001D instead of 11EC", KSF,
     "        cmp #$EC\n        bne @dhk_ikm_ready\n", "        cmp #$1D\n        bne @dhk_ikm_ready\n", KS),
    ("K05", "the hybrid IKM is never selected (always classic)", KSF,
     "        cmp #$EC\n        bne @dhk_ikm_ready\n", "        cmp #$EC\n        jmp @dhk_ikm_ready\n", KS),
    ("K06", "the IKM pointer still names tls_shared_secret", KSF,
     "        lda #<input_buffer\n        sta hkdf_ikm_ptr\n        lda #>input_buffer\n        sta hkdf_ikm_ptr+1\n        lda #64\n",
     "        lda #64\n", KS),
    ("K07", "the concatenation stops one byte short", KSF,
     "        ldx #31\n@dhk_cat:", "        ldx #30\n@dhk_cat:", KS),
    ("K08", "the x25519 ss is not zeroed after the extract", KSF,
     "@dhk_zss:\n        sta tls_shared_secret,x\n", "@dhk_zss:\n" + nop(3), KS),
    ("K09", "tls_mlkem_ss is not zeroed after the extract", KSF,
     "        sta tls_mlkem_ss,x\n        dex\n        bpl @dhk_zss\n", nop(3) + "        dex\n        bpl @dhk_zss\n", KS),
    ("K10", "the IKM concatenation in input_buffer is not zeroed", KSF,
     "@dhk_zero:\n        sta input_buffer,x\n", "@dhk_zero:\n" + nop(3), KS),
    ("K11", "hkdf_extract's copy of the IKM (hmac_data_buf) is not zeroed", KSF,
     "        sta hmac_data_buf,x\n        dex\n        bpl @dhk_zero\n", nop(3) + "        dex\n        bpl @dhk_zero\n", KS),
    ("K12", "the IKM zeroing covers only 32 of the 64 bytes", KSF,
     "        lda #0\n        ldx #63\n@dhk_zero:", "        lda #0\n        ldx #31\n@dhk_zero:", KS),
    ("X02", "hybrid for any group >= $EC (bne -> bcc after the compare)", KSF,
     "        cmp #$EC\n        bne @dhk_ikm_ready\n", "        cmp #$EC\n        bcc @dhk_ikm_ready\n", KS),
]


def run(cmd, env=None, timeout=3600):
    e = dict(os.environ, C64_SKIP_BUILD="1", C64_FAIL_FAST="1")
    e.update(env or {})
    r = subprocess.run([sys.executable] + cmd, cwd=REPO, env=e,
                       capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout + r.stderr


def build():
    subprocess.run(["make", "clean"], cwd=REPO, capture_output=True)
    r = subprocess.run(["make"] + PQ_ARGS, cwd=REPO, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if "--list" in sys.argv:
        for mid, what, f, _o, _n, suite in MUTANTS:
            print(f"{mid}  {what}  [{f}]  -> {' '.join(suite)}")
        return 0
    want = [m for m in MUTANTS if not args or m[0] in args]
    results = []
    rc, out = build()
    if rc:
        print(out[-2000:])
        return 2
    if "--no-control" not in sys.argv:
        # A mutant "killed" by a suite that is red on the unmodified tree
        # proves nothing: the controls go first.
        for c in (SH, KEM, KS):
            crc, cout = run(c, env={"C64_FAIL_FAST": "0"})
            print(f"control {' '.join(c)}: rc={crc}", flush=True)
            if crc:
                print(cout[-2500:])
                return 2
    for mid, what, f, old, new, suite in want:
        p = REPO / f
        orig = p.read_text()
        if orig.count(old) != 1:
            print(f"{mid}: pattern matches {orig.count(old)} times in {f}: FIX THE MUTANT")
            results.append((mid, what, "BAD-PATTERN"))
            continue
        t0 = time.monotonic()
        try:
            p.write_text(orig.replace(old, new, 1))
            rc, out = build()
            if rc:
                verdict = "BUILD-FAIL"
                print(out[-600:])
            else:
                rc, out = run(suite)
                killed = [ln for ln in out.splitlines() if "FAIL" in ln][:1]
                if rc == 0:
                    verdict = "SURVIVED"
                elif killed:
                    verdict = f"KILLED by: {killed[0].strip()[:110]}"
                else:
                    # non-zero exit without an assertion FAIL line: a crash,
                    # hang or harness error, not a kill by a check
                    verdict = f"CRASH-OR-HANG (rc={rc}, no FAIL line; NOT a kill): {out.strip()[-120:]!r}"
        finally:
            p.write_text(orig)
        print(f"{mid} {what}: {verdict} ({time.monotonic() - t0:.0f} s)", flush=True)
        results.append((mid, what, verdict))
    rc, out = build()
    ctl = run(SH)[0] if rc == 0 else rc
    print(f"\ncontrol after restore: build rc={rc}, test_pq_sh rc={ctl}")
    bad = [r for r in results if not r[2].startswith("KILLED")]
    print(f"{len(results) - len(bad)}/{len(results)} mutants killed")
    for r in bad:
        print("  NOT KILLED:", r)
    return 0 if not bad and ctl == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
