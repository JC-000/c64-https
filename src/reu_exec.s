; =============================================================================
; src/reu_exec.s — the one place c64-https executes a REU command (#191).
;
; c64-lib-contract SPEC §8.2 (contract#144/#146): on a turbo-clocked
; Ultimate 64 the REU's post-transfer restore can outlast the CPU, so the
; next REU register access after an execute can be lost or misapplied.
; Every execute must be followed, before the next REU register access, by
;   (a) a read of reu_status ($DF00) confirming bit 6 (END OF BLOCK),
;       spinning bounded if it is not, and
;   (b) a post-execute settle.
; Both sibling libraries do this inside their own code; this is the same
; obligation for the execute sites in our own source, which no library
; bump can reach. Every `sta reu_command` in src/ is `jsr reu_execute`
; instead; tools/test_reu_execute.py fails on a bare one.
;
; (a) is libs/nistcurves' nistcurves_reu_dma_wait, with a bound that
;     depends on whether the profile REQUIRES a REU:
;       REU_CONFIRM_LONG (comb, and the REU row-fetch default): 65,536
;         status reads, nistcurves' own bound -- a REU is there, so the
;         confirm must be able to actually wait for it;
;       otherwise (ip65-onchip, uci-onchip -- the no-REU products): 8
;         reads, libs/x25519's X25519_REU_SETTLE_ITER. These images boot on
;         machines with no REU, where $DF00 is not a REU register at all
;         and bit 6 need never appear, and reu_mul_init still executes 512
;         stashes at boot (boot.s keeps it; the C64U drops its first
;         TCP_CONNECT after a REU-quiet boot). 65,536 reads per stash would
;         add minutes to that boot at 1 MHz; 8 add ~0.1 s. x25519's
;         reporter saw bit 6 on the FIRST read in all 19,416 calls.
;     Reading $DF00 clears bits 5-7, so the test is on the byte just read.
;     Bit 5 (VERIFY ERROR) is not tested: nothing here issues VERIFY.
; (b) is nistcurves' settle loop at a longer count: execute -> next REU
;     register access through this routine is
;       lda/sta 6 + bit/bvs 7 + lda/sta 6 + (9*ITER - 1) + rts 6
;     = 24 + 9*ITER = 114 cycles at ITER=10 (the long variant's
;     lda/sta/sta is 10, so 118), against nistcurves' 106
;     (it counts a jsr we do not have) and the >= 49 cy floor measured at
;     48 MHz (U64E fw 3.15). 64 MHz is unbracketed upstream too; the C64U
;     runs our uci images there, so this errs long. The confirm read
;     itself costs ~49 cy at turbo on the U64E and is not counted.
;
; On expiry reu_dma_timeout is set to 1 (sticky; zero at boot, never
; cleared) and execution proceeds — there is no error channel, as upstream.
; With a working REU attached it reads 0, which is what makes it a rig
; oracle. Without one it depends on what $DF00 returns: 1 in VICE (the
; open-bus value never has bit 6 set for 8 reads); on real hardware the
; open bus follows the last VIC fetch, so no value is promised.
;
; In: A = REU command byte. Clobbers: A, N/V/Z. X, Y and C preserved, so
; it drops into every former `sta reu_command` site (reu_fetch_mul_row
; documents "Clobbers: A" to fe25519's hot loop).
;
; Segment: CRYPTO_AUX_CODE (jsr-only, resident at boot: ip65
; CRYPTO_OVERLAY, uci NET_CODE — NOT the uci-comb CRYPTO_OVERLAY tail the
; rigs' MemoryArbiter hands out, and not ip65's LOADER), except on ip65's
; REU default, where CRYPTO_OVERLAY is the tighter half of its pool and
; CRYPTO_RESIDENT has the room (CRYPTO_CODE).
; =============================================================================

.include "constants.inc"

.export reu_execute
.export reu_dma_timeout

.if .defined(USE_NISTCURVES_COMB) .or (.not .defined(USE_NISTCURVES_ONCHIP))
REU_CONFIRM_LONG = 1
.endif
REU_CONFIRM_READS = 8           ; short bound (no-REU products)
REU_SETTLE_ITER   = 10
; The settle floor tools/test_reu_execute.py also checks: 24 + 9*ITER
; cycles must stay above nistcurves' 106.
.assert 24 + 9 * REU_SETTLE_ITER >= 106, error, "REU settle below nistcurves' 106-cycle floor"

.if .defined(REU_CONFIRM_LONG) .and (.not .defined(BACKEND_UCI))
.segment "CRYPTO_CODE"
.else
.segment "CRYPTO_AUX_CODE"
.endif
reu_execute:
        sta reu_command
.ifdef REU_CONFIRM_LONG
        lda #0
        sta reu_wait_cnt
        sta reu_wait_cnt+1
@spin:
        bit reu_status          ; V = bit 6 END OF BLOCK; read clears 5-7
        bvs @settle
        inc reu_wait_cnt
        bne @spin
        inc reu_wait_cnt+1
        bne @spin
.else
        lda #REU_CONFIRM_READS
        sta reu_wait_cnt
@spin:
        bit reu_status          ; V = bit 6 END OF BLOCK; read clears 5-7
        bvs @settle
        dec reu_wait_cnt
        bne @spin
.endif
        lda #1                  ; bound expired: sticky flag, proceed
        sta reu_dma_timeout
@settle:
        lda #REU_SETTLE_ITER
        sta reu_wait_cnt
@settle_loop:
        dec reu_wait_cnt        ; 6 + 3 = 9 cycles per iteration
        bne @settle_loop
        rts

.segment "BSS"
.ifdef REU_CONFIRM_LONG
reu_wait_cnt:           .res 2
.else
reu_wait_cnt:           .res 1
.endif
reu_dma_timeout:        .res 1
