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
; (a) is libs/nistcurves' nistcurves_reu_dma_wait with a SHORTER bound:
;     REU_CONFIRM_READS status reads, not 65,536. Reason: the shipped
;     ip65-onchip image runs on a stock C64 with no REU, where $DF00 is
;     open bus and bit 6 need never appear — and reu_mul_init executes
;     512 stashes at boot regardless of profile (boot.s keeps it; the C64U
;     drops its first TCP_CONNECT after a REU-quiet boot). 65,536 reads
;     per stash would add minutes to that boot at 1 MHz; 8 add ~0.1 s.
;     8 is libs/x25519's X25519_REU_SETTLE_ITER, whose reporter saw bit 6
;     on the FIRST read in all 19,416 calls: headroom, not a tuned figure.
;     Reading $DF00 clears bits 5-7, so the test is on the byte just read.
;     Bit 5 (VERIFY ERROR) is not tested: nothing here issues VERIFY.
; (b) is nistcurves' settle loop at a longer count: execute -> next REU
;     register access through this routine is
;       lda/sta 6 + bit/bvs 7 + lda/sta 6 + (9*ITER - 1) + rts 6
;     = 24 + 9*ITER = 114 cycles at ITER=10, against nistcurves' 106
;     (it counts a jsr we do not have) and the >= 49 cy floor measured at
;     48 MHz (U64E fw 3.15). 64 MHz is unbracketed upstream too; the C64U
;     runs our uci images there, so this errs long. The confirm read
;     itself costs ~49 cy at turbo on the U64E and is not counted.
;
; On expiry reu_dma_timeout is set to 1 (sticky; zero at boot, never
; cleared) and execution proceeds — there is no error channel, as upstream.
; On a no-REU machine it is therefore 1 after boot by design; on a REU
; profile it should read 0, which is what makes it a rig oracle.
;
; In: A = REU command byte. Clobbers: A, N/V/Z. X, Y and C preserved, so
; it drops into every former `sta reu_command` site (reu_fetch_mul_row
; documents "Clobbers: A" to fe25519's hot loop).
;
; CRYPTO_AUX_CODE: jsr-only and resident at boot on both backends (ip65
; CRYPTO_OVERLAY, uci NET_CODE) — NOT the uci-comb CRYPTO_OVERLAY tail the
; rigs' MemoryArbiter hands out, and not ip65's LOADER.
; =============================================================================

.include "constants.inc"

.export reu_execute
.export reu_dma_timeout

REU_CONFIRM_READS = 8
REU_SETTLE_ITER   = 10

.segment "CRYPTO_AUX_CODE"
reu_execute:
        sta reu_command
        lda #REU_CONFIRM_READS
        sta reu_wait_cnt
@spin:
        bit reu_status          ; V = bit 6 END OF BLOCK; read clears 5-7
        bvs @settle
        dec reu_wait_cnt
        bne @spin
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
reu_wait_cnt:           .res 1
reu_dma_timeout:        .res 1
