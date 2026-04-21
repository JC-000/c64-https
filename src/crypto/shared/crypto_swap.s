; =============================================================================
; crypto_swap.s - Crypto overlay DMA dispatcher
;
; Pages one of two 8 KB overlay images (P-256, P-384) from REU
; bank 2 into the live CRYPTO_OVERLAY region. Call sites prefix each
; overlay-targeting primitive with `jsr crypto_swap_to_<overlay>`.
;
; Idempotent: re-entering with the same overlay already resident is a
; single-byte compare + rts (no DMA).
;
; Interrupt discipline: SEI around the DMA window; restores original I
; flag on exit. ~8 ms DMA latency at any CPU speed (REU bus runs at
; ~1 MHz regardless of turbo).
;
; Phase C.1 rollback note: the x25519 overlay integration was removed
; after it broke the TLS handshake at 48 MHz UCI. `crypto_swap_to_x25519`
; no longer exists; in-tree x25519 in `src/crypto/x25519.s` is
; always-resident. The remaining swap entry points exist for the
; external P-384 smoke test (tools/test_p384_symbols.py).
;
; `current_overlay`: 1 byte in CRYPTO_BSS (SHADOW_BSS-resident).
;   0 = none (uninitialized / swap_none)
;   2 = p256
;   3 = p384
;
; `CRYPTO_OVERLAY_START` is defined by the linker (cfg `MEMORY { }`
; `define = yes` on the CRYPTO_OVERLAY region — see cfg/c64-https-*.cfg).
; =============================================================================

        .include "constants.inc"        ; reu_* register equates
        .include "reu_layout.inc"

        .export crypto_swap_to_p256
        .export crypto_swap_to_p384
        .export crypto_swap_none
        .export current_overlay

        ; Export REU layout equates once (guarded against multi-include).
        .export REU_OVERLAY_P256
        .export REU_OVERLAY_P384
        .export OVERLAY_SIZE

        ; Live overlay slot start address (from the cfg's MEMORY{} define).
        .import __CRYPTO_OVERLAY_START__

; -----------------------------------------------------------------------------
; Overlay IDs — must stay in sync with `current_overlay` comments.
; -----------------------------------------------------------------------------
OV_NONE   = 0
OV_P256   = 2
OV_P384   = 3

; REU command: execute REU->C64 stash (bit 7 = start, bits 1-0 = direction
; 01 = REU-to-C64). Matches the DMA issue used elsewhere in the codebase.
REU_CMD_REU_TO_C64 = $91

; -----------------------------------------------------------------------------
; crypto_swap_to_p256 / _p384
; -----------------------------------------------------------------------------
.segment "LOADER_OVERFLOW"

crypto_swap_to_p256:
        lda #OV_P256
        cmp current_overlay
        beq swap_done_fast
        pha
        lda #<REU_OVERLAY_P256
        ldx #>REU_OVERLAY_P256
        ldy #^REU_OVERLAY_P256
        jsr do_swap
        pla
        sta current_overlay
        rts

crypto_swap_to_p384:
        lda #OV_P384
        cmp current_overlay
        beq swap_done_fast
        pha
        lda #<REU_OVERLAY_P384
        ldx #>REU_OVERLAY_P384
        ldy #^REU_OVERLAY_P384
        jsr do_swap
        pla
        sta current_overlay
        rts

crypto_swap_none:
        lda #OV_NONE
        sta current_overlay
        rts

swap_done_fast:
        rts

; -----------------------------------------------------------------------------
; do_swap - issue the REU -> C64 DMA of 8 KB into CRYPTO_OVERLAY
; IN:  A = REU source low byte
;      X = REU source middle byte
;      Y = REU source bank byte
; Clobbers A, X, Y. Saves / restores original I flag.
; -----------------------------------------------------------------------------
do_swap:
        ; Save current I flag on the stack (bit 2 of P).
        php
        sei

        ; REU source: bank + high/low address
        sta reu_reu_lo
        stx reu_reu_hi
        sty reu_reu_bank

        ; C64 target: CRYPTO_OVERLAY_START, 8 KB window
        lda #<__CRYPTO_OVERLAY_START__
        sta reu_c64_lo
        lda #>__CRYPTO_OVERLAY_START__
        sta reu_c64_hi

        ; 8 KB = $2000
        lda #<OVERLAY_SIZE
        sta reu_len_lo
        lda #>OVERLAY_SIZE
        sta reu_len_hi

        ; Normal autoincrement on both sides.
        lda #0
        sta reu_addr_ctrl

        ; Issue REU -> C64 DMA (command $91: bit7=start, 01=REU->C64).
        lda #REU_CMD_REU_TO_C64
        sta reu_command

        ; Restore original I flag.
        plp
        rts

; -----------------------------------------------------------------------------
; current_overlay - single-byte state tracking which overlay is resident.
; Lives in SHADOW_BSS-resident CRYPTO_BSS (via BSS segment) so it survives
; across calls without polluting ZP.
; -----------------------------------------------------------------------------
.segment "BSS"
current_overlay: .res 1
