; =============================================================================
; crypto_init.s - Top-level crypto init orchestrator
;
; Single entry point called from `src/boot.s` right after the entropy seed
; and before the menu loop. Subsequent phases (C.2/.3) will hang more
; per-library init routines off this file at the insertion marker below.
;
; Phase C.1 adds the x25519 sibling REU mul-table init (128 KB of
; multiplication rows stashed to REU banks 0-5 for fe25519_mul / _sqr
; hot paths) and the boot-time overlay stash that copies the x25519 code
; image from CRYPTO_OVERLAY ($4200) to REU bank 2 offset $0100, so future
; `crypto_swap_to_x25519` calls can restore it after a P-256 / P-384 swap.
;
; Dispatch order (executed once at boot):
;   1. mul_tables_init          (shared 8x8 sqtab)         [Phase C.0: stub]
;   2. x25519_sqtab_init        (sibling sqtab @ $7800)    [Phase C.1, UCI]
;   3. x25519_reu_mul_init      (x25519 128 KB REU stash)  [Phase C.1, UCI]
;   4. crypto_overlay_stash_x25519  (PRG image -> REU)     [Phase C.1, UCI]
;   5. poly1305_shoup_init      (Profile A Shoup r_tab)    [Phase C.2]
;   6. ec_precompute_256        (P-256 scalar precompute)  [Phase C.3]
;   7. ec_precompute_384        (P-384 scalar precompute)  [Phase C.3]
; =============================================================================

        .include "constants.inc"        ; reu_* register equates
        .include "reu_layout.inc"       ; REU_OVERLAY_X25519, OVERLAY_SIZE

        .export crypto_init
        .import mul_tables_init

.ifdef USE_X25519_SIBLING
        .import x25519_sqtab_init
        .import x25519_reu_mul_init
        .import current_overlay
        ; CRYPTO_OVERLAY start address (ld65 symbol from cfg MEMORY{}).
        .import __CRYPTO_OVERLAY_START__
.endif

; -----------------------------------------------------------------------------
; crypto_init - call each crypto module's init once at boot.
; -----------------------------------------------------------------------------
.segment "CODE"

crypto_init:
        jsr mul_tables_init

.ifdef USE_X25519_SIBLING
        ; Ensure BASIC ROM shadow is off so REU DMA targets above $8000
        ; land in plain RAM. boot.s already clears $01 bit 0 before
        ; reu_mul_init under ip65; replicate the guard here so the UCI
        ; path is self-contained.
        lda $01
        and #%11111110
        sta $01

        ; 2. Build the 1 KB quarter-square table at $7800/$7a00 (sibling's
        ;    fixed address — ABI with mul_8x8). This replaces the in-tree
        ;    poly1305.s `sqtab_init` call on the UCI path, because the
        ;    sibling's fe25519/mul_8x8 code loads from $7800 directly.
        jsr x25519_sqtab_init

        ; 3. Stash 256 full mul rows (128 KB) to REU banks 0-5 plus the
        ;    64-byte zero buffer at bank 2 offset $0000 used by
        ;    reu_clear_wide. Takes a few seconds at 1 MHz.
        jsr x25519_reu_mul_init

        ; 4. Stash the x25519 overlay image (8 KB starting at
        ;    CRYPTO_OVERLAY_START) to REU bank 2 offset $0100. The offset
        ;    dodges the 64-byte zero buffer written by reu_mul_init above.
        jsr crypto_overlay_stash_x25519

        ; The overlay is now live in CRYPTO_OVERLAY RAM (it was loaded
        ; there by the PRG) *and* in REU bank 2 offset $0100 (just
        ; stashed). Mark current_overlay = OV_X25519 so subsequent
        ; `crypto_swap_to_x25519` calls are no-ops until a P-256/P-384
        ; swap displaces it.
        lda #1                  ; OV_X25519
        sta current_overlay
.endif

        ; === Phase C.2-.3 insertion point ===
        ; Add `jsr <lib>_init` lines BELOW this marker (one per Phase C
        ; agent) in the dispatch order documented at the top of this file.
        ; ====================================

        rts

.ifdef USE_X25519_SIBLING
; -----------------------------------------------------------------------------
; crypto_overlay_stash_x25519 - one-shot boot-time DMA of the live
; x25519 overlay image into REU bank 2 offset $0100.
;
; The image is already resident at CRYPTO_OVERLAY_START because ld65 placed
; the OVERLAY_X25519 segment there at PRG load time. This STASH pushes a
; copy to REU so a future `crypto_swap_to_x25519` can DMA it back after a
; competing overlay (P-256 / P-384) has overwritten the C64-side slot.
;
; Clobbers A, X, Y. SEI / PLP around the DMA write window.
; -----------------------------------------------------------------------------
crypto_overlay_stash_x25519:
        php
        sei

        ; C64 source: CRYPTO_OVERLAY_START
        lda #<__CRYPTO_OVERLAY_START__
        sta reu_c64_lo
        lda #>__CRYPTO_OVERLAY_START__
        sta reu_c64_hi

        ; REU destination: bank 2 offset $0100
        ; REU_OVERLAY_X25519 = $20100 (see reu_layout.inc).
        lda #<REU_OVERLAY_X25519
        sta reu_reu_lo
        lda #>REU_OVERLAY_X25519
        sta reu_reu_hi
        lda #^REU_OVERLAY_X25519        ; bank = 2
        sta reu_reu_bank

        ; Transfer length: OVERLAY_SIZE = $2000 (8 KB)
        lda #<OVERLAY_SIZE
        sta reu_len_lo
        lda #>OVERLAY_SIZE
        sta reu_len_hi

        ; Normal autoincrement on both sides.
        lda #0
        sta reu_addr_ctrl

        ; REU STASH: execute + C64->REU (command $90: bit7=start, 00=C64->REU).
        lda #$90
        sta reu_command

        plp
        rts
.endif
