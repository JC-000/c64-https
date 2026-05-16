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
;
; -----------------------------------------------------------------------------
; Phase 1.5 split-overlay design (P-384 path) -- INFORMATIONAL ONLY
; -----------------------------------------------------------------------------
; Phase 1b's monolithic P-384 overlay (12.5 KB) overflowed the live UCI
; CRYPTO_OVERLAY slot (7,680 B at $4200-$5FFF).  The fix is functional:
; split the P-384 image into two halves along the SHA / curve boundary,
; each fitting the slot, and load them in sequence.
;
; Phase 1.5 emits the two .bin files; Phase 3 will extend this dispatcher
; with two new entry points (do NOT add them yet -- this comment is
; informational only).  The four overlay states the dispatcher will need
; to track:
;
;     0 = OV_NONE        (uninitialized / swap_none)
;     2 = OV_P256        (existing — unchanged)
;     4 = OV_P384_SHA384 (NEW — sha384.s code + IV/K[80] RODATA)
;     5 = OV_P384_CURVE  (NEW — fp384/mod384/points384/curve384/
;                         ecdsa_verify_384/shim)
;
; The legacy state 3 (OV_P384, monolithic) is now stale and will be
; removed by Phase 3 along with the existing crypto_swap_to_p384 entry
; point (the only consumer is tools/test_p384_symbols.py, which will
; be rewritten to drive the two halves in sequence).
;
; REU storage (see src/crypto/shared/reu_layout.inc):
;   REU_OVERLAY_P384_SHA384 = $60000  (bank 6)
;   REU_OVERLAY_P384_CURVE  = $70000  (bank 7)
;
; TLS-side call sequence (Phase 4a will implement the dispatcher):
;     ; --- 1. Hash the handshake transcript ---
;     jsr crypto_swap_to_p384_sha384
;     jsr sha384_init
;     ldx #<transcript ; ldy #>transcript ; jsr setup_sha_src/sha_len
;     jsr sha384_update      ; (one or more times)
;     jsr sha384_final       ; sha384_digest now holds the 48 B BE digest
;
;     ; --- 2. Splice the digest into the resident BE input struct ---
;     ;       (resident DATA at $C000 survives the swap window)
;     ldy #47
; @cp: lda sha384_digest,y
;      sta ecdsa_inputs_384+96,y
;      dey
;      bpl @cp
;
;     ; --- 3. Swap in the curve / verify overlay and call verify ---
;     jsr crypto_swap_to_p384_curve
;     lda #<ecdsa_inputs_384
;     ldx #>ecdsa_inputs_384
;     jsr ecdsa_verify_384
;     ; C=0 VALID, C=1 INVALID/malformed
;
; Resident DATA invariants (Phase 1b -- Phase 1.5 preserves these):
;     - sha384_digest (48 B) lives in the SHA archive's resident DATA;
;       written by sha384_final, read by the TLS-side splice loop above.
;     - ecdsa_inputs_384 (240 B BE struct: r|s|h|Qx|Qy each 48 B) lives
;       in the curve archive's resident DATA; TLS pre-fills r/s/Qx/Qy,
;       splices h from sha384_digest, then calls ecdsa_verify_384.
;     - All other ec384_* / fp384_* / ecdsa384_* RW buffers and the
;       sha_state / sha_w / sha_block_* SHA-384 state ALSO live in
;       resident DATA (CRYPTO_RESIDENT, $C000-$EFFF in the standalone
;       cfgs; CRYPTO_RESIDENT in the live UCI cfg).  Resident DATA
;       footprint is unchanged from Phase 1b's 3,541 B.
;
; ZP save/restore obligation (Phase 4a):
;     Phase 1.5 moves the sibling's SHA-384 streaming pointer slots
;     out of their default $04-$0B (which collide with c64-https's
;     canonical $04-$09 = w32_* ChaCha20/Poly1305 and $0A-$0D =
;     sha_temp1 SHA-256) into a free contiguous block at $3D-$44:
;         sha_src    = $3D / $3E
;         sha_len    = $3F / $40
;         sha_w_ptr  = $41 / $42
;         sha_w_ptr2 = $43 / $44
;     These slots are demonstrably unused by any other crypto / TLS /
;     ip65 / UCI / fe25519 / x25519 / ECDSA-bignum path during the
;     SHA-384 call window, so NO save/restore is required around the
;     SHA window.  Phase 4a's TLS dispatcher MAY clobber $3D-$44
;     freely while sha384_init/update/final is in flight.
;
;     If a future change introduces a competing user of $3D-$44, the
;     dispatcher must save/restore those eight bytes around the SHA
;     window OR move SHA-384 to a different free slot.  The choice
;     of $3D-$44 is documented in tools/integration/build_nistcurves_p384.sh.
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
