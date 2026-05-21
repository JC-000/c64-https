; =============================================================================
; crypto_swap.s - Crypto overlay DMA dispatcher (Phase 3 dual-overlay edition)
;
; Pages one of two REU-resident overlay images into the live CRYPTO_OVERLAY
; region on demand.  Phase 3 adds two new entry points
; (crypto_swap_to_p384_sha384 / crypto_swap_to_p384_curve) that load the
; sha384 and curve halves of the split P-384 build (Phase 1.5) from REU
; banks 6 and 7, replacing the now-stale single-image
; crypto_swap_to_p384.  The P-256 overlay swap was never exercised in
; production -- the in-tree P-256 path went away in Phase G and
; nistcurves-p256 is always-resident -- so the legacy crypto_swap_to_p256
; entry has been dropped along with the OV_P256 state.
;
; Idempotent: re-entering with the same overlay already resident is a
; single-byte compare + rts (no DMA).
;
; Interrupt discipline: SEI around the DMA window; restores original I
; flag on exit.  ~8 ms DMA latency at any CPU speed (REU bus runs at
; ~1 MHz regardless of turbo).
;
; -----------------------------------------------------------------------------
; Overlay state machine
; -----------------------------------------------------------------------------
; `current_overlay` is a single byte in CRYPTO_BSS (SHADOW_BSS-resident).
; Values are opaque to the swap engine -- they exist purely so callers
; can short-circuit a no-op swap.  The four states this dispatcher knows
; about:
;
;     0 = OV_NONE          (uninitialized / swap_none -- after boot,
;                           before any P-384 swap; live slot bytes are
;                           undefined and MUST NOT be jsr'd into.  Boot
;                           leaves current_overlay = OV_NONE so the
;                           first crypto_swap_to_p384_* call always
;                           DMAs.)
;     1 = OV_X25519_SIBLING (X25519 sibling rodata as set up by the
;                           Phase C.5 build under USE_X25519_SIBLING=1.
;                           Marker only -- there is no boot-time REU
;                           stash for the sibling rodata, so this entry
;                           does NOT DMA; it just records that the live
;                           slot already holds X25519 sibling rodata
;                           because the linker placed X25519_RODATA in
;                           CRYPTO_OVERLAY at PRG load time.  Once a
;                           P-384 overlay has been swapped in, calling
;                           crypto_swap_to_x25519_sibling ALONE is NOT
;                           sufficient to restore X25519 rodata bytes;
;                           a follow-up phase needs to add a REU stash
;                           for the sibling rodata if that round-trip
;                           is ever required.  Phase 3 leaves it as a
;                           state-only marker because the production
;                           TLS path (X25519 only / no P-384) never
;                           swaps anything in over X25519.)
;     4 = OV_P384_SHA384   (P-384 SHA-384 hash code + IV/K[80] RODATA;
;                           5,456 B unpadded.  REU bank 6, $60000.)
;     5 = OV_P384_CURVE    (P-384 fp384 / mod384 / points384 / curve384 /
;                           ecdsa_verify_384 + shim; 7,317 B unpadded.
;                           REU bank 7, $70000.)
;
; (IDs 2 and 3 intentionally skipped to leave headroom for future
;  overlays without renumbering.)
;
; -----------------------------------------------------------------------------
; Boot-time invariants (Phase 3)
; -----------------------------------------------------------------------------
; src/boot.s populates REU banks 6 and 7 from .incbin'd images at
; startup (see src/crypto/shared/p384_overlay_blobs.s and the
; reu_p384_overlay_init routine in boot.s).  Once boot finishes,
; subsequent calls to crypto_swap_to_p384_sha384 / _curve simply DMA
; from those banks into the live slot at $4200.  No call site needs
; to know about the boot-time staging.
;
; -----------------------------------------------------------------------------
; TLS-side call sequence (Phase 4a will implement the dispatcher)
; -----------------------------------------------------------------------------
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
;       resident DATA.  Resident DATA footprint is unchanged from
;       Phase 1b's 3,541 B.
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
; =============================================================================

        .include "constants.inc"        ; reu_* register equates
        .include "reu_layout.inc"
        .include "overlay_ids.inc"      ; OV_* constants (W3)

        .export crypto_swap_to_x25519_sibling
        .export crypto_swap_to_x25519           ; W3 new
        .export crypto_swap_to_p256_verify      ; W3 new
        .export crypto_swap_to_p384_sha384
        .export crypto_swap_to_p384_curve
        .export crypto_swap_none
        .export crypto_overlay_call             ; W3 new
        .export current_overlay

        ; Export REU layout equates once (kept in sync with reu_layout.inc).
        .export REU_OVERLAY_P384_SHA384
        .export REU_OVERLAY_P384_CURVE
        .export REU_OVERLAY_P256_VERIFY         ; W3 new
        .export REU_OVERLAY_X25519              ; W3 new
        .export OVERLAY_SIZE

        ; Live overlay slot start address (from the cfg's MEMORY{} define).
        .import __CRYPTO_OVERLAY_START__

; -----------------------------------------------------------------------------
; Overlay IDs -- canonical values live in `overlay_ids.inc` (W3).  This
; file's local equates above (OV_NONE, OV_X25519_SIBLING, OV_P384_SHA384,
; OV_P384_CURVE) were folded into the include; the .ifndef-guarded
; definitions there are the single source of truth.  `OV_P256_VERIFY`
; (id 2) and `OV_X25519` (id 3) are the new W3 additions.
;
; NB: the architecture plan's "OV_X25519=3, OV_P256_VERIFY=4" sketch
; assumed OV_P384_SHA384/CURVE were 1/2 — they are actually 4/5 (Phase 3
; intentionally skipped 2/3 for headroom).  The W3 IDs slot into the
; reserved gap so existing call sites that compare `current_overlay`
; against OV_P384_* see no renumber.
; -----------------------------------------------------------------------------
        .export OV_NONE
        .export OV_X25519_SIBLING
        .export OV_P256_VERIFY                  ; W3 new
        .export OV_X25519                       ; W3 new
        .export OV_P384_SHA384
        .export OV_P384_CURVE

; REU command: execute REU->C64 stash (bit 7 = start, bits 1-0 = direction
; 01 = REU-to-C64).  Matches the DMA issue used elsewhere in the codebase.
REU_CMD_REU_TO_C64 = $91

; -----------------------------------------------------------------------------
; crypto_swap_to_x25519_sibling -- state-only marker (no DMA).
;
; Records that the live slot holds X25519 sibling rodata.  Used at boot
; time only -- the linker has already placed X25519_RODATA in
; CRYPTO_OVERLAY at PRG load time when USE_X25519_SIBLING=1, so the
; first time the TLS path needs X25519 the bytes are already there and
; current_overlay just needs to reflect that.
;
; NOTE (Phase 3): if a future caller swaps in a P-384 overlay and then
; needs to round-trip back to X25519 sibling rodata, this entry is NOT
; sufficient -- it does not restore the bytes.  A subsequent phase
; needs to add a REU stash of the sibling rodata and a real DMA path
; here.  Today's TLS production path (no P-384) never triggers that
; sequence so the gap is benign.
; -----------------------------------------------------------------------------
.segment "LOADER_OVERFLOW"

crypto_swap_to_x25519_sibling:
        lda #OV_X25519_SIBLING
        sta current_overlay
swap_done_fast:
        rts

; -----------------------------------------------------------------------------
; crypto_swap_to_p384_sha384 -- DMA P-384 SHA-384 image from REU bank 6
; into the live CRYPTO_OVERLAY slot.  Idempotent.
; -----------------------------------------------------------------------------
crypto_swap_to_p384_sha384:
        lda #OV_P384_SHA384
        cmp current_overlay
        beq swap_done_fast
        pha
        lda #<REU_OVERLAY_P384_SHA384
        ldx #>REU_OVERLAY_P384_SHA384
        ldy #^REU_OVERLAY_P384_SHA384
        jsr do_swap
        pla
        sta current_overlay
        rts

; -----------------------------------------------------------------------------
; crypto_swap_to_p384_curve -- DMA P-384 curve / verify image from REU
; bank 7 into the live CRYPTO_OVERLAY slot.  Idempotent.
; -----------------------------------------------------------------------------
crypto_swap_to_p384_curve:
        lda #OV_P384_CURVE
        cmp current_overlay
        beq swap_done_fast
        pha
        lda #<REU_OVERLAY_P384_CURVE
        ldx #>REU_OVERLAY_P384_CURVE
        ldy #^REU_OVERLAY_P384_CURVE
        jsr do_swap
        pla
        sta current_overlay
        rts

; -----------------------------------------------------------------------------
; crypto_swap_to_x25519 -- DMA X25519 sibling image from REU bank 3
; (REU_OVERLAY_X25519) into the live CRYPTO_OVERLAY slot.  Idempotent.
;
; Distinct from `crypto_swap_to_x25519_sibling` above: that entry point
; is the legacy state-only marker (used when the linker placed the
; X25519 sibling rodata into the slot at PRG load time).  This new
; entry point DOES the DMA from REU, so it can be called after a
; P-384 or P-256 swap has overwritten the slot.  Boot-time stash
; happens in `reu_p384_overlay_init` (boot.s).
;
; Idempotent: re-entering with OV_X25519 already current is a single
; byte compare + rts (no DMA).  NB: arrival from the legacy
; OV_X25519_SIBLING state still triggers a DMA (the slot contents are
; assumed identical, but the marker IDs differ and the safe path is
; to refresh from REU rather than to assume the linker-placed bytes
; were not later overwritten).
; -----------------------------------------------------------------------------
crypto_swap_to_x25519:
        lda #OV_X25519
        cmp current_overlay
        beq swap_done_fast
        pha
        lda #<REU_OVERLAY_X25519
        ldx #>REU_OVERLAY_X25519
        ldy #^REU_OVERLAY_X25519
        jsr do_swap
        pla
        sta current_overlay
        rts

; -----------------------------------------------------------------------------
; crypto_swap_to_p256_verify -- DMA P-256 verify image (sibling
; libs/nistcurves verify-only minimal subset) from REU_OVERLAY_P256_VERIFY
; (bank 2 slot $22100) into the live CRYPTO_OVERLAY slot.  Idempotent.
;
; W3 new.  Today the P-256 verify primitives are always-resident in
; CRYPTO_RESIDENT (Phase C.4 sibling integration); W1 will later move
; them into the cold-path overlay slot.  Until that wiring, this
; entry point is callable but unused by TLS call sites.
; -----------------------------------------------------------------------------
crypto_swap_to_p256_verify:
        lda #OV_P256_VERIFY
        cmp current_overlay
        beq swap_done_fast
        pha
        lda #<REU_OVERLAY_P256_VERIFY
        ldx #>REU_OVERLAY_P256_VERIFY
        ldy #^REU_OVERLAY_P256_VERIFY
        jsr do_swap
        pla
        sta current_overlay
        rts

; -----------------------------------------------------------------------------
; crypto_swap_none -- mark the slot as undefined.
;
; Does NOT zero the slot bytes -- callers MUST NOT jsr into the slot
; while OV_NONE is current.  The state byte is the contract.
; -----------------------------------------------------------------------------
crypto_swap_none:
        lda #OV_NONE
        sta current_overlay
        rts

; -----------------------------------------------------------------------------
; crypto_overlay_call -- swap-then-call convenience wrapper (W3 new).
;
; Performs an idempotent swap to the requested overlay (no-op if it is
; already current) and then JSRs to (slot_base + offset).  Designed
; so a TLS call site can do:
;
;       lda #OV_P256_VERIFY
;       ldx #<(ecdsa_verify_256 - __CRYPTO_OVERLAY_START__)
;       ldy #>(ecdsa_verify_256 - __CRYPTO_OVERLAY_START__)
;       jsr crypto_overlay_call
;
; instead of two separate jsr's (swap, then jsr abs).  The dispatcher
; is responsible for ensuring fn_offset+slot_base is a valid entry
; point — there is no symbol-table check here.
;
; Inputs:
;       A = overlay id (OV_*)
;       X = fn offset low byte (relative to __CRYPTO_OVERLAY_START__)
;       Y = fn offset high byte
;
; Behaviour:
;   * Stashes X / Y / A in self-modifying-code (SMC) slots before
;     branching to the swap helper so the swap is free to clobber
;     all three registers.
;   * Dispatches on A to the matching crypto_swap_to_<id> entry point.
;     Unknown IDs return immediately without swapping or JSRing
;     (the call is a no-op; current_overlay is left untouched).
;   * After the swap returns, indirect-jsrs through the SMC'd absolute
;     address (slot_base + offset).
;   * The callee's return value (C flag + A/X/Y) passes through
;     unchanged to the caller.
;
; ABI mirror: documented identically in overlay_ids.inc usage notes.
; -----------------------------------------------------------------------------
crypto_overlay_call:
        ; Save the overlay id for the dispatch below.  txa/tya in the
        ; pointer math below clobbers A, so we have to stash it first.
        pha

        ; Compute slot_base + (Y:X) and stash into the indirect JSR slot.
        clc
        txa
        adc #<__CRYPTO_OVERLAY_START__
        sta @call_target+1
        tya
        adc #>__CRYPTO_OVERLAY_START__
        sta @call_target+2

        ; Recover the overlay id and dispatch.  Order: most-frequent
        ; first (X25519 + P-256 verify will be the W1 hot pair; the
        ; P-384 pair is the legacy / 0x0503-only path).
        pla
        cmp #OV_X25519
        bne @not_x25519
        jsr crypto_swap_to_x25519
        jmp @call_target
@not_x25519:
        cmp #OV_P256_VERIFY
        bne @not_p256
        jsr crypto_swap_to_p256_verify
        jmp @call_target
@not_p256:
        cmp #OV_P384_SHA384
        bne @not_sha384
        jsr crypto_swap_to_p384_sha384
        jmp @call_target
@not_sha384:
        cmp #OV_P384_CURVE
        bne @not_curve
        jsr crypto_swap_to_p384_curve
        jmp @call_target
@not_curve:
        ; Unknown overlay id -- no-op (caller error).  Leaves
        ; current_overlay untouched and returns with C=1 to surface
        ; the misuse.
        sec
        rts

@call_target:
        jsr $0000               ; absolute address SMC'd above
        rts

; -----------------------------------------------------------------------------
; do_swap - issue the REU -> C64 DMA of OVERLAY_SIZE bytes into
; CRYPTO_OVERLAY.
; IN:  A = REU source low byte
;      X = REU source middle byte
;      Y = REU source bank byte
; Clobbers A, X, Y.  Saves / restores original I flag.
; -----------------------------------------------------------------------------
do_swap:
        ; Save current I flag on the stack (bit 2 of P).
        php
        sei

        ; REU source: bank + high/low address
        sta reu_reu_lo
        stx reu_reu_hi
        sty reu_reu_bank

        ; C64 target: CRYPTO_OVERLAY_START
        lda #<__CRYPTO_OVERLAY_START__
        sta reu_c64_lo
        lda #>__CRYPTO_OVERLAY_START__
        sta reu_c64_hi

        ; Transfer length = OVERLAY_SIZE ($1E00 = 7,680 B; matches the
        ; live CRYPTO_OVERLAY slot under UCI and the padded .bin images
        ; produced by tools/integration/build_nistcurves_p384_bin.sh).
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
; Lives in SHADOW_BSS-resident CRYPTO_BSS (via BSS segment) so it
; survives across calls without polluting ZP.
; -----------------------------------------------------------------------------
.segment "BSS"
current_overlay: .res 1
