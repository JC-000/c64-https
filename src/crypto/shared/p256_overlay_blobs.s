; =============================================================================
; p256_overlay_blobs.s -- Embedded P-256 verify overlay image (W3).
;
; Mirror of p384_overlay_blobs.s for the P-256 verify minimal-subset
; overlay image.  Embedded when the top-level Makefile flag
; EMBED_P256_OVERLAY=1 is set (which propagates to ca65 as
; -D USE_OVERLAY_P256_EMBED=1).
;
; Mutually exclusive with USE_OVERLAY_P384_EMBED at the cfg level: both
; target the CRYPTO_OVERLAY slot at $4200 at PRG-load time, so the
; Makefile turns USE_OVERLAY_P384_EMBED off when EMBED_P256_OVERLAY=1.
; If both were set the linker would overflow the 7,680 B slot.
;
; Output:
;   build/lib/nistcurves-p256-verify.bin (7,680 B padded) -- staged into
;   CRYPTO_OVERLAY at PRG load time, then DMA'd by
;   reu_p384_overlay_init (boot.s) to REU bank 2 slot $22100.  After
;   the stash, future calls to `crypto_swap_to_p256_verify` DMA the
;   image back into the live slot.
;
; Inert when USE_OVERLAY_P256_EMBED is undefined (default build):
; the segment is left empty (`optional = yes` in the cfg) and boot
; skips the DMA.  This is the default state -- the P-256 verify
; primitives stay always-resident in CRYPTO_RESIDENT until W1 wires
; them into a cold-path overlay swap.
; =============================================================================

        .setcpu "6502"

.ifdef USE_OVERLAY_P256_EMBED

        .export p256_overlay_verify_blob
        .export p256_overlay_verify_blob_end

; -----------------------------------------------------------------------------
; P-256 verify overlay image (REU_OVERLAY_P256_VERIFY source)
;
; Loads into the live CRYPTO_OVERLAY slot at $4200-$5FFF at PRG load
; time, then boot DMAs it to REU bank 2 slot $22100.  The .incbin path
; is resolved by ca65 relative to this source file: from
; src/crypto/shared/ the build/ tree is two levels up.
; -----------------------------------------------------------------------------
        .segment "OVERLAY_BLOB_P256"
p256_overlay_verify_blob:
        .incbin "../../../build/lib/nistcurves-p256-verify.bin"
p256_overlay_verify_blob_end:

.endif ; .ifdef USE_OVERLAY_P256_EMBED
