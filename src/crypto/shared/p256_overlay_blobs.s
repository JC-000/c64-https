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
; time, then boot DMAs it to REU bank 2 slot $22100.
;
; Path is relative to ca65's BINARY include path, set by the Makefile to
; an absolute $(abspath build).  The `../../../` this used to carry was
; an escape hatch, not a path: ca65 resolves .incbin against the CURRENT
; DIRECTORY first and only falls back to this file's directory, so from a
; git worktree (three levels down, at .claude/worktrees/<name>/) it
; climbed into the PRIMARY checkout and embedded that tree's overlay
; image.  Worse here than for the ip65 blob, which is deterministic:
; build/ is branch- and flag-dependent, so the borrowed image could have
; come from a different pin entirely, with no diagnostic.  See issue #116
; and the longer note in src/net/ip65/ip65_blob.s.
; -----------------------------------------------------------------------------
        .segment "OVERLAY_BLOB_P256"
p256_overlay_verify_blob:
        .incbin "lib/nistcurves-p256-verify.bin"
p256_overlay_verify_blob_end:

.endif ; .ifdef USE_OVERLAY_P256_EMBED
