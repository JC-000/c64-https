; =============================================================================
; p384_overlay_blobs.s -- Embedded P-384 split overlay images (Phase 3).
;
; Phase 1.5 split the monolithic P-384 overlay into two 7,680 B images:
;
;   build/lib/overlay-p384-sha384.bin  (REU bank 6, $60000)
;   build/lib/overlay-p384-curve.bin   (REU bank 7, $70000)
;
; Phase 3 boots them into REU at startup so the TLS path (Phase 4a) can
; jsr crypto_swap_to_p384_{sha384,curve} on demand without staging
; anything from disk at handshake time.  This file is the .incbin
; equivalent of src/net/ip65/ip65_blob.s -- it just embeds the two
; .bin payloads into the linker-controlled MEMORY map so ld65 places
; them at known C64 addresses.  src/boot.s::reu_p384_overlay_init then
; copies them out to REU banks 6/7 in two STASH DMAs (~16 ms total at
; any CPU speed) and the C64 RAM holding the staging copies is free
; to be reused (CRYPTO_OVERLAY for the live overlay slot itself, and
; the under-KERNAL block at $E000-$FDFF for whatever).
;
; -----------------------------------------------------------------------------
; Boot strategy: ".incbin into a fixed RAM region" (Phase 3)
; -----------------------------------------------------------------------------
; Why this layout instead of disk-LOAD-at-boot?  C64 PRG is a single
; contiguous load, and 47 KB (existing PRG) + 15 KB (two blobs) =
; ~62 KB does not fit anywhere in main RAM that avoids the I/O hole at
; $D000-$DFFF.  We work around it by:
;
;   1. Placing the SHA-384 blob at $4200-$5FFF (CRYPTO_OVERLAY region).
;      Under default builds the live overlay slot is otherwise empty
;      at PRG load time; the blob occupies it transiently until boot
;      DMAs it out.  After boot the slot is "free" (current_overlay =
;      OV_NONE) and the next jsr crypto_swap_to_p384_sha384 will DMA
;      the same bytes back from REU bank 6.  Under USE_X25519_SIBLING=1
;      the X25519 sibling rodata occupies CRYPTO_OVERLAY at PRG load
;      time -- this file is .ifdef-gated out in that build (see below)
;      and REU bank 6 is left unpopulated.  The shipped TLS path under
;      the sibling flag never calls crypto_swap_to_p384_sha384 so the
;      gap is benign.
;
;   2. Placing the CURVE blob at $E000-$FDFF (under KERNAL ROM).  The
;      C64 ALWAYS has RAM there; the KERNAL ROM only intercepts reads.
;      KERNAL LOAD writes pass through to the underlying RAM regardless
;      of $01 banking, so the PRG load deposits the blob bytes there
;      cleanly.  Boot reads them back via REU DMA (which doesn't go
;      through CPU $01 banking either) and stashes them in REU bank 7.
;      Once the DMA completes the under-KERNAL block is free for any
;      future use.
;
; The PRG file gains ~15 KB (one 7,680 B blob + the 8 KB pad from
; $C000-$DFFF that ld65 generates between CRYPTO_RESIDENT and the
; under-KERNAL region) growing to ~62 KB.  Loading via VICE warp /
; Ultimate-64 fastload writes bytes directly to RAM (no real CPU I/O
; passthrough during the load), so the embedded $D000-$DFFF zeros
; cause no harm.  On a real C64 + 1541 the load WOULD momentarily
; write zeros to VIC/SID/CIA registers; the PRG is not intended for
; that target.
;
; The gating below mirrors the same `.ifdef USE_X25519_SIBLING` guard
; used in src/boot.s and src/data.s -- a Make-time -D from the top
; Makefile toggles it.
; =============================================================================

        .setcpu "6502"

; The blobs are embedded only when USE_OVERLAY_P384_EMBED is asserted by
; the top-level Makefile (UCI backend, no USE_X25519_SIBLING flag).
; Under ip65 there is no room in main RAM after the existing layout
; (NET_BSS_TAIL has only ~800 B of slack and CRYPTO_OVERLAY is a
; zero-size alias).  Under USE_X25519_SIBLING=1 the X25519 sibling
; rodata occupies CRYPTO_OVERLAY at PRG load time so the SHA blob
; cannot share that slot.  Either gate leaves the segments empty;
; boot's reu_p384_overlay_init detects the empty state via a build-time
; flag and skips the DMAs entirely.
.ifdef USE_OVERLAY_P384_EMBED

        ; Force-link the two segments by exporting two anchor symbols.
        ; Without these, ld65 can theoretically drop optional segments
        ; that have no `.import` references; the boot code DMAs from the
        ; segments by symbol so a stable label per segment is required
        ; anyway.
        .export p384_overlay_sha384_blob
        .export p384_overlay_sha384_blob_end
        .export p384_overlay_curve_blob
        .export p384_overlay_curve_blob_end

; -----------------------------------------------------------------------------
; SHA-384 overlay image (REU bank 6 source)
;
; Loads into the live CRYPTO_OVERLAY slot at $4200-$5FFF at PRG load
; time, then boot DMAs it to REU bank 6.
;
; Path is relative to ca65's BINARY include path (absolute $(abspath
; build), set by the Makefile).  The former `../../../` escaped the
; checkout entirely when assembled from a git worktree — see issue #116
; and the note in src/net/ip65/ip65_blob.s.
; -----------------------------------------------------------------------------
        .segment "OVERLAY_BLOB_SHA384"
p384_overlay_sha384_blob:
        .incbin "lib/overlay-p384-sha384.bin"
p384_overlay_sha384_blob_end:

; -----------------------------------------------------------------------------
; CURVE overlay image (REU bank 7 source)
;
; Loads into the under-KERNAL region at $E000-$FDFF at PRG load time,
; then boot DMAs it to REU bank 7.
; -----------------------------------------------------------------------------
        .segment "OVERLAY_BLOB_CURVE"
p384_overlay_curve_blob:
        .incbin "lib/overlay-p384-curve.bin"
p384_overlay_curve_blob_end:

.endif ; .ifdef USE_OVERLAY_P384_EMBED
