; =============================================================================
; overlay_ids.inc -- Canonical overlay-ID constants for the CRYPTO_OVERLAY
; paging slot.  Single source of truth shared between the dispatcher
; (crypto_swap.s) and any caller that compares against `current_overlay`
; or passes an ID to `crypto_overlay_call`.
;
; The IDs are opaque to the swap engine itself -- they exist purely so
; idempotent callers can short-circuit a no-op swap by comparing against
; `current_overlay`.  Numbering rules:
;   * OV_NONE = 0 is the post-boot / undefined-slot sentinel.
;   * Distinct non-zero values per overlay.  Gaps are tolerated; new
;     overlays should pick the lowest unused ID rather than renumber
;     existing ones (forward compatibility across call-sites).
;   * IDs are .ifndef-guarded so this file is safe to include twice in a
;     single translation unit (e.g. boot.s + crypto_swap.s pulling in
;     the same header).
;
; Phase reference:
;   1, 4, 5 -- pre-existing (Phase 3 dual-overlay edition).
;   2, 3    -- new entry points added by the library-ingestion
;              architecture W3 work (X25519 + P-256 verify real DMA).
; =============================================================================

.ifndef OV_NONE
OV_NONE           = 0
.endif

; OV_X25519_SIBLING (legacy marker) -- predates the W3 real DMA path.
; Retained because the existing `crypto_swap_to_x25519_sibling` entry
; point in crypto_swap.s still sets it (state-only, no DMA).  New
; callers that DMA the sibling image from REU use OV_X25519 instead.
.ifndef OV_X25519_SIBLING
OV_X25519_SIBLING = 1
.endif

; OV_P256_VERIFY -- W3 new.  Set by `crypto_swap_to_p256_verify`
; after DMA'ing the P-256 verify image (libs/nistcurves' P-256 verify
; minimal-subset) from REU_OVERLAY_P256_VERIFY into the live slot.
.ifndef OV_P256_VERIFY
OV_P256_VERIFY    = 2
.endif

; OV_X25519 -- W3 new.  Set by `crypto_swap_to_x25519` after DMA'ing
; the X25519 sibling image (code + rodata) from REU_OVERLAY_X25519
; into the live slot.  Distinct from OV_X25519_SIBLING (which is the
; state-only marker for the linker-placed PRG-load-time image).
.ifndef OV_X25519
OV_X25519         = 3
.endif

; OV_P384_SHA384 / OV_P384_CURVE -- pre-existing (Phase 3).
.ifndef OV_P384_SHA384
OV_P384_SHA384    = 4
.endif
.ifndef OV_P384_CURVE
OV_P384_CURVE     = 5
.endif
