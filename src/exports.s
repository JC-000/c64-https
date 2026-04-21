; src/exports.s — Single-compilation-unit re-exports of `=` equates.
;
; Many symbols in constants.inc are defined as numeric equates
; (`foo = $c000`). Those don't appear in the ld65 map unless something
; `.export`s them. constants.inc is `.include`d in many translation
; units, so putting `.export` there would cause duplicate-symbol
; errors. This file is assembled exactly once and is the single place
; that promotes those equates to linker-visible symbols so the
; c64-test-harness Labels reader can find them in build/labels.txt.
;
; Only BACKEND-AGNOSTIC symbols live here. ip65-specific exports live
; in src/net/ip65/exports.s and are linked only when BACKEND=ip65.
;
; Add symbols here as the harness needs them.

.include "constants.inc"

.export tcp_recv_buf

; Promote the fe25519 ZP equates so tools/test_x25519.py can resolve
; them via labels.txt.
.export fe_src1
.export fe_src2
.export fe_dst

; Phase F fallout: tools/test_crypto.py resolves these ZP equates via
; labels.txt and failed under both backends because the equates were
; never linker-visible. Promote them here — they have stable addresses
; across in-tree and canonical-ZP layouts.
.export cc20_data_ptr
.export cc20_remain
.export zp_ptr

; Phase C.4: c64-nist-curves fp256.s references a handful of REU DMA
; registers via `.import` (it was written to live in a linker-visible
; symbol world). Promote the numeric equates from constants.inc so ld65
; can resolve the sibling's imports.
.export reu_reu_hi
.export reu_reu_bank
.export reu_command
