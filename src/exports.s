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
