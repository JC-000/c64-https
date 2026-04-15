; src/exports.s — Single-compilation-unit re-exports of `=` equates.
;
; Many symbols in constants.inc and ip65_symbols.inc are defined as
; numeric equates (`foo = $c000`). Those don't appear in the ld65 map
; unless something `.export`s them. constants.inc/ip65_symbols.inc are
; `.include`d in many translation units, so putting `.export` there
; would cause duplicate-symbol errors. This file is assembled exactly
; once and is the single place that promotes those equates to
; linker-visible symbols so the c64-test-harness Labels reader can
; find them in build/labels.txt.
;
; Add symbols here as the harness needs them.

.include "constants.inc"
.include "ip65_symbols.inc"

.export tcp_recv_buf
.export ip65_init
.export ip65_process
