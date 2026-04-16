; src/net/ip65/exports.s — ip65-backend-only re-exports.
;
; Promotes ip65 numeric equates to linker-visible symbols so they appear
; in build/labels.txt for the c64-test-harness Labels reader.
;
; This file is linked ONLY when BACKEND=ip65. Under BACKEND=uci these
; symbols do not exist and must not be referenced. Backend-agnostic
; exports live in src/exports.s.

.include "ip65_symbols.inc"

.export ip65_init
.export ip65_process
