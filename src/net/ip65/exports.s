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

; --- ip65 refit: SCRATCH_UNION drift guard -----------------------------
; cfg/c64-https-ip65.cfg time-shares cert_buf's RAM with
; LIB_NISTCURVES_P256_BSS (verify-time scratch) via the SCRATCH_UNION
; region at $A000. Both anchors are pinned in the cfg; this link-time
; assert catches any silent drift (e.g. someone dropping the start=
; pin or reordering segments) before it becomes runtime corruption.
; ip65-only file, so the UCI backends (where cert_buf floats) are
; unaffected.
.import cert_buf
.assert cert_buf = $A000, lderror, "ip65 refit: cert_buf must sit at $A000 (SCRATCH_UNION anchor) - see cfg/c64-https-ip65.cfg"
