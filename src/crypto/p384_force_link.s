; =============================================================================
; p384_force_link.s - Force linker to pull P-384 archive members
;
; Phase C.3 (Option B): the c64-nist-curves sibling at libs/nistcurves/
; supplies three variable-base P-384 primitives (ec_point_double_384,
; ec_point_add_384, ec_jacobian_to_affine_384). None of the production
; TLS call sites reference them yet — tools/test_p384_symbols.py is the
; sole caller at the moment. Without a visible .import, ld65 would omit
; the archive members entirely and the symbols would not appear in
; build/labels.txt.
;
; This stub emits a three-word reference table in CRYPTO_AUX_CODE (UCI
; backend) so each archive member is forced into the link. The table
; itself is tiny (6 bytes) and unreachable at runtime.
;
; Inert when USE_NISTCURVES_P384 is undefined (ip65 backend), so the
; same file can sit unconditionally in CRYPTO_SRCS without affecting
; non-UCI builds.
; =============================================================================

        .setcpu "6502"

.ifdef USE_NISTCURVES_P384

        .import ec_point_double_384
        .import ec_point_add_384
        .import ec_jacobian_to_affine_384

        .segment "CRYPTO_AUX_CODE"
p384_force_link_refs:
        .word ec_point_double_384
        .word ec_point_add_384
        .word ec_jacobian_to_affine_384

.endif
