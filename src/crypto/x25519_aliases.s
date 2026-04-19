; =============================================================================
; x25519_aliases.s - Phase C.1 compatibility aliases for c64-x25519 sibling
;
; Under BACKEND=uci the in-tree src/crypto/fe25519.s and src/crypto/x25519.s
; are skipped (Makefile ifeq gate) and the c64-x25519 sibling provides the
; primitives as `fe25519_*`. This file aliases the legacy `fe_*` names that
; the test harness (tools/test_x25519.py) and in-tree callers (tls_ecdh.s)
; resolve through the VICE label file.
;
; Guarded by `.ifdef USE_X25519_SIBLING` — the Makefile sets this only under
; BACKEND=uci, so ip65 builds see this file as a no-op translation unit
; (ca65 still compiles it; it just emits no symbols).
; =============================================================================

.ifdef USE_X25519_SIBLING

; --- Primitive imports from the c64-x25519 archive ---
.import fe25519_add, fe25519_sub, fe25519_mul, fe25519_sqr
.import fe25519_inv, fe25519_mul_a24
.import fe25519_copy, fe25519_zero, fe25519_one, fe25519_cswap
.import fe25519_reduce_final

; --- Page-aligned field buffer imports ---
; The sibling `data.s` places fe25519_tmp1..4 on 32-byte boundaries so
; the self-mod abs,Y loops in fe25519_add/sub/reduce_final don't cross
; page boundaries. Aliasing `fe_tmp1..4` to them lets the existing
; test harness (tools/test_x25519.py uses `fe_tmp1..3` as scratch
; buffers) feed aligned inputs to the sibling's routines.
.import fe25519_tmp1, fe25519_tmp2, fe25519_tmp3, fe25519_tmp4

; --- Legacy fe_* aliases ---
; Most of these use ca65 `:=` to equate the legacy name to the imported
; sibling symbol. `fe_mul` and `fe_sqr` are the exceptions: the sibling
; routines intentionally skip the final reduction (the X25519 ladder
; doesn't need canonical output between steps), but tools/test_x25519.py
; expects reduced [0, p) outputs. Wrap both in tiny trampolines that
; tack `fe25519_reduce_final` onto the tail.
.export fe_add
.export fe_sub
.export fe_mul
.export fe_sqr
.export fe_inv
.export fe_mul_a24
.export fe_copy
.export fe_zero
.export fe_one
.export fe_cswap
.export fe_reduce_final
.export fe_tmp1
.export fe_tmp2
.export fe_tmp3
.export fe_tmp4

fe_add          := fe25519_add
fe_sub          := fe25519_sub
fe_inv          := fe25519_inv
fe_mul_a24      := fe25519_mul_a24
fe_copy         := fe25519_copy
fe_zero         := fe25519_zero
fe_one          := fe25519_one
fe_cswap        := fe25519_cswap
fe_reduce_final := fe25519_reduce_final
fe_tmp1         := fe25519_tmp1
fe_tmp2         := fe25519_tmp2
fe_tmp3         := fe25519_tmp3
fe_tmp4         := fe25519_tmp4

; Trampolines in CRYPTO_CODE (always resident). Both sibling primitives
; live in OVERLAY_X25519; the overlay must be paged in before these
; trampolines are called (crypto_swap_to_x25519 at boot ensures this
; for the entire x25519 lifetime in Phase C.1, since nothing else
; overlays the slot yet).
.segment "CRYPTO_CODE"

fe_mul:
        jsr fe25519_mul
        jmp fe25519_reduce_final

fe_sqr:
        jsr fe25519_sqr
        jmp fe25519_reduce_final

.endif
