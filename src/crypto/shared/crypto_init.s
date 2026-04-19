; =============================================================================
; crypto_init.s - Top-level crypto init orchestrator
;
; Single entry point called from `src/boot.s` right after the entropy seed
; and before the menu loop. Subsequent phases (C.1/.2/.3) will hang
; per-library init routines off this file at the insertion marker below.
;
; Phase C.0: the only call is into the shared `mul_tables_init` stub.
; This proves the dispatch path compiles and runs without altering the
; boot image meaningfully (single JSR into an RTS).
;
; Phase C.1/.2/.3 will add these imports + calls in strict order:
;   1. mul_tables_init          (shared 8x8 sqtab)         [Phase C.0: stub]
;   2. x25519_reu_mul_init      (x25519 128 KB REU stash)  [Phase C.1]
;   3. poly1305_shoup_init      (Profile A Shoup r_tab)    [Phase C.2]
;   4. ec_precompute_256        (P-256 scalar precompute)  [Phase C.3]
;   5. ec_precompute_384        (P-384 scalar precompute)  [Phase C.3]
; =============================================================================

        .export crypto_init
        .import mul_tables_init

; -----------------------------------------------------------------------------
; crypto_init - call each crypto module's init once at boot.
; -----------------------------------------------------------------------------
.segment "CODE"

crypto_init:
        jsr mul_tables_init

        ; === Phase C.1-.3 insertion point ===
        ; Add `jsr <lib>_init` lines BELOW this marker (one per Phase C
        ; agent) in the dispatch order documented at the top of this file.
        ; ====================================

        rts
