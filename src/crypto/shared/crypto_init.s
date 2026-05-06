; =============================================================================
; crypto_init.s - Top-level crypto init orchestrator
;
; Single entry point called from `src/boot.s` right after the entropy seed
; and before the menu loop. Subsequent phases (C.3) will hang more
; per-library init routines off this file at the insertion marker below.
;
; Phase C.1 (rolled back) attempted to add x25519 sibling REU mul-table
; init here under BACKEND=uci. The integration deadlocked the TLS
; handshake at 48 MHz — see the rollback commit. The in-tree x25519
; under `src/crypto/x25519.s` provides its own init (`reu_mul_init`
; in `src/boot.s`), driven directly from `boot.s` rather than through
; this orchestrator.
;
; Dispatch order (executed once at boot):
;   1. mul_tables_init          (shared 8x8 sqtab)         [Phase C.0: stub]
;   2. poly1305_shoup_init      (Profile A Shoup r_tab)    [Phase C.2]
;   3. ec_precompute_256        (P-256 scalar precompute)  [Phase C.3]
;   4. ec_precompute_384        (P-384 scalar precompute)  [Phase C.3]
; =============================================================================

        .include "constants.inc"        ; reu_* register equates

        .export crypto_init
        .import mul_tables_init

; -----------------------------------------------------------------------------
; crypto_init - call each crypto module's init once at boot.
; -----------------------------------------------------------------------------
.segment "CODE"

crypto_init:
        jsr mul_tables_init

        ; === Phase C.2-.3 insertion point ===
        ; Add `jsr <lib>_init` lines BELOW this marker (one per Phase C
        ; agent) in the dispatch order documented at the top of this file.
        ; ====================================

        rts
