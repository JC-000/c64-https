; =============================================================================
; mul_tables.s - Shared 8x8 quarter-square multiply tables (STUBBED)
;
; Phase C.0: this file is a stub. `mul_tables_init` returns immediately;
; `sqtab_lo` / `sqtab_hi` labels are *not* defined here yet — the in-tree
; `src/data.s` still owns the definitions (512-byte tables containing the
; full quarter-square formula) and the in-tree init in
; `src/crypto/*_sqtab_init.s` still populates them.
;
; Phase C.1/.2/.3: the first sibling lib to integrate pulls the canonical
; `sqtab_lo` / `sqtab_hi` labels + their init into this file, under
; `.ifdef CANONICAL_SQTAB`. Subsequent lib integrations redirect their
; internal `sqtab_init` to the shared entry point here.
;
; Public API:
;   mul_tables_init   - build the 256x256 quarter-square tables
;                       (currently: stub; returns immediately).
;   sqtab_lo, sqtab_hi - 256-byte tables, page-aligned, in TABLES_BSS
;                       (currently: defined by src/data.s; re-homed here
;                        under CANONICAL_SQTAB in a later phase).
; =============================================================================

        .export mul_tables_init

; -----------------------------------------------------------------------------
; mul_tables_init - stub for Phase C.0. Existing in-tree `sqtab_init`
; (imported by boot.s) still handles table population. A later phase
; redirects boot.s to call `mul_tables_init` instead.
; -----------------------------------------------------------------------------
.segment "CODE"

mul_tables_init:
        rts

; -----------------------------------------------------------------------------
; Table labels — only defined under CANONICAL_SQTAB to avoid duplicating
; the legacy `src/data.s` definitions in Phase C.0.
; -----------------------------------------------------------------------------
.ifdef CANONICAL_SQTAB
        .export sqtab_lo
        .export sqtab_hi

.segment "TABLES_BSS"
sqtab_lo:       .res 256
sqtab_hi:       .res 256
.endif
