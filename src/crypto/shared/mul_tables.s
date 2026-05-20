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
;   sqtab_lo, sqtab_hi - 512-byte tables each (1 KB total), page-aligned,
;                       in TABLES_BSS. Layout `sqtab_hi = sqtab_lo + $0200`;
;                       semantics `(sqtab_hi[n] << 8) | sqtab_lo[n] =
;                       floor(n^2 / 4)` for n in 0..510.
;                       (currently: defined by src/data.s; re-homed here
;                        under CANONICAL_SQTAB in a later phase.)
;
; Size note: each table is 512 bytes, not 256. The earlier stub used
; `.res 256` which would silently truncate at n >= 256 once any sibling
; lib redirected its init here — every in-the-wild implementation uses
; 512 B per table (see `src/data.s:136` here, and the audit in
; `c64-lib-contract` issue #5). Fixed before any redirect lands.
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
sqtab_lo:       .res 512
sqtab_hi:       .res 512
.endif
