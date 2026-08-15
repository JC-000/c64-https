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

; =============================================================================
; c64-lib-contract SPEC §6.5 — canonical names for the shared multiply
; buffers c64-https provides.
;
; c64-https owns these four buffers (src/data.s under the default build;
; the sibling's data module under USE_X25519_SIBLING=1) and the
; integration wrapper therefore DROPS libs/nistcurves' `data_shared.o`
; from the archive — two providers of the same RAM would be a duplicate
; symbol at best and two disjoint copies at worst.
;
; From libs/nistcurves v0.10.0 the library's own objects reference these
; buffers by their §6.5 canonical names (`nistcurves_mul_*`), because
; `mul_` is registered to c64-x25519 in the §2 prefix registry. Upstream
; keeps the bare `mul_*` spellings as same-address aliases *inside*
; data_shared.o — which is exactly the object we drop — so at the v0.10.1
; pin the link fails with four unresolved externals:
;
;   Unresolved external 'nistcurves_mul_cached_a' referenced in:
;     src/fp256.s(188) ...            (likewise _dma_hi, _dma_lo, _src2_buf)
;
; The aliases below close that. They are deliberately *here* rather than
; beside either definition site: `src/data.s` declares the buffers only
; under `.ifndef USE_X25519_SIBLING`, and the sibling's generated data
; module declares them otherwise, so a definition-site alias would have to
; be written twice and kept in step. Importing the bare name binds to
; whichever provider the link selected, with no duplication and no gating.
;
; When upstream drops the bare `mul_*` aliases at its next MAJOR, the
; migration is to rename the definitions and delete this block — not to
; add a second set of buffers.
        .import mul_dma_lo, mul_dma_hi, mul_cached_a, mul_src2_buf
        .export nistcurves_mul_dma_lo, nistcurves_mul_dma_hi
        .export nistcurves_mul_cached_a, nistcurves_mul_src2_buf

nistcurves_mul_dma_lo   = mul_dma_lo
nistcurves_mul_dma_hi   = mul_dma_hi
nistcurves_mul_cached_a = mul_cached_a
nistcurves_mul_src2_buf = mul_src2_buf
