; src/lib_contract_asserts.s — c64-lib-contract conformance asserts.
;
; Assembled into every build, both backends, every profile. Emits no
; bytes: it exists purely so that a set of facts this project currently
; only *believes* about its vendored libraries become link-time errors
; when they stop being true.
;
; Contract: https://github.com/JC-000/c64-lib-contract — read SPEC.md on
; `main`, NOT the newest git tag (tags lag: newest tag v0.4.0, main is
; v0.8.0 as of 2026-08-14). Clauses referenced here: §1 (version
; identification), §3 (REU layout), §5 (aggregate manifest equates),
; §8.0 (shared-primitive ownership bitmask), §13.3 (rx ring shape).
;
; ---------------------------------------------------------------------
; WHY `.assert ..., lderror` AND NOT `.if ... .error`
; ---------------------------------------------------------------------
; SPEC §1's consumer-side snippet is written as
;
;     .import LIB_X25519_VERSION_MAJOR
;     .if LIB_X25519_VERSION_MAJOR < 1 .and LIB_X25519_VERSION_MINOR < 8
;         .error "this consumer needs c64-x25519 v0.8 or later"
;     .endif
;
; That cannot assemble. `.if` needs a constant expression, and an
; `.import`ed symbol has no value until link. Measured on ca65 V2.18:
;
;     t_if.s(3): Error: Constant expression expected
;
; The form that works is `.assert <expr>, lderror, "<msg>"`, which defers
; evaluation to ld65 — the same reasoning the contract itself applies in
; §13.0/§13.8 ("NET_BACKEND_FAMILIES is .import'ed, so its value is not
; known until link") — so §1 and §13 of the contract disagree, and §1 is
; the one that does not run. Written up in c64-https#70 for escalation
; upstream. Do not "fix" the asserts below back into `.if` form.
;
; ---------------------------------------------------------------------
; WHAT IS *NOT* ASSERTED HERE, AND WHY
; ---------------------------------------------------------------------
; §5 fit check (`LIB_NISTCURVES_RESIDENT_BYTES < __CRYPTO_HOT_SIZE__`):
;   not usable. The manifest ships one RESIDENT_BYTES for the whole
;   library (27,000 B at the v0.6.0 pin) while we link a minimal §6
;   variant archive (`lib-p256-verify`). 27,000 > CRYPTO_HOT's 16,384,
;   so the contract's own worked example fails against every
;   minimal-archive consumer. Flagged in c64-https#70.
;
; §8.0 disjointness/coverage (`(LIB_A & LIB_B) = 0`, `(CONSUMES & ~OWNED) = 0`):
;   not writable today. c64-https is the APP_OWNED case — it provides
;   all three §8 primitives itself (sqtab_init + mul_8x8 + ct_mul_8x8 in
;   src/crypto/poly1305.s:21,24,213; mul_tables_init in
;   src/crypto/shared/mul_tables.s:32; reu_mul_init in src/boot.s:31;
;   mul_dma_lo/hi in src/data.s:123) — but the library's manifest still
;   exports LIB_NISTCURVES_SHARED_PRIMITIVES = $0007, i.e. it claims to
;   own all three. The disjointness assert would therefore FAIL, and
;   correctly so: we resolve the double-ownership by *deleting archive
;   members* (tools/integration/build_nistcurves_p256.sh drops
;   mul_8x8.o and data_shared.o) rather than by the contract's
;   `SHARED_*` deferral switches, so the shipped mask describes the
;   upstream archive and not the one we link. The fix is to rebuild
;   lib_manifest.o with those switches — the wrapper already does
;   exactly this for zp_config.o — and is sequenced in c64-https#70.
;   Until then the tripwire below pins the value we measured.
;
; §5 LIB_NISTCURVES_SHARED_CONSUMES (contract v0.5.0): absent at the
;   v0.6.0 pin. Nothing to import.

.include "constants.inc"

; =====================================================================
; §8.0 bit constants — copied verbatim from SPEC §8.0.
;
; These are plain assemble-time equates and MUST NOT be .export'ed
; (normative as of contract v0.7.3): they are unprefixed and identically
; valued in every adopter, so exporting them recreates the #43
; duplicate-external collision on a symbol family the v0.7.0 prefixed
; forms do not cover. `.ifndef`-guarded so a -D define can override.
; =====================================================================
.ifndef LIB_SHARED_PRIMITIVES_SQTAB
  LIB_SHARED_PRIMITIVES_SQTAB      = $0001
.endif
.ifndef LIB_SHARED_PRIMITIVES_REU_MUL
  LIB_SHARED_PRIMITIVES_REU_MUL    = $0002
.endif
.ifndef LIB_SHARED_PRIMITIVES_CT_MUL_8X8
  LIB_SHARED_PRIMITIVES_CT_MUL_8X8 = $0004
.endif

; Primitives provided by c64-https's own modules (SPEC §8.0 "APP_OWNED").
APP_OWNED = LIB_SHARED_PRIMITIVES_SQTAB | LIB_SHARED_PRIMITIVES_REU_MUL | LIB_SHARED_PRIMITIVES_CT_MUL_8X8


; =====================================================================
; §1 — library version gate (libs/nistcurves)
; =====================================================================
; The v0.6.0 pin predates contract v0.7.0, so it exports only the
; DEPRECATED bare `LIB_VERSION_*` / `LIB_ABI_VERSION` names — there is
; no `LIB_NISTCURVES_VERSION_MAJOR` to import yet. Importing the bare
; names is safe *only* because exactly one contract library is in the
; link: `USE_X25519_SIBLING=1` does not link on either backend, so the
; two-library #43 collision is unreachable in every shipping config.
;
; WHEN A SECOND CONTRACT LIBRARY EVER LINKS: build both with
; `ca65 -D LIB_NO_BARE_EXPORTS=1` and switch the import below to the
; `LIB_NISTCURVES_*` / `LIB_X25519_*` prefixed forms (contract v0.7.0).
; Both libraries emit the prefixed forms from v0.7.0 onward.
;
; ONLY the ABI generation counter is imported, deliberately. A MAJOR/
; MINOR floor assert is the obvious companion and is NOT here because
; the v0.6.0 pin exports those three without an address-size hint
; (libs/nistcurves/src/lib_version.s:33-35 — only ABI_VERSION carries
; `:abs`). Their values fit in a byte, so ca65 infers `zeropage` while
; a consumer `.import` defaults to absolute, and every build then emits
;
;   ld65: Warning: Address size mismatch for 'LIB_VERSION_MAJOR'
;
; twice. Measured on ld65 V2.18. This is the same defect contract
; v0.7.4 fixed for the §8.4 `_REGION`/`_SHARED` equates, recurring in
; §1; the contract's own note says the natural workaround (importing as
; `: zeropage`) is wrong, because it pins a manifest constant to an
; address size that is an artifact of its current value. Upstream fixed
; it at v0.9.0 (all four exports gained `:abs`, alongside the prefixed
; forms), so the floor assert becomes available warning-free at any pin
; >= v0.9.0 — add it then rather than eating two warnings per build now.

; ABI generation counter (§1 as restated in contract v0.7.5: an
; independent monotonic counter, NOT a mirror of MAJOR). This is the
; load-bearing breakage gate — pre-1.0 libraries take breaking changes
; on MINOR bumps, so MAJOR carries no signal.
;
; nistcurves shipped 0 from v0.3.0 through v0.8.0 and bumped to 1 at
; v0.9.0, where it also REMOVED 17 exported symbols (c64-nist-curves
; #90/#91). If a submodule bump makes this assert fire, that is the gate
; working: re-check the integration against the new export surface, then
; update the expected value on the next line — do not delete the assert.
.import LIB_ABI_VERSION
.assert LIB_ABI_VERSION = 0, lderror, "libs/nistcurves: exported-surface generation changed (LIB_ABI_VERSION != 0) — re-check the integration, then bump the expected value in src/lib_contract_asserts.s"


; =====================================================================
; §3 — REU bank budget
; =====================================================================
; c64-https reserves REU banks 6 and 7 for the P-384 overlay images
; (src/boot.s:840-841 stashes the SHA-384 blob to bank 6 and the curve
; blob to bank 7). No vendored library may claim them. The library's own
; claim is $07 (banks 0/1 mul table + bank 2 Lim-Lee comb) under the REU
; profile and $04 under FP_ONCHIP_MUL, both of which pass; this assert
; exists to catch an upstream expansion into our reserved pair, which
; would otherwise corrupt the overlay images at first swap-in with no
; diagnostic at all.
.import LIB_NISTCURVES_REU_BANKS_USED
.assert (LIB_NISTCURVES_REU_BANKS_USED & $C0) = 0, lderror, "libs/nistcurves claims REU bank 6 and/or 7 — reserved by c64-https for the P-384 overlay images (src/boot.s:840)"


; =====================================================================
; §8.0 — shared-primitive ownership tripwire
; =====================================================================
; See the header note: the contract's disjointness assert is not
; writable here yet. What IS checkable is that upstream's ownership
; claim has not moved out from under the archive surgery in
; tools/integration/build_nistcurves_p256.sh. Measured $0007 on both
; the REU and FP_ONCHIP_MUL variants at the v0.6.0 pin.
;
; If this fires, upstream changed which §8 primitives it owns. Re-derive
; which archive members the wrapper must drop (or which `SHARED_*`
; deferral switches it must pass) BEFORE updating the expected value.
.import LIB_NISTCURVES_SHARED_PRIMITIVES
.assert LIB_NISTCURVES_SHARED_PRIMITIVES = APP_OWNED, lderror, "libs/nistcurves shared-primitive ownership claim moved — re-derive the archive member drops in tools/integration/build_nistcurves_p256.sh before touching this assert"


; =====================================================================
; §13.3 — TCP rx ring shape
; =====================================================================
; The ring mask must be 2^n - 1 or the backends' `and TCP_RECV_MASK`
; wrap arithmetic aliases addresses instead of wrapping. Assemble-time
; (`error`, not `lderror`) because TCP_RECV_MASK is a local equate from
; constants.inc, not an import.
.assert (TCP_RECV_MASK & (TCP_RECV_MASK + 1)) = 0, error, "TCP_RECV_MASK must be 2^n - 1 (c64-lib-contract SPEC §13.3)"
