; src/lib_contract_asserts.s — c64-lib-contract conformance asserts.
;
; Assembled into every build, both backends, every profile. Emits no
; bytes: it exists purely so that a set of facts this project currently
; only *believes* about its vendored libraries become link-time errors
; when they stop being true.
;
; Contract: https://github.com/JC-000/c64-lib-contract — **pin the tag**.
;
; That advice INVERTED at contract v0.10.3 (2026-08-15), the repo's first
; GitHub release. This file used to say "read SPEC.md on `main`, NOT the
; newest git tag", and it was right at the time: tags lagged badly, newest
; v0.4.0 against a v0.8.0 main. They no longer do — v0.10.3 is both the
; newest tag and the newest SPEC.
;
; One caveat, because the release notes state it wrongly. They claim
; "every version since v0.4.1 is tagged (gapless series)"; it is not.
; Measured against the v0.10.3 changelog: 31 changelog versions, 30 tags,
; and **0.10.1 has no tag**. It was a doc-only section reorder with zero
; normative change, so the hole costs nothing — but do not write tooling
; that assumes every changelog version is resolvable as a ref. Pin
; v0.10.3 or later.
;
; Clauses referenced here: §1 (version identification), §3 (REU layout),
; §5 (aggregate manifest equates), §8.0 (shared-primitive ownership
; bitmask), §13.3 (rx ring shape).
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
; known until link") — so §1 and §13 of the contract disagreed, and §1 was
; the one that did not run.
;
; **Fixed upstream at contract v0.10.2** (c64-lib-contract#107, filed off
; this repo's v0.10.0 alignment pass): §7's ABI-gate bullet had restated
; the same broken `.if`-on-import form that v0.8.1 had already corrected
; in §1, and it is now `.assert`/`lderror` with a §1 cross-reference. The
; companion defect in the same issue — §8.0's consumes-mask snippet using
; `.if ::` on an unset `-D` selector, which fails to assemble in the
; adopter's own default build — is now `.ifdef`.
;
; Both were copy-paste hazards rather than anything c64-https shipped:
; the asserts below were written in the working form from the start, which
; is how the defect was noticed. Do not "fix" them back into `.if` form.
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
;   claims ownership of primitives we provide ($0007 on the REU archive,
;   $0005 on the FP_ONCHIP_MUL one at the v0.9.1 pin). The disjointness
;   assert would therefore FAIL, and correctly so: we resolve the
;   double-ownership by *deleting archive members*
;   (tools/integration/build_nistcurves_p256.sh drops mul_8x8.o and
;   data_shared.o, and rebuilds mul_8x8_onchip.o under the SHARED_*
;   switches) rather than by declaring the deferral in the manifest, so
;   the shipped mask describes the upstream archive and not the one we
;   link. After our surgery the linked archive owns NONE of the three.
;   The clean fix is to rebuild the lib_manifest object with those
;   switches — the wrapper already does exactly this for zp_config —
;   and is sequenced in c64-https#70. It is deliberately not done here:
;   it changes what the manifest reports for every consumer-side §5
;   check at once, which is not a change to make under release
;   pressure. Until then the tripwire below pins the values we measured.
;
; §5 LIB_NISTCURVES_SHARED_CONSUMES (contract v0.5.0): present from the
;   v0.9.0 pin ($0007 REU / $0005 onchip, mirroring PRIMITIVES). Not
;   imported yet — the §8.0 coverage assert it enables
;   (`CONSUMES & ~(APP_OWNED | LIB_OWNED) = 0`) is part of the same #70
;   work as the deferral switches above, and asserting on a mask that
;   describes the pre-surgery archive would encode the same mismatch
;   twice.

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
; nistcurves shipped 0 from v0.3.0 through v0.8.0, bumped to 1 at v0.9.0
; (17 exported symbols REMOVED, c64-nist-curves #90/#91), and to 2 at
; v0.10.0 (the lib-contract phase-3 namespace wave, c64-nist-curves #103).
; If a submodule bump makes this assert fire, that is the gate working:
; re-check the integration against the new export surface, then update the
; expected value on the next line — do not delete the assert.
;
; THE v0.9.1 -> v0.10.1 RE-CHECK, so the next person can audit the audit
; rather than re-run it blind. Method: `git diff v0.9.1 v0.10.1 -- src/`
; filtered to `.export`/`.exportzp` lines, cross-checked against every
; import of c64-https's own objects (od65 --dump-imports over build/*.o,
; build/crypto/**, build/net/**, excluding build/lib staging).
;
;   Removed, unconditionally: LIB_SHARED_REU_MUL_BANK,
;   LIB_SHARED_REU_MUL_OFFSET, LIB_SHARED_REU_MUL_BANKS_USED — the three
;   unprefixed §8.2 consumer-INPUT equates. c64-https imports **none** of
;   them (grep count 0 over the import dump), and could not usefully have:
;   every §8.2 consumer defines the same three, which is precisely why
;   exporting them produced `ld65: Duplicate external identifier` in any
;   two-library link. Replaced by the prefixed OUTPUT counterparts
;   LIB_NISTCURVES_SHARED_REU_MUL_* (#105), which c64-https also does not
;   import — it owns its REU layout in src/crypto/shared/reu_layout.inc.
;
;   Everything else in the wave is ADDITIVE at the default gate: the §6.5
;   rename window (#107) adds canonical `nistcurves_zp_*` /
;   `nistcurves_mul_*` names while KEEPING the bare forms as same-address
;   aliases, export-gated behind -D LIB_NO_BARE_EXPORTS=1. c64-https links
;   ungated, so `mul_dma_lo` / `mul_dma_hi` / `mul_cached_a` /
;   `mul_src2_buf` — which src/data.s provides and boot.s imports — are
;   untouched. The functional surface c64-https actually consumes is the
;   same four symbols as at v0.9.1: ec_base_x, ec_gx256, ec_scalar_mul_var,
;   ecdsa_verify_256, all still exported.
;
;   One INPUT-side break is real and was migrated: `-D zp_ptr2=$3d` in
;   tools/integration/build_nistcurves_p256.sh now hard-errors, because
;   the bare alias assignment is no longer `.ifndef`-guarded. The override
;   is spelled `-D nistcurves_zp_ptr2=$3d` from this pin; the wrapper's
;   od65 post-check was retargeted to the canonical name so it cannot go
;   vacuous. See that script's ZP_OVERRIDES block.
; PREFIXED FORM, from the v0.11.2 pin. The wrapper builds the archive with
; `-D LIB_NO_BARE_EXPORTS=1` (SPEC §6.5) — which is what lets src/data.s
; keep its own adopter-private mul_dma_* buffers without colliding — so the
; bare `LIB_ABI_VERSION` is no longer exported and importing it fails as an
; unresolved external. This is exactly the migration the note above
; anticipated; it arrived via the bare-export gate rather than via a second
; contract library entering the link.
.import LIB_NISTCURVES_ABI_VERSION
.assert LIB_NISTCURVES_ABI_VERSION = 2, lderror, "libs/nistcurves: exported-surface generation changed (LIB_NISTCURVES_ABI_VERSION != 2) — re-check the integration, then bump the expected value in src/lib_contract_asserts.s"


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
; §8.0 — shared-primitive ownership, DECLARED rather than surgical
; =====================================================================
; This section used to say the contract's disjointness assert was "not
; writable here yet". It is writable now, and both halves are below.
;
; THE OLD SHAPE. c64-https has always been the §8.0 APP_OWNED case — it
; provides all three shared primitives itself (sqtab_init + mul_8x8 +
; ct_mul_8x8 in src/crypto/poly1305.s, mul_tables_init in
; src/crypto/shared/mul_tables.s, reu_mul_init in src/boot.s, mul_dma_lo/hi
; in src/data.s) — but resolved the resulting double-ownership by DELETING
; archive members. The shipped manifest therefore described upstream's
; archive rather than the one we linked: the mask claimed the library owned
; all three while the linked archive owned none. Asserting disjointness
; against that number would have encoded the mismatch, not caught it.
;
; THE NEW SHAPE (libs/nistcurves v0.11.2 + SPEC §6.2). The wrapper requests
; the deferral through CONTRACT_DEFINES — four SHARED_* switches plus
; LIB_NO_BARE_EXPORTS=1 — instead of ar65 surgery. Per §8.0's
; conditional-mask rule the manifest then ATTESTS the deferral:
;
;   archive                    PRIMITIVES   CONSUMES
;   lib-p256-verify (REU)         $0000        $0007
;   lib-p256-verify-onchip        $0000        $0005
;   lib-p256-comb-onchip          $0000        $0005
;
; **Only PRIMITIVES is profile-independent.** CONSUMES is NOT: under
; FP_ONCHIP_MUL the manifest zeroes the reu_mul bit in BOTH masks, because
; that build genuinely does not read the primitive — upstream hard-asserts
; it (`src/lib_manifest.s`, "FP_ONCHIP_MUL manifest must not claim SPEC 8.2
; reu_mul consumption"). That is §8.0's three-state table working: a
; deferral switch drops a bit from ownership only, while a profile gate
; drops it from ownership AND consumption.
;
; Measured with od65 on the staged archives at the v0.11.2 pin. All three
; asserts below pass in every profile regardless, since $0005 & ~$0007 = 0.
; Do not "correct" $0005 to $0007 on an onchip archive — it is right.
.import LIB_NISTCURVES_SHARED_PRIMITIVES
.import LIB_NISTCURVES_SHARED_CONSUMES

; --- The library must own nothing, in every profile ---
; If this fires, the wrapper's CONTRACT_DEFINES did not reach the manifest
; TU. Do NOT restore the member drops to work around it: that puts the
; mismatch back and silently invalidates the two asserts below.
.assert LIB_NISTCURVES_SHARED_PRIMITIVES = 0, lderror, "libs/nistcurves: SHARED_PRIMITIVES is not $0000. c64-https requests full 8.0 deferral via CONTRACT_DEFINES, so the archive must own no shared primitive. Most likely the defines did not reach lib_manifest*.o. Do not restore the ar65 member drops to work around this."

; --- §8.0 disjointness: no primitive owned twice ---
.assert (APP_OWNED & LIB_NISTCURVES_SHARED_PRIMITIVES) = 0, lderror, "c64-https and libs/nistcurves both claim ownership of a shared primitive (SPEC 8.0 disjointness). c64-https provides sqtab_init/mul_8x8/ct_mul_8x8 in poly1305.s and reu_mul_init in boot.s; the library must defer all of them."

; --- §8.0 coverage: everything the library READS, somebody PROVIDES ---
; CONSUMES & ~(APP_OWNED | LIB_OWNED) = 0.
;
; HONEST SCOPE: this assert CANNOT FIRE TODAY, and must not be read as
; guarding the poly_prod rendezvous. APP_OWNED is $0007, which covers every
; §8.0 bit allocated so far, and CONSUMES is drawn from those same three
; bits — so the expression is identically zero. It is kept because it is
; the clause's canonical form and it arms itself the day a fourth primitive
; is allocated ($0008) and nistcurves consumes it.
;
; The failure it sounds like it catches is covered elsewhere: defines
; missing from the manifest TU trip the PRIMITIVES = 0 assert above;
; defines missing from the code TUs trip a duplicate-external link error
; against our own exports. And the poly_prod rendezvous is caught by
; neither — only by the comb/onchip ECDSA KAT.
.assert (LIB_NISTCURVES_SHARED_CONSUMES & ~(APP_OWNED | LIB_NISTCURVES_SHARED_PRIMITIVES)) = 0, lderror, "libs/nistcurves consumes a shared primitive that neither it nor c64-https provides (SPEC 8.0 coverage)."


; =====================================================================
; §13 — network backend ABI
; =====================================================================
; Lives in src/net_abi_asserts.s (issue #70): the §13.0 family asserts
; plus the §13.3 ring-mask check that used to sit here.
;
; §13 was RETIRED at contract v1.0.0 (2026-09-03) — a network backend is
; source in its consumer's own tree, so it never crossed a library boundary.
; Its numbers resolve at tag `v0.17.1` only. No assert moved or weakened:
; NO §13 assert has a contract-derived counterparty, whereas the §5/§8.0
; asserts above DO compare our values against the sibling archive's exported
; manifest. (§13's ip65 blob-footprint assert is not purely local either —
; its counterparty is the .incbin'd submodule artifact — but that is a
; submodule bump, not a contract release.) See src/net_abi.inc.
