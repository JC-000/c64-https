; src/contract_footprint_asserts.s — c64-lib-contract SPEC §6.6 consumer
; footprint asserts.
;
; Emits no bytes. Companion to src/lib_contract_asserts.s, kept as a
; separate TU because §6.6 landed at contract v0.10.0 and its gating is
; profile-dependent in a way the §1/§3/§8.0/§13.3 gates are not (see the
; comb exclusion below).
;
; Contract: https://github.com/JC-000/c64-lib-contract — read SPEC.md on
; `main`, NOT the newest git tag (tags lag; main is v0.10.0 as of
; 2026-08-15). Clause referenced here: §6.6 (consumer footprint asserts).
;
; ---------------------------------------------------------------------
; WHAT §6.6 IS FOR
; ---------------------------------------------------------------------
; SPEC §6.6 exists because of a failure measured in THIS repo and filed
; upstream as c64-lib-contract#69: a MINOR library bump grows resident
; code or rodata, the consumer's region overflows at link time, and there
; is no advance signal that the bump was a spatial event. c64-https hit it
; twice — most recently v0.7.0's +208 B validation gate against CRYPTO_HOT's
; ~1 byte of slack, bisected across three tags to find.
;
; The clause's consumer pattern binds the library's declared footprint to
; a region budget:
;
;     .import LIB_NISTCURVES_RESIDENT_BYTES
;     .import LIB_NISTCURVES_COLD_BYTES
;     .import __MAIN_SIZE__               ; cfg: MAIN: ... define = yes;
;     .assert LIB_NISTCURVES_RESIDENT_BYTES + LIB_NISTCURVES_COLD_BYTES \
;             <= __MAIN_SIZE__, lderror, "..."
;
; No cfg change was needed to adopt it: every MEMORY area in both
; cfg/c64-https-uci.cfg and cfg/c64-https-ip65.cfg already carries
; `define = yes`, so ld65 publishes __CRYPTO_HOT_SIZE__ /
; __CRYPTO_RESIDENT_SIZE__ already (verified in build/labels.txt).
;
; ---------------------------------------------------------------------
; WHAT THIS ASSERT ACTUALLY CATCHES — AND WHAT IT DOES NOT
; ---------------------------------------------------------------------
; Stated plainly, because a gate whose reach is overestimated is worse
; than no gate.
;
; It does NOT tightly bound region pressure. CRYPTO_HOT is $4000 (16,384 B)
; and holds c64-https's own crypto as well as the library, so at the v0.9.1
; pin the assert compares 8,700 + 430 = 9,130 against 16,384 — roughly
; 7 KB of slack, while the region's REAL free space is 81 bytes
; (__CRYPTO_HOT_LAST__ = $9FAF against a $A000 end, measured). A bump that
; grows the archive by 100 B still overflows the region without tripping
; this assert. Making it tight would require hardcoding a per-pin budget
; constant, which then needs maintenance on every bump and fires as a
; false alarm on any growth of c64-https's own code; that trade was
; considered and declined.
;
; What it DOES catch is a §6.4 per-variant-manifest regression, and that
; is not hypothetical — it is measured live in this tree on a sibling
; profile. §6.6's whole implication ("declared <= budget implies actual <=
; budget") rests on the manifest describing the archive we link. When it
; does not, the number is not conservative, it is meaningless. At the
; v0.9.1 pin, measured with od65 on the staged archives:
;
;   profile          manifest member                      RESIDENT  COLD
;   reu              lib_manifest_p256verify.o                8700   430
;   onchip           lib_manifest_p256verify_onchip.o         8700   240
;   onchip-comb      lib_manifest_onchip.o                   27000  1650   <- whole library
;
; 27,000 B is the whole-library figure against a 16,384 B region. That is
; the exact number that made §6.6 unadoptable before contract v0.9.0's
; §6.4, and it is still live for the comb profile — so if a future bump
; regresses `reu` or `onchip` the same way, this assert names it instead of
; leaving an opaque segment overflow to be bisected.
;
; ---------------------------------------------------------------------
; WHY THE COMB PROFILE IS EXCLUDED
; ---------------------------------------------------------------------
; The comb archive would FAIL this assert today (27,000 + 1,650 = 28,650
; against 16,384) and the failure would be a false alarm: the comb PRG
; links and runs, so the declared number is wrong, not the build.
;
; The cause is ours, not upstream's. `tools/integration/build_nistcurves_p256.sh`
; builds the comb profile from upstream's FULL `lib-onchip` archive and
; then `rm -f`s ~7 members (fp384, mod384, curve384, points384_*, ...) to
; narrow it to the P-256 comb set. Upstream's `lib_manifest_onchip.o`
; legitimately describes the archive upstream shipped; it survives our
; member surgery still describing the pre-surgery set. The `reu` and
; `onchip` profiles are unaffected because they build from upstream's
; already-minimal `lib-p256-verify` / `lib-p256-verify-onchip` targets,
; which carry per-variant manifests.
;
; This is precisely the harm SPEC §6.1 names: "an archive whose member set
; a consumer has edited is outside every §5/§8.0 manifest claim it ships."
; The sanctioned remedy is §6.2 `CONTRACT_DEFINES` / `CONTRACT_ZP_DEFINES`
; plus §6.3's `lib-app-owned` target, so the configuration is reachable
; without surgery. Neither exists in the pinned v0.9.1; both ARE implemented
; on libs/nistcurves master (v0.10.1, measured). Retiring the surgery is
; therefore unblocked by the wave bump and is sequenced in c64-https#70 —
; when it lands, delete the .ifdef below and the comb profile is covered
; by the same assert as the other two.
;
; The comb profile is deliberately excluded from `make package`, so no
; shipped artifact is affected by the gap this exclusion leaves open.

.ifndef USE_NISTCURVES_COMB

.import LIB_NISTCURVES_RESIDENT_BYTES
.import LIB_NISTCURVES_COLD_BYTES

; The code+rodata region differs by backend: CRYPTO_HOT under UCI,
; CRYPTO_RESIDENT under ip65. Both are $6000-$9FFF ($4000 bytes) and both
; are declared `define = yes`, so the published size symbol is the only
; thing that differs. BACKEND_UCI / BACKEND_IP65 come from the Makefile.
.ifdef BACKEND_UCI
    .import __CRYPTO_HOT_SIZE__
    .assert LIB_NISTCURVES_RESIDENT_BYTES + LIB_NISTCURVES_COLD_BYTES <= __CRYPTO_HOT_SIZE__, lderror, "libs/nistcurves declared footprint (LIB_NISTCURVES_RESIDENT_BYTES + _COLD_BYTES) exceeds CRYPTO_HOT. Contract SPEC 6.6. Most likely cause is a 6.4 regression: the archive ships a whole-library manifest instead of a per-variant one (27000 B is the whole-library value). Check with od65 --dump-exports on the staged lib_manifest*.o before assuming the library really grew."
.else
    .import __CRYPTO_RESIDENT_SIZE__
    .assert LIB_NISTCURVES_RESIDENT_BYTES + LIB_NISTCURVES_COLD_BYTES <= __CRYPTO_RESIDENT_SIZE__, lderror, "libs/nistcurves declared footprint (LIB_NISTCURVES_RESIDENT_BYTES + _COLD_BYTES) exceeds CRYPTO_RESIDENT. Contract SPEC 6.6. Most likely cause is a 6.4 regression: the archive ships a whole-library manifest instead of a per-variant one (27000 B is the whole-library value). Check with od65 --dump-exports on the staged lib_manifest*.o before assuming the library really grew."
.endif

.endif ; USE_NISTCURVES_COMB
