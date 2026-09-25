#!/usr/bin/env bash
# =============================================================================
# tools/integration/build_x25519.sh - Build c64-x25519 v0.16.0
# X25519 primitives as a resident .a archive linked into the main PRG.
#
# Optional sibling-library integration (Phase C.5). Produces
# build/lib/x25519.a containing:
#   - fe25519 field arithmetic (fe25519_mul/sqr/inv/...)
#   - X25519 Montgomery ladder (x25519_scalarmult, x25519_clamp, x25519_base)
#   - x25519_init (reu_mul_init + REU DMA helpers reu_fetch_mul_row,
#     reu_fetch_doubled_row, reu_clear_wide)
#   - data buffers (x25_*, fe25519_tmp*, mul_*, sqr_*, a24_*, fe_p)
#   - util (vic_blank, vic_unblank, bench helpers — pulled in if referenced)
#
# Submodule pin: v0.16.0 (16157a1). What each bump since v0.6.0
# changed that this wrapper had to be migrated through:
#
#   v0.7.0  RFC 7748 decodeUCoordinate fix (upstream #64) — adds the
#           `x25_x1` buffer, declared in the BSS module below. This is
#           a CORRECTNESS fix, not a refactor: v0.4.0-v0.6.0 return a
#           deterministically wrong shared secret for any peer u with
#           bit 255 set.
#   v0.8.0  SPEC §4 segment-prefix migration (CODE -> LIB_X25519_CODE)
#           plus the cold/init split (LIB_X25519_INIT_CODE). Handled by
#           the segment-rewrite block near the bottom of this script.
#           Also adds the X25519_ONCHIP_MUL no-REU profile.
#   v0.9.0  contract v0.7.0/v0.5.0 manifest migration: lib_manifest.s,
#           prefixed exports, SHARED_CONSUMES. Not staged — c64-https
#           imports no contract manifest equate, so nothing to do.
#   v0.10.0 LIB_ABI_VERSION 1 -> 2 (v0.9.0 erratum) + contract v0.7.4
#           precalc macro. No source-level consumer impact here.
#   v0.11.x ABI 2 -> 3 (bare LIB_SHARED_REU_MUL_* / zp_ptr1 / zp_tmp1 /
#           zp_tmp2 export removals, poly_carry -> mul_carry rename),
#           then three PATCH releases of upstream build-correctness
#           fixes. Nothing to migrate: this wrapper stages neither
#           lib_manifest.s nor lib_version.s, and it does not use
#           upstream's `make lib-*` surface at all — it assembles the
#           staged sources itself, so upstream's own build defects
#           (#109/#110) cannot reach us.
#   v0.12.0 SPEC v0.13.0 §8.2 REU post-execute settle + a
#           fe25519_mul_a24 byte-31 carry fold. The carry fold IS a
#           correctness fix and it DOES reach us — fe25519.s is staged.
#           It landed at v0.12.0, i.e. before the v0.13.0 pin this bump
#           starts from, so it is already in the shipped analysis.
#   v0.13.0 Documentation, headers and verification machinery only;
#           upstream PRG byte-identical to v0.12.0. Note for anyone
#           calling reu_fetch_mul_row / reu_fetch_doubled_row directly:
#           they clobber A and C, not A only, and always have — v0.13.0
#           corrected the header that said otherwise.
#   v0.14.0 Contract SPEC v1.1.0 alignment + §6.1 member isolation
#           (LIB_PRECALC_* split out of lib_manifest.s — that member is
#           not staged). But reu_config.s IS staged, and it changed by
#           56 lines here: the §8.2 base-bank assert tightened from
#           `< $FE` to `< 31`, a new unconditional
#           `.global mul_dma_lo, mul_dma_hi`, and two new `lderror`
#           asserts that fire if a consumer overrides
#           LIB_SHARED_REU_MUL_STAGE_LO/HI without the code following.
#           Nothing to migrate — we pass none of those overrides and our
#           bank is well under 31 — but note this is the counterexample
#           to the "most upstream change never reaches us" reasoning
#           below: reu_config.s is one of the six staged files, so a
#           change in it DOES reach ca65. It happens to ship nothing
#           this time. Check it, not just the unstaged members, at every
#           bump.
#   v0.15.0 ABI 3 -> 4, and the first upstream PRG change since
#           v0.11.3. Three parts, none of which reach us: the §8.2
#           staging buffers mul_dma_lo/hi/carry split into
#           src/mul_stage.s (not staged); reu_fetch_mul_row honouring
#           the documented `A = a` fetch entry (x25519_init.s IS
#           staged, and this is where the +3 bytes below come from);
#           and a constant-time regression fix re-aligning
#           mul38_lo_tab (upstream's own tables, not ours).
#   v0.16.0 §6.1 member isolation, count 2: mul_8x8.o exported eight
#           displaceable names governed by two different switches, so
#           the §8.1 group (sqtab_init / mul_tables_init) moved to
#           src/sqtab_init.s. ABI stays 4. Nothing to migrate — this
#           wrapper stages NEITHER file (see "Excluded" below) — but
#           the split is why the exclusion note names two files now
#           where it used to name one.
#
# WHY SO LITTLE OF THAT REACHES US, and why that is the useful thing to
# know at the next bump: this wrapper does not link upstream's archive.
# It stages a WHITELIST of three upstream sources (fe25519.s, x25519.s,
# x25519_init.s, plus constants.s and its two transitive includes) and
# emits the BSS and RODATA modules itself from the heredocs below. Every
# upstream change to any other member — manifests, version equates,
# mul_8x8, mul_stage, util, main — is structurally invisible here, which
# is why an ABI generation bump (3 -> 4 at v0.15.0) passed through with
# no wrapper edit. The corollary is the thing to watch: a change inside
# one of those three staged files reaches us with NO link-time gate at
# all, because lib_version.s is not staged and so no `.assert
# LIB_X25519_ABI_VERSION = N, lderror` can be written. That gap is what
# tools/test_x25519_pin.py exists to cover.
#
# Measured delta of the whole v0.13.0 -> v0.16.0 range as it reaches
# this wrapper (od65 --dump-segments on the staged objects, both tags):
# +3 bytes in CRYPTO_CODE (x25519_init.s, the `A = a` fix), and ZERO
# bytes in X25519_RODATA and X25519_BSS at both tags. fe25519.s and
# x25519.s are byte-identical across the range. Those are per-object
# od65 counts; for the LINKED footprints of those two segments, and why
# summing objects does not give you one, see the Makefile block beside
# X25519_SEG_LADDER.
#
# Zero-page layout (src/zp_config.s): byte-identical across THIS bump —
# `git diff v0.13.0 v0.16.0 -- src/zp_config.s` is empty — so the
# time-sharing analysis below did not need revisiting for it.
#
# It is NOT byte-identical across the wider v0.6.0 -> v0.16.0 range this
# log now covers (29 insertions / 19 deletions), and the difference is
# not cosmetic: v0.11.0 DELETED three ZP slot definitions — zp_ptr1
# ($fb), zp_tmp1 ($02), zp_tmp2 ($03), moved to upstream's own main.s
# per contract #83 — and renamed poly_carry to mul_carry ($1c), leaving
# an `.ifdef poly_carry` / `.error` guard behind for consumers still
# passing the old override. A wrong ZP slot is silent runtime
# corruption with no link error, so that claim is re-derived rather
# than inherited:
#
#   - None of the three sources this wrapper assembles (fe25519.s,
#     x25519.s, x25519_init.s) references any of the four names. The
#     only hits at v0.16.0 are inside zp_config.s itself — its own
#     comments and the .error guard.
#   - c64-https defines zp_tmp1/zp_tmp2 itself, at the SAME addresses
#     ($02/$03, src/crypto/shared/zp_canon.inc), so the upstream
#     removal deletes what would now be a duplicate, not a slot we
#     depend on.
#   - This wrapper passes no -D poly_carry, so the .error guard is
#     never armed.
#
# Re-check those three points, not just the diffstat, at the next bump.
#
# Earlier contract-§1/§2/§3/§5 adoption remains in place: every ZP slot
# is `.exportzp`-ed (zp_config.s), LIB_VERSION_*/LIB_ABI_VERSION
# absolute exports (lib_version.s), X25519_REU_BANK configurable REU
# base (reu_config.s), and the LIB_X25519_* aggregate manifest equates.
#
# PROFILE: always X25519_ONCHIP_MUL=1 (upstream issue #72). This archive is
# the ONLY X25519 in every build (issue #245 retired the in-tree copy), and
# it is built the same way on all five profiles:
#   - the onchip products have no REU, so the REU row-fetch profile is not
#     an option there, and one profile everywhere keeps the REU-profile
#     A/B builds testing the same X25519 the shipped images run;
#   - the onchip profile has no REU surface at all (no reu_mul_init, no
#     reu_fetch_mul_row, no reu_probe, no §8.2 settle), so it cannot collide
#     with the §8.2 reu_mul that src/boot.s owns for libs/nistcurves, and it
#     claims no REU bank.
# fe25519_mul generates each product row through the §8.3 ct_mul_8x8 body
# that src/crypto/poly1305.s provides (with its two SMC bake sites), into
# mul_dma_lo/hi. fe25519_sqr runs mult66 over c64-https's sqtab.
#
# Excluded (replaced by in-tree equivalents):
#   - src/mul_8x8.s and src/sqtab_init.s: in-tree src/crypto/poly1305.s
#     exports mul_8x8 / ct_mul_8x8 / smc_sum_a_imm / smc_diff_a_imm /
#     sqtab_init, and src/data.s owns sqtab_lo/hi (c64-lib-contract §8.0/
#     §8.1/§8.3: c64-https owns SQTAB and the CT multiply body). The
#     sibling reads the table through its own equates baked from
#     LIB_SHARED_SQTAB_BASE below.
#   - src/data.s: replaced by the generated module below plus
#     src/crypto/x25519_tables.s (see DATA LAYOUT).
#   - src/main.s, src/util.s, manifests: no in-PRG user. (lib_version.s IS
#     staged, for the link-time ABI gate in src/lib_contract_asserts.s.)
#
# DATA LAYOUT. Upstream's data.s is not staged; its contents are split by
# lifetime, because where each piece may live differs:
#   X25519_BSS     (this script)  17 x 32 B field buffers, 32-byte aligned.
#                                 Pure per-call scratch: every one is written
#                                 before it is read inside x25519_scalarmult
#                                 / x25519_base, or by the caller just before
#                                 the call (x25_scalar, x25_u).
#   X25519_RODATA  (this script)  x25_basepoint + fe_p, 64 B initialized.
#   X25519_TABLES  (src/crypto/x25519_tables.s)
#                                 mul38 / sqr / a24 lookup tables, 2 KB,
#                                 page-aligned BSS filled by
#                                 x25519_tables_init. Generated rather than
#                                 stored: 2 KB of RODATA fits no shipped
#                                 profile, 2 KB of BSS does.
#   src/data.s                    mul_dma_lo/hi, mul_cached_a, mul_src2_buf:
#                                 shared multiply scratch that
#                                 libs/nistcurves also uses (src/crypto/
#                                 shared/mul_tables.s). c64-https owns them.
# The sibling's mul_dma_carry and REU-settle bytes are REU-profile-only and
# are not declared: an onchip build never references them.
#
# Usage (from the top-level Makefile, every build):
#   bash tools/integration/build_x25519.sh
# Produces:
#   build/lib/x25519.a
#   build/lib/x25519.sizes.txt  (per-source byte counts)
# =============================================================================
set -eo pipefail

# --- Paths ---
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB_SRC="$PROJECT_ROOT/libs/x25519/src"
STAGING="$PROJECT_ROOT/build/lib/x25519_staging"
OUT_DIR="$PROJECT_ROOT/build/lib"
ARCHIVE="$OUT_DIR/x25519.a"
SIZES="$OUT_DIR/x25519.sizes.txt"

CA65="${CA65:-ca65}"
AR65="${AR65:-ar65}"

# --- Canonical ZP defines ---
# The sibling's src/zp_config.s wraps every library-owned ZP equate in
# `.ifndef <name>` AND `.exportzp`-s the symbol (issue #44, closes
# c64-lib-contract §2). c64-https uses the sibling's defaults. They are
# time-shared with c64-https's own slots, all of which are per-operation
# scratch that is dead across both X25519 call sites in src/tls_ecdh.s:
#
#   Sibling claim   c64-https slot at same addr   Why it is free there
#   -------------   ---------------------------   --------------------
#   $14-$16         cc20_* / lmul0 / lmul1        ChaCha20 / Poly1305 state,
#                                                 set up per call
#   $1C             poly_carry                    Poly1305, per call
#   $1E-$21         tls_rec_ptr/idx/direction     set by tls_select_keys /
#                                                 tls_build_nonce per record
#   $22-$2F         fp_* (ECDSA operand ptrs)     libs/nistcurves, per call;
#                                                 verify never overlaps X25519
#   $40-$7F         ZP_WIDE (fe_wide)             reserved in every cfg for
#                                                 exactly this; nothing else
#                                                 is placed there
#
# No ZP -D overrides needed — sibling defaults match c64-https's map.
ZP_DEFINES=()

# --- Profile ---
# Value-gated (`.if ::X25519_ONCHIP_MUL`), so it MUST be spelled `=1`: ca65
# defines a bare `-D X25519_ONCHIP_MUL` as 0, which silently selects the REU
# row-fetch profile. The post-assemble check below catches that.
PROFILE_DEFINES=(-D X25519_ONCHIP_MUL=1)

# --- c64-lib-contract §8.1 shared sqtab adoption ---
# c64-https owns the canonical 1 KB quarter-square table — `sqtab_lo` /
# `sqtab_hi` at $BC00 / $BE00 in TABLES_BSS (src/data.s), filled by
# src/crypto/poly1305.s::sqtab_init at boot. The sibling's fe25519_sqr
# mult66 path reads it through `.ifndef`-guarded equates in constants.s
# derived from LIB_SHARED_SQTAB_BASE, so the value here must equal where
# ld65 actually put the table. A disagreement is neither a link nor a boot
# failure, only a wrong shared secret, so the Makefile's $(PRG) recipe
# greps build/labels.txt for sqtab_lo at $BC00 after every link.
#
# SHARED_SQTAB_INIT: the host supplies the §8.1 init (poly1305.s), so the
# sibling's own body collapses.
X25519_SQTAB_BASE="${X25519_SQTAB_BASE:-\$BC00}"
SQTAB_DEFINES=(
    -D "LIB_SHARED_SQTAB_BASE=$X25519_SQTAB_BASE"
    -D SHARED_SQTAB_INIT=1
)

# --- Stage sources ---
rm -rf "$STAGING"
mkdir -p "$STAGING"

cp "$LIB_SRC"/constants.s "$STAGING/"
# zp_config.s + reu_config.s — transitively .include'd from constants.s
# (contract §2 + §3). Both set ZP_CONFIG_NO_EXPORTS / REU_CONFIG_NO_EXPORTS
# when included via constants.s, so their export directives fire at most
# once per archive.
cp "$LIB_SRC"/zp_config.s  "$STAGING/"
cp "$LIB_SRC"/reu_config.s "$STAGING/"
cp "$LIB_SRC"/fe25519.s    "$STAGING/fe25519_raw.s"
cp "$LIB_SRC"/x25519.s     "$STAGING/x25519_raw.s"
cp "$LIB_SRC"/x25519_init.s "$STAGING/x25519_init_raw.s"
# lib_version.s: pure equates, so c64-https can gate the pin at link time
# (src/lib_contract_asserts.s imports LIB_X25519_ABI_VERSION). Assembled
# with LIB_NO_BARE_EXPORTS so its deprecated bare LIB_ABI_VERSION & co. do
# not collide with libs/nistcurves' (contract §1, #43).
cp "$LIB_SRC"/lib_version.s "$STAGING/lib_version.s"

cat > "$STAGING/data_x25519_bss_raw.s" <<'BSS_EOF'
.setcpu "6502"

; =============================================================================
; data_x25519_bss_raw.s — the sibling's 32-byte field buffers, restated from
; libs/x25519/src/data.s (which is not staged; see build_x25519.sh).
;
; 32-byte alignment is the whole contract (upstream docs/LIBRARY.md §6):
; every access is `abs,y` / `(zp),y` with Y in 0..31, so a 32-aligned buffer
; never crosses a page. Upstream additionally page-aligns the two groups of
; eight; that buys nothing the 32-byte rule does not, and here it would cost
; up to 255 B of fill per group. The asserts below are the contract.
; =============================================================================

.export fe25519_tmp1, fe25519_tmp2, fe25519_tmp3, fe25519_tmp4
.export x25_x2, x25_z2, x25_x3, x25_z3
.export x25_a, x25_b, x25_da, x25_cb, x25_e
.export x25_scalar, x25_u, x25_result, x25_x1

.segment "X25519_BSS"

        .align 32
fe25519_tmp1:   .res 32
fe25519_tmp2:   .res 32
fe25519_tmp3:   .res 32
fe25519_tmp4:   .res 32
x25_x2:         .res 32
x25_z2:         .res 32
x25_x3:         .res 32
x25_z3:         .res 32
x25_a:          .res 32
x25_b:          .res 32
x25_da:         .res 32
x25_cb:         .res 32
x25_e:          .res 32
x25_scalar:     .res 32
x25_u:          .res 32
x25_result:     .res 32
; RFC 7748 decoded u-coordinate (upstream #64, v0.7.0). x25519_scalarmult
; writes the bit-255-masked copy of x25_u here and the ladder's x_1 reads
; it. Dropping it fails the link on x25519.s's import, not silently.
x25_x1:         .res 32

;
; mul_dma_carry: the onchip profile never touches it, but fe25519_sqr's
; pre-doubled DMA bodies are assembled unconditionally and reference it,
; while their only entry (the trampoline patch) is inside `.if ::SQR_DMA_K`,
; which the onchip profile forces to 0. Upstream's mul_stage.s allocates
; 256 B for it anyway; here it is an alias so the dead reference links
; without costing a page. It is read-only in that dead code.
.import mul_dma_hi
.export mul_dma_carry
mul_dma_carry = mul_dma_hi

.assert (fe25519_tmp1 & $1F) = 0, lderror, "fe25519_tmp1 must be 32-byte aligned"
.assert (fe25519_tmp2 & $1F) = 0, lderror, "fe25519_tmp2 must be 32-byte aligned"
.assert (fe25519_tmp3 & $1F) = 0, lderror, "fe25519_tmp3 must be 32-byte aligned"
.assert (fe25519_tmp4 & $1F) = 0, lderror, "fe25519_tmp4 must be 32-byte aligned"
.assert (x25_x2 & $1F) = 0, lderror, "x25_x2 must be 32-byte aligned"
.assert (x25_z2 & $1F) = 0, lderror, "x25_z2 must be 32-byte aligned"
.assert (x25_x3 & $1F) = 0, lderror, "x25_x3 must be 32-byte aligned"
.assert (x25_z3 & $1F) = 0, lderror, "x25_z3 must be 32-byte aligned"
.assert (x25_a & $1F) = 0, lderror, "x25_a must be 32-byte aligned"
.assert (x25_b & $1F) = 0, lderror, "x25_b must be 32-byte aligned"
.assert (x25_da & $1F) = 0, lderror, "x25_da must be 32-byte aligned"
.assert (x25_cb & $1F) = 0, lderror, "x25_cb must be 32-byte aligned"
.assert (x25_e & $1F) = 0, lderror, "x25_e must be 32-byte aligned"
.assert (x25_scalar & $1F) = 0, lderror, "x25_scalar must be 32-byte aligned"
.assert (x25_u & $1F) = 0, lderror, "x25_u must be 32-byte aligned"
.assert (x25_result & $1F) = 0, lderror, "x25_result must be 32-byte aligned"
.assert (x25_x1 & $1F) = 0, lderror, "x25_x1 must be 32-byte aligned"
BSS_EOF

cat > "$STAGING/data_x25519_rodata_raw.s" <<'RODATA_EOF'
.setcpu "6502"

; =============================================================================
; data_x25519_rodata_raw.s — the sibling's two initialized field constants,
; restated from libs/x25519/src/data.s. Type `ro`, never `bss`: ld65 drops
; init bytes from bss segments, which once left fe_p = 0 at runtime.
; The lookup tables upstream also keeps here are src/crypto/x25519_tables.s.
; =============================================================================

.export x25_basepoint, fe_p

.segment "X25519_RODATA"

        .align 32
x25_basepoint:
        .byte 9
        .res 31, 0
fe_p:
        .byte $ed
        .res 30, $ff
        .byte $7f

.assert (x25_basepoint & $1F) = 0, lderror, "x25_basepoint must be 32-byte aligned"
.assert (fe_p & $1F) = 0, lderror, "fe_p must be 32-byte aligned"
RODATA_EOF

# --- Route the sibling's code segments into c64-https segments ---
#
# c64-https's cfgs do not declare the SPEC §4 `LIB_X25519_*` names, so each
# code segment is rewritten to one they do. Per-source, because ca65 emits
# one segment per source and the Makefile has to be able to split the
# sibling across regions on the tightest profile:
#
#   knob                source          v0.16.0 onchip   what it is
#   X25519_SEG_FE25519  fe25519.s          2,692 B       field arithmetic
#   X25519_SEG_LADDER   x25519.s             709 B       Montgomery ladder
#   X25519_SEG_REU      x25519_init.s         10 B       reu_clear_wide
#
# (od65 --dump-segsize on $STAGING/obj/*.o; re-measure at every pin bump.)
# Defaults (the Makefile passes the same): fe25519.s -> CRYPTO_CODE, the
# rest keep the SPEC §4 name LIB_X25519_CODE, which every cfg declares and
# places itself — CRYPTO_OVERLAY on comb, where CRYPTO_HOT cannot take the
# whole sibling. So the archive is the same bytes on every profile.
# The onchip profile has no LIB_X25519_INIT_CODE content at all; the rule
# stays so an upstream change there fails the leftover check, not ld65.
X25519_SEG_FE25519="${X25519_SEG_FE25519:-CRYPTO_CODE}"
X25519_SEG_LADDER="${X25519_SEG_LADDER:-LIB_X25519_CODE}"
X25519_SEG_REU="${X25519_SEG_REU:-LIB_X25519_CODE}"
X25519_INIT_SEGMENT="${X25519_INIT_SEGMENT:-LIB_X25519_CODE}"

for src in fe25519_raw x25519_raw x25519_init_raw; do
    case "$src" in
        fe25519_raw)     hot_seg="$X25519_SEG_FE25519" ;;
        x25519_raw)      hot_seg="$X25519_SEG_LADDER"  ;;
        x25519_init_raw) hot_seg="$X25519_SEG_REU"     ;;
    esac
    sed -i '' \
        -e 's/^\.segment "LIB_X25519_INIT_CODE"$/.segment "'"$X25519_INIT_SEGMENT"'"/' \
        -e 's/^\.segment "LIB_X25519_CODE"$/.segment "'"$hot_seg"'"/' \
        -e 's/^\.segment "CODE"$/.segment "'"$hot_seg"'"/' \
        "$STAGING/$src.s"
done

# --- Sanity: every sibling code segment must now be one we placed ---
# Catches a leftover pre-§4 `CODE` and any `LIB_X25519_*` segment a future
# bump introduces: one second here instead of an unplaced-segment ld65 error.
for src in fe25519_raw x25519_raw x25519_init_raw; do
    leftover=$(grep -E '^\.segment "(CODE|LIB_X25519_[A-Z_]*)"$' "$STAGING/$src.s" \
               | grep -vxF ".segment \"$X25519_SEG_FE25519\"" \
               | grep -vxF ".segment \"$X25519_SEG_LADDER\"" \
               | grep -vxF ".segment \"$X25519_SEG_REU\"" \
               | grep -vxF ".segment \"$X25519_INIT_SEGMENT\"" || true)
    if [ -n "$leftover" ]; then
        echo "ERROR: unrewritten sibling segment in $src.s:" >&2
        echo "$leftover" >&2
        echo "  -> no c64-https cfg declares it; extend the rewrite above." >&2
        exit 1
    fi
done

# --- Assemble each staged .s file ---
OBJ_DIR="$STAGING/obj"
rm -rf "$OBJ_DIR"
mkdir -p "$OBJ_DIR" "$OUT_DIR"

OBJS=(fe25519_raw x25519_raw x25519_init_raw data_x25519_bss_raw data_x25519_rodata_raw lib_version)
for src in "${OBJS[@]}"; do
    # `-g` embeds cc65 debug info for build/c64-https.dbg; no code change.
    "$CA65" \
        -g \
        -I "$STAGING" \
        "${ZP_DEFINES[@]}" \
        "${PROFILE_DEFINES[@]}" \
        "${SQTAB_DEFINES[@]}" \
        -D LIB_NO_BARE_EXPORTS=1 \
        ${X25519_EXTRA_DEFINES:-} \
        -o "$OBJ_DIR/$src.o" "$STAGING/$src.s"
done

# --- Profile check: the archive must carry no REU surface ---
# The onchip profile exports none of these; the REU profile exports all of
# them. A present name means the profile define did not take (a bare -D, or
# an upstream gate rename), and the onchip products would then DMA from an
# REU they do not have — the row fetch no-ops and the shared secret is wrong
# with no error anywhere.
if command -v od65 >/dev/null 2>&1; then
    reu_syms=$(od65 --dump-exports "$OBJ_DIR/x25519_init_raw.o" \
               | grep -oE '"(reu_mul_init|reu_fetch_mul_row|reu_fetch_doubled_row|reu_probe)"' || true)
    if [ -n "$reu_syms" ]; then
        echo "ERROR: x25519 archive exports REU-profile symbols: $reu_syms" >&2
        echo "  -> X25519_ONCHIP_MUL=1 did not select the onchip profile." >&2
        exit 1
    fi
fi

# --- Archive ---
OBJ_PATHS=()
for src in "${OBJS[@]}"; do OBJ_PATHS+=("$OBJ_DIR/$src.o"); done
rm -f "$ARCHIVE"
"$AR65" a "$ARCHIVE" "${OBJ_PATHS[@]}"

# --- Per-source byte counts ---
{
    echo "# x25519.a per-source byte counts (ca65 .o file sizes)"
    for src in "${OBJS[@]}"; do
        bytes=$(wc -c < "$OBJ_DIR/$src.o")
        printf '%-24s %d bytes (.o)\n' "$src" "$bytes"
    done
} > "$SIZES"

echo "built $ARCHIVE"
cat "$SIZES"
