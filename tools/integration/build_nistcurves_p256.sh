#!/usr/bin/env bash
# =============================================================================
# tools/integration/build_nistcurves_p256.sh - Build c64-nist-curves P-256
# ECDSA verify primitives as a resident .a archive linked into the main PRG.
#
# Phase C.4 + W5 (library-ingestion architecture). Under the c64-lib-contract
# (libs/nistcurves v0.5.0), the upstream library publishes
# `make lib-p256-verify` / `make lib-p256-verify-onchip` build targets that
# produce minimal-subset archives carrying exactly the symbols needed for
# variable-base P-256 verify. This script delegates the heavy lifting to
# `make -C libs/nistcurves`, then performs adjustments before placing the
# result at the location the top-level Makefile expects:
#
#   1. Rebuild the archive's `zp_config*.o` member with c64-https's ZP-slot
#      overrides (the upstream defaults collide with c64-https's canonical map
#      on three slots: zp_ptr2, fp_mul_i, fp_mul_j). The library's zp_config.s
#      `.ifndef`-guards every slot, so an override-built version replaces the
#      upstream default cleanly. The member name is DISCOVERED from the
#      archive, not hardcoded — upstream v0.9.0 gave each archive its own
#      per-variant object (`zp_config_p256verify.o`), and a hardcoded name
#      would drop the overrides silently. Post-checked with od65.
#
#   2. Drop `mul_8x8[_onchip].o` (REU profile) and `data_shared.o` (both
#      profiles) from the archive. c64-https's in-tree
#      `src/crypto/poly1305.s` and `src/data.s` already export the same
#      symbols (mul_8x8, sqtab_init, poly_prod_lo/hi, mul_cached_a,
#      mul_src2_buf, mul_dma_lo/hi). Including the library's copies would
#      cause ld65 duplicate-symbol errors.
#
#   3. ONCHIP PROFILE ONLY (issue #69 / v0.5.0): re-add a REBUILT
#      `mul_8x8_onchip.o`, assembled with the SPEC §8.1/§8.3 consumer-shared
#      defines:
#        -D FP_ONCHIP_MUL=1        row-gen loop og_common/og_src_ld kept
#        -D SHARED_CT_MUL_8X8=1    canonical ct_mul_8x8 + poly_prod +
#                                  smc_* SUPPLIED BY src/crypto/poly1305.s
#        -D SHARED_SQTAB_INIT=1    sqtab_init SUPPLIED BY poly1305.s
#        -D LIB_SHARED_SQTAB_BASE=$BC00
#                                  sqtab_lo/hi become absolute equates at
#                                  the address data.s's placeholder reserves
#                                  (post-link check in the Makefile verifies)
#      The resulting object provides og_common / og_src_ld (imported by
#      fp256_onchip.o's gen_mul_row stubs) + the sqtab equates +
#      reu_fetch_mul_row (boot.s gates its duplicate export under
#      USE_NISTCURVES_ONCHIP).
#
# Usage:  build_nistcurves_p256.sh [reu|onchip]     (default: reu)
#
# Outputs (reu):    build/lib/nistcurves-p256.a         + .sizes.txt
# Outputs (onchip): build/lib/nistcurves-p256-onchip.a  + .sizes.txt
# =============================================================================
set -eo pipefail

PROFILE="${1:-reu}"
case "$PROFILE" in reu|onchip|onchip-comb) ;; *) echo "ERROR: profile must be reu|onchip|onchip-comb, got '$PROFILE'" >&2; exit 2;; esac

# --- Paths ---
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB_DIR="$PROJECT_ROOT/libs/nistcurves"
LIB_SRC="$LIB_DIR/src"
LIB_BUILD="$LIB_DIR/build"
OUT_DIR="$PROJECT_ROOT/build/lib"
if [ "$PROFILE" = "onchip-comb" ]; then
    # Comb-accelerated turbo profile: stage from the FULL onchip archive
    # (the only shipped archive whose ecdsa256.o is the comb variant and
    # which carries points256_comb.o + data_p256_limlee.o), then drop
    # everything non-P-256 in step 4b. Consumer boot obligation grows by
    # ec_precompute_256 (REU bank 2 $0000-$3FFF anchors, SPEC §8.3/§8.5).
    UPSTREAM_TARGET="lib-onchip"
    UPSTREAM_ARCHIVE="$LIB_BUILD/lib/nistcurves-onchip.a"
    STAGING="$PROJECT_ROOT/build/lib/nistcurves_p256_onchip_comb_staging"
    ARCHIVE="$OUT_DIR/nistcurves-p256-onchip-comb.a"
    SIZES="$OUT_DIR/nistcurves-p256-onchip-comb.sizes.txt"
elif [ "$PROFILE" = "onchip" ]; then
    UPSTREAM_TARGET="lib-p256-verify-onchip"
    UPSTREAM_ARCHIVE="$LIB_BUILD/lib/nistcurves-p256-verify-onchip.a"
    STAGING="$PROJECT_ROOT/build/lib/nistcurves_p256_onchip_staging"
    ARCHIVE="$OUT_DIR/nistcurves-p256-onchip.a"
    SIZES="$OUT_DIR/nistcurves-p256-onchip.sizes.txt"
else
    UPSTREAM_TARGET="lib-p256-verify"
    UPSTREAM_ARCHIVE="$LIB_BUILD/lib/nistcurves-p256-verify.a"
    STAGING="$PROJECT_ROOT/build/lib/nistcurves_p256_staging"
    ARCHIVE="$OUT_DIR/nistcurves-p256.a"
    SIZES="$OUT_DIR/nistcurves-p256.sizes.txt"
fi

CA65="${CA65:-ca65}"
AR65="${AR65:-ar65}"

# --- ZP-slot overrides (c64-https canonical map) ---
# nistcurves_zp_ptr2 = $3D : library default $fd collides with c64-https
#                 zp_temp/zp_count used by der_decode.s during cert parsing.
# fp_mul_i = $39, fp_mul_j = $3A : library defaults $2c/$2d collide with
#                 c64-https fe25519 ZP claim ($2c-$37). $39-$3a is otherwise
#                 unused inside ZP_CRYPTO.
# Other slots match upstream defaults — see libs/nistcurves/src/zp_config.s.
#
# THE POINTER SLOT IS SPELLED `nistcurves_zp_ptr2` FROM v0.10.0. The
# spelling is PROBED, never hardcoded, because both spellings are wrong at
# some pin this script has to build.
#
# c64-lib-contract SPEC §2 gained a ZP prefix registry at v0.9.0: a bare
# `zp_ptr2` is unregistered (three adopters had independently converged on
# bare zp_tmp1/zp_ptr1 — contract #83), so c64-nist-curves renamed its four
# general-scratch slots to the registered `nistcurves_zp_*` family and left
# the bare names as aliases for the §6.5 rename window, in the "loud-break"
# shape that clause ratifies:
#
#     .ifndef nistcurves_zp_ptr2
#       nistcurves_zp_ptr2 = $fd
#     .endif
#     zp_ptr2 = nistcurves_zp_ptr2        <- NOT .ifndef-guarded
#
# Measured, ca65 V2.18, against each pin's own zp_config.s:
#
#   spelling                      v0.9.1                v0.10.1
#   -D 'zp_ptr2=$3d'              overrides correctly   Error: Symbol
#                                                       'zp_ptr2' is
#                                                       already defined
#   -D 'nistcurves_zp_ptr2=$3d'   defines an unused     overrides both
#                                 symbol; real slot     names to $3D
#                                 stays at $fd
#
# Neither spelling is safe across both, so probe the library source and
# follow it. Note the v0.9.1 + canonical cell is a *wrong value*, not a
# silent one: the `check_zp_slot` guards below read the emitted object with
# od65, so that combination stops the build (as `$fd` != `$3d`, or as
# `<absent>` if the guard is aimed at the canonical name). The probe's value
# is being loud AND correct at both pins, rather than merely loud at one.
#
# fp_mul_i / fp_mul_j need no probe: `fp_` is a registered §2 prefix for
# c64-nist-curves, so those names are canonical already and keep their
# `.ifndef` guards across the migration (verified on v0.10.1).
if grep -qE '^[[:space:]]*\.ifndef[[:space:]]+nistcurves_zp_ptr2[[:space:]]*$' "$LIB_SRC/zp_config.s"; then
    ZP_PTR2_SLOT='nistcurves_zp_ptr2'
else
    ZP_PTR2_SLOT='zp_ptr2'
fi
ZP_OVERRIDES=(
    '-D' "$ZP_PTR2_SLOT=\$3d"
    '-D' 'fp_mul_i=$39'
    '-D' 'fp_mul_j=$3a'
)

# --- 1. Build upstream's verify archive ---
# Upstream's Makefile builds every module with the same recipe (no per-file
# CA65FLAGS hook), so we cannot pass -D overrides via `make CA65=...` here.
# We build upstream with its defaults, then rebuild the TUs that need
# consumer overrides (zp_config.o always; mul_8x8_onchip.o under onchip).
echo "[p256/$PROFILE] building libs/nistcurves $UPSTREAM_TARGET (upstream defaults)..."
make -s -C "$LIB_DIR" "$UPSTREAM_TARGET" >/dev/null

if [ ! -f "$UPSTREAM_ARCHIVE" ]; then
    echo "ERROR: upstream archive missing: $UPSTREAM_ARCHIVE" >&2
    exit 1
fi

# --- 2. Stage upstream object files ---
rm -rf "$STAGING"
mkdir -p "$STAGING" "$OUT_DIR"
cp "$UPSTREAM_ARCHIVE" "$STAGING/upstream.a"
(cd "$STAGING" && "$AR65" x upstream.a $( "$AR65" t upstream.a ))

# --- 3. Rebuild the archive's zp_config member with c64-https overrides ---
# The member NAME is discovered, never hardcoded. Upstream v0.9.0 (issue #90)
# gave each of the nine archives its own per-variant ZP object, so
# `nistcurves-p256-verify.a` ships `zp_config_p256verify.o` and only the FULL
# archive still ships a plain `zp_config.o`. Step 5 re-archives strictly by
# `ar65 t upstream.a`, so writing to a hardcoded `zp_config.o` here would have
# been SILENTLY DROPPED from the output and the upstream-default object
# archived in its place — reinstating exactly the ZP collisions these
# overrides exist to prevent (zp_ptr2 $fd vs c64-https zp_temp/zp_count during
# cert parsing; fp_mul_i/j $2c/$2d inside the fe25519 claim $2c-$37). That is
# memory corruption at runtime, not a link error, so it must fail loudly here.
ZP_MEMBER=""
for m in $( "$AR65" t "$STAGING/upstream.a" ); do
    case "$m" in zp_config*.o)
        [ -z "$ZP_MEMBER" ] || { echo "ERROR: upstream archive has more than one zp_config member ($ZP_MEMBER, $m) — teach this script which one to override" >&2; exit 1; }
        ZP_MEMBER="$m" ;;
    esac
done
[ -n "$ZP_MEMBER" ] || { echo "ERROR: no zp_config*.o member in $UPSTREAM_ARCHIVE — upstream layout changed; the c64-https ZP overrides would be silently lost" >&2; exit 1; }

# The variant gate decides which slots the object .exportzp's (zp_config.s
# lines ~132-141), so it must match what upstream built the member with.
case "$ZP_MEMBER" in
    zp_config.o)             ZP_VARIANT_DEFINE=() ;;
    zp_config_p256verify.o)  ZP_VARIANT_DEFINE=('-D' 'LIB_P256_VERIFY_ONLY') ;;
    zp_config_p384verify.o)  ZP_VARIANT_DEFINE=('-D' 'LIB_P384_VERIFY_ONLY') ;;
    zp_config_p384curve.o)   ZP_VARIANT_DEFINE=('-D' 'LIB_P384_CURVE_ONLY') ;;
    zp_config_sha384.o)      ZP_VARIANT_DEFINE=('-D' 'LIB_SHA384_ONLY') ;;
    *) echo "ERROR: unrecognised zp_config member '$ZP_MEMBER' — add its upstream -D gate to this case block" >&2; exit 1 ;;
esac

echo "[p256/$PROFILE] rebuilding $ZP_MEMBER with c64-https ZP overrides..."
"$CA65" \
    --cpu 6502 \
    -g \
    -I "$LIB_SRC" \
    "${ZP_VARIANT_DEFINE[@]+"${ZP_VARIANT_DEFINE[@]}"}" \
    "${ZP_OVERRIDES[@]}" \
    -o "$STAGING/$ZP_MEMBER" \
    "$LIB_SRC/zp_config.s"

# 3b. Prove the overrides actually landed in the object that gets archived.
# A ZP collision here is silent at link time and only shows up as corrupted
# cert parsing at runtime, so assert the values rather than trusting the -D.
check_zp_slot() {
    local name="$1" want="$2" got
    got=$("${OD65:-od65}" --dump-exports "$STAGING/$ZP_MEMBER" \
          | awk -v n="\"$name\"" '$1=="Name:" && $2==n {f=1; next} f && $1=="Value:" {gsub(/[()]/,"",$3); print $3; exit}')
    if [ "$got" != "$want" ]; then
        echo "ERROR: $ZP_MEMBER exports $name = ${got:-<absent>}, expected $want (c64-https ZP override did not take)" >&2
        exit 1
    fi
}
# Both spellings are checked. On the pinned v0.9.1 these are the same symbol
# and the second call is a no-op restatement; on a §2-migrated pin they are
# the canonical slot and its deprecated alias, and checking both proves the
# alias tracks the override rather than splitting one slot across two
# addresses — the silent outcome contract §6.5 forbids.
check_zp_slot "$ZP_PTR2_SLOT" 61   # $3d — canonical spelling for this pin
check_zp_slot zp_ptr2  61      # $3d
check_zp_slot fp_mul_i 57      # $39
check_zp_slot fp_mul_j 58      # $3a

# --- 4. Drop conflicting members / rebuild the onchip mul object ---
# `reu_mul_init.o` is the SPEC §8.2 `reu_mul` provider. c64-https is the
# §8.0 APP_OWNED case for that primitive — src/boot.s::reu_mul_init builds
# the 128 KB REU multiply table itself — so the library's provider is
# surplus in every configuration. Dropping it is the archive-surgery
# spelling of `-D SHARED_REU_MUL_INIT` (the wrapper cannot pass that
# define: upstream's Makefile builds every module with one recipe, which
# is why step 3 rebuilds rather than reconfigures).
#
# It is a NO-OP for the shipped builds and load-bearing for one that is
# not shipped yet. Default build: boot.o defines `reu_mul_init` and
# `reu_fetch_mul_row` itself, so ld65 has no undefined symbol this member
# could satisfy and never pulls it — the four REU-profile PRGs are
# byte-identical with and without the drop (measured). Onchip archives
# never contained it. But under `USE_X25519_SIBLING=1`, boot.o *imports*
# `reu_mul_init` (the sibling owns the table), ld65 pulls this member to
# satisfy it because nistcurves-p256.a precedes x25519.a on the link line,
# and then the sibling's own provider arrives via `reu_clear_wide` —
# `ld65: Error: Duplicate external identifier: 'reu_mul_tables_init'`,
# the failure README.md and CLAUDE.md both recorded as unconditional.
# Note the near miss: had ld65 resolved instead of erroring, `reu_mul_init`
# would have bound to the library's table builder rather than the
# sibling's, which is a different routine writing through a different
# buffer set.
rm -f "$STAGING/mul_8x8.o" "$STAGING/data_shared.o" "$STAGING/reu_mul_init.o"
# 4b. onchip-comb: the full onchip archive carries both curves + SHA-384 +
# reference-inverse extras; keep only the P-256 comb verify set.
if [ "$PROFILE" = "onchip-comb" ]; then
    rm -f "$STAGING"/fp384_onchip.o "$STAGING"/mod384.o "$STAGING"/curve384.o \
          "$STAGING"/points384_core.o "$STAGING"/points384_comb.o \
          "$STAGING"/data_p384.o "$STAGING"/data_p384_limlee.o \
          "$STAGING"/ecdsa384.o "$STAGING"/ecdsa384_msg.o \
          "$STAGING"/sha384*.o "$STAGING"/data_sha.o \
          "$STAGING"/inv256.o "$STAGING"/data_p256_invref.o
fi
if [ "$PROFILE" = "onchip" ] || [ "$PROFILE" = "onchip-comb" ]; then
    # Rebuild (not drop): fp256_onchip.o imports og_common/og_src_ld which
    # only this TU provides. The SHARED_* defines strip everything that
    # would collide with the in-tree providers (see header comment #3).
    #
    # Upstream gap (candidate c64-nist-curves issue): the og_common block
    # references ct_mul_8x8 / smc_* as same-TU symbols, so
    # SHARED_CT_MUL_8X8 alone leaves them undefined — the guard combo was
    # never exercised upstream. Bridge it with a generated glue TU that
    # declares the .imports and then .includes the PRISTINE library source
    # (composition, not a source patch — libs/ stays untouched).
    #
    # THE IMPORT LIST SHRANK AT v0.10.1, AND SHRINKING IT WAS MANDATORY.
    # Upstream moved three of the five symbols this glue used to supply
    # into its own source, so re-declaring them is now a hard assemble
    # error rather than a harmless duplicate:
    #
    #   poly_prod_lo / poly_prod_hi  defined unconditionally at
    #       mul_8x8.s:223-225, deliberately OUTSIDE the SHARED_CT_MUL_8X8
    #       gate (contract v0.9.1 adopter-private-buffer rule: fp_sqr's
    #       diagonal path writes them with no ct_mul_8x8 involved).
    #       Importing them here now yields
    #       `mul_8x8.s(223): Error: Symbol 'poly_prod_lo' is already an
    #       import`. The consumer side moved to match: under
    #       USE_NISTCURVES_ONCHIP, src/crypto/poly1305.s IMPORTS this
    #       object's pair instead of defining its own, so og_common's
    #       `jsr ct_mul_8x8` and its poly_prod read-back address the same
    #       two bytes. See the ownership comment in poly1305.s — getting
    #       this wrong is silent wrong crypto, not a link error.
    #   mul_cached_a                 upstream imports the §6.5 canonical
    #       `nistcurves_mul_cached_a` itself (mul_8x8.s:30); the bare name
    #       is aliased for it in src/crypto/shared/mul_tables.s.
    #
    # ct_mul_8x8 and the two SMC bake sites are still ours to supply:
    # upstream declares no import for them under SHARED_CT_MUL_8X8.
    cat > "$STAGING/mul_8x8_onchip_glue.s" <<'EOF'
; generated by build_nistcurves_p256.sh (onchip profile) — do not edit
.import ct_mul_8x8
.import smc_sum_a_imm, smc_diff_a_imm
.include "mul_8x8.s"
EOF
    "$CA65" \
        --cpu 6502 \
        -g \
        -I "$LIB_SRC" \
        -D FP_ONCHIP_MUL=1 \
        -D SHARED_CT_MUL_8X8=1 \
        -D SHARED_SQTAB_INIT=1 \
        -D 'LIB_SHARED_SQTAB_BASE=$BC00' \
        -o "$STAGING/mul_8x8_onchip.o" \
        "$STAGING/mul_8x8_onchip_glue.s"
else
    rm -f "$STAGING/mul_8x8_onchip.o"
fi

# --- 5. Re-archive into c64-https's expected location ---
# Member list is taken from the upstream archive dynamically (v0.5.0
# renamed/added members vs v0.3.0: ecdsa256_nocomb.o, precalc_manifest.o,
# lib_manifest_onchip.o, ...) minus the dropped members above, so this
# script no longer needs touching when upstream reshuffles objects.
MEMBERS=()
for m in $( "$AR65" t "$STAGING/upstream.a" ); do
    [ -f "$STAGING/$m" ] || continue        # dropped members
    MEMBERS+=("$STAGING/$m")
done
rm -f "$ARCHIVE"
"$AR65" a "$ARCHIVE" "${MEMBERS[@]}"

# --- 6. Per-source byte counts (for the supervisor's PR description) ---
{
    echo "# $(basename "$ARCHIVE") per-source byte counts (ca65 .o file sizes)"
    for m in $( "$AR65" t "$STAGING/upstream.a" ); do
        if [ -f "$STAGING/$m" ]; then
            bytes=$(wc -c < "$STAGING/$m")
            printf '%-24s %d bytes (.o)\n' "${m%.o}" "$bytes"
        fi
    done
} > "$SIZES"

echo "built $ARCHIVE"
cat "$SIZES"
