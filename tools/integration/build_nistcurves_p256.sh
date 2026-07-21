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
#   1. Rebuild `zp_config.o` with c64-https's ZP-slot overrides (the upstream
#      defaults collide with c64-https's canonical map on three slots:
#      zp_ptr2, fp_mul_i, fp_mul_j). The library's zp_config.s `.ifndef`-
#      guards every slot, so an override-built version replaces the
#      upstream default cleanly.
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
# zp_ptr2 = $3D : library default $fd collides with c64-https zp_temp/zp_count
#                 used by der_decode.s during cert parsing.
# fp_mul_i = $39, fp_mul_j = $3A : library defaults $2c/$2d collide with
#                 c64-https fe25519 ZP claim ($2c-$37). $39-$3a is otherwise
#                 unused inside ZP_CRYPTO.
# Other slots match upstream defaults — see libs/nistcurves/src/zp_config.s.
ZP_OVERRIDES=(
    '-D' 'zp_ptr2=$3d'
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

# --- 3. Rebuild zp_config.o with c64-https overrides ---
"$CA65" \
    --cpu 6502 \
    -g \
    -I "$LIB_SRC" \
    "${ZP_OVERRIDES[@]}" \
    -o "$STAGING/zp_config.o" \
    "$LIB_SRC/zp_config.s"

# --- 4. Drop conflicting members / rebuild the onchip mul object ---
rm -f "$STAGING/mul_8x8.o" "$STAGING/data_shared.o"
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
    # references ct_mul_8x8 / smc_* / poly_prod_* as same-TU symbols, so
    # SHARED_CT_MUL_8X8 alone leaves them undefined — the guard combo was
    # never exercised upstream. Bridge it with a generated glue TU that
    # declares the .imports and then .includes the PRISTINE library source
    # (composition, not a source patch — libs/ stays untouched).
    cat > "$STAGING/mul_8x8_onchip_glue.s" <<'EOF'
; generated by build_nistcurves_p256.sh (onchip profile) — do not edit
.import ct_mul_8x8
.import smc_sum_a_imm, smc_diff_a_imm
.import poly_prod_lo, poly_prod_hi
.import mul_cached_a
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
