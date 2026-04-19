#!/usr/bin/env bash
# =============================================================================
# tools/integration/build_nistcurves_p384.sh - Build c64-nist-curves P-384
# primitives as a REU overlay .a archive for the UCI backend.
#
# Phase C.3 of the sibling-lib integration. Produces build/lib/nistcurves-p384.a
# containing ONLY the three variable-base P-384 primitives used by TLS
# (ec_point_double_384, ec_point_add_384, ec_jacobian_to_affine_384)
# plus their fp/mod helpers.
#
# Segment layout:
#   OVERLAY_P384     - all P-384 runtime code (fp384 + mod384 + points384).
#                      Paged into the live CRYPTO_OVERLAY slot via REU DMA.
#   CRYPTO_RESIDENT  - P-384 RW data (ec384_* points, fp384_* tmps, etc.)
#                      routed through the DATA / BSS segments.
#
# Excluded (upstream JC-000/c64-nist-curves#17 tracks what's missing):
#   - ec_scalar_mul_384     - fixed-base-only (Lim-Lee comb over precomputed
#                             anchors). Not useful without variable-base mul.
#   - ec_precompute_384     - builds the Lim-Lee comb table; needs REU bank 2
#                             layout that conflicts with the overlay store.
#   - Lim-Lee anchor tables (ec_anchor1_384_x..ec_anchor8_384_y) and
#     comb-scalar state (cm_k_384, ec384_sc_byte/mask, ec384_precomp_i).
#   - P-256 modules (fp256/mod256/curve256/points256/inv256). P-256 stays
#     in-tree (see src/crypto/ecdsa_*.s); Phase C.3 does not swap it out.
#   - curve384.s (ec_a384/b384/gx384/gy384constants). Only imported by the
#     stripped ec_precompute_384 / ec_scalar_mul_384.
#
# The mul_8x8 runtime + mul_dma_lo/hi tables + reu_fetch_mul_row come
# from the already-linked c64-x25519 sibling archive (build/lib/x25519.a).
# P-384's fp_mul_384 / fp_sqr_384 reuse those REU-backed product tables;
# the table layout (a*512 offset, 256 lo + 256 hi bytes per row) matches
# between the two siblings.
#
# The script stages the sibling's .s files in build/lib/nistcurves_p384_staging/,
# applies a sed-patch to each to override their `.segment "CODE"` / "DATA"
# directives, and assembles with canonical ZP equates passed via -D.
#
# Usage (from top-level Makefile):
#   bash tools/integration/build_nistcurves_p384.sh
# Produces:
#   build/lib/nistcurves-p384.a
#   build/lib/nistcurves-p384.sizes.txt   (per-source byte counts)
# =============================================================================
set -eo pipefail

# --- Paths ---
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB_SRC="$PROJECT_ROOT/libs/nistcurves/src"
STAGING="$PROJECT_ROOT/build/lib/nistcurves_p384_staging"
OUT_DIR="$PROJECT_ROOT/build/lib"
ARCHIVE="$OUT_DIR/nistcurves-p384.a"
SIZES="$OUT_DIR/nistcurves-p384.sizes.txt"

CA65="${CA65:-ca65}"
AR65="${AR65:-ar65}"

# --- Canonical ZP defines ---
# The sibling's zp_config.s wraps every ZP equate in .ifndef, so command-line
# -D values win over the defaults. We pin the sibling to c64-https's
# canonical ZP map (src/crypto/shared/zp_canon.inc) so the archive's
# absolute ZP references line up with TLS call-site expectations.
#
# Note: fp_mul_i / fp_mul_j overlap with x25_byte_idx / x25_bit_mask at
# $39/$3a. This is fine because x25519 and P-384 run at different times
# (different overlays; only one resident at a time) and the canonical
# map documents the time-sharing.
ZP_DEFINES=(
    '-Dproc_port=$01'
    '-Dzp_tmp1=$02'
    '-Dzp_tmp2=$03'
    '-Dzp_ptr1=$fb'
    '-Dzp_ptr2=$fd'
    '-Dfp_src1=$22'
    '-Dfp_src2=$24'
    '-Dfp_dst=$26'
    '-Dfp_misc=$28'
    '-Dfp_carry=$2a'
    '-Dfp_loop=$2b'
    '-Dfp_mul_i=$39'
    '-Dfp_mul_j=$3a'
    '-Dec_scalar_ptr=$3b'
    '-Dpoly_i=$1a'
    '-Dpoly_j=$1b'
    '-Dpoly_carry=$1c'
    '-Dpoly_tmp=$1d'
)

# --- Stage sources ---
rm -rf "$STAGING"
mkdir -p "$STAGING"

# The sibling's constants.s is pulled in via -I; we don't stage it here
# (it has no segment directives we'd rewrite, and it's .include'd by
# zp_config.s / data.s transitively).
cp "$LIB_SRC"/constants.s "$STAGING/"
cp "$LIB_SRC"/zp_config.s "$STAGING/"
cp "$LIB_SRC"/fp384.s      "$STAGING/fp384_raw.s"
cp "$LIB_SRC"/mod384.s     "$STAGING/mod384_raw.s"
cp "$LIB_SRC"/points384.s  "$STAGING/points384_raw.s"
cp "$LIB_SRC"/data.s       "$STAGING/data_raw.s"

# --- Strip points384.s of ec_precompute_384 and ec_scalar_mul_384 ---
# Those live between lines 787 (just before ec_precompute_384:) and
# 1489 (just before the ec_jacobian_to_affine_384: header).
# We also strip the `.export ec_precompute_384, ec_scalar_mul_384` line
# so the archive doesn't advertise symbols whose bodies were removed.
# The remaining three `.export` symbols (ec_point_double_384,
# ec_point_add_384, ec_jacobian_to_affine_384) stay.
#
# Imports that the removed bodies relied on (anchors, cm_k_384, sc_byte,
# sc_mask, precomp_i, ec_gx384, ec_gy384, ec_set_modp_384... wait ec_set_modp
# is still used by double/add) — we remove ONLY the anchor + comb-state
# imports since everything else is used by the retained primitives.
sed -i '787,1489d' "$STAGING/points384_raw.s"
sed -i '/^\.export ec_precompute_384, ec_scalar_mul_384$/d' "$STAGING/points384_raw.s"
# Strip imports only used by the removed bodies. Patterns are anchored
# to avoid accidentally deleting unrelated lines.
sed -i '/^\.import ec_gx384, ec_gy384$/d' "$STAGING/points384_raw.s"
sed -i '/^\.import ec_anchor[1-8]_384_x/d' "$STAGING/points384_raw.s"
sed -i '/^\.import ec_anchor[1-8]_384_y/d' "$STAGING/points384_raw.s"
sed -i '/^\.import cm_k_384, mul_dma_lo$/d' "$STAGING/points384_raw.s"
sed -i '/^\.import ec384_sc_byte, ec384_sc_mask, ec384_precomp_i$/d' "$STAGING/points384_raw.s"

# --- Strip data_raw.s of P-256 content + Lim-Lee comb anchors ---
# We only keep the P-384 RW buffers that fp384 / mod384 / points384 reference:
#   fp384_wide, fp384_tmp1..4, fp384_r0..r3, fp384_inv_u/v/x1/x2,
#   ec384_p1/p2/p3, ec384_t1..t6, ec384_affine_x/y, fp384_red_tmp
#
# We drop:
#   - P-256 field buffers (fp_wide, fp_tmp*, fp_r*, fp_inv_*, ec_p1..)
#     because c64-https's in-tree ECDSA P-256 already provides these and
#     we must not double-define them. ALSO: fp_wide in c64-nist-curves
#     is 64 bytes while the in-tree ecdsa_fp.s `fp_wide` is local (no
#     export) — keeping the sibling's fp_wide would create a collision.
#   - mul_cached_a, mul_src2_buf, mul_dma_lo/hi — provided by the
#     x25519 sibling (already linked first in SIBLING_LIB_ARCHIVES).
#   - Lim-Lee anchors (ec_anchor*_x/y, ec_aff2g_256_*), cm_k / cm_k_384,
#     ec384_sc_*, ec384_precomp_i — only used by the stripped scalar-mul
#     and precompute bodies.
#
# Strategy: write a brand new data_raw.s that pulls only what we need.
# We keep the sibling's data.s around for reference but emit an
# explicit minimal one.
cat > "$STAGING/data_raw.s" <<'DATA_EOF'
; =============================================================================
; data_raw.s - Minimal P-384 RW buffers for c64-https / c64-nist-curves
;              integration. Hand-extracted from the sibling's data.s so the
;              P-256 side (in-tree) and the x25519 sibling's shared mul
;              tables remain unclobbered.
;
; All exports here are P-384-exclusive.
; =============================================================================
.setcpu "6502"

.segment "DATA"

; --- P-384 field arithmetic working buffers (48 bytes each) ---
.export fp384_wide
fp384_wide:     .res 96, 0    ; 768-bit product from multiply
.export fp384_tmp1
fp384_tmp1:     .res 48, 0
.export fp384_tmp2
fp384_tmp2:     .res 48, 0
.export fp384_tmp3
fp384_tmp3:     .res 48, 0
.export fp384_tmp4
fp384_tmp4:     .res 48, 0

; --- P-384 result registers ---
.export fp384_r0
fp384_r0:       .res 48, 0
.export fp384_r1
fp384_r1:       .res 48, 0
.export fp384_r2
fp384_r2:       .res 48, 0
.export fp384_r3
fp384_r3:       .res 48, 0

; --- P-384 modular inverse working space ---
.export fp384_inv_u
fp384_inv_u:    .res 48, 0
.export fp384_inv_v
fp384_inv_v:    .res 48, 0
.export fp384_inv_x1
fp384_inv_x1:   .res 48, 0
.export fp384_inv_x2
fp384_inv_x2:   .res 48, 0

; --- P-384 point storage (Jacobian: X=48 + Y=48 + Z=48 = 144 bytes) ---
.export ec384_p1
ec384_p1:       .res 144, 0
.export ec384_p2
ec384_p2:       .res 144, 0
.export ec384_p3
ec384_p3:       .res 144, 0

; --- P-384 point math temporaries ---
.export ec384_t1
ec384_t1:       .res 48, 0
.export ec384_t2
ec384_t2:       .res 48, 0
.export ec384_t3
ec384_t3:       .res 48, 0
.export ec384_t4
ec384_t4:       .res 48, 0
.export ec384_t5
ec384_t5:       .res 48, 0
.export ec384_t6
ec384_t6:       .res 48, 0

; --- P-384 affine output ---
.export ec384_affine_x
ec384_affine_x: .res 48, 0
.export ec384_affine_y
ec384_affine_y: .res 48, 0

; --- P-384 Solinas reduction scratch ---
.export fp384_red_tmp
fp384_red_tmp:  .res 49, 0
DATA_EOF

# --- Route CODE segments to OVERLAY_P384 ---
# fp384_raw.s and mod384_raw.s use `.segment "CODE"` (once each) and
# fp384_raw.s has a second `.segment "BSS"` block at the tail. Those
# tail BSS buffers (fp384_sqr_extra, mul_src2_buf_384, fp384_sqr_pairs)
# must go in CRYPTO_RESIDENT BSS (always-resident state, not overlay)
# since the overlay gets swapped out between calls. We rename the BSS
# segment to the c64-https canonical `BSS` name which the UCI cfg maps
# into CRYPTO_RESIDENT_2 BSS.
sed -i 's/^\.segment "CODE"/.segment "OVERLAY_P384"/' "$STAGING/fp384_raw.s"
sed -i 's/^\.segment "CODE"/.segment "OVERLAY_P384"/' "$STAGING/mod384_raw.s"
sed -i 's/^\.segment "CODE"/.segment "OVERLAY_P384"/' "$STAGING/points384_raw.s"
# fp384_raw.s .segment "BSS" stays — already matches the canonical BSS
# segment which cfg/c64-https-uci.cfg maps into CRYPTO_RESIDENT_2.

# --- mod384.s curve constants (ec_p384, ec_n384) live in CODE segment
# in the sibling and are emitted inline with .byte directives. After the
# CODE->OVERLAY_P384 rewrite they flow into the overlay alongside the
# code that reads them; that is intentional (ec_p384 is used by
# fp_mod_reduce384 which IS in the overlay).

# --- ec_sc_byte / ec_sc_mask ---
# points384.s had `.import ec384_sc_byte, ec384_sc_mask, ec384_precomp_i`
# — we stripped that import above since only the removed precompute /
# scalarmul bodies referenced those names. Double-check nothing leaked:
if grep -qE '\bec384_sc_byte\b|\bec384_sc_mask\b|\bec384_precomp_i\b|\bcm_k_384\b|\bec_anchor[0-9]_384\b|\bec_gx384\b|\bec_gy384\b' "$STAGING/points384_raw.s"; then
    echo "ERROR: stripped points384 still references removed-body symbols" >&2
    exit 1
fi

# --- Assemble each staged .s file ---
OBJ_DIR="$STAGING/obj"
rm -rf "$OBJ_DIR"
mkdir -p "$OBJ_DIR" "$OUT_DIR"

# zp_config.s is the single point of truth for the library's ZP equates.
# We assemble it with `-D` overrides so the sibling's defaults are
# replaced by c64-https's canonical ZP map. The other source files use
# `.importzp` to pull these equates from the linker-resolved zp_config.o.
"$CA65" \
    -I "$STAGING" \
    -I "$PROJECT_ROOT/src/crypto/shared" \
    "${ZP_DEFINES[@]}" \
    -o "$OBJ_DIR/zp_config.o" "$STAGING/zp_config.s"

# Other files: NO -D. Let `.importzp` resolve through the linker to
# zp_config.o's `.exportzp` declarations. If we passed -D here the
# assembler would treat the symbol as locally-defined absolute and
# conflict with the .importzp declaration.
for src in fp384_raw mod384_raw points384_raw data_raw; do
    "$CA65" \
        -I "$STAGING" \
        -I "$PROJECT_ROOT/src/crypto/shared" \
        -o "$OBJ_DIR/$src.o" "$STAGING/$src.s"
done

# --- Archive into nistcurves-p384.a ---
rm -f "$ARCHIVE"
"$AR65" a "$ARCHIVE" \
    "$OBJ_DIR/zp_config.o" \
    "$OBJ_DIR/fp384_raw.o" \
    "$OBJ_DIR/mod384_raw.o" \
    "$OBJ_DIR/points384_raw.o" \
    "$OBJ_DIR/data_raw.o"

# --- Per-source byte counts ---
{
    echo "# nistcurves-p384.a per-source byte counts (ca65 .o file sizes)"
    for src in zp_config fp384_raw mod384_raw points384_raw data_raw; do
        bytes=$(wc -c < "$OBJ_DIR/$src.o")
        printf '%-24s %d bytes (.o)\n' "$src" "$bytes"
    done
} > "$SIZES"

echo "built $ARCHIVE"
cat "$SIZES"
