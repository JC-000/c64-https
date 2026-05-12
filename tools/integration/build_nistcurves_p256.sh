#!/usr/bin/env bash
# =============================================================================
# tools/integration/build_nistcurves_p256.sh - Build c64-nist-curves P-256
# ECDSA verify primitives as a resident .a archive linked into the main PRG.
#
# Phase C.4 of the sibling-lib integration. Produces build/lib/nistcurves-p256.a
# containing the P-256 field arithmetic, modular arithmetic, variable-base
# scalar multiply, Jacobian->affine conversion, and packaged ECDSA verify
# (ecdsa_verify_256). No overlay mechanism; all code always-resident.
#
# Excluded (to fit the budget + avoid REU precompute):
#   - ec_scalar_mul   - Lim-Lee fixed-base comb. Needs a 16 KB REU bank-2
#                       precompute table built by ec_precompute_256 at boot.
#                       Replaced by a shim in src/crypto/ecdsa_verify.s that
#                       copies G into ec_base_x/y and tail-calls
#                       ec_scalar_mul_var. The dispatcher is the ONLY caller
#                       of ecdsa_verify_256, so the shim covers the sole
#                       in-PRG use of ec_scalar_mul.
#   - ec_precompute_256 - builds the Lim-Lee anchor table into REU bank 2.
#                         Only useful with ec_scalar_mul.
#   - Lim-Lee anchor tables (ec_anchor1_x..ec_anchor8_y, cm_k, ec_aff2g_256_*)
#     and all sm256_reu_* REU DMA helpers that service them.
#   - All P-384 data/arith (fp384_*, ec384_*, ecdsa384_*, cm_k_384, anchors).
#     Lives in nistcurves-p384.a under the separate Phase C.3b smoke test.
#   - Shared mul infrastructure (mul_cached_a, mul_src2_buf, mul_dma_lo/hi,
#     mul_8x8, sqtab_init, sqtab_lo/hi, poly_prod_lo/hi, reu_fetch_mul_row) -
#     the in-tree src/data.s + src/crypto/poly1305.s + src/boot.s already
#     provide these and they are shared across fe25519 + P-256 via the REU
#     DMA row-fetch pipeline. Adding the sibling's copies would collide.
#   - ecdsa_inputs_256, ecdsa_result_256 test-driver scratch - only used by
#     the nist-curves PRG's own test harness.
#
# The script stages the sibling's .s files in build/lib/nistcurves_p256_staging/,
# applies sed patches to strip Lim-Lee bodies + provide a minimal P-256-only
# data.s, and assembles with canonical ZP equates passed via -D.
#
# Usage (from top-level Makefile):
#   bash tools/integration/build_nistcurves_p256.sh
# Produces:
#   build/lib/nistcurves-p256.a
#   build/lib/nistcurves-p256.sizes.txt   (per-source byte counts)
# =============================================================================
set -eo pipefail

# --- Paths ---
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB_SRC="$PROJECT_ROOT/libs/nistcurves/src"
STAGING="$PROJECT_ROOT/build/lib/nistcurves_p256_staging"
OUT_DIR="$PROJECT_ROOT/build/lib"
ARCHIVE="$OUT_DIR/nistcurves-p256.a"
SIZES="$OUT_DIR/nistcurves-p256.sizes.txt"

CA65="${CA65:-ca65}"
AR65="${AR65:-ar65}"

# --- Canonical ZP defines ---
# Mirrors the P-384 build's -D flag set. zp_ptr2 is relocated into
# $3D-$3E (inside ZP_CRYPTO, otherwise unused) because the sibling's
# default ($fd-$fe) overlaps with c64-https's zp_temp/zp_count used
# by der_decode.s during cert parsing. ecdsa_verify_256 runs AFTER
# DER parsing completes, so the clobber would be fine in practice,
# but the relocation keeps the lifetime isolation explicit.
ZP_DEFINES=(
    '-Dproc_port=$01'
    '-Dzp_tmp1=$02'
    '-Dzp_tmp2=$03'
    '-Dzp_ptr1=$fb'
    '-Dzp_ptr2=$3d'
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

cp "$LIB_SRC"/constants.s "$STAGING/"
cp "$LIB_SRC"/zp_config.s "$STAGING/"
cp "$LIB_SRC"/fp256.s      "$STAGING/fp256_raw.s"
cp "$LIB_SRC"/mod256.s     "$STAGING/mod256_raw.s"
cp "$LIB_SRC"/points256.s  "$STAGING/points256_raw.s"
cp "$LIB_SRC"/ecdsa256.s   "$STAGING/ecdsa256_raw.s"

# --- Strip points256.s of the Lim-Lee / REU precompute bodies ---
# Lines 762-1458 in the upstream file cover:
#   - sm256_reu_stash_affine / sm256_reu_fetch_affine / sm256_calc_offset_64
#     / sm256_reu_restore (REU DMA helpers for bank-2 anchor table)
#   - ec_precompute_256 and its internal helpers (load_G_jac, successive-double
#     helpers, anchor accumulate)
#   - ec_scalar_mul (Lim-Lee 8-way fixed-base comb) and its anchor-loader
#     helpers + anchor base-address table + cm_* / sm256_* state vars
# Keeps ec_point_double (line 60-410), ec_point_add (411-761),
# ec_scalar_mul_var (1459-1609), ec_jacobian_to_affine (1610-end).
sed -i '' '762,1467d' "$STAGING/points256_raw.s"

# Strip exports + imports that only the removed bodies used.
sed -i '' '/^\.export ec_precompute_256, ec_scalar_mul, ec_scalar_mul_var$/c\
.export ec_scalar_mul_var' "$STAGING/points256_raw.s"
# Anchor + Lim-Lee state imports
sed -i '' '/^\.import ec_aff2g_256_x, ec_aff2g_256_y$/d' "$STAGING/points256_raw.s"
sed -i '' '/^\.import ec_anchor[1-8]_x, ec_anchor[1-8]_x, ec_anchor[1-8]_x, ec_anchor[1-8]_x$/d' "$STAGING/points256_raw.s"
sed -i '' '/^\.import ec_anchor[1-8]_y, ec_anchor[1-8]_y, ec_anchor[1-8]_y, ec_anchor[1-8]_y$/d' "$STAGING/points256_raw.s"
sed -i '' '/^\.import ec_anchor.*$/d' "$STAGING/points256_raw.s"
sed -i '' '/^\.import cm_k, mul_dma_lo$/d' "$STAGING/points256_raw.s"
sed -i '' '/^\.import ec_sc_byte, ec_sc_mask$/d' "$STAGING/points256_raw.s"
# REU DMA register imports. v0.2.0 added a "defensive REU register init"
# block at the top of ec_scalar_mul_var (lines 753-757) that touches
# reu_reu_lo + reu_addr_ctrl, so those two must stay imported even though
# ec_scalar_mul_var is the only retained body. The rest are only used by
# the stripped REU anchor helpers and Lim-Lee comb.
sed -i '' '/^\.import reu_c64_lo, reu_c64_hi, reu_reu_lo, reu_reu_hi$/c\
.import reu_reu_lo' "$STAGING/points256_raw.s"
sed -i '' '/^\.import reu_reu_bank, reu_len_lo, reu_len_hi$/d' "$STAGING/points256_raw.s"
sed -i '' '/^\.import reu_addr_ctrl, reu_command$/c\
.import reu_addr_ctrl' "$STAGING/points256_raw.s"
# ec_mulp / ec_sqrp are used by all three retained bodies - keep.
# fp_tmp1 is used by ec_scalar_mul_var - keep.

# Sanity: no leftover non-comment references to stripped symbols.
# Filter out comment lines (first non-blank char is `;`) before checking.
if grep -v '^\s*;' "$STAGING/points256_raw.s" \
   | grep -qE '\bec_anchor[0-9]+_|\bcm_k\b|\bec_aff2g_256|\bec_sc_byte\b|\bec_sc_mask\b|\bsm256_reu|\bec_scalar_mul\b[^_]'; then
    echo "ERROR: stripped points256 still references removed-body symbols" >&2
    grep -v '^\s*;' "$STAGING/points256_raw.s" \
      | grep -nE '\bec_anchor[0-9]+_|\bcm_k\b|\bec_aff2g_256|\bec_sc_byte\b|\bec_sc_mask\b|\bsm256_reu|\bec_scalar_mul\b[^_]' \
      | head -5 >&2
    exit 1
fi

# --- Strip curve256.s to ec_a256, ec_b256, ec_gx256, ec_gy256 only ---
# The test vector constants (ecdsa_test_*) are used only by the sibling's
# own test PRG and would add ~256 B of dead rodata here.
cat > "$STAGING/curve256_raw.s" <<'CURVE_EOF'
.setcpu "6502"

; =============================================================================
; curve256_raw.s - P-256 curve parameters for c64-https Phase C.4.
; Hand-trimmed from libs/nistcurves/src/curve256.s: test vectors dropped
; (only used by the sibling's standalone test harness).
; =============================================================================

.segment "RODATA"

.export ec_a256, ec_b256, ec_gx256, ec_gy256

; Coefficient a = p - 3
ec_a256:
        .byte $FC, $FF, $FF, $FF, $FF, $FF, $FF, $FF
        .byte $FF, $FF, $FF, $FF, $00, $00, $00, $00
        .byte $00, $00, $00, $00, $00, $00, $00, $00
        .byte $01, $00, $00, $00, $FF, $FF, $FF, $FF

; Coefficient b
ec_b256:
        .byte $4B, $60, $D2, $27, $3E, $3C, $CE, $3B
        .byte $F6, $B0, $53, $CC, $B0, $06, $1D, $65
        .byte $BC, $86, $98, $76, $55, $BD, $EB, $B3
        .byte $E7, $93, $3A, $AA, $D8, $35, $C6, $5A

; Generator x coordinate (LE)
ec_gx256:
        .byte $96, $C2, $98, $D8, $45, $39, $A1, $F4
        .byte $A0, $33, $EB, $2D, $81, $7D, $03, $77
        .byte $F2, $40, $A4, $63, $E5, $E6, $BC, $F8
        .byte $47, $42, $2C, $E1, $F2, $D1, $17, $6B

; Generator y coordinate (LE)
ec_gy256:
        .byte $F5, $51, $BF, $37, $68, $40, $B6, $CB
        .byte $CE, $5E, $31, $6B, $57, $33, $CE, $2B
        .byte $16, $9E, $0F, $7C, $4A, $EB, $E7, $8E
        .byte $9B, $7F, $1A, $FE, $E2, $42, $E3, $4F
CURVE_EOF

# --- Emit minimal data_p256_raw.s ---
# Keeps only the RW buffers that fp256 / mod256 / points256 (post-strip) /
# ecdsa256 reference. Shared mul infrastructure (mul_cached_a, mul_src2_buf,
# mul_dma_lo, mul_dma_hi) is provided by in-tree src/data.s. P-384 data and
# Lim-Lee anchors are excluded.
cat > "$STAGING/data_p256_raw.s" <<'DATA_EOF'
.setcpu "6502"

; =============================================================================
; data_p256_raw.s - Minimal P-256 RW buffers for c64-https / c64-nist-curves
;              integration (Phase C.4). Hand-extracted from the sibling's
;              data.s so in-tree shared mul buffers remain unclobbered and
;              P-384 / Lim-Lee state is omitted.
;
; All exports here are P-256-exclusive.
; =============================================================================

.segment "DATA"

; --- P-256 field arithmetic working buffers (32 bytes each) ---
; fp_tmp2/3/4 and fp_r1/2/3 are declared by the sibling's full data.s
; but never .importe'd from the retained fp256/mod256/points256/ecdsa256
; bodies; pruned here to save BSS (~192 B).
.export fp_wide
fp_wide:        .res 64, 0    ; 512-bit product from multiply
.export fp_tmp1
fp_tmp1:        .res 32, 0

; --- P-256 result registers (only fp_r0 referenced) ---
.export fp_r0
fp_r0:          .res 32, 0

; --- P-256 modular inverse working space ---
.export fp_inv_u
fp_inv_u:       .res 32, 0
.export fp_inv_v
fp_inv_v:       .res 32, 0
.export fp_inv_x1
fp_inv_x1:      .res 32, 0
.export fp_inv_x2
fp_inv_x2:      .res 32, 0

; --- P-256 point storage (Jacobian: X=32 + Y=32 + Z=32 = 96 bytes) ---
.export ec_p1
ec_p1:          .res 96, 0
.export ec_p2
ec_p2:          .res 96, 0
.export ec_p3
ec_p3:          .res 96, 0

; --- P-256 point math temporaries ---
.export ec_t1
ec_t1:          .res 32, 0
.export ec_t2
ec_t2:          .res 32, 0
.export ec_t3
ec_t3:          .res 32, 0
.export ec_t4
ec_t4:          .res 32, 0
.export ec_t5
ec_t5:          .res 32, 0
.export ec_t6
ec_t6:          .res 32, 0

; --- P-256 affine output ---
.export ec_affine_x
ec_affine_x:    .res 32, 0
.export ec_affine_y
ec_affine_y:    .res 32, 0

; --- Variable-base scalar-mul input (affine, 32 bytes each, LE). ---
.export ec_base_x
ec_base_x:      .res 32, 0
.export ec_base_y
ec_base_y:      .res 32, 0

; --- Solinas reduction scratch (33 bytes: 32 + carry) ---
.export fp_red_tmp
fp_red_tmp:     .res 33, 0

; --- ECDSA verify scratch (P-256). All 32-byte little-endian unless noted. ---
.export ecdsa_r
ecdsa_r:        .res 32, 0      ; LE r (byte-reversed from BE input)
.export ecdsa_s
ecdsa_s:        .res 32, 0      ; LE s
.export ecdsa_h
ecdsa_h:        .res 32, 0      ; LE message hash
.export ecdsa_qx
ecdsa_qx:       .res 32, 0      ; LE public-key affine X
.export ecdsa_qy
ecdsa_qy:       .res 32, 0      ; LE public-key affine Y
.export ecdsa_w
ecdsa_w:        .res 32, 0      ; LE w = s^-1 mod n
.export ecdsa_u1
ecdsa_u1:       .res 32, 0      ; LE u1 = h*w mod n
.export ecdsa_u2
ecdsa_u2:       .res 32, 0      ; LE u2 = r*w mod n
.export ecdsa_u1_be
ecdsa_u1_be:    .res 32, 0      ; BE u1 (scalar_mul input)
.export ecdsa_u2_be
ecdsa_u2_be:    .res 32, 0      ; BE u2 (scalar_mul_var input)
.export ecdsa_u1g_x
ecdsa_u1g_x:    .res 32, 0      ; LE affine X of u1*G
.export ecdsa_u1g_y
ecdsa_u1g_y:    .res 32, 0      ; LE affine Y of u1*G

; --- fp_reverse32 staging buffer (one 32-byte scratch). ---
.export fp_rev_buf
fp_rev_buf:     .res 32, 0
DATA_EOF

# --- Emit minimal REU register equates ---
# v0.2.0 added a "defensive REU register init" block at the top of
# ec_scalar_mul_var (and also in fp256/ecdsa256 modular-inverse paths)
# that touches reu_reu_lo + reu_addr_ctrl. The sibling's constants.s
# provides these but also exports VIC/CIA/KERNAL equates that would
# collide with c64-https's in-tree definitions, so we emit a minimal
# equate file with only what the retained bodies actually reference.
cat > "$STAGING/reu_equates_raw.s" <<'REU_EOF'
.setcpu "6502"

; Minimal REU hardware register equates used by retained P-256 bodies
; in v0.2.0 (defensive REU register init in ec_scalar_mul_var, fp_inv,
; ecdsa inverse). Mirror of values in libs/nistcurves/src/constants.s.
.export reu_reu_lo, reu_addr_ctrl
reu_reu_lo    = $df04
reu_addr_ctrl = $df0a
REU_EOF

# --- Route CODE segments in the raw .s files to CRYPTO_CODE. ---
# The sibling uses `.segment "CODE"`, which under c64-https's cfg is the
# LOADER region ($0801-$1FFF). We want this code in CRYPTO_RESIDENT.
for src in fp256_raw mod256_raw points256_raw ecdsa256_raw; do
    sed -i '' 's/^\.segment "CODE"/.segment "CRYPTO_CODE"/' "$STAGING/$src.s"
done

# --- Route DATA segment in data_p256_raw.s to CRYPTO_BSS. ---
# The c64-https cfg has no "DATA" segment slot; our minimal data file
# only contains `.res` (zero-init) declarations, so CRYPTO_BSS is the
# right home. Don't accidentally match anything inside a string or
# comment: the data_p256_raw.s we emit has exactly one such directive.
sed -i '' 's/^\.segment "DATA"$/.segment "CRYPTO_BSS"/' "$STAGING/data_p256_raw.s"

# Sanity: no leftover `.segment "CODE"` hunks outside the expected
# pattern (the raw files should only have one CODE segment each).
for src in fp256_raw mod256_raw points256_raw ecdsa256_raw; do
    if grep -qE '^\.segment "CODE"$' "$STAGING/$src.s"; then
        echo "ERROR: leftover .segment \"CODE\" in $src.s" >&2
        exit 1
    fi
done

# --- Assemble each staged .s file ---
OBJ_DIR="$STAGING/obj"
rm -rf "$OBJ_DIR"
mkdir -p "$OBJ_DIR" "$OUT_DIR"

# zp_config.s is the single point of truth for ZP equates; we apply -D
# overrides so sibling defaults get replaced with c64-https's canonical map.
"$CA65" \
    -I "$STAGING" \
    -I "$PROJECT_ROOT/src/crypto/shared" \
    "${ZP_DEFINES[@]}" \
    -o "$OBJ_DIR/zp_config.o" "$STAGING/zp_config.s"

for src in fp256_raw mod256_raw points256_raw ecdsa256_raw curve256_raw data_p256_raw reu_equates_raw; do
    "$CA65" \
        -I "$STAGING" \
        -I "$PROJECT_ROOT/src/crypto/shared" \
        -o "$OBJ_DIR/$src.o" "$STAGING/$src.s"
done

# --- Archive ---
rm -f "$ARCHIVE"
"$AR65" a "$ARCHIVE" \
    "$OBJ_DIR/zp_config.o" \
    "$OBJ_DIR/fp256_raw.o" \
    "$OBJ_DIR/mod256_raw.o" \
    "$OBJ_DIR/points256_raw.o" \
    "$OBJ_DIR/ecdsa256_raw.o" \
    "$OBJ_DIR/curve256_raw.o" \
    "$OBJ_DIR/data_p256_raw.o" \
    "$OBJ_DIR/reu_equates_raw.o"

# --- Per-source byte counts ---
{
    echo "# nistcurves-p256.a per-source byte counts (ca65 .o file sizes)"
    for src in zp_config fp256_raw mod256_raw points256_raw ecdsa256_raw curve256_raw data_p256_raw reu_equates_raw; do
        bytes=$(wc -c < "$OBJ_DIR/$src.o")
        printf '%-24s %d bytes (.o)\n' "$src" "$bytes"
    done
} > "$SIZES"

echo "built $ARCHIVE"
cat "$SIZES"
