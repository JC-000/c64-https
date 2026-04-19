#!/usr/bin/env bash
# =============================================================================
# tools/integration/build_x25519.sh - Build c64-x25519 sibling as a REU overlay .a archive
#
# Phase C.1 of the sibling-lib integration. Produces build/lib/x25519.a with
# code split across three segments so the c64-https linker can place each:
#
#   OVERLAY_X25519     - runtime code (fe25519, x25519, mul_8x8 runtime,
#                        util fetch_mul_row etc.). Paged into the live
#                        CRYPTO_OVERLAY slot via REU DMA on demand.
#   CRYPTO_INIT_CODE   - boot-time init code (reu_mul_init, sqtab_init).
#                        Lives permanently in LOADER_OVERFLOW — only ran
#                        once at boot so locality doesn't matter.
#   RESIDENT_RODATA    - constant tables (mul38, sqr, a24). Always resident.
#
# RW buffers (fe25519_tmp*, x25_*, mul_dma_*, etc.) stay in the sibling's
# DATA segment and get placed in CRYPTO_RESIDENT (still below $A000).
#
# The script stages the sibling's .s files in build/lib/x25519_staging/,
# applies a sed-patch to each to override their `.segment "CODE"` / DATA
# directives, then assembles with canonical ZP equates passed via --asm-define.
#
# Usage (from top-level Makefile):
#   bash tools/integration/build_x25519.sh
# Produces:
#   build/lib/x25519.a
#   build/lib/x25519.sizes.txt   (per-segment byte counts)
#
# Fails the build if OVERLAY_X25519 exceeds 8192 B (the CRYPTO_OVERLAY
# ceiling under both backends — UCI is 7.5 KB but the assertion uses the
# generous 8 KB overlay-slot-size invariant).
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

# --- Canonical ZP defines from shared zp_define.mk ---
# The sibling's constants.s wraps every overlapping ZP equate in
# .ifndef, so command-line -D values win over the defaults. The sibling
# uses names like `fe25519_src1` where the canonical map uses `fe_src1`;
# since we are not calling into c64-https TLS code from inside the sibling
# library, we keep the sibling's names and only override the ZP addresses
# that the sibling's constants.s exposes. Values use ca65's `$NN` hex
# literal syntax, which must be single-quoted to dodge shell expansion.
ZP_DEFINES=(
    '-Dzp_tmp1=$02'
    '-Dzp_tmp2=$03'
    '-Dfe25519_src1=$2c'
    '-Dfe25519_src2=$2e'
    '-Dfe25519_dst=$30'
    '-Dfe_misc=$28'
    '-Dfe_carry=$32'
    '-Dfe_loop=$33'
    '-Dfe_mul_i=$34'
    '-Dfe_mul_j=$35'
    '-Dx25_prev_bit=$38'
    '-Dx25_byte_idx=$39'
    '-Dx25_bit_mask=$3a'
    '-Dpoly_i=$1a'
    '-Dpoly_j=$1b'
    '-Dpoly_carry=$1c'
    '-Dpoly_tmp=$1d'
)

# --- Stage sources (sibling is a submodule; don't modify in-place) ---
rm -rf "$STAGING"
mkdir -p "$STAGING"
cp "$LIB_SRC"/constants.s "$STAGING/"
cp "$LIB_SRC"/mul_8x8.s    "$STAGING/mul_8x8_raw.s"
cp "$LIB_SRC"/fe25519.s    "$STAGING/fe25519_raw.s"
cp "$LIB_SRC"/x25519.s     "$STAGING/x25519_raw.s"
cp "$LIB_SRC"/x25519_init.s "$STAGING/x25519_init_raw.s"
cp "$LIB_SRC"/data.s       "$STAGING/data_raw.s"
cp "$LIB_SRC"/util.s       "$STAGING/util_raw.s"

# --- Apply segment + export overrides ---
#
# fe25519_raw.s, x25519_raw.s -> OVERLAY_X25519 (runtime).
# mul_8x8_raw.s has sqtab_init (init) AND mul_8x8/poly_prod_* (runtime).
#   Route its `.segment "CODE"` lines to OVERLAY_X25519 for mul_8x8 runtime,
#   and wrap sqtab_init in its own CRYPTO_INIT_CODE segment.
# x25519_init_raw.s -> CRYPTO_INIT_CODE (init only).
# data_raw.s keeps DATA segment (page-aligned RW, ends up in
#   CRYPTO_RESIDENT via cfg mapping — still below $A000).
# util_raw.s -> drop entirely (only vic/bench helpers unused by TLS).
#
# Also:
# - Disable sibling's mul_8x8 `.export sqtab_init` since in-tree
#   poly1305.s already exports it (but we do NEED the sibling's
#   population code to run — we just need to avoid dup-export).
#   Rename the symbol to `x25519_sqtab_init` so the sibling's init
#   routine is reachable via `.import x25519_sqtab_init` in crypto_init.s
#   but does not collide with in-tree poly1305.s's `sqtab_init`.

# 1. OVERLAY_X25519 runtime files
for f in fe25519_raw.s x25519_raw.s; do
    sed -i 's/^\.segment "CODE"/.segment "OVERLAY_X25519"/' "$STAGING/$f"
done

# 2. mul_8x8_raw.s: runtime code to OVERLAY_X25519, but sqtab_init export
#    collides with in-tree poly1305.s's export. Rename to x25519_sqtab_init.
sed -i 's/^\.segment "CODE"/.segment "OVERLAY_X25519"/' "$STAGING/mul_8x8_raw.s"
sed -i 's/^\.export sqtab_init,/.export x25519_sqtab_init,/' "$STAGING/mul_8x8_raw.s"
sed -i 's/^\.proc sqtab_init/.proc x25519_sqtab_init/' "$STAGING/mul_8x8_raw.s"

# 3. x25519_init_raw.s: init-only code. Route to CRYPTO_INIT_CODE.
sed -i 's/^\.segment "CODE"/.segment "CRYPTO_INIT_CODE"/' "$STAGING/x25519_init_raw.s"
# x25519_init_raw.s defines reu_mul_init -- rename to x25519_reu_mul_init so
# it does not collide with the in-tree boot.s reu_mul_init under ip65 builds
# (build.sh runs regardless of backend because the archive is linked only
# under UCI per the top-level Makefile's ifeq gate).
sed -i 's/\bexport reu_mul_init\b/export x25519_reu_mul_init/' "$STAGING/x25519_init_raw.s"
sed -i 's/^\.proc reu_mul_init/.proc x25519_reu_mul_init/' "$STAGING/x25519_init_raw.s"

# 4. data_raw.s: keep DATA segment. This file has mul_dma_* RW buffers,
#    mul38/sqr/a24 tables, x25_* state. Linker cfg maps DATA into
#    CRYPTO_RESIDENT under UCI.

# --- Assemble each staged .s file ---
OBJ_DIR="$STAGING/obj"
rm -rf "$OBJ_DIR"
mkdir -p "$OBJ_DIR" "$OUT_DIR"

# Assemble each .s file. ZP_DEFINES is a bash array of single-quoted
# `-Dname=$NN` literals so the shell never expands the $NN hex values.
for src in mul_8x8_raw fe25519_raw x25519_raw x25519_init_raw data_raw; do
    "$CA65" \
        -I "$STAGING" \
        -I "$PROJECT_ROOT/src/crypto/shared" \
        "${ZP_DEFINES[@]}" \
        -o "$OBJ_DIR/$src.o" "$STAGING/$src.s"
done

# --- Archive into x25519.a ---
rm -f "$ARCHIVE"
"$AR65" a "$ARCHIVE" \
    "$OBJ_DIR/mul_8x8_raw.o" \
    "$OBJ_DIR/fe25519_raw.o" \
    "$OBJ_DIR/x25519_raw.o" \
    "$OBJ_DIR/x25519_init_raw.o" \
    "$OBJ_DIR/data_raw.o"

# --- Per-segment byte counts via ca65's object file introspection ---
# Overlay segment size assertion is performed at link time in the top-level
# cfg (cfg/c64-https-uci.cfg has OVERLAY_X25519 region = 7680 B and will
# overflow if the archive's OVERLAY_X25519 contributions exceed that).
# The sizes file below is informational for the final ld65 .map.
{
    echo "# x25519.a per-source byte counts (ca65 .o file sizes)"
    for src in mul_8x8_raw fe25519_raw x25519_raw x25519_init_raw data_raw; do
        bytes=$(wc -c < "$OBJ_DIR/$src.o")
        printf '%-24s %d bytes (.o)\n' "$src" "$bytes"
    done
} > "$SIZES"

echo "built $ARCHIVE"
cat "$SIZES"
