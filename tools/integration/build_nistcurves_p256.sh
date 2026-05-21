#!/usr/bin/env bash
# =============================================================================
# tools/integration/build_nistcurves_p256.sh - Build c64-nist-curves P-256
# ECDSA verify primitives as a resident .a archive linked into the main PRG.
#
# Phase C.4 + W5 (library-ingestion architecture). Under the c64-lib-contract
# (libs/nistcurves v0.3.0), the upstream library publishes a
# `make lib-p256-verify` build target that produces a minimal-subset archive
# carrying exactly the symbols needed for variable-base P-256 verify. This
# script delegates the heavy lifting to `make -C libs/nistcurves`, then
# performs two adjustments before placing the result at the location the
# top-level Makefile expects:
#
#   1. Rebuild `zp_config.o` with c64-https's ZP-slot overrides (the upstream
#      defaults collide with c64-https's canonical map on three slots:
#      zp_ptr2, fp_mul_i, fp_mul_j). The library's zp_config.s `.ifndef`-
#      guards every slot, so an override-built version replaces the
#      upstream default cleanly.
#
#   2. Drop `mul_8x8.o` and `data_shared.o` from the archive. c64-https's
#      in-tree `src/crypto/poly1305.s` and `src/data.s` already export the
#      same symbols (mul_8x8, sqtab_init, poly_prod_lo/hi, mul_cached_a,
#      mul_src2_buf, mul_dma_lo/hi). Including the library's copies would
#      cause ld65 duplicate-symbol errors.
#
# Pre-contract this script was ~400 lines of `sed -i ''` strips and
# heredoc'd hand-extracted curve/data files. Post-contract the
# `make lib-p256-verify` target replaces all of that — no segment
# rewriting (upstream now emits `LIB_NISTCURVES_P256_*` segments by
# convention), no body strips (the lib-p256-verify variant excludes the
# Lim-Lee comb + precompute already), no hand-extracted data heredoc
# (upstream's `data_p256.s` is the canonical RW state list).
#
# Outputs:
#   build/lib/nistcurves-p256.a            - the consumer-side archive
#   build/lib/nistcurves-p256.sizes.txt    - per-source byte counts
# =============================================================================
set -eo pipefail

# --- Paths ---
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB_DIR="$PROJECT_ROOT/libs/nistcurves"
LIB_SRC="$LIB_DIR/src"
LIB_BUILD="$LIB_DIR/build"
STAGING="$PROJECT_ROOT/build/lib/nistcurves_p256_staging"
OUT_DIR="$PROJECT_ROOT/build/lib"
ARCHIVE="$OUT_DIR/nistcurves-p256.a"
SIZES="$OUT_DIR/nistcurves-p256.sizes.txt"

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

# --- 1. Build upstream's lib-p256-verify archive ---
# Upstream's Makefile builds every module with the same recipe (no per-file
# CA65FLAGS hook), so we cannot pass -D overrides via `make CA65=...` here:
# the override would land on every .s, including fp256.s which only
# `.importzp`s the slots and would error on a redefinition. We therefore
# build upstream with its defaults, then rebuild zp_config.o ourselves with
# the overrides below.
#
# Note on c64-lib-contract SPEC §8.1: nistcurves v0.3.0's `mul_8x8.s` is
# the only TU that references sqtab_lo / sqtab_hi (via the local
# `.ifndef LIB_SHARED_SQTAB_BASE` equate in that file). Step 4 below
# drops `mul_8x8.o` from the archive entirely — c64-https provides the
# canonical `sqtab_lo` / `sqtab_hi` via src/data.s and the population
# init via src/crypto/poly1305.s::sqtab_init. So no LIB_SHARED_SQTAB_BASE
# / SHARED_SQTAB_INIT override is needed at the nistcurves Makefile
# invocation — the upstream default baked into mul_8x8.o is discarded
# before it reaches the link.
echo "[p256] building libs/nistcurves lib-p256-verify (upstream defaults)..."
make -s -C "$LIB_DIR" lib-p256-verify >/dev/null

UPSTREAM_ARCHIVE="$LIB_BUILD/lib/nistcurves-p256-verify.a"
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
# `.ifndef`-guarded slots in src/zp_config.s let -D flags win cleanly.
# The .exportzp declarations propagate the override values to every
# `.importzp` site via the link.
"$CA65" \
    --cpu 6502 \
    -g \
    -I "$LIB_SRC" \
    "${ZP_OVERRIDES[@]}" \
    -o "$STAGING/zp_config.o" \
    "$LIB_SRC/zp_config.s"

# --- 4. Drop conflicting members ---
# mul_8x8.o: exports mul_8x8, sqtab_init, poly_prod_lo/hi, sqtab_lo/hi,
#            reu_fetch_mul_row. c64-https's src/crypto/poly1305.s already
#            exports these — including upstream's copy causes ld65 dup-sym.
# data_shared.o: exports mul_cached_a, mul_src2_buf, mul_dma_lo/hi.
#            c64-https's src/data.s already exports these — same conflict.
rm -f "$STAGING/mul_8x8.o" "$STAGING/data_shared.o"

# --- 5. Re-archive into c64-https's expected location ---
# Order matches upstream's lib-p256-verify recipe so labels.txt diffs
# stay readable across bumps.
rm -f "$ARCHIVE"
"$AR65" a "$ARCHIVE" \
    "$STAGING/lib_version.o" \
    "$STAGING/lib_manifest.o" \
    "$STAGING/zp_config.o" \
    "$STAGING/constants.o" \
    "$STAGING/reu_config.o" \
    "$STAGING/fp256.o" \
    "$STAGING/mod256.o" \
    "$STAGING/curve256.o" \
    "$STAGING/points256_core.o" \
    "$STAGING/ecdsa256.o" \
    "$STAGING/data_p256.o"

# --- 6. Per-source byte counts (for the supervisor's PR description) ---
{
    echo "# nistcurves-p256.a per-source byte counts (ca65 .o file sizes)"
    for src in lib_version lib_manifest zp_config constants reu_config \
               fp256 mod256 curve256 points256_core ecdsa256 data_p256; do
        if [ -f "$STAGING/$src.o" ]; then
            bytes=$(wc -c < "$STAGING/$src.o")
            printf '%-24s %d bytes (.o)\n' "$src" "$bytes"
        fi
    done
} > "$SIZES"

echo "built $ARCHIVE"
cat "$SIZES"
