#!/usr/bin/env bash
# =============================================================================
# tools/integration/build_nistcurves_p384_bin.sh — Extract a standalone
# P-384 overlay image (.bin) and VICE labels from nistcurves-p384.a.
#
# Phase C.3b. The production PRG does NOT link nistcurves-p384.a (the
# Makefile `USE_NISTCURVES_P384` gate is intentionally commented). Instead,
# tools/test_p384_symbols.py loads the output of THIS script into the
# U64/VICE REU at harness time, then pages it into the live CRYPTO_OVERLAY
# slot via crypto_swap_to_p384.
#
# Outputs:
#   build/lib/overlay-p384.bin     — raw 8192-byte OVERLAY_P384 image,
#                                    padded with $00 to the full 8 KB slot.
#   build/labels-p384.txt          — VICE-format labels for the P-384
#                                    symbols (ec_point_double_384 etc.
#                                    plus the DATA-resident ec384_p1,
#                                    ec384_affine_x and friends).
#
# The cfg at cfg/p384-overlay.cfg places:
#   * OVERLAY_P384 at $4200 (matches CRYPTO_OVERLAY base under UCI).
#   * DATA / BSS   at $7C00 (matches CRYPTO_RESIDENT_2 under UCI).
# so the labels line up with where the harness-time swap actually lands
# the overlay.
#
# Imports resolved via ld65 --define:
#   * REU register equates (not exported by the in-tree build — the
#     sibling archive `.import`s them explicitly).
#   * mul_cached_a / mul_dma_lo / mul_dma_hi / poly_prod_lo / poly_prod_hi /
#     reu_fetch_mul_row — these come from the x25519 sibling at runtime,
#     but for the standalone link we define them at their UCI-backend
#     addresses (read out of build/labels.txt if available, else stubbed
#     to $0000 — irrelevant to the OVERLAY_P384 image bytes since those
#     references are resolved as references, not inlined data).
#
# Usage (from the top-level Makefile):
#   bash tools/integration/build_nistcurves_p384_bin.sh
# =============================================================================
set -eo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ARCHIVE="$PROJECT_ROOT/build/lib/nistcurves-p384.a"
CFG="$PROJECT_ROOT/cfg/p384-overlay.cfg"
OUT_DIR="$PROJECT_ROOT/build/lib"
BIN_OUT="$OUT_DIR/overlay-p384.bin"
LABELS_OUT="$PROJECT_ROOT/build/labels-p384.txt"
MAP_OUT="$OUT_DIR/overlay-p384.map"

LD65="${LD65:-ld65}"

if [ ! -f "$ARCHIVE" ]; then
    echo "ERROR: $ARCHIVE does not exist — run tools/integration/build_nistcurves_p384.sh first" >&2
    exit 1
fi

# ld65 requires at least one plain .o on the command line; an archive
# alone is not enough even with --force-import. Extract the archive
# members into a scratch dir and pass them all as objects.
AR65="${AR65:-ar65}"
SCRATCH="$OUT_DIR/p384_bin_scratch"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cp "$ARCHIVE" "$SCRATCH/"
(cd "$SCRATCH" && "$AR65" x "$(basename "$ARCHIVE")" \
    zp_config.o fp384_raw.o mod384_raw.o points384_raw.o data_raw.o)

# Try to pick up x25519-sibling addresses from the main build's labels.txt
# so references resolve to the real runtime locations. If the main build
# hasn't happened yet, stub them to $0000 — the overlay binary doesn't
# actually dereference these; only labels.txt addresses would be wrong,
# and we strip them below anyway.
MAIN_LABELS="$PROJECT_ROOT/build/labels.txt"
lookup_label () {
    local name="$1"
    local fallback="$2"
    if [ -f "$MAIN_LABELS" ]; then
        local hex
        hex=$(grep -E " \.${name}\$" "$MAIN_LABELS" | head -n1 | awk '{print $2}' | sed 's|^C:||')
        if [ -n "$hex" ]; then
            printf '$%s' "$hex"
            return
        fi
    fi
    printf '%s' "$fallback"
}

DEF_MUL_CACHED_A=$(lookup_label mul_cached_a '$0000')
DEF_MUL_DMA_LO=$(lookup_label mul_dma_lo   '$0000')
DEF_MUL_DMA_HI=$(lookup_label mul_dma_hi   '$0000')
DEF_REU_FETCH_MUL_ROW=$(lookup_label reu_fetch_mul_row '$0000')

# poly_prod_lo / poly_prod_hi: 2-byte mul_8x8 output register. The x25519
# sibling emits these INSIDE OVERLAY_X25519 ($42A0) — unusable when our
# P-384 overlay is swapped in (same slot, different code bytes). Point
# the P-384 standalone link to stable scratch RAM at $CFFE-$CFFF, which
# sits in TCP_BUF past the P-384 DATA block ($C000-$C636).
DEF_POLY_PROD_LO='$CFFE'
DEF_POLY_PROD_HI='$CFFF'

mkdir -p "$OUT_DIR"

# Link. ld65 -Ln emits labels in the old ca65 format; the main Makefile
# rewrites `al 00XXXX .name` to `al C:XXXX .name` via sed. Mirror that.
"$LD65" \
    -C "$CFG" \
    -o "$BIN_OUT" \
    -Ln "$LABELS_OUT" \
    -m "$MAP_OUT" \
    --define reu_status=\$df00 \
    --define reu_command=\$df01 \
    --define reu_c64_lo=\$df02 \
    --define reu_c64_hi=\$df03 \
    --define reu_reu_lo=\$df04 \
    --define reu_reu_hi=\$df05 \
    --define reu_reu_bank=\$df06 \
    --define reu_len_lo=\$df07 \
    --define reu_len_hi=\$df08 \
    --define reu_addr_ctrl=\$df0a \
    --define mul_cached_a="$DEF_MUL_CACHED_A" \
    --define mul_dma_lo="$DEF_MUL_DMA_LO" \
    --define mul_dma_hi="$DEF_MUL_DMA_HI" \
    --define poly_prod_lo="$DEF_POLY_PROD_LO" \
    --define poly_prod_hi="$DEF_POLY_PROD_HI" \
    --define reu_fetch_mul_row="$DEF_REU_FETCH_MUL_ROW" \
    "$SCRATCH/zp_config.o" \
    "$SCRATCH/fp384_raw.o" \
    "$SCRATCH/mod384_raw.o" \
    "$SCRATCH/points384_raw.o" \
    "$SCRATCH/data_raw.o"

# Normalise labels to VICE format (al C:XXXX .name) so c64-test-harness's
# Labels.from_file() reader accepts it identically to build/labels.txt.
sed -i 's/^al 00\([0-9a-fA-F]\{4\}\) /al C:\1 /' "$LABELS_OUT"

# ld65 writes the DATA segment bytes (RESIDENT region at $7C00) into the
# output file too, even though RESIDENT has no `file = %O` — so the raw
# output is ~9.5 KB. Truncate to exactly 8192 bytes to get the OVERLAY_P384
# slot image. DATA lives at runtime addresses and is zero-init; the harness
# does not need its bytes in the overlay image.
truncate -s 8192 "$BIN_OUT"

size=$(wc -c < "$BIN_OUT")
if [ "$size" -ne 8192 ]; then
    echo "ERROR: $BIN_OUT is $size bytes, expected 8192" >&2
    exit 1
fi

echo "built $BIN_OUT (8192 bytes) and $LABELS_OUT"
