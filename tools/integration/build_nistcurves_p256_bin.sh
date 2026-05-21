#!/usr/bin/env bash
# =============================================================================
# tools/integration/build_nistcurves_p256_bin.sh -- Link the always-resident
# P-256 sibling archive (`build/lib/nistcurves-p256.a`) as a padded
# overlay .bin image suitable for embedding into the PRG via
# .incbin (src/crypto/shared/p256_overlay_blobs.s).
#
# W3 (library-ingestion architecture) artefact.  Today the P-256 verify
# primitives ship always-resident in CRYPTO_RESIDENT; the W1 follow-on
# will move them into the cold-path CRYPTO_OVERLAY slot.  This .bin is
# the staging image for that move: boot will DMA the bytes from
# CRYPTO_OVERLAY (PRG-load placement) to REU bank 2 slot $22100, and
# `crypto_swap_to_p256_verify` will DMA them back on demand.
#
# Mirrors tools/integration/build_nistcurves_p384_bin.sh's contract:
#   * Inputs: build/lib/nistcurves-p256.a (built by
#     build_nistcurves_p256.sh).
#   * Output: build/lib/nistcurves-p256-verify.bin (7,680 B padded).
#   * Per-image size report: build/lib/nistcurves-p256-verify.sizes.txt.
#   * Per-image label file: build/labels-p256-verify.txt.
#   * Per-image cc65 .dbg sidecar:
#     build/lib/nistcurves-p256-verify.dbg.
#
# The cfg `cfg/p256-overlay-verify.cfg` routes CRYPTO_CODE /
# CRYPTO_RODATA / RODATA into the OVERLAY_REGION ($4200, $1E00 B) and
# pins DATA / BSS at $C000 RESIDENT just so labels resolve.  The .bin
# output is truncated to $1E00 so only the overlay portion lands in
# the file.
#
# Usage (from top-level Makefile):
#   bash tools/integration/build_nistcurves_p256_bin.sh
# =============================================================================
set -eo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ARCHIVE="$PROJECT_ROOT/build/lib/nistcurves-p256.a"
CFG="$PROJECT_ROOT/cfg/p256-overlay-verify.cfg"
OUT_DIR="$PROJECT_ROOT/build/lib"
BIN_OUT="$OUT_DIR/nistcurves-p256-verify.bin"
SIZES_OUT="$OUT_DIR/nistcurves-p256-verify.sizes.txt"
LABELS_OUT="$PROJECT_ROOT/build/labels-p256-verify.txt"
MAP_OUT="$OUT_DIR/nistcurves-p256-verify.map"
DBG_OUT="${BIN_OUT%.bin}.dbg"

# Live UCI CRYPTO_OVERLAY slot size: $1E00 = 7,680 B.  The .bin is
# truncated / padded to exactly this many bytes so it DMAs cleanly
# into the live slot.
SLOT_BYTES=7680

LD65="${LD65:-ld65}"
AR65="${AR65:-ar65}"

if [ ! -f "$ARCHIVE" ]; then
    echo "ERROR: archive missing -- run tools/integration/build_nistcurves_p256.sh first" >&2
    echo "  missing: $ARCHIVE" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

# Extract archive members; ld65 wants plain .o files on the command line.
scratch="$OUT_DIR/p256_bin_scratch"
rm -rf "$scratch"
mkdir -p "$scratch"
cp "$ARCHIVE" "$scratch/"

archive_basename=$(basename "$ARCHIVE")
members=$( (cd "$scratch" && "$AR65" t "$archive_basename") | tr -d '\r' )
if [ -z "$members" ]; then
    echo "ERROR: $archive_basename appears empty" >&2
    exit 1
fi
(cd "$scratch" && "$AR65" x "$archive_basename" $members)

obj_args=()
for m in $members; do
    obj_args+=("$scratch/$m")
done

# Symbol --defines.  The P-256 minimal subset imports REU register
# equates (reu_reu_lo, reu_addr_ctrl from reu_equates_raw.s inside the
# archive) plus shared mul infrastructure (mul_cached_a, mul_dma_lo,
# mul_dma_hi, mul_8x8, poly_prod_lo/hi, reu_fetch_mul_row) provided by
# the main PRG's in-tree poly1305.s / data.s / boot.s.  For the
# standalone overlay link we pin those imports at fixed addresses --
# either resolved from build/labels.txt (the main PRG's runtime
# addresses, so the overlay's fp_mul ends up reading/writing the right
# cells when the .bin is DMA'd live) or stubbed.  See the P-384
# overlay script for the same pattern.
MAIN_LABELS="$PROJECT_ROOT/build/labels.txt"

lookup_label () {
    local name="$1"
    local fallback="$2"
    if [ ! -f "$MAIN_LABELS" ]; then
        echo "$fallback"
        return
    fi
    local hex
    hex=$(grep -E " \.${name}\$" "$MAIN_LABELS" | head -n1 | awk '{print $2}' | sed 's|^C:||')
    if [ -z "$hex" ]; then
        echo "$fallback"
    else
        printf '$%s' "$hex"
    fi
}

# Stubs are $0000 (intentional -- the .bin will be regenerated on the
# second pass once build/labels.txt exists, mirroring the P-384
# bootstrap workflow in the top-level Makefile).
DEF_MUL_CACHED_A=$(lookup_label mul_cached_a '$0000')
DEF_MUL_DMA_LO=$(lookup_label mul_dma_lo '$0000')
DEF_MUL_DMA_HI=$(lookup_label mul_dma_hi '$0000')
DEF_REU_FETCH_MUL_ROW=$(lookup_label reu_fetch_mul_row '$0000')
DEF_POLY_PROD_LO=$(lookup_label poly_prod_lo '$CFFE')
DEF_POLY_PROD_HI=$(lookup_label poly_prod_hi '$CFFF')
DEF_MUL_8X8=$(lookup_label mul_8x8 '$0000')
# ec_scalar_mul is provided by the shim in src/crypto/ecdsa_verify.s in
# the always-resident path -- for the standalone overlay link it is
# referenced from ecdsa256_raw.s but never called from any path we
# actually exercise (TLS uses ec_scalar_mul_var; ec_scalar_mul is the
# Lim-Lee fixed-base entry whose body was stripped).  Pin to a stub
# address; the in-PRG link resolves it properly.  Same for
# mul_src2_buf (lives in src/data.s under the main PRG).
DEF_EC_SCALAR_MUL=$(lookup_label ec_scalar_mul '$0000')
DEF_MUL_SRC2_BUF=$(lookup_label mul_src2_buf '$0000')

# Link.  Route the P-256 archive's segments into OVERLAY_REGION via
# the cfg (which lists CRYPTO_CODE / CRYPTO_RODATA / RODATA / CODE as
# overlay-bound and DATA / BSS / CRYPTO_BSS as RESIDENT-bound).  The
# zp_config.o object emits ZP equates only -- nothing in the output
# image -- so no segment routing is needed for it.
# NB: the archive's reu_equates_raw.s already exports reu_reu_lo and
# reu_addr_ctrl (the two slots v0.2.0's defensive REU init touches in
# ec_scalar_mul_var).  Defining them again here would conflict --
# pass only the symbols the archive imports without providing.
"$LD65" \
    -C "$CFG" \
    -o "$BIN_OUT" \
    -Ln "$LABELS_OUT" \
    -m "$MAP_OUT" \
    --dbgfile "$DBG_OUT" \
    --define mul_cached_a="$DEF_MUL_CACHED_A" \
    --define mul_dma_lo="$DEF_MUL_DMA_LO" \
    --define mul_dma_hi="$DEF_MUL_DMA_HI" \
    --define poly_prod_lo="$DEF_POLY_PROD_LO" \
    --define poly_prod_hi="$DEF_POLY_PROD_HI" \
    --define reu_fetch_mul_row="$DEF_REU_FETCH_MUL_ROW" \
    --define mul_8x8="$DEF_MUL_8X8" \
    --define ec_scalar_mul="$DEF_EC_SCALAR_MUL" \
    --define mul_src2_buf="$DEF_MUL_SRC2_BUF" \
    "${obj_args[@]}"

# Normalise labels to VICE format so c64-test-harness's
# Labels.from_file() reader accepts it identically to build/labels.txt.
sed -i '' 's/^al 00\([0-9a-fA-F]\{4\}\) /al C:\1 /' "$LABELS_OUT"

# Compute the on-disk overlay segment size from the .map (this only
# captures the OVERLAY_P256_VERIFY segment by name; other segments
# routed into OVERLAY_REGION via the cfg add to the file size but
# don't show under the named segment).
seg_name="OVERLAY_P256_VERIFY"
overlay_hex=$(awk -v seg="$seg_name" '
    /^Segment list:/ { in_seg=1; next }
    /^Exports list/  { in_seg=0 }
    in_seg && $1 == seg { print $4; exit }
' "$MAP_OUT")
overlay_bytes=""
if [ -n "$overlay_hex" ]; then
    overlay_bytes=$(printf '%d' "0x$overlay_hex")
fi

# Truncate / pad to exactly $SLOT_BYTES so the .bin DMAs into the
# live UCI overlay slot ($1E00 = 7,680 B).
truncate -s "$SLOT_BYTES" "$BIN_OUT"

size=$(wc -c < "$BIN_OUT")
if [ "$size" -ne "$SLOT_BYTES" ]; then
    echo "ERROR: $BIN_OUT is $size bytes, expected $SLOT_BYTES" >&2
    exit 1
fi

{
    echo "# nistcurves-p256-verify overlay image (W3)"
    echo "# slot size:           $SLOT_BYTES B (\$1E00 -- UCI CRYPTO_OVERLAY)"
    if [ -n "$overlay_bytes" ]; then
        echo "# unpadded overlay:    $overlay_bytes B"
        echo "# padded .bin:         $size B"
        echo "# headroom:            $((SLOT_BYTES - overlay_bytes)) B"
        if [ "$overlay_bytes" -gt "$SLOT_BYTES" ]; then
            echo "# *** OVERFLOW: overlay exceeds slot by $((overlay_bytes - SLOT_BYTES)) B ***"
        fi
    else
        echo "# unpadded overlay:    (unknown -- see $MAP_OUT)"
        echo "# padded .bin:         $size B"
    fi
} > "$SIZES_OUT"

if [ -n "$overlay_bytes" ] && [ "$overlay_bytes" -gt "$SLOT_BYTES" ]; then
    echo "ERROR: $BIN_OUT overlay segment ($overlay_bytes B) exceeds 7,680 B slot by $((overlay_bytes - SLOT_BYTES)) B" >&2
    exit 1
fi

echo "built $BIN_OUT ($size B padded; overlay = ${overlay_bytes:-unknown} B)"
cat "$SIZES_OUT"
