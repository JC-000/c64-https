#!/usr/bin/env bash
# =============================================================================
# tools/integration/build_nistcurves_p384_bin.sh — Extract the two split
# P-384 overlay images (.bin) and VICE labels for the SHA-384 and curve /
# verify halves.
#
# Phase 1.5 split.  Phase 1b's monolithic overlay (12,836 B) overflowed
# the live UCI CRYPTO_OVERLAY slot ($1E00 = 7,680 B at $4200-$5FFF).
# This script now produces TWO 7.5 KB-padded images, one per archive
# half emitted by build_nistcurves_p384.sh.  Each image fits the live
# slot; the TLS path loads them in sequence (sha384 first, then curve).
#
# Outputs:
#   build/lib/overlay-p384-sha384.bin  - 7,680-byte padded overlay image
#                                        for the SHA-384 hash code.
#                                        REU dest: REU_OVERLAY_P384_SHA384
#                                        (bank 6, $60000) -- see
#                                        src/crypto/shared/reu_layout.inc.
#   build/lib/overlay-p384-curve.bin   - 7,680-byte padded overlay image
#                                        for the curve / verify code.
#                                        REU dest: REU_OVERLAY_P384_CURVE
#                                        (bank 7, $70000).
#   build/lib/overlay-p384-sha384.sizes.txt
#   build/lib/overlay-p384-curve.sizes.txt
#   build/labels-p384-sha384.txt       - VICE-format labels for the SHA
#                                        archive's symbols.
#   build/labels-p384-curve.txt        - VICE-format labels for the curve
#                                        archive's symbols.
#
# The cfgs at cfg/p384-overlay-sha384.cfg and cfg/p384-overlay-curve.cfg
# pin both OVERLAY_REGION at $4200 size $1E00 (matches the live UCI
# CRYPTO_OVERLAY) and DATA / BSS at $C000 (matches the standalone
# RESIDENT region).
#
# The production PRG does NOT link nistcurves-p384-*.a (the Makefile
# `USE_NISTCURVES_P384` gate is intentionally commented).  These outputs
# are smoke-test infrastructure: a future Phase 3 / Phase 4a harness
# will load both .bins into REU at test time, then DMA them into the
# live slot via crypto_swap_to_p384_sha384 / crypto_swap_to_p384_curve
# (Phase 3 will add those; the existing crypto_swap_to_p384 entry point
# is now stale and will be replaced — see crypto_swap.s comment block).
#
# Imports resolved via ld65 --define:
#   * REU register equates (not exported by the in-tree build — the
#     sibling archive `.import`s them explicitly).
#   * mul_cached_a / mul_dma_lo / mul_dma_hi / poly_prod_lo / poly_prod_hi /
#     reu_fetch_mul_row — these come from the x25519 sibling at runtime,
#     but for the standalone link we define them at their UCI-backend
#     addresses (read out of build/labels.txt if available, else stubbed
#     to $0000 — irrelevant to the OVERLAY_P384_* image bytes since those
#     references are resolved as references, not inlined data).
#
# Usage (from the top-level Makefile):
#   bash tools/integration/build_nistcurves_p384_bin.sh
# =============================================================================
set -eo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ARCHIVE_SHA="$PROJECT_ROOT/build/lib/nistcurves-p384-sha384.a"
ARCHIVE_CURVE="$PROJECT_ROOT/build/lib/nistcurves-p384-curve.a"
CFG_SHA="$PROJECT_ROOT/cfg/p384-overlay-sha384.cfg"
CFG_CURVE="$PROJECT_ROOT/cfg/p384-overlay-curve.cfg"
OUT_DIR="$PROJECT_ROOT/build/lib"
BIN_OUT_SHA="$OUT_DIR/overlay-p384-sha384.bin"
BIN_OUT_CURVE="$OUT_DIR/overlay-p384-curve.bin"
SIZES_OUT_SHA="$OUT_DIR/overlay-p384-sha384.sizes.txt"
SIZES_OUT_CURVE="$OUT_DIR/overlay-p384-curve.sizes.txt"
LABELS_OUT_SHA="$PROJECT_ROOT/build/labels-p384-sha384.txt"
LABELS_OUT_CURVE="$PROJECT_ROOT/build/labels-p384-curve.txt"
MAP_OUT_SHA="$OUT_DIR/overlay-p384-sha384.map"
MAP_OUT_CURVE="$OUT_DIR/overlay-p384-curve.map"

# Live UCI CRYPTO_OVERLAY slot size: $1E00 = 7,680 B.  Each .bin is
# truncated/padded to exactly this many bytes so it DMAs cleanly into
# the live slot.
SLOT_BYTES=7680

LD65="${LD65:-ld65}"
AR65="${AR65:-ar65}"

if [ ! -f "$ARCHIVE_SHA" ] || [ ! -f "$ARCHIVE_CURVE" ]; then
    echo "ERROR: archive(s) missing — run tools/integration/build_nistcurves_p384.sh first" >&2
    [ ! -f "$ARCHIVE_SHA" ]   && echo "  missing: $ARCHIVE_SHA"   >&2
    [ ! -f "$ARCHIVE_CURVE" ] && echo "  missing: $ARCHIVE_CURVE" >&2
    exit 1
fi

# Pick up main-PRG addresses for mul_dma_lo / mul_dma_hi / mul_cached_a /
# reu_fetch_mul_row so the curve overlay's fp_mul_384 reads/writes the
# right runtime cells (e.g. mul_dma_lo at $BA00 in the main PRG's
# TABLES_BSS).  These symbols belong to the main PRG, not to the overlay
# itself; the overlay's fp_mul_384 was assembled against `.import`s for
# them and ld65 needs `--define`'d addresses to resolve them at overlay
# link time.
#
# Phase 5 Fix D: if build/labels.txt is missing OR any required symbol is
# missing from it, ABORT with a clear error rather than silently falling
# back to $0000 stubs (which used to produce a curve overlay whose
# fp_mul_384 read/wrote $0000/$0001 — silent corruption with no obvious
# symptom downstream).  The Makefile lists build/labels.txt as an
# order-only dep on the overlay-bin target so the main PRG's labels are
# present by the time this script runs in normal incremental builds; on
# a clean tree the user must build the main PRG first (which builds
# overlay-bins as a transitive dep — the cycle resolves on the second
# pass).
MAIN_LABELS="$PROJECT_ROOT/build/labels.txt"
if [ ! -f "$MAIN_LABELS" ]; then
    echo "ERROR: $MAIN_LABELS not found." >&2
    echo "  The overlay-bin link needs the main PRG's runtime addresses for" >&2
    echo "  mul_dma_lo / mul_dma_hi / mul_cached_a / reu_fetch_mul_row." >&2
    echo "  Run 'make' (or 'make BACKEND=uci') once first to produce" >&2
    echo "  build/labels.txt, then re-run 'make p384-overlay'." >&2
    exit 3
fi

lookup_label () {
    local name="$1"
    local hex
    hex=$(grep -E " \.${name}\$" "$MAIN_LABELS" | head -n1 | awk '{print $2}' | sed 's|^C:||')
    if [ -z "$hex" ]; then
        echo "ERROR: required symbol '$name' missing from $MAIN_LABELS" >&2
        echo "  Did the main PRG link complete successfully?  See build/c64-https.map." >&2
        exit 4
    fi
    printf '$%s' "$hex"
}

DEF_MUL_CACHED_A=$(lookup_label mul_cached_a)
DEF_MUL_DMA_LO=$(lookup_label mul_dma_lo)
DEF_MUL_DMA_HI=$(lookup_label mul_dma_hi)
DEF_REU_FETCH_MUL_ROW=$(lookup_label reu_fetch_mul_row)

# poly_prod_lo / poly_prod_hi: 2-byte mul_8x8 output register.  The x25519
# sibling emits these INSIDE OVERLAY_X25519 ($42A0) — unusable when our
# P-384 overlay is swapped in (same slot, different code bytes).  Point
# the P-384 standalone link to stable scratch RAM at $CFFE-$CFFF, which
# sits in TCP_BUF past the P-384 DATA block.
DEF_POLY_PROD_LO='$CFFE'
DEF_POLY_PROD_HI='$CFFF'

mkdir -p "$OUT_DIR"

# -----------------------------------------------------------------------------
# Helper: link one archive into a padded .bin + labels file.
# Args: archive_path, cfg_path, bin_out, labels_out, map_out, sizes_out, archive_label
# -----------------------------------------------------------------------------
link_one () {
    local archive="$1"
    local cfg="$2"
    local bin_out="$3"
    local labels_out="$4"
    local map_out="$5"
    local sizes_out="$6"
    local label="$7"

    local scratch="$OUT_DIR/p384_bin_scratch_${label}"
    rm -rf "$scratch"
    mkdir -p "$scratch"
    cp "$archive" "$scratch/"

    # ld65 requires plain .o objects on the command line; an archive alone
    # is not enough even with --force-import.  Extract the archive members
    # and pass them as objects.  We don't know in advance which members
    # the archive holds, so use `ar65 t` to enumerate.
    local archive_basename
    archive_basename=$(basename "$archive")
    local members
    members=$( (cd "$scratch" && "$AR65" t "$archive_basename") | tr -d '\r' )
    if [ -z "$members" ]; then
        echo "ERROR: $archive_basename appears empty" >&2
        exit 1
    fi
    (cd "$scratch" && "$AR65" x "$archive_basename" $members)

    local obj_args=()
    local m
    for m in $members; do
        obj_args+=("$scratch/$m")
    done

    # Sidecar .dbg path: build/lib/overlay-p384-{sha384,curve}.dbg.
    # Pairs with the `-g` ca65 flag added in build_nistcurves_p384.sh so
    # ld65 can merge per-source line/symbol records.  Does not affect the
    # padded .bin image bytes.
    local dbg_out
    dbg_out="${bin_out%.bin}.dbg"

    "$LD65" \
        -C "$cfg" \
        -o "$bin_out" \
        -Ln "$labels_out" \
        -m "$map_out" \
        --dbgfile "$dbg_out" \
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
        "${obj_args[@]}"

    # Normalise labels to VICE format (al C:XXXX .name) so c64-test-harness's
    # Labels.from_file() reader accepts it identically to build/labels.txt.
    sed -i '' 's/^al 00\([0-9a-fA-F]\{4\}\) /al C:\1 /' "$labels_out"

    # Compute the on-disk OVERLAY image size from the .map (so the sizes
    # report reflects the real loaded bytes, not the post-truncate size).
    local seg_name
    if [ "$label" = "sha384" ]; then
        seg_name="OVERLAY_P384_SHA384"
    else
        seg_name="OVERLAY_P384_CURVE"
    fi
    # macOS awk lacks strtonum(); parse the hex Size field via printf.
    # The .map has TWO sections that mention segment names:
    #   "Modules list" rows:  Offs=000000  Size=001550  Align=00001
    #   "Segment list" rows:  Name Start End Size Align (hex, no prefix)
    # We want the Segment list size, so anchor on its header line.
    local overlay_hex
    overlay_hex=$(awk -v seg="$seg_name" '
        /^Segment list:/ { in_seg=1; next }
        /^Exports list/  { in_seg=0 }
        in_seg && $1 == seg { print $4; exit }
    ' "$map_out")
    local overlay_bytes=""
    if [ -n "$overlay_hex" ]; then
        overlay_bytes=$(printf '%d' "0x$overlay_hex")
    fi

    # ld65 writes the DATA segment bytes (RESIDENT region at $C000) into
    # the output file too, even though RESIDENT has no `file = %O` — so
    # the raw output is much larger than the slot.  Truncate / pad to
    # exactly $SLOT_BYTES so the .bin DMAs into the live UCI overlay
    # slot (which is exactly $1E00 = 7,680 B).  DATA lives at runtime
    # addresses and is zero-init; the harness does not need its bytes
    # in the overlay image.
    truncate -s "$SLOT_BYTES" "$bin_out"

    local size
    size=$(wc -c < "$bin_out")
    if [ "$size" -ne "$SLOT_BYTES" ]; then
        echo "ERROR: $bin_out is $size bytes, expected $SLOT_BYTES" >&2
        exit 1
    fi

    {
        echo "# nistcurves-p384-${label} overlay image (Phase 1.5 split)"
        echo "# slot size:           $SLOT_BYTES B (\$1E00 — UCI CRYPTO_OVERLAY)"
        if [ -n "$overlay_bytes" ]; then
            echo "# unpadded overlay:    $overlay_bytes B"
            echo "# padded .bin:         $size B"
            echo "# headroom:            $((SLOT_BYTES - overlay_bytes)) B"
            if [ "$overlay_bytes" -gt "$SLOT_BYTES" ]; then
                echo "# *** OVERFLOW: overlay exceeds slot by $((overlay_bytes - SLOT_BYTES)) B ***"
            fi
        else
            echo "# unpadded overlay:    (unknown — see $map_out)"
            echo "# padded .bin:         $size B"
        fi
    } > "$sizes_out"

    if [ -n "$overlay_bytes" ] && [ "$overlay_bytes" -gt "$SLOT_BYTES" ]; then
        echo "ERROR: $bin_out overlay segment ($overlay_bytes B) exceeds 7,680 B slot by $((overlay_bytes - SLOT_BYTES)) B" >&2
        exit 1
    fi

    echo "built $bin_out ($size B padded; overlay = ${overlay_bytes:-unknown} B)"
}

link_one "$ARCHIVE_SHA"   "$CFG_SHA"   "$BIN_OUT_SHA"   "$LABELS_OUT_SHA"   "$MAP_OUT_SHA"   "$SIZES_OUT_SHA"   "sha384"
link_one "$ARCHIVE_CURVE" "$CFG_CURVE" "$BIN_OUT_CURVE" "$LABELS_OUT_CURVE" "$MAP_OUT_CURVE" "$SIZES_OUT_CURVE" "curve"

echo
echo "Phase 1.5 split overlay sizes:"
cat "$SIZES_OUT_SHA"
echo
cat "$SIZES_OUT_CURVE"
