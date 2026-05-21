#!/usr/bin/env bash
# =============================================================================
# tools/integration/gen_p384_overlay_equates.sh — Phase 5 Fix C.
#
# Extract P-384 overlay-resident symbol addresses from
# build/labels-p384-sha384.txt and build/labels-p384-curve.txt and emit a
# ca65 .inc file (build/p384_overlay_equates.inc) that the TLS-side P-384
# verify dispatcher (src/crypto/ecdsa_verify_384.s) can `.include` to
# pick them up at assembly time.
#
# Phase 4a hand-pasted these addresses as numeric equates.  When the
# overlay images are rebuilt (e.g. after a libs/nistcurves bump or an
# overlay-cfg restructure) the addresses move silently — the dispatcher
# carries on calling stale addresses with no link-time error.  Wiring
# the equates through a generated `.inc` lets ca65's `.assert` (in the
# dispatcher itself) catch drift, and at minimum the dispatcher will
# fail to build if a required label disappears entirely from the
# overlay labels file.
#
# Symbols extracted (must exist in the overlay labels):
#   sha384_init        — overlay code entry, expected $4200 (sha384 cfg)
#   sha384_update      — overlay code entry
#   sha384_final       — overlay code entry
#   sha384_digest      — overlay-resident DATA, 48 B BE digest output
#   ecdsa_verify_384   — overlay code entry, expected $4200..$5FFF
#   ecdsa_inputs_384   — overlay-resident DATA, 240 B BE input struct
#
# Usage (from the Makefile):
#   bash tools/integration/gen_p384_overlay_equates.sh \
#        build/labels-p384-sha384.txt \
#        build/labels-p384-curve.txt \
#        build/p384_overlay_equates.inc
# =============================================================================
set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <sha384_labels.txt> <curve_labels.txt> <out.inc>" >&2
    exit 64
fi

SHA_LABELS="$1"
CURVE_LABELS="$2"
OUT="$3"

if [ ! -f "$SHA_LABELS" ]; then
    echo "ERROR: SHA-384 overlay labels not found: $SHA_LABELS" >&2
    exit 1
fi
if [ ! -f "$CURVE_LABELS" ]; then
    echo "ERROR: curve overlay labels not found: $CURVE_LABELS" >&2
    exit 1
fi

# lookup_label <labels-file> <symbol-name>
# Emits the 4-hex-char address (e.g. 4200) or fails if the symbol is missing.
lookup_label () {
    local file="$1"
    local name="$2"
    # Format: "al C:HHHH .name"  (post-ld65 sed normalisation in Makefile).
    local hex
    hex=$(awk -v n=".$name" '$3 == n { sub(/^C:/, "", $2); print $2; exit }' "$file")
    if [ -z "$hex" ]; then
        echo "ERROR: symbol '$name' not found in $file" >&2
        exit 2
    fi
    echo "$hex"
}

SHA384_INIT=$(lookup_label   "$SHA_LABELS"   sha384_init)
SHA384_UPDATE=$(lookup_label "$SHA_LABELS"   sha384_update)
SHA384_FINAL=$(lookup_label  "$SHA_LABELS"   sha384_final)
SHA384_DIGEST=$(lookup_label "$SHA_LABELS"   sha384_digest)
ECDSA_VERIFY_384=$(lookup_label "$CURVE_LABELS" ecdsa_verify_384)
ECDSA_INPUTS_384=$(lookup_label "$CURVE_LABELS" ecdsa_inputs_384)

mkdir -p "$(dirname "$OUT")"

# Atomic write: stage to a temp file then mv into place, so a partial
# write can't poison incremental builds.
TMP="$(mktemp "${OUT}.XXXXXX")"
trap 'rm -f "$TMP"' EXIT

cat > "$TMP" <<EOF
; =============================================================================
; build/p384_overlay_equates.inc - GENERATED FILE, DO NOT EDIT.
;
; Phase 5 Fix C: P-384 overlay-resident symbol addresses, extracted from
; build/labels-p384-{sha384,curve}.txt by
; tools/integration/gen_p384_overlay_equates.sh and included by
; src/crypto/ecdsa_verify_384.s.
;
; If the overlay images are rebuilt and the addresses move, this file
; regenerates and the dispatcher's .assert pins (compile-time sanity
; checks on slot residency / data-region offsets) will catch drift at
; build time rather than at runtime.
; =============================================================================

; --- SHA-384 overlay (banked into \$4200 by crypto_swap_to_p384_sha384) ---
sha384_init     = \$$SHA384_INIT
sha384_update   = \$$SHA384_UPDATE
sha384_final    = \$$SHA384_FINAL
; SHA-384 resident DATA (lives at \$C000+, survives curve-overlay swap-in
; because the dispatcher copies sha384_digest out before the swap):
sha384_digest   = \$$SHA384_DIGEST                ; 48 B BE digest output

; --- Curve / verify overlay (banked into \$4200 by crypto_swap_to_p384_curve) ---
ecdsa_verify_384 = \$$ECDSA_VERIFY_384
; Curve resident DATA:
ecdsa_inputs_384 = \$$ECDSA_INPUTS_384                ; 240 B BE struct r|s|h|Qx|Qy
EOF

mv "$TMP" "$OUT"
trap - EXIT

echo "generated $OUT"
echo "  sha384_init      = \$$SHA384_INIT"
echo "  sha384_update    = \$$SHA384_UPDATE"
echo "  sha384_final     = \$$SHA384_FINAL"
echo "  sha384_digest    = \$$SHA384_DIGEST"
echo "  ecdsa_verify_384 = \$$ECDSA_VERIFY_384"
echo "  ecdsa_inputs_384 = \$$ECDSA_INPUTS_384"
