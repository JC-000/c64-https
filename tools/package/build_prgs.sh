#!/usr/bin/env bash
# =============================================================================
# tools/package/build_prgs.sh - Build the release PRG matrix into dist/.
#
# Produces the shippable PRG variants and starts a fresh dist/MANIFEST.txt
# build log (git HEAD, per-variant result + PRG size). The D64 assembly step
# (build_d64.sh) appends to the same manifest and writes the final checksum
# section, so this script MUST run first.
#
# Variants:
#   1. c64-https-uci-reu.prg     — make BACKEND=uci                (default REU
#                                   profile, nistcurves v0.6.0)
#   2. c64-https-uci-onchip.prg  — make BACKEND=uci USE_NISTCURVES_ONCHIP=1
#                                   (no-REU on-chip verify path)
#   3. ip65/RR-Net               — make BACKEND=ip65. Expected to FAIL to link
#                                   at the current nistcurves pin
#                                   (CRYPTO_COLD_SHADOW overflow, tracked as
#                                   c64-nist-curves#54). The exact ld65 error
#                                   is captured to dist/ip65-link-error.txt and
#                                   summarized in the manifest. If it links
#                                   anyway, dist/c64-https-ip65-reu.prg is kept.
#
# A `make clean` runs between every flag combination: the build does NOT track
# CA65FLAGS changes, so stale .o files cause spurious unresolved externals.
#
# Usage:  tools/package/build_prgs.sh
# =============================================================================
set -eo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"

DIST="$PROJECT_ROOT/dist"
BUILT_PRG="$PROJECT_ROOT/build/c64-https.prg"
MANIFEST="$DIST/MANIFEST.txt"
IP65_ERR="$DIST/ip65-link-error.txt"

mkdir -p "$DIST"

GIT_HEAD="$(git rev-parse HEAD)"
GIT_HEAD_SHORT="$(git rev-parse --short HEAD)"

# Fresh manifest — this script owns the header + build-log section.
{
    echo "c64-https release manifest"
    echo "generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "git HEAD:  $GIT_HEAD"
    echo
    echo "== build variants =="
} > "$MANIFEST"

# build_variant <dist-basename> <make-args...>
# Runs `make clean && make <args>`, copies the resulting PRG to dist/ and
# records size + git sha in the manifest.
build_variant() {
    local out="$1"; shift
    echo "[package] make clean && make $*"
    make clean >/dev/null
    make "$@"
    if [ ! -f "$BUILT_PRG" ]; then
        echo "ERROR: expected $BUILT_PRG after 'make $*', not found" >&2
        exit 1
    fi
    cp "$BUILT_PRG" "$DIST/$out"
    local bytes
    bytes=$(wc -c < "$DIST/$out" | tr -d ' ')
    printf '%-28s %8s bytes   make %s   (HEAD %s)\n' \
        "$out" "$bytes" "$*" "$GIT_HEAD_SHORT" >> "$MANIFEST"
    echo "[package] wrote dist/$out ($bytes bytes)"
}

# --- Variant 1: UCI, default REU profile ---
build_variant "c64-https-uci-reu.prg" BACKEND=uci

# --- Variant 2: UCI, on-chip (no-REU) verify path ---
build_variant "c64-https-uci-onchip.prg" BACKEND=uci USE_NISTCURVES_ONCHIP=1

# --- Variant 3: ip65 / RR-Net (expected link failure at current pin) ---
echo "[package] make clean && make BACKEND=ip65 (expected to fail at current nistcurves pin)"
make clean >/dev/null
if make BACKEND=ip65 >"$IP65_ERR" 2>&1; then
    # Surprise: it linked. Keep the artifact.
    cp "$BUILT_PRG" "$DIST/c64-https-ip65-reu.prg"
    bytes=$(wc -c < "$DIST/c64-https-ip65-reu.prg" | tr -d ' ')
    printf '%-28s %8s bytes   make BACKEND=ip65   (HEAD %s)\n' \
        "c64-https-ip65-reu.prg" "$bytes" "$GIT_HEAD_SHORT" >> "$MANIFEST"
    echo "[package] ip65 UNEXPECTEDLY linked — wrote dist/c64-https-ip65-reu.prg ($bytes bytes)"
    { echo; echo "== ip65 result =="; echo "ip65 linked successfully (unexpected — see prior campaign notes)."; } >> "$MANIFEST"
else
    echo "[package] ip65 build failed as expected — error captured to dist/ip65-link-error.txt"
    {
        echo
        echo "== ip65 result =="
        echo "ip65 FAILED to link (expected; c64-nist-curves#54). Last lines of ld65 output:"
        echo "----------------------------------------------------------------"
        tail -n 12 "$IP65_ERR"
        echo "----------------------------------------------------------------"
        echo "(full output: dist/ip65-link-error.txt)"
    } >> "$MANIFEST"
fi

echo "[package] PRG matrix complete."
