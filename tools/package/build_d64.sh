#!/usr/bin/env bash
# =============================================================================
# tools/package/build_d64.sh - Assemble dist/c64-https.d64 and finalize the
# release manifest.
#
# Bundles both UCI PRGs (produced by build_prgs.sh) onto a single 1541 disk
# image via VICE's `c1541`, verifies the directory reads back, then appends the
# D64 section and the final sha256 checksum section to dist/MANIFEST.txt. This
# script runs LAST in the package flow so its checksum section covers every
# artifact in dist/ (PRGs, the D64, and the optional listener zip).
#
# Disk filenames are <=16 char PETSCII:
#   HTTPS-REU   <- c64-https-uci-reu.prg    (default REU verify profile)
#   HTTPS-NOREU <- c64-https-uci-onchip.prg (on-chip / no-REU verify path)
#
# Usage:  tools/package/build_d64.sh
# =============================================================================
set -eo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"

DIST="$PROJECT_ROOT/dist"
MANIFEST="$DIST/MANIFEST.txt"
D64="$DIST/c64-https.d64"
C1541="${C1541:-c1541}"

REU_PRG="$DIST/c64-https-uci-reu.prg"
ONCHIP_PRG="$DIST/c64-https-uci-onchip.prg"

if ! command -v "$C1541" >/dev/null 2>&1; then
    echo "ERROR: c1541 not found in PATH (ships with VICE). Set C1541=... to override." >&2
    exit 1
fi
for f in "$REU_PRG" "$ONCHIP_PRG"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: missing $f — run tools/package/build_prgs.sh first." >&2
        exit 1
    fi
done
if [ ! -f "$MANIFEST" ]; then
    echo "ERROR: missing $MANIFEST — run tools/package/build_prgs.sh first." >&2
    exit 1
fi

# --- Assemble the disk image ---
# c1541 -write takes a host path + a target 1541 filename; PRGs are written as
# PRG-type files. -format wipes/labels the image first.
rm -f "$D64"
echo "[package] formatting $D64"
"$C1541" -format "c64-https,01" d64 "$D64" >/dev/null
echo "[package] writing PRGs to disk image"
"$C1541" -attach "$D64" \
    -write "$REU_PRG"    "https-reu,p" \
    -write "$ONCHIP_PRG" "https-noreu,p" >/dev/null

# --- Read back the directory to verify ---
# c1541 prints a harmless "OPENCBM: ... libopencbm.dylib failed!" line when the
# real-drive backend is absent (always, on a dev box); drop it so the recorded
# listing is just the disk directory.
echo "[package] directory listing:"
LISTING="$("$C1541" -attach "$D64" -list | grep -v '^OPENCBM:')"
echo "$LISTING"

# --- Append D64 section to the manifest ---
{
    echo
    echo "== d64 image =="
    echo "c64-https.d64 (1541 image, both UCI PRGs)"
    echo "directory listing:"
    echo "----------------------------------------------------------------"
    echo "$LISTING"
    echo "----------------------------------------------------------------"
} >> "$MANIFEST"

# --- Final section: sha256 of every artifact in dist/ (except the manifest) ---
{
    echo
    echo "== sha256 checksums =="
} >> "$MANIFEST"

# Prefer sha256sum; fall back to `shasum -a 256` on macOS.
if command -v sha256sum >/dev/null 2>&1; then
    SHA_CMD=(sha256sum)
else
    SHA_CMD=(shasum -a 256)
fi

# Stable, sorted list of artifacts, manifest excluded so the checksum section
# never has to hash the file it is being written into. BSD find (macOS) lacks
# -printf, so strip the leading ./ with sed.
( cd "$DIST" && find . -maxdepth 1 -type f ! -name 'MANIFEST.txt' | sed 's|^\./||' | sort ) \
| while IFS= read -r f; do
    ( cd "$DIST" && "${SHA_CMD[@]}" "$f" ) >> "$MANIFEST"
done

echo "[package] wrote $D64 and finalized $MANIFEST"
