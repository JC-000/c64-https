#!/usr/bin/env bash
# =============================================================================
# tools/package/_common.sh — shared definitions for the release packaging
# scripts. Sourced, never executed.
#
# The single source of truth for the release variant matrix lives here so that
# build_prgs.sh, build_d64.sh and write_manifest.sh cannot drift apart.
# =============================================================================

# --- Variant matrix -----------------------------------------------------------
# One line per shipped PRG:
#   <key>|<prg basename>|<make args>|<1541 filename>|<backend>|<one-line guidance>
#
# 1541 filenames are <=16 chars and lowercase here because c1541 uppercases
# into PETSCII on write. They are the same on the single-variant disk and on
# the per-backend disk, so a user only ever learns one name. Keep them stable
# across releases — people type them.
#
# Nothing here is version-specific: adding a profile or a backend is one line,
# and every downstream script picks it up with no further edits.
PACKAGE_VARIANTS=(
  "uci-reu|c64-https-uci-reu.prg|BACKEND=uci|uci-reu|uci|Ultimate 64 / C64 Ultimate (UCI networking). Needs the REU enabled. Faster below ~18 MHz — the right pick at stock 1 MHz."
  "uci-onchip|c64-https-uci-onchip.prg|BACKEND=uci USE_NISTCURVES_ONCHIP=1|uci-noreu|uci|Ultimate 64 / C64 Ultimate (UCI networking). No REU required. Faster above ~18 MHz — the right pick at 32/48/64 MHz turbo."
  "ip65-reu|c64-https-ip65-reu.prg|BACKEND=ip65|ip65-reu|ip65|Stock C64 + RR-Net / cs8900a cartridge. Needs an REU. Faster below ~18 MHz, i.e. at any speed a real stock C64 runs at."
  "ip65-onchip|c64-https-ip65-onchip.prg|BACKEND=ip65 USE_NISTCURVES_ONCHIP=1|ip65-noreu|ip65|Stock C64 + RR-Net / cs8900a cartridge, no REU at all. The only image a bone-stock C64 can run end to end; slowest (~36 min per handshake at 1 MHz)."
)

# Backends, in matrix order, deduplicated. Used for the per-backend disks.
package_backends() {
    local line
    for line in "${PACKAGE_VARIANTS[@]}"; do
        printf '%s\n' "$(variant_field "$line" 5)"
    done | awk 'NF && !seen[$0]++'
}

# Field accessors — `variant_field <line> <1-based index>`.
variant_field() { printf '%s' "$1" | cut -d'|' -f"$2"; }

# --- Paths --------------------------------------------------------------------
# PROJECT_ROOT must be set by the caller before sourcing (it knows its own $0).
: "${PROJECT_ROOT:?_common.sh: PROJECT_ROOT must be set before sourcing}"

DIST="$PROJECT_ROOT/dist"
BUILT_PRG="$PROJECT_ROOT/build/c64-https.prg"
BUILD_INFO="$DIST/build-info.txt"     # machine-readable; write_manifest.sh reads it
MANIFEST="$DIST/MANIFEST.txt"

# --- sha256, portably ---------------------------------------------------------
if command -v sha256sum >/dev/null 2>&1; then
    sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
else
    sha256_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi

# --- Submodule pins (offline) -------------------------------------------------
# Deliberately NOT `git submodule status`: it renders versions via `git
# describe` *without* `--tags`, so a lightweight tag (c64-x25519 v0.6.0 is one)
# is invisible and the pin reads as "5 commits past v0.5.0". Read the gitlink
# from the tree and resolve the tag inside the submodule with --tags.
# Prints "<path> <sha> <tag-or-(untagged)>" per submodule.
submodule_pins() {
    git -C "$PROJECT_ROOT" config --file .gitmodules \
        --get-regexp '^submodule\..*\.path$' 2>/dev/null \
    | awk '{print $2}' | sort | while read -r sub; do
        local sha tag
        sha="$(git -C "$PROJECT_ROOT" ls-tree HEAD "$sub" | awk '{print $3}')"
        [ -n "$sha" ] || continue
        tag="$(git -C "$PROJECT_ROOT/$sub" describe --tags --exact-match "$sha" \
               2>/dev/null || true)"
        [ -n "$tag" ] || tag="(untagged)"
        printf '%s %s %s\n' "$sub" "$sha" "$tag"
    done
}
