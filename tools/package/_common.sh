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
# into PETSCII on write. Keep them stable across releases — people type them.
#
# The <backend> field no longer selects a disk: per-backend combo images were
# retired when the UCI lineup reached three variants (3 x 248 blocks against a
# .d64's 664). It is retained because build_prgs.sh records it in build-info
# and verify_release.py tolerates its absence in old records.
#
# Nothing here is version-specific: adding a profile or a backend is one line,
# and every downstream script picks it up with no further edits.
PACKAGE_VARIANTS=(
  "ip65-onchip|c64-https-ip65-onchip.prg|BACKEND=ip65 USE_NISTCURVES_ONCHIP=1|ip65-noreu|ip65|MAXIMUM COMPATIBILITY. Bone-stock C64 + RR-Net / cs8900a cartridge. No REU, no turbo, nothing optional at all — the only image a completely unmodified machine can run end to end. Slowest: ~36 min per handshake at 1 MHz."
  "uci-onchip|c64-https-uci-onchip.prg|BACKEND=uci USE_NISTCURVES_ONCHIP=1|uci-noreu|uci|TURBO, NO REU. Ultimate 64 / C64 Ultimate at 32/48/64 MHz with the REU disabled or absent. Boots straight to the menu."
  "uci-comb|c64-https-uci-comb.prg|BACKEND=uci USE_NISTCURVES_ONCHIP_COMB=1|uci-comb|uci|TURBO + REU — FASTEST. Ultimate 64 / C64 Ultimate at 32/48/64 MHz with the REU enabled. ~1.7x faster verify than the no-REU turbo image (measured: 16.4 s vs 28.4 s on a U64E at 48 MHz). Costs a one-time table build at every boot: ~34 s at 64 MHz, ~45 s at 48 MHz. Needs REU bank 2."
)

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
        local head_sha built_sha tag
        # The COMMITTED gitlink...
        head_sha="$(git -C "$PROJECT_ROOT" ls-tree HEAD "$sub" | awk '{print $3}')"
        # ...and what is actually CHECKED OUT, which is what the PRGs were
        # built against. These differ whenever a submodule bump has not been
        # committed yet, and reporting the gitlink in that state puts a wrong
        # library version in a release manifest with no warning — observed for
        # real: a build against nistcurves v0.11.0 / x25519 v0.11.1 produced a
        # MANIFEST claiming v0.10.1 / v0.11.0.
        built_sha="$(git -C "$PROJECT_ROOT/$sub" rev-parse HEAD 2>/dev/null || true)"
        [ -n "$built_sha" ] || built_sha="$head_sha"
        [ -n "$built_sha" ] || continue
        # --tags matters: c64-x25519 has tagged releases lightweight, and
        # `describe` without it considers annotated tags only.
        tag="$(git -C "$PROJECT_ROOT/$sub" describe --tags --exact-match "$built_sha" \
               2>/dev/null || true)"
        [ -n "$tag" ] || tag="(untagged)"
        # Say so loudly rather than quietly reporting the built sha: a release
        # whose submodules are not committed cannot be rebuilt from HEAD.
        if [ -n "$head_sha" ] && [ "$built_sha" != "$head_sha" ]; then
            tag="$tag !! UNCOMMITTED BUMP — HEAD gitlink is ${head_sha%"${head_sha#????????????}"}"
        fi
        printf '%s %s %s\n' "$sub" "$built_sha" "$tag"
    done
}
