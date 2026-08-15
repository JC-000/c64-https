#!/usr/bin/env bash
# =============================================================================
# tools/package/build_d64.sh — assemble the release 1541 disk images.
#
# Produces, from the PRGs build_prgs.sh left in dist/:
#
#   c64-https-<key>.d64        one per variant, one PRG each (4 images)
#   c64-https-<backend>.d64    one per backend, both of that backend's
#                              profiles on one disk (2 images)
#
# WHY NOT ONE DISK WITH ALL FOUR: it does not fit, and that is arithmetic, not
# preference. A .d64 holds 664 free blocks = 168,656 usable bytes; the four
# PRGs total ~220 KB (2 x 62,977 UCI + 2 x 47,105 ip65). Each backend's pair
# does fit (UCI ~496 blocks, ip65 ~371), so the per-backend disk is the largest
# useful bundle. The per-variant singles are the "I know what I want, give me
# one disk" case and are what the release notes point at.
#
# Every image is bootable with LOAD"*",8,1 (the wanted PRG is the first file on
# the single-variant disks). File names are shared between the single and the
# per-backend disk so a user only ever learns one name.
#
# Usage:  tools/package/build_d64.sh     [C1541=... to override the tool]
# =============================================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"
# shellcheck source=tools/package/_common.sh
. "$PROJECT_ROOT/tools/package/_common.sh"

C1541="${C1541:-c1541}"
D64_LIST="$DIST/d64-listings.txt"   # write_manifest.sh reads this

if ! command -v "$C1541" >/dev/null 2>&1; then
    echo "ERROR: c1541 not found in PATH (it ships with VICE). Set C1541=... to override." >&2
    exit 1
fi

# c1541 interleaves its own chatter with the directory: a harmless OPENCBM line
# when the real-drive backend is absent (i.e. always, on a dev box), plus
# attach/detach/recognised notices naming absolute host paths. Strip all of it
# so the recorded listing is the disk directory and nothing machine-specific —
# otherwise the manifest would differ between two builders' checkouts.
c1541_list() {
    "$C1541" -attach "$1" -list \
        | grep -Ev '^(OPENCBM:|D64 disk image |Unit [0-9]+ drive )'
}

: > "$D64_LIST"

# make_disk <image path> <disk label> <disk id> <host-prg> <1541-name> [...]
# Silently drops PRGs that are not present and makes no disk at all when none
# of its inputs exist. A missing PRG means its variant failed to build, which
# build_prgs.sh has already reported and recorded; erroring out a second time
# here would only stop the surviving variants from getting disks.
make_disk() {
    local image="$1" label="$2" id="$3"; shift 3
    local -a writes=()
    while [ "$#" -gt 0 ]; do
        if [ -f "$1" ]; then
            writes+=(-write "$1" "$2,p")
        else
            echo "[package] skipping $(basename "$1") on $(basename "$image") — not built"
        fi
        shift 2
    done
    if [ "${#writes[@]}" -eq 0 ]; then
        echo "[package] $(basename "$image"): no PRGs available, image not created"
        return 0
    fi
    rm -f "$image"
    "$C1541" -format "$label,$id" d64 "$image" >/dev/null
    "$C1541" -attach "$image" "${writes[@]}" >/dev/null
    local listing
    listing="$(c1541_list "$image")"
    echo "[package] $(basename "$image"):"
    printf '%s\n' "$listing" | sed 's/^/[package]   /'
    {
        echo "image=$(basename "$image")"
        printf '%s\n' "$listing"
        echo "---"
    } >> "$D64_LIST"
}

# --- One image per variant ----------------------------------------------------
rm -f "$DIST"/c64-https-*.d64      # stale images from a previous, fuller run

for line in "${PACKAGE_VARIANTS[@]}"; do
    key="$(variant_field "$line" 1)"
    prg="$(variant_field "$line" 2)"
    name="$(variant_field "$line" 4)"
    # Disk label is the variant key: <=16 PETSCII chars, and it makes the
    # directory header self-identifying when four near-identical disks are
    # sitting in a downloads folder.
    make_disk "$DIST/c64-https-$key.d64" "$key" "01" "$DIST/$prg" "$name"
done

# --- No per-backend combo images ------------------------------------------
# Retired deliberately. Their premise was "a user only ever learns one
# name", and that breaks the moment a backend carries three variants: the
# UCI set is 3 x 248 = 744 blocks against a .d64's 664, so a combo image
# could not hold the lineup even if we wanted one. Rather than ship a disk
# that silently omits a variant, every image now carries exactly the one
# product named on its label, so what a consumer downloads is what they
# get. See PACKAGE_VARIANTS in _common.sh for the three products.

echo "[package] disk images complete."
