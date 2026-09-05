#!/usr/bin/env bash
# =============================================================================
# tools/package/build_d64.sh — assemble the release 1541 disk images.
#
# Produces, from the PRGs build_prgs.sh left in dist/:
#
#   c64-https-<key>.d64        one per variant, one PRG each, one image per
#                              product in PACKAGE_VARIANTS (_common.sh is the
#                              matrix -- do not restate the count here).
#
# WHY NO COMBO DISKS: they existed and were retired. The reasoning is at the
# "No per-backend combo images" block near the bottom of this file, where the
# code that does not emit them lives; it is not repeated here.
#
# What is worth stating up here is which reason applies TODAY, because the
# arithmetic that triggered the retirement no longer reaches: it was 3 x 248
# blocks against a .d64's 664, WHEN the UCI lineup carried three variants.
# PACKAGE_VARIANTS carries two UCI products now, 2 x 248 = 496, which fits.
# So a per-backend UCI disk is possible and is omitted by CURATION, not by
# capacity: one product per disk means the label is the whole contents, and
# no image can silently omit a variant. (An all-three disk still does not
# fit -- 248 + 248 + 186 = 682 against 664 -- but that was never the disk
# anyone proposed.)
#
# Every image is bootable with LOAD"*",8,1 -- there is only one PRG on each,
# so the label is the whole contents.
#
# THE RULE THAT KEEPS THIS FILE HONEST, since six sites in this tree broke it
# in one session: DELEGATE A SINGLE-OWNER FACT RATHER THAN RESTATING IT, and
# where it must be restated -- history, incident records -- PUT IT IN THE PAST
# TENSE AND NAME THE CONDITION THAT MADE IT TRUE.
#
# Stated that way because the tempting shorter version ("restated numbers go
# stale, delegated ones do not") is false, and this tree falsifies it twice
# over. _common.sh:18 and verify_release.py:135 both RESTATE 3 x 248 = 744
# and are both still accurate -- they say the lineup REACHED three variants,
# so the sentence stays true after the lineup moved. Meanwhile the four sites
# that started this whole sweep (write_manifest.sh, build_prgs.sh's TRAP 1,
# test_build_flags_stamp.py, test_tls_deframer.py) went stale restating a
# RATIONALE with no number in them at all. Tense is what saved the survivors;
# single ownership, not arithmetic, is what sank the casualties.
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
    # directory header self-identifying when several near-identical disks are
    # sitting in a downloads folder. (No count here on purpose -- it is
    # len(PACKAGE_VARIANTS). Four copies of the word "four" went stale in
    # this tree by spelling it out; see the header for the rule that
    # actually covers them.)
    make_disk "$DIST/c64-https-$key.d64" "$key" "01" "$DIST/$prg" "$name"
done

# --- No per-backend combo images ------------------------------------------
# Retired deliberately. Their premise was "a user only ever learns one
# name", and that broke WHEN the UCI lineup reached three variants: 3 x 248
# = 744 blocks against a .d64's 664, so the combo image could not hold the
# lineup it was named after. Past tense on purpose -- the lineup is two UCI
# products today (2 x 248 = 496, which fits), so that arithmetic is the
# HISTORY of the decision and no longer its justification.
#
# What keeps them retired is curation: one product per disk means the label
# is the whole contents, so no image can silently omit a variant and what a
# consumer downloads is what boots. That reason does not depend on how many
# variants there happen to be, which is why it is the one stated. See
# PACKAGE_VARIANTS in _common.sh for the products themselves.

echo "[package] disk images complete."
