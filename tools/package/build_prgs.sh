#!/usr/bin/env bash
# =============================================================================
# tools/package/build_prgs.sh — build the release PRG matrix into dist/.
#
# Three variants, one per shipped product (PACKAGE_VARIANTS in _common.sh):
#
#   c64-https-ip65-onchip.prg  make BACKEND=ip65 USE_NISTCURVES_ONCHIP=1
#   c64-https-uci-onchip.prg   make BACKEND=uci  USE_NISTCURVES_ONCHIP=1
#   c64-https-uci-comb.prg     make BACKEND=uci  USE_NISTCURVES_ONCHIP_COMB=1
#
# The matrix itself lives in _common.sh; this script has no per-variant
# knowledge and nothing version-specific, so it survives a library bump with
# zero edits.
#
# TWO TRAPS this script exists to avoid, both observed in this repo:
#
#   1. `make clean` runs before EVERY variant, and it is load-bearing — but
#      for a different reason than it used to be.
#
#      It used to be about the flags. `BACKEND=` is not a -D flag, it selects
#      an include path, and make's dependency graph had no way to see it:
#      skipping the clean yielded either a mixed binary at exactly the right
#      size, or (macOS GNU Make 3.81, 1-second mtime resolution) no relink at
#      all, leaving the *other* variant's PRG in place. Exit 0 either way.
#      Issue #159 closed that in the Makefile: `build/flags.stamp` holds the
#      fully expanded ca65/ld65 command lines, is content-compared at Makefile
#      *parse* time, and on any change deletes every object and the PRG before
#      make builds its file database. (`build/labels.txt`, `.map` and `.dbg`
#      survive that rm; harmless here, since every variant starts clean.)
#
#      What the stamp does NOT reach is `build/lib/*.a`. Its invalidation is
#      exactly `rm -f $(ALL_OBJS) $(PRG)`, and ALL_OBJS is the four .o lists;
#      the sibling-archive rules have no prerequisites at all — nothing under
#      libs/ is a prerequisite of any archive rule — so an archive that
#      already exists is up to date by definition, whatever the submodule pin
#      now says. SIBLING_LIB_ARCHIVES is stamped, but that is the archive
#      *filename* list: it is keyed on the profile flags, and reads no
#      submodule state at all. Which cuts both ways, and the safe half is
#      worth stating: a PROFILE change needs no clean, because it names a
#      different archive and one that is not there gets built. A PIN change
#      does — the filename does not move, so the archive from the old
#      checkout stays, and `make clean` (rm -rf build) is the only thing that
#      rebuilds it.
#
#      That is what makes the submodule pins this script writes into
#      dist/build-info.txt, and write_manifest.sh prints in dist/MANIFEST.txt,
#      an attestation rather than a guess. Without the clean, an archive built
#      from a previous libs/nistcurves checkout links into the release PRG
#      while the manifest reports the current pin, at exit 0. #124's staleness
#      probe does not catch it: the probe lives inside
#      build_nistcurves_p256.sh, which is not run when the .a is already
#      there. `CA65=` has the same shape — it is stamped, so the objects go,
#      but the wrapper is not re-invoked.
#   2. Every build is checked by PRG sha256, recorded in dist/build-info.txt.
#      Object hashes are worthless as evidence — ca65 stamps wall-clock time
#      into every .o header — but ld65 does not propagate it, so the PRG is
#      deterministic and comparable.
#
# Also bootstraps the ip65 blob (`ip65-build/ip65-c64.bin`), which is a
# gitignored artifact a plain `make` will NOT build: a fresh clone dies in the
# ca65 `.incbin` before any link.
#
# Writes dist/build-info.txt (git HEAD, submodule pins, per-variant args/size/
# sha256). write_manifest.sh consumes it.
#
# Usage:  tools/package/build_prgs.sh
# =============================================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"
# shellcheck source=tools/package/_common.sh
. "$PROJECT_ROOT/tools/package/_common.sh"

mkdir -p "$DIST"

# Clear stale PRGs from a previous, differently-shaped run — the same reason
# build_d64.sh clears stale .d64s. Without this, RETIRING a variant leaves its
# PRG behind and write_manifest.sh hashes every artifact present in dist/, so
# the dropped variant reappears in the checksum list with no disk, no
# description and no verification behind it. Observed for real when the
# lineup went from four variants to three: c64-https-{ip65,uci}-reu.prg
# survived into MANIFEST.txt as though they had shipped.
#
# Scoped to our own PRGs on purpose: dist/ also holds the generated listener,
# and a blanket wipe would delete work this script cannot rebuild.
rm -f "$DIST"/c64-https-*.prg

GIT_HEAD="$(git rev-parse HEAD)"
GIT_HEAD_SHORT="$(git rev-parse --short HEAD)"
GIT_DIRTY=""
git diff --quiet HEAD -- 2>/dev/null || GIT_DIRTY=" (working tree DIRTY)"

# --- ip65 blob bootstrap ------------------------------------------------------
IP65_BIN="$PROJECT_ROOT/ip65-build/ip65-c64.bin"
if [ ! -f "$IP65_BIN" ]; then
    echo "[package] ip65 blob absent — bootstrapping (make ip65-libs && make ip65-blob)"
    if [ ! -e "$PROJECT_ROOT/ip65/Makefile" ]; then
        echo "ERROR: ip65 submodule not checked out. Run:" >&2
        echo "         git submodule update --init --recursive" >&2
        exit 1
    fi
    make ip65-libs >/dev/null
    make ip65-blob >/dev/null
    echo "[package] ip65 blob built: $(wc -c < "$IP65_BIN" | tr -d ' ') bytes, $(sha256_of "$IP65_BIN")"
fi

# --- Fresh build-info ---------------------------------------------------------
{
    echo "# c64-https release build info"
    echo "# generated by tools/package/build_prgs.sh"
    echo "generated=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "git_head=$GIT_HEAD"
    echo "git_head_short=$GIT_HEAD_SHORT"
    echo "git_dirty=$([ -n "$GIT_DIRTY" ] && echo yes || echo no)"
    echo "ip65_blob_sha256=$(sha256_of "$IP65_BIN")"
    echo "ip65_blob_bytes=$(wc -c < "$IP65_BIN" | tr -d ' ')"
    submodule_pins | while read -r sub sha tag; do
        echo "submodule=$sub $sha $tag"
    done
} > "$BUILD_INFO"

# --- Build every variant ------------------------------------------------------
echo "[package] HEAD $GIT_HEAD_SHORT$GIT_DIRTY"
failed=0
for line in "${PACKAGE_VARIANTS[@]}"; do
    key="$(variant_field "$line" 1)"
    prg="$(variant_field "$line" 2)"
    args="$(variant_field "$line" 3)"

    echo "[package] === $key ==="
    echo "[package] make clean && make $args"
    make clean >/dev/null
    log="$DIST/build-$key.log"
    # Word-splitting $args is intentional — it is a make argument list.
    # shellcheck disable=SC2086
    if ! make $args >"$log" 2>&1; then
        echo "[package] BUILD FAILED for $key — see $log" >&2
        tail -n 15 "$log" >&2
        # Pull the first ca65/ld65 diagnostic out of the log so the manifest
        # can state WHY a variant is missing without anyone opening the log.
        # Falls back to the last line for failures that are not toolchain
        # diagnostics (a missing submodule, a full disk).
        reason="$(grep -m1 -E '^(ld65|ca65|ar65|od65):|Error:' "$log" || true)"
        [ -n "$reason" ] || reason="$(tail -n1 "$log")"
        {
            echo "variant=$key prg=$prg args=$args result=FAILED log=$(basename "$log")"
            echo "failreason=$key $reason"
        } >> "$BUILD_INFO"
        failed=$((failed + 1))
        continue
    fi
    if [ ! -f "$BUILT_PRG" ]; then
        echo "[package] ERROR: make $args exited 0 but $BUILT_PRG is missing" >&2
        {
            echo "variant=$key prg=$prg args=$args result=FAILED log=(none)"
            echo "failreason=$key make exited 0 but produced no PRG"
        } >> "$BUILD_INFO"
        failed=$((failed + 1))
        continue
    fi
    cp "$BUILT_PRG" "$DIST/$prg"
    rm -f "$log"
    bytes="$(wc -c < "$DIST/$prg" | tr -d ' ')"
    sha="$(sha256_of "$DIST/$prg")"
    # backend= lets verify_release.py derive which disk images MUST exist
    # without re-parsing this matrix, keeping _common.sh the only place a
    # variant is declared.
    echo "variant=$key prg=$prg args=$args result=OK bytes=$bytes sha256=$sha backend=$(variant_field "$line" 5)" \
        >> "$BUILD_INFO"
    printf '[package] wrote dist/%s  %s bytes  %s\n' "$prg" "$bytes" "$sha"
done

# Exit status is three-valued on purpose, and the Makefile depends on it:
#
#   0  every variant built
#   2  PARTIAL — some built, some did not
#   1  nothing built at all
#
# A hard `exit 1` on the first failure used to abort `make package` before the
# disk images, the listener and the manifest were ever produced, which meant a
# single broken variant left the operator with no artifacts AND no written
# record of what broke. Partial is the common case during a library bump (one
# profile's archive trips a link assert while the other is fine), and the
# useful outcome there is "here are the three that work, here is the error for
# the fourth" — the release still cannot be cut, but the blocker is legible
# and the good artifacts are testable. The non-zero status is what stops
# anyone mistaking a partial run for a complete one.
built=$(( ${#PACKAGE_VARIANTS[@]} - failed ))
if [ "$failed" -ne 0 ]; then
    echo "[package] PRG matrix INCOMPLETE — $built/${#PACKAGE_VARIANTS[@]} variants built," \
         "$failed FAILED (see dist/build-*.log and the manifest)." >&2
    [ "$built" -gt 0 ] && exit 2
    exit 1
fi
echo "[package] PRG matrix complete (${#PACKAGE_VARIANTS[@]} variants)."
