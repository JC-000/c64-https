#!/usr/bin/env bash
# =============================================================================
# tools/package/write_manifest.sh — compose dist/MANIFEST.txt.
#
# Runs LAST. Reads dist/build-info.txt (from build_prgs.sh) and
# dist/d64-listings.txt (from build_d64.sh), then hashes every artifact
# actually present in dist/. Nothing here is version-specific: sizes, hashes,
# git HEAD and submodule pins are all read at run time, and the variant
# guidance comes from the matrix in _common.sh.
#
# Usage:  tools/package/write_manifest.sh
# =============================================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"
# shellcheck source=tools/package/_common.sh
. "$PROJECT_ROOT/tools/package/_common.sh"

D64_LIST="$DIST/d64-listings.txt"

[ -f "$BUILD_INFO" ] || { echo "ERROR: missing $BUILD_INFO — run build_prgs.sh first." >&2; exit 1; }

info() { grep "^$1=" "$BUILD_INFO" | head -1 | cut -d= -f2-; }

{
echo "=============================================================================="
echo " c64-https — prebuilt release artifacts"
echo "=============================================================================="
echo
echo "TLS 1.3 / HTTPS client for the Commodore 64. Everything here is prebuilt:"
echo "you need no assembler, no cc65, no Python packages and no build step."
echo
echo "generated : $(info generated)"
echo "git HEAD  : $(info git_head)"
if [ "$(info git_dirty)" = "yes" ]; then
echo "            WARNING: built from a DIRTY working tree, not a clean checkout"
fi
echo "ip65 blob : $(info ip65_blob_bytes) bytes, sha256 $(info ip65_blob_sha256)"
echo
# A partial release must announce itself at the top, not bury the gap in a
# checksum list that simply has fewer lines than it should. Anyone diffing two
# manifests would otherwise have to notice an absence.
if grep -q '^failreason=' "$BUILD_INFO"; then
echo "!! INCOMPLETE RELEASE — some variants did not build !!"
echo
echo "   The artifacts below are real and usable, but this is NOT the full"
echo "   matrix and must not be tagged as one. Missing:"
echo
grep '^failreason=' "$BUILD_INFO" | cut -d= -f2- | while read -r key reason; do
    prg=""
    for line in "${PACKAGE_VARIANTS[@]}"; do
        [ "$(variant_field "$line" 1)" = "$key" ] || continue
        prg="$(variant_field "$line" 2)"
        echo "     $prg"
        echo "       make $(variant_field "$line" 3)"
    done
    [ -n "$prg" ] || echo "     $key"
    echo "       $reason"
    echo
done
echo "------------------------------------------------------------------------------"
echo
fi
echo "submodule pins:"
grep '^submodule=' "$BUILD_INFO" | cut -d= -f2- | while read -r sub sha tag; do
    printf '  %-18s %s  %s\n' "$sub" "$tag" "$sha"
done
echo
echo "------------------------------------------------------------------------------"
echo " WHICH ONE DO I WANT?"
echo "------------------------------------------------------------------------------"
echo
echo "Three things decide it."
echo
echo "1. How is your C64 on the network?"
echo "     Ultimate 64 / Ultimate 64 Elite / C64 Ultimate  ->  the 'uci' images"
echo "     a stock C64 with an RR-Net / cs8900a cartridge  ->  the 'ip65' images"
echo
echo "2. Which of the three do I want?"
echo "     Three products, one disk each. The disk carries exactly what its"
echo "     label says — there are no combined images to pick through."
echo
echo "     ip65-onchip   a completely unmodified C64 + RR-Net cartridge."
echo "                   No REU, no turbo, no options. If you are not sure"
echo "                   what you have, this is the one that will run."
echo "                   ~36 min per handshake at 1 MHz."
echo
echo "     uci-onchip    Ultimate 64 / C64 Ultimate at turbo, REU off."
echo "                   Boots straight to the menu."
echo
echo "     uci-comb      Ultimate 64 / C64 Ultimate at turbo, REU ON."
echo "                   The fastest image: ~1.7x quicker verify than"
echo "                   uci-onchip. It builds a 16 KB table into REU"
echo "                   bank 2 at every boot before the menu appears —"
echo "                   ~34 s at 64 MHz, ~45 s at 48 MHz. That is the"
echo "                   program working, not a hang."
echo
echo "   Why the split: below about 5 MHz the extra table work costs more"
echo "   than it saves, and below ~18 MHz the plain REU multiply path wins"
echo "   outright — so the comb image is a turbo product and the compat"
echo "   image is a stock-clock one. Both crossovers are measured, not"
echo "   estimated; see the wall-clock sections of CLAUDE.md."
echo
echo "3. The screen goes blank during the slow parts. That is deliberate."
echo "     Every image blanks the VIC-II across the two X25519 scalar"
echo "     multiplies and the ECDSA verify, which stops the video chip"
echo "     stealing bus cycles and buys about 6.5%. Measured, not guessed:"
echo "     6.35% in VICE at 1 MHz, 6.78% (on-chip) and 6.60% (REU) on a"
echo "     U64E at 48 MHz."
echo "     The screen comes back between handshake phases, so the progress"
echo "     line keeps updating — if it is blank for minutes at a time, that"
echo "     is the crypto running, not a hang."
echo
for line in "${PACKAGE_VARIANTS[@]}"; do
    key="$(variant_field "$line" 1)"
    prg="$(variant_field "$line" 2)"
    note="$(variant_field "$line" 6)"
    if grep -q "^failreason=$key " "$BUILD_INFO"; then
        echo "  $prg  — NOT IN THIS RELEASE (failed to build)"
        echo "      $note"
        echo
        continue
    fi
    echo "  $prg"
    echo "      $note"
    echo "      disk: c64-https-$key.d64"
    echo
done
echo "------------------------------------------------------------------------------"
echo " PRG VARIANTS"
echo "------------------------------------------------------------------------------"
echo
printf '  %-28s %8s  %s\n' "file" "bytes" "built with"
grep '^variant=' "$BUILD_INFO" | while read -r rec; do
    # shellcheck disable=SC2086
    set -- $rec
    prg=""; bytes=""; args=""
    for kv in "$@"; do
        case "$kv" in
            prg=*)   prg="${kv#prg=}" ;;
            bytes=*) bytes="${kv#bytes=}" ;;
        esac
    done
    args="$(printf '%s' "$rec" | sed -n 's/.*args=\(.*\) result=.*/\1/p')"
    case "$rec" in
        *" result=FAILED"*) bytes="FAILED" ;;
    esac
    printf '  %-28s %8s  make %s\n' "$prg" "$bytes" "$args"
done
echo
echo "  Every variant is built after a 'make clean' — BACKEND= selects an include"
echo "  path that make's dependency graph cannot see, so an incremental build can"
echo "  silently produce a mixed image at exactly the right size."
echo
echo "------------------------------------------------------------------------------"
echo " DISK IMAGES (.d64)"
echo "------------------------------------------------------------------------------"
echo
echo "  One product per disk, one PRG per disk. Load with:"
echo
echo "      LOAD\"*\",8,1"
echo "      RUN"
echo
echo "  There are deliberately no combined images. A .d64 has 664 free blocks and"
echo "  each UCI PRG is 248, so the three-product lineup (744 blocks) cannot fit on"
echo "  one disk and a per-backend image would have had to silently omit a product."
echo "  Shipping one variant per disk means the label is the whole contents: what"
echo "  you downloaded is what boots."
echo
if [ -f "$D64_LIST" ]; then
    while IFS= read -r ln; do
        case "$ln" in
            image=*) echo "  ${ln#image=}" ;;
            ---)     echo ;;
            *)       echo "      $ln" ;;
        esac
    done < "$D64_LIST"
fi
echo "------------------------------------------------------------------------------"
echo " TEST LISTENER — c64-https-listener.py"
echo "------------------------------------------------------------------------------"
echo
echo "  A single self-extracting Python file that stands up the whole server side"
echo "  of the end-to-end test: it mints a fresh self-signed ECDSA P-256"
echo "  certificate, serves TLS 1.3 only, and returns the canonical response the"
echo "  C64 client expects."
echo
echo "      python3 c64-https-listener.py --port 4433     # serve"
echo "      python3 c64-https-listener.py --selftest      # prove it works, no C64"
echo "      python3 c64-https-listener.py --extract ./src # unpack its sources"
echo
echo "  DEPENDENCIES: none. Nothing to pip install, no venv, no network access."
echo "  Certificate generation is pure Python (P-256 + DER + ECDSA-SHA256); TLS"
echo "  is the standard library's ssl module."
echo
echo "  LIMITATION, stated here so you do not discover it by running it: the"
echo "  listener needs an interpreter whose ssl module supports TLS 1.3, i.e. one"
echo "  linked against OpenSSL 1.1.1 or newer. macOS's /usr/bin/python3 is linked"
echo "  against LibreSSL 2.8.3, has no TLS 1.3, and cannot serve this client at"
echo "  any price — install python3 from python.org or Homebrew there. The"
echo "  listener detects this at startup and says so in one line. Most Linux"
echo "  distributions ship a suitable python3."
echo
echo "  The certificate it generates is a throwaway test fixture and not a trust"
echo "  anchor. Do not deploy it anywhere real."
echo
echo "------------------------------------------------------------------------------"
echo " SHA256 CHECKSUMS"
echo "------------------------------------------------------------------------------"
echo
} > "$MANIFEST"

# Hash every artifact in dist/, excluding the manifest itself and the two
# intermediate files the packaging scripts pass between each other.
( cd "$DIST" && find . -maxdepth 1 -type f \
    ! -name 'MANIFEST.txt' ! -name 'build-info.txt' ! -name 'd64-listings.txt' \
    ! -name '*.log' \
    | sed 's|^\./||' | sort ) \
| while IFS= read -r f; do
    printf '  %s  %s\n' "$(sha256_of "$DIST/$f")" "$f" >> "$MANIFEST"
done

echo "[package] wrote $MANIFEST"
