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
echo "submodule pins:"
grep '^submodule=' "$BUILD_INFO" | cut -d= -f2- | while read -r sub sha tag; do
    printf '  %-18s %s  %s\n' "$sub" "$tag" "$sha"
done
echo
echo "------------------------------------------------------------------------------"
echo " WHICH ONE DO I WANT?"
echo "------------------------------------------------------------------------------"
echo
echo "Two questions decide it."
echo
echo "1. How is your C64 on the network?"
echo "     Ultimate 64 / Ultimate 64 Elite / C64 Ultimate  ->  the 'uci' images"
echo "     a stock C64 with an RR-Net / cs8900a cartridge  ->  the 'ip65' images"
echo
echo "2. Do you have a RAM Expansion Unit (REU), and how fast is the CPU?"
echo "     'reu' images use the REU to accelerate the ECDSA verify. They need"
echo "     one, and they are FASTER below about 18 MHz — which includes every"
echo "     real stock C64 at 1 MHz."
echo "     'onchip' images need NO REU at all and do the same work on the CPU."
echo "     They are FASTER above about 18 MHz, so they are the right pick for"
echo "     Ultimate turbo modes (32/48/64 MHz)."
echo "   The ~18 MHz crossover is measured, not estimated: the REU's DMA rate is"
echo "   anchored to the ~1 MHz bus, so the REU profile carries a wall-clock"
echo "   floor no amount of turbo removes, while the on-chip profile scales with"
echo "   the clock. On a U64E the sign flips between the 16 and 20 MHz settings."
echo
for line in "${PACKAGE_VARIANTS[@]}"; do
    key="$(variant_field "$line" 1)"
    prg="$(variant_field "$line" 2)"
    note="$(variant_field "$line" 6)"
    echo "  $prg"
    echo "      $note"
    echo "      disk: c64-https-$key.d64   (also on c64-https-$(variant_field "$line" 5).d64)"
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
echo "  Each variant ships as its own single-PRG 1541 image, plus one image per"
echo "  networking backend carrying both of that backend's profiles. Load with:"
echo
echo "      LOAD\"*\",8,1        (single-variant disks — one file, first on disk)"
echo "      LOAD\"UCI-REU\",8,1  (or whichever name the directory shows)"
echo "      RUN"
echo
echo "  There is deliberately no all-in-one image: the four PRGs total 868 blocks"
echo "  and a .d64 has 664 free. Each backend's pair does fit (UCI 496, ip65 372),"
echo "  so the per-backend disk is the largest bundle a real 1541 can hold."
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
