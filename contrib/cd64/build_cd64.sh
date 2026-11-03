#!/bin/bash
# Linux/macOS mirror of Commodore Desk 64's build_disk.bat: the core, the
# overlays (WEB with web_tls.asm's WEBTLS) and one D81, optionally with
# extra files -- the c64-https HANDOFF=1 helper goes on as "https".
#   KICKASS_JAR=/path/KickAss.jar CHARGEN_ROM=<VICE>/C64/chargen-901225-01.bin \
#     contrib/cd64/build_cd64.sh <cd64 checkout> build/c64-https.prg:https
# Writes <checkout>/build/CD64.d81. Their own scripts are run as they are;
# make_fonts.py's hardcoded Windows ROM path is substituted at run time.
set -euo pipefail
KA="java -jar ${KICKASS_JAR:?set KICKASS_JAR to KickAss.jar (v5.25 tested)}"
C1541=${C1541:-c1541}
ROM=${CHARGEN_ROM:?set CHARGEN_ROM to VICE C64/chargen-901225-01.bin}
CHECKOUT=$1; shift
EXTRA=()                         # resolved before the cd: paths are the caller's
for x in "$@"; do EXTRA+=("$(cd "$(dirname "${x%%:*}")" && pwd)/$(basename "${x%%:*}"):${x##*:}"); done
cd "$CHECKOUT"
mkdir -p build
# One-time inputs (their README): the char ROM and the generated fonts.
[ -f data/chargen.bin ] || head -c 2048 "$ROM" > data/chargen.bin
if [ ! -f data/lower.bin ]; then
  python3 -I -c "import sys; s=open('tools/make_fonts.py').read(); s=s.replace('C:/Users/aegwh/OneDrive/dev/c64/vice/C64/chargen-901225-01.bin', sys.argv[1]); exec(compile(s,'make_fonts.py','exec'))" "$ROM"
  python3 -I tools/make_fremenfont.py
fi
ka() { local log; log=$(mktemp); if ! $KA "$@" >"$log" 2>&1 || grep -q "^Error" "$log"; then grep -v JAVA_TOOL "$log" | tail -15; echo "KICKASS FAILED: $*"; exit 1; fi; rm -f "$log"; }
ka disk_main.asm -vicesymbols -odir build
python3 -I tools/export_core_syms.py
python3 -I tools/make_help.py
for m in bbs email time radio; do ka ${m}_main.asm -odir build; done
python3 -I tools/make_weather_sprites.py
for m in weather web calendar; do ka ${m}_main.asm -odir build; done
python3 -I tools/make_radio_seq.py
python3 -I tools/make_radio_seq.py data/bookmarks.txt build/bookmarks.seq
python3 -I tools/make_stoneicons.py
ka boot_main.asm -o build/boot.prg -odir build
args=(-format "commodore desk,cd" d81 build/CD64.d81)
for f in boot cd64 helptext files editor paint calc setup desktool sidplay inet bbs email time radio weather web webtls calendar stoneicon lower tiny fremen serif mono casual heavy; do
  [ -f build/$f.prg ] && args+=(-write build/$f.prg $f) || echo "missing build/$f.prg"
done
[ -f build/bookmarks.seq ] && args+=(-write build/bookmarks.seq "bookmarks,s")
for x in ${EXTRA[@]+"${EXTRA[@]}"}; do args+=(-write "${x%%:*}" "${x##*:}"); done
$C1541 "${args[@]}" >/dev/null
echo "built $(pwd)/build/CD64.d81"
