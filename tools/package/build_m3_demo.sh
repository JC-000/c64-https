#!/usr/bin/env bash
# =============================================================================
# tools/package/build_m3_demo.sh — the "just run it" BACKEND=uci-m3 demo.
#
# Produces dist/m3-demo/ from a clean tree:
#
#   c64-https-uci-m3-demo.prg   the M3 client, default target en.wikipedia.org
#   c64-https-uci-m3-demo.d64   that PRG alone, bootable with LOAD"*",8,1
#   README.txt                  what it is, what it needs, how to run it, and
#                               the provenance (commit, flags, sha256s)
#
# Separate from `make package` on purpose. The M3 variant is SECONDARY (the
# 6510 crypto is the product), so it is not in PACKAGE_VARIANTS, and nothing
# here reads or writes that matrix or the shipped products in dist/.
#
# It proves its own output before writing the README:
#   - a second clean build reproduces the PRG byte for byte;
#   - c1541 reads the PRG back out of the .d64, byte for byte.
# Any failure exits non-zero and leaves no README, so a half-made demo never
# looks finished.
#
# Usage:  make package-m3-demo        [C1541=... to override the tool]
# =============================================================================
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

C1541="${C1541:-c1541}"
OUT="dist/m3-demo"
NAME="c64-https-uci-m3-demo"
DISK_FILE="c64-https-m3"            # the 1541 file name (<= 16 chars)
DEMO_HOST="en.wikipedia.org"
DEMO_PATH="/wiki/Commodore_64"
MAKE_ARGS=(BACKEND=uci-m3 "HTTPS_HOST=$DEMO_HOST" "HTTPS_PATH=$DEMO_PATH")

# What the firmware side published; quoted in the README, checked nowhere
# here (the device is not involved in a build).
FIRMWARE="1541ultimate esp-tls/m3 f2e46946 or later (U64 firmware 3.15 with ESP32 IDENT 1.309)"
SPEC="M3-SPEC v1 (= r7.7), sha256 c265fdfcfdd08dee989a96eee25fae66fb6650ee4be8bb24f8dd791d9ee3db9f, with errata v1.1 (f9a39ff334b34cb0e1a63d5d508675de552ac8eacb23ccd6095a7f4c72788f9a) and v1.2 (a6802f40db3229d53591ef6e0773641d723186e779dd8726abff5915cbe551a4)"

die() { echo "[m3-demo] ERROR: $*" >&2; exit 1; }
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

command -v "$C1541" >/dev/null 2>&1 \
    || die "c1541 not found in PATH (it ships with VICE). Set C1541=... to override."

rm -rf "$OUT"
mkdir -p "$OUT"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

build_once() {
    make clean >/dev/null
    make "${MAKE_ARGS[@]}" >"$tmp/build.log" 2>&1 \
        || { tail -20 "$tmp/build.log" >&2; die "build failed: make ${MAKE_ARGS[*]}"; }
}

echo "[m3-demo] building: make ${MAKE_ARGS[*]}"
build_once
cp build/c64-https.prg "$OUT/$NAME.prg"
flags_line="$(grep '^CA65FLAGS=' build/flags.stamp | sed 's/--bin-include-dir [^ ]*//g; s/  */ /g')"

echo "[m3-demo] rebuilding from clean to prove the PRG is reproducible"
build_once
[ "$(sha build/c64-https.prg)" = "$(sha "$OUT/$NAME.prg")" ] \
    || die "the second clean build differs from the first"

echo "[m3-demo] writing $NAME.d64"
"$C1541" -format "c64-https-m3,m3" d64 "$OUT/$NAME.d64" >/dev/null
"$C1541" -attach "$OUT/$NAME.d64" -write "$OUT/$NAME.prg" "$DISK_FILE,p" >/dev/null
"$C1541" -attach "$OUT/$NAME.d64" -read "$DISK_FILE" "$tmp/readback.prg" >/dev/null
cmp -s "$tmp/readback.prg" "$OUT/$NAME.prg" \
    || die "the PRG read back out of the .d64 differs from the one written"
listing="$("$C1541" -attach "$OUT/$NAME.d64" -list \
    | grep -Ev '^(OPENCBM:|D64 disk image |Unit [0-9]+ drive )')"

commit="$(git rev-parse HEAD)"
dirty=""
git diff --quiet HEAD -- . ':!dist' 2>/dev/null || dirty=" (WORKING TREE MODIFIED: not a clean commit build)"
prg_sha="$(sha "$OUT/$NAME.prg")"
d64_sha="$(sha "$OUT/$NAME.d64")"
prg_bytes="$(wc -c < "$OUT/$NAME.prg" | tr -d ' ')"

cat > "$OUT/README.txt" <<EOF
c64-https M3 demo — HTTPS on a C64, with TLS done by the Ultimate's ESP32
==========================================================================

The C64 speaks HTTP; the Ultimate's ESP32 runs the TLS session (connect,
handshake, certificate verification against its Mozilla CA store) through the
M3 TLS-socket commands of the Ultimate Command Interface. This is a
SECONDARY variant of c64-https: the main product does all of TLS 1.3 on the
6510 itself and does not need this firmware.

Files
-----
  $NAME.prg   $prg_bytes bytes
    sha256 $prg_sha
  $NAME.d64   the PRG alone, as "$DISK_FILE"
    sha256 $d64_sha

Directory of the .d64:
$(printf '%s\n' "$listing" | sed 's/^/  /')

Built from
----------
  commit  $commit$dirty
  make    ${MAKE_ARGS[*]}
  $flags_line
  The PRG is deterministic: \`make clean && make ${MAKE_ARGS[*]}\` at that
  commit reproduces the sha256 above (this script checked it twice).

What it needs
-------------
  - An Ultimate 64 (Elite) running firmware with the M3 TLS sockets:
    $FIRMWARE.
  - Its WiFi module up (the ESP32 does the TLS), the network connected, and
    the clock set by SNTP (certificate dates are checked).
  - The Ultimate's Command Interface enabled.
  - No REU. Turbo is optional but recommended: the client paces every UCI
    register access for the FPGA, so the default article (about 750 KB)
    takes about 3.5 min at 48 MHz and hours at 1 MHz. Small pages are
    fine at any speed.
  Interface implemented: $SPEC.

How to run it
-------------
  Mount the .d64 on drive 8, then:
      LOAD"*",8,1
      RUN
  The program starts the network (I re-runs it), then:
      G        fetch a page. It asks for HOST and PATH; RETURN on an empty
               field keeps the default, $DEMO_HOST $DEMO_PATH.
      Q        quit to BASIC.
  A fetch prints OPEN TLS (ULTIMATE)..., TLS HANDSHAKE OK, PROTOCOL TLS 1.3,
  REQUEST SENT, the first 200 bytes of the body, then CONNECTION CLOSED.
  A body cut short of its own framing prints BODY INCOMPLETE and the
  firmware's status line before CONNECTION CLOSED.

Three URLs to try
-----------------
  1. $DEMO_HOST $DEMO_PATH   (the default: about 750 KB; about 3.5 min at
     48 MHz, the body counted to its Content-Length)
  2. github.com /robots.txt               (14 KB)
  3. 208-80-153-224.nip.io /              (a NEGATIVE: a Wikipedia address
     under a name its certificate does not carry. Expected:
     TLS HANDSHAKE FAILED / 94,CERTIFICATE NAME MISMATCH: 0x00000004)

What an unsupported device shows
--------------------------------
  - Firmware without the M3 commands: I prints NETWORK INIT FAILED and the
    firmware's answer, 21,UNKNOWN COMMAND.
  - No Command Interface (a plain C64, or the interface disabled): NETWORK
    INIT FAILED.
  - M3 firmware but no usable TLS module (WiFi off, no ESP32, a build without
    TLS): G waits up to 30 s for the module, then prints TLS HANDSHAKE FAILED
    and 90,TLS NOT AVAILABLE (or 87 no entropy / 92 no trusted time).
  - Any refusal prints the firmware's own status line, e.g. 93 (certificate
    not trusted), 94 (name mismatch), 95 (expired).
  - NETWORK INTERFACE NOT RESPONDING - PRESS RESET means the interface
    stopped answering; the program halts on purpose. Press the reset button
    (if it repeats, power-cycle the Ultimate).

Source: https://github.com/JC-000/c64-https (src/net/uci-m3/).
EOF

echo "[m3-demo] done: $OUT"
echo "[m3-demo]   $NAME.prg  $prg_sha"
echo "[m3-demo]   $NAME.d64  $d64_sha"
