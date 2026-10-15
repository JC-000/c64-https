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
#   SHA256SUMS                  sha256 of the PRG, the .d64 and README.txt,
#                               in `shasum -a 256 -c` form
#
# These four are the GitHub pre-release's assets; nothing else is written.
#
# Separate from `make package` on purpose. The M3 variant is SECONDARY (the
# 6510 crypto is the product), so it is not in PACKAGE_VARIANTS, and nothing
# here reads or writes that matrix or the shipped products in dist/.
#
# It refuses a working tree with any change, untracked files included: the
# README names a commit, and the PRG must be what that commit builds.
#
# make runs in a scrubbed environment (PATH, HOME, TMPDIR only), so neither
# an exported knob (HTTPS_SNI=..., VIC_BLANK=0) nor one given on the
# `make package-m3-demo` command line (it reaches here through MAKEFLAGS)
# can leak into the demo build. build/flags.stamp is then checked to hold
# the uci-m3 cfg and no -D beyond the backend's own.
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
# FIRMWARE is the firmware side's own one-line description (agreed with
# them); the source branch, the prebuilt image and its sha256 follow. The
# image line is printed only when FIRMWARE_IMAGE_SHA is set. These and
# UPSTREAM_PRS are plain constants, not env knobs, so the README is a
# function of the commit: a later commit swaps them.
FIRMWARE="TLS client sockets for the Ultimate 64 / U64 Elite, from
      JC-000/1541ultimate branch pr/3-tls-r1 (f3df8261), prebuilt image in
      prerelease tls-preview-f3df8261. Not upstream; proposed on
      GideonZ/1541ultimate#952."
FIRMWARE_SOURCE="https://github.com/JC-000/1541ultimate/tree/pr/3-tls-r1"
FIRMWARE_PRERELEASE="https://github.com/JC-000/1541ultimate/releases/tag/tls-preview-f3df8261"
FIRMWARE_IMAGE_SHA="15e9ff7cd8a11daf1f4698d574480381d475db7754e1d276d9aa95e8013ded3c"
# The build the "Measured" figures were taken on (the image above).
MEASURED_FW="firmware 3.15 git f3df8261 (the image above, ESP module 1.8)"
# Change it once an upstream PR implements $21-$25.
UPSTREAM_PRS="not upstream yet. GideonZ/1541ultimate#952 is the proposal issue;
      this demo follows its proposed command numbering (\$21 OPEN_TLS,
      \$23 TLS_INFO, \$25 TLS_RELEASE). No upstream PR implements these
      commands yet (GideonZ/1541ultimate#953 adds GET_RANDOM only)."
# Earlier demo images (this script's history, JC-000/c64-https 82a549a to
# 9eabd50) were validated on these builds; neither is public.
EARLIER_RUNS="esp-tls/m3 f2e46946 and esp-tls/m3-master 3a1ff9ff"

# The image the "Measured" figures below were taken with, and its commit.
# The README says THIS image only when the PRG just built is that one;
# otherwise it names the measured PRG and says this one was not run, so a
# rebuild after an unrelated change cannot inherit the claim. Update both,
# with the figures, after each demo-rig run.
# MEASURED_COMMIT is a commit on master that reproduces that PRG (the
# adapter diff below runs from it); MEASURED_BUILT is where the measured
# image itself was built.
MEASURED_PRG_SHA="916d41628a17b9436bbf58a71f7350c721a06e459cf5c33e5baeb1ad61af9a24"
MEASURED_COMMIT="daaef3354ec443b0feb09dfa2900795f9fa265ce"
MEASURED_COMMIT_NOTE="the merge of JC-000/c64-https#299"
MEASURED_BUILT="daaef33 on 2026-10-14"
SPEC="M3-SPEC v1 (= r7.7), sha256 c265fdfcfdd08dee989a96eee25fae66fb6650ee4be8bb24f8dd791d9ee3db9f, with errata v1.1 (f9a39ff334b34cb0e1a63d5d508675de552ac8eacb23ccd6095a7f4c72788f9a) and v1.2 (a6802f40db3229d53591ef6e0773641d723186e779dd8726abff5915cbe551a4)"

die() { echo "[m3-demo] ERROR: $*" >&2; exit 1; }
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

command -v "$C1541" >/dev/null 2>&1 \
    || die "c1541 not found in PATH (it ships with VICE). Set C1541=... to override."

[ -z "$(git status --porcelain --untracked-files=all)" ] \
    || { git status --short --untracked-files=all >&2
         die "the working tree is not clean (untracked files count): commit or remove the changes above"; }

rm -rf "$OUT"
mkdir -p "$OUT"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

scrubbed_make() {
    env -i PATH="$PATH" HOME="$HOME" ${TMPDIR:+TMPDIR="$TMPDIR"} make "$@"
}

# The demo is the bare backend: its -D set, its cfg, the default target.
check_stamp() {
    local stamp=build/flags.stamp defines
    grep -qx 'BACKEND=uci-m3' "$stamp" || die "$stamp: BACKEND is not uci-m3"
    grep -q '^LD65FLAGS=-C cfg/c64-https-uci-m3.cfg ' "$stamp" \
        || die "$stamp: not linked with cfg/c64-https-uci-m3.cfg"
    defines="$(grep '^CA65FLAGS=' "$stamp" | grep -o -- '-D [^ ]*' | tr '\n' ' ')"
    [ "$defines" = "-D BACKEND_UCI=1 -D BACKEND_UCI_M3=1 " ] \
        || die "$stamp: unexpected defines: $defines"
    grep -qx ".define HTTPS_HOST_STR \"$DEMO_HOST\"" build/https_host.inc \
        && grep -qx ".define HTTPS_PATH_STR \"$DEMO_PATH\"" build/https_host.inc \
        && grep -qx '.define HTTPS_SNI_STR ""' build/https_host.inc \
        || die "build/https_host.inc does not hold the demo target"
}

build_once() {
    scrubbed_make clean >/dev/null
    scrubbed_make "${MAKE_ARGS[@]}" >"$tmp/build.log" 2>&1 \
        || { tail -20 "$tmp/build.log" >&2; die "build failed: make ${MAKE_ARGS[*]}"; }
    check_stamp
}

echo "[m3-demo] building: make ${MAKE_ARGS[*]}"
build_once
cp build/c64-https.prg "$OUT/$NAME.prg"
flags_line="$(grep '^CA65FLAGS=' build/flags.stamp | sed 's/--bin-include-dir [^ ]*//g; s/  */ /g')"
# Path and sha256 of each tool make linked, from the stamp: a ca65 that is
# not cc65's shows here, since nothing else in this script can tell.
toolchain="$(grep '^TOOLCHAIN=' build/flags.stamp | sed 's/^TOOLCHAIN=//' \
    | awk '{ for (i = 1; i + 2 <= NF; i += 3) print "    " $i, $(i+1), $(i+2) }')"

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
prg_sha="$(sha "$OUT/$NAME.prg")"
d64_sha="$(sha "$OUT/$NAME.d64")"
prg_bytes="$(wc -c < "$OUT/$NAME.prg" | tr -d ' ')"

# The M3 adapter's sources: everything under src/net/uci-m3/ (some of it,
# m3_https_get.inc and net_tuning.inc, is included from boot.s/exports.s,
# not from the adapter's objects), every file ca65 read for the objects in
# build/net/uci-m3/ (their .d files: the .s files and every .include, such
# as src/net/uci/uci_regs.inc), and the backend's cfg. Derived from git and
# this build, not listed by hand. The directory itself is also a pathspec,
# so a file deleted from it since the measured commit counts too.
shopt -s nullglob
adapter_deps=(build/net/uci-m3/*.d)
shopt -u nullglob
[ "${#adapter_deps[@]}" -gt 0 ] || die "no build/net/uci-m3/*.d: cannot list the adapter's sources"
adapter_files=()
while IFS= read -r f; do adapter_files+=("$f"); done < <(
    { git ls-files -- src/net/uci-m3
      sed -n 's/^build\/[^:]*:[[:space:]]*//p' "${adapter_deps[@]}" | tr ' \t' '\n\n'
      echo cfg/c64-https-uci-m3.cfg; } | grep -v -e '^$' -e '^build/' | sort -u)
[ "${#adapter_files[@]}" -gt 1 ] || die "cannot list the adapter's sources"

if [ "$prg_sha" = "$MEASURED_PRG_SHA" ]; then
    measured_with="Measured with THIS image (PRG sha256 above)"
    this_run="The run recorded for this image is the one under \"Measured\" below."
else
    # Whether the adapter's sources moved since the measured commit, from
    # git rather than from prose; "unknown" if that commit is not here.
    if ! git cat-file -e "$MEASURED_COMMIT^{commit}" 2>/dev/null; then
        adapter="whether the M3 adapter's sources changed since is unknown here"
    else
        changed="$(git diff --name-only "$MEASURED_COMMIT" HEAD -- src/net/uci-m3 "${adapter_files[@]}" \
            | sort -u | sed 's/^/    /')"
        if [ -z "$changed" ]; then
            adapter="the M3 adapter's ${#adapter_files[@]} source files (src/net/uci-m3/, what its
objects include, and its cfg) are unchanged since"
        else
            adapter="changed since in the M3 adapter's sources:
$changed"
        fi
    fi
    measured_with="NOT measured with this image. Measured with PRG sha256
  $MEASURED_PRG_SHA
reproducible from commit $MEASURED_COMMIT
($MEASURED_COMMIT_NOTE);
the measured image was built from $MEASURED_BUILT
($adapter)"
    this_run="This image has no recorded run on any firmware."
    echo "[m3-demo] NOTE: this PRG is not the measured one; the README says so"
fi

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
  commit  $commit
  make    ${MAKE_ARGS[*]}
  $flags_line
  toolchain (path, sha256):
$toolchain
  The PRG is deterministic: \`make clean && make ${MAKE_ARGS[*]}\` at that
  commit reproduces the sha256 above (this script checked it twice).

What it needs
-------------
  - An Ultimate 64 (Elite) running firmware with the M3 TLS sockets.
    Firmware: $FIRMWARE
    Source:
      $FIRMWARE_SOURCE
    Prebuilt image:
      $FIRMWARE_PRERELEASE
${FIRMWARE_IMAGE_SHA:+    Image sha256:
      $FIRMWARE_IMAGE_SHA
}    Upstream status:
      $UPSTREAM_PRS
    $this_run
    Earlier demo images were validated on the non-public builds
    $EARLIER_RUNS.
  - Its WiFi module up (the ESP32 does the TLS), the network connected, and
    the clock set by SNTP (certificate dates are checked).
  - The Ultimate's Command Interface enabled.
  - No REU. Turbo is optional. The same M3 adapter, in its REU-sink
    build, fetched en.wikipedia.org /robots.txt (28,275 B) on the U64E:
    17.5 s from G to the whole body at 1 MHz (turbo off), handshake done
    at 5.8 s (sink build 146647e4, firmware f3df8261, 2026-10-15); and 6 s
    from G at 48 MHz (esp-tls/m3-master 3a1ff9ff, 2026-10-13). Large pages
    were not timed at 1 MHz.
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

Four URLs to try
----------------
  1. $DEMO_HOST $DEMO_PATH   (the default)
  2. github.com /robots.txt
  3. 208-80-153-224.nip.io /              (a NEGATIVE: a Wikipedia address
     under a name its certificate does not carry. Expected:
     TLS HANDSHAKE FAILED / 94,CERTIFICATE NAME MISMATCH: 0x00000004.
     It depends on two things outside this project: the nip.io DNS service,
     and 208.80.153.224 still serving Wikipedia. If either changes, pick
     another <ip-with-dashes>.nip.io name for a site whose certificate does
     not name it.)
  4. badssl.com /                         (a NEGATIVE: a server without
     TLS 1.3. Expected: TLS HANDSHAKE FAILED / 14,TLS ALERT RECEIVED: 40 /
     THE SERVER DOES NOT DO TLS 1.3. It depends on badssl.com staying
     TLS 1.2 only.)

$measured_with, validated on an Ultimate 64
Elite (U64E), $MEASURED_FW,
48 MHz, REU disabled, 2026-10-15. URLs 1-3: the .d64 mounted on drive 8
and loaded with LOAD"*",8,1 (tools/uci/rig_https_m3_demo.py):
  1. HTTP 200, 759,171 B consumed == Content-Length, 20 s from G to
     CONNECTION CLOSED (the page size changes as the article is edited).
  2. HTTP 200, 16,739 B consumed == Content-Length, 5 s.
  3. Refused: 94,CERTIFICATE NAME MISMATCH: 0x00000004.
URL 4: the same PRG written into memory over the Ultimate's REST interface
instead of loaded from the disk (tools/uci/rig_https_m3.py refuse):
  4. Refused: 14,TLS ALERT RECEIVED: 40, then THE SERVER DOES NOT DO
     TLS 1.3.
  Other Ultimate models, and other clock speeds, have not been tested
  with this image.

What an unsupported device shows
--------------------------------
(Per the M3 spec and our model tests, not yet observed on hardware with
this image.)
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

# SHA256SUMS last, over everything a release would attach (shasum -c format).
( cd "$OUT" && shasum -a 256 "$NAME.prg" "$NAME.d64" README.txt > SHA256SUMS )

echo "[m3-demo] done: $OUT"
echo "[m3-demo]   $NAME.prg  $prg_sha"
echo "[m3-demo]   $NAME.d64  $d64_sha"
