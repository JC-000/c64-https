#!/usr/bin/env bash
# =============================================================================
# tools/package/write_release_sums.sh — the release's top-level SHA256SUMS.
#
# Writes <out>/SHA256SUMS in `shasum -a 256 -c` form over every asset a
# release attaches, so the file is generated, never typed:
#
#   from dist/ (make package):
#     c64-https-ip65-onchip.{prg,d64}  c64-https-uci-onchip.{prg,d64}
#     c64-https-uci-comb.{prg,d64}     MANIFEST.txt  build-info.txt
#     c64-https-listener.py
#   from the M3 demo directory (carried forward or `make package-m3-demo`):
#     c64-https-uci-m3-demo.{prg,d64}  c64-https-uci-m3-demo-README.txt
#     c64-https-uci-m3-demo-SHA256SUMS
#
# The M3 demo's own README is attached under the name
# c64-https-uci-m3-demo-README.txt and its checksum file under
# c64-https-uci-m3-demo-SHA256SUMS; inside the demo package they are
# README.txt and SHA256SUMS, so pass either spelling.
#
#   tools/package/write_release_sums.sh <assets-dir>
#
# <assets-dir> is the directory the release's files are gathered in (dist/
# plus the M3 files copied or linked next to them). Refuses a missing file:
# a release that silently omits an asset from its checksum list is the
# failure this exists to prevent. Nothing but SHA256SUMS is written.
# =============================================================================
set -euo pipefail

DIR="${1:?usage: write_release_sums.sh <assets-dir>}"
cd "$DIR"

ASSETS=(
  c64-https-ip65-onchip.prg c64-https-ip65-onchip.d64
  c64-https-uci-onchip.prg  c64-https-uci-onchip.d64
  c64-https-uci-comb.prg    c64-https-uci-comb.d64
  c64-https-uci-m3-demo.prg c64-https-uci-m3-demo.d64
  c64-https-uci-m3-demo-README.txt
  c64-https-uci-m3-demo-SHA256SUMS
  c64-https-listener.py
  MANIFEST.txt
  build-info.txt
)

missing=0
for f in "${ASSETS[@]}"; do
    [ -f "$f" ] || { echo "write_release_sums: missing $f in $DIR" >&2; missing=1; }
done
[ "$missing" = 0 ] || exit 1

shasum -a 256 "${ASSETS[@]}" > SHA256SUMS
shasum -a 256 -c SHA256SUMS >/dev/null
echo "wrote $DIR/SHA256SUMS (${#ASSETS[@]} assets, verified)"
