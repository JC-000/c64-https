#!/usr/bin/env bash
# sibling_src_digest.sh <submodule> <wrapper>... -- print what a sibling
# archive was built FROM, for the Makefile's parse-time compare.
#
# The body is content, not mtimes: the gitlink the superproject index
# records, the commit checked out in the submodule, the CA65/AR65 toolchain
# the wrappers will run, the sha256 of each wrapper script, and one sha256
# over every source file in the submodule (tracked plus
# untracked-not-ignored, so upstream's ignored build/ output is excluded).
# Any change to any of them changes the body, and the Makefile then DELETES
# the archive -- absence, which macOS GNU Make 3.81's 1-second mtime
# resolution cannot defeat. See SIBLING_SRC_CHECK in the Makefile.
#
# Never fails: a line it cannot compute reads "unknown", which still
# compares, so a broken probe costs a rebuild rather than a stale link.
set -o pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 0

if command -v sha256sum >/dev/null 2>&1; then
    SHA256="sha256sum"
else
    SHA256="shasum -a 256"
fi

sub="$1"; shift

echo "submodule=$sub"
echo "gitlink=$(git ls-files -s -- "$sub" 2>/dev/null | cut -d' ' -f2 || true)"
echo "head=$(git -C "$sub" rev-parse HEAD 2>/dev/null || echo unknown)"
# The toolchain the wrappers will run: the value as given (the Makefile
# passes CA65/AR65 through) and what its first word resolves to on PATH.
for var in CA65 AR65; do
    val="${!var:-$(echo "$var" | tr 'A-Z' 'a-z')}"
    echo "$var=$val -> $(command -v "${val%% *}" 2>/dev/null || echo unresolved)"
done
for w in "$@"; do
    echo "wrapper=$w $($SHA256 < "$w" 2>/dev/null | cut -d' ' -f1 || echo unknown)"
done
tree=$(cd "$sub" 2>/dev/null &&
       { git ls-files -co --exclude-standard -z 2>/dev/null ||
         find . -type f ! -path './.git/*' ! -name .git ! -path './build/*' -print0 | sort -z; } |
       xargs -0 $SHA256 2>/dev/null | $SHA256 | cut -d' ' -f1)
echo "tree=${tree:-unknown}"
