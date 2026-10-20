#!/usr/bin/env bash
# mkvenv.sh — build a test venv for ANY python3, no version pinned.
#
#   tools/mkvenv.sh [python]        default: python3 on PATH
#
# Creates .venv-<major.minor> at the repo root (one per interpreter, so
# macOS's python3 and Homebrew's latest can sit side by side), installs
# requirements-dev.txt, and installs the sibling c64-test-harness editable
# (C64_TEST_HARNESS_ROOT, else ../c64-test-harness) when this interpreter
# meets the harness's requires-python. When it does not, that is reported:
# the suites that import the harness cannot run under this interpreter.
# Uses uv when present, else the interpreter's own venv + pip. Prints the
# venv's python path on the last line of stdout.
set -euo pipefail

cd "$(dirname "$0")/.."
PY="${1:-python3}"
command -v "$PY" >/dev/null || { echo "no such interpreter: $PY" >&2; exit 2; }
VER="$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
VENV=".venv-$VER"
VPY="$VENV/bin/python"
HARNESS="${C64_TEST_HARNESS_ROOT:-../c64-test-harness}"

if command -v uv >/dev/null; then
    uv venv -q --allow-existing -p "$PY" "$VENV"
    pip_install() { uv pip install -q -p "$VPY" "$@"; }
else
    [ -x "$VPY" ] || "$PY" -m venv "$VENV"
    pip_install() { "$VPY" -m pip install -q "$@"; }
fi

pip_install -r requirements-dev.txt

if [ ! -f "$HARNESS/pyproject.toml" ]; then
    echo "NOTE: no c64-test-harness checkout at $HARNESS -- harness suites will not import" >&2
elif "$VPY" - "$HARNESS/pyproject.toml" <<'EOF'
import re, sys
spec = re.search(r'requires-python\s*=\s*"([^"]+)"', open(sys.argv[1]).read())
floor = re.search(r">=\s*(\d+)\.(\d+)", spec.group(1)) if spec else None
sys.exit(0 if not floor or sys.version_info[:2] >= tuple(map(int, floor.groups())) else 1)
EOF
then
    pip_install -e "$HARNESS"
else
    echo "NOTE: c64-test-harness does not support python $VER (see its requires-python);" \
         "harness suites will not import under this interpreter" >&2
fi

echo "$VPY"
