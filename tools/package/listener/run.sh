#!/usr/bin/env bash
# One-shot bootstrap for the c64-https TLS 1.3 test listener.
#
# Creates a local virtualenv if needed, installs the (minimal) deps,
# generates a fresh self-signed ECDSA P-256 cert if one isn't present,
# and starts the listener. Works on a fresh machine with only a system
# `python3` (>=3.8) available.
#
# All arguments are passed straight through to listener.py, e.g.:
#   ./run.sh --port 4433
#   ./run.sh --bind 0.0.0.0 --serve-forever
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

PYTHON="${PYTHON:-python3}"
VENV_DIR="${VENV_DIR:-$HERE/.venv}"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "ERROR: '$PYTHON' not found on PATH. Install Python 3.8+ or set PYTHON=..." >&2
    exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtualenv at $VENV_DIR ..."
    "$PYTHON" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo "Installing dependencies ..."
python -m pip install --upgrade pip >/dev/null
python -m pip install -r "$HERE/requirements.txt"

echo "Ensuring certificate ..."
python "$HERE/gen_certs.py"

echo "Starting listener ..."
exec python "$HERE/listener.py" "$@"
