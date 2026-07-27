#!/usr/bin/env bash
# Build dist/c64-https-listener.zip — the self-contained TLS 1.3 test
# listener package. The zip lets someone stand up the entire server side
# of the c64-https end-to-end test on a fresh machine (including cert
# generation) with zero dependency on this repo's committed certs or on
# the c64-test-harness package.
#
# Standalone-runnable; a teammate wires this into `make package`.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
SRC_DIR="$HERE/listener"
DIST_DIR="$REPO_ROOT/dist"
ZIP_PATH="$DIST_DIR/c64-https-listener.zip"

# Files that make up the package (nothing else from the tree leaks in).
FILES=(
    "run.sh"
    "listener.py"
    "gen_certs.py"
    "requirements.txt"
    "README.md"
)

echo "Building c64-https listener zip"
echo "  source : $SRC_DIR"
echo "  output : $ZIP_PATH"

# Verify every expected file exists before we build.
for f in "${FILES[@]}"; do
    if [ ! -f "$SRC_DIR/$f" ]; then
        echo "ERROR: missing $SRC_DIR/$f" >&2
        exit 1
    fi
done

# Ensure the shell scripts are executable inside the zip.
chmod +x "$SRC_DIR/run.sh"

mkdir -p "$DIST_DIR"
rm -f "$ZIP_PATH"

# Stage into a top-level "listener/" directory so the unzip is tidy.
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/listener"
for f in "${FILES[@]}"; do
    cp "$SRC_DIR/$f" "$STAGE/listener/$f"
done
chmod +x "$STAGE/listener/run.sh"

( cd "$STAGE" && zip -r -q "$ZIP_PATH" listener )

echo "Wrote $ZIP_PATH"
unzip -l "$ZIP_PATH"
