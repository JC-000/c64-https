#!/usr/bin/env bash
# One-arg wrapper around tools/run_all_tests.py honoring C64_SKIP_BUILD.
#
# Usage: run_vice_suite.sh [run_all_tests.py args...]
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

C64_SKIP_BUILD="${C64_SKIP_BUILD:-0}" python3 tools/run_all_tests.py "$@"
