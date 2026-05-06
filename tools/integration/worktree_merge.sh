#!/usr/bin/env bash
# Merge a feature branch into master with --no-ff, then run the baseline
# test suite. Aborts the merge if tests fail, leaving master untouched.
#
# Usage: worktree_merge.sh <branch>
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <branch>" >&2
  exit 2
fi

branch="$1"
root="$(git rev-parse --show-toplevel)"
cd "$root"

git checkout master
git merge --no-ff "$branch" -m "Merge $branch into master"

if ! make; then
  echo "build failed after merging $branch; aborting merge" >&2
  git reset --merge HEAD^
  exit 1
fi

if ! python3 tools/run_all_tests.py --skip-slow; then
  echo "tests failed after merging $branch; aborting merge" >&2
  git reset --merge HEAD^
  exit 1
fi

echo "merged $branch; tests green"
