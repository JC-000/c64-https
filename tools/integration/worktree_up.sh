#!/usr/bin/env bash
# Create a git worktree for a per-lib integration phase.
# Usage: worktree_up.sh <slug> <branch>
# Prints the absolute worktree path on success.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <slug> <branch>" >&2
  exit 2
fi

slug="$1"
branch="$2"
root="$(git rev-parse --show-toplevel)"
wt="$root/.claude/worktrees/$slug"

git worktree add "$wt" -b "$branch"
echo "$wt"
