#!/usr/bin/env bash
# Pre-seed the three sibling repos' .claude/settings.local.json files with
# the Bash/permission patterns downstream integration agents need, so cross-
# repo dispatches do not stall on approval prompts.
#
# Merges into permissions.allow (dedupe against existing; preserve order;
# append new entries at the end) and ensures a core set of deny patterns.
# Creates the file if missing. Never touches c64-https's own settings.
#
# Invokes tools/integration/_merge_allow.py.
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MERGER="$HERE/_merge_allow.py"

SIBLINGS=(
  "/home/someone/c64-x25519"
  "/home/someone/c64-ChaCha20-Poly1305"
  "/home/someone/c64-nist-curves"
)

ALLOW=(
  "Bash(python3 *)"
  "Bash(make *)"
  "Bash(make)"
  "Bash(make clean)"
  "Bash(make run)"
  "Bash(ca65 *)"
  "Bash(ld65 *)"
  "Bash(ar65 *)"
  "Bash(x64sc *)"
  "Bash(timeout *)"
  "Bash(git submodule *)"
  "Bash(git worktree *)"
  "Bash(git add *)"
  "Bash(git commit *)"
  "Bash(git checkout *)"
  "Bash(bash *.sh)"
  "Bash(bash tools/integration/*.sh *)"
)

DENY=(
  "Bash(rm -rf *)"
  "Bash(git push --force *)"
  "Bash(killall *)"
)

for repo in "${SIBLINGS[@]}"; do
  if [[ ! -d "$repo" ]]; then
    echo "FATAL: sibling repo missing: $repo" >&2
    exit 1
  fi
  mkdir -p "$repo/.claude"
  settings="$repo/.claude/settings.local.json"
  python3 "$MERGER" "$settings" \
    --allow "${ALLOW[@]}" \
    --deny "${DENY[@]}"
done
