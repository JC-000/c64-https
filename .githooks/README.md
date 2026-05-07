# Client-side git hooks

Optional, opt-in hooks for keeping commits to this repo well-formed.

## What they check

- `pre-commit` — author and committer email must equal the project's
  expected GitHub noreply address. Any mismatch aborts the commit.
- `commit-msg` — two checks:
  1. The message must not match any regex listed in a local
     forbidden-patterns file (see below). Failure prints a generic
     "matches a forbidden pattern" message; the offending pattern is
     never echoed.
  2. `Co-authored-by:` trailers must use the project's expected human
     noreply address or `noreply@anthropic.com`. Anything else is
     rejected.

## Wiring them in

Hooks are not active just by sitting in the repo. After cloning, run:

```sh
git config core.hooksPath .githooks
```

This is a per-clone setting and is intentionally not committed.

## Local forbidden-patterns config

The `commit-msg` forbidden-pattern check reads from a file outside the
repo, so the patterns themselves never enter public history. The path
is deliberately generic so a single config file is shared with any
other repo's hook (and with a global `core.hooksPath` hook) on the
same machine.

- Default path: `$HOME/.config/git-hooks/forbidden-patterns.txt`
- Override:    set `$GIT_HOOKS_FORBIDDEN_FILE` to any readable path.
- Format:      one POSIX ERE per line; blank lines and lines starting
               with `#` are ignored.
- Matching:    case-insensitive (`grep -iE`) against the full commit
               message file.
- Missing:     if the file does not exist or is not readable, the check
               is silently skipped — a fresh clone is not blocked.

Example file:

```
# Internal-only domains and tracker IDs
bannedexample\.com
secret-tracker-[0-9]+
```

To install the example as the default config:

```sh
mkdir -p ~/.config/git-hooks
$EDITOR ~/.config/git-hooks/forbidden-patterns.txt
```
