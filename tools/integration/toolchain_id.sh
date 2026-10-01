#!/usr/bin/env bash
# toolchain_id.sh NAME=command... -- one line per tool: NAME, the file its
# command resolves to, and that file's sha256.
#
# Feeds build/flags.stamp and the sibling-archive digests. Recording the
# command (or the PATH it resolves through) is not enough:
# /opt/homebrew/bin/ca65 is a symlink into Cellar/cc65/<version>, so a
# `brew upgrade` swaps the binary behind an unchanged path. Hashing the
# symlink's final target catches that. `ca65 --version` does not: the 2.19
# bottle reports V2.18.
#
# Never fails: an unresolvable tool reads "unresolved", which still
# compares, so a broken probe costs a rebuild rather than a stale link.

if command -v sha256sum >/dev/null 2>&1; then
    SHA256="sha256sum"
else
    SHA256="shasum -a 256"
fi

for pair in "$@"; do
    name="${pair%%=*}"
    cmd="${pair#*=}"
    cmd="${cmd%% *}"
    path=$(command -v "$cmd" 2>/dev/null)
    real=$( { realpath "$path" || readlink -f "$path"; } 2>/dev/null)
    real="${real:-$path}"
    sum=$($SHA256 < "$real" 2>/dev/null | cut -d' ' -f1)
    printf '%s=%s %s %s\n' "$name" "$cmd" "${real:-unresolved}" "${sum:-unresolved}"
done
