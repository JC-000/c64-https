#!/usr/bin/env bash
# U64E test suites must be dispatched via a live Phase F agent so that a
# human-aware decision can be made per feedback_never_inline_u64e. This
# wrapper exists to satisfy the plan's file list and deliberately refuses
# to run.
echo "Use Phase F agent directly for U64E; this wrapper exists to satisfy the plan's file list" >&2
exit 2
