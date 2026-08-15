; src/net/ip65/ip65_blob.s — ca65 wrapper around the pre-built ip65 binary.
;
; The ip65 library is built by the legacy ACME Makefile pipeline into
;   ip65-build/ip65-c64.bin
; which is a ~7KB blob pre-linked at $2000 (jump table + library code).
; This wrapper incbin's that blob into the NET_CODE segment so ld65 places
; it at $2000 inside the final c64-https.prg image.
;
; Do NOT modify ip65-build/ or the ip65 submodule — they remain the source
; of truth for the ip65 binary. This file just glues the pre-built blob
; into the ca65 link.
;
; Segment NET_CODE is defined by cfg/c64-https-ip65.cfg as
;   start = $2000, size = $2000, file = %O, type = ro
; so ld65 places the blob at $2000 and the loader fragments written in
; Phase 3 Batch D Round 1 are unaffected.

.segment "NET_CODE"

; The blob is found through ca65's BINARY include path, set by the
; Makefile to an absolute $(abspath $(IP65_BUILD)). Hence the bare
; filename: there is deliberately no `../` here to resolve.
;
; It used to read `../../../ip65-build/ip65-c64.bin`, on the belief that
; ca65 resolves .incbin relative to the including source file. It does
; not — or rather, not first. **ca65 tries the CURRENT DIRECTORY first**
; and falls back to the source file's directory only on a miss. From the
; repo root the two coincide, which is why the old spelling worked and
; why the wrong rule survived in this comment for so long.
;
; They stop coinciding inside a git worktree. One lives at
; <repo>/.claude/worktrees/<name>/ — exactly three levels down — so
; `../../../` climbed out of the worktree and into the PRIMARY checkout,
; and every worktree build embedded the primary's blob while make's
; dependency graph tracked the worktree's. Nothing diagnosed it: the two
; copies are normally byte-identical, so it stayed invisible until
; someone bumped the ip65 submodule on a branch. Measured, ca65 V2.18,
; with distinguishable bytes planted in each copy (issue #116):
;
;   .incbin "../../../ip65-build/…"                     -> PRIMARY's bytes
;   --bin-include-dir <abs> + .incbin "ip65-c64.bin"    -> worktree's
;
; Note `-I` does NOT feed .incbin — that is the source-include path, and
; pointing it at a blob directory fails with "Cannot open include file"
; even though the file is sitting in it. Binary includes have their own
; search path, hence --bin-include-dir.
;
; Two properties worth preserving if this is ever respelled: an absent
; blob now FAILS the assemble instead of quietly resolving elsewhere, and
; adding the flag while leaving a `../` operand in place would silently
; keep the old behaviour — the operand is the load-bearing half.
;
; The build ORDER is guaranteed separately, by an explicit dependency edge
; in the Makefile (build/net/ip65/ip65_blob.o: $(IP65_BIN)) — make cannot
; see through .incbin, so without it this object could be assembled before
; the blob exists (issue #89).
.incbin "ip65-c64.bin"
