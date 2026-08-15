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

; Three levels up from this file's directory (src/net/ip65/) is the repo
; root, where ip65-build/ lives.
;
; CAUTION: ca65 does NOT resolve .incbin relative to the including source
; file only — it also tries the path relative to the current directory,
; which is the repo root when make runs. From there `../../../` escapes
; three levels ABOVE the checkout. A git worktree under
; <repo>/.claude/worktrees/<name>/ sits at exactly that depth, so if its
; own ip65-build/ip65-c64.bin is missing this silently picks up the parent
; checkout's blob and the build looks fine. Measure blob behaviour in a
; real clone, never in a nested worktree.
;
; The build order is guaranteed by an explicit dependency edge in the
; Makefile (build/net/ip65/ip65_blob.o: $(IP65_BIN)) — make cannot see
; through .incbin, so without it this object could be assembled before
; the blob exists (issue #89).
.incbin "../../../ip65-build/ip65-c64.bin"
