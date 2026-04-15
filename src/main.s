; =============================================================================
; main.s - Program entry
; Converted from ACME to ca65 in Phase 3 Batch D.
;
; The original main.asm was a top-level ACME orchestrator that !source'd every
; other .asm file and placed the ip65 binary blob at $2000 and crypto code at
; $6000. Under ca65, each .s file is an independent translation unit, and
; segment placement is driven by the ld65 config (MEMORY/SEGMENTS). So there is
; no orchestration to do here: all !source lines drop away, the !binary ip65
; blob moves to src/net/ip65/ip65_blob.s, and the * = $2000 / * = $6000 anchors
; are enforced by segment placement in the ld65 cfg ("CRYPTO_CODE" etc).
;
; This file therefore contains no code of its own. It exists only so the
; per-file build list stays consistent; it assembles to an empty CODE
; contribution.
; =============================================================================

.segment "CODE"
