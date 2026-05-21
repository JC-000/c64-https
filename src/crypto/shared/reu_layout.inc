; =============================================================================
; reu_layout.inc - Authoritative REU (Ram Expansion Unit) bank map
;
; The REU is the backing store for all oversize crypto tables plus the
; three swappable crypto overlays (x25519, P-256, P-384).
;
; Bank map (REU 24-bit address):
;   $00000-$1FFFF  (banks 0-1, 128 KB)  x25519 mul tables
;   $20000-$2FFFF  (bank 2,     64 KB)  overlay store (3x 8 KB slots + slack)
;   $30000-$3FFFF  (bank 3,     64 KB)  P-256 precompute
;   $40000-$7FFFF  (banks 4-7, 256 KB)  P-384 precompute + headroom
;
; Each overlay image is 8 KB. The live overlay slot (CRYPTO_OVERLAY
; region, 8 KB on ip65 / 7.75 KB on UCI) is loaded by `crypto_swap_to_*`
; from the overlay store bank.
;
; Downstream libs pick up their bases via `--asm-define REU_BASE_<LIB>=…`
; or by including this file.
; =============================================================================

; --- x25519 mul tables (2 banks, used by in-tree reu_mul_init in boot.s) ---
.ifndef REU_X25519_MUL_TABLES_BASE
REU_X25519_MUL_TABLES_BASE = $00000
.endif

; --- overlay storage (single bank; 8 KB slots for P-256 and P-384) ---
; The x25519 overlay slot was removed after the Phase C.1 integration
; was rolled back — in-tree x25519 is always-resident. Offset $0100
; base kept for the remaining slots to match the external P-384 test
; harness's stash layout.
.ifndef REU_OVERLAY_STORE_BASE
REU_OVERLAY_STORE_BASE     = $20100
.endif
.ifndef REU_OVERLAY_P256
REU_OVERLAY_P256           = $22100
.endif
.ifndef REU_OVERLAY_P384
REU_OVERLAY_P384           = $24100
.endif

; --- W3: P-256 verify overlay image (library-ingestion architecture §2.5) ---
; The architecture plan §2.5 proposes "bank 2 at offset $1F00" for this
; image.  Offset $1F00 falls inside the slot-1 span ($20100-$22100), so
; we reuse the existing REU_OVERLAY_P256 slot at $22100 instead: it is
; the second 8 KB-aligned slot in bank 2, it is already 8 KB-padded
; (matching OVERLAY_SIZE), and it has been declared since Phase 1.5
; without a current production consumer (the P-256 sibling is always-
; resident, no live overlay swap).  This avoids carving a second slot
; out of bank 2.  The alias is `.ifndef`-guarded; downstream override
; via `--asm-define REU_OVERLAY_P256_VERIFY=$xxxxx` remains available.
.ifndef REU_OVERLAY_P256_VERIFY
REU_OVERLAY_P256_VERIFY    = REU_OVERLAY_P256
.endif

; --- W3: X25519 sibling overlay image (library-ingestion architecture §2.5) ---
; Architecture plan §2.5: "x25519 sibling tables get bank 3 (resolves
; the c64-x25519 #43 collision concern)."  Bank 3 ($30000) was nominally
; reserved for P-256 fixed-base precompute, but the TLS path uses
; ec_scalar_mul_var (variable-base) only — the reservation has no
; runtime consumer.  Using bank 3 for the X25519 sibling code+rodata
; image keeps the production overlay store (bank 2) free for the
; existing P-384 SHA384/Curve halves at $22100/$24100 and the new
; P-256 verify slot above.
;
; This is the IMAGE address (DMA source for `crypto_swap_to_x25519`)
; — the sibling's running mul/doubled/17-bit-carry tables continue to
; live in their own REU homes (currently banks 0-2 under v0.4.0).
; When c64-x25519 #43 lands and the sibling's table bases become
; `--asm-define`-able, the consumer-side override will relocate the
; sibling tables (e.g. to bank 4+) so they don't collide with the
; bank-3 image staging.  Until then, USE_X25519_SIBLING=1 + a real
; `crypto_swap_to_x25519` overwrite of CRYPTO_OVERLAY is gated behind
; W1's hot/cold partition (no current TLS caller).
.ifndef REU_OVERLAY_X25519
REU_OVERLAY_X25519         = $30000
.endif

; --- P-256 precompute (1 bank) ---
; NB: REU_OVERLAY_X25519 above lives at the same bank ($30000).  Both
; are reservations -- the P-256 precompute is unused at runtime (the
; TLS dispatcher uses variable-base scalar mul, no Lim-Lee table),
; and the X25519 sibling image is similarly cold until W1 wires a
; real swap into TLS.  When either becomes hot, the cfg has to pick
; one and relocate the other.
.ifndef REU_P256_PRECOMPUTE_BASE
REU_P256_PRECOMPUTE_BASE   = $30000
.endif

; --- P-384 precompute (4 banks at $40000-$5FFFF) ---
; Banks 4-5 are reserved for any future Lim-Lee-style precompute table
; for P-384 fixed-base scalar mul.  Currently unused: the Phase 1b/1.5
; overlay strips the Lim-Lee body and replaces it with a shim that
; tail-calls ec_scalar_mul_var_384 (no precompute).
.ifndef REU_P384_PRECOMPUTE_BASE
REU_P384_PRECOMPUTE_BASE   = $40000
.endif

; --- P-384 split-overlay storage (Phase 1.5) ---
; Phase 1b's monolithic OVERLAY_P384 (12.5 KB) overflowed the live UCI
; CRYPTO_OVERLAY slot (7.5 KB).  The fix: two halves, loaded one at a
; time on demand.  Bank 6 holds the SHA-384 hash code; bank 7 holds the
; curve / verify code.  Each image is padded to OVERLAY_SIZE (8 KB) for
; DMA alignment; actual code is < 7,680 B per half (fits the live slot).
;
; Layout (REU 24-bit address):
;   $60000-$6FFFF  bank 6 (64 KB)  REU_OVERLAY_P384_SHA384
;                                  (8 KB image; remaining 56 KB headroom)
;   $70000-$7FFFF  bank 7 (64 KB)  REU_OVERLAY_P384_CURVE
;                                  (8 KB image; remaining 56 KB headroom)
;
; The TLS path (Phase 4a) drives the two halves in sequence:
;   1. crypto_swap_to_p384_sha384 -> sha384_init/update/final
;   2. crypto_swap_to_p384_curve  -> ecdsa_verify_384 (digest pre-staged
;                                    in resident DATA at ecdsa_inputs_384[96..143])
; Phase 3 will add the swap entry points; the existing
; crypto_swap_to_p384 (single-image) is now stale.
.ifndef REU_OVERLAY_P384_SHA384
REU_OVERLAY_P384_SHA384    = $60000
.endif
.ifndef REU_OVERLAY_P384_CURVE
REU_OVERLAY_P384_CURVE     = $70000
.endif

; --- Phase C.5 collision note (USE_X25519_SIBLING=1) ---
; The sibling c64-x25519 v0.4.0 reu_mul_init populates banks 3, 4, and 5
; with its own doubled-product and 17th-bit-carry tables for fe25519_sqr.
; Banks 3 / 4 / 5 are also nominally reserved here for P-256 precompute
; (bank 3) and P-384 precompute (banks 4-5). The collision is THEORETICAL
; under the current TLS path:
;   - P-256 always uses ec_scalar_mul_var (variable-base) which does not
;     touch REU_P256_PRECOMPUTE_BASE.
;   - P-384 is stubbed at the TLS layer (see project_p384_stubbed memory
;     note); the smoke-test overlay loader uses banks 4-5 only at test
;     time, not in the production handshake.
; If either P-256 fixed-base scalar mul or P-384 precompute is ever
; wired into the production TLS path while USE_X25519_SIBLING=1, the
; sibling's banks 3-5 tables get clobbered and X25519 silently corrupts.
; Resolve at that time by relocating one or the other (the sibling's
; cfg/x25519.cfg pins these via SYMBOLS — downstream override available).

; --- overlay slot size (bytes) ---
; Each overlay image occupies exactly this many bytes in the REU store
; and is DMA'd into the live CRYPTO_OVERLAY region at runtime.
;
; Phase 3: trimmed from $2000 (8 KB) to $1E00 (7,680 B) to match the
; actual live UCI CRYPTO_OVERLAY slot ($4200-$5FFF) and the padded
; .bin image size from tools/integration/build_nistcurves_p384_bin.sh
; (`SLOT_BYTES=7680`).  The previous $2000 value caused crypto_swap.s
; to DMA 512 bytes past the slot, into the start of CRYPTO_RESIDENT
; RODATA at $6000-$61FF -- silently corrupting that range on every
; swap.  Tests didn't catch it because no code read $6000+ between
; back-to-back swaps; the production TLS path (Phase 4a) WOULD have
; been broken by it.
.ifndef OVERLAY_SIZE
OVERLAY_SIZE               = $1E00   ; 7,680 B
.endif

; Note: `.export` of these equates happens once in
; `src/crypto/shared/crypto_swap.s` (guarded by `.ifndef REU_LAYOUT_EXPORTED`
; there) — including this file in multiple TUs does not double-export.
