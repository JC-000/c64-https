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

; --- P-256 precompute (1 bank) ---
.ifndef REU_P256_PRECOMPUTE_BASE
REU_P256_PRECOMPUTE_BASE   = $30000
.endif

; --- P-384 precompute (4 banks) ---
.ifndef REU_P384_PRECOMPUTE_BASE
REU_P384_PRECOMPUTE_BASE   = $40000
.endif

; --- overlay slot size (bytes) ---
; Each overlay image occupies exactly this many bytes in the REU store and
; is DMA'd into the live CRYPTO_OVERLAY region at runtime.
.ifndef OVERLAY_SIZE
OVERLAY_SIZE               = $2000   ; 8 KB
.endif

; Note: `.export` of these equates happens once in
; `src/crypto/shared/crypto_swap.s` (guarded by `.ifndef REU_LAYOUT_EXPORTED`
; there) — including this file in multiple TUs does not double-export.
