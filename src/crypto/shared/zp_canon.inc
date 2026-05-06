; =============================================================================
; zp_canon.inc - Canonical zero-page map for c64-https and sibling crypto libs
;
; Authoritative copy of the crypto zero-page assignments. Sibling libraries
; (`c64-x25519`, `c64-ChaCha20-Poly1305`, `c64-nist-curves`) wrap every ZP
; equate in `.ifndef`/`.endif` so this file can be the single source of truth
; passed via `ca65 --asm-define <name>=<addr>` or via `.include` at build
; time.
;
; Each equate is wrapped in `.ifndef` so downstream users may override
; individual addresses by pre-defining them on the ca65 command line.
;
; Layout mirrors `src/constants.inc:44-107` verbatim. When `constants.inc`
; is pruned in Phase G, this file remains.
; =============================================================================

; --- Shared tmp (used by both crypto and general code) ---
.ifndef zp_tmp1
zp_tmp1         = $02           ; general temp
.endif
.ifndef zp_tmp2
zp_tmp2         = $03           ; general temp
.endif

; --- word32 pointers (ChaCha20 / Poly1305 via wireguard) ---
.ifndef w32_src1
w32_src1        = $04           ; 2 bytes ($04-$05)
.endif
.ifndef w32_src2
w32_src2        = $06           ; 2 bytes ($06-$07)
.endif
.ifndef w32_dst
w32_dst         = $08           ; 2 bytes ($08-$09)
.endif

; --- SHA-256 accumulators ---
.ifndef sha_temp1
sha_temp1       = $0a           ; 4 bytes ($0A-$0D)
.endif
.ifndef sha_temp2
sha_temp2       = $0e           ; 4 bytes ($0E-$11)
.endif
.ifndef sha256_round
sha256_round    = $12           ; 1 byte
.endif

; --- ChaCha20 state / mult66 pointers (time-shared: fe25519 and ChaCha20 never run simultaneously) ---
.ifndef cc20_round
cc20_round      = $14           ; 1 byte
.endif
.ifndef cc20_qr_idx
cc20_qr_idx     = $15           ; 1 byte
.endif
.ifndef cc20_data_ptr
cc20_data_ptr   = $16           ; 2 bytes ($16-$17)
.endif
.ifndef cc20_remain
cc20_remain     = $18           ; low byte of 16-bit ChaCha20/AEAD length
.endif
.ifndef cc20_buf_pos
cc20_buf_pos    = $19           ; 1 byte
.endif

; --- mult66 indirect-indexed multiply pointers (time-shared with ChaCha20) ---
.ifndef lmul0
lmul0           = $14           ; 2 bytes ($14-$15) — sqtab lookup pointer
.endif
.ifndef lmul1
lmul1           = $16           ; 2 bytes ($16-$17) — sqtab_hi lookup pointer
.endif

; --- Poly1305 state ---
.ifndef poly_i
poly_i          = $1a           ; 1 byte
.endif
.ifndef poly_j
poly_j          = $1b           ; 1 byte
.endif
.ifndef poly_carry
poly_carry      = $1c           ; 1 byte
.endif
.ifndef poly_tmp
poly_tmp        = $1d           ; 1 byte
.endif

; --- TLS record layer ---
.ifndef tls_rec_ptr
tls_rec_ptr     = $1e           ; 2 bytes ($1E-$1F)
.endif
.ifndef tls_rec_idx
tls_rec_idx     = $20           ; 1 byte
.endif
.ifndef tls_direction
tls_direction   = $21           ; 1 byte
.endif

; --- ECDSA P-256/P-384 bignum arithmetic ---
; Overlaps with x25519 at $39-$3A but the two never run simultaneously.
.ifndef fp_src1
fp_src1         = $22           ; 2 bytes ($22-$23)
.endif
.ifndef fp_src2
fp_src2         = $24           ; 2 bytes ($24-$25)
.endif
.ifndef fp_dst
fp_dst          = $26           ; 2 bytes ($26-$27)
.endif
.ifndef fp_misc
fp_misc         = $28           ; 2 bytes ($28-$29)
.endif
.ifndef fp_carry
fp_carry        = $2a           ; 1 byte
.endif
.ifndef fp_loop
fp_loop         = $2b           ; 1 byte
.endif
.ifndef fp_mul_i
fp_mul_i        = $39           ; 1 byte (shares with x25_byte_idx)
.endif
.ifndef fp_mul_j
fp_mul_j        = $3a           ; 1 byte (shares with x25_bit_mask)
.endif
.ifndef ec_scalar_ptr
ec_scalar_ptr   = $3b           ; 2 bytes ($3B-$3C)
.endif

; --- fe25519 field arithmetic ---
.ifndef fe_src1
fe_src1         = $2c           ; 2 bytes ($2C-$2D)
.endif
.ifndef fe_src2
fe_src2         = $2e           ; 2 bytes ($2E-$2F)
.endif
.ifndef fe_dst
fe_dst          = $30           ; 2 bytes ($30-$31)
.endif
.ifndef fe_carry
fe_carry        = $32           ; 1 byte
.endif
.ifndef fe_loop
fe_loop         = $33           ; 1 byte
.endif
.ifndef fe_mul_i
fe_mul_i        = $34           ; 1 byte
.endif
.ifndef fe_mul_j
fe_mul_j        = $35           ; 1 byte
.endif
; $36-$37 reserved (fe25519 uses fe_tmp1..4 as 32-byte data labels)

; --- x25519 state ---
.ifndef x25_prev_bit
x25_prev_bit    = $38           ; 1 byte — previous k_t for swap
.endif
.ifndef x25_byte_idx
x25_byte_idx    = $39           ; 1 byte — byte index in scalar
.endif
.ifndef x25_bit_mask
x25_bit_mask    = $3a           ; 1 byte — current bit mask
.endif
