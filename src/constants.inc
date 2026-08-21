; =============================================================================
; constants.inc - System equates, zero page, hardware addresses
;
; Converted from constants.asm (ACME) to ca65 include file. Pure equates,
; no code or data — included by every .s module that needs the symbols.
; ACME `=` assignments are syntactically identical in ca65.
; =============================================================================

; =============================================================================
; C64 system addresses
; =============================================================================
chrout          = $ffd2         ; KERNAL character output
chrin           = $ffcf         ; KERNAL character input
getin           = $ffe4         ; KERNAL get key
setlfs          = $ffba         ; KERNAL set file params
setnam          = $ffbd         ; KERNAL set filename
open            = $ffc0         ; KERNAL open file
close           = $ffc3         ; KERNAL close file
chkin           = $ffc6         ; KERNAL set input channel
chkout          = $ffc9         ; KERNAL set output channel
clrchn          = $ffcc         ; KERNAL clear channels
readst          = $ffb7         ; KERNAL read status
load            = $ffd5         ; KERNAL load

screen_ram      = $0400         ; screen memory
color_ram       = $d800         ; color memory
border_color    = $d020
bg_color        = $d021

; CIA / SID for entropy
sid_osc3        = $d41b         ; SID oscillator 3 output
cia1_ta_lo      = $dc04         ; CIA1 timer A low
cia1_ta_hi      = $dc05         ; CIA1 timer A high
cia1_cra        = $dc0e         ; CIA1 control register A

; =============================================================================
; Zero page assignments — time-shared with ip65 ($02-$1B)
;
; ip65 uses $02-$1B (cc65 standard ZP) during ip65_process / tcp_send / etc.
; Crypto modules use overlapping ranges. Before calling ip65, save $02-$1B
; to zp_save_buf. After ip65 returns, restore. This costs ~60 cycles per
; ip65 call — negligible vs. network latency.
; =============================================================================

; --- Shared tmp (used by both crypto and general code) ---
zp_tmp1         = $02           ; general temp
zp_tmp2         = $03           ; general temp

; --- word32 pointers (ChaCha20 / Poly1305 via wireguard) ---
w32_src1        = $04           ; 2 bytes ($04-$05)
w32_src2        = $06           ; 2 bytes ($06-$07)
w32_dst         = $08           ; 2 bytes ($08-$09)

; --- SHA-256 accumulators ---
sha_temp1       = $0a           ; 4 bytes ($0A-$0D)
sha_temp2       = $0e           ; 4 bytes ($0E-$11)
sha256_round    = $12           ; 1 byte

; --- ChaCha20 state / mult66 pointers (time-shared: fe25519 and ChaCha20 never run simultaneously) ---
cc20_round      = $14           ; 1 byte
cc20_qr_idx     = $15           ; 1 byte
cc20_data_ptr   = $16           ; 2 bytes ($16-$17)
cc20_remain     = $18           ; low byte of 16-bit ChaCha20/AEAD length
                                ; (high byte = cc20_remain_hi in data.asm)
cc20_buf_pos    = $19           ; 1 byte

; --- mult66 indirect-indexed multiply pointers (time-shared with ChaCha20) ---
lmul0           = $14           ; 2 bytes ($14-$15) — sqtab lookup pointer
lmul1           = $16           ; 2 bytes ($16-$17) — sqtab_hi lookup pointer

; --- Poly1305 state ---
poly_i          = $1a           ; 1 byte
poly_j          = $1b           ; 1 byte
poly_carry      = $1c           ; 1 byte
poly_tmp        = $1d           ; 1 byte

; --- TLS record layer ---
tls_rec_ptr     = $1e           ; 2 bytes ($1E-$1F) — pointer to record data
tls_rec_idx     = $20           ; 1 byte — index during record read/write
tls_direction   = $21           ; 1 byte — 0=write, 1=read (key/IV/seq select)

; --- ECDSA P-256/P-384 bignum arithmetic (from c64-aes256-ecdsa) ---
; These overlap with x25519 at $39-$3A but never run simultaneously.
fp_src1         = $22           ; 2 bytes ($22-$23) — operand 1 pointer
fp_src2         = $24           ; 2 bytes ($24-$25) — operand 2 pointer
fp_dst          = $26           ; 2 bytes ($26-$27) — destination pointer
fp_misc         = $28           ; 2 bytes ($28-$29) — modulus pointer
fp_carry        = $2a           ; 1 byte
fp_loop         = $2b           ; 1 byte
fp_mul_i        = $39           ; 1 byte (shares with x25_byte_idx — OK, never simultaneous)
fp_mul_j        = $3a           ; 1 byte (shares with x25_bit_mask — OK)
ec_scalar_ptr   = $3b           ; 2 bytes ($3B-$3C) — scalar for point multiply

; --- fe25519 field arithmetic (relocated from wireguard $1E-$29) ---
fe_src1         = $2c           ; 2 bytes ($2C-$2D) — operand 1 pointer
fe_src2         = $2e           ; 2 bytes ($2E-$2F) — operand 2 pointer
fe_dst          = $30           ; 2 bytes ($30-$31) — destination pointer
fe_carry        = $32           ; 1 byte
fe_loop         = $33           ; 1 byte
fe_mul_i        = $34           ; 1 byte
fe_mul_j        = $35           ; 1 byte
; $36-$37 reserved (fe25519 uses fe_tmp1..4 as 32-byte data labels)

; --- x25519 state (relocated from wireguard $2A-$2D) ---
x25_prev_bit    = $38           ; 1 byte — previous k_t for swap
x25_byte_idx    = $39           ; 1 byte — byte index in scalar
x25_bit_mask    = $3a           ; 1 byte — current bit mask

; --- TLS handshake-message base pointer (W1 streaming deframer) ---
; Points at the current handshake message; the message handlers in
; tls_cert.s / tls_keyschedule.s read the message through this pointer
; instead of hardcoding tls_rec_buf, so the streaming deframer can
; dispatch a message at any offset (tls_rec_buf + N, or a carry buffer).
; $3E-$3F is inside ZP_CRYPTO ($22-$3F) but past the ECDSA bignum claim
; ($22-$3C) and nistcurves_zp_ptr2 ($3D); ECDSA never touches $3E-$3F,
; so the pointer survives across ecdsa_verify inside
; tls_handle_cert_verify.  Do NOT relocate to $36-$37: that pair looks
; free but sits inside fe25519's declared $2C-$37 claim.
tls_hs_ptr      = $3e           ; 2 bytes ($3E-$3F)

; --- General pointers (shared, save/restore around ip65) ---
zp_ptr          = $fb           ; 2 bytes ($FB-$FC)
zp_temp         = $fd           ; 1 byte
zp_count        = $fe           ; 2 bytes ($FE-$FF) — 16-bit count
                                ; (tls_transcript_update reads both bytes;
                                ; single-byte users still write only $FE
                                ; and implicitly leave $FF untouched — OK
                                ; because those call sites don't read $FF)

; --- Quarter-square multiply table (shared by Poly1305 and ECDSA) ---
; sqtab_lo/sqtab_hi now defined as labels in data.asm — moved out of $7800 to free code space

; --- REU (Ram Expansion Unit) registers ---
reu_status      = $df00         ; status register
reu_command     = $df01         ; command register
reu_c64_lo      = $df02         ; C64 base address low
reu_c64_hi      = $df03         ; C64 base address high
reu_reu_lo      = $df04         ; REU base address low
reu_reu_hi      = $df05         ; REU base address high
reu_reu_bank    = $df06         ; REU bank
reu_len_lo      = $df07         ; transfer length low
reu_len_hi      = $df08         ; transfer length high
reu_addr_ctrl   = $df0a         ; address control

; --- SID voice 3 setup for noise (entropy collection) ---
sid_base        = $d400
sid_v3_freq_lo  = $d40e
sid_v3_freq_hi  = $d40f
sid_v3_ctrl     = $d412
sid_v3_ad       = $d413
sid_v3_sr       = $d414

; --- ip65 ZP overlap zone + jump table ---
; Moved to src/net/ip65/ip65_symbols.inc (single source of truth). Files
; that need ip65_* symbols must `.include "ip65_symbols.inc"` directly.

; =============================================================================
; TLS 1.3 constants
; =============================================================================
TLS_VERSION_12          = $0303 ; legacy version in ClientHello
TLS_VERSION_13          = $0304 ; actual TLS 1.3

; content types
TLS_CT_CHANGE_CIPHER    = 20
TLS_CT_ALERT            = 21
TLS_CT_HANDSHAKE        = 22
TLS_CT_APPLICATION      = 23

; handshake types
TLS_HS_CLIENT_HELLO     = 1
TLS_HS_SERVER_HELLO     = 2
TLS_HS_ENCRYPTED_EXT    = 8
TLS_HS_CERTIFICATE      = 11
TLS_HS_CERT_VERIFY      = 15
TLS_HS_FINISHED         = 20

; cipher suite
TLS_CHACHA20_POLY1305_SHA256 = $1303

; named groups
TLS_GROUP_SECP256R1     = $0017
TLS_GROUP_X25519        = $001d

; signature algorithm
TLS_SIG_ECDSA_SECP256R1_SHA256 = $0403

; extensions
TLS_EXT_SERVER_NAME     = $0000
TLS_EXT_MAX_FRAG_LEN    = $0001
TLS_EXT_SUPPORTED_GROUPS = $000a
TLS_EXT_SIG_ALGORITHMS  = $000d
TLS_EXT_SUPPORTED_VERSIONS = $002b
TLS_EXT_KEY_SHARE       = $0033

; max_fragment_length values (RFC 6066)
TLS_MAX_FRAG_512        = 1
TLS_MAX_FRAG_1024       = 2
TLS_MAX_FRAG_2048       = 3
TLS_MAX_FRAG_4096       = 4

; TLS state machine states
TLS_STATE_IDLE          = 0
TLS_STATE_CLIENT_HELLO  = 1
TLS_STATE_SERVER_HELLO  = 2
TLS_STATE_ENCRYPTED_EXT = 3
TLS_STATE_CERTIFICATE   = 4
TLS_STATE_CERT_VERIFY   = 5
TLS_STATE_FINISHED      = 6
TLS_STATE_CONNECTED     = 7
TLS_STATE_ERROR         = $ff

; alert levels
TLS_ALERT_WARNING       = 1
TLS_ALERT_FATAL         = 2

; =============================================================================
; Buffer sizes
; =============================================================================
TLS_RECORD_MAX          = 512   ; negotiated via max_fragment_length
TCP_RECV_BUF_SIZE       = 4096  ; ring buffer for ip65 callback data (masked wrap)
TCP_RECV_MASK           = $0fff ; 12-bit mask for 16-bit head/tail wrap
HTTP_BUF_SIZE           = 256   ; HTTP request/response line buffer

; TCP receive ring buffer lives at $C000-$CFFF (4KB always-RAM region between
; BASIC ROM shadow and I/O). Declared here as an equate rather than in
; data.asm so the PRG/BSS stays small — the RAM exists regardless.
tcp_recv_buf            = $c000
