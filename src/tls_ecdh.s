; tls_ecdh.s — TLS 1.3 ECDH (X25519) wrapper
; Converted from ACME to ca65 in Phase 3 Batch B.
;
; Uses x25519 (RFC 7748) for ephemeral key exchange.
;
; tls_ecdh_generate_keypair:
;   Input: tls_ecdhe_privkey (32 bytes) = random scalar (caller fills with DRBG)
;   Output: tls_ecdhe_pubkey (32 bytes) = x25519 public key
;   Computes: pubkey = x25519(privkey, basepoint_9)
;
; tls_ecdh_compute_shared:
;   Input: tls_ecdhe_privkey (32 bytes) = our private key
;          tls_server_pubkey (32 bytes) = server's public key from key_share
;   Output: tls_shared_secret (32 bytes) = x25519(privkey, server_pubkey)
;
; x25519 API:
;   x25_scalar (32 bytes) = scalar input
;   x25_u (32 bytes)      = u-coordinate input
;   x25_result (32 bytes) = output
;   x25519_base           = scalar * basepoint(9) (clamps + scalarmult)
;   x25519_scalarmult     = scalar * u (raw, caller must clamp)

.include "constants.inc"

.export tls_ecdh_generate_keypair
.export tls_ecdh_compute_shared

.import x25519_base
.import x25519_scalarmult
.import vic_blank
.import vic_unblank
.import x25519_clamp
.import x25_scalar
.import x25_u
.import x25_result
.import tls_ecdhe_privkey
.import tls_ecdhe_pubkey
.import tls_server_pubkey
.import tls_shared_secret

.segment "CODE"

; =============================================================================
; tls_ecdh_generate_keypair
;
; Copy privkey to x25_scalar, call x25519_base (clamps and multiplies by
; basepoint 9), copy result to tls_ecdhe_pubkey.
;
; Clobbers: A, X, Y, all fe_*/x25_* ZP vars
; =============================================================================
tls_ecdh_generate_keypair:
        ; Copy tls_ecdhe_privkey -> x25_scalar
        ldx #31
@copy_priv:
        lda tls_ecdhe_privkey,x
        sta x25_scalar,x
        dex
        bpl @copy_priv

        ; Compute public key = scalar * basepoint(9)
        ; x25519_base handles clamping and copies basepoint to x25_u.
        ; Blanked: no screen output happens inside, and badline DMA costs
        ; ~6.3% of the 6510 (measured, see src/vic.s).
        jsr vic_blank
        jsr x25519_base
        jsr vic_unblank

        ; Copy x25_result -> tls_ecdhe_pubkey
        ldx #31
@copy_pub:
        lda x25_result,x
        sta tls_ecdhe_pubkey,x
        dex
        bpl @copy_pub

        rts

; =============================================================================
; tls_ecdh_compute_shared
;
; Copy privkey to x25_scalar (and clamp it), copy server pubkey to x25_u,
; call x25519_scalarmult, copy result to tls_shared_secret.
;
; Clobbers: A, X, Y, all fe_*/x25_* ZP vars
; =============================================================================
tls_ecdh_compute_shared:
        ; Copy tls_ecdhe_privkey -> x25_scalar
        ldx #31
@copy_priv:
        lda tls_ecdhe_privkey,x
        sta x25_scalar,x
        dex
        bpl @copy_priv

        ; Clamp the scalar per RFC 7748
        jsr x25519_clamp

        ; Copy tls_server_pubkey -> x25_u
        ldx #31
@copy_srv:
        lda tls_server_pubkey,x
        sta x25_u,x
        dex
        bpl @copy_srv

        ; Compute shared secret = scalar * server_pubkey
        jsr vic_blank
        jsr x25519_scalarmult
        jsr vic_unblank

        ; Copy x25_result -> tls_shared_secret
        ldx #31
@copy_ss:
        lda x25_result,x
        sta tls_shared_secret,x
        dex
        bpl @copy_ss

        ; --- All-zero shared secret => abort (issue #153) -------------------
        ; RFC 8446 §7.4.2 and RFC 7748 §6.1 both require this check. A server
        ; (or an on-path attacker rewriting the ServerHello) that sends a
        ; low-order key_share — 32 zero bytes is the simplest of them — forces
        ; x25519(k, U) = 0 for every clamped scalar k. The key schedule then
        ; collapses: handshake_secret = HKDF-Extract(constant, 0^32) is a
        ; constant, and every secret below it is Derive-Secret(constant,
        ; label, Transcript-Hash(CH || SH)) over two PLAINTEXT messages. Any
        ; passive observer who recorded the session can then derive the
        ; traffic keys — the attacker who injected the key_share need not stay
        ; on the path. That is a passive decryption break, not merely the
        ; documented "an active attacker can impersonate any server".
        ;
        ; Checking the OUTPUT (rather than blacklisting known-bad key_shares)
        ; is what the RFC mandates and is what catches every low-order point.
        ; C=1 here aborts the handshake in tls_recv_server_hello.
        ldx #31
        lda #0
@ss_or:
        ora tls_shared_secret,x
        dex
        bpl @ss_or
        tax                     ; Z = (accumulated OR == 0); dex/bpl clobbered it
        bne @ss_ok
        sec
        rts
@ss_ok:
        clc
        rts
