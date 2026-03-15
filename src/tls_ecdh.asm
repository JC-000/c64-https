; =============================================================================
; tls_ecdh.asm - ECDH key exchange wrapper for TLS 1.3
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
; =============================================================================

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
        ; x25519_base handles clamping and copies basepoint to x25_u
        jsr x25519_base

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
        jsr x25519_scalarmult

        ; Copy x25_result -> tls_shared_secret
        ldx #31
@copy_ss:
        lda x25_result,x
        sta tls_shared_secret,x
        dex
        bpl @copy_ss

        rts
