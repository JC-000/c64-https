; =============================================================================
; tls_handshake.asm - TLS 1.3 handshake message construction and parsing
;
; Builds ClientHello, parses ServerHello, handles transcript hash.
; =============================================================================

; =============================================================================
; tls_build_client_hello - construct ClientHello message
; Output: tls_hs_buf/tls_hs_len contain the ClientHello
; =============================================================================
tls_build_client_hello:
        ; ClientHello structure (RFC 8446 Section 4.1.2):
        ;   ProtocolVersion legacy_version = 0x0303
        ;   Random random (32 bytes)
        ;   opaque legacy_session_id<0..32>  (empty for TLS 1.3)
        ;   CipherSuites cipher_suites<2..2^16-2>
        ;   opaque legacy_compression_methods<1..2^8-1>  (single byte: 0x00)
        ;   Extension extensions<8..2^16-1>
        ;
        ; Extensions we send:
        ;   - supported_versions: TLS 1.3 only
        ;   - supported_groups: secp256r1
        ;   - key_share: our ECDHE public key (65 bytes, uncompressed P-256)
        ;   - signature_algorithms: ecdsa_secp256r1_sha256
        ;   - server_name: target hostname (SNI)
        ;   - max_fragment_length: 512 bytes

        ; TODO: implement
        ; 1. Write legacy_version (0x0303)
        ; 2. Copy tls_client_random (32 bytes)
        ; 3. Empty session ID (length byte = 0)
        ; 4. Cipher suites: length=2, TLS_CHACHA20_POLY1305_SHA256
        ; 5. Compression: length=1, null (0x00)
        ; 6. Extensions (see tls_build_extensions)
        ; 7. Wrap in handshake header (type=1, length)
        ; 8. Feed into transcript hash
        rts

; =============================================================================
; tls_build_extensions - append ClientHello extensions to buffer
; =============================================================================
tls_build_extensions:
        ; TODO: build each extension with type(2) + length(2) + data
        ; Extension order matters for some servers
        rts

; =============================================================================
; tls_parse_server_hello - parse ServerHello message
; Input: tls_hs_buf/tls_hs_len contain raw ServerHello
; Output: C=0 success, C=1 parse error or unsupported
; =============================================================================
tls_parse_server_hello:
        ; ServerHello structure:
        ;   ProtocolVersion legacy_version = 0x0303
        ;   Random random (32 bytes)
        ;   opaque legacy_session_id_echo<0..32>
        ;   CipherSuite cipher_suite (2 bytes)
        ;   uint8 legacy_compression_method = 0
        ;   Extension extensions<6..2^16-1>
        ;
        ; We must find:
        ;   - supported_versions ext confirming TLS 1.3
        ;   - key_share ext with server's ECDHE public key
        ;   - cipher_suite must be TLS_CHACHA20_POLY1305_SHA256
        ;
        ; Special: if random ends with SHA-256("HelloRetryRequest"),
        ; this is actually an HRR and we must handle differently.

        ; TODO: implement parsing
        ; 1. Skip version (2), copy server_random (32)
        ; 2. Skip session_id echo (length-prefixed)
        ; 3. Check cipher_suite == 0x1303
        ; 4. Skip compression (1 byte)
        ; 5. Parse extensions: find supported_versions + key_share
        ; 6. Copy server ECDHE public key to tls_server_pubkey
        ; 7. Feed into transcript hash
        clc
        rts

; =============================================================================
; tls_parse_encrypted_extensions - parse EncryptedExtensions
; Input: decrypted handshake message in tls_hs_buf
; Output: C=0 success, C=1 error
; =============================================================================
tls_parse_encrypted_extensions:
        ; Usually contains max_fragment_length confirmation (if we requested it)
        ; and possibly server_name acknowledgment.
        ; For MVP: just verify message type and skip contents.
        ; TODO
        clc
        rts

; =============================================================================
; Transcript hash management
; The transcript hash is a running SHA-256 over all handshake messages.
; Used for key derivation and Finished MAC computation.
; =============================================================================

; tls_transcript_update - feed handshake message into running hash
; Input: tls_hs_buf/tls_hs_len = message (including handshake header)
tls_transcript_update:
        ; TODO: call sha256_update with the handshake message data
        rts

; tls_transcript_hash - get current transcript hash
; Output: tls_transcript (32 bytes) = SHA-256 of all messages so far
tls_transcript_hash:
        ; TODO: finalize a copy of the running hash state
        ; (must not destroy the running state — clone h0-h7 first)
        rts
