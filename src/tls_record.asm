; =============================================================================
; tls_record.asm - TLS 1.3 record layer
;
; TLS record format (RFC 8446 Section 5.1):
;   ContentType     (1 byte)  — always 23 (application_data) for encrypted
;   ProtocolVersion (2 bytes) — always 0x0303 (TLS 1.2 for compatibility)
;   Length          (2 bytes) — big-endian, max 16384+256
;   Fragment        (n bytes) — encrypted payload + 16-byte AEAD tag
;
; For encrypted records, the actual content type is appended to the plaintext
; before encryption (inner content type), and the outer type is always 23.
;
; We negotiate max_fragment_length = 512 bytes to fit C64 RAM constraints.
; With 16-byte Poly1305 tag + 1-byte inner content type, max encrypted
; record payload = 512 + 1 + 16 = 529 bytes.
; =============================================================================

; =============================================================================
; tls_record_write - build and send a TLS record
; Input: A = content type, tls_rec_ptr/tls_rec_len = plaintext
;        tls_state determines whether to encrypt
; Output: C=0 success, C=1 failure
; =============================================================================
tls_record_write:
        sta tls_rec_type

        ; if in handshake (pre-encryption), send plaintext
        lda tls_state
        cmp #TLS_STATE_SERVER_HELLO
        bcc @send_plain         ; IDLE or CLIENT_HELLO: plaintext

        ; encrypted record: encrypt payload + append inner content type
        jsr @encrypt_record
        bcs @fail
        jmp @send

@send_plain:
        ; build plaintext record header
        jsr @build_header
        ; send header + payload via TCP
        jsr @send_header
        bcs @fail
        jmp @send_payload

@encrypt_record:
        ; TODO:
        ; 1. Copy plaintext to tls_enc_buf
        ; 2. Append inner content type byte
        ; 3. Build AEAD nonce from sequence number XOR IV
        ; 4. Encrypt with ChaCha20-Poly1305 (adds 16-byte tag)
        ; 5. Set outer content type = 23, length = encrypted length
        ; 6. Increment sequence number
        clc
        rts

@build_header:
        ; content type
        lda tls_rec_type
        sta tls_rec_header
        ; protocol version 0x0303
        lda #$03
        sta tls_rec_header+1
        sta tls_rec_header+2
        ; length (big-endian)
        lda tls_rec_len+1       ; high byte
        sta tls_rec_header+3
        lda tls_rec_len         ; low byte
        sta tls_rec_header+4
        rts

@send_header:
        ; TODO: send 5-byte header via net_tcp_send
        clc
        rts

@send_payload:
        ; TODO: send payload via net_tcp_send
@send:
        clc
        rts

@fail:
        sec
        rts

; =============================================================================
; tls_record_read - read a TLS record from TCP receive buffer
; Output: C=0 success (record in tls_rec_buf, type in tls_rec_type),
;         C=1 incomplete/error
; =============================================================================
tls_record_read:
        ; TODO:
        ; 1. Read 5-byte header from net_recv_byte
        ; 2. Validate: version == 0x0303, length <= TLS_RECORD_MAX + 256
        ; 3. Read 'length' bytes of payload into tls_rec_buf
        ; 4. If encrypted, decrypt and strip inner content type
        clc
        rts

; =============================================================================
; tls_record_decrypt - decrypt an encrypted TLS record in-place
; Input: tls_rec_buf contains encrypted payload, tls_rec_len = length
; Output: C=0 success (plaintext in tls_rec_buf, real type in tls_rec_type),
;         C=1 AEAD verification failed
; =============================================================================
tls_record_decrypt:
        ; TODO:
        ; 1. Build nonce from read sequence number XOR read IV
        ; 2. Decrypt with ChaCha20-Poly1305 AEAD
        ; 3. Verify tag (last 16 bytes)
        ; 4. Strip padding zeros, extract inner content type (last non-zero byte)
        ; 5. Increment read sequence number
        clc
        rts

; =============================================================================
; tls_build_nonce - XOR 8-byte sequence number into 12-byte IV
; Input: A=0 for write nonce, A=1 for read nonce
; Output: tls_nonce (12 bytes)
; =============================================================================
tls_build_nonce:
        ; TODO:
        ; iv[0..3] are fixed, iv[4..11] XOR with 64-bit sequence number
        rts
