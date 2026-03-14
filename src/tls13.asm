; =============================================================================
; tls13.asm - TLS 1.3 state machine
;
; Orchestrates the TLS 1.3 handshake and application data flow:
;
;   IDLE -> CLIENT_HELLO -> SERVER_HELLO -> ENCRYPTED_EXT ->
;   CERTIFICATE -> CERT_VERIFY -> FINISHED -> CONNECTED
;
; TLS 1.3 full handshake (1-RTT):
;
;   Client                              Server
;   ------                              ------
;   ClientHello          -------->
;     + key_share                       ServerHello
;     + supported_versions              + key_share
;     + signature_algorithms            + supported_versions
;     + server_name              {EncryptedExtensions}
;     + max_fragment_length      {Certificate}
;     + supported_groups         {CertificateVerify}
;                                <--------  {Finished}
;   {Finished}           -------->
;   [Application Data]   <------->  [Application Data]
;
; After ServerHello, all messages are encrypted with handshake keys
; derived from ECDHE shared secret via HKDF.
; After both Finished, traffic keys replace handshake keys.
; =============================================================================

; =============================================================================
; tls_connect - perform full TLS 1.3 handshake
; Input: TCP connection already established
; Output: C=0 success (CONNECTED state), C=1 failure
; =============================================================================
tls_connect:
        ; init state
        lda #TLS_STATE_IDLE
        sta tls_state

        ; generate client random (32 bytes)
        ; jsr drbg_fill_bytes   ; TODO: fill tls_client_random

        ; generate ECDHE keypair
        ; jsr tls_generate_ecdhe_keypair  ; TODO

        ; --- send ClientHello ---
        lda #TLS_STATE_CLIENT_HELLO
        sta tls_state
        jsr tls_send_client_hello
        bcs @error

        ; --- receive ServerHello ---
        lda #TLS_STATE_SERVER_HELLO
        sta tls_state
        jsr tls_recv_server_hello
        bcs @error

        ; derive handshake keys from ECDHE shared secret
        jsr tls_derive_handshake_keys
        bcs @error

        ; --- receive EncryptedExtensions (encrypted) ---
        lda #TLS_STATE_ENCRYPTED_EXT
        sta tls_state
        jsr tls_recv_encrypted
        bcs @error

        ; --- receive Certificate (encrypted) ---
        lda #TLS_STATE_CERTIFICATE
        sta tls_state
        jsr tls_recv_encrypted
        bcs @error

        ; --- receive CertificateVerify (encrypted) ---
        lda #TLS_STATE_CERT_VERIFY
        sta tls_state
        jsr tls_recv_encrypted
        bcs @error

        ; --- receive server Finished (encrypted) ---
        lda #TLS_STATE_FINISHED
        sta tls_state
        jsr tls_recv_encrypted
        bcs @error

        ; verify server Finished
        jsr tls_verify_finished
        bcs @error

        ; derive application traffic keys
        jsr tls_derive_traffic_keys
        bcs @error

        ; --- send client Finished (encrypted) ---
        jsr tls_send_finished
        bcs @error

        ; connected!
        lda #TLS_STATE_CONNECTED
        sta tls_state
        clc
        rts

@error:
        lda #TLS_STATE_ERROR
        sta tls_state
        sec
        rts

; =============================================================================
; tls_send - send application data (encrypted)
; Input: tls_app_ptr/tls_app_len = data to send
; Output: C=0 success, C=1 failure
; Requires: tls_state == TLS_STATE_CONNECTED
; =============================================================================
tls_send:
        ; wrap in TLS record, encrypt with traffic key, send via TCP
        ; jsr tls_record_encrypt        ; TODO
        ; jsr net_tcp_send              ; TODO
        rts

; =============================================================================
; tls_recv - receive and decrypt application data
; Input: none (reads from TCP receive buffer)
; Output: C=0 success (data in tls_app_buf), C=1 no data or error
; =============================================================================
tls_recv:
        ; read TLS record from TCP buffer, decrypt, return plaintext
        ; jsr tls_record_read           ; TODO
        ; jsr tls_record_decrypt        ; TODO
        rts

; =============================================================================
; tls_close - send close_notify alert and tear down
; =============================================================================
tls_close:
        ; jsr tls_send_alert            ; TODO: close_notify
        ; jsr net_tcp_close
        lda #TLS_STATE_IDLE
        sta tls_state
        rts

; =============================================================================
; Stub routines — to be implemented
; =============================================================================
tls_send_client_hello:
        ; TODO: build ClientHello with extensions, send as TLS record
        clc
        rts

tls_recv_server_hello:
        ; TODO: parse ServerHello, extract key_share, server random
        clc
        rts

tls_derive_handshake_keys:
        ; TODO: ECDHE shared secret -> HKDF-Expand-Label -> handshake keys
        clc
        rts

tls_recv_encrypted:
        ; TODO: read encrypted handshake message, decrypt, dispatch by type
        clc
        rts

tls_verify_finished:
        ; TODO: verify server Finished MAC against transcript hash
        clc
        rts

tls_derive_traffic_keys:
        ; TODO: HKDF-Expand-Label with handshake secret -> app traffic keys
        clc
        rts

tls_send_finished:
        ; TODO: compute client Finished MAC, encrypt, send
        clc
        rts
