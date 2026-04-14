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
        lda #<tls_client_random
        sta zp_ptr
        lda #>tls_client_random
        sta zp_ptr+1
        lda #32
        jsr drbg_fill_bytes

        ; generate ECDHE keypair (random private key + compute public key)
        lda #<tls_ecdhe_privkey
        sta zp_ptr
        lda #>tls_ecdhe_privkey
        sta zp_ptr+1
        lda #32
        jsr drbg_fill_bytes
        jsr tls_ecdh_generate_keypair

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
        lda tls_state           ; preserve last attempted state
        sta tls_last_state
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
        ; copy app data from tls_app_ptr to tls_rec_buf
        lda tls_app_ptr
        sta zp_ptr
        lda tls_app_ptr+1
        sta zp_ptr+1
        lda tls_app_len
        sta tls_rec_len
        lda tls_app_len+1
        sta tls_rec_len+1
        ; copy bytes
        ldy #0
@copy:
        cpy tls_app_len
        beq @copy_done
        lda (zp_ptr),y
        sta tls_rec_buf,y
        iny
        bne @copy
@copy_done:
        ; set inner content type and send encrypted
        lda #TLS_CT_APPLICATION
        sta tls_rec_type
        jsr tls_record_send_encrypted
        rts

; =============================================================================
; tls_recv - receive and decrypt application data
; Input: none (reads from TCP receive buffer)
; Output: C=0 success (data in tls_app_buf), C=1 no data or error
; =============================================================================
tls_recv:
        jsr net_poll
        jsr tls_record_recv_and_decrypt
        bcs @recv_fail
        ; verify it's application data
        lda tls_rec_type
        cmp #TLS_CT_APPLICATION
        bne @recv_fail
        ; set tls_app_ptr to tls_rec_buf, tls_app_len to tls_rec_len
        lda #<tls_rec_buf
        sta tls_app_ptr
        lda #>tls_rec_buf
        sta tls_app_ptr+1
        lda tls_rec_len
        sta tls_app_len
        lda tls_rec_len+1
        sta tls_app_len+1
        clc
        rts
@recv_fail:
        sec
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
; tls_send_client_hello - build and send ClientHello, init transcript
; Output: C=0 success, C=1 send failure
; =============================================================================
tls_send_client_hello:
        ; initialize transcript hash
        jsr tls_transcript_init

        ; build ClientHello into tls_hs_buf, sets tls_hs_len
        jsr tls_build_client_hello

        ; copy tls_hs_buf to tls_rec_buf (tls_hs_len bytes)
        ldy #0
@ch_copy:
        cpy tls_hs_len
        beq @ch_copy_done
        lda tls_hs_buf,y
        sta tls_rec_buf,y
        iny
        bne @ch_copy
@ch_copy_done:
        ; set record length
        lda tls_hs_len
        sta tls_rec_len
        lda tls_hs_len+1
        sta tls_rec_len+1

        ; send as plaintext handshake record
        lda #TLS_CT_HANDSHAKE
        jsr tls_record_send_plaintext
        bcs @ch_fail

        ; update transcript with ClientHello
        lda #<tls_hs_buf
        sta zp_ptr
        lda #>tls_hs_buf
        sta zp_ptr+1
        lda tls_hs_len
        sta zp_count
        jsr tls_transcript_update

        clc
        rts
@ch_fail:
        sec
        rts

; =============================================================================
; tls_recv_server_hello - receive and parse ServerHello, update transcript
; Output: C=0 success, C=1 timeout or parse error
; =============================================================================
tls_recv_server_hello:
        lda #$01
        sta tls_recv_progress
        lda #0
        sta @sh_timeout
        sta @sh_timeout+1
        sta tls_recv_poll_count
        sta tls_recv_poll_count+1
@sh_wait:
        inc tls_recv_poll_count
        bne +
        inc tls_recv_poll_count+1
+
        jsr net_poll
        jsr tls_record_recv_and_decrypt
        bcc @sh_got_record
        inc @sh_timeout
        bne @sh_wait
        inc @sh_timeout+1
        bne @sh_wait
        ; timeout
        sec
        rts
@sh_got_record:
        lda #$02
        sta tls_recv_progress
        ; verify content type is handshake
        lda tls_rec_type
        cmp #TLS_CT_HANDSHAKE
        bne @sh_error
        lda #$03
        sta tls_recv_progress

        ; copy tls_rec_buf to tls_hs_buf (tls_rec_len bytes)
        ldy #0
@sh_copy:
        cpy tls_rec_len
        beq @sh_copy_done
        lda tls_rec_buf,y
        sta tls_hs_buf,y
        iny
        bne @sh_copy
@sh_copy_done:
        lda tls_rec_len
        sta tls_hs_len
        lda tls_rec_len+1
        sta tls_hs_len+1
        lda #$04
        sta tls_recv_progress

        ; parse ServerHello
        jsr tls_parse_server_hello
        bcs @sh_error
        lda #$05
        sta tls_recv_progress

        ; compute ECDH shared secret now that tls_server_pubkey is populated
        jsr tls_ecdh_compute_shared
        clc

        ; update transcript with ServerHello
        lda #<tls_hs_buf
        sta zp_ptr
        lda #>tls_hs_buf
        sta zp_ptr+1
        lda tls_hs_len
        sta zp_count
        jsr tls_transcript_update

        clc
        rts
@sh_error:
        sec
        rts
@sh_timeout: !word 0

; tls_derive_handshake_keys — in tls_keyschedule.asm
; tls_derive_traffic_keys — in tls_keyschedule.asm
; tls_verify_finished — in tls_keyschedule.asm

; =============================================================================
; tls_recv_encrypted - receive encrypted handshake msg, decrypt, dispatch
; Output: C=0 success, C=1 timeout/error
; =============================================================================
tls_recv_encrypted:
        lda #0
        sta @enc_timeout
        sta @enc_timeout+1
@enc_wait:
        jsr net_poll
        jsr tls_record_recv_and_decrypt
        bcc @enc_got_record
        inc @enc_timeout
        bne @enc_wait
        inc @enc_timeout+1
        bne @enc_wait
        ; timeout
        sec
        rts
@enc_got_record:
        ; verify inner content type is handshake
        lda tls_rec_type
        cmp #TLS_CT_HANDSHAKE
        bne @enc_error

        ; copy tls_rec_buf to tls_hs_buf
        ldy #0
@enc_copy:
        cpy tls_rec_len
        beq @enc_copy_done
        lda tls_rec_buf,y
        sta tls_hs_buf,y
        iny
        bne @enc_copy
@enc_copy_done:
        lda tls_rec_len
        sta tls_hs_len
        lda tls_rec_len+1
        sta tls_hs_len+1

        ; update transcript with the handshake message
        lda #<tls_hs_buf
        sta zp_ptr
        lda #>tls_hs_buf
        sta zp_ptr+1
        lda tls_hs_len
        sta zp_count
        jsr tls_transcript_update

        ; dispatch based on handshake type (first byte of tls_hs_buf)
        lda tls_hs_buf
        cmp #TLS_HS_ENCRYPTED_EXT
        beq @enc_ok                     ; accept, nothing to extract for MVP
        cmp #TLS_HS_CERTIFICATE
        beq @enc_cert
        cmp #TLS_HS_CERT_VERIFY
        beq @enc_cert_verify
        cmp #TLS_HS_FINISHED
        beq @enc_ok                     ; accept, verified later by tls_verify_finished
        ; unknown handshake type for current state
        bne @enc_error

@enc_cert:
        jsr tls_handle_certificate
        bcs @enc_error
        clc
        rts

@enc_cert_verify:
        jsr tls_handle_cert_verify
        bcs @enc_error
        clc
        rts

@enc_ok:
        clc
        rts
@enc_error:
        sec
        rts
@enc_timeout: !word 0

; =============================================================================
; tls_send_finished - compute client Finished, encrypt, send
; Output: C=0 success, C=1 failure
; =============================================================================
tls_send_finished:
        ; compute client Finished verify_data into tls_hs_buf, sets tls_hs_len
        jsr tls_compute_finished

        ; update transcript with the finished message
        lda #<tls_hs_buf
        sta zp_ptr
        lda #>tls_hs_buf
        sta zp_ptr+1
        lda tls_hs_len
        sta zp_count
        jsr tls_transcript_update

        ; copy tls_hs_buf to tls_rec_buf
        ldy #0
@fin_copy:
        cpy tls_hs_len
        beq @fin_copy_done
        lda tls_hs_buf,y
        sta tls_rec_buf,y
        iny
        bne @fin_copy
@fin_copy_done:
        ; set record length and inner content type
        lda tls_hs_len
        sta tls_rec_len
        lda tls_hs_len+1
        sta tls_rec_len+1
        lda #TLS_CT_HANDSHAKE
        sta tls_rec_type

        ; encrypt and send
        jsr tls_record_send_encrypted
        rts
