; =============================================================================
; tls_record_io.asm - TCP-facing record layer I/O
;
; Handles building TLS record headers, sending records over TCP via
; net_tcp_send, and reading complete records from the TCP receive ring
; buffer via net_recv_byte.
;
; External dependencies:
;   net.asm       — net_tcp_send, net_recv_byte, net_send_len
;   constants.asm — TLS constants, ZP equates
;   data.asm      — tls_rec_header, tls_rec_buf, tls_rec_len, tls_rec_type,
;                   tls_state
;   tls_record.asm — tls_record_decrypt
;
; ZP used: tls_rec_ptr ($1E), tls_rec_idx ($20), zp_ptr ($FB)
; =============================================================================

; Maximum record payload we can buffer (512 data + 1 inner type + 16 tag + 19 pad)
TLS_REC_BUF_MAX = 548

; =============================================================================
; tls_send_record - send a TLS record over TCP
;
; Input:  tls_rec_header (5 bytes) already built
;         tls_rec_buf contains payload, tls_rec_len = payload length
; Output: C=0 success, C=1 TCP send error
; =============================================================================
tls_send_record:
        ; --- Send 5-byte header ---
        lda #<tls_rec_header
        ldx #>tls_rec_header
        ; set net_send_len = 5
        pha
        lda #5
        sta net_send_len
        lda #0
        sta net_send_len+1
        pla
        jsr net_tcp_send
        bcs @fail

        ; --- Send payload ---
        lda #<tls_rec_buf
        ldx #>tls_rec_buf
        ; copy tls_rec_len to net_send_len
        pha
        lda tls_rec_len
        sta net_send_len
        lda tls_rec_len+1
        sta net_send_len+1
        pla
        jsr net_tcp_send
        ; carry already set/clear from net_tcp_send
        rts

@fail:
        sec
        rts

; =============================================================================
; tls_recv_record - read a complete TLS record from TCP receive ring buffer
;
; Output: tls_rec_header (5 bytes), tls_rec_buf (payload),
;         tls_rec_len, tls_rec_type
;         C=0 success (complete record available)
;         C=1 incomplete (not enough data yet) or error
;
; Uses a state machine (tls_recv_state):
;   State 0: reading 5-byte header
;   State 1: reading payload (tls_rec_len bytes)
;
; Designed to be called repeatedly from the main loop.
; =============================================================================
tls_recv_record:
        lda tls_recv_state
        beq @state0_enter       ; state 0: reading header
        jmp @read_payload       ; state 1: reading payload

@state0_enter:
        ; --- State 0: reading header bytes ---
        lda #$02
        sta tls_recv_sub_progress
@read_header:
        jsr net_recv_byte
        bcc +                   ; data available, continue
        jmp @incomplete
+

        ; store byte in tls_rec_header + offset
        ldx tls_recv_count      ; low byte is sufficient (max 5)
        sta tls_rec_header,x

        ; If this was the first byte (header[0] = content type), validate it
        ; immediately. Valid TLS content types are 20..23. Rejecting garbage
        ; early limits resync damage to 1 byte per failed attempt instead of 5.
        cpx #0
        bne @store_continue
        cmp #20
        bcs +
        jmp @error              ; < 20: invalid
+       cmp #24
        bcc @store_continue
        jmp @error              ; >= 24: invalid
@store_continue:

        ; increment tls_recv_count (16-bit)
        inc tls_recv_count
        bne +
        inc tls_recv_count+1
+
        ; have we received all 5 header bytes?
        lda tls_recv_count
        cmp #5
        bne @read_header        ; loop for more header bytes
        lda tls_recv_count+1
        bne @read_header        ; (shouldn't happen, but safe)

        ; --- Parse header ---
        lda #$03
        sta tls_recv_sub_progress
        ; tls_rec_type = header[0]
        lda tls_rec_header
        sta tls_rec_type

        ; Validate version = 0x0303 (header[1..2])
        lda tls_rec_header+1
        cmp #$03
        beq +
        jmp @error
+       lda tls_rec_header+2
        cmp #$03
        beq +
        jmp @error
+
        lda #$04
        sta tls_recv_sub_progress

        ; tls_rec_len = header[3] * 256 + header[4] (big-endian)
        lda tls_rec_header+4    ; low byte
        sta tls_rec_len
        lda tls_rec_header+3    ; high byte
        sta tls_rec_len+1

        ; Validate tls_rec_len <= TLS_REC_BUF_MAX (548 = $0224)
        lda tls_rec_len+1
        cmp #>TLS_REC_BUF_MAX
        bcc @len_ok             ; high byte < 2: definitely ok
        beq +                   ; high byte == 2: check low byte
        jmp @error              ; high byte > 2: too big
+       lda tls_rec_len
        cmp #<TLS_REC_BUF_MAX+1
        bcc @len_ok
        jmp @error              ; low byte >= $25: too big

@len_ok:
        lda #$05
        sta tls_recv_sub_progress
        ; Switch to state 1, reset count
        lda #1
        sta tls_recv_state
        lda #0
        sta tls_recv_count
        sta tls_recv_count+1

        ; If payload length is zero, record is complete immediately
        lda tls_rec_len
        ora tls_rec_len+1
        beq @complete

        ; Fall through to read payload bytes

        ; --- State 1: reading payload bytes ---
@read_payload:
        lda #$06
        sta tls_recv_sub_progress
        jsr net_recv_byte
        bcs @incomplete         ; no data available

        ; Save the received byte
        sta @recv_byte_tmp

        ; Calculate destination: tls_rec_buf + tls_recv_count
        clc
        lda tls_recv_count
        adc #<tls_rec_buf
        sta zp_ptr
        lda tls_recv_count+1
        adc #>tls_rec_buf
        sta zp_ptr+1

        ; Store byte at destination
        lda @recv_byte_tmp
        ldy #0
        sta (zp_ptr),y

        ; Increment tls_recv_count (16-bit)
        inc tls_recv_count
        bne +
        inc tls_recv_count+1
+
        ; Check if tls_recv_count == tls_rec_len
        lda tls_recv_count
        cmp tls_rec_len
        bne @read_payload
        lda tls_recv_count+1
        cmp tls_rec_len+1
        bne @read_payload

        jmp @complete

@recv_byte_tmp: !byte 0

        ; --- Record complete ---
@complete:
        lda #$07
        sta tls_recv_sub_progress
        ; Reset state machine for next record
        lda #0
        sta tls_recv_state
        sta tls_recv_count
        sta tls_recv_count+1
        clc
        rts

@incomplete:
        sec
        rts

@error:
        ; Reset state machine on error
        lda #0
        sta tls_recv_state
        sta tls_recv_count
        sta tls_recv_count+1
        sec
        rts

; =============================================================================
; tls_record_send_plaintext - send a plaintext (unencrypted) TLS record
;
; Input:  A = content type
;         tls_rec_buf = payload data
;         tls_rec_len = payload length
; Output: C=0 success, C=1 TCP send error
;
; Used for ClientHello before encryption is established.
; =============================================================================
tls_record_send_plaintext:
        ; Build 5-byte record header
        ; header[0] = content type
        sta tls_rec_header

        ; header[1..2] = version 0x0303
        lda #$03
        sta tls_rec_header+1
        sta tls_rec_header+2

        ; header[3..4] = length (big-endian)
        lda tls_rec_len+1       ; high byte
        sta tls_rec_header+3
        lda tls_rec_len         ; low byte
        sta tls_rec_header+4

        ; Send the record
        jsr tls_send_record
        rts

; =============================================================================
; tls_record_send_encrypted - send an encrypted TLS record
;
; Input:  tls_rec_buf = plaintext payload
;         tls_rec_len = plaintext length
;         tls_rec_type = inner content type
; Output: C=0 success, C=1 error
;
; Calls tls_record_encrypt (from tls_record.asm) to build the header,
; encrypt in-place, and update tls_rec_len, then sends via TCP.
; =============================================================================
tls_record_send_encrypted:
        ; Encrypt: appends inner content type, encrypts payload+type,
        ; appends Poly1305 tag, builds outer header (type=23, version=0x0303),
        ; updates tls_rec_len to encrypted length.
        jsr tls_record_encrypt
        bcs @enc_fail

        ; Send the encrypted record
        jsr tls_send_record
        rts

@enc_fail:
        sec
        rts

; =============================================================================
; tls_record_recv_and_decrypt - receive a complete record and decrypt if needed
;
; Output: C=0 success (plaintext in tls_rec_buf, type in tls_rec_type)
;         C=1 incomplete, error, or AEAD verification failure
;
; After ServerHello, all incoming records are encrypted. This routine
; handles both plaintext and encrypted records based on tls_state.
; =============================================================================
tls_record_recv_and_decrypt:
@retry:
        lda #$01
        sta tls_recv_sub_progress
        ; Try to receive a complete record
        jsr tls_recv_record
        bcs @recv_incomplete

        ; RFC 8446 Section 5: TLS 1.3 clients MUST ignore ChangeCipherSpec
        ; records sent during the handshake for middlebox compatibility.
        lda tls_rec_type
        cmp #TLS_CT_CHANGE_CIPHER
        beq @retry

        ; Record received. Check if decryption is needed.
        ; After ServerHello (state >= TLS_STATE_ENCRYPTED_EXT), records are encrypted.
        ; The ServerHello record itself is plaintext even though tls_state is
        ; set to SERVER_HELLO during its receipt.
        lda tls_state
        cmp #TLS_STATE_ENCRYPTED_EXT
        bcc @plaintext          ; state < ENCRYPTED_EXT: no decryption

        ; Decrypt the record in-place
        lda #$08
        sta tls_recv_sub_progress
        jsr tls_record_decrypt
        bcs @aead_fail          ; AEAD verification failed
        lda #$09
        sta tls_recv_sub_progress

@plaintext:
        lda #$0A
        sta tls_recv_sub_progress
        clc
        rts

@recv_incomplete:
        sec
        rts

@aead_fail:
        sec
        rts

; =============================================================================
; Module data — state machine for tls_recv_record
; =============================================================================
tls_recv_state: !byte 0        ; 0 = reading header, 1 = reading payload
tls_recv_count: !word 0        ; bytes received so far in current phase
