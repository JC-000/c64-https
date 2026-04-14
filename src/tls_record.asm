; =============================================================================
; tls_record.asm - TLS 1.3 record layer
;
; TLS record format (RFC 8446 Section 5.1):
;   ContentType     (1 byte)  -- always 23 (application_data) for encrypted
;   ProtocolVersion (2 bytes) -- always 0x0303 (TLS 1.2 for compatibility)
;   Length          (2 bytes) -- big-endian, max 16384+256
;   Fragment        (n bytes) -- encrypted payload + 16-byte AEAD tag
;
; For encrypted records, the actual content type is appended to the plaintext
; before encryption (inner content type), and the outer type is always 23.
;
; We negotiate max_fragment_length = 512 bytes to fit C64 RAM constraints.
; With 16-byte Poly1305 tag + 1-byte inner content type, max encrypted
; record payload = 512 + 1 + 16 = 529 bytes.
; =============================================================================

; =============================================================================
; tls_select_keys - Select key/IV/seq pointers based on direction and state
;
; Input:  A = direction (0=write, 1=read)
; Output: zp_ptr ($FB) = IV pointer
;         tls_rec_ptr ($1E) = sequence number pointer
;         aead_key filled with the appropriate 32-byte key
; Uses tls_state: < TLS_STATE_CONNECTED -> handshake keys, else -> app keys
; Clobbers: A, X, Y
; =============================================================================
tls_select_keys:
        sta tls_direction
        ; Determine key phase: handshake or application
        lda tls_state
        cmp #TLS_STATE_CONNECTED
        bcs @app_keys

        ; --- Handshake keys ---
        lda tls_direction
        bne @hs_read
        ; Handshake write
        lda #<tls_hs_write_iv
        sta zp_ptr
        lda #>tls_hs_write_iv
        sta zp_ptr+1
        lda #<tls_hs_write_key
        ldx #>tls_hs_write_key
        jmp @copy_key_and_seq
@hs_read:
        lda #<tls_hs_read_iv
        sta zp_ptr
        lda #>tls_hs_read_iv
        sta zp_ptr+1
        lda #<tls_hs_read_key
        ldx #>tls_hs_read_key
        jmp @copy_key_and_seq

@app_keys:
        lda tls_direction
        bne @app_read
        ; Application write
        lda #<tls_app_write_iv
        sta zp_ptr
        lda #>tls_app_write_iv
        sta zp_ptr+1
        lda #<tls_app_write_key
        ldx #>tls_app_write_key
        jmp @copy_key_and_seq
@app_read:
        lda #<tls_app_read_iv
        sta zp_ptr
        lda #>tls_app_read_iv
        sta zp_ptr+1
        lda #<tls_app_read_key
        ldx #>tls_app_read_key
        ; fall through

@copy_key_and_seq:
        ; A/X = low/high of key source address
        ; Copy 32-byte key to aead_key
        sta zp_temp             ; save key ptr low
        stx zp_temp+1           ; borrow zp_count for key ptr high
        ; Use zp_temp as a temp pointer - store in tls_rec_ptr temporarily
        lda zp_temp
        sta tls_rec_ptr
        lda zp_temp+1
        sta tls_rec_ptr+1
        ldy #0
@copy_key:
        lda (tls_rec_ptr),y
        sta aead_key,y
        iny
        cpy #32
        bne @copy_key

        ; Set tls_rec_ptr to the correct sequence number
        lda tls_direction
        bne @read_seq
        lda #<tls_write_seq
        sta tls_rec_ptr
        lda #>tls_write_seq
        sta tls_rec_ptr+1
        rts
@read_seq:
        lda #<tls_read_seq
        sta tls_rec_ptr
        lda #>tls_read_seq
        sta tls_rec_ptr+1
        rts

; =============================================================================
; tls_build_nonce - Build AEAD nonce from IV and sequence number (RFC 8446 S5.3)
;
; Input:  A = direction (0=write nonce, 1=read nonce)
; Output: tls_nonce (12 bytes)
;         Also sets up aead_key via tls_select_keys
;
; nonce[0..3]  = iv[0..3]  (seq is left-padded with 4 zero bytes)
; nonce[4..11] = iv[4..11] XOR seq[0..7]
;
; Clobbers: A, X, Y
; =============================================================================
tls_build_nonce:
        ; Select keys, IV pointer (zp_ptr), and seq pointer (tls_rec_ptr)
        jsr tls_select_keys

        ; Copy iv[0..3] to tls_nonce[0..3] (unrolled)
        ldy #0
        lda (zp_ptr),y
        sta tls_nonce
        iny
        lda (zp_ptr),y
        sta tls_nonce+1
        iny
        lda (zp_ptr),y
        sta tls_nonce+2
        iny
        lda (zp_ptr),y
        sta tls_nonce+3

        ; Advance zp_ptr by 4 so it points to iv[4]
        clc
        lda zp_ptr
        adc #4
        sta zp_ptr
        bcc @no_carry
        inc zp_ptr+1
@no_carry:
        ; XOR iv[4..11] with seq[0..7], store in tls_nonce[4..11]
        ldy #7
@xor_loop:
        lda (zp_ptr),y
        eor (tls_rec_ptr),y
        sta tls_nonce+4,y
        dey
        bpl @xor_loop

        rts

; =============================================================================
; tls_seq_increment - Increment 64-bit big-endian sequence number
;
; Input:  tls_rec_ptr ($1E) points to 8-byte sequence number (big-endian)
; Clobbers: A, Y
; =============================================================================
tls_seq_increment:
        ldy #7                  ; start at least-significant byte
        lda (tls_rec_ptr),y
        clc
        adc #1
        sta (tls_rec_ptr),y
        bcc @done               ; no carry, we're done
        dey
@carry_loop:
        lda (tls_rec_ptr),y
        adc #0                  ; carry is set from previous add
        sta (tls_rec_ptr),y
        bcc @done
        dey
        bpl @carry_loop
@done:
        rts

; =============================================================================
; tls_record_encrypt - Encrypt plaintext in tls_rec_buf for sending
;
; Input:  tls_rec_buf = plaintext
;         tls_rec_len = plaintext length (16-bit LE)
;         tls_rec_type = inner content type to append
; Output: tls_rec_buf = ciphertext || tag (in-place)
;         tls_rec_len updated to ciphertext + inner_type + tag length
;         tls_rec_header = 5-byte TLS record header (built as AAD)
;         C=0 success
; Clobbers: A, X, Y
; =============================================================================
tls_record_encrypt:
        ; --- 1. Append inner content type after plaintext ---
        ; Index = tls_rec_len (16-bit), but we only support <=512 so high byte
        ; is at most 1. Use zp_ptr to index into tls_rec_buf.
        lda tls_rec_type
        ldx tls_rec_len+1       ; high byte of length
        beq @append_lo          ; if 0, offset < 256
        ; high byte = 1: offset >= 256, use tls_rec_buf+256 base
        ldy tls_rec_len         ; low byte is offset within second page
        sta tls_rec_buf+256,y
        jmp @calc_lengths
@append_lo:
        ldy tls_rec_len
        sta tls_rec_buf,y

@calc_lengths:
        ; --- 2. Calculate AEAD plaintext length = rec_len + 1 (inner type) ---
        ; Save in tls_enc_aead_len (NOT zp_temp — it gets clobbered by tls_select_keys)
        clc
        lda tls_rec_len
        adc #1
        sta tls_enc_aead_len    ; AEAD plaintext length low
        lda tls_rec_len+1
        adc #0
        sta tls_enc_aead_len+1  ; AEAD plaintext length high

        ; --- 3. Build record header (AAD) ---
        ; header[0] = 23 (TLS_CT_APPLICATION)
        lda #TLS_CT_APPLICATION
        sta tls_rec_header
        ; header[1..2] = 0x0303
        lda #$03
        sta tls_rec_header+1
        sta tls_rec_header+2
        ; header[3..4] = (plaintext_len + 1 + 16) big-endian
        ; total = AEAD_plaintext_len + 16
        clc
        lda tls_enc_aead_len    ; AEAD plaintext low
        adc #16
        tax                     ; save low byte in X
        lda tls_enc_aead_len+1  ; AEAD plaintext high
        adc #0
        sta tls_rec_header+3    ; high byte first (big-endian)
        stx tls_rec_header+4    ; low byte second

        ; --- 4. Build nonce (write direction) ---
        lda #0                  ; direction = write
        jsr tls_build_nonce

        ; --- 5. Set up AEAD parameters ---
        ; aead_key already copied by tls_select_keys (called from tls_build_nonce)

        ; Copy tls_nonce -> aead_nonce
        ldx #11
@copy_nonce:
        lda tls_nonce,x
        sta aead_nonce,x
        dex
        bpl @copy_nonce

        ; aead_aad_ptr -> tls_rec_header
        lda #<tls_rec_header
        sta aead_aad_ptr
        lda #>tls_rec_header
        sta aead_aad_ptr+1

        ; aead_aad_len = 5
        lda #5
        sta aead_aad_len

        ; aead_data_ptr -> tls_rec_buf
        lda #<tls_rec_buf
        sta aead_data_ptr
        lda #>tls_rec_buf
        sta aead_data_ptr+1

        ; aead_data_len = AEAD plaintext length (16-bit)
        lda tls_enc_aead_len
        sta aead_data_len
        lda tls_enc_aead_len+1
        sta aead_data_len+1

        ; --- 6. Encrypt ---
        jsr aead_encrypt

        ; --- 7. Copy poly1305_tag (16 bytes) to end of ciphertext ---
        ; Destination = tls_rec_buf + AEAD plaintext length
        ; Use zp_ptr to point to destination
        clc
        lda #<tls_rec_buf
        adc tls_enc_aead_len    ; AEAD plaintext len low
        sta zp_ptr
        lda #>tls_rec_buf
        adc tls_enc_aead_len+1  ; AEAD plaintext len high
        sta zp_ptr+1

        ldy #0
@copy_tag:
        lda poly1305_tag,y
        sta (zp_ptr),y
        iny
        cpy #16
        bne @copy_tag

        ; --- 8. Update tls_rec_len = AEAD plaintext length + 16 ---
        clc
        lda tls_enc_aead_len
        adc #16
        sta tls_rec_len
        lda tls_enc_aead_len+1
        adc #0
        sta tls_rec_len+1

        ; --- 9. Increment write sequence number ---
        ; tls_rec_ptr was set by tls_build_nonce -> tls_select_keys to write_seq
        ; but tls_rec_ptr may have been clobbered by AEAD, so reset it
        lda #<tls_write_seq
        sta tls_rec_ptr
        lda #>tls_write_seq
        sta tls_rec_ptr+1
        jsr tls_seq_increment

        ; --- 10. Success ---
        clc
        rts

; =============================================================================
; tls_record_decrypt - Decrypt received encrypted record in-place
;
; Input:  tls_rec_buf = encrypted payload (ciphertext + 16-byte tag)
;         tls_rec_len = total length (16-bit LE, ciphertext + tag)
;         tls_rec_header = 5-byte record header (used as AAD)
; Output: tls_rec_buf = decrypted plaintext (inner type stripped)
;         tls_rec_type = inner content type
;         tls_rec_len = plaintext length (minus inner type byte)
;         C=0 success, C=1 AEAD verification failed
; Clobbers: A, X, Y
; =============================================================================
tls_record_decrypt:
        ; --- 1. Calculate ciphertext length = tls_rec_len - 16 ---
        sec
        lda tls_rec_len
        sbc #16
        sta tls_enc_aead_len    ; ciphertext_len low
        lda tls_rec_len+1
        sbc #0
        sta tls_enc_aead_len+1  ; ciphertext_len high

        ; --- 2. Copy last 16 bytes of payload to aead_tag ---
        ; Tag starts at tls_rec_buf + ciphertext_len
        clc
        lda #<tls_rec_buf
        adc tls_enc_aead_len
        sta zp_ptr
        lda #>tls_rec_buf
        adc tls_enc_aead_len+1
        sta zp_ptr+1

        ldy #0
@copy_tag_in:
        lda (zp_ptr),y
        sta aead_tag,y
        iny
        cpy #16
        bne @copy_tag_in

        ; --- 3. Build nonce (read direction) ---
        lda #1                  ; direction = read
        jsr tls_build_nonce

        ; --- 4. Set up AEAD parameters ---
        ; aead_key already set by tls_select_keys

        ; Copy tls_nonce -> aead_nonce
        ldx #11
@copy_nonce_d:
        lda tls_nonce,x
        sta aead_nonce,x
        dex
        bpl @copy_nonce_d

        ; aead_aad_ptr -> tls_rec_header
        lda #<tls_rec_header
        sta aead_aad_ptr
        lda #>tls_rec_header
        sta aead_aad_ptr+1

        ; aead_aad_len = 5
        lda #5
        sta aead_aad_len

        ; aead_data_ptr -> tls_rec_buf
        lda #<tls_rec_buf
        sta aead_data_ptr
        lda #>tls_rec_buf
        sta aead_data_ptr+1

        ; aead_data_len = ciphertext_len (16-bit)
        lda tls_enc_aead_len
        sta aead_data_len
        lda tls_enc_aead_len+1
        sta aead_data_len+1

        ; --- 5. Decrypt and verify ---
        jsr aead_decrypt

        ; --- 6. Check result ---
        cmp #0
        bne @auth_fail

        ; --- 7. Extract inner content type (last byte of decrypted plaintext) ---
        ; Inner type is at tls_rec_buf[ciphertext_len - 1]
        ; tls_enc_aead_len still has ciphertext_len (not clobbered by AEAD)
        ; Compute index = ciphertext_len - 1
        sec
        lda tls_enc_aead_len
        sbc #1
        tay                     ; Y = (ciphertext_len - 1) low byte
        lda tls_enc_aead_len+1
        sbc #0
        beq @inner_lo_page      ; if high byte = 0, in first page
        ; High page: read from tls_rec_buf+256,y
        lda tls_rec_buf+256,y
        jmp @got_inner_type
@inner_lo_page:
        lda tls_rec_buf,y
@got_inner_type:
        sta tls_rec_type

        ; --- 8. Update tls_rec_len = ciphertext_len - 1 ---
        sec
        lda tls_enc_aead_len
        sbc #1
        sta tls_rec_len
        lda tls_enc_aead_len+1
        sbc #0
        sta tls_rec_len+1

        ; --- 9. Increment read sequence number ---
        lda #<tls_read_seq
        sta tls_rec_ptr
        lda #>tls_read_seq
        sta tls_rec_ptr+1
        jsr tls_seq_increment

        ; --- 10. Success ---
        clc
        rts

@auth_fail:
        sec
        rts

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
        jsr tls_record_encrypt
        bcs @fail
        jmp @send

@send_plain:
        ; build plaintext record header
        jsr @build_header
        ; send header + payload via TCP
        jsr @send_header
        bcs @fail
        jmp @send_payload

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
@send_payload:
@send:
        ; send header + payload via tls_record_io
        jsr tls_send_record
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
        ; Delegates to tls_recv_record (tls_record_io.asm) which handles
        ; header parsing, validation, and payload buffering.
        jsr tls_recv_record
        rts

; =============================================================================
; Record layer working data (inline, not in data.asm)
; =============================================================================
tls_enc_aead_len:       !word 0 ; AEAD plaintext/ciphertext length (survives ZP clobber)
