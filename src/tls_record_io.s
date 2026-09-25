; tls_record_io.s — TLS record TCP I/O
; Converted from ACME to ca65 in Phase 3 Batch B.
;
; Handles building TLS record headers, sending records over TCP via
; net_tcp_send, and reading complete records from the TCP receive ring
; buffer via net_recv_byte.
;
; External dependencies:
;   net.s        — net_tcp_send, net_recv_byte, net_send_len
;   constants.inc — TLS constants, ZP equates (via .include)
;   data.s       — tls_rec_header, tls_rec_buf, tls_rec_len, tls_rec_type,
;                  tls_state
;   tls_record.s — tls_record_encrypt, tls_record_decrypt
;
; ZP used: tls_rec_ptr ($1E), tls_rec_idx ($20), zp_ptr ($FB)
; =============================================================================

.include "constants.inc"

.export tls_send_record
.export tls_recv_record
.export tls_record_send_plaintext
.export tls_record_send_encrypted
.export tls_record_recv_and_decrypt
.export tls_recv_state
.export tls_recv_count
.export tls_rx_reset

.include "net_abi.inc"          ; net_tcp_send, net_recv_byte, net_send_len
.import tls_record_encrypt
.import tls_record_decrypt
.import tls_rec_header
.import tls_rec_buf
.import tls_rec_len
.import tls_rec_type
.import tls_state
.import tls_last_state
.import tls_recv_sub_progress

.segment "CODE"

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
        bcc :+                  ; data available, continue
        jmp @incomplete
:

        ; store byte in tls_rec_header + offset
        ldx tls_recv_count      ; low byte is sufficient (max 5)
        sta tls_rec_header,x

        ; If this was the first byte (header[0] = content type), validate it
        ; immediately. Valid TLS content types are 20..23. Rejecting garbage
        ; early limits resync damage to 1 byte per failed attempt instead of 5.
        cpx #0
        bne @store_continue
        cmp #20
        bcs :+
        jmp @error              ; < 20: invalid
:       cmp #24
        bcc @store_continue
        jmp @error              ; >= 24: invalid
@store_continue:

        ; increment tls_recv_count (16-bit)
        inc tls_recv_count
        bne :+
        inc tls_recv_count+1
:
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
        beq :+
        jmp @error
:       lda tls_rec_header+2
        cmp #$03
        beq :+
        jmp @error
:
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
        beq :+                  ; high byte == 2: check low byte
        jmp @error              ; high byte > 2: too big
:       lda tls_rec_len
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
        bne :+
        inc tls_recv_count+1
:
        ; Check if tls_recv_count == tls_rec_len
        lda tls_recv_count
        cmp tls_rec_len
        bne @read_payload
        lda tls_recv_count+1
        cmp tls_rec_len+1
        bne @read_payload

        jmp @complete

@recv_byte_tmp: .byte 0

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
        ; Malformed header (type, version or length). Before the handshake
        ; keys this resets the reader and resyncs a byte at a time, as it
        ; always did; once records are encrypted it is fatal (#239) — see
        ; tls_rec_frame_fail. TLS_CODE, off the ip65 LOADER.
        jmp tls_rec_frame_fail

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
; Calls tls_record_encrypt (from tls_record.s) to build the header,
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
;         C=1 and tls_state != TLS_STATE_ERROR: no complete record yet, or
;             a malformed header was skipped — poll again
;         C=1 and tls_state == TLS_STATE_ERROR: AEAD authentication failed,
;             or a malformed record header arrived after ServerHello, and
;             the connection is ABORTED (issue #239) — fatal, stop
;
; After ServerHello, all incoming records are encrypted. This routine
; handles both plaintext and encrypted records based on tls_state.
;
; Issue #239: the tag failure used to return the same bare C=1 as "record
; incomplete", so every caller polled on. After one lost or altered byte
; tls_read_seq stops advancing, every later record fails its tag too, and
; the fetch sat in its tick budget (~87 min on UCI) instead of failing.
; tls_rec_auth_fail now latches the error; each looping caller tests
; bit 7 of tls_state (ERROR is the only state with it set) before counting
; the failure as an idle tick. A header that fails validation once records
; are encrypted latches it too (tls_rec_frame_fail): it used to reset the
; reader and resync one byte at a time through ciphertext, which after a
; lost header byte meant scanning silently to the next real header. No
; bad_record_mac alert is sent: tls_close sends no close_notify either,
; and ip65 has no bytes for one.
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
        jsr tls_rec_decrypt_chk ; length guard, then tls_record_decrypt
        bcs @aead_fail          ; AEAD verification failed (or short record)
        lda #$09
        sta tls_recv_sub_progress

@plaintext:
        lda #$0A
        sta tls_recv_sub_progress
        clc
        rts

@recv_incomplete:                ; reached only by bcs: C is already 1
        rts

@aead_fail:
        jmp tls_rec_auth_fail   ; far: TLS_CODE, off the ip65 LOADER

; =============================================================================
; Fail-closed record-layer helpers (issue #239). Never CODE: that lands in
; ip65's LOADER region, the tight one. Under UCI they go in TLS_CODE
; (NET_CODE, which has room); under ip65 in CRYPTO_CODE, i.e. the
; CRYPTO_RESIDENT half of the CRYPTO_OVERLAY+CRYPTO_RESIDENT pool, because
; TLS_CODE's half (CRYPTO_OVERLAY) would be left with single-digit bytes.
;
; tls_rx_reset: called at tls_connect entry. Drops whatever an earlier
;   connection left unread in the TCP ring (head := tail) and puts the
;   record reader back at a record boundary. Nothing that far back reset
;   either, so after an aborted fetch the next connect used to read the old
;   connection's ciphertext as its "ServerHello". Safe to discard: TLS 1.3
;   is client-first — the server sends nothing on a new connection until it
;   has our ClientHello, which tls_connect has not sent yet — and both
;   backends append to the ring only inside net_poll, never asynchronously.
;
; tls_rec_decrypt_chk: in front of tls_record_decrypt. Once records are
;   encrypted a record of 16 B or less cannot hold a tag plus an inner type,
;   and tls_record_decrypt computes tls_rec_len - 16 unchecked: below 16 it
;   underflows and Poly1305 sweeps ~64 KB, I/O at $D000-$DFFF included
;   (read side effects: CIA ICR, the UCI $DF1C-$DF1F queues). Rejected as a
;   fatal framing error ($0C). ChangeCipherSpec (1 B) never gets here — it
;   is skipped before the decrypt — and in the plaintext phase nothing is
;   decrypted, so neither needs an exemption.
;
; tls_rec_frame_fail: jmp'd from tls_recv_record's @error (bad content
;   type, version or length). Resets the record reader either way. While
;   tls_state < TLS_STATE_ENCRYPTED_EXT (ClientHello/ServerHello, plaintext)
;   it returns C=1 and the caller resyncs a byte at a time, exactly as
;   before; from EncryptedExtensions on it latches with sub-progress $0C.
;
; tls_rec_auth_fail: tail-jumped from tls_record_recv_and_decrypt on an
;   AEAD tag failure; sub-progress $0B. The record is discarded and
;   tls_read_seq is not advanced (tls_record_decrypt returns before the
;   increment). If the short-record guard already latched, it keeps that.
;
; The latch records the state the failure hit in tls_last_state
; (TLS_STATE_CONNECTED for application data — tls_connect never writes that
; value there, so it names this abort) and sets tls_state = ERROR, which
; the looping callers test. Output: C=1 always.
; =============================================================================
.ifdef BACKEND_UCI
.segment "TLS_CODE"
.else
.segment "CRYPTO_CODE"
.endif
tls_rx_reset:
        lda tcp_recv_tail
        sta tcp_recv_head
        lda tcp_recv_tail+1
        sta tcp_recv_head+1
tls_rec_reader_reset:
        lda #0
        sta tls_recv_state
        sta tls_recv_count
        sta tls_recv_count+1
        rts

tls_rec_decrypt_chk:
        lda tls_rec_len+1
        bne @long               ; >= 256 B
        lda #16
        cmp tls_rec_len         ; C = (tls_rec_len <= 16)
        bcs tls_rec_frame_fail  ; too short for a tag: fatal (state >= 3 here)
@long:
        jmp tls_record_decrypt

tls_rec_frame_fail:
        jsr tls_rec_reader_reset
        lda tls_state
        cmp #TLS_STATE_ENCRYPTED_EXT
        bcc tls_rec_fail_ret    ; plaintext phase: resync, not fatal
        lda #$0C                ; sub-progress: bad/short header after keys
        bne tls_rec_latch       ; always
tls_rec_auth_fail:
        bit tls_state
        bmi tls_rec_fail_ret    ; already latched by the length guard
        lda #$0B                ; sub-progress: AEAD tag rejected
tls_rec_latch:
        sta tls_recv_sub_progress
        lda tls_state
        sta tls_last_state
        lda #TLS_STATE_ERROR
        sta tls_state
tls_rec_fail_ret:
        sec
        rts
.segment "CODE"

; =============================================================================
; Module data — state machine for tls_recv_record
; =============================================================================
tls_recv_state: .byte 0        ; 0 = reading header, 1 = reading payload
tls_recv_count: .word 0        ; bytes received so far in current phase
