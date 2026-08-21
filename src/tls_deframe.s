; tls_deframe.s — W1 streaming handshake-message deframer
;
; Sits between the TLS record layer and the handshake-message handlers.
; A real server's encrypted flight does not align handshake messages
; with TLS records: with max_fragment_length honored the flight arrives
; as 11-14 records where one message (Certificate, ~2.7 KB) spans many
; records and several messages (CertificateVerify + Finished) share one
; record. The pre-deframer dispatch in tls13.s assumed exactly one
; message per record, starting at tls_rec_buf[0].
;
; Contract (consumed by the TLS_STREAM_DEFRAME path in tls13.s):
;
;   tls_deframe_init        — once per handshake, before the first
;                             encrypted message is received. Marks the
;                             current record (the ServerHello) exhausted
;                             and clears all message state.
;   tls_deframe_new_record  — after tls_record_recv_and_decrypt leaves a
;                             fresh handshake-plaintext record in
;                             tls_rec_buf / tls_rec_len.
;   tls_deframe_pump        — consume bytes from the current record.
;                             Returns:
;                               C=0        one complete handshake message
;                                          was dispatched successfully
;                               C=1, A=0   record exhausted — fetch the
;                                          next record and pump again
;                               C=1, A!=0  error (code also stored in
;                                          df_last_err)
;
; Routing per message (design settled 2026-08-16 — see the sprint plan):
;   - message wholly inside the current record  -> dispatch IN PLACE,
;     zero copy: tls_hs_ptr = tls_rec_buf + offset. This covers 100% of
;     the local-listener traffic, so the existing e2e is the control.
;   - message spanning records (EE / CertVerify / Finished, all small)
;     -> assembled into df_carry_buf, dispatched from there.
;   - Certificate spanning records -> W2 streaming consumer
;     (tls_cert_stream_* below): the leaf is copied into cert_buf, the
;     rest of the chain is counted and discarded without buffering.
;
; Transcript discipline (RFC 8446 §4.4.*, historically the most
; bug-prone path here — see "Summary of recent fixes" items 1/2/4 in
; CLAUDE.md): the handlers need tls_transcript to hold the hash of
; everything BEFORE the current message. The pre-deframer code
; snapshotted before dispatch and folded the record after. Per MESSAGE
; that becomes:
;   1. when a message header completes, snapshot the running hash
;      (tls_transcript_hash — non-destructive) BEFORE folding any of
;      this message's bytes,
;   2. fold the header + each body chunk into the running hash as it is
;      consumed (fold-as-you-go: required for the streaming Certificate,
;      whose bytes are not retained; equivalent for the other paths),
;   3. dispatch the handler once the message is complete — it sees the
;      pre-message snapshot in tls_transcript, exactly as before.
;
; ZP usage: zp_ptr/zp_count (transcript + copy scratch, recomputed after
; every external call), zp_tmp1/zp_tmp2 (carry/cert copy destination
; pointer), tls_hs_ptr ($3E-$3F, set before each dispatch).
;
; Memory: code in its own TLS_DEFRAME_CODE segment, routed to the
; CRYPTO_OVERLAY region by both UCI cfgs — CRYPTO_HOT cannot absorb it
; under the plain-uci cfg (446 B short with the REU-profile archive).
; CRYPTO_OVERLAY is free in every default build; the overlay-embed
; flags (EMBED_P256_OVERLAY / USE_OVERLAY_P384_EMBED) that stage
; runtime-swapped images there are mutually exclusive with a resident
; deframer, exactly as they already are with LIB_NISTCURVES_MUL_CODE.
; State + carry buffer live in the NET_BSS_TAIL region (~378 B free
; under UCI comb).
; The whole module is gated on TLS_STREAM_DEFRAME (UCI-only for now:
; ip65 has neither the code nor the BSS headroom — see the Makefile).

.include "constants.inc"

.ifdef TLS_STREAM_DEFRAME

.export tls_deframe_init
.export tls_deframe_new_record
.export tls_deframe_pump
; State exported for the VICE test harness (tools/test_tls_deframe.py)
; and hardware post-mortems.
.export df_mode
.export df_hdr
.export df_hdr_have
.export df_msg_rem
.export df_rec_off
.export df_last_err
.export df_carry_buf

.import tls_rec_buf
.import tls_rec_len
.import tls_transcript_hash
.import tls_transcript_update
.import tls_handle_certificate
.import tls_handle_cert_verify
.import tls_verify_finished
.import tls_recv_sub_progress

; Carry buffer: 4-byte handshake header + body. EncryptedExtensions,
; CertificateVerify and Finished are all well under 256 B; Certificate
; never comes here (streamed). 280 total fits NET_BSS_TAIL's slack.
DF_CARRY_SIZE     = 280
DF_CARRY_MAX_BODY = DF_CARRY_SIZE - 4

; df_last_err codes (A on a C=1 return; 0 means "need more data")
DF_ERR_HDR_LEN    = $01         ; 24-bit length high byte non-zero
DF_ERR_TOO_BIG    = $02         ; spanning non-Certificate message > carry cap
DF_ERR_DISPATCH   = $03         ; message handler returned C=1
DF_ERR_TYPE       = $04         ; unknown handshake message type

; df_mode values
DF_MODE_HDR       = 0           ; collecting the 4-byte message header
DF_MODE_CARRY     = 1           ; assembling body into df_carry_buf
DF_MODE_STREAM    = 2           ; streaming Certificate body (W2)

.segment "TLS_DEFRAME_CODE"

; =============================================================================
; tls_deframe_init — reset all deframer state; mark current record consumed
; (tls_rec_len still holds the ServerHello record length at call time).
; =============================================================================
tls_deframe_init:
        lda #0
        sta df_mode
        sta df_hdr_have
        sta df_hdr_split
        sta df_last_err
        lda tls_rec_len
        sta df_rec_off
        lda tls_rec_len+1
        sta df_rec_off+1
        rts

; =============================================================================
; tls_deframe_new_record — a fresh decrypted handshake record sits in
; tls_rec_buf / tls_rec_len; start consuming it from offset 0.
; =============================================================================
tls_deframe_new_record:
        lda #0
        sta df_rec_off
        sta df_rec_off+1
        rts

; =============================================================================
; tls_deframe_pump — consume bytes from the current record until one
; message completes (dispatch it) or the record is exhausted.
; See the contract in the file header for the C/A return protocol.
; =============================================================================
tls_deframe_pump:
        ; df_avail = tls_rec_len - df_rec_off
        sec
        lda tls_rec_len
        sbc df_rec_off
        sta df_avail
        lda tls_rec_len+1
        sbc df_rec_off+1
        sta df_avail+1

        lda df_mode
        beq @hdr_phase
        cmp #DF_MODE_CARRY
        bne :+
        jmp df_carry_body
:       jmp df_stream_body

; --- header phase: collect up to 4 header bytes ----------------------------
@hdr_phase:
@hdr_loop:
        lda df_hdr_have
        cmp #4
        bcs @hdr_complete
        ; any record bytes left?
        lda df_avail
        ora df_avail+1
        bne :+
        ; record exhausted mid-header (or before one started)
        lda df_hdr_have
        beq @hdr_need_data
        lda #1
        sta df_hdr_split
@hdr_need_data:
        jmp df_need_data
:
        jsr df_rec_cursor       ; zp_ptr = tls_rec_buf + df_rec_off
        ldy #0
        lda (zp_ptr),y
        ldx df_hdr_have
        sta df_hdr,x
        inc df_hdr_have
        ; df_rec_off++
        inc df_rec_off
        bne :+
        inc df_rec_off+1
:       ; df_avail--
        lda df_avail
        bne :+
        dec df_avail+1
:       dec df_avail
        jmp @hdr_loop

; --- header complete: validate, snapshot, fold, route ----------------------
@hdr_complete:
        lda #$30
        sta tls_recv_sub_progress

        ; 24-bit length high byte must be 0 (no handshake message we
        ; accept exceeds 64 KB; the record layer caps well below that)
        lda df_hdr+1
        beq :+
        lda #DF_ERR_HDR_LEN
        jmp df_fail
:
        lda df_hdr+2
        sta df_msg_len+1
        sta df_msg_rem+1
        lda df_hdr+3
        sta df_msg_len
        sta df_msg_rem

        ; Snapshot the running transcript hash BEFORE any byte of this
        ; message is folded — handlers (CertVerify, Finished) verify
        ; against the transcript EXCLUDING their own message.
        jsr tls_transcript_hash

        ; Fold the 4 header bytes into the running transcript.
        lda #<df_hdr
        sta zp_ptr
        lda #>df_hdr
        sta zp_ptr+1
        lda #4
        sta zp_count
        lda #0
        sta zp_count+1
        jsr tls_transcript_update

        ; Route: in place iff the header was not split across records
        ; AND the whole body is inside the current record.
        lda df_hdr_split
        bne @route_spanning
        lda df_avail+1
        cmp df_msg_len+1
        bcc @route_spanning
        bne @in_place
        lda df_avail
        cmp df_msg_len
        bcc @route_spanning

; --- in-place dispatch: zero copy -----------------------------------------
@in_place:
        lda #$31
        sta tls_recv_sub_progress
        jsr df_rec_cursor       ; zp_ptr = body start
        ; message start (incl. header) = body - 4
        lda zp_ptr
        sec
        sbc #4
        sta tls_hs_ptr
        lda zp_ptr+1
        sbc #0
        sta tls_hs_ptr+1
        ; fold the body into the running transcript
        lda df_msg_len
        sta zp_count
        lda df_msg_len+1
        sta zp_count+1
        jsr tls_transcript_update
        ; consume the body
        clc
        lda df_rec_off
        adc df_msg_len
        sta df_rec_off
        lda df_rec_off+1
        adc df_msg_len+1
        sta df_rec_off+1
        jmp df_dispatch

; --- spanning message: carry buffer (or W2 Certificate stream) -------------
@route_spanning:
        lda df_hdr             ; message type
        cmp #TLS_HS_CERTIFICATE
        bne @route_carry
        jmp df_stream_begin

@route_carry:
        ; must fit: body <= DF_CARRY_MAX_BODY
        lda df_msg_len+1
        cmp #>DF_CARRY_MAX_BODY
        bcc @carry_fits
        bne @carry_too_big
        lda df_msg_len
        cmp #<(DF_CARRY_MAX_BODY+1)
        bcc @carry_fits
@carry_too_big:
        lda #DF_ERR_TOO_BIG
        jmp df_fail
@carry_fits:
        ; carry[0..3] = header
        ldx #3
:       lda df_hdr,x
        sta df_carry_buf,x
        dex
        bpl :-
        lda #4
        sta df_carry_off
        lda #0
        sta df_carry_off+1
        lda #DF_MODE_CARRY
        sta df_mode
        ; fall through into the body consumer

; --- carry-mode body consumer ----------------------------------------------
df_carry_body:
        lda df_avail
        ora df_avail+1
        bne :+
        jmp df_need_data
:
        jsr df_chunk_min        ; df_chunk = min(df_avail, df_msg_rem)

        ; fold the chunk (from the record) into the running transcript
        jsr df_rec_cursor
        lda df_chunk
        sta zp_count
        lda df_chunk+1
        sta zp_count+1
        jsr tls_transcript_update

        ; copy chunk: (tls_rec_buf + df_rec_off) -> (df_carry_buf + df_carry_off)
        jsr df_rec_cursor
        clc
        lda #<df_carry_buf
        adc df_carry_off
        sta zp_tmp1
        lda #>df_carry_buf
        adc df_carry_off+1
        sta zp_tmp2
        jsr df_copy_chunk

        ; df_carry_off += chunk
        clc
        lda df_carry_off
        adc df_chunk
        sta df_carry_off
        lda df_carry_off+1
        adc df_chunk+1
        sta df_carry_off+1

        jsr df_consume_chunk    ; rec_off += chunk, msg_rem -= chunk

        lda df_msg_rem
        ora df_msg_rem+1
        beq :+
        jmp df_need_data        ; record exhausted (chunk == avail)
:
        ; message complete — dispatch from the carry buffer
        lda #$32
        sta tls_recv_sub_progress
        lda #<df_carry_buf
        sta tls_hs_ptr
        lda #>df_carry_buf
        sta tls_hs_ptr+1
        jmp df_dispatch

; =============================================================================
; df_dispatch — (tls_hs_ptr) points at a complete message (incl. 4-byte
; header, type = df_hdr[0]). Resets per-message state, runs the handler.
; =============================================================================
df_dispatch:
        lda #0
        sta df_mode
        sta df_hdr_have
        sta df_hdr_split

        lda df_hdr             ; message type
        cmp #TLS_HS_ENCRYPTED_EXT
        beq @disp_ok            ; accept, nothing to extract for MVP
        cmp #TLS_HS_CERTIFICATE
        beq @disp_cert
        cmp #TLS_HS_CERT_VERIFY
        beq @disp_cv
        cmp #TLS_HS_FINISHED
        beq @disp_fin
        lda #DF_ERR_TYPE
        jmp df_fail
@disp_cert:
        jsr tls_handle_certificate
        jmp @disp_check
@disp_cv:
        jsr tls_handle_cert_verify
        jmp @disp_check
@disp_fin:
        ; Verify server Finished with the pre-Finished transcript
        ; snapshot taken at header-complete time above.
        jsr tls_verify_finished
@disp_check:
        bcs @disp_fail
@disp_ok:
        clc
        rts
@disp_fail:
        lda #DF_ERR_DISPATCH
        ; fall through to df_fail

; --- shared exits -----------------------------------------------------------
df_fail:
        sta df_last_err
        sec
        rts

df_need_data:
        lda #0
        sec
        rts

; =============================================================================
; W2 streaming Certificate consumer — placeholder in W1: a Certificate
; that spans records is rejected until the streaming consumer lands.
; =============================================================================
df_stream_begin:
df_stream_body:
        lda #DF_ERR_TOO_BIG
        jmp df_fail

; =============================================================================
; Helpers
; =============================================================================

; zp_ptr = tls_rec_buf + df_rec_off. Clobbers A.
df_rec_cursor:
        clc
        lda #<tls_rec_buf
        adc df_rec_off
        sta zp_ptr
        lda #>tls_rec_buf
        adc df_rec_off+1
        sta zp_ptr+1
        rts

; df_chunk = min(df_avail, df_msg_rem). Clobbers A.
df_chunk_min:
        lda df_avail+1
        cmp df_msg_rem+1
        bcc @use_avail
        bne @use_rem
        lda df_avail
        cmp df_msg_rem
        bcc @use_avail
@use_rem:
        lda df_msg_rem
        sta df_chunk
        lda df_msg_rem+1
        sta df_chunk+1
        rts
@use_avail:
        lda df_avail
        sta df_chunk
        lda df_avail+1
        sta df_chunk+1
        rts

; Consume df_chunk record bytes into the current message:
; df_rec_off += df_chunk, df_avail -= df_chunk, df_msg_rem -= df_chunk.
df_consume_chunk:
        clc
        lda df_rec_off
        adc df_chunk
        sta df_rec_off
        lda df_rec_off+1
        adc df_chunk+1
        sta df_rec_off+1
        sec
        lda df_avail
        sbc df_chunk
        sta df_avail
        lda df_avail+1
        sbc df_chunk+1
        sta df_avail+1
        sec
        lda df_msg_rem
        sbc df_chunk
        sta df_msg_rem
        lda df_msg_rem+1
        sbc df_chunk+1
        sta df_msg_rem+1
        rts

; Copy df_chunk bytes from (zp_ptr) to (zp_tmp1). Clobbers A,X,Y and
; advances both pointers' high bytes across pages.
df_copy_chunk:
        ldx df_chunk+1
        beq @tail
@page:  ldy #0
:       lda (zp_ptr),y
        sta (zp_tmp1),y
        iny
        bne :-
        inc zp_ptr+1
        inc zp_tmp2
        dex
        bne @page
@tail:  lda df_chunk
        beq @done
        ldy #0
:       lda (zp_ptr),y
        sta (zp_tmp1),y
        iny
        cpy df_chunk
        bne :-
@done:  rts

; =============================================================================
; Deframer state — NET_BSS_TAIL region (UCI: ~378 B free under comb)
; =============================================================================
.segment "NET_BSS_TAIL"

df_mode:        .res 1          ; DF_MODE_*
df_hdr:         .res 4          ; handshake header: type + 24-bit length
df_hdr_have:    .res 1          ; header bytes collected (0-4)
df_hdr_split:   .res 1          ; 1 = header began in an earlier record
df_msg_len:     .res 2          ; declared body length
df_msg_rem:     .res 2          ; body bytes still unconsumed
df_rec_off:     .res 2          ; consumed offset into tls_rec_buf
df_avail:       .res 2          ; unconsumed bytes in current record
df_chunk:       .res 2          ; current chunk length
df_carry_off:   .res 2          ; write offset into df_carry_buf
df_last_err:    .res 1          ; DF_ERR_* of the last failure
df_carry_buf:   .res DF_CARRY_SIZE

.endif  ; TLS_STREAM_DEFRAME
