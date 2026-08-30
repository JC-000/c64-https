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
.include "net_tuning.inc"       ; CERT_BUF_SIZE (2048 UCI / 1536 ip65)
.include "tls_hs_seq.inc"       ; TLS_HS_SEQ_CHECK / _TABLE (issue #152)

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
; Exported for tools/test_hs_sequence.py, which reads the bytes ADJACENT to
; the table to build the out-of-window cases that give the gate's two range
; checks real teeth (a wrong-state index would land on those bytes).
.export tls_hs_allowed

.import tls_rec_buf
.import tls_rec_len
.import tls_transcript_hash
.import tls_transcript_update
.import tls_handle_certificate
.import tls_handle_cert_verify
.import tls_verify_finished
.import tls_cert_stream_finish
.import cert_buf
.import tls_recv_sub_progress
.import tls_state               ; issue #152: which message is due (data.s)

; Carry buffer: 4-byte handshake header + body. EncryptedExtensions,
; CertificateVerify and Finished are all well under 256 B; Certificate
; never comes here (streamed). 280 total fits NET_BSS_TAIL's slack.
DF_CARRY_SIZE     = 280
DF_CARRY_MAX_BODY = DF_CARRY_SIZE - 4

; df_last_err codes (A on a C=1 return; 0 means "need more data")
DF_ERR_HDR_LEN    = $01         ; 24-bit length high byte non-zero
DF_ERR_TOO_BIG    = $02         ; spanning non-Certificate message > carry cap
DF_ERR_DISPATCH   = $03         ; message handler returned C=1
DF_ERR_TYPE      = $04          ; unknown handshake message type
DF_ERR_CERT_FMT   = $05         ; streamed Certificate malformed / no usable key
DF_ERR_CERT_TOO_BIG = $06       ; leaf certificate exceeds cert_buf (CERT_BUF_SIZE)
DF_ERR_SEQ        = $07         ; message is not the one tls_state requires (#152)

; df_mode values
DF_MODE_HDR       = 0           ; collecting the 4-byte message header
DF_MODE_CARRY     = 1           ; assembling body into df_carry_buf
DF_MODE_STREAM    = 2           ; streaming Certificate body (W2)

; Streaming-Certificate sub-states (df_cs_state)
CS_CTX        = 0               ; certificate_request_context length (1 B, must be 0)
CS_LIST_LEN   = 1               ; certificate_list length (3 B)
CS_ENTRY_LEN  = 2               ; CertificateEntry cert_data length (3 B)
CS_ENTRY_DATA = 3               ; cert_data bytes (leaf -> cert_buf, rest discarded)
CS_EXT_LEN    = 4               ; per-entry extensions length (2 B)
CS_EXT_DATA   = 5               ; extension bytes (discarded)

; Leaf staging capacity — cert_buf in src/der_decode.s (CERT_BUF_BSS),
; sized per-backend by net_tuning.inc (2048 UCI / 1536 ip65), so the
; two can never drift. The cap check runs BEFORE any copy, so an
; oversize leaf is a clean DF_ERR_CERT_TOO_BIG, never a write past
; cert_buf+CERT_BUF_SIZE.
DF_CERT_BUF_SIZE  = CERT_BUF_SIZE
; The @el_leaf_fits comparison below tests only the high byte plus a
; low-byte-of-need == 0 check, which is exact ONLY while the cap's own
; low byte is zero. Keep it a whole number of pages or rewrite the check.
.assert (DF_CERT_BUF_SIZE .MOD 256) = 0, error, "DF_CERT_BUF_SIZE must be page-aligned (leaf cap check assumes low byte 0)"

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

        ; =====================================================================
        ; Issue #152 — THE sequence gate. Every handshake message the deframer
        ; produces passes through here, whichever route it takes below, and
        ; this is the last point at which they have not yet diverged: df_hdr
        ; is complete (df_hdr_have == 4) and df_hdr_split is already known,
        ; but @in_place, @route_carry and df_stream_begin are all still ahead.
        ;
        ; INVARIANT FOR ANYONE ADDING A ROUTE: nothing below may accept a
        ; message that did not come through this check. Do not re-implement it
        ; per route — that is exactly how the first cut of this fix failed.
        ; It gated df_dispatch only, and the streamed-Certificate route
        ; (@route_spanning -> df_stream_begin -> df_stream_body) never reaches
        ; df_dispatch: it consumes the message incrementally and returns C=0
        ; from @msg_end. The attacker picks the record framing, so "spanning"
        ; costs them nothing — a 2-byte first record splits the header of any
        ; Certificate, however small — and four spanning Certificates then
        ; satisfied all four of tls_connect's receives with no
        ; CertificateVerify and no server Finished. Same security outcome as
        ; the four-EncryptedExtensions attack, different filler message.
        ;
        ; Placed before the transcript snapshot/fold below so a rejected
        ; message leaves the running hash untouched.
        ; =====================================================================
        lda df_hdr              ; message type
        TLS_HS_SEQ_CHECK @hdr_seq_bad

        ; 24-bit length high byte must be 0 (no handshake message we
        ; accept exceeds 64 KB; the record layer caps well below that)
        lda df_hdr+1
        beq :+
        lda #DF_ERR_HDR_LEN
        jmp df_fail
@hdr_seq_bad:
        ; Not the message this step of the handshake requires. Refused before
        ; the transcript fold, before any route, before any handler.
        lda #DF_ERR_SEQ
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
        lda df_chunk
        sta df_copy_len
        lda df_chunk+1
        sta df_copy_len+1
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

        ; Expected-type table read by the TLS_HS_SEQ_CHECK at @hdr_complete
        ; (issue #152). It sits here, between routines, because a
        ; non-cheap-local label inside a routine closes its @-label scope.
        TLS_HS_SEQ_TABLE

; =============================================================================
; df_dispatch — (tls_hs_ptr) points at a complete message (incl. 4-byte
; header, type = df_hdr[0]). Resets per-message state, runs the handler.
;
; Issue #152: df_dispatch does NOT re-check the message sequence. It is
; reachable only from @in_place and the carry-complete path, both of which
; are downstream of the single gate at @hdr_complete — putting a second copy
; here would suggest per-route gating is the pattern, which is the mistake
; that let the streamed-Certificate route through.
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
; W2 streaming Certificate consumer
;
; Parses the Certificate message incrementally as its bytes arrive:
; certificate_request_context, certificate_list length, then per entry
; the cert_data length + data + extensions. Only the FIRST entry (the
; leaf) is copied — into cert_buf — and the moment it is complete the
; public key is extracted via tls_cert_stream_finish (same extraction
; as the in-place path). Every later entry is counted and discarded
; without buffering. Message bytes are folded into the running
; transcript in bulk at the top of each pump (fold-as-you-go — the
; bytes are not retained, so there is nothing to fold later).
;
; Reached only for a Certificate that is NOT wholly inside one record;
; the wholly-in-record case dispatches in place through
; tls_handle_certificate exactly as before.
; =============================================================================
df_stream_begin:
        lda #$33
        sta tls_recv_sub_progress
        lda #DF_MODE_STREAM
        sta df_mode
        lda #CS_CTX
        sta df_cs_state
        lda #0
        sta df_cs_idx
        sta df_cs_entry
        sta df_cs_off
        sta df_cs_off+1
        ; fall through into the body consumer

df_stream_body:
        ; anything to consume this pump?
        lda df_avail
        ora df_avail+1
        bne :+
        jmp df_need_data
:
        ; df_take = min(df_avail, df_msg_rem); fold it all into the
        ; running transcript up front — the parse loop below consumes
        ; exactly df_take bytes before returning.
        jsr df_chunk_min
        lda df_chunk
        sta df_take
        lda df_chunk+1
        sta df_take+1
        jsr df_rec_cursor
        lda df_take
        sta zp_count
        lda df_take+1
        sta zp_count+1
        jsr tls_transcript_update

@parse:
        lda df_take
        ora df_take+1
        bne @have_bytes
        ; out of bytes this pump — message complete?
        lda df_msg_rem
        ora df_msg_rem+1
        bne @more_later
        jmp @msg_end
@more_later:
        jmp df_need_data

@have_bytes:
        lda df_cs_state
        cmp #CS_ENTRY_DATA
        bne :+
        jmp @entry_data
:       cmp #CS_EXT_DATA
        bne :+
        jmp @ext_data
:       cmp #CS_CTX
        beq @ctx
        cmp #CS_LIST_LEN
        beq @list_len
        cmp #CS_ENTRY_LEN
        beq @entry_len
        ; CS_EXT_LEN
        jmp @ext_len

@ctx:
        ; certificate_request_context length — must be 0 for a server
        ; Certificate (RFC 8446 §4.4.2)
        jsr df_cs_take_byte
        beq :+
        jmp @cert_fmt_err
:       lda #CS_LIST_LEN
        sta df_cs_state
        lda #0
        sta df_cs_idx
        jmp @parse

@list_len:
        ; certificate_list length, 3 bytes. High byte must be 0 (the
        ; 16-bit message length already caps everything below 64 KB);
        ; the low 16 bits are not tracked — df_msg_rem bounds the walk.
        jsr df_cs_take_byte
        ldx df_cs_idx
        bne :+
        cmp #0
        beq :+
        jmp @cert_fmt_err
:       inc df_cs_idx
        lda df_cs_idx
        cmp #3
        bne @parse
        lda #CS_ENTRY_LEN
        sta df_cs_state
        lda #0
        sta df_cs_idx
        jmp @parse

@entry_len:
        ; CertificateEntry cert_data length, 3 bytes big-endian
        jsr df_cs_take_byte
        ldx df_cs_idx
        bne @el_not_first
        cmp #0
        beq @el_next
        jmp @cert_fmt_err       ; entry >= 64 KB
@el_not_first:
        cpx #1
        bne :+
        sta df_cs_tmp+1         ; length high byte
        jmp @el_next
:       sta df_cs_tmp           ; length low byte
@el_next:
        inc df_cs_idx
        lda df_cs_idx
        cmp #3
        beq :+
        jmp @parse
:       ; length complete
        lda df_cs_tmp
        sta df_cs_need
        lda df_cs_tmp+1
        sta df_cs_need+1
        lda #0
        sta df_cs_idx
        lda df_cs_entry
        bne @el_done            ; not the leaf — just skip its bytes
        ; leaf: must fit cert_buf. Checked BEFORE any copy.
        lda df_cs_need+1
        cmp #>DF_CERT_BUF_SIZE
        bcc @el_leaf_fits
        bne @el_leaf_too_big
        lda df_cs_need
        beq @el_leaf_fits       ; exactly DF_CERT_BUF_SIZE still fits
@el_leaf_too_big:
        lda #DF_ERR_CERT_TOO_BIG
        jmp df_fail
@el_leaf_fits:
        lda #0
        sta df_cs_off
        sta df_cs_off+1
@el_done:
        lda #CS_ENTRY_DATA
        sta df_cs_state
        jmp @parse

@entry_data:
        ; cert_data bytes: copy to cert_buf for the leaf, discard others
        lda df_cs_need
        ora df_cs_need+1
        beq @entry_data_done
        jsr df_cs_min_take_need ; df_n = min(df_take, df_cs_need)
        lda df_cs_entry
        bne @ed_skip_copy
        ; leaf: copy df_n bytes (record cursor) -> cert_buf + df_cs_off
        jsr df_rec_cursor
        clc
        lda #<cert_buf
        adc df_cs_off
        sta zp_tmp1
        lda #>cert_buf
        adc df_cs_off+1
        sta zp_tmp2
        lda df_n
        sta df_copy_len
        lda df_n+1
        sta df_copy_len+1
        jsr df_copy_chunk
        clc
        lda df_cs_off
        adc df_n
        sta df_cs_off
        lda df_cs_off+1
        adc df_n+1
        sta df_cs_off+1
@ed_skip_copy:
        jsr df_cs_advance_n     ; consumes df_n, also df_cs_need -= df_n
        lda df_cs_need
        ora df_cs_need+1
        beq @entry_data_done
        jmp @parse              ; df_take exhausted — loop top handles it
@entry_data_done:
        lda df_cs_entry
        bne @edd_not_leaf
        ; Leaf complete — extract the public key NOW (remaining chain
        ; entries only get skipped; nothing else reads cert_buf).
        lda df_cs_tmp           ; leaf length (df_cs_tmp survives
        ldx df_cs_tmp+1         ;  CS_ENTRY_DATA untouched)
        jsr tls_cert_stream_finish
        bcc @edd_not_leaf
        jmp @cert_fmt_err       ; no usable EC public key in the leaf
@edd_not_leaf:
        lda #CS_EXT_LEN
        sta df_cs_state
        lda #0
        sta df_cs_idx
        jmp @parse

@ext_len:
        ; per-entry extensions length, 2 bytes big-endian
        jsr df_cs_take_byte
        ldx df_cs_idx
        bne :+
        sta df_cs_tmp+1
        jmp @xl_next
:       sta df_cs_tmp
@xl_next:
        inc df_cs_idx
        lda df_cs_idx
        cmp #2
        beq :+
        jmp @parse
:       lda df_cs_tmp
        sta df_cs_need
        lda df_cs_tmp+1
        sta df_cs_need+1
        lda #0
        sta df_cs_idx
        lda df_cs_need
        ora df_cs_need+1
        beq @entry_done         ; no extensions
        lda #CS_EXT_DATA
        sta df_cs_state
        jmp @parse

@ext_data:
        jsr df_cs_min_take_need
        jsr df_cs_advance_n
        lda df_cs_need
        ora df_cs_need+1
        beq @entry_done
        jmp @parse
@entry_done:
        inc df_cs_entry
        lda #CS_ENTRY_LEN
        sta df_cs_state
        lda #0
        sta df_cs_idx
        jmp @parse

@msg_end:
        ; The declared message length ran out. It must have done so
        ; cleanly between entries, with at least one entry consumed
        ; (the leaf, whose extraction already succeeded above).
        lda df_cs_state
        cmp #CS_ENTRY_LEN
        bne @cert_fmt_err
        lda df_cs_idx
        bne @cert_fmt_err
        lda df_cs_entry
        beq @cert_fmt_err
        lda #$34
        sta tls_recv_sub_progress
        ; message done — reset per-message state, report success.
        ; (No df_dispatch here: the streamed Certificate was consumed
        ; incrementally; there is nothing left to hand to a handler.)
        lda #0
        sta df_mode
        sta df_hdr_have
        sta df_hdr_split
        clc
        rts

@cert_fmt_err:
        lda #DF_ERR_CERT_FMT
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

; Copy df_copy_len bytes from (zp_ptr) to (zp_tmp1). Clobbers A,X,Y and
; advances both pointers' high bytes across pages.
df_copy_chunk:
        ldx df_copy_len+1
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
@tail:  lda df_copy_len
        beq @done
        ldy #0
:       lda (zp_ptr),y
        sta (zp_tmp1),y
        iny
        cpy df_copy_len
        bne :-
@done:  rts

; --- streaming-Certificate helpers ------------------------------------------

; Take one message byte from the record cursor. Returns it in A (flags
; reflect A). Advances df_rec_off; decrements df_take and df_msg_rem.
df_cs_take_byte:
        jsr df_rec_cursor
        ldy #0
        lda (zp_ptr),y
        pha
        inc df_rec_off
        bne :+
        inc df_rec_off+1
:       lda df_take
        bne :+
        dec df_take+1
:       dec df_take
        lda df_msg_rem
        bne :+
        dec df_msg_rem+1
:       dec df_msg_rem
        pla
        rts

; df_n = min(df_take, df_cs_need). Clobbers A.
df_cs_min_take_need:
        lda df_take+1
        cmp df_cs_need+1
        bcc @use_take
        bne @use_need
        lda df_take
        cmp df_cs_need
        bcc @use_take
@use_need:
        lda df_cs_need
        sta df_n
        lda df_cs_need+1
        sta df_n+1
        rts
@use_take:
        lda df_take
        sta df_n
        lda df_take+1
        sta df_n+1
        rts

; Consume df_n message bytes in bulk:
; df_rec_off += n; df_take -= n; df_msg_rem -= n; df_cs_need -= n.
df_cs_advance_n:
        clc
        lda df_rec_off
        adc df_n
        sta df_rec_off
        lda df_rec_off+1
        adc df_n+1
        sta df_rec_off+1
        sec
        lda df_take
        sbc df_n
        sta df_take
        lda df_take+1
        sbc df_n+1
        sta df_take+1
        sec
        lda df_msg_rem
        sbc df_n
        sta df_msg_rem
        lda df_msg_rem+1
        sbc df_n+1
        sta df_msg_rem+1
        sec
        lda df_cs_need
        sbc df_n
        sta df_cs_need
        lda df_cs_need+1
        sbc df_n+1
        sta df_cs_need+1
        rts

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
df_copy_len:    .res 2          ; df_copy_chunk length parameter

; streaming-Certificate consumer state
df_take:        .res 2          ; message bytes left to parse this pump
df_n:           .res 2          ; current bulk sub-operation length
df_cs_state:    .res 1          ; CS_*
df_cs_idx:      .res 1          ; byte index within a multi-byte field
df_cs_tmp:      .res 2          ; field accumulator (hi/lo)
df_cs_need:     .res 2          ; bytes remaining of current data field
df_cs_entry:    .res 1          ; CertificateEntry counter (0 = leaf)
df_cs_off:      .res 2          ; leaf write offset into cert_buf

df_carry_buf:   .res DF_CARRY_SIZE

.endif  ; TLS_STREAM_DEFRAME
