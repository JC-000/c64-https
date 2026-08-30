; tls13.s — TLS 1.3 state machine and record assembly
; Converted from ACME to ca65 in Phase 3 Batch C.
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

.include "constants.inc"
; Backend-sensitive loop budgets (resolved via -I src/net/$(BACKEND)).
.include "net_tuning.inc"
; Handshake message sequence gate, shared with src/tls_deframe.s (issue #152).
.include "tls_hs_seq.inc"

; --- Public exports ---
.export tls_connect
.export tls_send
.export tls_recv
.export tls_close
.export tls_send_client_hello
.export tls_recv_server_hello
.export tls_recv_encrypted
.export tls_send_finished

; --- TLS BSS / data (data.asm) ---
.import tls_state
.import tls_last_state
.import tls_client_random
.import tls_ecdhe_privkey
.import tls_rec_buf
.import tls_rec_len
.import tls_rec_type
.import tls_app_ptr
.import tls_app_len
.import tls_recv_progress
.import tls_recv_poll_count

; --- Crypto / DRBG / ECDH helpers ---
.import drbg_fill_bytes
.import tls_ecdh_generate_keypair
.import tls_ecdh_compute_shared

; --- TLS record layer (tls_record.s / tls_record_io.s) ---
.import tls_record_send_plaintext
.import tls_record_send_encrypted
.import tls_record_recv_and_decrypt

; --- ClientHello / ServerHello builders & parsers (tls_handshake) ---
.import tls_build_client_hello
.import tls_parse_server_hello

; --- Transcript hash (tls_transcript.s) ---
.import tls_transcript_init
.import tls_transcript_update
.import tls_transcript_hash

; --- Key schedule (tls_keyschedule.s) ---
.import tls_derive_handshake_keys
.import tls_derive_traffic_keys
.import tls_compute_finished
.import tls_verify_finished
.import tls_verify_data
.import tls_c_hs_secret

; --- HKDF scratch (hkdf.s / data.asm) ---
.import hkdf_prk

; --- AEAD sequence counters (data.asm). Reset at every key-epoch change
;     per RFC 8446 §5.3: the sequence number MUST be zero at the beginning
;     of a connection and whenever the key is changed. ---
.import tls_write_seq
.import tls_read_seq

; --- Encrypted handshake sub-handlers (tls_cert.s) ---
.import tls_handle_certificate
.import tls_handle_cert_verify

.ifdef TLS_STREAM_DEFRAME
; --- W1 streaming handshake-message deframer (tls_deframe.s) ---
.import tls_deframe_init
.import tls_deframe_new_record
.import tls_deframe_pump
.endif

; --- Networking (net.s) ---
.include "net_abi.inc"          ; net_poll

; --- Console output (main/util) ---
.import print_string

; --- Status strings (data.asm / rodata) ---
.import ch_sent_msg
.import sh_recv_msg
.import hk1_msg
.import keys_ok_msg
.import ee_recv_msg
.import cert_recv_msg
.import cv_recv_msg
.import fin_recv_msg
.import cfin_sent_msg
.import enc1_msg
.import rx_msg
.import got2_msg
.import got_msg
.import dec_msg
.import proc_msg

.segment "CODE"

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
        bcc @ok1
        jmp @error
@ok1:
        lda #<ch_sent_msg
        ldy #>ch_sent_msg
        jsr print_string

        ; --- receive ServerHello ---
        lda #TLS_STATE_SERVER_HELLO
        sta tls_state
        jsr tls_recv_server_hello
        bcc @ok2
        jmp @error
@ok2:
        lda #<sh_recv_msg
        ldy #>sh_recv_msg
        jsr print_string

        lda #<hk1_msg
        ldy #>hk1_msg
        jsr print_string

        ; finalize transcript hash = SHA-256(CH || SH) for "s hs traffic"
        ; / "c hs traffic" context. tls_transcript_hash is non-destructive:
        ; it snapshots the running state and restores it, so subsequent
        ; tls_transcript_update calls (EE, Cert, CertVerify, ServerFinished,
        ; client Finished) still feed the same streaming SHA-256.
        jsr tls_transcript_hash

        ; derive handshake keys from ECDHE shared secret
        jsr tls_derive_handshake_keys
        bcc @ok3
        jmp @error
@ok3:
        lda #<keys_ok_msg
        ldy #>keys_ok_msg
        jsr print_string

.ifdef TLS_STREAM_DEFRAME
        ; Reset the streaming deframer. The ServerHello record has been
        ; fully consumed; the encrypted handshake messages begin with
        ; the next record fetched by tls_recv_encrypted.
        jsr tls_deframe_init
.endif

        ; --- receive EncryptedExtensions (encrypted) ---
        lda #TLS_STATE_ENCRYPTED_EXT
        sta tls_state
        jsr tls_recv_encrypted
        bcc @ok4
        jmp @error
@ok4:
        lda #<ee_recv_msg
        ldy #>ee_recv_msg
        jsr print_string

        ; --- receive Certificate (encrypted) ---
        lda #TLS_STATE_CERTIFICATE
        sta tls_state
        jsr tls_recv_encrypted
        bcc @ok5
        jmp @error
@ok5:
        lda #<cert_recv_msg
        ldy #>cert_recv_msg
        jsr print_string

        ; --- receive CertificateVerify (encrypted) ---
        lda #TLS_STATE_CERT_VERIFY
        sta tls_state
        jsr tls_recv_encrypted
        bcc @ok6
        jmp @error
@ok6:
        lda #<cv_recv_msg
        ldy #>cv_recv_msg
        jsr print_string

        ; --- receive + verify server Finished (encrypted) ---
        ; tls_recv_encrypted dispatches to tls_verify_finished internally
        ; for TLS_HS_FINISHED, so that it runs against the pre-Finished
        ; transcript (the running hash is updated AFTER the handler).
        lda #TLS_STATE_FINISHED
        sta tls_state
        jsr tls_recv_encrypted
        bcc @ok7
        jmp @error
@ok7:
        lda #<fin_recv_msg
        ldy #>fin_recv_msg
        jsr print_string

        ; finalize transcript hash = SHA-256(CH || .. || ServerFinished)
        ; for application-traffic-key derivation and for the client
        ; Finished HMAC.  Non-destructive finalize preserves the running
        ; state for the subsequent client Finished update.
        jsr tls_transcript_hash

        ; --- send client Finished (encrypted) ---
        ;
        ; ORDERING: tls_send_finished MUST run before tls_derive_traffic_keys.
        ;
        ; tls_derive_traffic_keys overwrites tls_c_hs_secret / tls_s_hs_secret
        ; in place with the c_ap_traffic / s_ap_traffic secrets (see the
        ; "reuse temp buffer" comments in tls_keyschedule.s).  The client
        ; Finished HMAC needs the client HANDSHAKE traffic secret though,
        ; so we must compute + send it while those buffers still hold
        ; the right value.  Both derivations sign the same transcript
        ; (Transcript-Hash(ClientHello..ServerFinished)), so the single
        ; snapshot above is shared cleanly.
        jsr tls_send_finished
        bcc @ok8
        jmp @error
@ok8:
        lda #<cfin_sent_msg
        ldy #>cfin_sent_msg
        jsr print_string

        ; derive application traffic keys
        jsr tls_derive_traffic_keys
        bcc @ok10
        jmp @error
@ok10:

        ; RFC 8446 §5.3: reset BOTH AEAD sequence counters at the key-epoch
        ; boundary.  The write counter was at 1 after sending client Finished
        ; under the handshake write key; the read counter was at 4 after
        ; consuming EE/Cert/CV/ServerFinished under the handshake read key.
        ; Next write (HTTP GET via tls_send) uses the application WRITE key
        ; and must start from seq=0; next read (server NewSessionTicket or
        ; application data) uses the application READ key and must likewise
        ; start from seq=0.  Leaving either non-zero desynchronises the
        ; AEAD nonce with the peer and the server returns record-layer
        ; failure on the first application record we send.
        ldx #7
@seq_reset:
        lda #0
        sta tls_write_seq,x
        sta tls_read_seq,x
        dex
        bpl @seq_reset

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

        ; build ClientHello directly into tls_rec_buf, sets tls_rec_len
        jsr tls_build_client_hello

        ; send as plaintext handshake record
        lda #TLS_CT_HANDSHAKE
        jsr tls_record_send_plaintext
        bcs @ch_fail

        ; update transcript with ClientHello (content still in tls_rec_buf;
        ; tls_record_send_plaintext prepends the 5-byte record header but
        ; does not touch the payload bytes).
        lda #<tls_rec_buf
        sta zp_ptr
        lda #>tls_rec_buf
        sta zp_ptr+1
        lda tls_rec_len
        sta zp_count
        lda tls_rec_len+1
        sta zp_count+1
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
        sta sh_timeout
        sta sh_timeout+1
        sta tls_recv_poll_count
        sta tls_recv_poll_count+1
@sh_wait:
        inc tls_recv_poll_count
        bne :+
        inc tls_recv_poll_count+1
:
        jsr net_poll
        jsr tls_record_recv_and_decrypt
        bcc @sh_got_record
        inc sh_timeout
        bne @sh_wait
        inc sh_timeout+1
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

        ; ServerHello plaintext already sits in tls_rec_buf / tls_rec_len;
        ; no staging copy is needed (the old copy was truncated to the low
        ; 8 bits of length, which broke any record >=256 B).  Invariant:
        ; tls_parse_server_hello must finish reading tls_rec_buf before the
        ; next record is fetched — the state machine enforces this, since
        ; the handler runs synchronously and the next recv sits after the
        ; return.
        lda #$04
        sta tls_recv_progress

        ; parse ServerHello
        jsr tls_parse_server_hello
        bcs @sh_error
        lda #$05
        sta tls_recv_progress

        ; Drain frames already at the NIC and ACK them BEFORE the
        ; multi-minute ECDHE stall. The server's post-SH flight is on
        ; the wire/in the chip by now (it splits at the 512 B default
        ; MSS because ip65's SYN carries no MSS option); without this
        ; drain the tail sits unACKed while we compute, and impatient
        ; peers drop the connection (macOS: hard drop after 13
        ; retransmits ≈ 54 s on a LAN — the C64 then verifies the whole
        ; buffered flight offline and dies SENDING client Finished into
        ; an RST'd socket). Draining here leaves zero unACKed data
        ; across every later crypto stall; idle connections survive.
        ; Safe: SH is fully parsed above, and net_poll only appends to
        ; the TCP ring — it never touches tls_rec_buf.
        ;
        ; The budget is BACKEND-SENSITIVE and therefore lives in the
        ; per-backend net_tuning.inc (issue #73): an ip65 net_poll is a
        ; cheap NIC pump, but a UCI net_poll is a full firmware command
        ; round-trip (~40 ms measured at 48 MHz, mostly clock-invariant
        ; FPGA turnaround). Sizing this loop on ip65's poll cost alone
        ; cost UCI ~80 s of pure wall-clock — and UCI firmware ACKs
        ; autonomously, so the drain has nothing to buy there anyway.
        ; See each backend's net_tuning.inc for the values + rationale.
        ldy #NET_SH_DRAIN_OUTER
@sh_drain_outer:
        ldx #NET_SH_DRAIN_INNER
@sh_drain:
        tya
        pha
        txa
        pha
        jsr net_poll
        pla
        tax
        pla
        tay
        dex
        bne @sh_drain
        dey
        bne @sh_drain_outer

        ; compute ECDH shared secret now that tls_server_pubkey is populated
        jsr tls_ecdh_compute_shared
        clc

        ; update transcript with ServerHello
        lda #<tls_rec_buf
        sta zp_ptr
        lda #>tls_rec_buf
        sta zp_ptr+1
        lda tls_rec_len
        sta zp_count
        lda tls_rec_len+1
        sta zp_count+1
        jsr tls_transcript_update

        clc
        rts
@sh_error:
        sec
        rts

; tls_derive_handshake_keys - in tls_keyschedule.s
; tls_derive_traffic_keys   - in tls_keyschedule.s
; tls_verify_finished       - in tls_keyschedule.s

.ifdef TLS_STREAM_DEFRAME
; =============================================================================
; tls_recv_encrypted — streaming variant (W1 deframer, tls_deframe.s).
;
; Handshake messages no longer line up with records in either direction
; (a real server's Certificate spans ~6 records; CertificateVerify and
; Finished share the tail record), so instead of dispatching "the one
; message in this record" we pump the deframer: it consumes the current
; record's unconsumed bytes first and asks for another record only when
; it runs dry. Returns once ONE handshake message has been dispatched
; successfully, so tls_connect's state machine and progress markers are
; unchanged. Transcript discipline (snapshot before dispatch, fold per
; MESSAGE — see the pre-deframer comment in the .else branch below, and
; the fold-as-you-go note in tls_deframe.s) lives inside the deframer.
;
; Output: C=0 one message dispatched, C=1 timeout/error
; =============================================================================
tls_recv_encrypted:
        lda #<enc1_msg
        ldy #>enc1_msg
        jsr print_string
        lda #0
        sta enc_timeout
        sta enc_timeout+1
        lda #<rx_msg
        ldy #>rx_msg
        jsr print_string
@df_pump:
        jsr tls_deframe_pump
        bcc @df_msg_done
        cmp #0
        beq @enc_wait           ; A=0: record exhausted — fetch the next
        jmp @enc_error          ; A!=0: deframe/handler error
@enc_wait:
        jsr net_poll
        jsr tls_record_recv_and_decrypt
        bcc @enc_got_record
        inc enc_timeout
        bne @enc_wait
        inc enc_timeout+1
        bne @enc_wait
        ; timeout
        sec
        rts
@enc_got_record:
        lda #<got2_msg
        ldy #>got2_msg
        jsr print_string
        ; verify inner content type is handshake
        lda tls_rec_type
        cmp #TLS_CT_HANDSHAKE
        bne @enc_error
        jsr tls_deframe_new_record
        jmp @df_pump
@df_msg_done:
        lda #<proc_msg
        ldy #>proc_msg
        jsr print_string
        clc
        rts
@enc_error:
        sec
        rts

.else   ; !TLS_STREAM_DEFRAME — one message per record (ip65 path)

; =============================================================================
; tls_recv_encrypted - receive encrypted handshake msg, decrypt, dispatch
; Output: C=0 success, C=1 timeout/error
; =============================================================================
tls_recv_encrypted:
        lda #<enc1_msg
        ldy #>enc1_msg
        jsr print_string
        lda #0
        sta enc_timeout
        sta enc_timeout+1
        lda #<rx_msg
        ldy #>rx_msg
        jsr print_string
@enc_wait:
        jsr net_poll
        jsr tls_record_recv_and_decrypt
        bcs :+
        ; success -- print GOT2 marker so we can distinguish progress
        lda #<got2_msg
        ldy #>got2_msg
        jsr print_string
        clc
        jmp @enc_got_record
:
        inc enc_timeout
        bne @enc_wait
        inc enc_timeout+1
        bne @enc_wait
        ; timeout
        sec
        rts
@enc_got_record:
        pha
        lda #<got_msg
        ldy #>got_msg
        jsr print_string
        pla
        ; verify inner content type is handshake
        lda tls_rec_type
        cmp #TLS_CT_HANDSHAKE
        bne @enc_error

        ; Decrypted handshake plaintext already sits in tls_rec_buf /
        ; tls_rec_len (tls_record_decrypt leaves it in-place with the inner
        ; content type byte stripped).
        ;
        ; Transcript discipline (RFC 8446 §4.4.*):
        ;   - CertificateVerify is signed over Transcript-Hash(ClientHello..Certificate)
        ;     — i.e. the transcript BEFORE the CertVerify message itself.
        ;   - server Finished verify_data is HMAC over
        ;     Transcript-Hash(ClientHello..CertificateVerify) — again, the
        ;     transcript BEFORE Finished.
        ;
        ; So the handlers need tls_transcript to hold the hash EXCLUDING the
        ; current message.  We:
        ;   1. snapshot the running hash into tls_transcript (non-destructive)
        ;      BEFORE the dispatch so tls_handle_cert_verify /
        ;      tls_verify_finished see the correct value,
        ;   2. run the handler,
        ;   3. fold the current message into the running transcript for the
        ;      next message.
        ;
        ; The previous order (update-then-dispatch) left tls_transcript holding
        ; the stale CH||SH hash at CertVerify time, causing the ECDSA verify
        ; step to compute a wrong signed-content digest and reject the
        ; signature.  Invariant: handlers MUST finish reading tls_rec_buf
        ; before the next record is fetched — enforced by the synchronous
        ; dispatch/return flow.

        ; Snapshot running transcript hash BEFORE dispatch.
        jsr tls_transcript_hash

        lda #<dec_msg
        ldy #>dec_msg
        jsr print_string
        lda #<proc_msg
        ldy #>proc_msg
        jsr print_string

        ; dispatch based on handshake type (first byte of tls_rec_buf)
        ;
        ; Issue #152: the type must first be the one the current tls_state
        ; requires. tls_connect issues four unconditional receives and each
        ; returns C=0 on ANY dispatched message, so without this gate four
        ; EncryptedExtensions satisfy the whole flight and the client
        ; "completes" a handshake in which no certificate was ever presented.
        ; Identical gate to df_dispatch's (same macro) — the defect was in
        ; both arms.
        lda tls_rec_buf
        TLS_HS_SEQ_CHECK @enc_error
        cmp #TLS_HS_ENCRYPTED_EXT
        beq @enc_dispatched             ; accept, nothing to extract for MVP
        cmp #TLS_HS_CERTIFICATE
        beq @enc_cert
        cmp #TLS_HS_CERT_VERIFY
        beq @enc_cert_verify
        cmp #TLS_HS_FINISHED
        beq @enc_finished               ; verify here with pre-Finished transcript
        ; unknown handshake type for current state
        bne @enc_error

@enc_cert:
        jsr tls_handle_certificate
        bcs @enc_error
        jmp @enc_update_transcript

@enc_cert_verify:
        jsr tls_handle_cert_verify
        bcs @enc_error
        jmp @enc_update_transcript

@enc_finished:
        ; Verify server Finished with pre-Finished transcript. Must happen
        ; BEFORE we fold this message into the running hash, otherwise the
        ; client Finished (and the subsequent app-traffic key derivation)
        ; would see a mis-ordered transcript.
        jsr tls_verify_finished
        bcs @enc_error
        jmp @enc_update_transcript

@enc_dispatched:
        ; Fall through: EE etc. accepted, nothing to extract.
@enc_update_transcript:
        ; After a successful handler, fold this message into the running
        ; transcript so the NEXT message sees the correct prefix hash.
        lda #<tls_rec_buf
        sta zp_ptr
        lda #>tls_rec_buf
        sta zp_ptr+1
        lda tls_rec_len
        sta zp_count
        lda tls_rec_len+1
        sta zp_count+1
        jsr tls_transcript_update
        clc
        rts
@enc_error:
        sec
        rts

        ; Expected-type table read by the TLS_HS_SEQ_CHECK above (issue
        ; #152). Unreachable as code — it sits behind the rts.
        TLS_HS_SEQ_TABLE

.endif  ; TLS_STREAM_DEFRAME

; =============================================================================
; tls_send_finished - compute client Finished, encrypt, send
; Output: C=0 success, C=1 failure
; =============================================================================
tls_send_finished:
        ; tls_compute_finished reads hkdf_prk and treats it as the traffic
        ; secret to derive the finished_key from.  For the CLIENT Finished we
        ; need the client HANDSHAKE traffic secret; the previous call into
        ; the key schedule (tls_verify_finished) left hkdf_prk set to the
        ; SERVER handshake traffic secret, which would silently produce the
        ; wrong verify_data and let the server reject our Finished with a
        ; DIGEST_CHECK_FAILED alert.  Explicitly load c_hs_secret first.
        ldx #31
@sf_load_prk:
        lda tls_c_hs_secret,x
        sta hkdf_prk,x
        dex
        bpl @sf_load_prk

        ; Compute verify_data into tls_verify_data (32 bytes).
        jsr tls_compute_finished

        ; Assemble the Finished handshake message directly in tls_rec_buf:
        ;   [0]   0x14  (TLS_HS_FINISHED)
        ;   [1-3] 0x000020 (24-bit length = 32)
        ;   [4-35] verify_data (32 bytes copied from tls_verify_data)
        lda #TLS_HS_FINISHED
        sta tls_rec_buf+0
        lda #0
        sta tls_rec_buf+1
        sta tls_rec_buf+2
        lda #32
        sta tls_rec_buf+3

        ldx #31
@fin_copy_vd:
        lda tls_verify_data,x
        sta tls_rec_buf+4,x
        dex
        bpl @fin_copy_vd

        ; tls_rec_len = 36, inner content type = handshake
        lda #36
        sta tls_rec_len
        lda #0
        sta tls_rec_len+1
        lda #TLS_CT_HANDSHAKE
        sta tls_rec_type

        ; update transcript with the finished message (36 bytes)
        lda #<tls_rec_buf
        sta zp_ptr
        lda #>tls_rec_buf
        sta zp_ptr+1
        lda #36
        sta zp_count
        lda #0
        sta zp_count+1
        jsr tls_transcript_update

        ; encrypt and send
        jsr tls_record_send_encrypted
        rts

; =============================================================================
; File-local BSS — 16-bit timeout counters used by recv routines.
; Originally `@sh_timeout` / `@enc_timeout` cheap locals embedded in code with
; `!word 0`. Promoted to module-scope BSS so ca65 can place them cleanly; they
; are not exported.
; =============================================================================
.segment "BSS"
sh_timeout:     .res 2
enc_timeout:    .res 2
