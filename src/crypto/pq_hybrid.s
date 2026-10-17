; =============================================================================
; pq_hybrid.s - PQ_HYBRID=1: X25519MLKEM768 client side, PQC plan phase P4.
; Linked only under PQ_HYBRID=1 (the Makefile filters it out otherwise), so an
; unset build is byte-identical to one that has never heard of it.
;
;   pq_connect_prep   tls_connect, between the X25519 keypair and the
;                     ClientHello: DRBG-fill the 64 B d||z seed, KeyGen, zero
;                     the 2,400 B dk at once, arm the sectioned ClientHello
;                     with the ek. C=1: refused (tls_sh_err = SH_ERR_PQ_KEYGEN).
;   pq_sh_init        start of tls_recv_server_hello.
;   pq_sh_feed        once per plaintext record: feed the record's bytes to the
;                     ServerHello state machine and fold them into the
;                     transcript. C=1: refused (tls_sh_err); C=0 with Z=1: the
;                     message is complete; C=0 with Z=0: wait for another record.
;   pq_sh_decaps      after the ServerHello (and the drain): if the server chose
;                     11EC, Decaps the ct into tls_mlkem_ss; always scrubs the
;                     seed. C=1: refused (SH_ERR_PQ_DECAPS).
;   pq_secrets_zero   tls_connect's error exit: seed + ss.
;
; The ServerHello is NOT buffered. A hybrid one is 1,178 B and a server
; fragments it under max_fragment_length (OpenSSL: 512 + 512 + 154), while the
; record buffer is 548 B, so it is read through a byte-at-a-time machine:
; each state is "gather N bytes to a destination, then run a handler". The
; handlers check the fields and arm the next state; nothing is held but the
; 16-bit field count, the 16-bit bytes-left-in-message and a 6 B gather
; buffer. Every record's bytes are folded into the transcript exactly once,
; in wire order, right after its bytes were parsed (before the next record
; overwrites tls_rec_buf, and before X25519_SCRATCH, which overlays it, runs).
;
; WHAT IT ACCEPTS (everything else is refused with a distinct tls_sh_err,
; src/constants.inc): handshake type 2, total length 40..1535; legacy_version
; 0303; an EMPTY session id echo (what we sent); suite 1303; compression 0;
; extension block exactly filling the message; supported_versions = 0304 once;
; key_share once, group 001D with a 32 B share, or group 11EC with a 1,120 B
; share (ML-KEM ct 1,088 || x25519 32) and only if the hybrid was offered;
; unknown extensions are skipped (as the single-record parser did) but must fit.
; The HelloRetryRequest random is a refusal (SH_ERR_HRR). A zero-length record,
; a non-handshake record mid-message and any byte after the message are
; refusals.
;
; HANDSHAKE ORDER (#152). TLS_HS_SEQ_CHECK derives the one legal type from
; tls_state and is wired to the post-ServerHello dispatchers; here the first
; message is checked by the machine's own header state (type must be 2), which
; is the same rule - the ServerHello is the only legal first message - and a
; second message type cannot get in, because the length field bounds the
; machine and DONE refuses every further byte. Reusing the macro would only add
; its table lookup in front of the same comparison.
;
; WHERE THINGS LIVE. ek (1,184 B) and ct (1,088 B) both use cert_buf: the ek is
; dead once the ClientHello is sent, the ct once Decaps returns, and nothing
; writes cert_buf between KeyGen and Certificate except the comb cold bank,
; which refuses to run while tls_state is not IDLE/ERROR. The 64 B seed and the
; 32 B ML-KEM secret are in NET_BSS_TAIL, below $4200: not cert_buf, not
; tls_rec_buf (X25519_SCRATCH), not the $B100 ML-KEM window, not $D000-$DFFF,
; not the TCP ring. src/session_scrub.s zeroes both.
; =============================================================================

.ifndef PQ_HYBRID
.error "pq_hybrid.s is PQ_HYBRID-only; the Makefile filters it out otherwise"
.endif

.include "constants.inc"

.export pq_connect_prep, pq_sh_init, pq_sh_feed, pq_sh_decaps
.export pq_secrets_zero, pq_seed_zero
.export tls_pq_seed, tls_mlkem_ss, tls_kex_group, tls_pq_offered
.export shs_state

.import cert_buf
.import tls_server_random, tls_server_pubkey
.import tls_rec_buf, tls_rec_len, tls_rec_type
.import tls_sh_err, tls_sh_chk_hrr
.import tls_ch_ks_ptr, tls_ch_ks_len
.import tls_transcript_update
.import drbg_fill_bytes
.import pq_mlkem_keygen, pq_mlkem_decaps_seed
.import mlkem_arg_ek, mlkem_arg_dk, mlkem_arg_ct, mlkem_arg_key, mlkem_arg_seed, mlkem_arg_z
.import __NET_BSS_TAIL_START__

; --- Secrets and state (NET_BSS_TAIL: file-backed zero, below cert_buf) ------
.segment "NET_BSS_TAIL"
tls_pq_seed:    .res MLKEM_SEED_SIZE    ; d || z, DRBG output; live KeyGen..Decaps
tls_mlkem_ss:   .res MLKEM_SS_SIZE      ; Decaps' K (P5: mlkem_ss || x25519_ss)
tls_kex_group:  .res 1                  ; 0 none yet, $1D x25519, $EC hybrid (P5 reads)
tls_pq_offered: .res 1                  ; 1 = this connection's ClientHello offered 11EC
shs_state:      .res 1
shs_cnt:        .res 2                  ; bytes left in the current field
shs_rem:        .res 2                  ; bytes left in the message after its header
shs_d:          .res 2                  ; length of the extension being read
shs_f:          .res 6                  ; gather buffer for the small fields
shs_seen:       .res 1                  ; bit0 supported_versions, bit1 key_share

; The seed + ss pair is one scrub span (src/session_scrub.s) and must sit in
; the free tail of the NET_BSS_TAIL region, below cert_buf and clear of every
; union the ML-KEM, X25519 and P-256 buffers use.
.assert tls_mlkem_ss = tls_pq_seed + MLKEM_SEED_SIZE, lderror, "tls_mlkem_ss must follow tls_pq_seed (one scrub span)"
.assert tls_pq_seed >= __NET_BSS_TAIL_START__, lderror, "tls_pq_seed is below NET_BSS_TAIL"
.assert tls_mlkem_ss + MLKEM_SS_SIZE <= cert_buf, lderror, "PQ secrets overlap cert_buf"
; pq_set_args writes the library's parameter block as one 12-byte struct.
.assert mlkem_arg_dk = mlkem_arg_ek + 2, lderror, "mlkem_arg_* is no longer one contiguous struct (dk)"
.assert mlkem_arg_ct = mlkem_arg_ek + 4, lderror, "mlkem_arg_* is no longer one contiguous struct (ct)"
.assert mlkem_arg_key = mlkem_arg_ek + 6, lderror, "mlkem_arg_* is no longer one contiguous struct (key)"
.assert mlkem_arg_seed = mlkem_arg_ek + 8, lderror, "mlkem_arg_* is no longer one contiguous struct (seed)"
.assert mlkem_arg_z = mlkem_arg_ek + 10, lderror, "mlkem_arg_* is no longer one contiguous struct (z)"
.assert (tls_pq_seed + MLKEM_SEED_SIZE + MLKEM_SS_SIZE) < $4200, lderror, "PQ secrets are not below $4200"

SS_HDR  = 0
SS_VER  = 1
SS_RND  = 2
SS_FIX  = 3
SS_EXH  = 4
SS_SV   = 5
SS_KSH  = 6
SS_CT   = 7
SS_PUB  = 8
SS_SKIP = 9
SS_DONE = 10

SHS_MAX_HI = 6                          ; message length < 6*256 = 1536

        .segment "PQ_GLUE"

; -----------------------------------------------------------------------------
; The parameter block. libs/mlkem keeps six 16-bit pointers (ek dk ct key seed
; z) contiguous in LIB_MLKEM_BSS, a window X25519 rebuilds: fill it after the
; last X25519 and right before the call. One table serves KeyGen (ek, dk, d, z)
; and Decaps-from-seed (seed = d||z, ct, key); each ignores the rest.
; -----------------------------------------------------------------------------
pq_set_args:
        ldx #11
:       lda pq_arg_tab,x
        sta mlkem_arg_ek,x
        dex
        bpl :-
        rts
pq_arg_tab:
        .word cert_buf, mlkem_dk_scratch, cert_buf, tls_mlkem_ss
        .word tls_pq_seed, tls_pq_seed + 32

; pq_secrets_zero / pq_seed_zero: zero seed + ss (96 B) / the seed (64 B).
pq_secrets_zero:
        ldx #MLKEM_SEED_SIZE + MLKEM_SS_SIZE
        bne pq_zero_x
pq_seed_zero:
        ldx #MLKEM_SEED_SIZE
pq_zero_x:
        lda #0
:       dex
        sta tls_pq_seed,x
        bne :-
        rts

; pq_dk_zero: zero the 2,400 B dk scratch (the TCP ring base).
pq_dk_zero:
        lda #<mlkem_dk_scratch
        sta zp_ptr
        lda #>mlkem_dk_scratch
        sta zp_ptr+1
        ldx #>MLKEM_DK_SIZE
        ldy #0
        tya
:       sta (zp_ptr),y
        iny
        bne :-
        inc zp_ptr+1
        dex
        bne :-
:       sta (zp_ptr),y          ; the last <MLKEM_DK_SIZE bytes
        iny
        cpy #<MLKEM_DK_SIZE
        bne :-
        rts

; -----------------------------------------------------------------------------
; pq_connect_prep - KeyGen and arm the ClientHello. Called by tls_connect after
; tls_ecdh_generate_keypair (the last X25519 before the hello) and before
; tls_send_client_hello.
; ORDERING (src/constants.inc, mlkem_dk_scratch): the dk lands in the TCP ring.
; tls_connect has reset the ring (tls_rx_reset) and has not polled since, and
; the server speaks only after our ClientHello, so no server byte can be in it;
; the dk is zeroed right after KeyGen returns, before the first net_poll.
; Out: C=0 armed (tls_ch_ks_ptr = cert_buf, tls_ch_ks_len = 1,184);
;      C=1 tls_sh_err = SH_ERR_PQ_KEYGEN, nothing armed, dk already zeroed.
; -----------------------------------------------------------------------------
pq_connect_prep:
        lda #0
        sta tls_pq_offered
        jsr pq_secrets_zero             ; no earlier session's ss survives
        lda #<tls_pq_seed
        sta zp_ptr
        lda #>tls_pq_seed
        sta zp_ptr+1
        lda #MLKEM_SEED_SIZE
        jsr drbg_fill_bytes
        jsr pq_set_args
        jsr pq_mlkem_keygen             ; C=1/A=$FF refused; C=0: A = status
        pha
        jsr pq_dk_zero                  ; BEFORE anything else, success or not
        pla
        bne @fail                       ; refusal ($FF) or a non-zero status
        lda #<cert_buf
        sta tls_ch_ks_ptr
        lda #>cert_buf
        sta tls_ch_ks_ptr+1
        lda #<MLKEM_EK_SIZE
        sta tls_ch_ks_len
        lda #>MLKEM_EK_SIZE
        sta tls_ch_ks_len+1
        inc tls_pq_offered
        clc
        rts
@fail:  lda #SH_ERR_PQ_KEYGEN
        sta tls_sh_err
        sec
        rts

; -----------------------------------------------------------------------------
; pq_sh_decaps - Decaps the ServerHello's ct if the server chose 11EC.
; The args are rewritten here: nothing may sit between them and the call.
; The seed is zeroed on every successful exit (no longer needed); the secrets
; are zeroed by tls_connect's error exit otherwise.
; -----------------------------------------------------------------------------
pq_sh_decaps:
        lda tls_kex_group
        cmp #$EC
        bne @done
        jsr pq_set_args
        jsr pq_mlkem_decaps_seed        ; A = status; C=1/A=$FF refused
        bcs @fail
        cmp #0
        bne @fail
@done:  jsr pq_seed_zero
        clc
        rts
@fail:  lda #SH_ERR_PQ_DECAPS
        sta tls_sh_err
        sec
        rts

        .segment "PQ_CODE"

; -----------------------------------------------------------------------------
; The ServerHello machine. State tables, indexed by SS_*: field length, and the
; destination (high byte 0 = discard).
; -----------------------------------------------------------------------------
tab_cl: .byte 4, 2, 32, 6, 4, 2, 4, <MLKEM_CT_SIZE, 32, 0, 0
tab_ch: .byte 0, 0, 0,  0, 0, 0, 0, >MLKEM_CT_SIZE, 0,  0, 0
tab_dl: .byte <shs_f, <shs_f, <tls_server_random, <shs_f, <shs_f, <shs_f, <shs_f, <cert_buf, <tls_server_pubkey, 0, 0
tab_dh: .byte >shs_f, >shs_f, >tls_server_random, >shs_f, >shs_f, >shs_f, >shs_f, >cert_buf, >tls_server_pubkey, 0, 0

; Handlers, entered by RTS-dispatch from shs_byte with the field complete.
; Out: C=0 (next state armed) or C=1, tls_sh_err set.
hnd_l: .byte <(h_hdr-1), <(h_ver-1), <(h_rnd-1), <(h_fix-1), <(h_exh-1), <(h_sv-1), <(h_ksh-1), <(h_ct-1), <(h_pub-1), <(h_skip-1)
hnd_h: .byte >(h_hdr-1), >(h_ver-1), >(h_rnd-1), >(h_fix-1), >(h_exh-1), >(h_sv-1), >(h_ksh-1), >(h_ct-1), >(h_pub-1), >(h_skip-1)

; pq_sh_init - fresh machine, clean error code.
pq_sh_init:
        lda #0
        sta tls_sh_err
        sta shs_seen
        sta tls_kex_group
        lda #SS_HDR
        ; fall through

; shs_arm - A = state: load its count and destination. Out: C=0.
shs_arm:
        sta shs_state
        tax
        lda tab_cl,x
        sta shs_cnt
        lda tab_ch,x
        sta shs_cnt+1
        lda tab_dl,x
        sta shs_st+1
        lda tab_dh,x
        sta shs_st+2
        clc
        rts

shs_fail:
        sta tls_sh_err
        sec
        rts

; shs_byte - A = the next ServerHello byte. Out: C=0, or C=1 with tls_sh_err.
shs_byte:
        ldx shs_state
        cpx #SS_DONE
        bne shs_live
        lda #SH_ERR_TRAIL
        bne shs_fail
shs_live:  ldy shs_st+2
        beq shs_nost
shs_st: sta $FFFF                       ; operand patched by shs_arm
        inc shs_st+1
        bne shs_nost
        inc shs_st+2
shs_nost:  cpx #SS_HDR                     ; the header is not counted in the length
        beq shs_nodec
        lda shs_rem
        bne :+
        dec shs_rem+1
:       dec shs_rem
shs_nodec: lda shs_cnt
        bne :+
        dec shs_cnt+1
:       dec shs_cnt
        lda shs_cnt
        ora shs_cnt+1
        beq shs_field
        clc
        rts
shs_field: lda hnd_h,x
        pha
        lda hnd_l,x
        pha
        rts                             ; "returns" into the handler

; --- handlers ----------------------------------------------------------------
; Each handler keeps its own error stubs: a branch reaches only +-127 B and the
; handlers together are ~400 B, so one shared stub block would be out of range.
h_hdr:  lda shs_f                       ; type
        cmp #TLS_HS_SERVER_HELLO
        bne @bad
        lda shs_f+1                     ; length is 24-bit: top byte 0
        bne @bad
        lda shs_f+2
        cmp #SHS_MAX_HI
        bcs @bad
        sta shs_rem+1
        lda shs_f+3
        sta shs_rem
        lda shs_rem+1
        bne @len_ok
        lda shs_rem
        cmp #40                         ; version 2 + random 32 + fixed 6
        bcc @bad
@len_ok:
        lda #SS_VER
        jmp shs_arm
@bad:   lda #SH_ERR_HDR
        jmp shs_fail

h_ver:  lda shs_f
        cmp #$03
        bne @bad
        lda shs_f+1
        cmp #$03
        bne @bad
        lda #SS_RND
        jmp shs_arm
@bad:   lda #SH_ERR_FIXED
        jmp shs_fail

h_rnd:  jsr tls_sh_chk_hrr              ; C=1: tls_sh_err = SH_ERR_HRR
        bcs @hrr
        lda #SS_FIX
        jmp shs_arm
@hrr:   lda #SH_ERR_HRR
        jmp shs_fail

h_fix:  lda shs_f                       ; session id echo length 0
        bne @bad
        lda shs_f+1                     ; suite 1303
        cmp #$13
        bne @bad
        lda shs_f+2
        cmp #$03
        bne @bad
        lda shs_f+3                     ; compression null
        bne @bad
        lda shs_f+4                     ; extensions_length == what is left
        cmp shs_rem+1
        bne @ext
        lda shs_f+5
        cmp shs_rem
        bne @ext
        jmp ext_next
@bad:   lda #SH_ERR_FIXED
        jmp shs_fail
@ext:   lda #SH_ERR_EXTLEN
        jmp shs_fail

; ext_next - the previous extension is complete: another header, or the end.
ext_next:
        lda shs_rem
        ora shs_rem+1
        bne @more
        lda shs_seen                    ; end of message
        cmp #3
        bne @missing
        lda #SS_DONE
        jmp shs_arm
@more:  lda shs_rem+1
        bne @hdr
        lda shs_rem
        cmp #4
        bcc @ext
@hdr:   lda #SS_EXH
        jmp shs_arm
@missing:
        lda #SH_ERR_MISSING
        jmp shs_fail
@ext:   lda #SH_ERR_EXTLEN
        jmp shs_fail

h_exh:  lda shs_f+2                     ; D = data length
        sta shs_d+1
        lda shs_f+3
        sta shs_d
        lda shs_rem                     ; D must fit in what is left
        cmp shs_d
        lda shs_rem+1
        sbc shs_d+1
        bcc @ext
        lda shs_f                       ; type
        bne @other
        lda shs_f+1
        cmp #$2b
        beq @sv
        cmp #$33
        beq @ks
@other: lda shs_d
        ora shs_d+1
        beq @none
        lda #SS_SKIP
        jsr shs_arm
        lda shs_d
        sta shs_cnt
        lda shs_d+1
        sta shs_cnt+1
        rts                             ; C=0 from shs_arm
@none:  jmp ext_next
@sv:    lda shs_seen
        and #1
        bne @ver
        lda shs_d+1
        bne @ver
        lda shs_d
        cmp #2
        bne @ver
        lda #SS_SV
        jmp shs_arm
@ks:    lda shs_seen
        and #2
        bne @kslen
        lda shs_d+1
        bne @ks_ok
        lda shs_d
        cmp #4
        bcc @kslen
@ks_ok: lda #SS_KSH
        jmp shs_arm
@ext:   lda #SH_ERR_EXTLEN
        jmp shs_fail
@ver:   lda #SH_ERR_VERSION
        jmp shs_fail
@kslen: lda #SH_ERR_KSLEN
        jmp shs_fail

h_sv:   lda shs_f
        cmp #$03
        bne @bad
        lda shs_f+1
        cmp #$04
        bne @bad
        lda shs_seen
        ora #1
        sta shs_seen
        jmp ext_next
@bad:   lda #SH_ERR_VERSION
        jmp shs_fail

h_ksh:  lda shs_f+3                     ; key length + 4 must equal D
        clc
        adc #4
        tax
        lda shs_f+2
        adc #0
        cmp shs_d+1
        bne @kslen
        cpx shs_d
        bne @kslen
        lda shs_f                       ; group
        beq @g00
        cmp #$11
        bne @grp
        lda shs_f+1
        cmp #$ec
        bne @grp
        lda tls_pq_offered              ; 11EC only if this hello offered it
        beq @grp
        lda shs_f+2                     ; exactly 1,120
        cmp #>MLKEM_HYB_SH_KEY
        bne @kslen
        lda shs_f+3
        cmp #<MLKEM_HYB_SH_KEY
        bne @kslen
        lda #$ec
        sta tls_kex_group
        lda #SS_CT
        jmp shs_arm
@g00:   lda shs_f+1
        cmp #$1d
        bne @grp
        lda shs_f+2                     ; exactly 32
        bne @kslen
        lda shs_f+3
        cmp #32
        bne @kslen
        lda #$1d
        sta tls_kex_group
        lda #SS_PUB
        jmp shs_arm
@grp:   lda #SH_ERR_GROUP
        jmp shs_fail
@kslen: lda #SH_ERR_KSLEN
        jmp shs_fail

h_ct:   lda #SS_PUB                     ; the x25519 share follows the ct
        jmp shs_arm

h_pub:  lda shs_seen
        ora #2
        sta shs_seen
        jmp ext_next

h_skip: jmp ext_next

; -----------------------------------------------------------------------------
; pq_sh_feed - one plaintext record (tls_rec_buf / tls_rec_len / tls_rec_type).
; Out: C=1 refused (tls_sh_err set); C=0, Z=1 the ServerHello is complete,
;      C=0, Z=0 it needs another record.
; -----------------------------------------------------------------------------
pq_sh_feed:
        lda tls_rec_type
        cmp #TLS_CT_HANDSHAKE
        bne @bad_rec
        lda tls_rec_len
        ora tls_rec_len+1
        bne @ok_rec
@bad_rec:
        lda #SH_ERR_RECTYPE
        jmp shs_fail
@ok_rec:
        lda #<tls_rec_buf
        sta zp_ptr
        lda #>tls_rec_buf
        sta zp_ptr+1
        lda tls_rec_len
        sta zp_count
        lda tls_rec_len+1
        sta zp_count+1
@byte:  ldy #0
        lda (zp_ptr),y
        jsr shs_byte
        bcs @out
        inc zp_ptr
        bne :+
        inc zp_ptr+1
:       lda zp_count
        bne :+
        dec zp_count+1
:       dec zp_count
        lda zp_count
        ora zp_count+1
        bne @byte
        lda #<tls_rec_buf               ; fold the record, once, in order
        sta zp_ptr
        lda #>tls_rec_buf
        sta zp_ptr+1
        lda tls_rec_len
        sta zp_count
        lda tls_rec_len+1
        sta zp_count+1
        jsr tls_transcript_update
        clc
        lda shs_state
        eor #SS_DONE                    ; Z=1: complete; C stays 0
@out:   rts
