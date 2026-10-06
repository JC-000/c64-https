; src/net/uci/trust_policy.s — the trust policy's no-connection halves
;
; Issue #155 phase 2, lane L3 (UCI, TRUST_STORE=1). Precedence: build pin
; (only for HTTPS_HOST) > signed bundle > trust on first use. The store's
; I/O is src/net/uci/trust_store.s; the resident hook that runs inside the
; handshake is src/cert_pin.s; the bundle is src/net/uci/trust_bundle.s.
; Modes and verdicts: src/trust_policy.inc.
;
; do_https_get (src/boot.s) calls, in order:
;
;   trust_pre     after the target prompt, BEFORE net_tcp_connect.
;                 Out: C=0 dial, tp_mode set; C=1 do not dial (reported).
;   trust_bundle  (TRUST_BUNDLE=1) checks the bundle trust_pre read.
;   ...           the dial and the handshake; the hook sets cert_pin_status
;   trust_post    after net_tcp_close, on EVERY exit after the dial.
;                 Out: C=0 dial this fetch again, unpinned (tp_mode =
;                 TP_M_UNPINNED); C=1 done. The carry is inverted on
;                 purpose: a cold-bank refusal returns C=1, which must not
;                 read as "redial".
;
; Every keyboard read in the policy is in this file, so none can happen
; while a socket is open: trust_pre returns before the dial and trust_post
; runs after the close (on comb the cold bank refuses both otherwise).
; Each question flushes the key buffer first: an answer typed before the
; question was shown does not count.
;
; trust_pre:
;   * typed host == HTTPS_HOST in a pinned build: TP_M_PIN. No store, no
;     bundle, no prompt, never recorded, never overridden (DECISIONS 11, Q2
;     and Q5): an enforcing pin stays enforcing.
;   * else trust_store_load(tls_hostname):
;       FAIL   "TRUST FAIL nn", then "CONTINUE UNPINNED? Y/N" (Q5). Y:
;              TP_M_UNPINNED for this one fetch, with the UNPINNED banner;
;              anything else: NOT DIALLED. The armed accept is dropped.
;       EMPTY  "TRUST STORE EMPTY" on every GET, then first use.
;       VALID  the host's record: TP_M_STORE. None: TP_M_FIRST.
;     An armed accept survives only if it was armed for THIS host key.
;     Under TRUST_BUNDLE, TRUST.P is then read into the ring.
;
; trust_post (only what this attempt earned; tp_mode is cleared on exit):
;   * TP_M_UNPINNED: the banner again, below the result. Never records.
;   * handshake completed (tls_reached_connected: server Finished verified,
;     the name check passed, client Finished sent) with
;       TP_ST_FIRST   record tp_got as TOFU — unless the bundle pin
;                     disagreed (tp_bwarn): then "RECORD KEY? A=YES" (Q3)
;                     and, on A, record it as ACCEPTED;
;       TP_ST_ACCEPT  record tp_got as ACCEPTED (it equals the armed hash);
;       anything else (MATCH, PINWARN) writes nothing.
;   * TP_ST_CHANGED (the store's key differs, no matching accept): print
;     the server's whole 32 B hash, then
;       "ACCEPT ON RETRY? A=YES": arm tp_override = exactly that hash for
;          this host key; the NEXT 'G' for the same host records it only
;          if the server presents that hash again;
;       otherwise "CONTINUE UNPINNED? Y/N" (Q5): Y redials this fetch with
;          TP_M_UNPINNED, which never records.
;   * The armed accept is consumed by every attempt that reaches here,
;     except the one that just armed it.
;
; Placement: TRUST_POLICY_CODE + TRUST_POLICY_RODATA. Resident on uci /
; uci-onchip; on comb they are linked into the cold bank's TRUST group
; beside the store, so the policy calls the store's cold_ts_* bodies
; directly (a cold tenant must never call cold_call: the fetch would
; overwrite it). TRUST_PROMPT_CODE (the shared question, the key reader,
; the hex helpers) rides the same group on comb; under TRUST_BUNDLE the
; group is full, so it is TRUST_PROMPT_RES, resident. The policy's state is
; resident: TRUST_POLICY_BSS (_RES under TRUST_BUNDLE), in src/cert_pin.s.

.include "constants.inc"
.include "trust_store.inc"
.include "trust_policy.inc"

.import print_string, print_hex4, print_hexn
.import tls_hostname, tls_reached_connected
.import cert_pin_status
.import tp_mode, tp_bwarn, tp_ovr_armed, tp_got, tp_override, tp_ovr_key
.import ts_state, ts_reason, ts_key, ts_rec
.import trust_store_lookup
.ifdef HTTPS_PIN_SPKI
.import http_host_target
.endif
.ifdef TRUST_BUNDLE
.import ts_read_file
.import tb_found, tb_loaded, tb_noted, TB_FILE_MAX
.endif

.export trust_pre, trust_post

TB_LETTER       = 'P' - 'A'     ; TRUST.P, beside the store's TRUST.A/.B
KEY_A           = $41           ; PETSCII 'A' / 'Y', unshifted
KEY_Y           = $59
NDX             = $c6           ; KERNAL keyboard buffer count
DISPLAY_LEN     = 12

.ifdef COLD_BANK
; uci-comb: the bodies run from the cold bank's TRUST group. These stubs
; are the public names; cold_call_ui reports a refusal ("COLD BANK FAIL")
; and returns C=1, which both callers read as "stop". A refusal by the
; bank itself (cold_err != 0: a socket in ERROR, a latched DMA timeout)
; skips the body's own clears, so the stub makes the one that must not be
; skipped: the attempt consumes the armed accept and the mode, resident.
.include "cold_bank.inc"
.import cold_call_ui, cold_err
.import cold_ts_load, cold_ts_stage, cold_ts_save
.export cold_tp_pre, cold_tp_post

.segment "CODE"
trust_pre:
        ldy #COLD_E_TP_PRE
        .byte $2C               ; bit abs: skips the ldy below
trust_post:
        ldy #COLD_E_TP_POST
        jsr cold_call_ui
        bcc @out                ; the body ran and said C=0
        lda cold_err
        beq @stop               ; the body ran: its clears are done
        lda #TP_M_NONE
        sta tp_mode
        sta tp_ovr_armed
@stop:  sec
@out:   rts
.assert TP_M_NONE = 0, error, "the refusal clears tp_ovr_armed with TP_M_NONE"

TP_TS_LOAD  = cold_ts_load
TP_TS_STAGE = cold_ts_stage
TP_TS_SAVE  = cold_ts_save
.else
.import trust_store_load, trust_store_stage, trust_store_save
TP_TS_LOAD  = trust_store_load
TP_TS_STAGE = trust_store_stage
TP_TS_SAVE  = trust_store_save
.endif

.segment "TRUST_POLICY_CODE"

; =============================================================================
; trust_pre — see the header.
; =============================================================================
.ifdef COLD_BANK
cold_tp_pre:
.else
trust_pre:
.endif
        lda #0
        sta cert_pin_status
        sta tp_bwarn
        sta tp_mode             ; refuse, until a mode is chosen below
.ifdef TRUST_BUNDLE
        sta tb_found
        sta tb_loaded
.endif
.ifdef HTTPS_PIN_SPKI
        jsr tp_is_build_host
        bne @store
        sta tp_ovr_armed        ; A = 0: an accept never reaches a pin
        lda #TP_M_PIN
        sta tp_mode
        lda #<tp_pin_msg
        ldy #>tp_pin_msg
        jsr print_string
        clc
        rts
@store:
.endif
        lda #<tls_hostname
        ldx #>tls_hostname
        jsr TP_TS_LOAD
        bcc @loaded
        ; Fail closed (S3 §4.3) unless the operator overrides this one
        ; fetch (DECISIONS 11, Q5). Either way the armed accept is gone.
        lda #0
        sta tp_ovr_armed
        lda #<tp_fail_msg       ; "TRUST FAIL nn"
        ldy #>tp_fail_msg
        jsr print_string
        lda #<ts_reason
        ldy #>ts_reason
        jsr tp_hex1_cr
        jsr tp_ask_unpinned
        bcc @ret                ; Y: dial this one fetch, unpinned
        lda #<tp_nodial_msg
        ldy #>tp_nodial_msg
        jsr print_string
        sec
@ret:   rts
@loaded:
        ; An armed accept belongs to one host key: any other host drops it.
        ldx #TS_KEY_SIZE-1
@ovr:   lda ts_key,x
        cmp tp_ovr_key,x
        bne @disarm
        dex
        bpl @ovr
        bmi @armed_ok           ; always
@disarm:
        lda #0
        sta tp_ovr_armed
@armed_ok:
        lda ts_state
        cmp #TS_ST_EMPTY
        bne @lookup
        lda #<tp_empty_msg      ; every GET: a deleted store stays visible
        ldy #>tp_empty_msg
        jsr print_string
@lookup:
        jsr trust_store_lookup
        bcc @known
        lda #TP_M_FIRST
        sta tp_mode
        lda #<tp_new_msg
        ldy #>tp_new_msg
        jsr print_string
        jmp @bundle
@known:
        lda #TP_M_STORE
        sta tp_mode
        lda #<tp_known_msg
        ldy #>tp_known_msg
        jsr print_string
        lda #<(ts_rec + TS_REC_SPKI)
        ldy #>(ts_rec + TS_REC_SPKI)
        jsr tp_hex4_cr
        lda tp_ovr_armed
        beq @bundle
        lda #<tp_armed_msg      ; "ACCEPT ARMED xxxxxxxx"
        ldy #>tp_armed_msg
        jsr print_string
        lda #<tp_override
        ldy #>tp_override
        jsr tp_hex4_cr
@bundle:
.ifdef TRUST_BUNDLE
        ; TRUST.P into the ring, for trust_bundle. The store image the
        ; ring held is already consumed into ts_rec.
        ldx #TB_LETTER
        lda #<(TB_FILE_MAX + 1) ; one more than fits: a bigger file shows
        ldy #>(TB_FILE_MAX + 1)
        jsr ts_read_file
        bne @no_bundle
        inc tb_loaded
        bne @dial               ; always
@no_bundle:
        cmp #TS_SLOT_ABSENT
        bne @bundle_err
        lda tb_noted            ; absent: say so once per boot
        bne @dial
        inc tb_noted
        lda #<tp_nobundle_msg
        ldy #>tp_nobundle_msg
        jsr print_string
        jmp @dial
@bundle_err:
        sta tp_tmp
        lda #<tp_bundle_rd_msg  ; "BUNDLE READ FAIL nn"
        ldy #>tp_bundle_rd_msg
        jsr print_string
        lda #<tp_tmp
        ldy #>tp_tmp
        jsr tp_hex1_cr
.endif
@dial:
        clc
        rts

; =============================================================================
; trust_post — see the header.
; =============================================================================
.ifdef COLD_BANK
cold_tp_post:
.else
trust_post:
.endif
        lda tp_mode
        cmp #TP_M_UNPINNED
        bne @not_unpinned
        jsr tp_unpinned_banner  ; below the result, where it is read
@done:
        lda #0                  ; the armed accept was this attempt's
        sta tp_ovr_armed
@keep_armed:
        lda #TP_M_NONE
        sta tp_mode             ; nothing is sticky
        sec
        rts
@not_unpinned:
        lda tls_reached_connected
        beq @refused
        lda cert_pin_status
        cmp #TP_ST_ACCEPT
        beq @accepted
        cmp #TP_ST_FIRST
        bne @done               ; MATCH / PINWARN: nothing to write
.ifdef TRUST_BUNDLE
        lda tp_bwarn
        beq @tofu
        lda #<tp_record_q_msg   ; Q3: the bundle disagreed at first use
        ldy #>tp_record_q_msg
        jsr print_string
        jsr tp_getkey
        cmp #KEY_A
        beq @accepted
        lda #<tp_notrec_msg
        ldy #>tp_notrec_msg
        jsr print_string
        jmp @done
@tofu:
.endif
        lda #TS_MODE_TOFU
        .byte $2C               ; bit abs: skips the lda below
@accepted:
        lda #TS_MODE_ACCEPTED
        jsr tp_record
        jmp @done

@refused:
        lda cert_pin_status
        cmp #TP_ST_CHANGED      ; only the store mode sets it
        bne @done
        jsr tp_changed          ; shows, asks, arms
        bcs @keep_armed         ; as the operator left it
        rts                     ; C=0: redial, unpinned

; tp_changed — after a KEY CHANGED refusal: show the server's whole hash
; (32 bits of it is grindable), then "ACCEPT ON RETRY? A=YES"; on A arm
; tp_override = exactly that hash for exactly this host key. Otherwise
; "CONTINUE UNPINNED? Y/N". Out: C=0 redial unpinned (tp_mode set); C=1
; done, tp_ovr_armed != 0 only if armed here.
tp_changed:
        lda tp_ovr_armed
        beq @show
        lda #<tp_notseen_msg    ; armed, and the server sent another key
        ldy #>tp_notseen_msg
        jsr print_string
@show:  lda #0                  ; the old accept is spent either way
        sta tp_ovr_armed
        lda #<tp_server_msg
        ldy #>tp_server_msg
        jsr print_string
        lda #<tp_got
        ldy #>tp_got
        jsr @half
        lda #<(tp_got + TP_HASH_LEN/2)
        ldy #>(tp_got + TP_HASH_LEN/2)
        jsr @half
        lda #<tp_accept_q_msg   ; "ACCEPT ON RETRY? A=YES"
        ldy #>tp_accept_q_msg
        jsr print_string
        jsr tp_getkey
        cmp #KEY_A
        beq :+
        jmp tp_ask_unpinned
:
        ldx #TP_HASH_LEN-1      ; arm: exactly the hash just shown...
@arm:   lda tp_got,x
        sta tp_override,x
        dex
        bpl @arm
        ldx #TS_KEY_SIZE-1      ; ...for exactly this host key
@armk:  lda ts_key,x
        sta tp_ovr_key,x
        dex
        bpl @armk
        inc tp_ovr_armed
        lda #<tp_armed_ok_msg
        ldy #>tp_armed_ok_msg
        jsr print_string
        sec
        rts
@half:  ldx #TP_HASH_LEN/2
        jsr print_hexn
        jmp tp_cr

; tp_record — A = TS_MODE_*: build ts_rec for this host from tp_got, stage
; it and save it; report the outcome. The store's load from trust_pre is
; still the current one: nothing touches the store in between.
tp_record:
        sta ts_rec + TS_REC_MODE
        ldx #TP_HASH_LEN-1
@spki:  lda tp_got,x
        sta ts_rec + TS_REC_SPKI,x
        dex
        bpl @spki
        lda #0
        sta ts_rec + TS_REC_FLAGS
        sta ts_rec + TS_REC_USES
        sta ts_rec + TS_REC_USES+1
        ldx #0                  ; display: the host's first 12 bytes,
        ldy #0                  ;  zero-padded (Y = 0 once it ends)
@disp:  lda tls_hostname,x
        bne :+
        ldy #$FF
:       cpy #0
        beq :+
        lda #0
:       sta ts_rec + TS_REC_DISPLAY,x
        inx
        cpx #DISPLAY_LEN
        bne @disp
        lda #<ts_rec            ; the store forces the host key to ts_key
        ldx #>ts_rec
        jsr TP_TS_STAGE
        jsr TP_TS_SAVE
        bcs @fail
        lda #<tp_recorded_msg
        ldy #>tp_recorded_msg
        jsr print_string
        lda #<tp_got
        ldy #>tp_got
        jmp tp_hex4_cr
@fail:
        lda ts_reason
        cmp #TS_R_FULL
        bne @err
        lda #<tp_full_msg       ; no eviction: the operator decides
        ldy #>tp_full_msg
        jmp print_string
@err:
        lda #<tp_savefail_msg
        ldy #>tp_savefail_msg
        jsr print_string
        lda #<ts_reason
        ldy #>ts_reason
        jmp tp_hex1_cr

tp_tmp:         .byte 0         ; written before it is read, every call

; The messages: their own segment, so the uci cfg can put them where the
; room is. On comb they ride the TRUST group with the code (cfg).
.segment "TRUST_POLICY_RODATA"

tp_empty_msg:   .byte "TRUST STORE EMPTY", $0d, 0
tp_new_msg:     .byte "TRUST: NEW HOST", $0d, 0
tp_known_msg:   .byte "TRUST: KNOWN KEY ", 0
tp_armed_msg:   .byte "ACCEPT ARMED ", 0
tp_fail_msg:    .byte "TRUST FAIL ", 0
tp_nodial_msg:  .byte "NOT DIALLED", $0d, 0
tp_recorded_msg: .byte "KEY RECORDED ", 0
tp_full_msg:    .byte "TRUST STORE FULL", $0d, 0
tp_savefail_msg: .byte "TRUST SAVE FAIL ", 0
tp_notseen_msg: .byte "ACCEPTED KEY NOT SEEN", $0d, 0
tp_server_msg:  .byte "SERVER KEY:", $0d, 0
tp_accept_q_msg: .byte "ACCEPT ON RETRY? A=YES ", 0
tp_armed_ok_msg: .byte "ACCEPT ARMED: G, SAME HOST", $0d, 0
.ifdef TRUST_BUNDLE
tp_record_q_msg: .byte "RECORD KEY? A=YES ", 0
tp_notrec_msg:  .byte "KEY NOT RECORDED", $0d, 0
tp_nobundle_msg: .byte "NO BUNDLE", $0d, 0
tp_bundle_rd_msg: .byte "BUNDLE READ FAIL ", 0
.endif

; =============================================================================
; TRUST_PROMPT_CODE: the shared question, the key reader and the hex
; helpers. Called only from trust_pre / trust_post, so on comb they can
; ride the cold TRUST group with them; under TRUST_BUNDLE that group is
; full and they are TRUST_PROMPT_RES, resident (the cfgs place both).
; =============================================================================
.ifdef TRUST_BUNDLE
.segment "TRUST_PROMPT_RES"
.else
.segment "TRUST_PROMPT_CODE"
.endif

; tp_ask_unpinned — "CONTINUE UNPINNED? Y/N". C=0 and tp_mode =
; TP_M_UNPINNED (banner shown) on Y; C=1 otherwise.
tp_ask_unpinned:
        lda #<tp_unpinned_q_msg
        ldy #>tp_unpinned_q_msg
        jsr print_string
        jsr tp_getkey
        cmp #KEY_Y
        sec
        bne @no
        lda #TP_M_UNPINNED
        sta tp_mode
        jsr tp_unpinned_banner
        clc
@no:    rts

tp_unpinned_banner:
        lda #<tp_unpinned_msg
        ldy #>tp_unpinned_msg
        jmp print_string

; tp_getkey — flush the key buffer, wait for one key, echo it and a
; RETURN. Out: A = the key (PETSCII).
tp_getkey:
        lda #0
        sta NDX                 ; only a key typed after the question
@wait:  jsr getin
        beq @wait
        pha
        cmp #$20                ; echo printable keys only: a CLR or a
        bcc @cr                 ;  colour key must not wipe the evidence
        cmp #$60
        bcs @cr
        jsr chrout
@cr:    jsr tp_cr
        pla
        rts

; tp_hex4_cr / tp_hex1_cr — 4 bytes / 1 byte at A/Y in hex, then RETURN.
tp_hex4_cr:
        jsr print_hex4
        jmp tp_cr
tp_hex1_cr:
        ldx #1
        jsr print_hexn
tp_cr:  lda #$0d
        jmp chrout

.ifdef HTTPS_PIN_SPKI
; tp_is_build_host — Z=1 iff tls_hostname is HTTPS_HOST, A-Z folded on
; both sides (the RETURN default copies the build string verbatim).
; Out: A = 0 when Z=1.
tp_is_build_host:
        ldy #$FF
@c:     iny
        lda http_host_target,y
        jsr @fold
        sta tp_fold_tmp
        lda tls_hostname,y
        jsr @fold
        cmp tp_fold_tmp
        bne @out
        cmp #0
        bne @c
@out:   rts
@fold:  cmp #'A'
        bcc :+
        cmp #'Z'+1
        bcs :+
        ora #$20
:       rts

tp_fold_tmp:    .byte 0         ; written before it is read
tp_pin_msg:     .byte "TRUST: BUILD PIN", $0d, 0
.endif

tp_unpinned_q_msg: .byte "CONTINUE UNPINNED? Y/N ", 0
tp_unpinned_msg:   .byte "** UNPINNED: KEY NOT CHECKED **", $0d, 0
