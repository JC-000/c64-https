; =============================================================================
; cert_pin.s — leaf SubjectPublicKeyInfo pin (issue #155, phase 1)
;
; `make HTTPS_PIN_SPKI_SHA256=<64 hex>` compiles in the SHA-256 of the
; server's leaf SPKI DER — the value `tools/spki_pin.py` prints, byte-identical
; to `openssl x509 -pubkey | openssl pkey -pubin -outform DER | sha256`. Unset,
; this translation unit assembles to nothing and every PRG is unchanged.
;
; WHAT IS HASHED — read before "fixing" it to walk the DER structure.
; The live key extractor, x509_extract_pubkey (src/tls_cert.s), does not parse
; the certificate: it SCANS for the first ecPublicKey OID and copies the
; point after it. A pin computed over the structurally-parsed SPKI
; (der_decode.s step 4g) would therefore pin one key and verify another: a
; certificate whose real SPKI is the pinned one, with the attacker's own SPKI
; bytes planted earlier (in the subject, say), passes that pin while
; CertificateVerify is checked against the attacker's key. So the hash is
; taken over the 91 bytes the extractor ACTUALLY read the key from: the window
; ending at the last byte of Qy. A P-256 SPKI is always
;
;   30 59 30 13 06 07 <ecPublicKey> 06 08 <prime256v1> 03 42 00 04 Qx Qy
;   \______________ 27 bytes ______________________/        32  32  = 91
;
; and SHA-256 fixes every byte of the window, so a matching hash means Qx sat
; at window+27 and Qy at window+59 — exactly where the extractor copied
; ecdsa_pubkey_x/y from. Where in the certificate the window sits does not
; matter; which key gets verified does. P-256 leaves only: ecdsa_curve_id
; must be 0, because a P-384 extraction writes the _384 slots and leaves
; ecdsa_pubkey_x/y holding whatever an EARLIER connection put there.
;
; POSITIVE FLAG, not abort-on-mismatch (#152 interlock). cert_pin_status is
; zeroed every connection as the handshake keys are derived (cert_pin_hs_keys,
; which tls_connect calls in place of tls_derive_handshake_keys — no
; Certificate can be processed before those keys exist) and set only by
; cert_pin_check. tls_connect calls cert_pin_send_finished in place of
; tls_send_finished, which refuses (C=1, nothing sent) unless
; cert_pin_require passes; its caller's existing abort does the rest. A flight
; that never delivers a Certificate never runs the check, and fails there.
; Wrapping the two existing calls is what keeps the pin at ZERO bytes in
; tls13.s / boot.s, i.e. in ip65's LOADER.
;
;   cert_pin_status   $00  check has not run this connection
;                     $01  SPKI matched the pin
;                     $80  mismatch (or non-P-256 leaf). Enforce builds abort
;                          the Certificate; HTTPS_PIN_WARN=1 builds report and
;                          continue, and the flag still records that it ran.
;
; No zero page and no BSS of its own (same convention as x509_name.s): the
; status byte lives in CERT_PIN_UI, which every cfg keeps in RAM.
;
; TRUST_STORE=1 (#155 phase 2, L3) makes this file the trust policy's ONE
; resident hook, pinned build or not: the same hash, the same interlock,
; but what the hash is compared with comes from tp_mode, which trust_pre
; (src/net/uci/trust_policy.s) sets before the dial:
;
;   TP_M_STORE     the store's record for the typed host (ts_rec). A
;                  mismatch is KEY CHANGED and aborts, unless the operator
;                  armed the override with exactly this 32 B hash (ACCEPT);
;   TP_M_FIRST     first use: nothing to compare, continue;
;   TP_M_UNPINNED  the operator's one-fetch override: continue;
;   TP_M_PIN       the build pin (typed host == HTTPS_HOST), as above;
;   TP_M_NONE      trust_pre never ran: refuse.
;
; The hash goes to tp_got for trust_post, which records it after the close.
; Under TRUST_BUNDLE a signed bundle's leaf pin (tb_spki) is advisory: a
; mismatch prints BUNDLE MISMATCH and sets tp_bwarn, never aborts.
; cert_pin_status takes the TP_ST_* verdicts (src/trust_policy.inc): only a
; positive one lets cert_pin_require pass. Nothing here reads the keyboard.
; Without TRUST_STORE every byte below assembles exactly as before.
; =============================================================================

.include "constants.inc"

.if .defined(HTTPS_PIN_SPKI) .or .defined(TRUST_STORE)

.ifdef HTTPS_PIN_SPKI
.include "https_host.inc"               ; HTTPS_PIN_SPKI_BYTES
.endif

.export cert_pin_check
.export cert_pin_require
.ifdef HTTPS_PIN_SPKI
.export cert_pin_banner
.endif
.export cert_pin_hs_keys
.export cert_pin_send_finished
.export cert_pin_status
.ifdef HTTPS_PIN_SPKI
.export cert_pin_expected
.endif

.ifdef TRUST_STORE
.include "trust_store.inc"
.include "trust_policy.inc"
.export tp_mode, tp_bwarn, tp_ovr_armed, tp_got, tp_override, tp_ovr_key
.export print_hex4, print_hexn, tp_cmp_got, trust_state_init
.import ts_rec
.ifdef TRUST_BUNDLE
.export tb_found, tb_spki
.import tb_loaded, tb_noted, tb_verdict
.endif
.endif

.import sha256_init
.import sha256_process_block
.import sha256_final
.import sha256_block
.import sha256_hash
.import ecdsa_curve_id
.import print_string
.import tls_derive_handshake_keys
.import tls_send_finished
.ifdef X509_VERIFY_NAME
.import x509_verify_hostname
.endif

PIN_SPKI_LEN    = 91                    ; P-256 SPKI TLV, tag to last Qy byte
PIN_Y_OFFSET    = 59                    ; Qy's offset inside that TLV
PIN_ST_MATCH    = $01
PIN_ST_BAD      = $80

; Under TRUST_STORE the hook has its own segment, so a cfg can place it
; without moving the plain pin's CERT_PIN_CODE (comb: NET_CODE, adv-268 /
; #273 -- CRYPTO_HOT has no room for it beside the wider body sink).
.ifdef TRUST_STORE
.segment "TRUST_HOOK_CODE"
.else
.segment "CERT_PIN_CODE"
.endif

; -----------------------------------------------------------------------------
; cert_pin_check — tail of x509_extract_pubkey's success exit
;   Input : zp_ptr -> Qy as the extractor copied it (zp_count = 32)
;   Output: C=0 accept (then the name check's verdict, if linked); C=1 reject
;   Clobbers: A, X, Y, zp_ptr, sha256 working state
; -----------------------------------------------------------------------------
cert_pin_check:
        sec                             ; window = Qy - 59
        lda zp_ptr
        sbc #PIN_Y_OFFSET
        sta zp_ptr
        bcs :+
        dec zp_ptr+1
:
        jsr sha256_init
        ldy #0                          ; Y walks the window
        ldx #0                          ; X walks the block
@fill:  lda (zp_ptr),y
        sta sha256_block,x
        iny
        inx
        cpx #64
        bne @more
        jsr sha256_process_block        ; the one full block; no zero page
        ldx #0
        ldy #64                         ; (it clobbers X/Y: restore both)
@more:  cpy #PIN_SPKI_LEN
        bne @fill
        lda #$80
@pad:   sta sha256_block,x
        lda #0
        inx
        cpx #64
        bne @pad
        lda #>(PIN_SPKI_LEN * 8)        ; bit length, big-endian, in [62..63]
        sta sha256_block+62
        lda #<(PIN_SPKI_LEN * 8)
        sta sha256_block+63
        jsr sha256_process_block
        jsr sha256_final

.ifndef TRUST_STORE
        lda ecdsa_curve_id              ; P-256 only — see the header
        bne @bad
        ldx #31
@cmp:   lda sha256_hash,x
        cmp cert_pin_expected,x
        bne @bad
        dex
        bpl @cmp
        lda #PIN_ST_MATCH
        sta cert_pin_status
@pass:
.ifdef X509_VERIFY_NAME
        jmp x509_verify_hostname        ; its carry IS our result (#135)
.else
        clc
        rts
.endif

@bad:
        lda #PIN_ST_BAD
        sta cert_pin_status
        jsr cert_pin_report
.ifdef HTTPS_PIN_WARN
        jmp @pass                       ; report, do not abort
.else
        sec
        rts
.endif

.else ; TRUST_STORE: the policy hook
        ldx #TP_HASH_LEN-1              ; keep it: sha256_hash is reused
:       lda sha256_hash,x               ;  long before trust_post runs
        sta tp_got,x
        dex
        bpl :-
        lda ecdsa_curve_id              ; P-256 only — see the header
        bne @refuse
        lda tp_mode
        cmp #TP_M_FIRST
        beq @set                        ; A = TP_ST_FIRST
        cmp #TP_M_UNPINNED
        beq @set                        ; A = TP_ST_UNPINNED
        cmp #TP_M_STORE
        beq @store
.ifdef HTTPS_PIN_SPKI
        cmp #TP_M_PIN
        beq @pin
.endif
@refuse:                                ; TP_M_NONE, or not a P-256 window
        lda #TP_ST_REFUSED
        sta cert_pin_status
        sec
        rts

@store:
        lda #<(ts_rec + TS_REC_SPKI)
        ldy #>(ts_rec + TS_REC_SPKI)
        jsr tp_cmp_got
        beq @match
        lda tp_ovr_armed                ; the operator's one-shot accept:
        beq @changed                    ;  all 32 bytes, or nothing
        lda #<tp_override
        ldy #>tp_override
        jsr tp_cmp_got
        bne @changed
        lda #TP_ST_ACCEPT
        bne @set                        ; always
@changed:
        lda #TP_ST_CHANGED
        sta cert_pin_status
        ldx #TP_REP_CHANGED
        jsr tp_report
        sec
        rts

.ifdef HTTPS_PIN_SPKI
@pin:
        lda #<cert_pin_expected
        ldy #>cert_pin_expected
        jsr tp_cmp_got
        beq @match
        ldx #TP_REP_PIN
        jsr tp_report
.ifdef HTTPS_PIN_WARN
        lda #TP_ST_PINWARN              ; report, do not abort
        bne @set
.else
        jmp @refuse
.endif
.endif

@match: lda #TP_ST_MATCH
@set:   sta cert_pin_status
.ifdef TRUST_BUNDLE
        ; Advisory only (DECISIONS 3). trust_pre clears tb_found for the
        ; build-pin mode, so this never second-guesses a build pin.
        lda tb_found
        beq @pass
        lda #<tb_spki
        ldy #>tb_spki
        jsr tp_cmp_got
        beq @pass
        lda #1                          ; NOT A: on a mismatch tp_cmp_got
        sta tp_bwarn                    ;  leaves the pin's byte there, $00 too
        ldx #TP_REP_BUNDLE
        jsr tp_report
.endif
@pass:
.ifdef X509_VERIFY_NAME
        jmp x509_verify_hostname        ; its carry IS our result (#135)
.else
        clc
        rts
.endif

; tp_cmp_got — A/Y = 32 B. Z=1 iff they equal tp_got. Clobbers zp_ptr, Y.
; Only Z is the verdict: on a mismatch A is whatever byte differed (maybe 0).
tp_cmp_got:
        sta zp_ptr
        sty zp_ptr+1
        ldy #TP_HASH_LEN-1
@c:     lda (zp_ptr),y
        cmp tp_got,y
        bne @out
        dey
        bpl @c
        lda #0                          ; Z=1: all equal
@out:   rts

; trust_state_init — boot (src/boot.s start): forget the policy's state.
; TRUST_POLICY_BSS is not under the boot-zeroed shadow, so without this an
; accept armed before 'Q' survives RUN (or a reset and SYS) -- adv-268 #2.
trust_state_init:
        lda #0
        ldx #tp_bss_end - tp_bss_start
:       sta tp_bss_start-1,x
        dex
        bne :-
.ifdef TRUST_BUNDLE
        sta tb_loaded
        sta tb_noted
        sta tb_verdict
.endif
        rts
.endif ; TRUST_STORE

; Everything below — the interlock, the status byte, the diagnostic and the
; pin itself — is a separate segment so the comb cfg can split the ~270 B
; across two regions (neither of its tails holds all of it with a long
; target string); the uci cfg puts both halves in CRYPTO_OVERLAY.
; Holds cert_pin_status: RAM only.
.segment "CERT_PIN_UI"

; -----------------------------------------------------------------------------
; cert_pin_require — the interlock tls_connect runs before traffic keys
;   Output: C=0 the pin check ran this connection and allows the handshake
;           (enforce: matched; warn: ran at all). C=1 otherwise.
; -----------------------------------------------------------------------------
cert_pin_require:
        lda cert_pin_status
.ifdef TRUST_STORE
        beq :+                          ; never ran
        bmi :+                          ; refused (TP_ST_CHANGED/_REFUSED)
        clc
        rts
:       sec
        rts
.elseif .defined(HTTPS_PIN_WARN)
        sec
        beq :+
        clc
:       rts
.else
        eor #PIN_ST_MATCH               ; 0 iff matched
        cmp #1                          ; C=1 iff not matched
        rts
.endif

cert_pin_status:
        .byte 0

; -----------------------------------------------------------------------------
; cert_pin_hs_keys — tls_connect's tls_derive_handshake_keys call site
; cert_pin_send_finished — tls_connect's tls_send_finished call site
; -----------------------------------------------------------------------------
cert_pin_hs_keys:
        lda #0
        sta cert_pin_status             ; new handshake: nothing pinned yet
        jmp tls_derive_handshake_keys

cert_pin_send_finished:
        jsr cert_pin_require
        bcs :+                          ; refused: send nothing, C=1
        jmp tls_send_finished
:       rts

; -----------------------------------------------------------------------------
; cert_pin_report — "PIN FAIL EXP xxxxxxxx GOT yyyyyyyy" ("PIN WARN ..." in
; warn mode): the first 4 bytes of both, so the operator reads the server's
; new fingerprint off the screen instead of meeting an undifferentiated stall.
; -----------------------------------------------------------------------------
.ifndef TRUST_STORE
cert_pin_report:
        lda #<pin_fail_msg
        ldy #>pin_fail_msg
        jsr print_string
        jsr print_expected4
        lda #<pin_got_msg
        ldy #>pin_got_msg
        jsr print_string
        lda #<sha256_hash
        ldy #>sha256_hash
        jsr print_hex4
        lda #$0d
        jmp chrout
.else
; tp_report — X = TP_REP_*: "<what> EXP xxxxxxxx GOT yyyyyyyy", the first
; 4 bytes of the expected hash and of tp_got. Clobbers A, X, Y, zp_ptr.
tp_report:
        lda tp_rep_msg_lo,x
        ldy tp_rep_msg_hi,x
        jsr print_string
        lda tp_rep_exp_lo,x
        ldy tp_rep_exp_hi,x
        jsr print_hex4
        lda #<pin_got_msg
        ldy #>pin_got_msg
        jsr print_string
        lda #<tp_got
        ldy #>tp_got
        jsr print_hex4
        lda #$0d
        jmp chrout

; One row per report: its message and the hash it was expecting.
.ifdef TRUST_BUNDLE
TP_BUNDLE_EXP = tb_spki
.else
TP_BUNDLE_EXP = 0                       ; no bundle: never reported
.endif
.define TP_REP_MSGS tp_changed_msg, tp_bundle_msg
.define TP_REP_EXPS ts_rec + TS_REC_SPKI, TP_BUNDLE_EXP
TP_REP_CHANGED  = 0
TP_REP_BUNDLE   = 1
TP_REP_PIN      = 2                     ; HTTPS_PIN_SPKI only
.ifdef HTTPS_PIN_SPKI
tp_rep_msg_lo:  .lobytes TP_REP_MSGS, pin_fail_msg
tp_rep_msg_hi:  .hibytes TP_REP_MSGS, pin_fail_msg
tp_rep_exp_lo:  .lobytes TP_REP_EXPS, cert_pin_expected
tp_rep_exp_hi:  .hibytes TP_REP_EXPS, cert_pin_expected
.else
tp_rep_msg_lo:  .lobytes TP_REP_MSGS
tp_rep_msg_hi:  .hibytes TP_REP_MSGS
tp_rep_exp_lo:  .lobytes TP_REP_EXPS
tp_rep_exp_hi:  .hibytes TP_REP_EXPS
.endif
.endif ; TRUST_STORE

.ifdef HTTPS_PIN_SPKI
.ifdef TRUST_STORE
; A pinned trust build: the pin's own pieces ride TRUST_HOOK_CODE, which
; the comb cfgs put where the room is (CERT_PIN_UI's region is the tighter one).
.segment "TRUST_HOOK_CODE"
.endif
; -----------------------------------------------------------------------------
; cert_pin_banner — boot banner line, so a pinned build is identifiable
; before it ever fails: "SPKI PIN xxxxxxxx" (+ " WARN" in warn mode). Takes
; boot.s's print_string call for the banner tail: prints the pin line, then
; the string in A/Y.
; -----------------------------------------------------------------------------
cert_pin_banner:
        pha
        tya
        pha
        jsr @line
        pla
        tay
        pla
        jmp print_string
@line:
        lda #<pin_banner_msg
        ldy #>pin_banner_msg
        jsr print_string
        jsr print_expected4
        lda #<pin_banner_tail
        ldy #>pin_banner_tail
        jmp print_string

print_expected4:
        lda #<cert_pin_expected
        ldy #>cert_pin_expected
        ; fall through
.endif
; print_hex4 — 4 bytes at A/Y (lo/hi) as 8 hex digits
.ifdef TRUST_STORE
; print_hexn — X bytes (1..255) at A/Y as 2X hex digits
.endif
print_hex4:
.ifdef TRUST_STORE
        ldx #4
print_hexn:
        stx @n+1
.endif
        sta zp_ptr
        sty zp_ptr+1
        ldy #0
@byte:  lda (zp_ptr),y
        pha
        lsr
        lsr
        lsr
        lsr
        jsr @nib
        pla
        and #$0f
        jsr @nib
        iny
@n:     cpy #4
        bne @byte
        rts
@nib:   cmp #10                         ; CHROUT preserves Y
        bcc :+
        adc #6                          ; C=1: +7 lands on 'A'
:       adc #'0'
        jmp chrout

.ifdef HTTPS_PIN_SPKI
.ifdef TRUST_STORE
.segment "TRUST_HOOK_CODE"
.endif
cert_pin_expected:
        .byte HTTPS_PIN_SPKI_BYTES
        .assert * - cert_pin_expected = 32, error, "HTTPS_PIN_SPKI_BYTES must be 32 bytes"

pin_fail_msg:
.ifdef HTTPS_PIN_WARN
        .byte "PIN WARN EXP ", 0
.else
        .byte "PIN FAIL EXP ", 0
.endif
.endif
pin_got_msg:
        .byte " GOT ", 0
.ifdef HTTPS_PIN_SPKI
pin_banner_msg:
        .byte "SPKI PIN ", 0
pin_banner_tail:
.ifdef HTTPS_PIN_WARN
        .byte " WARN"
.endif
        .byte $0d, 0
.endif

.ifdef TRUST_STORE
tp_changed_msg:
        .byte "KEY CHANGED EXP ", 0
tp_bundle_msg:
        .byte "BUNDLE MISMATCH EXP ", 0

; The policy's resident state: it outlives the cold calls that set and
; read it (src/net/uci/trust_policy.s) and the handshake in between.
.segment "TRUST_POLICY_BSS"
tp_bss_start:
tp_mode:      .res 1            ; TP_M_*: this connection's mode
tp_bwarn:     .res 1            ; != 0: the bundle pin disagreed
tp_ovr_armed: .res 1            ; != 0: tp_override applies to tp_ovr_key
tp_got:       .res TP_HASH_LEN  ; the server's SPKI hash, this connection
tp_override:  .res TP_HASH_LEN  ; the one hash the operator accepted
tp_ovr_key:   .res TS_KEY_SIZE  ; ...for this host key (ts_key)
.ifdef TRUST_BUNDLE
tb_found:     .res 1            ; != 0: tb_spki is the bundle's pin
tb_spki:      .res TP_HASH_LEN
.endif
tp_bss_end:
.assert tp_bss_end - tp_bss_start <= 255, error, "trust_state_init clears with X"
.endif

.endif ; HTTPS_PIN_SPKI .or TRUST_STORE
