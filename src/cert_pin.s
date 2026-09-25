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
; zeroed by tls_connect and written only here; tls_connect calls
; cert_pin_require before deriving traffic keys. A flight that never delivers
; a Certificate never runs this code, and fails there.
;
;   cert_pin_status   $00  check has not run this connection
;                     $01  SPKI matched the pin
;                     $80  mismatch (or non-P-256 leaf). Enforce builds abort
;                          the Certificate; HTTPS_PIN_WARN=1 builds report and
;                          continue, and the flag still records that it ran.
;
; No zero page and no BSS of its own (same convention as x509_name.s): the
; status byte lives in CERT_PIN_UI, which every cfg keeps in RAM.
; =============================================================================

.include "constants.inc"

.ifdef HTTPS_PIN_SPKI

.include "https_host.inc"               ; HTTPS_PIN_SPKI_BYTES

.export cert_pin_check
.export cert_pin_require
.export cert_pin_banner
.export cert_pin_status
.export cert_pin_expected

.import sha256_init
.import sha256_process_block
.import sha256_final
.import sha256_block
.import sha256_hash
.import ecdsa_curve_id
.import print_string
.ifdef X509_VERIFY_NAME
.import x509_verify_hostname
.endif

PIN_SPKI_LEN    = 91                    ; P-256 SPKI TLV, tag to last Qy byte
PIN_Y_OFFSET    = 59                    ; Qy's offset inside that TLV
PIN_ST_MATCH    = $01
PIN_ST_BAD      = $80

.segment "CERT_PIN_CODE"

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

; Everything below — the interlock, the status byte, the diagnostic and the
; pin itself — is a separate segment so the comb cfg can split the ~280 B
; across two regions: neither of its tails holds all of it, and the overlay
; tail is also HTTPS_TARGET_RODATA's budget, so the half that goes there is
; kept as small as possible. The uci cfg puts both halves in CRYPTO_OVERLAY.
; Holds cert_pin_status: RAM only.
.segment "CERT_PIN_UI"

; -----------------------------------------------------------------------------
; cert_pin_require — the interlock tls_connect runs before traffic keys
;   Output: C=0 the pin check ran this connection and allows the handshake
;           (enforce: matched; warn: ran at all). C=1 otherwise.
; -----------------------------------------------------------------------------
cert_pin_require:
        lda cert_pin_status
.ifdef HTTPS_PIN_WARN
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
; cert_pin_report — "PIN FAIL EXP xxxxxxxx GOT yyyyyyyy" ("PIN WARN ..." in
; warn mode): the first 4 bytes of both, so the operator reads the server's
; new fingerprint off the screen instead of meeting an undifferentiated stall.
; -----------------------------------------------------------------------------
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

; -----------------------------------------------------------------------------
; cert_pin_banner — boot banner line, so a pinned build is identifiable
; before it ever fails: "SPKI PIN xxxxxxxx" (+ " WARN" in warn mode).
; -----------------------------------------------------------------------------
cert_pin_banner:
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
; print_hex4 — 4 bytes at A/Y (lo/hi) as 8 hex digits
print_hex4:
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
        cpy #4
        bne @byte
        rts
@nib:   cmp #10                         ; CHROUT preserves Y
        bcc :+
        adc #6                          ; C=1: +7 lands on 'A'
:       adc #'0'
        jmp chrout

cert_pin_expected:
        .byte HTTPS_PIN_SPKI_BYTES
        .assert * - cert_pin_expected = 32, error, "HTTPS_PIN_SPKI_BYTES must be 32 bytes"

pin_fail_msg:
.ifdef HTTPS_PIN_WARN
        .byte "PIN WARN EXP ", 0
.else
        .byte "PIN FAIL EXP ", 0
.endif
pin_got_msg:
        .byte " GOT ", 0
pin_banner_msg:
        .byte "SPKI PIN ", 0
pin_banner_tail:
.ifdef HTTPS_PIN_WARN
        .byte " WARN"
.endif
        .byte $0d, 0

.endif ; HTTPS_PIN_SPKI
