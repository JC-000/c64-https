; =============================================================================
; x509_name.s — RFC 6125 server name validation (issue #135)
;
; Compares the leaf certificate's subjectAltName dNSName entries against the
; host we actually asked for (tls_hostname, populated by http_get for both the
; menu path and the DMA-trampoline path the rigs use).
;
; READ THIS BEFORE TRUSTING IT. Name validation alone does NOT authenticate a
; server. This client performs no certificate chain validation — no trust
; store, no root CAs, no issuer check — so an attacker who can redirect the
; connection can self-sign a certificate carrying the CORRECT name and this
; check passes it happily. What it buys is narrower: "any certificate is
; accepted" becomes "any certificate naming the right host is accepted". Real,
; modest, and documented as such under README's "What this client does NOT
; authenticate".
;
; SAN ONLY — no commonName fallback. RFC 6125 §6.4.4 deprecates CN, every
; CA-issued certificate since ~2017 carries SAN (all four real servers this
; project fetches from do), and omitting CN costs nothing in reach while
; saving a second parser to get wrong. A certificate with NO SAN extension is
; REJECTED, which is what current browsers do.
;
; No zero page of its own. State lives in storage inside this segment — the
; same convention der_decode.s uses for its @tbs_end — because
; CRYPTO_COLD_SHADOW is full in both backends and no new BSS was available.
; The three walks (optional-field scan, extension scan, name scan) are
; SEQUENTIAL, never nested, so they share one `limit` variable.
; =============================================================================

.include "constants.inc"

.ifdef X509_VERIFY_NAME
.export x509_verify_hostname

.import der_read_tag
.import der_read_length
.import der_skip
.import der_skip_tlv
.import der_len
.import cert_data_ptr
.import tls_hostname
.import tls_hostname_len
.endif

; Gated: the routine is 491 B and ip65's largest free block is 170 B
; (NET_CODE) — see the placement note in CLAUDE.md. Under BACKEND=ip65 this
; TU contributes nothing and the segment is `optional = yes`, so the link is
; unaffected; the call site in tls_cert.s is gated on the same symbol.
.ifdef X509_VERIFY_NAME

.segment "X509_NAME_CODE"

; -----------------------------------------------------------------------------
; x509_verify_hostname
;   Input : cert_data_ptr -> leaf DER; tls_hostname / tls_hostname_len
;   Output: C=0 a dNSName matched; C=1 no match / no SAN / malformed
;   Clobbers: A, X, Y, zp_ptr, der_len
; -----------------------------------------------------------------------------
x509_verify_hostname:
        lda tls_hostname_len            ; nothing to validate against
        bne :+
        sec
        rts
:
        lda cert_data_ptr
        sta zp_ptr
        lda cert_data_ptr+1
        sta zp_ptr+1

        jsr der_read_tag                ; Certificate SEQUENCE
        cmp #$30
        beq :+
        jmp fail
:
        jsr der_read_length

        jsr der_read_tag                ; TBSCertificate SEQUENCE
        cmp #$30
        beq :+
        jmp fail
:
        jsr der_read_length
        jsr set_limit                   ; limit = end of TBS

        jsr der_read_tag                ; [0] version, else serialNumber
        cmp #$a0
        bne @no_version
        jsr der_read_length
        jsr der_skip
        jsr der_skip_tlv                ; serialNumber
        jmp @after_serial
@no_version:
        jsr der_read_length
        jsr der_skip                    ; that tag WAS serialNumber
@after_serial:
        jsr der_skip_tlv                ; signature AlgorithmIdentifier
        jsr der_skip_tlv                ; issuer
        jsr der_skip_tlv                ; validity
        jsr der_skip_tlv                ; subject
        jsr der_skip_tlv                ; subjectPublicKeyInfo

@scan_opt:                              ; skip optional [1] / [2], find [3]
        jsr at_limit
        bcc :+
        jmp fail                        ; no extensions at all -> no SAN
:
        jsr der_read_tag
        cmp #$a3
        beq @found_exts
        jsr der_read_length
        jsr der_skip
        jmp @scan_opt

@found_exts:
        jsr der_read_length             ; [3] wrapper length
        jsr der_read_tag                ; Extensions SEQUENCE
        cmp #$30
        beq :+
        jmp fail
:
        jsr der_read_length
        jsr set_limit                   ; limit = end of extension list

@ext_loop:
        jsr at_limit
        bcc :+
        jmp fail                        ; every extension seen, no SAN
:
        jsr der_read_tag
        cmp #$30
        beq :+
        jmp fail
:
        jsr der_read_length
        clc                             ; this_end = start of the NEXT ext
        lda zp_ptr
        adc der_len
        sta this_end
        lda zp_ptr+1
        adc der_len+1
        sta this_end+1

        jsr der_read_tag                ; extnID
        cmp #$06
        bne @next_ext
        jsr der_read_length
        lda der_len+1
        bne @next_ext
        lda der_len
        cmp #3                          ; 2.5.29.17 -> 55 1D 11
        bne @next_ext
        ldy #0
        lda (zp_ptr),y
        cmp #$55
        bne @next_ext
        iny
        lda (zp_ptr),y
        cmp #$1d
        bne @next_ext
        iny
        lda (zp_ptr),y
        cmp #$11
        beq @found_san

@next_ext:
        lda this_end
        sta zp_ptr
        lda this_end+1
        sta zp_ptr+1
        jmp @ext_loop

@found_san:
        jsr der_skip                    ; past the OID value
        jsr der_read_tag
        cmp #$01                        ; optional critical BOOLEAN
        bne :+
        jsr der_read_length
        jsr der_skip
        jsr der_read_tag
:       cmp #$04                        ; extnValue OCTET STRING
        beq :+
        jmp fail
:
        jsr der_read_length
        jsr der_read_tag                ; GeneralNames SEQUENCE
        cmp #$30
        beq :+
        jmp fail
:
        jsr der_read_length
        jsr set_limit                   ; limit = end of the name list

@name_loop:
        jsr at_limit
        bcc :+
        jmp fail                        ; all names checked, none matched
:
        jsr der_read_tag
        pha
        jsr der_read_length
        pla
        cmp #$82                        ; [2] IMPLICIT IA5String = dNSName
        bne @skip_name
        jsr match_name
        bcc @match
@skip_name:
        jsr der_skip
        jmp @name_loop

@match:
        clc
        rts
fail:
        sec
        rts

; -----------------------------------------------------------------------------
; set_limit — limit = zp_ptr + der_len. Preserves zp_ptr and der_len.
; -----------------------------------------------------------------------------
set_limit:
        clc
        lda zp_ptr
        adc der_len
        sta limit
        lda zp_ptr+1
        adc der_len+1
        sta limit+1
        rts

; -----------------------------------------------------------------------------
; at_limit — C=1 when zp_ptr has reached or passed `limit`.
; -----------------------------------------------------------------------------
at_limit:
        lda zp_ptr+1
        cmp limit+1
        bcc @below
        bne @at
        lda zp_ptr
        cmp limit
        bcc @below
@at:    sec
        rts
@below: clc
        rts

; -----------------------------------------------------------------------------
; match_name — compare the dNSName at (zp_ptr), length der_len, against
; tls_hostname. Case-insensitive ASCII. Leftmost-label wildcards per RFC 6125
; §6.4.3: "*." matches exactly ONE label and the remainder must itself contain
; a dot, so *.com can never match example.com.
;
; MUST leave zp_ptr and der_len untouched — the caller still has to der_skip
; this name when it does not match.
;   Output: C=0 match, C=1 no match
; -----------------------------------------------------------------------------
match_name:
        lda der_len+1                   ; names are never >= 256 bytes
        bne no_match
        lda der_len
        beq no_match

        ldy #0                          ; Y = cert-name index
        ldx #0                          ; X = hostname index
        lda (zp_ptr),y
        cmp #'*'
        bne @lengths                    ; exact match: Y=0, X=0

        ; --- wildcard: cert is "*." + suffix ---
        lda der_len
        cmp #3                          ; need at least "*.x"
        bcc no_match
        ldy #1
        lda (zp_ptr),y
        cmp #'.'
        bne no_match
        ldy #2                          ; cert suffix starts here

        ; the suffix must itself contain a dot (rejects *.com)
        stx tmp                         ; X is still 0 here
@scan_dot:
        cpy der_len
        bcs no_match
        lda (zp_ptr),y
        cmp #'.'
        beq @suffix_ok
        iny
        bne @scan_dot
@suffix_ok:
        ldy #2                          ; restore cert suffix start

        ; host suffix starts after ITS first dot
@find_dot:
        cpx tls_hostname_len
        bcs no_match                    ; hostname has no dot -> no match
        lda tls_hostname,x
        cmp #'.'
        beq @got_dot
        inx
        bne @find_dot
@got_dot:
        inx

@lengths:
        ; remaining lengths must be equal, or a prefix would match
        sty tmp
        sec
        lda der_len
        sbc tmp
        sta clen
        stx tmp
        sec
        lda tls_hostname_len
        sbc tmp
        cmp clen
        bne no_match

@cmp_loop:
        cpy der_len
        bcs @equal                      ; consumed the whole name
        lda (zp_ptr),y
        jsr to_lower
        sta tmp
        lda tls_hostname,x
        jsr to_lower
        cmp tmp
        bne no_match
        iny
        inx
        bne @cmp_loop
@equal:
        clc
        rts
no_match:
        sec
        rts

; -----------------------------------------------------------------------------
; to_lower — fold A-Z to a-z. DNS names are case-insensitive (RFC 4343).
; -----------------------------------------------------------------------------
to_lower:
        cmp #'A'
        bcc :+
        cmp #'Z'+1
        bcs :+
        adc #$20                        ; C=0 here (bcc/bcs both fell through)
:       rts

limit:    .word 0
this_end: .word 0
tmp:      .byte 0
clen:     .byte 0

.endif ; X509_VERIFY_NAME
