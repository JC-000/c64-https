; der_decode.s — X.509 ASN.1 DER decoder
; Converted from ACME to ca65 in Phase 3 Batch C.
;
; A "skip-and-seek" parser that extracts only the fields needed for TLS 1.3
; certificate verification: TBS bytes (for hashing), public key, and signature.
;
; Supports ECDSA with P-256 (secp256r1) and P-384 (secp384r1) certificates.
;
; ZP usage (Tier 1, always safe):
;   zp_ptr   ($FB-$FC) - parse cursor into certificate buffer
;   zp_temp  ($FD)      - temporary
;   zp_count ($FE)      - temporary

.include "constants.inc"

; --- Public exports: code ---
.export der_read_tag
.export der_read_length
.export der_skip
.export der_skip_tlv
.export der_match_oid
.export x509_parse_cert

; --- Public exports: OID tables (RODATA) ---
.export oid_ec_pubkey
.export oid_prime256v1
.export oid_secp384r1
.export oid_sha256_ecdsa
.export oid_sha384_ecdsa

; --- Public exports: BSS data ---
.export der_len
.export cert_tbs_ptr
.export cert_tbs_len
.export cert_pubkey
.export cert_pubkey_len
.export cert_sig_r
.export cert_sig_s
.export cert_sig_len
.export cert_curve_id
.export cert_buf
.export cert_buf_len

; =============================================================================
.segment "CODE"
; =============================================================================

; =============================================================================
; der_read_tag - Read the tag byte at (zp_ptr) and advance pointer
; Output: A = tag byte
; Clobbers: Y
; =============================================================================
der_read_tag:
        ldy #0
        lda (zp_ptr),y
        ; advance zp_ptr by 1
        inc zp_ptr
        bne :+
        inc zp_ptr+1
:       rts

; =============================================================================
; der_read_length - Read a DER length at (zp_ptr) and advance pointer
; Handles short form (< $80) and long form ($81 xx, $82 xx xx)
; Output: der_len (2 bytes, little-endian) = parsed length
; Clobbers: A, Y
; =============================================================================
der_read_length:
        ldy #0
        lda (zp_ptr),y
        bmi @long_form          ; bit 7 set = long form

        ; --- Short form: length < $80, single byte ---
        sta der_len
        lda #0
        sta der_len+1
        ; advance zp_ptr by 1
        inc zp_ptr
        bne :+
        inc zp_ptr+1
:       rts

@long_form:
        cmp #$81
        beq @one_byte_len
        cmp #$82
        beq @two_byte_len

        ; Unsupported length encoding (>= $83 or indefinite $80)
        ; Set der_len = 0 as error indicator
        lda #0
        sta der_len
        sta der_len+1
        rts

@one_byte_len:
        ; $81 xx: one length byte follows
        iny                     ; Y=1
        lda (zp_ptr),y
        sta der_len
        lda #0
        sta der_len+1
        ; advance zp_ptr by 2
        clc
        lda zp_ptr
        adc #2
        sta zp_ptr
        bcc :+
        inc zp_ptr+1
:       rts

@two_byte_len:
        ; $82 xx xx: two length bytes follow (big-endian)
        iny                     ; Y=1
        lda (zp_ptr),y          ; high byte
        sta der_len+1
        iny                     ; Y=2
        lda (zp_ptr),y          ; low byte
        sta der_len
        ; advance zp_ptr by 3
        clc
        lda zp_ptr
        adc #3
        sta zp_ptr
        bcc :+
        inc zp_ptr+1
:       rts

; =============================================================================
; der_skip - Advance zp_ptr by der_len bytes (skip over a TLV value)
; Input: der_len (2 bytes, little-endian)
; Clobbers: A
; =============================================================================
der_skip:
        clc
        lda zp_ptr
        adc der_len
        sta zp_ptr
        lda zp_ptr+1
        adc der_len+1
        sta zp_ptr+1
        rts

; =============================================================================
; der_skip_tlv - Read tag + length, then skip the value. Convenience wrapper.
; Clobbers: A, Y
; =============================================================================
der_skip_tlv:
        jsr der_read_tag
        jsr der_read_length
        jmp der_skip            ; tail call

; =============================================================================
; der_match_oid - Compare bytes at (zp_ptr) against a known OID
; Input: A/X = pointer to expected OID bytes (lo/hi), Y = OID length
; Output: Z flag set if match, clear if mismatch
; Does NOT advance zp_ptr
; Clobbers: A, Y
; =============================================================================
der_match_oid:
        ; Store expected OID pointer in @oid_ptr (self-modifying)
        sta @oid_ptr+1
        stx @oid_ptr+2
        ; Save OID length
        sty zp_temp
        dey                     ; start comparing from last byte
@oid_cmp_loop:
        lda (zp_ptr),y
@oid_ptr:
        cmp $ffff,y             ; self-modified: address of OID table
        bne @oid_mismatch
        dey
        bpl @oid_cmp_loop
        ; All bytes matched — force Z=1
        lda #0
        rts

@oid_mismatch:
        lda #1                  ; clear Z flag
        rts

; =============================================================================
; x509_parse_cert - Parse X.509 certificate to extract TBS, pubkey, signature
;
; Input: cert_buf contains DER-encoded certificate, cert_buf_len = length
; Output: C=0 success, C=1 parse error
;         cert_tbs_ptr / cert_tbs_len  - TBS region for SHA-256
;         cert_pubkey / cert_pubkey_len - public key Qx||Qy
;         cert_sig_r / cert_sig_s / cert_sig_len - signature components
;         cert_curve_id - 0=P-256, 1=P-384
; =============================================================================
x509_parse_cert:
        ; --- Initialize parse cursor to start of cert_buf ---
        lda #<cert_buf
        sta zp_ptr
        lda #>cert_buf
        sta zp_ptr+1

        ; --- Step 1: Read outer SEQUENCE tag+length ---
        jsr der_read_tag
        cmp #$30                ; SEQUENCE
        beq :+
        jmp @parse_error
:       jsr der_read_length

        ; --- Step 2: Save pointer to start of TBS SEQUENCE ---
        lda zp_ptr
        sta cert_tbs_ptr
        lda zp_ptr+1
        sta cert_tbs_ptr+1

        ; --- Step 3: Read TBS SEQUENCE tag+length ---
        jsr der_read_tag
        cmp #$30                ; SEQUENCE
        beq :+
        jmp @parse_error
:
        jsr der_read_length

        ; cert_tbs_len = (zp_ptr - cert_tbs_ptr) + der_len
        sec
        lda zp_ptr
        sbc cert_tbs_ptr
        sta cert_tbs_len
        lda zp_ptr+1
        sbc cert_tbs_ptr+1
        sta cert_tbs_len+1
        ; Now add der_len (the value length)
        clc
        lda cert_tbs_len
        adc der_len
        sta cert_tbs_len
        lda cert_tbs_len+1
        adc der_len+1
        sta cert_tbs_len+1

        ; Save end-of-TBS pointer for later (zp_ptr + der_len)
        clc
        lda zp_ptr
        adc der_len
        sta @tbs_end
        lda zp_ptr+1
        adc der_len+1
        sta @tbs_end+1

        ; --- Step 4: Parse inside TBS ---

        ; 4a: Skip [0] EXPLICIT version (tag $A0)
        jsr der_read_tag
        cmp #$a0                ; context-specific, constructed, tag 0
        bne @no_version         ; v1 certs may omit version
        jsr der_read_length
        jsr der_skip
        jmp @parse_serial

@no_version:
        ; Tag wasn't $A0, so it's the serialNumber INTEGER.
        jsr der_read_length
        jsr der_skip
        jmp @skip_sig_alg

@parse_serial:
        ; 4b: Skip INTEGER serialNumber
        jsr der_skip_tlv

@skip_sig_alg:
        ; 4c: Skip SEQUENCE signatureAlgorithm
        jsr der_skip_tlv

        ; 4d: Skip SEQUENCE issuer
        jsr der_skip_tlv

        ; 4e: Skip SEQUENCE validity
        jsr der_skip_tlv

        ; 4f: Skip SEQUENCE subject
        jsr der_skip_tlv

        ; --- 4g: Parse SEQUENCE subjectPublicKeyInfo ---
        jsr der_read_tag
        cmp #$30                ; SEQUENCE
        beq :+
        jmp @parse_error
:       jsr der_read_length

        ; Parse SEQUENCE algorithm identifier
        jsr der_read_tag
        cmp #$30                ; SEQUENCE
        beq :+
        jmp @parse_error
:       jsr der_read_length
        ; Save end of algorithmIdentifier
        clc
        lda zp_ptr
        adc der_len
        sta @algid_end
        lda zp_ptr+1
        adc der_len+1
        sta @algid_end+1

        ; Read OID tag inside algorithmIdentifier
        jsr der_read_tag
        cmp #$06                ; OID
        beq :+
        jmp @parse_error
:       jsr der_read_length

        ; Match ecPublicKey OID (1.2.840.10045.2.1)
        lda #<oid_ec_pubkey
        ldx #>oid_ec_pubkey
        ldy #7                  ; length of oid_ec_pubkey
        jsr der_match_oid
        bne @parse_error_jmp

        ; Skip past the ecPublicKey OID value
        jsr der_skip

        ; Now read the curve OID
        jsr der_read_tag
        cmp #$06                ; OID
        beq :+
@parse_error_jmp:
        jmp @parse_error
:       jsr der_read_length

        ; Try P-256 first
        lda #<oid_prime256v1
        ldx #>oid_prime256v1
        ldy #8                  ; length of oid_prime256v1
        jsr der_match_oid
        beq @curve_p256

        ; Try P-384
        lda #<oid_secp384r1
        ldx #>oid_secp384r1
        ldy #5                  ; length of oid_secp384r1
        jsr der_match_oid
        beq @curve_p384

        ; Unknown curve
        jmp @parse_error

@curve_p256:
        lda #0
        sta cert_curve_id
        lda #64
        sta cert_pubkey_len
        lda #32
        sta cert_sig_len
        jmp @curve_done

@curve_p384:
        lda #1
        sta cert_curve_id
        lda #96
        sta cert_pubkey_len
        lda #48
        sta cert_sig_len

@curve_done:
        ; Skip to end of algorithmIdentifier
        lda @algid_end
        sta zp_ptr
        lda @algid_end+1
        sta zp_ptr+1

        ; --- Parse BIT STRING containing the public key ---
        jsr der_read_tag
        cmp #$03                ; BIT STRING
        beq :+
        jmp @parse_error
:       jsr der_read_length

        ; Skip unused bits byte (always $00)
        ldy #0
        lda (zp_ptr),y
        ; (should be $00, but don't error-check — just skip)
        inc zp_ptr
        bne :+
        inc zp_ptr+1
:
        ; Skip uncompressed point marker ($04)
        ldy #0
        lda (zp_ptr),y
        cmp #$04
        beq :+
        jmp @parse_error
:       inc zp_ptr
        bne :+
        inc zp_ptr+1
:
        ; --- Copy Qx to cert_pubkey ---
        ; Length is cert_sig_len (32 for P-256, 48 for P-384) = half of pubkey
        lda cert_sig_len        ; 32 or 48
        sta zp_count
        ldy #0
@copy_qx:
        lda (zp_ptr),y
        sta cert_pubkey,y
        iny
        cpy zp_count
        bne @copy_qx

        ; Advance zp_ptr by coordinate size
        clc
        lda zp_ptr
        adc zp_count
        sta zp_ptr
        bcc :+
        inc zp_ptr+1
:
        ; --- Copy Qy to cert_pubkey + coord_size ---
        ; Destination offset = cert_sig_len (32 or 48)
        ldx zp_count            ; dest starts at offset 32 or 48
        ldy #0
@copy_qy:
        lda (zp_ptr),y
        sta cert_pubkey,x
        inx
        iny
        cpy zp_count
        bne @copy_qy

        ; Advance zp_ptr past Qy
        clc
        lda zp_ptr
        adc zp_count
        sta zp_ptr
        bcc :+
        inc zp_ptr+1
:

        ; --- Skip any remaining TBS fields (extensions, etc.) ---
        ; Jump to saved end-of-TBS
        lda @tbs_end
        sta zp_ptr
        lda @tbs_end+1
        sta zp_ptr+1

        ; --- Step 5: Skip SEQUENCE signatureAlgorithm (after TBS) ---
        jsr der_skip_tlv

        ; --- Step 6: Parse BIT STRING signatureValue ---
        jsr der_read_tag
        cmp #$03                ; BIT STRING
        beq :+
        jmp @parse_error
:       jsr der_read_length

        ; Skip unused bits byte ($00)
        inc zp_ptr
        bne :+
        inc zp_ptr+1
:
        ; Read inner SEQUENCE (contains r, s as INTEGERs)
        jsr der_read_tag
        cmp #$30                ; SEQUENCE
        beq :+
        jmp @parse_error
:       jsr der_read_length

        ; --- Parse INTEGER r ---
        jsr der_read_tag
        cmp #$02                ; INTEGER
        beq :+
        jmp @parse_error
:       jsr der_read_length

        ; Handle leading zero pad byte
        ; If der_len > cert_sig_len, there's a leading $00
        lda der_len
        sec
        sbc cert_sig_len
        beq @copy_r             ; exact length, no padding
        ; Leading pad byte(s) — skip (der_len - cert_sig_len) bytes
        sta zp_temp             ; number of pad bytes to skip
@skip_r_pad:
        inc zp_ptr
        bne :+
        inc zp_ptr+1
:       dec zp_temp
        bne @skip_r_pad

@copy_r:
        ldy #0
        ldx cert_sig_len        ; 32 or 48
        stx zp_count
@copy_r_loop:
        lda (zp_ptr),y
        sta cert_sig_r,y
        iny
        cpy zp_count
        bne @copy_r_loop

        ; Advance past r value
        clc
        lda zp_ptr
        adc zp_count
        sta zp_ptr
        bcc :+
        inc zp_ptr+1
:

        ; --- Parse INTEGER s ---
        jsr der_read_tag
        cmp #$02                ; INTEGER
        beq :+
        jmp @parse_error
:       jsr der_read_length

        ; Handle leading zero pad byte
        lda der_len
        sec
        sbc cert_sig_len
        beq @copy_s
        sta zp_temp
@skip_s_pad:
        inc zp_ptr
        bne :+
        inc zp_ptr+1
:       dec zp_temp
        bne @skip_s_pad

@copy_s:
        ldy #0
        ldx cert_sig_len
        stx zp_count
@copy_s_loop:
        lda (zp_ptr),y
        sta cert_sig_s,y
        iny
        cpy zp_count
        bne @copy_s_loop

        ; --- Success ---
        clc
        rts

@parse_error:
        sec
        rts

; --- Local temporaries (not ZP, just inline storage within x509_parse_cert) ---
@tbs_end:        .word 0
@algid_end:      .word 0

; =============================================================================
.segment "RODATA"
; =============================================================================

; Known OIDs (DER-encoded value bytes, without tag and length)
oid_ec_pubkey:                          ; 1.2.840.10045.2.1 (ecPublicKey)
        .byte $2a,$86,$48,$ce,$3d,$02,$01
oid_prime256v1:                         ; 1.2.840.10045.3.1.7 (P-256)
        .byte $2a,$86,$48,$ce,$3d,$03,$01,$07
oid_secp384r1:                          ; 1.3.132.0.34 (P-384)
        .byte $2b,$81,$04,$00,$22
oid_sha256_ecdsa:                       ; 1.2.840.10045.4.3.2 (ecdsa-with-SHA256)
        .byte $2a,$86,$48,$ce,$3d,$04,$03,$02
oid_sha384_ecdsa:                       ; 1.2.840.10045.4.3.3 (ecdsa-with-SHA384)
        .byte $2a,$86,$48,$ce,$3d,$04,$03,$03

; =============================================================================
.segment "BSS"
; =============================================================================

der_len:           .res 2               ; last parsed length (16-bit LE)
cert_tbs_ptr:      .res 2               ; pointer to TBS bytes in cert_buf
cert_tbs_len:      .res 2               ; length of TBS (tag + length + value)
cert_pubkey:       .res 96              ; public key Qx||Qy (max 48+48 for P-384)
cert_pubkey_len:   .res 1               ; 64 (P-256) or 96 (P-384)
cert_sig_r:        .res 48              ; signature r component (max 48 for P-384)
cert_sig_s:        .res 48              ; signature s component (max 48 for P-384)
cert_sig_len:      .res 1               ; 32 (P-256) or 48 (P-384)
cert_curve_id:     .res 1               ; 0=P-256, 1=P-384
; ip65 refit: cert_buf gets its own segment (was BSS_TAIL alongside
; src/data.s::tls_rec_buf) so the ip65 cfg can pin it at $A000 and
; time-share the RAM with LIB_NISTCURVES_P256_BSS (verify-time scratch).
; LIFETIME CONTRACT: cert_buf (and cert_tbs_ptr/len, which point into
; it) are dead once x509_parse_cert / x509_extract_pubkey returns —
; the pubkey is extracted at Certificate-processing time, and the
; CertificateVerify path reads only tls_rec_buf + the transcript +
; the CRYPTO_BSS pubkey slots. ecdsa_verify may therefore scribble
; cert_buf freely. Any future cert-chain validation that re-reads
; cert_buf (or hashes TBS via cert_tbs_ptr) after Certificate
; processing MUST first break the union in cfg/c64-https-ip65.cfg.
.segment "CERT_BUF_BSS"
cert_buf:          .res 1536            ; certificate DER buffer
.segment "BSS"
cert_buf_len:      .res 2               ; certificate length
