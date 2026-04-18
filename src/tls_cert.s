; tls_cert.s — TLS 1.3 certificate chain validation
; Converted from ACME to ca65 in Phase 3 Batch C.
;
; Processes the server's Certificate message (extracts leaf cert and
; public key) and CertificateVerify message (verifies the server's
; signature over the transcript hash).
;
; External dependencies:
;   sha256.s:       sha256_init, sha256_process_block, sha256_final,
;                   sha256_hash, sha256_block
;   ecdsa_verify.s: ecdsa_verify, ecdsa_parse_der_sig, ecdsa_curve_id,
;                   ecdsa_hash, ecdsa_hash_len, ecdsa_sig_r, ecdsa_sig_s,
;                   ecdsa_sig_len, ecdsa_pubkey_x, ecdsa_pubkey_y
;   tls_transcript.s: tls_transcript (32-byte current hash)
;   data.asm:       tls_rec_buf, tls_rec_len
;                   (formerly tls_hs_buf/tls_hs_len — the staging buffer
;                    was removed.  Handshake records are parsed directly
;                    out of tls_rec_buf to avoid the 8-bit copy loop that
;                    truncated records >=256 B like the 352 B Certificate.)
;   constants.inc:  TLS_HS_CERTIFICATE, TLS_HS_CERT_VERIFY,
;                   zp_ptr, zp_count, zp_tmp1, zp_tmp2
;
; ZP usage: zp_ptr ($FB-$FC), zp_count ($FE), zp_tmp1 ($02), zp_tmp2 ($03)

        .include "constants.inc"

        .export tls_handle_certificate
        .export x509_extract_pubkey
        .export tls_handle_cert_verify

        .import tls_rec_buf
        .import tls_rec_len
        .import tls_transcript
        .import sha256_init
        .import sha256_process_block
        .import sha256_final
        .import sha256_block
        .import sha256_hash
        .import ecdsa_verify
        .import ecdsa_parse_der_sig
        .import ecdsa_curve_id
        .import ecdsa_hash
        .import ecdsa_hash_len
        .import ecdsa_sig_r
        .import ecdsa_sig_s
        .import ecdsa_sig_len
        .import ecdsa_pubkey_x
        .import ecdsa_pubkey_y

        .segment "TLS_CODE"

; =============================================================================
; tls_handle_certificate - Process TLS 1.3 Certificate message
;
; Input: tls_rec_buf contains the Certificate handshake message
;        tls_rec_len = message length
; Output: C=0 success (leaf cert pubkey extracted to ecdsa_pubkey_x/y)
;         C=1 error (bad format, unsupported key type)
; =============================================================================
tls_handle_certificate:
        ldy #0

        ; --- Verify handshake type = 11 (Certificate) ---
        lda tls_rec_buf
        cmp #TLS_HS_CERTIFICATE
        beq @cert_type_ok
        jmp @cert_error
@cert_type_ok:
        iny                         ; Y=1

        ; --- Skip 24-bit handshake length [1-3] ---
        iny                         ; Y=2
        iny                         ; Y=3
        iny                         ; Y=4

        ; --- certificate_request_context length [4] ---
        ; For server Certificate, this is always 0
        lda tls_rec_buf,y
        bne @cert_error             ; non-zero context length = unexpected
        iny                         ; Y=5

        ; --- certificate_list length [5-7] (24-bit, skip high byte) ---
        ; High byte must be 0 (certs < 64K)
        lda tls_rec_buf,y
        bne @cert_error             ; cert list > 65535 bytes
        iny                         ; Y=6
        lda tls_rec_buf,y            ; cert_list_len high byte (of 16-bit)
        sta cert_list_len_hi
        iny                         ; Y=7
        lda tls_rec_buf,y            ; cert_list_len low byte
        sta cert_list_len_lo
        iny                         ; Y=8

        ; --- First CertificateEntry ---
        ; cert_data length [8-10] (24-bit)
        lda tls_rec_buf,y            ; high byte (must be 0)
        bne @cert_error
        iny                         ; Y=9
        lda tls_rec_buf,y
        sta cert_data_len_hi
        iny                         ; Y=10
        lda tls_rec_buf,y
        sta cert_data_len_lo
        iny                         ; Y=11

        ; cert_data starts at tls_rec_buf + Y
        ; Store pointer to cert data
        tya
        clc
        adc #<tls_rec_buf
        sta cert_data_ptr
        lda #0
        adc #>tls_rec_buf
        sta cert_data_ptr+1

        ; Save cert_data start offset for extension skipping later
        sty cert_data_offset

        ; --- Parse X.509 certificate to extract ECDSA public key ---
        jsr x509_extract_pubkey
        bcc @cert_key_ok
        jmp @cert_error

@cert_key_ok:
        ; Public key is now in ecdsa_pubkey_x/y.
        ; Skip past cert_data + extensions to be done.

        ; Advance Y past cert_data
        lda cert_data_offset
        clc
        adc cert_data_len_lo
        sta zp_tmp1                 ; low byte of position after cert_data
        lda #0
        adc cert_data_len_hi
        sta zp_tmp2                 ; high byte adjustment (for >256 byte certs)

        ; For MVP, we use zp_ptr as a 16-bit index into tls_rec_buf.
        ; Skip extensions after the leaf cert.
        lda zp_tmp1
        sta cert_parse_pos
        lda zp_tmp2
        sta cert_parse_pos+1

        ; Read extensions length (2 bytes) at cert_parse_pos
        ; For simplicity, assume offset < 256 for now (typical small certs)
        ldy zp_tmp1
        lda tls_rec_buf,y
        sta cert_ext_len_hi
        iny
        lda tls_rec_buf,y
        sta cert_ext_len_lo
        iny

        ; Done — we only need the leaf cert's public key.
        clc
        rts

@cert_error:
        sec
        rts

; =============================================================================
; x509_extract_pubkey - Extract ECDSA public key from DER certificate
;
; Input: cert_data_ptr = pointer to DER certificate
;        cert_data_len_hi/lo = certificate length
; Output: ecdsa_pubkey_x/y filled (32 or 48 bytes depending on curve)
;         C=0 success, C=1 not found / unsupported
; =============================================================================
x509_extract_pubkey:
        ; Set up pointer to scan through cert data
        lda cert_data_ptr
        sta zp_ptr
        lda cert_data_ptr+1
        sta zp_ptr+1

        ; Compute end address = cert_data_ptr + cert_data_len
        lda cert_data_ptr
        clc
        adc cert_data_len_lo
        sta cert_end_lo
        lda cert_data_ptr+1
        adc cert_data_len_hi
        sta cert_end_hi

        ; Scan for ecPublicKey OID: 06 07 2A 86 48 CE 3D 02 01
@scan_loop:
        ; Check if we've reached the end
        lda zp_ptr+1
        cmp cert_end_hi
        bcc @scan_continue
        beq :+
        jmp @scan_not_found
:
        lda zp_ptr
        cmp cert_end_lo
        bcc :+
        jmp @scan_not_found
:

@scan_continue:
        ldy #0
        lda (zp_ptr),y
        cmp #$06                    ; ASN.1 OID tag
        beq :+
        jmp @scan_next
:

        ; Check if this is ecPublicKey OID
        iny
        lda (zp_ptr),y
        cmp #$07                    ; OID length = 7
        beq :+
        jmp @scan_next
:

        ; Compare remaining OID bytes: 2A 86 48 CE 3D 02 01
        iny
        lda (zp_ptr),y
        cmp #$2a
        beq :+
        jmp @scan_next
:
        iny
        lda (zp_ptr),y
        cmp #$86
        beq :+
        jmp @scan_next
:
        iny
        lda (zp_ptr),y
        cmp #$48
        beq :+
        jmp @scan_next
:
        iny
        lda (zp_ptr),y
        cmp #$ce
        beq :+
        jmp @scan_next
:
        iny
        lda (zp_ptr),y
        cmp #$3d
        beq :+
        jmp @scan_next
:
        iny
        lda (zp_ptr),y
        cmp #$02
        beq :+
        jmp @scan_next
:
        iny
        lda (zp_ptr),y
        cmp #$01
        beq :+
        jmp @scan_next
:

        ; Found ecPublicKey OID! Now check curve OID that follows.
        iny                         ; Y = 9, pointing to next byte

        ; Check for curve OID tag
        lda (zp_ptr),y
        cmp #$06                    ; OID tag
        beq :+
        jmp @scan_next
:

        iny
        lda (zp_ptr),y              ; OID length
        cmp #$08                    ; P-256 curve OID length
        beq @check_p256_oid
        cmp #$05                    ; P-384 curve OID length
        beq @check_p384_oid
        jmp @scan_next

@check_p256_oid:
        ; P-256 OID: 2A 86 48 CE 3D 03 01 07
        iny
        lda (zp_ptr),y
        cmp #$2a
        bne @scan_next
        iny
        lda (zp_ptr),y
        cmp #$86
        bne @scan_next
        iny
        lda (zp_ptr),y
        cmp #$48
        bne @scan_next
        iny
        lda (zp_ptr),y
        cmp #$ce
        bne @scan_next
        iny
        lda (zp_ptr),y
        cmp #$3d
        bne @scan_next
        iny
        lda (zp_ptr),y
        cmp #$03
        bne @scan_next
        iny
        lda (zp_ptr),y
        cmp #$01
        bne @scan_next
        iny
        lda (zp_ptr),y
        cmp #$07
        bne @scan_next

        ; P-256 curve confirmed
        lda #0
        sta ecdsa_curve_id
        lda #32
        sta ecdsa_sig_len
        sta ecdsa_hash_len
        iny                         ; past curve OID
        jmp @find_bitstring

@check_p384_oid:
        ; P-384 OID: 2B 81 04 00 22
        iny
        lda (zp_ptr),y
        cmp #$2b
        bne @scan_next
        iny
        lda (zp_ptr),y
        cmp #$81
        bne @scan_next
        iny
        lda (zp_ptr),y
        cmp #$04
        bne @scan_next
        iny
        lda (zp_ptr),y
        cmp #$00
        bne @scan_next
        iny
        lda (zp_ptr),y
        cmp #$22
        bne @scan_next

        ; P-384 curve confirmed
        lda #1
        sta ecdsa_curve_id
        lda #48
        sta ecdsa_sig_len
        sta ecdsa_hash_len
        iny                         ; past curve OID
        jmp @find_bitstring

@scan_next:
        ; Advance pointer by 1 and continue scanning
        inc zp_ptr
        bne :+
        inc zp_ptr+1
:       jmp @scan_loop

@scan_not_found:
        sec
        rts

@find_bitstring:
        ; After the algorithm identifier, we need the BIT STRING
        ; containing the uncompressed EC point.

        ; Advance zp_ptr by Y to current position
        tya
        clc
        adc zp_ptr
        sta zp_ptr
        lda #0
        adc zp_ptr+1
        sta zp_ptr+1

        ; Scan forward for BIT STRING tag (0x03)
        ldy #0
@bs_scan:
        ; Safety: don't scan past cert end
        lda zp_ptr+1
        cmp cert_end_hi
        bcc @bs_check
        bne @scan_not_found
        lda zp_ptr
        cmp cert_end_lo
        bcs @scan_not_found

@bs_check:
        lda (zp_ptr),y
        cmp #$03                    ; BIT STRING tag
        beq @bs_found
        ; Advance
        inc zp_ptr
        bne @bs_scan
        inc zp_ptr+1
        jmp @bs_scan

@bs_found:
        ; Skip BIT STRING tag
        iny                         ; past tag

        ; Read length (may be 1 or 2 byte DER length)
        lda (zp_ptr),y
        cmp #$81                    ; long form (1 extra length byte)?
        beq @bs_long_len
        cmp #$82                    ; long form (2 extra length bytes)?
        beq @bs_long2_len
        ; Short form: length is this byte
        sta cert_bs_len
        iny
        jmp @bs_skip_unused

@bs_long_len:
        iny
        lda (zp_ptr),y
        sta cert_bs_len
        iny
        jmp @bs_skip_unused

@bs_long2_len:
        iny                         ; skip high byte (assume 0 for certs < 256)
        iny
        lda (zp_ptr),y
        sta cert_bs_len
        iny

@bs_skip_unused:
        ; Next byte should be 0x00 (unused bits count)
        lda (zp_ptr),y
        cmp #$00
        bne @scan_not_found
        iny

        ; Next byte should be 0x04 (uncompressed point)
        lda (zp_ptr),y
        cmp #$04
        bne @scan_not_found
        iny

        ; Advance zp_ptr to point at X coordinate
        tya
        clc
        adc zp_ptr
        sta zp_ptr
        lda #0
        adc zp_ptr+1
        sta zp_ptr+1

        ; Copy X coordinate to ecdsa_pubkey_x
        lda ecdsa_sig_len           ; 32 or 48
        sta zp_count
        ldy #0
@copy_x:
        lda (zp_ptr),y
        sta ecdsa_pubkey_x,y
        iny
        cpy zp_count
        bne @copy_x

        ; Advance zp_ptr past X
        lda zp_count
        clc
        adc zp_ptr
        sta zp_ptr
        lda #0
        adc zp_ptr+1
        sta zp_ptr+1

        ; Copy Y coordinate to ecdsa_pubkey_y
        ldy #0
@copy_y:
        lda (zp_ptr),y
        sta ecdsa_pubkey_y,y
        iny
        cpy zp_count
        bne @copy_y

        ; Success
        clc
        rts


; =============================================================================
; tls_handle_cert_verify - Process TLS 1.3 CertificateVerify message
;
; Input: tls_rec_buf contains the CertificateVerify handshake message
;        tls_transcript (32 bytes) = current transcript hash
;        Server's public key already in ecdsa_pubkey_x/y
; Output: C=0 signature valid, C=1 invalid
; =============================================================================
tls_handle_cert_verify:
        ; --- Verify handshake type = 15 (CertificateVerify) ---
        lda tls_rec_buf
        cmp #TLS_HS_CERT_VERIFY
        beq @cv_type_ok
        jmp @cv_error
@cv_type_ok:

        ; --- Read signature algorithm [4-5] ---
        ; Must be 0x0403 (ecdsa_secp256r1_sha256)
        lda tls_rec_buf+4
        cmp #$04
        beq :+
        jmp @cv_error
:
        lda tls_rec_buf+5
        cmp #$03
        beq :+
        jmp @cv_error
:

        ; --- Read signature length [6-7] (big-endian) ---
        lda tls_rec_buf+6            ; high byte (expect 0)
        beq :+
        jmp @cv_error               ; signature > 255 bytes
:
        lda tls_rec_buf+7            ; low byte
        sta cv_sig_len

        ; --- Parse DER signature into ecdsa_sig_r/s ---
        ; Signature data starts at tls_rec_buf+8
        lda #<(tls_rec_buf+8)
        sta zp_ptr
        lda #>(tls_rec_buf+8)
        sta zp_ptr+1
        lda cv_sig_len
        sta zp_count

        ; Set component length for P-256 (32 bytes)
        lda #32
        sta ecdsa_sig_len

        jsr ecdsa_parse_der_sig
        bcc @cv_sig_parsed
        jmp @cv_error               ; DER parse failed

@cv_sig_parsed:
        ; ---------------------------------------------------------------
        ; Build the signed content and hash it with SHA-256
        ;
        ; Content (130 bytes):
        ;   [0-63]   64 x 0x20 (spaces)
        ;   [64-96]  "TLS 1.3, server CertificateVerify" (33 bytes)
        ;   [97]     0x00 (separator)
        ;   [98-129] transcript_hash (32 bytes)
        ; ---------------------------------------------------------------

        ; Initialize SHA-256
        jsr sha256_init

        ; --- Block 1: 64 spaces ---
        ldx #63
        lda #$20
@fill_spaces:
        sta sha256_block,x
        dex
        bpl @fill_spaces

        jsr sha256_process_block

        ; --- Block 2: label (33 bytes) + separator (1 byte) + hash[0..29] ---
        ldx #0
@copy_label:
        lda cv_label,x
        sta sha256_block,x
        inx
        cpx #33
        bne @copy_label

        ; Separator byte
        lda #$00
        sta sha256_block+33

        ; Copy first 30 bytes of transcript hash
        ldx #0
@copy_hash1:
        lda tls_transcript,x
        sta sha256_block+34,x
        inx
        cpx #30
        bne @copy_hash1

        jsr sha256_process_block

        ; --- Block 3: hash[30..31] + SHA-256 padding ---
        ; Clear block
        ldx #63
        lda #0
@clr_blk3:
        sta sha256_block,x
        dex
        bpl @clr_blk3

        ; Last 2 bytes of transcript hash
        lda tls_transcript+30
        sta sha256_block+0
        lda tls_transcript+31
        sta sha256_block+1

        ; SHA-256 padding: 0x80 after data
        lda #$80
        sta sha256_block+2

        ; Message length in bits = 130 * 8 = 1040 = $0410
        ; Write as 64-bit big-endian at block[56..63]
        lda #$04
        sta sha256_block+61
        lda #$10
        sta sha256_block+62
        ; All other length bytes are already 0

        jsr sha256_process_block

        ; Finalize: copy hash state to sha256_hash
        jsr sha256_final

        ; --- Copy hash to ecdsa_hash ---
        ldx #31
@copy_ecdsa_hash:
        lda sha256_hash,x
        sta ecdsa_hash,x
        dex
        bpl @copy_ecdsa_hash

        ; --- Set up verification parameters ---
        lda #0
        sta ecdsa_curve_id          ; P-256
        lda #32
        sta ecdsa_hash_len

        ; ecdsa_pubkey_x/y already set by tls_handle_certificate

        ; --- Verify signature ---
        jsr ecdsa_verify
        ; Carry flag already set/clear by ecdsa_verify
        rts

@cv_error:
        sec
        rts


; =============================================================================
; Signed content constant data
; =============================================================================

        .segment "RODATA"

; The CertificateVerify context string
; (The 64 spaces are generated dynamically in Block 1 above)
cv_label:
        .byte "TLS 1.3, server CertificateVerify"
        ; 33 bytes (no null terminator needed — length is fixed)


; =============================================================================
; Inline data — certificate parsing state
; =============================================================================

        .segment "BSS"

cert_list_len_hi:   .res 1
cert_list_len_lo:   .res 1
cert_data_len_hi:   .res 1
cert_data_len_lo:   .res 1
cert_data_ptr:      .res 2          ; pointer to DER cert data in tls_rec_buf
cert_data_offset:   .res 1          ; Y offset where cert_data starts
cert_parse_pos:     .res 2          ; 16-bit parse position
cert_ext_len_hi:    .res 1          ; extensions length high
cert_ext_len_lo:    .res 1          ; extensions length low
cert_end_lo:        .res 1          ; end address of cert data (low)
cert_end_hi:        .res 1          ; end address of cert data (high)
cert_bs_len:        .res 1          ; BIT STRING content length

; CertificateVerify parsing state
cv_sig_len:         .res 1          ; DER signature length
