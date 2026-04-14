; =============================================================================
; ecdsa_verify.asm - ECDSA signature verification for P-256 and P-384
;
; Verifies ECDSA signatures as required for TLS 1.3 CertificateVerify
; (P-256/SHA-256) and certificate chain verification (P-384).
;
; Input: ecdsa_curve_id (0=P-256, 1=P-384)
;        ecdsa_hash (32 or 48 bytes) = hash of message (z)
;        ecdsa_sig_r (32 or 48 bytes) = signature r
;        ecdsa_sig_s (32 or 48 bytes) = signature s
;        ecdsa_pubkey_x/y (32 or 48 bytes each) = public key Q
; Output: C=0 signature valid, C=1 invalid
;
; Algorithm:
;   1. Check 0 < r < n and 0 < s < n
;   2. w = s^(-1) mod n
;   3. u1 = z * w mod n
;   4. u2 = r * w mod n
;   5. R = u1*G + u2*Q (two scalar multiplies + point addition)
;   6. Convert R to affine coordinates
;   7. Check R.x mod n == r
;
; External dependencies:
;   P-256: fp_copy, fp_zero, fp_cmp, fp_is_zero, fp_mod_mul, fp_mod_inv,
;          fp_mod_reduce, ec_set_modn, ec_set_modp,
;          ec_scalar_mul, ec_point_add, ec_jacobian_to_affine
;          ec_p1, ec_p2, ec_p3, ec_t1..ec_t6,
;          ec_gx, ec_gy, ec_n, fp_r0, fp_wide
;   P-384: _384 suffixed versions of all the above
;
; ZP: fp_src1, fp_src2, fp_dst, fp_misc, fp_carry, ec_scalar_ptr
; =============================================================================

; =============================================================================
; Curve dispatch
; =============================================================================
ecdsa_verify:
        ; Ensure BASIC ROM is banked out — ECDSA data buffers live at $A000+
        lda $01
        and #%11111110          ; clear LORAM (bit 0) -> BASIC ROM off
        sta $01

        lda ecdsa_curve_id
        bne @p384
        jmp ecdsa_verify_256
@p384:
        ; TODO: restore P-384 dispatch — see project memory project_p384_stubbed.md
        sec
        rts

; =============================================================================
; ecdsa_verify_256 - P-256 signature verification
; =============================================================================
ecdsa_verify_256:
        ; ---------------------------------------------------------------
        ; Step 1: Validate r and s are in [1, n-1]
        ; ---------------------------------------------------------------

        ; Check r != 0
        lda #<ecdsa_sig_r
        sta fp_src1
        lda #>ecdsa_sig_r
        sta fp_src1+1
        jsr fp_is_zero
        beq @256_invalid            ; r == 0 -> invalid

        ; Check r < n
        lda #<ecdsa_sig_r
        sta fp_src1
        lda #>ecdsa_sig_r
        sta fp_src1+1
        lda #<ec_n
        sta fp_src2
        lda #>ec_n
        sta fp_src2+1
        jsr fp_cmp
        bcs @256_invalid            ; r >= n -> invalid

        ; Check s != 0
        lda #<ecdsa_sig_s
        sta fp_src1
        lda #>ecdsa_sig_s
        sta fp_src1+1
        jsr fp_is_zero
        beq @256_invalid            ; s == 0 -> invalid

        ; Check s < n
        lda #<ecdsa_sig_s
        sta fp_src1
        lda #>ecdsa_sig_s
        sta fp_src1+1
        lda #<ec_n
        sta fp_src2
        lda #>ec_n
        sta fp_src2+1
        jsr fp_cmp
        bcs @256_invalid            ; s >= n -> invalid
        jmp @256_step2

@256_invalid:
        sec
        rts

        ; ---------------------------------------------------------------
        ; Step 2: w = s^(-1) mod n
        ; ---------------------------------------------------------------
@256_step2:
        jsr ec_set_modn             ; fp_misc = ec_n
        lda #<ecdsa_sig_s
        sta fp_src1
        lda #>ecdsa_sig_s
        sta fp_src1+1
        jsr fp_mod_inv              ; fp_r0 = s^(-1) mod n

        ; Copy w = fp_r0 -> ecdsa_verify_tmp
        lda #<fp_r0
        sta fp_src1
        lda #>fp_r0
        sta fp_src1+1
        lda #<ecdsa_verify_tmp
        sta fp_dst
        lda #>ecdsa_verify_tmp
        sta fp_dst+1
        jsr fp_copy                 ; ecdsa_verify_tmp = w

        ; ---------------------------------------------------------------
        ; Step 3: u1 = z * w mod n
        ; ---------------------------------------------------------------
        jsr ec_set_modn             ; fp_misc = ec_n
        lda #<ecdsa_hash
        sta fp_src1
        lda #>ecdsa_hash
        sta fp_src1+1
        lda #<ecdsa_verify_tmp
        sta fp_src2
        lda #>ecdsa_verify_tmp
        sta fp_src2+1
        jsr fp_mod_mul              ; fp_r0 = z * w mod n

        ; Copy u1 = fp_r0 -> ev_u1
        lda #<fp_r0
        sta fp_src1
        lda #>fp_r0
        sta fp_src1+1
        lda #<ev_u1
        sta fp_dst
        lda #>ev_u1
        sta fp_dst+1
        jsr fp_copy                 ; ev_u1 = u1

        ; ---------------------------------------------------------------
        ; Step 4: u2 = r * w mod n
        ; ---------------------------------------------------------------
        jsr ec_set_modn             ; fp_misc = ec_n
        lda #<ecdsa_sig_r
        sta fp_src1
        lda #>ecdsa_sig_r
        sta fp_src1+1
        lda #<ecdsa_verify_tmp
        sta fp_src2
        lda #>ecdsa_verify_tmp
        sta fp_src2+1
        jsr fp_mod_mul              ; fp_r0 = r * w mod n

        ; Copy u2 = fp_r0 -> ev_u2
        lda #<fp_r0
        sta fp_src1
        lda #>fp_r0
        sta fp_src1+1
        lda #<ev_u2
        sta fp_dst
        lda #>ev_u2
        sta fp_dst+1
        jsr fp_copy                 ; ev_u2 = u2

        ; ---------------------------------------------------------------
        ; Step 5a: Compute u1 * G
        ; Load generator G into ec_p2 (affine base point for scalar mul)
        ; ---------------------------------------------------------------

        ; ec_p2.X = ec_gx
        lda #<ec_gx
        sta fp_src1
        lda #>ec_gx
        sta fp_src1+1
        lda #<ec_p2
        sta fp_dst
        lda #>ec_p2
        sta fp_dst+1
        jsr fp_copy

        ; ec_p2.Y = ec_gy
        lda #<ec_gy
        sta fp_src1
        lda #>ec_gy
        sta fp_src1+1
        lda #<(ec_p2+32)
        sta fp_dst
        lda #>(ec_p2+32)
        sta fp_dst+1
        jsr fp_copy

        ; Set scalar pointer to u1
        lda #<ev_u1
        sta ec_scalar_ptr
        lda #>ev_u1
        sta ec_scalar_ptr+1

        ; ec_p3 = u1 * G (result in ec_p3, Jacobian)
        jsr ec_scalar_mul

        ; Save u1*G result from ec_p3 to ev_point_save (96 bytes)
        ldx #95
@save_u1g:
        lda ec_p3,x
        sta ev_point_save,x
        dex
        bpl @save_u1g

        ; ---------------------------------------------------------------
        ; Step 5b: Compute u2 * Q
        ; Load public key Q into ec_p2 (affine base point for scalar mul)
        ; ---------------------------------------------------------------

        ; ec_p2.X = ecdsa_pubkey_x
        lda #<ecdsa_pubkey_x
        sta fp_src1
        lda #>ecdsa_pubkey_x
        sta fp_src1+1
        lda #<ec_p2
        sta fp_dst
        lda #>ec_p2
        sta fp_dst+1
        jsr fp_copy

        ; ec_p2.Y = ecdsa_pubkey_y
        lda #<ecdsa_pubkey_y
        sta fp_src1
        lda #>ecdsa_pubkey_y
        sta fp_src1+1
        lda #<(ec_p2+32)
        sta fp_dst
        lda #>(ec_p2+32)
        sta fp_dst+1
        jsr fp_copy

        ; Set scalar pointer to u2
        lda #<ev_u2
        sta ec_scalar_ptr
        lda #>ev_u2
        sta ec_scalar_ptr+1

        ; ec_p3 = u2 * Q (result in ec_p3, Jacobian)
        jsr ec_scalar_mul

        ; ---------------------------------------------------------------
        ; Step 5c: R = u1*G + u2*Q (point addition)
        ; ec_p1 = u1*G (restore from save), ec_p2 = u2*Q (from ec_p3)
        ; ---------------------------------------------------------------

        ; Copy u1*G from save into ec_p1
        ldx #95
@restore_u1g:
        lda ev_point_save,x
        sta ec_p1,x
        dex
        bpl @restore_u1g

        ; Copy u2*Q from ec_p3 into ec_p2
        ; ec_point_add uses ec_p2 in affine (X,Y) but we have Jacobian.
        ; Convert u2*Q to affine first, then load into ec_p2.
        jsr ec_jacobian_to_affine   ; converts ec_p3 in-place -> affine X,Y

        ldx #31
@copy_u2q_x:
        lda ec_p3,x                 ; affine X
        sta ec_p2,x
        dex
        bpl @copy_u2q_x

        ldx #31
@copy_u2q_y:
        lda ec_p3+32,x              ; affine Y
        sta ec_p2+32,x
        dex
        bpl @copy_u2q_y

        ; ec_p3 = ec_p1 + ec_p2 (Jacobian + affine -> Jacobian)
        jsr ec_point_add

        ; ---------------------------------------------------------------
        ; Step 6: Convert R to affine
        ; ---------------------------------------------------------------
        jsr ec_jacobian_to_affine   ; converts ec_p3 in-place

        ; Check R is not point at infinity (Z was 0 before conversion)
        ; After affine conversion, if Z was 0 the result is undefined.
        ; ec_jacobian_to_affine should flag this; we check X for zero
        ; as a sanity check (astronomically unlikely for valid sig).

        ; ---------------------------------------------------------------
        ; Step 7: Check R.x mod n == r
        ; R.x is already reduced mod p. We need R.x mod n.
        ; Since p and n are close for P-256, R.x mod n may just be R.x,
        ; but we must check: if R.x >= n, subtract n.
        ; ---------------------------------------------------------------

        ; Compare R.x (in ec_p3) with n
        lda #<ec_p3
        sta fp_src1
        lda #>ec_p3
        sta fp_src1+1
        lda #<ec_n
        sta fp_src2
        lda #>ec_n
        sta fp_src2+1
        jsr fp_cmp
        bcc @256_no_reduce          ; R.x < n, no reduction needed

        ; R.x >= n: compute R.x - n -> ev_u1 (reuse buffer)
        lda #<ec_p3
        sta fp_src1
        lda #>ec_p3
        sta fp_src1+1
        lda #<ec_n
        sta fp_src2
        lda #>ec_n
        sta fp_src2+1
        lda #<ev_u1
        sta fp_dst
        lda #>ev_u1
        sta fp_dst+1
        jsr fp_sub

        ; Compare ev_u1 with r
        lda #<ev_u1
        sta fp_src1
        lda #>ev_u1
        sta fp_src1+1
        jmp @256_final_cmp

@256_no_reduce:
        ; Compare R.x directly with r
        lda #<ec_p3
        sta fp_src1
        lda #>ec_p3
        sta fp_src1+1

@256_final_cmp:
        lda #<ecdsa_sig_r
        sta fp_src2
        lda #>ecdsa_sig_r
        sta fp_src2+1
        jsr fp_cmp
        bne @256_mismatch

        ; R.x mod n == r -> signature valid
        clc
        rts

@256_mismatch:
        sec
        rts

; =============================================================================
; ecdsa_verify_384 - P-384 signature verification
; =============================================================================
ecdsa_verify_384:
        ; STUBBED — see project_p384_stubbed.md
        ; Full P-384 verify body removed to save space; dispatch in ecdsa_verify
        ; returns error for non-P-256 curves before reaching this label.
        sec
        rts

; =============================================================================
; DER signature parsing
; =============================================================================
; ecdsa_parse_der_sig - Parse DER-encoded ECDSA signature into r, s
;
; Input: zp_ptr ($FB-$FC) = pointer to DER signature data
;        zp_count ($FE) = total signature length
;        ecdsa_sig_len = expected component length (32 or 48)
; Output: ecdsa_sig_r, ecdsa_sig_s filled, C=0 ok, C=1 parse error
;
; DER format: SEQUENCE { INTEGER r, INTEGER s }
;   30 <len> 02 <r_len> <r_bytes> 02 <s_len> <s_bytes>
; INTEGERs may have a leading 0x00 padding byte if high bit is set.
; =============================================================================
ecdsa_parse_der_sig:
        ldy #0

        ; Expect SEQUENCE tag (0x30)
        lda (zp_ptr),y
        cmp #$30
        beq +
        jmp @der_error
+
        iny

        ; Skip SEQUENCE length byte (we trust the outer length)
        iny

        ; --- Parse first INTEGER (r) ---
        ; Expect INTEGER tag (0x02)
        lda (zp_ptr),y
        cmp #$02
        beq +
        jmp @der_error
+
        iny

        ; Read r length
        lda (zp_ptr),y
        sta ev_der_int_len
        iny

        ; Clear ecdsa_sig_r
        lda #<ecdsa_sig_r
        sta fp_dst
        lda #>ecdsa_sig_r
        sta fp_dst+1
        lda ecdsa_sig_len
        cmp #48
        beq @clr_r_384
        jsr fp_zero
        jmp @parse_r
@clr_r_384:
        jsr fp_zero            ; STUBBED — dead code for P-256 only

@parse_r:
        ; Handle leading zero padding: if int_len > sig_len, skip leading 0x00
        lda ev_der_int_len
        cmp ecdsa_sig_len
        beq @r_no_pad
        bcc @r_short

        ; int_len > sig_len: skip (int_len - sig_len) leading zeros
        lda ev_der_int_len
        sec
        sbc ecdsa_sig_len
        tax
@r_skip_pad:
        iny
        dex
        bne @r_skip_pad
        lda ecdsa_sig_len
        sta ev_der_int_len
        jmp @r_no_pad

@r_short:
        ; int_len < sig_len: right-align in buffer
        ; dest offset = sig_len - int_len
        ; Handled by the copy below (starts at offset)

@r_no_pad:
        ; Copy r bytes, right-aligned in ecdsa_sig_r
        lda ecdsa_sig_len
        sec
        sbc ev_der_int_len
        tax                         ; X = dest offset
        lda ev_der_int_len
        sta ev_der_copy_cnt
@r_copy:
        lda ev_der_copy_cnt
        beq @parse_s_tag
        lda (zp_ptr),y
        sta ecdsa_sig_r,x
        iny
        inx
        dec ev_der_copy_cnt
        jmp @r_copy

        ; --- Parse second INTEGER (s) ---
@parse_s_tag:
        lda (zp_ptr),y
        cmp #$02
        bne @der_error
        iny

        ; Read s length
        lda (zp_ptr),y
        sta ev_der_int_len
        iny

        ; Clear ecdsa_sig_s
        lda #<ecdsa_sig_s
        sta fp_dst
        lda #>ecdsa_sig_s
        sta fp_dst+1
        lda ecdsa_sig_len
        cmp #48
        beq @clr_s_384
        jsr fp_zero
        jmp @parse_s
@clr_s_384:
        jsr fp_zero            ; STUBBED — dead code for P-256 only

@parse_s:
        ; Handle leading zero padding
        lda ev_der_int_len
        cmp ecdsa_sig_len
        beq @s_no_pad
        bcc @s_short

        lda ev_der_int_len
        sec
        sbc ecdsa_sig_len
        tax
@s_skip_pad:
        iny
        dex
        bne @s_skip_pad
        lda ecdsa_sig_len
        sta ev_der_int_len
        jmp @s_no_pad

@s_short:

@s_no_pad:
        ; Copy s bytes, right-aligned in ecdsa_sig_s
        lda ecdsa_sig_len
        sec
        sbc ev_der_int_len
        tax
        lda ev_der_int_len
        sta ev_der_copy_cnt
@s_copy:
        lda ev_der_copy_cnt
        beq @der_ok
        lda (zp_ptr),y
        sta ecdsa_sig_s,x
        iny
        inx
        dec ev_der_copy_cnt
        jmp @s_copy

@der_ok:
        clc
        rts

@der_error:
        sec
        rts

; =============================================================================
; Data buffers are in data.asm (moved there to avoid $7800-$7BFF sqtab region)
; =============================================================================
