; =============================================================================
; ecdsa_points_384.asm - Point operations for ECDSA P-384
; ec_point_double_384, ec_point_add_384, ec_scalar_mul_384,
; ec_jacobian_to_affine_384
;
; Adapted from ecdsa_points.asm (P-256) with 48-byte field elements.
; Jacobian point = 144 bytes (3 x 48). Y offset = +48, Z offset = +96.
; =============================================================================

; =============================================================================
; ec_point_double_384: ec_p3_384 = 2 * ec_p1_384 (Jacobian)
; Formula for a = -3 (P-384):
;   M = 3*(X1 - Z1^2)*(X1 + Z1^2)
;   S = 4*X1*Y1^2
;   X3 = M^2 - 2*S
;   Y3 = M*(S - X3) - 8*Y1^4
;   Z3 = 2*Y1*Z1
; =============================================================================
ec_point_double_384:
        ; Check Z1 == 0 (point at infinity)
        lda #<(ec_p1_384+96)
        sta fp_src1
        lda #>(ec_p1_384+96)
        sta fp_src1+1
        jsr fp_is_zero_384
        bne @notinf
        ; Result = infinity
        ldy #143
        lda #0
@ci:    sta ec_p3_384,y
        dey
        bpl @ci
        rts

@notinf:
        jsr ec_set_modp_384

        ; t1 = Z1^2
        lda #<(ec_p1_384+96)
        sta fp_src1
        lda #>(ec_p1_384+96)
        sta fp_src1+1
        lda #<(ec_p1_384+96)
        sta fp_src2
        lda #>(ec_p1_384+96)
        sta fp_src2+1
        lda #<ec_t1_384
        sta fp_dst
        lda #>ec_t1_384
        sta fp_dst+1
        jsr ec_mulp_384         ; t1 = Z1^2

        ; t2 = X1 - t1
        lda #<ec_p1_384
        sta fp_src1
        lda #>ec_p1_384
        sta fp_src1+1
        lda #<ec_t1_384
        sta fp_src2
        lda #>ec_t1_384
        sta fp_src2+1
        lda #<ec_t2_384
        sta fp_dst
        lda #>ec_t2_384
        sta fp_dst+1
        jsr fp_mod_sub_384      ; t2 = X1 - Z1^2

        ; t3 = X1 + t1
        lda #<ec_p1_384
        sta fp_src1
        lda #>ec_p1_384
        sta fp_src1+1
        lda #<ec_t1_384
        sta fp_src2
        lda #>ec_t1_384
        sta fp_src2+1
        lda #<ec_t3_384
        sta fp_dst
        lda #>ec_t3_384
        sta fp_dst+1
        jsr fp_mod_add_384      ; t3 = X1 + Z1^2

        ; t4 = t2 * t3 = (X1-Z^2)(X1+Z^2)
        lda #<ec_t2_384
        sta fp_src1
        lda #>ec_t2_384
        sta fp_src1+1
        lda #<ec_t3_384
        sta fp_src2
        lda #>ec_t3_384
        sta fp_src2+1
        lda #<ec_t4_384
        sta fp_dst
        lda #>ec_t4_384
        sta fp_dst+1
        jsr ec_mulp_384         ; t4 = X1^2 - Z1^4

        ; M = 3*t4: t5 = 2*t4, t2 = t5+t4 = 3*t4
        lda #<ec_t4_384
        sta fp_src1
        lda #>ec_t4_384
        sta fp_src1+1
        lda #<ec_t4_384
        sta fp_src2
        lda #>ec_t4_384
        sta fp_src2+1
        lda #<ec_t5_384
        sta fp_dst
        lda #>ec_t5_384
        sta fp_dst+1
        jsr fp_mod_add_384      ; t5 = 2*t4

        lda #<ec_t5_384
        sta fp_src1
        lda #>ec_t5_384
        sta fp_src1+1
        lda #<ec_t4_384
        sta fp_src2
        lda #>ec_t4_384
        sta fp_src2+1
        lda #<ec_t2_384
        sta fp_dst
        lda #>ec_t2_384
        sta fp_dst+1
        jsr fp_mod_add_384      ; t2 = M = 3*(X1^2 - Z1^4)

        ; t3 = Y1^2
        lda #<(ec_p1_384+48)
        sta fp_src1
        lda #>(ec_p1_384+48)
        sta fp_src1+1
        lda #<(ec_p1_384+48)
        sta fp_src2
        lda #>(ec_p1_384+48)
        sta fp_src2+1
        lda #<ec_t3_384
        sta fp_dst
        lda #>ec_t3_384
        sta fp_dst+1
        jsr ec_mulp_384         ; t3 = Y1^2

        ; t4 = X1 * Y1^2
        lda #<ec_p1_384
        sta fp_src1
        lda #>ec_p1_384
        sta fp_src1+1
        lda #<ec_t3_384
        sta fp_src2
        lda #>ec_t3_384
        sta fp_src2+1
        lda #<ec_t4_384
        sta fp_dst
        lda #>ec_t4_384
        sta fp_dst+1
        jsr ec_mulp_384         ; t4 = X1*Y1^2

        ; S = 4*X1*Y1^2 = 4*t4
        ; t5 = 2*t4
        lda #<ec_t4_384
        sta fp_src1
        lda #>ec_t4_384
        sta fp_src1+1
        lda #<ec_t4_384
        sta fp_src2
        lda #>ec_t4_384
        sta fp_src2+1
        lda #<ec_t5_384
        sta fp_dst
        lda #>ec_t5_384
        sta fp_dst+1
        jsr fp_mod_add_384      ; t5 = 2*X1*Y1^2

        ; t1 = S = 2*t5 = 4*X1*Y1^2
        lda #<ec_t5_384
        sta fp_src1
        lda #>ec_t5_384
        sta fp_src1+1
        lda #<ec_t5_384
        sta fp_src2
        lda #>ec_t5_384
        sta fp_src2+1
        lda #<ec_t1_384
        sta fp_dst
        lda #>ec_t1_384
        sta fp_dst+1
        jsr fp_mod_add_384      ; t1 = S = 4*X1*Y1^2

        ; X3 = M^2 - 2*S
        ; t4 = M^2
        lda #<ec_t2_384
        sta fp_src1
        lda #>ec_t2_384
        sta fp_src1+1
        lda #<ec_t2_384
        sta fp_src2
        lda #>ec_t2_384
        sta fp_src2+1
        lda #<ec_t4_384
        sta fp_dst
        lda #>ec_t4_384
        sta fp_dst+1
        jsr ec_mulp_384         ; t4 = M^2

        ; t5 = 2*S
        lda #<ec_t1_384
        sta fp_src1
        lda #>ec_t1_384
        sta fp_src1+1
        lda #<ec_t1_384
        sta fp_src2
        lda #>ec_t1_384
        sta fp_src2+1
        lda #<ec_t5_384
        sta fp_dst
        lda #>ec_t5_384
        sta fp_dst+1
        jsr fp_mod_add_384      ; t5 = 2*S

        ; X3 = t4 - t5
        lda #<ec_t4_384
        sta fp_src1
        lda #>ec_t4_384
        sta fp_src1+1
        lda #<ec_t5_384
        sta fp_src2
        lda #>ec_t5_384
        sta fp_src2+1
        lda #<ec_p3_384
        sta fp_dst
        lda #>ec_p3_384
        sta fp_dst+1
        jsr fp_mod_sub_384      ; X3 = M^2 - 2S

        ; Y3 = M*(S - X3) - 8*Y1^4
        ; t4 = S - X3
        lda #<ec_t1_384
        sta fp_src1
        lda #>ec_t1_384
        sta fp_src1+1
        lda #<ec_p3_384
        sta fp_src2
        lda #>ec_p3_384
        sta fp_src2+1
        lda #<ec_t4_384
        sta fp_dst
        lda #>ec_t4_384
        sta fp_dst+1
        jsr fp_mod_sub_384      ; t4 = S - X3

        ; t5 = M*(S-X3)
        lda #<ec_t2_384
        sta fp_src1
        lda #>ec_t2_384
        sta fp_src1+1
        lda #<ec_t4_384
        sta fp_src2
        lda #>ec_t4_384
        sta fp_src2+1
        lda #<ec_t5_384
        sta fp_dst
        lda #>ec_t5_384
        sta fp_dst+1
        jsr ec_mulp_384         ; t5 = M*(S-X3)

        ; t4 = Y1^4 = (Y1^2)^2 = t3^2
        lda #<ec_t3_384
        sta fp_src1
        lda #>ec_t3_384
        sta fp_src1+1
        lda #<ec_t3_384
        sta fp_src2
        lda #>ec_t3_384
        sta fp_src2+1
        lda #<ec_t4_384
        sta fp_dst
        lda #>ec_t4_384
        sta fp_dst+1
        jsr ec_mulp_384         ; t4 = Y1^4

        ; 8*Y1^4: t6 = 2*t4, t4 = 2*t6 = 4*Y1^4, t6 = 2*t4 = 8*Y1^4
        lda #<ec_t4_384
        sta fp_src1
        lda #>ec_t4_384
        sta fp_src1+1
        lda #<ec_t4_384
        sta fp_src2
        lda #>ec_t4_384
        sta fp_src2+1
        lda #<ec_t6_384
        sta fp_dst
        lda #>ec_t6_384
        sta fp_dst+1
        jsr fp_mod_add_384      ; t6 = 2*Y1^4

        lda #<ec_t6_384
        sta fp_src1
        lda #>ec_t6_384
        sta fp_src1+1
        lda #<ec_t6_384
        sta fp_src2
        lda #>ec_t6_384
        sta fp_src2+1
        lda #<ec_t4_384
        sta fp_dst
        lda #>ec_t4_384
        sta fp_dst+1
        jsr fp_mod_add_384      ; t4 = 4*Y1^4

        lda #<ec_t4_384
        sta fp_src1
        lda #>ec_t4_384
        sta fp_src1+1
        lda #<ec_t4_384
        sta fp_src2
        lda #>ec_t4_384
        sta fp_src2+1
        lda #<ec_t6_384
        sta fp_dst
        lda #>ec_t6_384
        sta fp_dst+1
        jsr fp_mod_add_384      ; t6 = 8*Y1^4

        ; Y3 = t5 - t6
        lda #<ec_t5_384
        sta fp_src1
        lda #>ec_t5_384
        sta fp_src1+1
        lda #<ec_t6_384
        sta fp_src2
        lda #>ec_t6_384
        sta fp_src2+1
        lda #<(ec_p3_384+48)
        sta fp_dst
        lda #>(ec_p3_384+48)
        sta fp_dst+1
        jsr fp_mod_sub_384      ; Y3 = M*(S-X3) - 8*Y1^4

        ; Z3 = 2*Y1*Z1
        ; t1 = Y1*Z1
        lda #<(ec_p1_384+48)
        sta fp_src1
        lda #>(ec_p1_384+48)
        sta fp_src1+1
        lda #<(ec_p1_384+96)
        sta fp_src2
        lda #>(ec_p1_384+96)
        sta fp_src2+1
        lda #<ec_t1_384
        sta fp_dst
        lda #>ec_t1_384
        sta fp_dst+1
        jsr ec_mulp_384         ; t1 = Y1*Z1

        ; Z3 = 2*t1
        lda #<ec_t1_384
        sta fp_src1
        lda #>ec_t1_384
        sta fp_src1+1
        lda #<ec_t1_384
        sta fp_src2
        lda #>ec_t1_384
        sta fp_src2+1
        lda #<(ec_p3_384+96)
        sta fp_dst
        lda #>(ec_p3_384+96)
        sta fp_dst+1
        jsr fp_mod_add_384      ; Z3 = 2*Y1*Z1

        rts

; =============================================================================
; ec_point_add_384: ec_p3_384 = ec_p1_384 + ec_p2_384
; P1 is Jacobian (X1,Y1,Z1). P2 is AFFINE (X2,Y2, Z2 assumed 1).
;
;   U2 = X2*Z1^2,  S2 = Y2*Z1^3
;   H = U2 - X1,   R = S2 - Y1
;   If H==0: if R==0 -> double, else -> infinity
;   X3 = R^2 - H^3 - 2*X1*H^2
;   Y3 = R*(X1*H^2 - X3) - Y1*H^3
;   Z3 = H*Z1
; =============================================================================
ec_point_add_384:
        ; If P1 is infinity (Z1==0): result = P2 with Z=1
        lda #<(ec_p1_384+96)
        sta fp_src1
        lda #>(ec_p1_384+96)
        sta fp_src1+1
        jsr fp_is_zero_384
        bne @p1ok

        ; Copy P2 to P3 as Jacobian with Z=1
        ldy #47
@cpx:   lda ec_p2_384,y
        sta ec_p3_384,y
        dey
        bpl @cpx
        ldy #47
@cpy:   lda ec_p2_384+48,y
        sta ec_p3_384+48,y
        dey
        bpl @cpy
        ldy #47
        lda #0
@clz:   sta ec_p3_384+96,y
        dey
        bpl @clz
        lda #1
        sta ec_p3_384+143       ; Z = 1
        rts

@p1ok:
        jsr ec_set_modp_384

        ; t1 = Z1^2
        lda #<(ec_p1_384+96)
        sta fp_src1
        lda #>(ec_p1_384+96)
        sta fp_src1+1
        lda #<(ec_p1_384+96)
        sta fp_src2
        lda #>(ec_p1_384+96)
        sta fp_src2+1
        lda #<ec_t1_384
        sta fp_dst
        lda #>ec_t1_384
        sta fp_dst+1
        jsr ec_mulp_384         ; t1 = Z1^2

        ; t2 = X2*Z1^2 = U2
        lda #<ec_p2_384
        sta fp_src1
        lda #>ec_p2_384
        sta fp_src1+1
        lda #<ec_t1_384
        sta fp_src2
        lda #>ec_t1_384
        sta fp_src2+1
        lda #<ec_t2_384
        sta fp_dst
        lda #>ec_t2_384
        sta fp_dst+1
        jsr ec_mulp_384         ; t2 = U2

        ; t3 = Z1^3 = Z1*t1
        lda #<(ec_p1_384+96)
        sta fp_src1
        lda #>(ec_p1_384+96)
        sta fp_src1+1
        lda #<ec_t1_384
        sta fp_src2
        lda #>ec_t1_384
        sta fp_src2+1
        lda #<ec_t3_384
        sta fp_dst
        lda #>ec_t3_384
        sta fp_dst+1
        jsr ec_mulp_384         ; t3 = Z1^3

        ; t4 = Y2*Z1^3 = S2
        lda #<(ec_p2_384+48)
        sta fp_src1
        lda #>(ec_p2_384+48)
        sta fp_src1+1
        lda #<ec_t3_384
        sta fp_src2
        lda #>ec_t3_384
        sta fp_src2+1
        lda #<ec_t4_384
        sta fp_dst
        lda #>ec_t4_384
        sta fp_dst+1
        jsr ec_mulp_384         ; t4 = S2

        ; H = U2 - X1 = t2 - X1 -> t1
        lda #<ec_t2_384
        sta fp_src1
        lda #>ec_t2_384
        sta fp_src1+1
        lda #<ec_p1_384
        sta fp_src2
        lda #>ec_p1_384
        sta fp_src2+1
        lda #<ec_t1_384
        sta fp_dst
        lda #>ec_t1_384
        sta fp_dst+1
        jsr fp_mod_sub_384      ; t1 = H = U2 - X1

        ; R = S2 - Y1 = t4 - Y1 -> t2
        lda #<ec_t4_384
        sta fp_src1
        lda #>ec_t4_384
        sta fp_src1+1
        lda #<(ec_p1_384+48)
        sta fp_src2
        lda #>(ec_p1_384+48)
        sta fp_src2+1
        lda #<ec_t2_384
        sta fp_dst
        lda #>ec_t2_384
        sta fp_dst+1
        jsr fp_mod_sub_384      ; t2 = R = S2 - Y1

        ; Check H == 0
        lda #<ec_t1_384
        sta fp_src1
        lda #>ec_t1_384
        sta fp_src1+1
        jsr fp_is_zero_384
        bne @h_nonzero

        ; H == 0: check R
        lda #<ec_t2_384
        sta fp_src1
        lda #>ec_t2_384
        sta fp_src1+1
        jsr fp_is_zero_384
        bne @set_inf
        ; H==0, R==0: points are equal, double P1
        jmp ec_point_double_384

@set_inf:
        ; H==0, R!=0: inverse points, result = infinity
        ldy #143
        lda #0
@sinf:  sta ec_p3_384,y
        dey
        bpl @sinf
        rts

@h_nonzero:
        ; t3 = H^2
        lda #<ec_t1_384
        sta fp_src1
        lda #>ec_t1_384
        sta fp_src1+1
        lda #<ec_t1_384
        sta fp_src2
        lda #>ec_t1_384
        sta fp_src2+1
        lda #<ec_t3_384
        sta fp_dst
        lda #>ec_t3_384
        sta fp_dst+1
        jsr ec_mulp_384         ; t3 = H^2

        ; t4 = H^3 = H*H^2
        lda #<ec_t1_384
        sta fp_src1
        lda #>ec_t1_384
        sta fp_src1+1
        lda #<ec_t3_384
        sta fp_src2
        lda #>ec_t3_384
        sta fp_src2+1
        lda #<ec_t4_384
        sta fp_dst
        lda #>ec_t4_384
        sta fp_dst+1
        jsr ec_mulp_384         ; t4 = H^3

        ; t5 = X1*H^2
        lda #<ec_p1_384
        sta fp_src1
        lda #>ec_p1_384
        sta fp_src1+1
        lda #<ec_t3_384
        sta fp_src2
        lda #>ec_t3_384
        sta fp_src2+1
        lda #<ec_t5_384
        sta fp_dst
        lda #>ec_t5_384
        sta fp_dst+1
        jsr ec_mulp_384         ; t5 = X1*H^2

        ; X3 = R^2 - H^3 - 2*X1*H^2
        ; t3 = R^2
        lda #<ec_t2_384
        sta fp_src1
        lda #>ec_t2_384
        sta fp_src1+1
        lda #<ec_t2_384
        sta fp_src2
        lda #>ec_t2_384
        sta fp_src2+1
        lda #<ec_t3_384
        sta fp_dst
        lda #>ec_t3_384
        sta fp_dst+1
        jsr ec_mulp_384         ; t3 = R^2

        ; t3 = R^2 - H^3
        lda #<ec_t3_384
        sta fp_src1
        lda #>ec_t3_384
        sta fp_src1+1
        lda #<ec_t4_384
        sta fp_src2
        lda #>ec_t4_384
        sta fp_src2+1
        lda #<ec_t3_384
        sta fp_dst
        lda #>ec_t3_384
        sta fp_dst+1
        jsr fp_mod_sub_384      ; t3 = R^2 - H^3

        ; t6 = 2*X1*H^2
        lda #<ec_t5_384
        sta fp_src1
        lda #>ec_t5_384
        sta fp_src1+1
        lda #<ec_t5_384
        sta fp_src2
        lda #>ec_t5_384
        sta fp_src2+1
        lda #<ec_t6_384
        sta fp_dst
        lda #>ec_t6_384
        sta fp_dst+1
        jsr fp_mod_add_384      ; t6 = 2*X1*H^2

        ; X3 = t3 - t6
        lda #<ec_t3_384
        sta fp_src1
        lda #>ec_t3_384
        sta fp_src1+1
        lda #<ec_t6_384
        sta fp_src2
        lda #>ec_t6_384
        sta fp_src2+1
        lda #<ec_p3_384
        sta fp_dst
        lda #>ec_p3_384
        sta fp_dst+1
        jsr fp_mod_sub_384      ; X3

        ; Y3 = R*(X1*H^2 - X3) - Y1*H^3
        ; t3 = X1*H^2 - X3 = t5 - X3
        lda #<ec_t5_384
        sta fp_src1
        lda #>ec_t5_384
        sta fp_src1+1
        lda #<ec_p3_384
        sta fp_src2
        lda #>ec_p3_384
        sta fp_src2+1
        lda #<ec_t3_384
        sta fp_dst
        lda #>ec_t3_384
        sta fp_dst+1
        jsr fp_mod_sub_384      ; t3 = X1*H^2 - X3

        ; t5 = R * t3
        lda #<ec_t2_384
        sta fp_src1
        lda #>ec_t2_384
        sta fp_src1+1
        lda #<ec_t3_384
        sta fp_src2
        lda #>ec_t3_384
        sta fp_src2+1
        lda #<ec_t5_384
        sta fp_dst
        lda #>ec_t5_384
        sta fp_dst+1
        jsr ec_mulp_384         ; t5 = R*(X1*H^2 - X3)

        ; t6 = Y1*H^3
        lda #<(ec_p1_384+48)
        sta fp_src1
        lda #>(ec_p1_384+48)
        sta fp_src1+1
        lda #<ec_t4_384
        sta fp_src2
        lda #>ec_t4_384
        sta fp_src2+1
        lda #<ec_t6_384
        sta fp_dst
        lda #>ec_t6_384
        sta fp_dst+1
        jsr ec_mulp_384         ; t6 = Y1*H^3

        ; Y3 = t5 - t6
        lda #<ec_t5_384
        sta fp_src1
        lda #>ec_t5_384
        sta fp_src1+1
        lda #<ec_t6_384
        sta fp_src2
        lda #>ec_t6_384
        sta fp_src2+1
        lda #<(ec_p3_384+48)
        sta fp_dst
        lda #>(ec_p3_384+48)
        sta fp_dst+1
        jsr fp_mod_sub_384      ; Y3

        ; Z3 = H*Z1 = t1*Z1
        lda #<ec_t1_384
        sta fp_src1
        lda #>ec_t1_384
        sta fp_src1+1
        lda #<(ec_p1_384+96)
        sta fp_src2
        lda #>(ec_p1_384+96)
        sta fp_src2+1
        lda #<(ec_p3_384+96)
        sta fp_dst
        lda #>(ec_p3_384+96)
        sta fp_dst+1
        jsr ec_mulp_384         ; Z3 = H*Z1

        rts

; =============================================================================
; ec_scalar_mul_384: ec_p3_384 = k * ec_p2_384
; k is a 48-byte scalar pointed to by ec_scalar_ptr (ZP $3b).
; ec_p2_384 must be set by caller to the affine point (X,Y) to multiply.
; Uses double-and-add with ec_p2_384 (affine).
; Result in ec_p3_384 (Jacobian).
; =============================================================================
ec_scalar_mul_384:
        ; Initialize ec_p1_384 = point at infinity (Z=0)
        ldy #143
        lda #0
@clr:   sta ec_p1_384,y
        dey
        bpl @clr

        ; Caller must set ec_p2_384 before calling

        ; Process 384 bits of k, MSB first
        lda #0
        sta ec_sc_byte_384      ; byte index 0..47
        lda #$80
        sta ec_sc_mask_384      ; bit mask

@bitloop:
        ; Double: ec_p1_384 = 2*ec_p1_384 (via ec_p3_384)
        jsr ec_point_double_384 ; ec_p3_384 = 2*ec_p1_384
        ; Copy ec_p3_384 -> ec_p1_384
        ldy #143
@cp1:   lda ec_p3_384,y
        sta ec_p1_384,y
        dey
        bpl @cp1

        ; Test bit of k
        ldy ec_sc_byte_384
        lda (ec_scalar_ptr),y
        and ec_sc_mask_384
        beq @nobit

        ; Add: ec_p1_384 = ec_p1_384 + ec_p2_384 (via ec_p3_384)
        jsr ec_point_add_384    ; ec_p3_384 = ec_p1_384 + G
        ; Copy ec_p3_384 -> ec_p1_384
        ldy #143
@cp2:   lda ec_p3_384,y
        sta ec_p1_384,y
        dey
        bpl @cp2

@nobit:
        ; Advance to next bit
        lsr ec_sc_mask_384
        bne @bitloop
        ; Next byte
        lda #$80
        sta ec_sc_mask_384
        inc ec_sc_byte_384
        lda ec_sc_byte_384
        cmp #48
        beq @done
        jmp @bitloop

@done:
        ; Result is in ec_p1_384; copy to ec_p3_384
        ldy #143
@cfin:  lda ec_p1_384,y
        sta ec_p3_384,y
        dey
        bpl @cfin
        rts

ec_sc_byte_384:     !byte 0
ec_sc_mask_384:     !byte 0

; =============================================================================
; ec_jacobian_to_affine_384: convert ec_p3_384 (Jacobian) to affine (x,y)
; Result: ec_affine_x_384, ec_affine_y_384 (48 bytes each)
; Computes x = X/Z^2, y = Y/Z^3 using modular inverse.
; =============================================================================
ec_affine_x_384:    !fill 48, 0
ec_affine_y_384:    !fill 48, 0

ec_jacobian_to_affine_384:
        jsr ec_set_modp_384

        ; Compute Z^(-1)
        lda #<(ec_p3_384+96)
        sta fp_src1
        lda #>(ec_p3_384+96)
        sta fp_src1+1
        jsr fp_mod_inv_384      ; fp_r0_384 = Z^(-1)

        ; Copy Z^(-1) to ec_t1_384
        ldy #47
@czi:   lda fp_r0_384,y
        sta ec_t1_384,y
        dey
        bpl @czi

        ; t2 = Z^(-2) = Z^(-1) * Z^(-1)
        lda #<ec_t1_384
        sta fp_src1
        lda #>ec_t1_384
        sta fp_src1+1
        lda #<ec_t1_384
        sta fp_src2
        lda #>ec_t1_384
        sta fp_src2+1
        lda #<ec_t2_384
        sta fp_dst
        lda #>ec_t2_384
        sta fp_dst+1
        jsr ec_mulp_384         ; t2 = Z^(-2)

        ; t3 = Z^(-3) = Z^(-2) * Z^(-1)
        lda #<ec_t2_384
        sta fp_src1
        lda #>ec_t2_384
        sta fp_src1+1
        lda #<ec_t1_384
        sta fp_src2
        lda #>ec_t1_384
        sta fp_src2+1
        lda #<ec_t3_384
        sta fp_dst
        lda #>ec_t3_384
        sta fp_dst+1
        jsr ec_mulp_384         ; t3 = Z^(-3)

        ; x = X * Z^(-2)
        lda #<ec_p3_384
        sta fp_src1
        lda #>ec_p3_384
        sta fp_src1+1
        lda #<ec_t2_384
        sta fp_src2
        lda #>ec_t2_384
        sta fp_src2+1
        lda #<ec_affine_x_384
        sta fp_dst
        lda #>ec_affine_x_384
        sta fp_dst+1
        jsr ec_mulp_384         ; affine_x = X*Z^(-2)

        ; y = Y * Z^(-3)
        lda #<(ec_p3_384+48)
        sta fp_src1
        lda #>(ec_p3_384+48)
        sta fp_src1+1
        lda #<ec_t3_384
        sta fp_src2
        lda #>ec_t3_384
        sta fp_src2+1
        lda #<ec_affine_y_384
        sta fp_dst
        lda #>ec_affine_y_384
        sta fp_dst+1
        jsr ec_mulp_384         ; affine_y = Y*Z^(-3)

        ; Copy affine result back to ec_p3_384
        ldy #47
@cpx:   lda ec_affine_x_384,y
        sta ec_p3_384,y
        dey
        bpl @cpx
        ldy #47
@cpy2:  lda ec_affine_y_384,y
        sta ec_p3_384+48,y
        dey
        bpl @cpy2

        rts
