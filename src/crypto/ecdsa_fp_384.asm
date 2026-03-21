; =============================================================================
; ecdsa_fp_384.asm - Big-number primitives for ECDSA P-384
; ZP pointers (shared), fp_copy_384, fp_zero_384, fp_cmp_384, fp_add_384,
; fp_sub_384, fp_rshift1_384, fp_mul_384, fp_is_zero_384, fp_chk_one_384
;
; Adapted from ecdsa_fp.asm (P-256) with 48-byte field elements.
; Uses the SAME ZP equates as P-256 — only data width changes.
; Quarter-square table (sqtab_lo/sqtab_hi) must already be built.
; =============================================================================

; --- Zero-page pointers (shared with P-256, already defined) ---
; fp_src1 = $22, fp_src2 = $24, fp_dst = $26, fp_misc = $28
; fp_carry = $2a, fp_loop = $2b
; fp_mul_i = $39, fp_mul_j = $3a
; sqtab_lo = $7800, sqtab_hi = $7a00

; =============================================================================
; fp_copy_384: copy 48 bytes from (fp_src1) to (fp_dst)
; =============================================================================
fp_copy_384:
        ldy #47
@lp:    lda (fp_src1),y
        sta (fp_dst),y
        dey
        bpl @lp
        rts

; =============================================================================
; fp_zero_384: zero 48 bytes at (fp_dst)
; =============================================================================
fp_zero_384:
        lda #0
        ldy #47
@lp:    sta (fp_dst),y
        dey
        bpl @lp
        rts

; =============================================================================
; fp_cmp_384: compare (fp_src1) vs (fp_src2), 48 bytes big-endian
; Carry set if src1 >= src2, clear if src1 < src2. Zero if equal.
; =============================================================================
fp_cmp_384:
        ldy #0
@lp:    lda (fp_src1),y
        cmp (fp_src2),y
        bne @done
        iny
        cpy #48
        bne @lp
@done:  rts

; =============================================================================
; fp_add_384: (fp_dst) = (fp_src1) + (fp_src2). Carry in fp_carry.
; =============================================================================
fp_add_384:
        clc
        ldy #47
@lp:    lda (fp_src1),y
        adc (fp_src2),y
        sta (fp_dst),y
        dey
        bpl @lp
        lda #0
        adc #0
        sta fp_carry
        rts

; =============================================================================
; fp_sub_384: (fp_dst) = (fp_src1) - (fp_src2). Borrow in fp_carry (1=borrow).
; =============================================================================
fp_sub_384:
        sec
        ldy #47
@lp:    lda (fp_src1),y
        sbc (fp_src2),y
        sta (fp_dst),y
        dey
        bpl @lp
        lda #0
        adc #0
        eor #1
        sta fp_carry
        rts

; =============================================================================
; fp_is_zero_384: test if (fp_src1) == 0. Z flag set if zero.
; =============================================================================
fp_is_zero_384:
        ldy #0
        lda #0
@lp:    ora (fp_src1),y
        iny
        cpy #48
        bne @lp
        cmp #0
        rts

; =============================================================================
; fp_rshift1_384: right-shift (fp_src1) by 1 bit in place
; =============================================================================
fp_rshift1_384:
        clc
        ldy #0
        ldx #48
@lp:    lda (fp_src1),y
        ror
        sta (fp_src1),y
        iny
        dex
        bne @lp
        rts

; =============================================================================
; fp_chk_one_384: check if (fp_src1) == 1. Z flag set if yes.
; =============================================================================
fp_chk_one_384:
        ldy #0
@lp:    lda (fp_src1),y
        bne @no
        iny
        cpy #47
        bne @lp
        lda (fp_src1),y
        cmp #1                  ; Z set if byte 47 == 1
        rts
@no:    lda #$ff                ; clear Z
        rts

; =============================================================================
; fp_mul_384: 384x384 -> 768 bit multiply
; (fp_src1) * (fp_src2) -> fp_wide_384 (96 bytes)
; Schoolbook with quarter-square 8x8 lookup.
; =============================================================================
fp_mul_384:
        ; Clear 96-byte result
        ldy #95
        lda #0
@clr:   sta fp_wide_384,y
        dey
        bpl @clr

        lda #47
        sta fp_mul_i
@outer:
        ldy fp_mul_i
        lda (fp_src1),y
        sta fp_a_byte_384
        bne @do_inner
        jmp @skip_o

@do_inner:
        lda #47
        sta fp_mul_j
@inner:
        ldy fp_mul_j
        lda (fp_src2),y
        beq @skip_i
        sta fp_b_byte_384

        ; a*b via quarter-square: sqtab[a+b] - sqtab[|a-b|]
        lda fp_a_byte_384
        clc
        adc fp_b_byte_384
        tax                     ; X = (a+b) low
        lda #0
        adc #0
        sta fp_s_hi_384         ; sum page (0 or 1)

        lda fp_a_byte_384
        sec
        sbc fp_b_byte_384
        bcs +
        eor #$ff
        adc #1
+       tay                     ; Y = |a-b| (always page 0)

        lda fp_s_hi_384
        beq @s0
        ; sum page 1
        lda sqtab_lo+256,x
        sec
        sbc sqtab_lo,y
        sta fp_p_lo_384
        lda sqtab_hi+256,x
        sbc sqtab_hi,y
        sta fp_p_hi_384
        jmp @add_prod
@s0:    lda sqtab_lo,x
        sec
        sbc sqtab_lo,y
        sta fp_p_lo_384
        lda sqtab_hi,x
        sbc sqtab_hi,y
        sta fp_p_hi_384

@add_prod:
        ; Add 16-bit product to fp_wide_384[i+j+1] (lo) and [i+j] (hi)
        lda fp_mul_i
        clc
        adc fp_mul_j
        tax
        inx                     ; X = i+j+1

        clc
        lda fp_wide_384,x
        adc fp_p_lo_384
        sta fp_wide_384,x
        dex                     ; X = i+j
        lda fp_wide_384,x
        adc fp_p_hi_384
        sta fp_wide_384,x
        bcc @skip_i
        ; Propagate carry
@prop:  dex
        bmi @skip_i
        lda fp_wide_384,x
        adc #0
        sta fp_wide_384,x
        bcs @prop

@skip_i:
        dec fp_mul_j
        bmi @skip_o
        jmp @inner
@skip_o:
        dec fp_mul_i
        bmi @mul_done
        jmp @outer
@mul_done:
        rts

fp_a_byte_384:  !byte 0
fp_b_byte_384:  !byte 0
fp_s_hi_384:    !byte 0
fp_p_lo_384:    !byte 0
fp_p_hi_384:    !byte 0
fp_wide_384:    !fill 96, 0
