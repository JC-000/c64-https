; =============================================================================
; ecdsa_fp.asm - Big-number primitives for ECDSA P-256
; ZP pointers, fp_copy, fp_zero, fp_cmp, fp_add, fp_sub, fp_rshift1,
; fp_mul, fp_init_sqtab
;
; Imported from c64-aes256-ecdsa for TLS 1.3 certificate verification.
; ZP equates (fp_src1=$22 etc.) are in constants.asm.
; Quarter-square table at $7800 is shared with Poly1305.
; =============================================================================

; =============================================================================
; fp_init_sqtab - quarter-square table at $7800-$7BFF
; NOT included here: sqtab_init in poly1305.asm already builds this table.
; Alias for callers that expect the ecdsa name:
; =============================================================================
fp_init_sqtab = sqtab_init

; =============================================================================
; fp_copy: copy 32 bytes from (fp_src1) to (fp_dst)
; =============================================================================
fp_copy:
        ldy #31
@lp:    lda (fp_src1),y
        sta (fp_dst),y
        dey
        bpl @lp
        rts

; =============================================================================
; fp_zero: zero 32 bytes at (fp_dst)
; =============================================================================
fp_zero:
        lda #0
        ldy #31
@lp:    sta (fp_dst),y
        dey
        bpl @lp
        rts

; =============================================================================
; fp_cmp: compare (fp_src1) vs (fp_src2), 32 bytes big-endian
; Carry set if src1 >= src2, clear if src1 < src2. Zero if equal.
; =============================================================================
fp_cmp:
        ldy #0
@lp:    lda (fp_src1),y
        cmp (fp_src2),y
        bne @done
        iny
        cpy #32
        bne @lp
@done:  rts

; =============================================================================
; fp_add: (fp_dst) = (fp_src1) + (fp_src2). Carry in fp_carry.
; =============================================================================
fp_add:
        clc
        ldy #31
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
; fp_sub: (fp_dst) = (fp_src1) - (fp_src2). Borrow in fp_carry (1=borrow).
; =============================================================================
fp_sub:
        sec
        ldy #31
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
; fp_is_zero: test if (fp_src1) == 0. Z flag set if zero.
; =============================================================================
fp_is_zero:
        ldy #0
        lda #0
@lp:    ora (fp_src1),y
        iny
        cpy #32
        bne @lp
        cmp #0
        rts

; =============================================================================
; fp_rshift1: right-shift (fp_src1) by 1 bit in place
; =============================================================================
fp_rshift1:
        clc
        ldy #0
        ldx #32
@lp:    lda (fp_src1),y
        ror
        sta (fp_src1),y
        iny
        dex
        bne @lp
        rts

; =============================================================================
; fp_mul: 256x256 -> 512 bit multiply
; (fp_src1) * (fp_src2) -> fp_wide (64 bytes)
; Schoolbook with quarter-square 8x8 lookup.
; =============================================================================
fp_mul:
        ; Clear 64-byte result
        ldy #63
        lda #0
@clr:   sta fp_wide,y
        dey
        bpl @clr

        lda #31
        sta fp_mul_i
@outer:
        ldy fp_mul_i
        lda (fp_src1),y
        sta fp_a_byte
        bne @do_inner
        jmp @skip_o

@do_inner:
        lda #31
        sta fp_mul_j
@inner:
        ldy fp_mul_j
        lda (fp_src2),y
        beq @skip_i
        sta fp_b_byte

        ; a*b via quarter-square: sqtab[a+b] - sqtab[|a-b|]
        lda fp_a_byte
        clc
        adc fp_b_byte
        tax                     ; X = (a+b) low
        lda #0
        adc #0
        sta fp_s_hi             ; sum page (0 or 1)

        lda fp_a_byte
        sec
        sbc fp_b_byte
        bcs +
        eor #$ff
        adc #1
+       tay                     ; Y = |a-b| (always page 0)

        lda fp_s_hi
        beq @s0
        ; sum page 1
        lda sqtab_lo+256,x
        sec
        sbc sqtab_lo,y
        sta fp_p_lo
        lda sqtab_hi+256,x
        sbc sqtab_hi,y
        sta fp_p_hi
        jmp @add_prod
@s0:    lda sqtab_lo,x
        sec
        sbc sqtab_lo,y
        sta fp_p_lo
        lda sqtab_hi,x
        sbc sqtab_hi,y
        sta fp_p_hi

@add_prod:
        ; Add 16-bit product to fp_wide[i+j+1] (lo) and [i+j] (hi)
        lda fp_mul_i
        clc
        adc fp_mul_j
        tax
        inx                     ; X = i+j+1

        clc
        lda fp_wide,x
        adc fp_p_lo
        sta fp_wide,x
        dex                     ; X = i+j
        lda fp_wide,x
        adc fp_p_hi
        sta fp_wide,x
        bcc @skip_i
        ; Propagate carry
@prop:  dex
        bmi @skip_i
        lda fp_wide,x
        adc #0
        sta fp_wide,x
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

fp_a_byte:  !byte 0
fp_b_byte:  !byte 0
fp_s_hi:    !byte 0
fp_p_lo:    !byte 0
fp_p_hi:    !byte 0
fp_wide:    !fill 64, 0
