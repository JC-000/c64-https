; =============================================================================
; ecdsa_mod_384.asm - Modular arithmetic for ECDSA P-384
; fp_mod_add_384, fp_mod_sub_384, fp_mod_reduce_384, fp_mod_mul_384,
; fp_mod_inv_384, result registers fp_r0_384-fp_r3_384
;
; Adapted from ecdsa_mod.asm (P-256) with 48-byte field elements.
; =============================================================================

; =============================================================================
; fp_mod_add_384: (fp_dst) = ((fp_src1) + (fp_src2)) mod (fp_misc)
; =============================================================================
fp_mod_add_384:
        jsr fp_add_384
        lda fp_carry
        bne @reduce

        ; Compare dst with modulus
        lda fp_src1
        pha
        lda fp_src1+1
        pha
        lda fp_src2
        pha
        lda fp_src2+1
        pha
        lda fp_dst
        sta fp_src1
        lda fp_dst+1
        sta fp_src1+1
        lda fp_misc
        sta fp_src2
        lda fp_misc+1
        sta fp_src2+1
        jsr fp_cmp_384
        pla
        sta fp_src2+1
        pla
        sta fp_src2
        pla
        sta fp_src1+1
        pla
        sta fp_src1
        bcc @done

@reduce:
        ; dst -= modulus
        lda fp_src1
        pha
        lda fp_src1+1
        pha
        lda fp_src2
        pha
        lda fp_src2+1
        pha
        lda fp_dst
        sta fp_src1
        lda fp_dst+1
        sta fp_src1+1
        lda fp_misc
        sta fp_src2
        lda fp_misc+1
        sta fp_src2+1
        jsr fp_sub_384
        pla
        sta fp_src2+1
        pla
        sta fp_src2
        pla
        sta fp_src1+1
        pla
        sta fp_src1
@done:  rts

; =============================================================================
; fp_mod_sub_384: (fp_dst) = ((fp_src1) - (fp_src2)) mod (fp_misc)
; =============================================================================
fp_mod_sub_384:
        jsr fp_sub_384
        lda fp_carry
        beq @done

        ; Underflow: add modulus
        lda fp_src1
        pha
        lda fp_src1+1
        pha
        lda fp_src2
        pha
        lda fp_src2+1
        pha
        lda fp_dst
        sta fp_src1
        lda fp_dst+1
        sta fp_src1+1
        lda fp_misc
        sta fp_src2
        lda fp_misc+1
        sta fp_src2+1
        jsr fp_add_384
        pla
        sta fp_src2+1
        pla
        sta fp_src2
        pla
        sta fp_src1+1
        pla
        sta fp_src1
@done:  rts

; =============================================================================
; fp_mod_reduce_384: reduce 768-bit fp_wide_384 mod (fp_misc) -> fp_r0_384
; Binary long division: for each of 768 bits, shift into remainder
; and conditionally subtract modulus.
; =============================================================================
fp_mod_reduce_384:
        ; Clear 49-byte remainder (48 + 1 overflow byte)
        ldy #48
        lda #0
@clr:   sta fp_rem_384,y
        dey
        bpl @clr

        lda #0
        sta fp_bc_384           ; byte counter in fp_wide_384
        lda #$80
        sta fp_bm_384           ; bit mask

@bitlp:
        ; Shift remainder left 1
        clc
        ldy #48
@shl:   lda fp_rem_384,y
        rol
        sta fp_rem_384,y
        dey
        bpl @shl

        ; OR in next bit from fp_wide_384
        ldy fp_bc_384
        lda fp_wide_384,y
        and fp_bm_384
        beq @nobit
        lda fp_rem_384+48
        ora #1
        sta fp_rem_384+48
@nobit:
        ; Compare remainder with modulus
        lda fp_rem_384          ; overflow byte
        bne @dosub

        ldy #0
@cmplp: lda fp_rem_384+1,y
        cmp (fp_misc),y
        bcc @nosub
        bne @dosub
        iny
        cpy #48
        bne @cmplp
        ; Equal: subtract

@dosub:
        sec
        ldy #47
@sublp: lda fp_rem_384+1,y
        sbc (fp_misc),y
        sta fp_rem_384+1,y
        dey
        bpl @sublp
        lda fp_rem_384
        sbc #0
        sta fp_rem_384

@nosub:
        ; Next bit
        lsr fp_bm_384
        bne @bitlp
        lda #$80
        sta fp_bm_384
        inc fp_bc_384
        lda fp_bc_384
        cmp #96
        bne @bitlp

        ; Copy result
        ldy #0
@cpy:   lda fp_rem_384+1,y
        sta fp_r0_384,y
        iny
        cpy #48
        bne @cpy
        rts

fp_rem_384: !fill 49, 0
fp_bc_384:  !byte 0
fp_bm_384:  !byte 0

; =============================================================================
; fp_mod_mul_384: fp_r0_384 = ((fp_src1) * (fp_src2)) mod (fp_misc)
; =============================================================================
fp_mod_mul_384:
        jsr fp_mul_384
        jsr fp_mod_reduce_384
        rts

; =============================================================================
; fp_mod_inv_384: fp_r0_384 = (fp_src1)^(-1) mod (fp_misc)
; Binary extended GCD algorithm.
; =============================================================================
fp_mod_inv_384:
        ; u = src1, v = mod, x1 = 1, x2 = 0
        lda fp_dst
        pha
        lda fp_dst+1
        pha

        ; Copy u = src1
        lda #<fp_inv_u_384
        sta fp_dst
        lda #>fp_inv_u_384
        sta fp_dst+1
        jsr fp_copy_384

        ; Copy v = mod
        lda fp_misc
        sta fp_src1
        lda fp_misc+1
        sta fp_src1+1
        lda #<fp_inv_v_384
        sta fp_dst
        lda #>fp_inv_v_384
        sta fp_dst+1
        jsr fp_copy_384

        ; x1 = 1
        lda #<fp_inv_x1_384
        sta fp_dst
        lda #>fp_inv_x1_384
        sta fp_dst+1
        jsr fp_zero_384
        lda #1
        sta fp_inv_x1_384+47

        ; x2 = 0
        lda #<fp_inv_x2_384
        sta fp_dst
        lda #>fp_inv_x2_384
        sta fp_dst+1
        jsr fp_zero_384

        pla
        sta fp_dst+1
        pla
        sta fp_dst

@mainlp:
        ; Check u == 1
        lda #<fp_inv_u_384
        sta fp_src1
        lda #>fp_inv_u_384
        sta fp_src1+1
        jsr fp_chk_one_384
        bne +
        jmp @u_one
+
        ; Check v == 1
        lda #<fp_inv_v_384
        sta fp_src1
        lda #>fp_inv_v_384
        sta fp_src1+1
        jsr fp_chk_one_384
        bne +
        jmp @v_one
+

        ; While u is even
@halfu: lda fp_inv_u_384+47
        and #1
        bne @halfv

        lda #<fp_inv_u_384
        sta fp_src1
        lda #>fp_inv_u_384
        sta fp_src1+1
        jsr fp_rshift1_384

        lda fp_inv_x1_384+47
        and #1
        beq @x1ev_nocarry
        ; x1 += mod
        lda #<fp_inv_x1_384
        sta fp_src1
        sta fp_dst
        lda #>fp_inv_x1_384
        sta fp_src1+1
        sta fp_dst+1
        lda fp_misc
        sta fp_src2
        lda fp_misc+1
        sta fp_src2+1
        jsr fp_add_384
        jmp @x1do_shift
@x1ev_nocarry:
        lda #0
        sta fp_carry
@x1do_shift:
        ; x1 >>= 1, with carry from fp_add shifted in as MSB
        lda fp_carry            ; carry from x1+mod (0 or 1)
        lsr                     ; shift into 6502 carry flag
        ldy #0
        ldx #48
@x1sh:  lda fp_inv_x1_384,y
        ror                     ; rotate carry in from left
        sta fp_inv_x1_384,y
        iny
        dex
        bne @x1sh
        jmp @halfu

        ; While v is even
@halfv: lda fp_inv_v_384+47
        and #1
        bne @comp

        lda #<fp_inv_v_384
        sta fp_src1
        lda #>fp_inv_v_384
        sta fp_src1+1
        jsr fp_rshift1_384

        lda fp_inv_x2_384+47
        and #1
        beq @x2ev_nocarry
        lda #<fp_inv_x2_384
        sta fp_src1
        sta fp_dst
        lda #>fp_inv_x2_384
        sta fp_src1+1
        sta fp_dst+1
        lda fp_misc
        sta fp_src2
        lda fp_misc+1
        sta fp_src2+1
        jsr fp_add_384
        jmp @x2do_shift
@x2ev_nocarry:
        lda #0
        sta fp_carry
@x2do_shift:
        ; x2 >>= 1, with carry from fp_add shifted in as MSB
        lda fp_carry
        lsr                     ; into 6502 carry
        ldy #0
        ldx #48
@x2sh:  lda fp_inv_x2_384,y
        ror
        sta fp_inv_x2_384,y
        iny
        dex
        bne @x2sh
        jmp @halfv

@comp:
        ; Compare u vs v
        lda #<fp_inv_u_384
        sta fp_src1
        lda #>fp_inv_u_384
        sta fp_src1+1
        lda #<fp_inv_v_384
        sta fp_src2
        lda #>fp_inv_v_384
        sta fp_src2+1
        jsr fp_cmp_384
        bcc @vbig

        ; u >= v: u -= v, x1 -= x2 mod m
        lda #<fp_inv_u_384
        sta fp_dst
        lda #>fp_inv_u_384
        sta fp_dst+1
        jsr fp_sub_384

        lda #<fp_inv_x1_384
        sta fp_src1
        lda #>fp_inv_x1_384
        sta fp_src1+1
        lda #<fp_inv_x2_384
        sta fp_src2
        lda #>fp_inv_x2_384
        sta fp_src2+1
        lda #<fp_inv_x1_384
        sta fp_dst
        lda #>fp_inv_x1_384
        sta fp_dst+1
        jsr fp_mod_sub_384
        jmp @mainlp

@vbig:
        ; v -= u, x2 -= x1 mod m
        lda #<fp_inv_v_384
        sta fp_src1
        lda #>fp_inv_v_384
        sta fp_src1+1
        lda #<fp_inv_u_384
        sta fp_src2
        lda #>fp_inv_u_384
        sta fp_src2+1
        lda #<fp_inv_v_384
        sta fp_dst
        lda #>fp_inv_v_384
        sta fp_dst+1
        jsr fp_sub_384

        lda #<fp_inv_x2_384
        sta fp_src1
        lda #>fp_inv_x2_384
        sta fp_src1+1
        lda #<fp_inv_x1_384
        sta fp_src2
        lda #>fp_inv_x1_384
        sta fp_src2+1
        lda #<fp_inv_x2_384
        sta fp_dst
        lda #>fp_inv_x2_384
        sta fp_dst+1
        jsr fp_mod_sub_384
        jmp @mainlp

@u_one: ; Result = x1
        ldy #47
@cu:    lda fp_inv_x1_384,y
        sta fp_r0_384,y
        dey
        bpl @cu
        rts

@v_one: ; Result = x2
        ldy #47
@cv:    lda fp_inv_x2_384,y
        sta fp_r0_384,y
        dey
        bpl @cv
        rts

fp_inv_u_384:   !fill 48, 0
fp_inv_v_384:   !fill 48, 0
fp_inv_x1_384:  !fill 48, 0
fp_inv_x2_384:  !fill 48, 0

; =============================================================================
; Working registers (48 bytes each)
; =============================================================================
fp_r0_384:      !fill 48, 0        ; primary result register
fp_r1_384:      !fill 48, 0
fp_r2_384:      !fill 48, 0
fp_r3_384:      !fill 48, 0
