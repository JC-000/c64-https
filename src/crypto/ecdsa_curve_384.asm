; =============================================================================
; ecdsa_curve_384.asm - P-384 curve parameters, point storage, helpers
; =============================================================================

; =============================================================================
; P-384 Curve Parameters (48 bytes each, big-endian)
; =============================================================================

; P-384 field prime p
ec_p_384:
        !byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF
        !byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FE
        !byte $FF,$FF,$FF,$FF,$00,$00,$00,$00,$00,$00,$00,$00,$FF,$FF,$FF,$FF

; P-384 group order n
ec_n_384:
        !byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF
        !byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$C7,$63,$4D,$81,$F4,$37,$2D,$DF
        !byte $58,$1A,$0D,$B2,$48,$B0,$A7,$7A,$EC,$EC,$19,$6A,$CC,$C5,$29,$73

; P-384 coefficient a = p - 3
ec_a_384:
        !byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF
        !byte $FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FF,$FE
        !byte $FF,$FF,$FF,$FF,$00,$00,$00,$00,$00,$00,$00,$00,$FF,$FF,$FF,$FC

; P-384 coefficient b
ec_b_384:
        !byte $B3,$31,$2F,$A7,$E2,$3E,$E7,$E4,$98,$8E,$05,$6B,$E3,$F8,$2D,$19
        !byte $18,$1D,$9C,$6E,$FE,$81,$41,$12,$03,$14,$08,$8F,$50,$13,$87,$5A
        !byte $C6,$56,$39,$8D,$8A,$2E,$D1,$9D,$2A,$85,$C8,$ED,$D3,$EC,$2A,$EF

; P-384 generator point Gx
ec_gx_384:
        !byte $AA,$87,$CA,$22,$BE,$8B,$05,$37,$8E,$B1,$C7,$1E,$F3,$20,$AD,$74
        !byte $6E,$1D,$3B,$62,$8B,$A7,$9B,$98,$59,$F7,$41,$E0,$82,$54,$2A,$38
        !byte $55,$02,$F2,$5D,$BF,$55,$29,$6C,$3A,$54,$5E,$38,$72,$76,$0A,$B7

; P-384 generator point Gy
ec_gy_384:
        !byte $36,$17,$DE,$4A,$96,$26,$2C,$6F,$5D,$9E,$98,$BF,$92,$92,$DC,$29
        !byte $F8,$F4,$1D,$BD,$28,$9A,$14,$7C,$E9,$DA,$31,$13,$B5,$F0,$B8,$C0
        !byte $0A,$60,$B1,$CE,$1D,$7E,$81,$9D,$7A,$43,$1D,$7C,$90,$EA,$0E,$5F

; =============================================================================
; Point storage (144 bytes each = 3 x 48 Jacobian coordinates)
; =============================================================================
ec_p1_384:  !fill 144, 0           ; working point (Jacobian)
ec_p2_384:  !fill 144, 0           ; second point (affine X,Y only used)
ec_p3_384:  !fill 144, 0           ; result point (Jacobian)

; =============================================================================
; Temporaries for point math (48 bytes each)
; =============================================================================
ec_t1_384:  !fill 48, 0
ec_t2_384:  !fill 48, 0
ec_t3_384:  !fill 48, 0
ec_t4_384:  !fill 48, 0
ec_t5_384:  !fill 48, 0
ec_t6_384:  !fill 48, 0

; =============================================================================
; Helper: set fp_misc = ec_p_384
; =============================================================================
ec_set_modp_384:
        lda #<ec_p_384
        sta fp_misc
        lda #>ec_p_384
        sta fp_misc+1
        rts

; =============================================================================
; Helper: set fp_misc = ec_n_384
; =============================================================================
ec_set_modn_384:
        lda #<ec_n_384
        sta fp_misc
        lda #>ec_n_384
        sta fp_misc+1
        rts

; =============================================================================
; ec_mulp_384: modular multiply mod p_384, result -> (fp_dst)
; fp_src1, fp_src2 already set. Result goes through fp_r0_384 then copied.
; =============================================================================
ec_mulp_384:
        jsr ec_set_modp_384
        jsr fp_mod_mul_384      ; result in fp_r0_384
        ; Copy fp_r0_384 -> (fp_dst)
        lda fp_src1
        pha
        lda fp_src1+1
        pha
        lda #<fp_r0_384
        sta fp_src1
        lda #>fp_r0_384
        sta fp_src1+1
        jsr fp_copy_384
        pla
        sta fp_src1+1
        pla
        sta fp_src1
        rts
