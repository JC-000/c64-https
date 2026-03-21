; =============================================================================
; ecdsa_curve.asm - P-256 curve parameters, point storage, helpers
;
; Imported from c64-aes256-ecdsa for TLS 1.3 certificate verification.
; Test vectors stripped — not needed for verification-only use.
; =============================================================================

; =============================================================================
; P-256 Curve Parameters
; =============================================================================
ec_p:   ; Field prime
        !byte $FF, $FF, $FF, $FF, $00, $00, $00, $01
        !byte $00, $00, $00, $00, $00, $00, $00, $00
        !byte $00, $00, $00, $00, $FF, $FF, $FF, $FF
        !byte $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF
ec_n:   ; Group order
        !byte $FF, $FF, $FF, $FF, $00, $00, $00, $00
        !byte $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF
        !byte $BC, $E6, $FA, $AD, $A7, $17, $9E, $84
        !byte $F3, $B9, $CA, $C2, $FC, $63, $25, $51
ec_a:   ; Coefficient a = p - 3
        !byte $FF, $FF, $FF, $FF, $00, $00, $00, $01
        !byte $00, $00, $00, $00, $00, $00, $00, $00
        !byte $00, $00, $00, $00, $FF, $FF, $FF, $FF
        !byte $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FC
ec_b:   ; Coefficient b
        !byte $5A, $C6, $35, $D8, $AA, $3A, $93, $E7
        !byte $B3, $EB, $BD, $55, $76, $98, $86, $BC
        !byte $65, $1D, $06, $B0, $CC, $53, $B0, $F6
        !byte $3B, $CE, $3C, $3E, $27, $D2, $60, $4B
ec_gx:  ; Generator x
        !byte $6B, $17, $D1, $F2, $E1, $2C, $42, $47
        !byte $F8, $BC, $E6, $E5, $63, $A4, $40, $F2
        !byte $77, $03, $7D, $81, $2D, $EB, $33, $A0
        !byte $F4, $A1, $39, $45, $D8, $98, $C2, $96
ec_gy:  ; Generator y
        !byte $4F, $E3, $42, $E2, $FE, $1A, $7F, $9B
        !byte $8E, $E7, $EB, $4A, $7C, $0F, $9E, $16
        !byte $2B, $CE, $33, $57, $6B, $31, $5E, $CE
        !byte $CB, $B6, $40, $68, $37, $BF, $51, $F5

; =============================================================================
; Elliptic Curve Point Operations (Jacobian Coordinates)
; =============================================================================
; Point = (X,Y,Z) each 32 bytes = 96 bytes total. Affine = X/Z^2, Y/Z^3.
; Point at infinity: Z = 0.
; All field arithmetic is mod ec_p.

; --- Point storage ---
ec_p1:  !fill 96, 0            ; working point (Jacobian)
ec_p2:  !fill 96, 0            ; second point (affine X,Y only used)
ec_p3:  !fill 96, 0            ; result point (Jacobian)

; --- Temporaries for point math (mod p) ---
ec_t1:  !fill 32, 0
ec_t2:  !fill 32, 0
ec_t3:  !fill 32, 0
ec_t4:  !fill 32, 0
ec_t5:  !fill 32, 0
ec_t6:  !fill 32, 0

; --- Helper: set fp_misc = ec_p ---
ec_set_modp:
        lda #<ec_p
        sta fp_misc
        lda #>ec_p
        sta fp_misc+1
        rts

; --- Helper: set fp_misc = ec_n ---
ec_set_modn:
        lda #<ec_n
        sta fp_misc
        lda #>ec_n
        sta fp_misc+1
        rts

; --- Helper: modular multiply mod p, result -> (fp_dst) ---
; fp_src1, fp_src2 already set. Result goes through fp_r0 then copied to dst.
ec_mulp:
        jsr ec_set_modp
        jsr fp_mod_mul          ; result in fp_r0
        ; Copy fp_r0 -> (fp_dst)
        lda fp_src1
        pha
        lda fp_src1+1
        pha
        lda #<fp_r0
        sta fp_src1
        lda #>fp_r0
        sta fp_src1+1
        jsr fp_copy
        pla
        sta fp_src1+1
        pla
        sta fp_src1
        rts
