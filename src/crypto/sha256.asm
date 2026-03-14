; =============================================================================
; sha256.asm - SHA-256 hash: init, update, final, process_block, H/K constants
; =============================================================================
; Adapted from c64-aes256-ecdsa for c64-https (TLS 1.3)
;
; ZP equates (sha_temp1, sha_temp2, sha256_round) are in constants.asm
; Data labels (sha256_h0-h7, sha_a-sha_h, sha_temp3, sha_t1, sha_t2,
;              sha256_block, sha256_w, sha256_hash, sha256_len,
;              input_buffer, input_length) are in data.asm
; =============================================================================

; =============================================================================
; SHA-256 Implementation
; =============================================================================

; SHA-256 initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
sha256_h0_init:
	!byte $6a, $09, $e6, $67
sha256_h1_init:
	!byte $bb, $67, $ae, $85
sha256_h2_init:
	!byte $3c, $6e, $f3, $72
sha256_h3_init:
	!byte $a5, $4f, $f5, $3a
sha256_h4_init:
	!byte $51, $0e, $52, $7f
sha256_h5_init:
	!byte $9b, $05, $68, $8c
sha256_h6_init:
	!byte $1f, $83, $d9, $ab
sha256_h7_init:
	!byte $5b, $e0, $cd, $19

; SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
sha256_k:
	!byte $42, $8a, $2f, $98, $71, $37, $44, $91, $b5, $c0, $fb, $cf, $e9, $b5, $db, $a5
	!byte $39, $56, $c2, $5b, $59, $f1, $11, $f1, $92, $3f, $82, $a4, $ab, $1c, $5e, $d5
	!byte $d8, $07, $aa, $98, $12, $83, $5b, $01, $24, $31, $85, $be, $55, $0c, $7d, $c3
	!byte $72, $be, $5d, $74, $80, $de, $b1, $fe, $9b, $dc, $06, $a7, $c1, $9b, $f1, $74
	!byte $e4, $9b, $69, $c1, $ef, $be, $47, $86, $0f, $c1, $9d, $c6, $24, $0c, $a1, $cc
	!byte $2d, $e9, $2c, $6f, $4a, $74, $84, $aa, $5c, $b0, $a9, $dc, $76, $f9, $88, $da
	!byte $98, $3e, $51, $52, $a8, $31, $c6, $6d, $b0, $03, $27, $c8, $bf, $59, $7f, $c7
	!byte $c6, $e0, $0b, $f3, $d5, $a7, $91, $47, $06, $ca, $63, $51, $14, $29, $29, $67
	!byte $27, $b7, $0a, $85, $2e, $1b, $21, $38, $4d, $2c, $6d, $fc, $53, $38, $0d, $13
	!byte $65, $0a, $73, $54, $76, $6a, $0a, $bb, $81, $c2, $c9, $2e, $92, $72, $2c, $85
	!byte $a2, $bf, $e8, $a1, $a8, $1a, $66, $4b, $c2, $4b, $8b, $70, $c7, $6c, $51, $a3
	!byte $d1, $92, $e8, $19, $d6, $99, $06, $24, $f4, $0e, $35, $85, $10, $6a, $a0, $70
	!byte $19, $a4, $c1, $16, $1e, $37, $6c, $08, $27, $48, $77, $4c, $34, $b0, $bc, $b5
	!byte $39, $1c, $0c, $b3, $4e, $d8, $aa, $4a, $5b, $9c, $ca, $4f, $68, $2e, $6f, $f3
	!byte $74, $8f, $82, $ee, $78, $a5, $63, $6f, $84, $c8, $78, $14, $8c, $c7, $02, $08
	!byte $90, $be, $ff, $fa, $a4, $50, $6c, $eb, $be, $f9, $a3, $f7, $c6, $71, $78, $f2

; =============================================================================
; sha256_init - initialize hash state
; =============================================================================
sha256_init:
	; copy initial hash values to working state
	ldx #0
@copy_h:
	lda sha256_h0_init,x
	sta sha256_h0,x
	lda sha256_h1_init,x
	sta sha256_h1,x
	lda sha256_h2_init,x
	sta sha256_h2,x
	lda sha256_h3_init,x
	sta sha256_h3,x
	lda sha256_h4_init,x
	sta sha256_h4,x
	lda sha256_h5_init,x
	sta sha256_h5,x
	lda sha256_h6_init,x
	sta sha256_h6,x
	lda sha256_h7_init,x
	sta sha256_h7,x
	inx
	cpx #4
	bne @copy_h

	; clear message length
	lda #0
	sta sha256_len
	sta sha256_len+1
	rts

; =============================================================================
; sha256_update - process input_buffer with input_length bytes
; =============================================================================
sha256_update:
	; store message length in bits (length * 8)
	lda input_length
	sta sha256_len
	lda #0
	sta sha256_len+1

	; multiply by 8 (shift left 3)
	asl sha256_len
	rol sha256_len+1
	asl sha256_len
	rol sha256_len+1
	asl sha256_len
	rol sha256_len+1

	; copy input to message block and pad
	; clear block first
	ldx #0
	lda #0
@clear_block:
	sta sha256_block,x
	inx
	cpx #64
	bne @clear_block

	; copy input data
	ldx #0
@copy_input:
	cpx input_length
	beq @add_padding
	lda input_buffer,x
	sta sha256_block,x
	inx
	cpx #64
	bcc @copy_input

@add_padding:
	; add 0x80 byte after message
	lda #$80
	sta sha256_block,x

	; if message is 55 bytes or less, length fits in this block
	; otherwise we'd need two blocks (not implemented for simplicity)
	lda input_length
	cmp #56
	bcs @need_extra_block

	; add length at end of block (big endian, 64-bit)
	; we only support up to 255 bytes, so just use low 16 bits
	lda sha256_len+1
	sta sha256_block+62
	lda sha256_len
	sta sha256_block+63

	; process the block
	jsr sha256_process_block
	rts

@need_extra_block:
	; for messages >= 56 bytes, need two blocks
	; process first block (message + padding)
	jsr sha256_process_block

	; clear second block
	ldx #0
	lda #0
@clear_block2:
	sta sha256_block,x
	inx
	cpx #64
	bne @clear_block2

	; add length at end
	lda sha256_len+1
	sta sha256_block+62
	lda sha256_len
	sta sha256_block+63

	; process second block
	jsr sha256_process_block
	rts

; =============================================================================
; sha256_final - copy hash state to output
; =============================================================================
sha256_final:
	; copy hash values to output (big endian)
	ldx #0
@copy:
	lda sha256_h0,x
	sta sha256_hash,x
	lda sha256_h1,x
	sta sha256_hash+4,x
	lda sha256_h2,x
	sta sha256_hash+8,x
	lda sha256_h3,x
	sta sha256_hash+12,x
	lda sha256_h4,x
	sta sha256_hash+16,x
	lda sha256_h5,x
	sta sha256_hash+20,x
	lda sha256_h6,x
	sta sha256_hash+24,x
	lda sha256_h7,x
	sta sha256_hash+28,x
	inx
	cpx #4
	bne @copy
	rts

; =============================================================================
; sha256_process_block - process one 64-byte block
; =============================================================================
sha256_process_block:
	; prepare message schedule W[0..63]
	; W[0..15] = block words (big endian)
	ldx #0
@copy_w:
	lda sha256_block,x
	sta sha256_w,x
	inx
	cpx #64
	bne @copy_w

	; W[16..63] = computed from previous words
	lda #16
	sta sha256_round

@compute_w:
	; w[i] = sig1(w[i-2]) + w[i-7] + sig0(w[i-15]) + w[i-16]

	; get w[i-2] and compute sig1
	lda sha256_round
	sec
	sbc #2
	asl
	asl
	tax
	jsr sha256_load_word    ; load w[i-2] to sha_temp1
	jsr sha256_sig1         ; result in sha_temp1

	; add w[i-7]
	lda sha256_round
	sec
	sbc #7
	asl
	asl
	tax
	jsr sha256_load_word_to_temp2
	jsr sha256_add_temp2_to_temp1

	; add sig0(w[i-15])
	; Save running sum (sig1(w[i-2]) + w[i-7]) before load_word overwrites it
	ldx #0
@save_sum:
	lda sha_temp1,x
	sta sha_t1,x
	inx
	cpx #4
	bne @save_sum

	lda sha256_round
	sec
	sbc #15
	asl
	asl
	tax
	jsr sha256_load_word    ; sha_temp1 = w[i-15]
	jsr sha256_sig0         ; sha_temp1 = sig0(w[i-15])

	; add saved running sum back
	ldx #0
@add_sum:
	lda sha_t1,x
	sta sha_temp2,x
	inx
	cpx #4
	bne @add_sum
	jsr sha256_add_temp2_to_temp1

	; add w[i-16]
	lda sha256_round
	sec
	sbc #16
	asl
	asl
	tax
	jsr sha256_load_word_to_temp2
	jsr sha256_add_temp2_to_temp1

	; store result as w[i]
	lda sha256_round
	asl
	asl
	tax
	ldy #0
@store_w:
	lda sha_temp1,y
	sta sha256_w,x
	inx
	iny
	cpy #4
	bne @store_w

	inc sha256_round
	lda sha256_round
	cmp #64
	bcs @w_done
	jmp @compute_w
@w_done:

	; initialize working variables
	ldx #0
@init_working:
	lda sha256_h0,x
	sta sha_a,x
	lda sha256_h1,x
	sta sha_b,x
	lda sha256_h2,x
	sta sha_c,x
	lda sha256_h3,x
	sta sha_d,x
	lda sha256_h4,x
	sta sha_e,x
	lda sha256_h5,x
	sta sha_f,x
	lda sha256_h6,x
	sta sha_g,x
	lda sha256_h7,x
	sta sha_h,x
	inx
	cpx #4
	bne @init_working

	; main compression loop (64 rounds)
	lda #0
	sta sha256_round

@main_loop:
	; T1 = h + Sig1(e) + Ch(e,f,g) + k[i] + w[i]
	; T2 = Sig0(a) + Maj(a,b,c)
	; h = g, g = f, f = e, e = d + T1, d = c, c = b, b = a, a = T1 + T2

	; compute Sig1(e)
	ldx #0
@load_e:
	lda sha_e,x
	sta sha_temp1,x
	inx
	cpx #4
	bne @load_e
	jsr sha256_big_sig1

	; add h
	ldx #0
@add_h:
	lda sha_h,x
	sta sha_temp2,x
	inx
	cpx #4
	bne @add_h
	jsr sha256_add_temp2_to_temp1

	; add Ch(e,f,g)
	jsr sha256_ch
	jsr sha256_add_temp2_to_temp1

	; add k[i]
	lda sha256_round
	asl
	asl
	tax
	ldy #0
@add_k:
	lda sha256_k,x
	sta sha_temp2,y
	inx
	iny
	cpy #4
	bne @add_k
	jsr sha256_add_temp2_to_temp1

	; add w[i]
	lda sha256_round
	asl
	asl
	tax
	ldy #0
@add_w:
	lda sha256_w,x
	sta sha_temp2,y
	inx
	iny
	cpy #4
	bne @add_w
	jsr sha256_add_temp2_to_temp1

	; save T1
	ldx #0
@save_t1:
	lda sha_temp1,x
	sta sha_t1,x
	inx
	cpx #4
	bne @save_t1

	; compute Sig0(a)
	ldx #0
@load_a:
	lda sha_a,x
	sta sha_temp1,x
	inx
	cpx #4
	bne @load_a
	jsr sha256_big_sig0

	; add Maj(a,b,c)
	jsr sha256_maj
	jsr sha256_add_temp2_to_temp1

	; save T2 to sha_t2
	ldx #0
@save_t2:
	lda sha_temp1,x
	sta sha_t2,x
	inx
	cpx #4
	bne @save_t2

	; compute e_new = d + T1 into sha_temp1 (before shift overwrites d)
	clc
	lda sha_d+3
	adc sha_t1+3
	sta sha_temp1+3
	lda sha_d+2
	adc sha_t1+2
	sta sha_temp1+2
	lda sha_d+1
	adc sha_t1+1
	sta sha_temp1+1
	lda sha_d
	adc sha_t1
	sta sha_temp1

	; block shift: h=g, g=f, f=e, d=c, c=b, b=a (28 bytes backward)
	ldy #27
@shift:
	lda sha_a,y
	sta sha_a+4,y
	dey
	bpl @shift

	; write e_new
	ldx #0
@write_e:
	lda sha_temp1,x
	sta sha_e,x
	inx
	cpx #4
	bne @write_e

	; a = T1 + T2
	clc
	lda sha_t1+3
	adc sha_t2+3
	sta sha_a+3
	lda sha_t1+2
	adc sha_t2+2
	sta sha_a+2
	lda sha_t1+1
	adc sha_t2+1
	sta sha_a+1
	lda sha_t1
	adc sha_t2
	sta sha_a

	inc sha256_round
	lda sha256_round
	cmp #64
	beq @done_rounds
	jmp @main_loop

@done_rounds:
	; add working variables to hash state
	jsr sha256_add_to_hash
	rts

; =============================================================================
; sha256_load_word - load 4 bytes from sha256_w+X to sha_temp1
; =============================================================================
sha256_load_word:
	ldy #0
@loop:
	lda sha256_w,x
	sta sha_temp1,y
	inx
	iny
	cpy #4
	bne @loop
	rts

; =============================================================================
; sha256_load_word_to_temp2 - load 4 bytes from sha256_w+X to sha_temp2
; =============================================================================
sha256_load_word_to_temp2:
	ldy #0
@loop:
	lda sha256_w,x
	sta sha_temp2,y
	inx
	iny
	cpy #4
	bne @loop
	rts

; =============================================================================
; sha256_add_temp2_to_temp1 - 32-bit addition
; =============================================================================
sha256_add_temp2_to_temp1:
	clc
	lda sha_temp1+3
	adc sha_temp2+3
	sta sha_temp1+3
	lda sha_temp1+2
	adc sha_temp2+2
	sta sha_temp1+2
	lda sha_temp1+1
	adc sha_temp2+1
	sta sha_temp1+1
	lda sha_temp1
	adc sha_temp2
	sta sha_temp1
	rts

; =============================================================================
; sha256_sig0 - lowercase sigma 0: rotr7 ^ rotr18 ^ shr3
; =============================================================================
sha256_sig0:
	; save input
	ldx #0
@save:
	lda sha_temp1,x
	sta sha_temp3,x
	inx
	cpx #4
	bne @save

	; rotr7
	jsr sha256_rotr7
	ldx #0
@save_r7:
	lda sha_temp1,x
	sta sha_temp2,x
	lda sha_temp3,x
	sta sha_temp1,x
	inx
	cpx #4
	bne @save_r7

	; rotr18
	jsr sha256_rotr18
	ldx #0
@xor_r18:
	lda sha_temp1,x
	eor sha_temp2,x
	sta sha_temp2,x
	lda sha_temp3,x
	sta sha_temp1,x
	inx
	cpx #4
	bne @xor_r18

	; shr3
	jsr sha256_shr3
	ldx #0
@xor_final:
	lda sha_temp1,x
	eor sha_temp2,x
	sta sha_temp1,x
	inx
	cpx #4
	bne @xor_final
	rts

; =============================================================================
; sha256_sig1 - lowercase sigma 1: rotr17 ^ rotr19 ^ shr10
; =============================================================================
sha256_sig1:
	ldx #0
@save:
	lda sha_temp1,x
	sta sha_temp3,x
	inx
	cpx #4
	bne @save

	jsr sha256_rotr17
	ldx #0
@save_r17:
	lda sha_temp1,x
	sta sha_temp2,x
	lda sha_temp3,x
	sta sha_temp1,x
	inx
	cpx #4
	bne @save_r17

	jsr sha256_rotr19
	ldx #0
@xor_r19:
	lda sha_temp1,x
	eor sha_temp2,x
	sta sha_temp2,x
	lda sha_temp3,x
	sta sha_temp1,x
	inx
	cpx #4
	bne @xor_r19

	jsr sha256_shr10
	ldx #0
@xor_final:
	lda sha_temp1,x
	eor sha_temp2,x
	sta sha_temp1,x
	inx
	cpx #4
	bne @xor_final
	rts

; =============================================================================
; sha256_big_sig0 - uppercase Sigma 0: rotr2 ^ rotr13 ^ rotr22
; =============================================================================
sha256_big_sig0:
	ldx #0
@save:
	lda sha_temp1,x
	sta sha_temp3,x
	inx
	cpx #4
	bne @save

	jsr sha256_rotr2
	ldx #0
@save_r2:
	lda sha_temp1,x
	sta sha_temp2,x
	lda sha_temp3,x
	sta sha_temp1,x
	inx
	cpx #4
	bne @save_r2

	jsr sha256_rotr13
	ldx #0
@xor_r13:
	lda sha_temp1,x
	eor sha_temp2,x
	sta sha_temp2,x
	lda sha_temp3,x
	sta sha_temp1,x
	inx
	cpx #4
	bne @xor_r13

	jsr sha256_rotr22
	ldx #0
@xor_final:
	lda sha_temp1,x
	eor sha_temp2,x
	sta sha_temp1,x
	inx
	cpx #4
	bne @xor_final
	rts

; =============================================================================
; sha256_big_sig1 - uppercase Sigma 1: rotr6 ^ rotr11 ^ rotr25
; =============================================================================
sha256_big_sig1:
	ldx #0
@save:
	lda sha_temp1,x
	sta sha_temp3,x
	inx
	cpx #4
	bne @save

	jsr sha256_rotr6
	ldx #0
@save_r6:
	lda sha_temp1,x
	sta sha_temp2,x
	lda sha_temp3,x
	sta sha_temp1,x
	inx
	cpx #4
	bne @save_r6

	jsr sha256_rotr11
	ldx #0
@xor_r11:
	lda sha_temp1,x
	eor sha_temp2,x
	sta sha_temp2,x
	lda sha_temp3,x
	sta sha_temp1,x
	inx
	cpx #4
	bne @xor_r11

	jsr sha256_rotr25
	ldx #0
@xor_final:
	lda sha_temp1,x
	eor sha_temp2,x
	sta sha_temp1,x
	inx
	cpx #4
	bne @xor_final
	rts

; =============================================================================
; sha256_ch - Ch(e,f,g) = (e AND f) XOR (NOT e AND g), result in sha_temp2
; =============================================================================
sha256_ch:
	ldx #0
@loop:
	lda sha_e,x
	and sha_f,x
	sta sha_temp2,x
	lda sha_e,x
	eor #$ff
	and sha_g,x
	eor sha_temp2,x
	sta sha_temp2,x
	inx
	cpx #4
	bne @loop
	rts

; =============================================================================
; sha256_maj - Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c), result in sha_temp2
; =============================================================================
sha256_maj:
	ldx #0
@loop:
	lda sha_a,x
	and sha_b,x
	sta sha_temp2,x
	lda sha_a,x
	and sha_c,x
	eor sha_temp2,x
	sta sha_temp2,x
	lda sha_b,x
	and sha_c,x
	eor sha_temp2,x
	sta sha_temp2,x
	inx
	cpx #4
	bne @loop
	rts


; =============================================================================
; sha256_add_to_hash - add working variables to hash state
; =============================================================================
sha256_add_to_hash:
	; h0 += a
	clc
	lda sha256_h0+3
	adc sha_a+3
	sta sha256_h0+3
	lda sha256_h0+2
	adc sha_a+2
	sta sha256_h0+2
	lda sha256_h0+1
	adc sha_a+1
	sta sha256_h0+1
	lda sha256_h0
	adc sha_a
	sta sha256_h0

	; h1 += b
	clc
	lda sha256_h1+3
	adc sha_b+3
	sta sha256_h1+3
	lda sha256_h1+2
	adc sha_b+2
	sta sha256_h1+2
	lda sha256_h1+1
	adc sha_b+1
	sta sha256_h1+1
	lda sha256_h1
	adc sha_b
	sta sha256_h1

	; h2 += c
	clc
	lda sha256_h2+3
	adc sha_c+3
	sta sha256_h2+3
	lda sha256_h2+2
	adc sha_c+2
	sta sha256_h2+2
	lda sha256_h2+1
	adc sha_c+1
	sta sha256_h2+1
	lda sha256_h2
	adc sha_c
	sta sha256_h2

	; h3 += d
	clc
	lda sha256_h3+3
	adc sha_d+3
	sta sha256_h3+3
	lda sha256_h3+2
	adc sha_d+2
	sta sha256_h3+2
	lda sha256_h3+1
	adc sha_d+1
	sta sha256_h3+1
	lda sha256_h3
	adc sha_d
	sta sha256_h3

	; h4 += e
	clc
	lda sha256_h4+3
	adc sha_e+3
	sta sha256_h4+3
	lda sha256_h4+2
	adc sha_e+2
	sta sha256_h4+2
	lda sha256_h4+1
	adc sha_e+1
	sta sha256_h4+1
	lda sha256_h4
	adc sha_e
	sta sha256_h4

	; h5 += f
	clc
	lda sha256_h5+3
	adc sha_f+3
	sta sha256_h5+3
	lda sha256_h5+2
	adc sha_f+2
	sta sha256_h5+2
	lda sha256_h5+1
	adc sha_f+1
	sta sha256_h5+1
	lda sha256_h5
	adc sha_f
	sta sha256_h5

	; h6 += g
	clc
	lda sha256_h6+3
	adc sha_g+3
	sta sha256_h6+3
	lda sha256_h6+2
	adc sha_g+2
	sta sha256_h6+2
	lda sha256_h6+1
	adc sha_g+1
	sta sha256_h6+1
	lda sha256_h6
	adc sha_g
	sta sha256_h6

	; h7 += h
	clc
	lda sha256_h7+3
	adc sha_h+3
	sta sha256_h7+3
	lda sha256_h7+2
	adc sha_h+2
	sta sha256_h7+2
	lda sha256_h7+1
	adc sha_h+1
	sta sha256_h7+1
	lda sha256_h7
	adc sha_h
	sta sha256_h7
	rts

; =============================================================================
; Rotation/shift primitives
; =============================================================================

; rotate sha_temp1 right by 1 bit
sha256_rotr1:
	lsr sha_temp1
	ror sha_temp1+1
	ror sha_temp1+2
	ror sha_temp1+3
	bcc +
	lda sha_temp1
	ora #$80
	sta sha_temp1
+	rts

; rotate sha_temp1 left by 1 bit
sha256_rotl1:
	asl sha_temp1+3
	rol sha_temp1+2
	rol sha_temp1+1
	rol sha_temp1
	bcc +
	lda sha_temp1+3
	ora #$01
	sta sha_temp1+3
+	rts

; rotate sha_temp1 right by 8: [B0 B1 B2 B3] -> [B3 B0 B1 B2]
sha256_rotr8:
	lda sha_temp1+3
	pha
	lda sha_temp1+2
	sta sha_temp1+3
	lda sha_temp1+1
	sta sha_temp1+2
	lda sha_temp1
	sta sha_temp1+1
	pla
	sta sha_temp1
	rts

; =============================================================================
; Rotation functions - decomposed into byte swaps + small bit rotates
; =============================================================================

; rotr2 = 2x rotr1
sha256_rotr2:
	jsr sha256_rotr1
	jmp sha256_rotr1

; rotr6 = rotr8 + rotl2
sha256_rotr6:
	jsr sha256_rotr8
	jsr sha256_rotl1
	jmp sha256_rotl1

; rotr7 = rotr8 + rotl1
sha256_rotr7:
	jsr sha256_rotr8
	jmp sha256_rotl1

; rotr11 = rotr8 + rotr3
sha256_rotr11:
	jsr sha256_rotr8
	jsr sha256_rotr1
	jsr sha256_rotr1
	jmp sha256_rotr1

; rotr13 = 2x rotr8 + rotl3
sha256_rotr13:
	jsr sha256_rotr8
	jsr sha256_rotr8
	jsr sha256_rotl1
	jsr sha256_rotl1
	jmp sha256_rotl1

; rotr17 = 2x rotr8 + rotr1
sha256_rotr17:
	jsr sha256_rotr8
	jsr sha256_rotr8
	jmp sha256_rotr1

; rotr18 = 2x rotr8 + rotr2
sha256_rotr18:
	jsr sha256_rotr8
	jsr sha256_rotr8
	jsr sha256_rotr1
	jmp sha256_rotr1

; rotr19 = 2x rotr8 + rotr3
sha256_rotr19:
	jsr sha256_rotr8
	jsr sha256_rotr8
	jsr sha256_rotr1
	jsr sha256_rotr1
	jmp sha256_rotr1

; rotr22 = 3x rotr8 + rotl2
sha256_rotr22:
	jsr sha256_rotr8
	jsr sha256_rotr8
	jsr sha256_rotr8
	jsr sha256_rotl1
	jmp sha256_rotl1

; rotr25 = 3x rotr8 + rotr1
sha256_rotr25:
	jsr sha256_rotr8
	jsr sha256_rotr8
	jsr sha256_rotr8
	jmp sha256_rotr1

; =============================================================================
; Shift right functions
; =============================================================================

; shr3 = 3x shr1
sha256_shr3:
	lsr sha_temp1
	ror sha_temp1+1
	ror sha_temp1+2
	ror sha_temp1+3
	lsr sha_temp1
	ror sha_temp1+1
	ror sha_temp1+2
	ror sha_temp1+3
	lsr sha_temp1
	ror sha_temp1+1
	ror sha_temp1+2
	ror sha_temp1+3
	rts

; shr10 = shr8 (byte shift with zero fill) + shr2
sha256_shr10:
	; shr8: [B0 B1 B2 B3] -> [00 B0 B1 B2]
	lda sha_temp1+2
	sta sha_temp1+3
	lda sha_temp1+1
	sta sha_temp1+2
	lda sha_temp1
	sta sha_temp1+1
	lda #0
	sta sha_temp1
	; shr2
	lsr sha_temp1+1
	ror sha_temp1+2
	ror sha_temp1+3
	lsr sha_temp1+1
	ror sha_temp1+2
	ror sha_temp1+3
	rts
