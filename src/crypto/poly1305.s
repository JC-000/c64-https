; poly1305.s — Poly1305 MAC
; Converted from ACME to ca65 in Phase 3 Batch A.
;
; 130-bit modular arithmetic using quarter-square lookup table for fast
; 8x8->16-bit byte multiplication.
;
; Accumulator h: 17 bytes (136 bits, room for carries in 130-bit range)
; Key r: 16 bytes (clamped per RFC 7539)
; Key s: 16 bytes (added to final result)

.include "constants.inc"

; --- External data (data.asm) ---
.import sqtab_lo, sqtab_hi
.import poly_h, poly_r, poly_s, poly_product, poly1305_tag
.import aead_scratch

; --- poly_prod_lo / poly_prod_hi ownership (c64-lib-contract v0.9.1
;     "adopter-private buffer" rule) ---
;
; These two bytes are the a*b -> 16-bit output of the §8.3 `ct_mul_8x8`
; body below, and ordinary scratch for anything else that wants a 16-bit
; product slot. Exactly ONE module in the link may define them, and every
; writer and reader must agree on which — they are a rendezvous, not
; private state, so a second copy is not a duplicate-symbol error but a
; silent wrong answer.
;
; Under USE_NISTCURVES_ONCHIP the owner is the sibling's
; `mul_8x8_onchip.o`, and it must be: from libs/nistcurves v0.10.0 that
; object defines poly_prod_lo/hi OUTSIDE the SHARED_CT_MUL_8X8 gate,
; because its own `fp_sqr` diagonal-squaring path writes them
; independently of ct_mul_8x8 (upstream's comment at
; libs/nistcurves/src/mul_8x8.s:207-222). Its `og_common` row generator
; then does `jsr ct_mul_8x8` — resolving to the body below — and reads
; the result back out of poly_prod_lo/hi. If this file kept its own pair,
; og_common would read two zero bytes on every product and every
; on-chip-generated multiply row would be wrong, with no link diagnostic
; anywhere. So we import instead: one pair of bytes, in
; LIB_NISTCURVES_MUL_CODE, written and read by both sides.
;
; Under every other profile the sibling's mul_8x8 object is dropped from
; the archive entirely, nothing else defines them, and this file owns
; them as before.
.ifdef USE_NISTCURVES_ONCHIP
.import poly_prod_lo
.import poly_prod_hi
.endif

; --- Exports ---
.export poly1305_init
.export poly1305_clamp
.export sqtab_init
.ifndef USE_NISTCURVES_ONCHIP
.export poly_prod_lo
.export poly_prod_hi
.endif
.export mul_8x8
.export poly1305_multiply
.export poly1305_reduce
.export poly1305_block
.export poly1305_update
.export poly1305_final

; =============================================================================
; Scratch / BSS
; =============================================================================
.segment "CRYPTO_BSS"

.ifndef USE_NISTCURVES_ONCHIP
poly_prod_lo:   .res 1
poly_prod_hi:   .res 1
.endif

mul_a:          .res 1
mul_b:          .res 1
mul_s_pg:       .res 1

; Temporaries for sqtab_init
sq_acc:         .res 3          ; 24-bit accumulator for i^2
sq_sh:          .res 3          ; 24-bit shifted result (i^2 / 4)
sq_ad:          .res 2          ; 16-bit addition term (2i+1)
sq_i:           .res 2          ; 16-bit index counter (0..511)

; =============================================================================
; Code
; =============================================================================
.segment "CRYPTO_CODE"

; =============================================================================
; poly1305_init - Initialize Poly1305 state
;
; Input: 32-byte one-time key at poly_r (first 16 bytes) and poly_s (next 16)
;        Caller must write the OTK: first 16 bytes -> poly_r, next 16 -> poly_s
;
; Operations:
;   1. Clamp r
;   2. Zero accumulator h
;   3. Build quarter-square multiply table
;
; Clobbers: A, X, Y
; =============================================================================
poly1305_init:
        ; 1. Clamp r per RFC 7539 S2.5
        jsr poly1305_clamp

        ; 2. Zero accumulator (17 bytes)
        ldx #16
        lda #0
@zero_h:
        sta poly_h,x
        dex
        bpl @zero_h

        ; 3. Build quarter-square table
        jsr sqtab_init
        rts

; =============================================================================
; poly1305_clamp - Clamp r per RFC 7539
;
; Clear top 4 bits of bytes 3, 7, 11, 15
; Clear bottom 2 bits of bytes 4, 8, 12
; =============================================================================
poly1305_clamp:
        ; Clear top 4 bits of r[3], r[7], r[11], r[15]
        lda poly_r+3
        and #$0f
        sta poly_r+3
        lda poly_r+7
        and #$0f
        sta poly_r+7
        lda poly_r+11
        and #$0f
        sta poly_r+11
        lda poly_r+15
        and #$0f
        sta poly_r+15

        ; Clear bottom 2 bits of r[4], r[8], r[12]
        lda poly_r+4
        and #$fc
        sta poly_r+4
        lda poly_r+8
        and #$fc
        sta poly_r+8
        lda poly_r+12
        and #$fc
        sta poly_r+12
        rts

; =============================================================================
; sqtab_init - Build quarter-square lookup table
;
; Computes floor(i^2/4) for i = 0..511 using recurrence i^2 = (i-1)^2 + 2i - 1
; Ported from c64-aes256-ecdsa fp_init_sqtab.
;
; Clobbers: A, X, Y
; =============================================================================
sqtab_init:
        lda #0
        sta sq_acc              ; accumulator = 0
        sta sq_acc+1
        sta sq_acc+2
        sta sq_i                ; index = 0
        sta sq_i+1

@loop:
        ; Compute f(i) = sq_acc >> 2 (divide by 4)
        lda sq_acc+2
        lsr
        sta sq_sh+2
        lda sq_acc+1
        ror
        sta sq_sh+1
        lda sq_acc
        ror
        sta sq_sh
        lsr sq_sh+2
        ror sq_sh+1
        ror sq_sh

        ; Store in table at index sq_i (0..511)
        ldx sq_i                ; low byte of index
        lda sq_i+1
        beq @pg0
        ; Page 1 (256..511)
        lda sq_sh
        sta sqtab_lo+256,x
        lda sq_sh+1
        sta sqtab_hi+256,x
        jmp @advance
@pg0:
        lda sq_sh
        sta sqtab_lo,x
        lda sq_sh+1
        sta sqtab_hi,x

@advance:
        ; sq_acc += 2*i + 1 (recurrence: (i+1)^2 = i^2 + 2i + 1)
        lda sq_i
        asl
        sta sq_ad
        lda sq_i+1
        rol
        sta sq_ad+1
        inc sq_ad
        bne :+
        inc sq_ad+1
:
        clc
        lda sq_acc
        adc sq_ad
        sta sq_acc
        lda sq_acc+1
        adc sq_ad+1
        sta sq_acc+1
        lda sq_acc+2
        adc #0
        sta sq_acc+2

        inc sq_i
        bne :+
        inc sq_i+1
:       lda sq_i+1
        cmp #2                  ; check if i reached 512 (0x200)
        beq @done
        jmp @loop
@done:  rts

; =============================================================================
; mul_8x8 - 8-bit x 8-bit -> 16-bit multiply using quarter-square table
;
; Input: A = multiplicand, X = multiplier
; Output: poly_prod_lo/hi = A * X (16-bit result)
;
; Uses identity: a*b = sqtab[a+b] - sqtab[|a-b|]
; Clobbers: A, X, Y
; =============================================================================
.if .defined(USE_NISTCURVES_ONCHIP) .or .defined(USE_X25519_SIBLING)
; --- c64-lib-contract §8.3 canonical body (issue #69 integration) ---
; The sibling's FP_ONCHIP_MUL row generator (og_common, rebuilt with
; SHARED_CT_MUL_8X8) imports ct_mul_8x8 + the SMC bake sites from the
; consumer. Body copied verbatim from libs/nistcurves/src/mul_8x8.s
; (the §8.3 reference copy). Convention: caller bakes `a` into
; smc_sum_a_imm+1 / smc_diff_a_imm+1 once per row, passes b in Y.
; The legacy in-tree convention (A=a, X=b, re-baked per call) is kept
; as the thin `mul_8x8` shim for poly1305/fe25519 call sites.
;
; USE_X25519_SIBLING selects this body too, as of the c64-x25519
; v0.10.0 bump. From v0.7.0 the sibling's x25519_init.s imports
; ct_mul_8x8 + both SMC bake sites UNCONDITIONALLY (it used to carry
; its own copy in mul_8x8.s, which this wrapper does not stage because
; that file's other exports collide with in-tree ones). Without this
; arm the sibling link dies on three unresolved externals — and it
; dies *behind* the memory-area overflows, so it only becomes visible
; once the placement problem is solved.
;
; The two arms are functionally equivalent implementations of the same
; a*b -> poly_prod_lo/hi contract, so widening the gate is a strict
; no-op for every configuration that does not set one of these flags:
; the default REU builds on both backends stay byte-identical (verified
; by PRG sha256, not by inspection). The two flags are mutually
; exclusive at Makefile:90, so this arm is never selected twice.
.export ct_mul_8x8
.export smc_sum_a_imm, smc_diff_a_imm

mul_8x8:                        ; legacy shim: A=a, X=b
        sta smc_sum_a_imm+1     ; bake a (per call — legacy sites only)
        sta smc_diff_a_imm+1
        txa
        tay                     ; Y = b
        ; fall through into ct_mul_8x8

ct_mul_8x8:
        ; --- Compute sum = a + b and SMC-patch the two abs,x hi bytes ---
        tya                     ; A = b
        clc
smc_sum_a_imm:
        adc #$00                ; SMC imm = a; A = (a+b).lo, C = sum-page bit
        tax                     ; X = (a+b) & $FF
        lda #>sqtab_lo
        adc #0                  ; sum-page carry folded into hi byte
        sta smc_lo_addr+2       ; patch sqtab_lo abs,x hi byte
        adc #(>sqtab_hi - >sqtab_lo)   ; C=0 after prior adc #0, so += 2
        sta smc_hi_addr+2       ; patch sqtab_hi abs,x hi byte

        ; --- Branchless |a-b| -> Y (sign-mask flip-and-negate) ---
        tya                     ; A = b
        sec
smc_diff_a_imm:
        sbc #$00                ; SMC imm = a; A = b-a, C=1 iff b>=a
        sta ct_diff_raw
        lda #$00
        sbc #$00                ; C=1: $00; C=0: $FF (sign mask)
        sta ct_sign_mask
        eor ct_diff_raw         ; raw XOR mask
        sec
        sbc ct_sign_mask        ; + (-mask): +0 if b>=a, +1 if b<a
        tay                     ; Y = |a-b| (in [0,255])

        ; --- Table-lookup subtract: sqtab[a+b] - sqtab[|a-b|] ---
smc_lo_addr:
        lda sqtab_lo,x          ; hi byte SMC-patched above
        sec
        sbc sqtab_lo,y
        sta poly_prod_lo
smc_hi_addr:
        lda sqtab_hi,x          ; hi byte SMC-patched above
        sbc sqtab_hi,y
        sta poly_prod_hi
        rts

ct_diff_raw:    .byte 0
ct_sign_mask:   .byte 0

.else
mul_8x8:
        sta mul_a               ; save A
        stx mul_b               ; save X

        ; Compute sum = a + b
        clc
        adc mul_b               ; A = a + b (low byte)
        tax                     ; X = sum low byte
        lda #0
        adc #0                  ; carry -> sum page (0 or 1)
        sta mul_s_pg            ; sum page

        ; Compute |a - b|
        lda mul_a
        sec
        sbc mul_b
        bcs :+
        eor #$ff
        adc #1                  ; negate (carry was clear, so ADC adds 1)
:       tay                     ; Y = |a-b| (always page 0, <=255)

        ; sqtab[sum] - sqtab[|diff|]
        lda mul_s_pg
        beq @s0
        ; sum is in page 1 (256..510)
        lda sqtab_lo+256,x
        sec
        sbc sqtab_lo,y
        sta poly_prod_lo
        lda sqtab_hi+256,x
        sbc sqtab_hi,y
        sta poly_prod_hi
        rts
@s0:
        ; sum is in page 0 (0..255)
        lda sqtab_lo,x
        sec
        sbc sqtab_lo,y
        sta poly_prod_lo
        lda sqtab_hi,x
        sbc sqtab_hi,y
        sta poly_prod_hi
        rts
.endif ; USE_NISTCURVES_ONCHIP / USE_X25519_SIBLING

; =============================================================================
; poly1305_multiply - Multiply h (17 bytes) by r (16 bytes), reduce mod 2^130-5
;
; Schoolbook multiply: for each byte pair h[i] * r[j], accumulate into
; poly_product[i+j..i+j+1]. Then reduce: top portion * 5, add to bottom.
;
; Clobbers: A, X, Y
; =============================================================================
poly1305_multiply:
        ; Zero the product buffer (33 bytes)
        ldx #32
        lda #0
@zero_prod:
        sta poly_product,x
        dex
        bpl @zero_prod

        ; Schoolbook multiply: h[i] * r[j] for i=0..16, j=0..15
        lda #0
        sta poly_i              ; i = 0 (h index)
@mul_outer:
        ldx poly_i
        lda poly_h,x
        beq @skip_h_zero       ; skip entire inner loop if h[i] = 0

        lda #0
        sta poly_j              ; j = 0 (r index)
@mul_inner:
        ; Load h[i] into A, r[j] into X for mul_8x8
        ldx poly_i
        lda poly_h,x           ; A = h[i]
        pha
        ldx poly_j
        lda poly_r,x           ; A = r[j]
        beq @skip_r_zero       ; skip if r[j] = 0
        tax                    ; X = r[j]
        pla                    ; A = h[i]
        jsr mul_8x8            ; poly_prod_lo/hi = h[i] * r[j]

        ; Add 16-bit product to poly_product[i+j .. i+j+1]
        lda poly_i
        clc
        adc poly_j
        tax                    ; X = i+j

        clc
        lda poly_product,x
        adc poly_prod_lo
        sta poly_product,x
        inx                    ; X = i+j+1
        lda poly_product,x
        adc poly_prod_hi
        sta poly_product,x
        bcc @next_j
        ; Propagate carry upward -- carry is set entering this loop
@prop_carry:
        inx
        cpx #33
        bcs @next_j            ; bounds check (clobbers carry)
        sec                    ; restore carry (we only get here if carry was set)
        lda poly_product,x
        adc #0
        sta poly_product,x
        bcs @prop_carry
        jmp @next_j

@skip_r_zero:
        pla                    ; discard saved h[i]
@next_j:
        inc poly_j
        lda poly_j
        cmp #16
        bcc @mul_inner

@skip_h_zero:
        inc poly_i
        lda poly_i
        cmp #17
        bcs @mul_done
        jmp @mul_outer
@mul_done:
        jmp poly1305_reduce

; =============================================================================
; poly1305_reduce - Reduce poly_product (33 bytes) mod 2^130-5 into poly_h
;
; product = bottom (130 bits) + overflow * 2^130
; result = bottom + overflow * 5  (since 2^130 = 5 mod p)
;
; Strategy:
;   1. Copy bottom 130 bits (product[0..15] + low 2 bits of product[16]) to h
;   2. Extract overflow = product >> 130 (right-shift product[16..32] by 2)
;   3. Add overflow * 5 to h
;      overflow*5 is computed as: for each overflow byte, multiply by 5
;      and add to h with running carry.
;
; Clobbers: A, X, Y
; =============================================================================
poly1305_reduce:
        ; 1. Copy bottom 130 bits to h
        ldx #15
@copy_lo:
        lda poly_product,x
        sta poly_h,x
        dex
        bpl @copy_lo
        lda poly_product+16
        and #$03               ; keep only low 2 bits (bits 128-129)
        sta poly_h+16

        ; 2. Extract overflow: right-shift product[16..32] by 2 bits
        ; Do 2 right-shift passes over bytes 32 down to 16
        ; IMPORTANT: Use DEY/BNE for loop control -- CPX clobbers carry,
        ; which would corrupt the ROR chain.
        clc
        ldy #17                ; 17 bytes (product[32] down to product[16])
        ldx #32
@rshift1:
        lda poly_product,x
        ror
        sta poly_product,x
        dex
        dey
        bne @rshift1

        clc
        ldy #17
        ldx #32
@rshift2:
        lda poly_product,x
        ror
        sta poly_product,x
        dex
        dey
        bne @rshift2

        ; product[16..32] now holds the overflow value (17 bytes)

        ; 3. Add overflow * 5 to h
        ; For each byte overflow[i] (product[16+i]):
        ;   tmp16 = overflow[i] * 5 + running_carry
        ;   h[i] += tmp16_lo  (with addition carry)
        ;   running_carry = tmp16_hi + addition_carry_out
        ;
        ; overflow[i]*5: use mul_8x8 would be slow (17 calls).
        ; Instead compute inline: byte*5 = byte*4 + byte = (byte<<2) + byte
        ; Result fits in 16 bits (max 255*5 = 1275).

        lda #0
        sta poly_carry          ; running carry from multiplication
        ldx #0
@reduce_loop:
        ; compute overflow[i] * 4
        lda poly_product+16,x
        asl
        sta poly_tmp
        lda #0
        rol                    ; carry from first shift
        sta poly_j              ; high byte temp (reuse poly_j as temp)
        lda poly_tmp
        asl
        sta poly_tmp
        lda poly_j
        rol
        sta poly_j              ; poly_j:poly_tmp = overflow[i] * 4

        ; add overflow[i] to get *5
        clc
        lda poly_tmp
        adc poly_product+16,x  ; + overflow[i]
        sta poly_tmp
        lda poly_j
        adc #0
        sta poly_j              ; poly_j:poly_tmp = overflow[i] * 5

        ; add running carry
        clc
        lda poly_tmp
        adc poly_carry
        sta poly_tmp
        lda poly_j
        adc #0
        sta poly_j              ; poly_j:poly_tmp = overflow[i]*5 + carry_in

        ; add to h[i]
        clc
        lda poly_h,x
        adc poly_tmp
        sta poly_h,x

        ; new running carry = poly_j + carry_out_from_addition
        lda poly_j
        adc #0
        sta poly_carry

        inx
        cpx #17
        bcc @reduce_loop

        rts

; =============================================================================
; poly1305_block - Process one 16-byte block
;
; Input: zp_ptr points to 16-byte block
;        A = high bit to add (1 for normal blocks, 0 for final partial)
;
; Operations: h += block (with high bit), then h *= r mod p
;
; Clobbers: A, X, Y
; =============================================================================
poly1305_block:
        sta poly_carry          ; save high bit value

        ; h += block (16 bytes from (zp_ptr))
        ; IMPORTANT: Use DEX/BNE for loop control -- CPY clobbers carry,
        ; which would break carry propagation in the multi-byte addition.
        clc
        ldx #16                ; byte counter
        ldy #0
@add_block:
        lda poly_h,y
        adc (zp_ptr),y
        sta poly_h,y
        iny
        dex
        bne @add_block

        ; h[16] += high bit + carry
        lda poly_h+16
        adc poly_carry
        sta poly_h+16

        ; h *= r mod p
        jsr poly1305_multiply
        rts

; =============================================================================
; poly1305_update - Process message data
;
; Input: zp_ptr = pointer to data, cc20_remain = length
;        (Reuses cc20_remain as a general byte counter)
;
; Clobbers: A, X, Y
; =============================================================================
poly1305_update:
        lda cc20_remain
        beq @upd_done

@next_block:
        lda cc20_remain
        cmp #16
        bcc @last_block         ; < 16 bytes remaining = partial final block

        ; Full 16-byte block with high bit = 1
        lda #1
        jsr poly1305_block

        ; Advance pointer by 16
        clc
        lda zp_ptr
        adc #16
        sta zp_ptr
        lda zp_ptr+1
        adc #0
        sta zp_ptr+1

        lda cc20_remain
        sec
        sbc #16
        sta cc20_remain
        bne @next_block
        rts

@last_block:
        ; Partial block: copy to aead_scratch with padding
        ; Zero the scratch buffer first
        ldx #15
        lda #0
@zero_scratch:
        sta aead_scratch,x
        dex
        bpl @zero_scratch

        ; Copy remaining bytes
        ldy #0
        ldx cc20_remain
        beq @pad_done
@copy_partial:
        lda (zp_ptr),y
        sta aead_scratch,y
        iny
        dex
        bne @copy_partial
@pad_done:
        ; Set 0x01 after the message bytes (at position n)
        ; This encodes the block as: data + 2^(8*n) per RFC 7539
        lda #$01
        sta aead_scratch,y

        ; Point zp_ptr to scratch buffer
        lda #<(aead_scratch)
        sta zp_ptr
        lda #>(aead_scratch)
        sta zp_ptr+1

        ; Process with high bit = 0 (the 0x01 in the buffer handles it)
        lda #0
        jsr poly1305_block

        lda #0
        sta cc20_remain

@upd_done:
        rts

; =============================================================================
; poly1305_final - Finalize Poly1305 tag
;
; 1. Full reduction of h mod 2^130-5
; 2. h += s
; 3. Output low 16 bytes to poly1305_tag
;
; Clobbers: A, X, Y
; =============================================================================
poly1305_final:
        ; --- Full reduction mod 2^130 - 5 ---
        ; Check if h >= p = 2^130 - 5
        ; Compute h + 5, check if it overflows 2^130
        ; If so, use h + 5 (mod 2^130), otherwise keep h

        ; Add 5 to h, store result in poly_product as temp
        clc
        lda poly_h
        adc #5
        sta poly_product
        ldy #16                ; 16 remaining bytes (indices 1..16)
        ldx #1
@add5:
        lda poly_h,x
        adc #0
        sta poly_product,x
        inx
        dey                    ; DEY doesn't affect carry
        bne @add5

        ; Check if bit 130 is set in the result (byte 16, bit 2)
        lda poly_product+16
        and #$04
        beq @no_reduce          ; h + 5 < 2^130, keep h as is

        ; h >= p, use reduced value (mask to 130 bits)
        ldx #0
@use_reduced:
        lda poly_product,x
        sta poly_h,x
        inx
        cpx #16
        bcc @use_reduced
        lda poly_product+16
        and #$03               ; mask to 2 bits (130 bits total)
        sta poly_h+16

@no_reduce:
        ; --- Add s to h ---
        clc
        ldy #16                ; 16 bytes
        ldx #0
@add_s:
        lda poly_h,x
        adc poly_s,x
        sta poly_h,x
        inx
        dey                    ; DEY doesn't affect carry
        bne @add_s

        ; --- Output tag: low 16 bytes of h ---
        ldx #0
@output:
        lda poly_h,x
        sta poly1305_tag,x
        inx
        cpx #16
        bcc @output
        rts
