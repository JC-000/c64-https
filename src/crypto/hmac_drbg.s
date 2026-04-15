; hmac_drbg.s — HMAC-DRBG deterministic RNG
; Converted from ACME to ca65 in Phase 3 Batch A.
; =============================================================================
; HMAC-SHA256 and HMAC-DRBG (RFC 6979 + entropy-seeded)
; =============================================================================
; Adapted from c64-aes256-ecdsa for c64-https (TLS 1.3)
;
; Routines:
;   hmac_sha256          - HMAC-SHA256(hmac_key, hmac_data_buf[hmac_data_len])
;   hmac_drbg_instantiate - Initialize DRBG from drbg_seed[drbg_seed_len]
;   hmac_drbg_generate   - Generate 32 bytes into drbg_output
;   drbg_init_entropy    - Collect 32B SID+CIA entropy, instantiate DRBG
;   drbg_random_byte     - Return 1 buffered random byte in A (preserves X,Y)
;   drbg_fill_bytes      - Fill buffer: zp_ptr=dest, A=count
;
; Uses SHA-256 primitives: sha256_init, sha256_process_block, sha256_final
; ZP equates (zp_ptr, zp_count) are in constants.inc
; Hardware addresses (sid_osc3, cia1_ta_lo) are in constants.inc
; Data labels (hmac_key, hmac_val, hmac_opad_block, hmac_data_buf,
;              hmac_data_len, hmac_result, drbg_seed, drbg_seed_len,
;              drbg_output, drbg_buf_idx, sha256_block, sha256_hash) in data.asm
; =============================================================================

.include "constants.inc"

.export hmac_sha256
.export hmac_drbg_update
.export hmac_drbg_instantiate
.export hmac_drbg_generate
.export extra_sid_count
.export extra_sid_lo
.export extra_sid_hi
.export drbg_init_entropy
.export drbg_random_byte
.export drbg_fill_bytes

; SHA-256 primitives
.import sha256_init
.import sha256_process_block
.import sha256_final

; Data (BSS) symbols from data.asm
.import hmac_key
.import hmac_val
.import hmac_opad_block
.import hmac_data_buf
.import hmac_data_len
.import hmac_result
.import drbg_seed
.import drbg_seed_len
.import drbg_output
.import drbg_buf_idx
.import sha256_block
.import sha256_hash

.segment "CRYPTO_CODE"

; =============================================================================
; hmac_sha256 - compute HMAC-SHA256
; Input:  hmac_key (32 bytes), hmac_data_buf (hmac_data_len bytes, max 97)
; Output: hmac_result (32 bytes)
; Clobbers: sha256 working state, hmac_opad_block
; =============================================================================
hmac_sha256:
	; --- Build K XOR ipad block in sha256_block ---
	; ipad = 0x36 repeated. Key is 32 bytes, pad remaining 32 with 0x36.
	ldx #0
@ipad_key:
	lda hmac_key,x
	eor #$36
	sta sha256_block,x
	inx
	cpx #32
	bne @ipad_key
	; Fill bytes 32-63 with 0x36 (key is only 32 bytes, rest is zero XOR 0x36)
	lda #$36
@ipad_pad:
	sta sha256_block,x
	inx
	cpx #64
	bne @ipad_pad

	; --- Also build K XOR opad block for later ---
	ldx #0
@opad_key:
	lda hmac_key,x
	eor #$5c
	sta hmac_opad_block,x
	inx
	cpx #32
	bne @opad_key
	lda #$5c
@opad_pad:
	sta hmac_opad_block,x
	inx
	cpx #64
	bne @opad_pad

	; --- Inner hash: H(K XOR ipad || data) ---
	jsr sha256_init
	jsr sha256_process_block        ; process ipad block (64 bytes)

	; Now process hmac_data_buf with proper padding
	; Total message length = 64 + hmac_data_len
	; We need to: copy data to sha256_block, add 0x80, add 64-bit length

	; Clear sha256_block
	ldx #0
	lda #0
@clear_inner:
	sta sha256_block,x
	inx
	cpx #64
	bne @clear_inner

	; Copy data bytes to sha256_block
	ldx #0
	lda hmac_data_len
	beq @inner_pad
@copy_inner:
	cpx hmac_data_len
	beq @inner_pad
	lda hmac_data_buf,x
	sta sha256_block,x
	inx
	cpx #64
	bcc @copy_inner
	; If we get here, data_len >= 64 — process this full block
	jsr sha256_process_block

	; Clear block for remainder
	ldx #0
	lda #0
@clear_inner2:
	sta sha256_block,x
	inx
	cpx #64
	bne @clear_inner2

	; Copy remaining bytes (data_len - 64)
	ldx #0
	ldy #64                         ; source offset
@copy_inner2:
	cpy hmac_data_len
	beq @inner_pad2
	lda hmac_data_buf,y
	sta sha256_block,x
	iny
	inx
	jmp @copy_inner2

@inner_pad2:
	; X = number of remainder bytes copied = data_len - 64
	; Add 0x80 padding
	lda #$80
	sta sha256_block,x

	; Check if length fits: need x+1+8 <= 64, i.e. x <= 55
	; data_len can be at most 97, so x = data_len - 64 <= 33. Always fits.

	; Compute bit length: (64 + data_len) * 8
	; = 512 + data_len * 8
	; Store in big-endian 64-bit at sha256_block+56
	; Upper bytes are 0 (already cleared)
	lda hmac_data_len
	sta sha256_block+63             ; low byte of data_len * 8 (before shift)
	lda #0
	sta sha256_block+62

	; Shift left 3 (multiply by 8)
	asl sha256_block+63
	rol sha256_block+62
	asl sha256_block+63
	rol sha256_block+62
	asl sha256_block+63
	rol sha256_block+62

	; Add 512 (= 0x0200)
	clc
	lda sha256_block+62
	adc #$02
	sta sha256_block+62
	lda #0
	adc sha256_block+61
	sta sha256_block+61

	jsr sha256_process_block
	jmp @inner_done

@inner_pad:
	; X = data_len (< 64)
	; Add 0x80 padding
	lda #$80
	sta sha256_block,x

	; Check if length fits in this block (data_len <= 55)
	lda hmac_data_len
	cmp #56
	bcs @inner_extra_block

	; Compute bit length: (64 + data_len) * 8
	lda hmac_data_len
	sta sha256_block+63
	lda #0
	sta sha256_block+62
	asl sha256_block+63
	rol sha256_block+62
	asl sha256_block+63
	rol sha256_block+62
	asl sha256_block+63
	rol sha256_block+62
	clc
	lda sha256_block+62
	adc #$02
	sta sha256_block+62
	lda #0
	adc sha256_block+61
	sta sha256_block+61

	jsr sha256_process_block
	jmp @inner_done

@inner_extra_block:
	; data_len is 56-63: process block with data+0x80, then another with length
	jsr sha256_process_block

	ldx #0
	lda #0
@clear_inner3:
	sta sha256_block,x
	inx
	cpx #64
	bne @clear_inner3

	; Bit length at end
	lda hmac_data_len
	sta sha256_block+63
	lda #0
	sta sha256_block+62
	asl sha256_block+63
	rol sha256_block+62
	asl sha256_block+63
	rol sha256_block+62
	asl sha256_block+63
	rol sha256_block+62
	clc
	lda sha256_block+62
	adc #$02
	sta sha256_block+62
	lda #0
	adc sha256_block+61
	sta sha256_block+61

	jsr sha256_process_block

@inner_done:
	jsr sha256_final

	; Save inner hash to hmac_result temporarily
	ldx #0
@save_inner:
	lda sha256_hash,x
	sta hmac_result,x
	inx
	cpx #32
	bne @save_inner

	; --- Outer hash: H(K XOR opad || inner_hash) ---
	; Copy opad block to sha256_block
	ldx #0
@copy_opad:
	lda hmac_opad_block,x
	sta sha256_block,x
	inx
	cpx #64
	bne @copy_opad

	jsr sha256_init
	jsr sha256_process_block        ; process opad block

	; Now hash the 32-byte inner hash with padding
	; Total message = 64 + 32 = 96 bytes = 768 bits = 0x0300
	; Clear block
	ldx #0
	lda #0
@clear_outer:
	sta sha256_block,x
	inx
	cpx #64
	bne @clear_outer

	; Copy inner hash (32 bytes)
	ldx #0
@copy_ihash:
	lda hmac_result,x
	sta sha256_block,x
	inx
	cpx #32
	bne @copy_ihash

	; Padding: 0x80 at position 32
	lda #$80
	sta sha256_block+32

	; Length: 96 * 8 = 768 = $0300
	lda #$03
	sta sha256_block+62
	lda #$00
	sta sha256_block+63

	jsr sha256_process_block
	jsr sha256_final

	; Copy final hash to hmac_result
	ldx #0
@copy_result:
	lda sha256_hash,x
	sta hmac_result,x
	inx
	cpx #32
	bne @copy_result

	rts

; =============================================================================
; hmac_drbg_update - HMAC-DRBG update(provided_data)
; Input: drbg_seed (provided_data), drbg_seed_len (0 if no provided_data)
; Uses/updates: hmac_key (K), hmac_val (V)
; =============================================================================
hmac_drbg_update:
	; --- Step 1: K = HMAC(K, V || 0x00 || provided_data) ---
	; Build hmac_data_buf = V || 0x00 || provided_data
	ldx #0
@copy_v1:
	lda hmac_val,x
	sta hmac_data_buf,x
	inx
	cpx #32
	bne @copy_v1

	lda #$00
	sta hmac_data_buf+32            ; separator byte

	; Copy provided_data (drbg_seed) if any
	lda drbg_seed_len
	beq @no_seed1
	ldx #0
@copy_seed1:
	cpx drbg_seed_len
	beq @seed1_done
	lda drbg_seed,x
	sta hmac_data_buf+33,x
	inx
	jmp @copy_seed1
@seed1_done:
	; hmac_data_len = 32 + 1 + seed_len
	clc
	lda drbg_seed_len
	adc #33
	sta hmac_data_len
	jmp @do_hmac1

@no_seed1:
	lda #33                         ; V(32) + 0x00(1)
	sta hmac_data_len

@do_hmac1:
	jsr hmac_sha256

	; K = hmac_result
	ldx #0
@update_k1:
	lda hmac_result,x
	sta hmac_key,x
	inx
	cpx #32
	bne @update_k1

	; --- Step 2: V = HMAC(K, V) ---
	ldx #0
@copy_v2:
	lda hmac_val,x
	sta hmac_data_buf,x
	inx
	cpx #32
	bne @copy_v2
	lda #32
	sta hmac_data_len

	jsr hmac_sha256

	; V = hmac_result
	ldx #0
@update_v1:
	lda hmac_result,x
	sta hmac_val,x
	inx
	cpx #32
	bne @update_v1

	; --- Step 3: If provided_data is empty, done ---
	lda drbg_seed_len
	beq @update_done

	; --- Step 4: K = HMAC(K, V || 0x01 || provided_data) ---
	ldx #0
@copy_v3:
	lda hmac_val,x
	sta hmac_data_buf,x
	inx
	cpx #32
	bne @copy_v3

	lda #$01
	sta hmac_data_buf+32            ; separator = 0x01

	ldx #0
@copy_seed2:
	cpx drbg_seed_len
	beq @seed2_done
	lda drbg_seed,x
	sta hmac_data_buf+33,x
	inx
	jmp @copy_seed2
@seed2_done:
	clc
	lda drbg_seed_len
	adc #33
	sta hmac_data_len

	jsr hmac_sha256

	; K = hmac_result
	ldx #0
@update_k2:
	lda hmac_result,x
	sta hmac_key,x
	inx
	cpx #32
	bne @update_k2

	; --- Step 5: V = HMAC(K, V) ---
	ldx #0
@copy_v4:
	lda hmac_val,x
	sta hmac_data_buf,x
	inx
	cpx #32
	bne @copy_v4
	lda #32
	sta hmac_data_len

	jsr hmac_sha256

	; V = hmac_result
	ldx #0
@update_v2:
	lda hmac_result,x
	sta hmac_val,x
	inx
	cpx #32
	bne @update_v2

@update_done:
	rts

; =============================================================================
; hmac_drbg_instantiate - initialize DRBG state from seed
; Input: drbg_seed (seed material), drbg_seed_len (length, typically 64)
; Output: hmac_key and hmac_val initialized
; =============================================================================
hmac_drbg_instantiate:
	; K = 0x00 * 32
	ldx #0
	lda #$00
@init_k:
	sta hmac_key,x
	inx
	cpx #32
	bne @init_k

	; V = 0x01 * 32
	ldx #0
	lda #$01
@init_v:
	sta hmac_val,x
	inx
	cpx #32
	bne @init_v

	; update(seed)
	jsr hmac_drbg_update
	rts

; =============================================================================
; hmac_drbg_generate - generate 32 bytes of output
; Input: DRBG state (hmac_key, hmac_val) must be instantiated
; Output: drbg_output (32 bytes)
; =============================================================================
hmac_drbg_generate:
	; V = HMAC(K, V)
	ldx #0
@copy_v:
	lda hmac_val,x
	sta hmac_data_buf,x
	inx
	cpx #32
	bne @copy_v
	lda #32
	sta hmac_data_len

	jsr hmac_sha256

	; V = hmac_result, also copy to output
	ldx #0
@copy_out:
	lda hmac_result,x
	sta hmac_val,x
	sta drbg_output,x
	inx
	cpx #32
	bne @copy_out

	; update("") - no provided data
	lda #0
	sta drbg_seed_len
	jsr hmac_drbg_update

	rts

; =============================================================================
; Extra SID configuration stubs (no extra SIDs in c64-https)
; In c64-aes256-ecdsa these come from the sid_config module.
; Set to 0 so drbg_init_entropy skips the extra-SID XOR loop.
; =============================================================================
extra_sid_count:
	.byte 0
extra_sid_lo:
	.byte 0
extra_sid_hi:
	.byte 0

; =============================================================================
; drbg_init_entropy - collect 32 bytes from SID+CIA hardware, instantiate DRBG
; Clobbers: A, X, Y
; =============================================================================
drbg_init_entropy:
	ldx #0
@collect:
	; Read SID oscillator 3 XOR CIA timer A low
	lda sid_osc3
	eor cia1_ta_lo
	sta drbg_seed,x

	; XOR with extra SIDs if available
	lda extra_sid_count
	beq @no_extra
	stx @ent_save_x+1	; save byte index (self-modifying)

	ldy #0
@extra_loop:
	cpy extra_sid_count
	bcs @extra_done
	lda extra_sid_lo,y
	sta zp_ptr
	lda extra_sid_hi,y
	sta zp_ptr+1
	sty @ent_save_y+1	; save SID index (self-modifying)
	ldy #$1b			; OSC3 offset
	lda (zp_ptr),y
@ent_save_x:
	ldx #0			; restored by self-modify
	eor drbg_seed,x
	sta drbg_seed,x
@ent_save_y:
	ldy #0			; restored by self-modify
	iny
	jmp @extra_loop
@extra_done:

@no_extra:
	; Short delay for fresh oscillator value (~30 cycles)
	ldy #6
@delay:
	dey
	bne @delay

	inx
	cpx #32
	bne @collect

	; Set seed length and instantiate DRBG
	lda #32
	sta drbg_seed_len
	jsr hmac_drbg_instantiate

	; Force fresh generate on first drbg_random_byte call
	lda #32
	sta drbg_buf_idx

	rts

; =============================================================================
; drbg_random_byte - return 1 buffered random byte in A
; Preserves X, Y (matches lfsr_random contract)
; Uses drbg_output[0..31] as buffer, drbg_buf_idx as position
; =============================================================================
drbg_random_byte:
	; Check if buffer exhausted
	lda drbg_buf_idx
	cmp #32
	bcc @have_byte

	; Buffer empty - generate 32 fresh bytes
	stx @restore_x+1	; save X (self-modifying)
	sty @restore_y+1	; save Y (self-modifying)

	jsr hmac_drbg_generate

	lda #0
	sta drbg_buf_idx

@restore_x:
	ldx #0			; restored by self-modify
@restore_y:
	ldy #0			; restored by self-modify

@have_byte:
	; Fetch byte from buffer
	stx @save_x2+1		; save X
	ldx drbg_buf_idx
	lda drbg_output,x
	inc drbg_buf_idx
@save_x2:
	ldx #0			; restored by self-modify
	rts

; =============================================================================
; drbg_fill_bytes - fill buffer with N random bytes
; Input: zp_ptr = destination address, A = count
; Clobbers: A, zp_count
; =============================================================================
drbg_fill_bytes:
	sta zp_count
@loop:
	jsr drbg_random_byte
	ldy #0
	sta (zp_ptr),y

	inc zp_ptr
	bne @no_carry
	inc zp_ptr+1
@no_carry:

	dec zp_count
	bne @loop
	rts
