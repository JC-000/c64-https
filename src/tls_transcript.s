; tls_transcript.s — TLS 1.3 handshake transcript hash
; Converted from ACME to ca65 in Phase 3 Batch B.
; =============================================================================
; Streaming SHA-256 transcript hash for TLS 1.3
; =============================================================================
; Maintains a running SHA-256 state across arbitrary-length handshake messages.
; Unlike sha256_update (single <=63 byte input), this handles multi-block
; incremental hashing with non-destructive finalization (clone-and-pad).
;
; ZP usage:
;   zp_ptr   ($FB-$FC) - source data pointer (tls_transcript_update)
;   zp_count ($FE-$FF) - remaining bytes in current call (16-bit LE)
;
; External dependencies (sha256.s / data.asm):
;   sha256_init, sha256_process_block, sha256_final
;   sha256_h0, sha256_block, sha256_hash
;   tls_transcript, tls_transcript_h0
; =============================================================================

.include "constants.inc"

.import sha256_init
.import sha256_process_block
.import sha256_final
.import sha256_h0
.import sha256_block
.import sha256_hash
.import tls_transcript
.import tls_transcript_h0

.export tls_transcript_init
.export tls_transcript_update
.export tls_transcript_hash

; =============================================================================
; Local data buffers (BSS)
; =============================================================================
.segment "BSS"

tls_transcript_block:     .res 64, 0   ; partial block buffer
tls_transcript_block_len: .res 1       ; bytes in current partial block (0-63)
tls_transcript_total_lo:  .res 1       ; total bytes hashed (low byte)
tls_transcript_total_hi:  .res 1       ; total bytes hashed (high byte)

; Temporary save area for tls_transcript_hash (32 bytes)
; Used to preserve running state during non-destructive finalization
tls_transcript_save:      .res 32, 0

.segment "CODE"

; =============================================================================
; tls_transcript_init - Initialize transcript hash state
; =============================================================================
; Calls sha256_init to load IV, then saves that initial state into the
; tls_transcript_h0..h7 shadow registers. Resets block buffer and counters.
; Clobbers: A, X
; =============================================================================
tls_transcript_init:
    ; Initialize SHA-256 with standard IV
    jsr sha256_init

    ; Save initial hash state to transcript shadow registers
    ldx #31
:   lda sha256_h0,x
    sta tls_transcript_h0,x
    dex
    bpl :-

    ; Reset partial block length and total byte counters
    lda #0
    sta tls_transcript_block_len
    sta tls_transcript_total_lo
    sta tls_transcript_total_hi
    rts

; =============================================================================
; tls_transcript_update - Feed data into the running transcript hash
; =============================================================================
; Input: zp_ptr        ($FB-$FC) = pointer to data
;        zp_count      ($FE)     = length low byte
;        zp_count+1    ($FF)     = length high byte  (16-bit LE total)
; Clobbers: A, X, Y
;
; Algorithm:
;   1. Copy bytes from source into tls_transcript_block at current offset
;   2. When block reaches 64 bytes, process it through SHA-256
;   3. Continue until all 16-bit input count consumed
;   4. Update total byte counter
;
; Previously zp_count was 8-bit, which silently truncated handshake
; messages larger than 256 bytes (e.g. the 352 B TLS 1.3 Certificate,
; which wrapped Y at 96 and lost the rest).  Now callers must set both
; zp_count and zp_count+1.
; =============================================================================
tls_transcript_update:
    ; Update total byte counter (16-bit += zp_count)
    clc
    lda tls_transcript_total_lo
    adc zp_count
    sta tls_transcript_total_lo
    lda tls_transcript_total_hi
    adc zp_count+1
    sta tls_transcript_total_hi

@update_loop:
    ; Check if any bytes remain (zp_count | zp_count+1 == 0 -> done)
    lda zp_count
    ora zp_count+1
    beq @update_done

    ; Load current block position
    ldx tls_transcript_block_len

    ; Copy bytes into partial block until block full or input exhausted
@copy_byte:
    ldy #0
    lda (zp_ptr),y

    sta tls_transcript_block,x
    inx

    ; Advance source pointer
    inc zp_ptr
    bne :+
    inc zp_ptr+1
:
    ; Decrement remaining 16-bit count
    lda zp_count
    bne :+
    dec zp_count+1
:   dec zp_count

    ; Check if block is full (64 bytes)
    cpx #64
    beq @block_full

    ; Check if more bytes remain
    lda zp_count
    ora zp_count+1
    bne @copy_byte

    ; Input exhausted, save block position and return
    stx tls_transcript_block_len
    rts

@block_full:
    ; Block is full — process it through SHA-256
    ; Reset block length (will be 0 after processing)
    lda #0
    sta tls_transcript_block_len

    ; Step 1: Restore running state to SHA-256 working registers
    ldx #31
:   lda tls_transcript_h0,x
    sta sha256_h0,x
    dex
    bpl :-

    ; Step 2: Copy transcript block to sha256_block
    ldx #63
:   lda tls_transcript_block,x
    sta sha256_block,x
    dex
    bpl :-

    ; Step 3: Process the block
    jsr sha256_process_block

    ; Step 4: Save updated state back to transcript shadow registers
    ldx #31
:   lda sha256_h0,x
    sta tls_transcript_h0,x
    dex
    bpl :-

    ; Continue with remaining bytes (if any)
    jmp @update_loop

@update_done:
    rts

; =============================================================================
; tls_transcript_hash - Get current hash WITHOUT destroying running state
; =============================================================================
; Output: tls_transcript (32 bytes) = current SHA-256 hash of all data fed so far
; Clobbers: A, X, Y
;
; This performs SHA-256 padding and finalization on a CLONE of the running
; state, so the transcript can continue to accept more data afterward.
; =============================================================================
tls_transcript_hash:
    ; Step 1: Save running state (will be restored at the end)
    ldx #31
:   lda tls_transcript_h0,x
    sta tls_transcript_save,x
    dex
    bpl :-

    ; Step 2: Restore running state to SHA-256 working registers
    ldx #31
:   lda tls_transcript_h0,x
    sta sha256_h0,x
    dex
    bpl :-

    ; Step 3: Copy partial block to sha256_block, zero-fill the rest
    ; First, clear the entire block
    lda #0
    ldx #63
:   sta sha256_block,x
    dex
    bpl :-

    ; Copy the partial data
    ldx tls_transcript_block_len
    beq @add_padding              ; no partial data to copy
    dex
:   lda tls_transcript_block,x
    sta sha256_block,x
    dex
    bpl :-

@add_padding:
    ; Step 4a: Append 0x80 byte after data
    ldx tls_transcript_block_len
    lda #$80
    sta sha256_block,x

    ; Step 4b: Check if padding fits in this block
    ; Need room for 0x80 + 8 bytes of length = need block_len <= 55
    lda tls_transcript_block_len
    cmp #56
    bcc @pad_fits

    ; Block_len >= 56: not enough room for length field
    ; Process this block (with 0x80 and zeros), then use a fresh block for length
    jsr sha256_process_block

    ; Clear the new block
    lda #0
    ldx #63
:   sta sha256_block,x
    dex
    bpl :-

@pad_fits:
    ; Step 4c: Write total bit count at block[56..63] (big-endian 64-bit)
    ; Total bits = tls_transcript_total * 8
    ; Since total is 16-bit, bit count is at most 19 bits
    ; bit_count = (total_hi : total_lo) << 3
    ;
    ; 64-bit big-endian layout in block[56..63]:
    ;   block[56..60] = 0 (high 40 bits always zero for 19-bit value)
    ;   block[61]     = high byte of bit count >> 16 (bits 16-18)
    ;   block[62]     = mid byte of bit count (bits 8-15)
    ;   block[63]     = low byte of bit count (bits 0-7)

    ; Compute bit count = total * 8 (shift left 3)
    lda tls_transcript_total_lo
    asl                           ; *2
    sta sha256_block+63
    lda tls_transcript_total_hi
    rol
    sta sha256_block+62
    lda #0
    rol
    sta sha256_block+61

    lda sha256_block+63
    asl                           ; *4
    sta sha256_block+63
    lda sha256_block+62
    rol
    sta sha256_block+62
    lda sha256_block+61
    rol
    sta sha256_block+61

    lda sha256_block+63
    asl                           ; *8
    sta sha256_block+63
    lda sha256_block+62
    rol
    sta sha256_block+62
    lda sha256_block+61
    rol
    sta sha256_block+61

    ; Step 5: Process final padded block
    jsr sha256_process_block

    ; Step 6: Copy hash state to output
    jsr sha256_final

    ; Copy sha256_hash to tls_transcript
    ldx #31
:   lda sha256_hash,x
    sta tls_transcript,x
    dex
    bpl :-

    ; Step 8: Restore running state from save area
    ldx #31
:   lda tls_transcript_save,x
    sta tls_transcript_h0,x
    dex
    bpl :-

    rts
