; =============================================================================
; hkdf.asm - HKDF-SHA256 (RFC 5869) for TLS 1.3 key derivation
;
; TLS 1.3 key schedule uses three HKDF operations:
;   HKDF-Extract(salt, IKM) = HMAC-SHA256(salt, IKM)
;   HKDF-Expand(PRK, info, L) = T(1) || T(2) || ... truncated to L bytes
;     where T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
;   HKDF-Expand-Label(Secret, Label, Context, Length) =
;     HKDF-Expand(Secret, HkdfLabel, Length)
;     where HkdfLabel = length(2) || "tls13 " || label || context
;
; For TLS 1.3 with SHA-256, L <= 32 always, so we only need T(1).
; This simplifies HKDF-Expand to a single HMAC call.
;
; Dependencies: hmac_sha256 from hmac_drbg.asm (HMAC-SHA256 primitive)
; =============================================================================

; =============================================================================
; hkdf_extract - HKDF-Extract(salt, IKM) -> PRK
; Input: hkdf_salt_ptr/hkdf_salt_len = salt (or zero-length for none)
;        hkdf_ikm_ptr/hkdf_ikm_len = input keying material
; Output: hkdf_prk (32 bytes)
; =============================================================================
hkdf_extract:
        ; HKDF-Extract = HMAC-SHA256(key=salt, data=IKM)
        ; If salt is empty, use 32 zero bytes as key.

        ; Step 1: Set up HMAC key from salt
        lda hkdf_salt_len
        beq .extract_zero_salt

        ; Non-empty salt: copy salt_len bytes via indirect addressing
        lda hkdf_salt_ptr
        sta zp_ptr
        lda hkdf_salt_ptr+1
        sta zp_ptr+1
        ldy #0
.extract_copy_salt:
        cpy hkdf_salt_len
        beq .extract_zero_rest
        lda (zp_ptr),y
        sta hmac_key,y
        iny
        bne .extract_copy_salt      ; always branches (salt_len < 256)

        ; Zero-fill remainder of hmac_key (32 - salt_len bytes)
.extract_zero_rest:
        cpy #32
        beq .extract_key_done
        lda #0
.extract_zero_loop:
        sta hmac_key,y
        iny
        cpy #32
        bne .extract_zero_loop
        beq .extract_key_done       ; always branches

        ; Empty salt: zero-fill all 32 bytes of hmac_key
.extract_zero_salt:
        ldx #31
        lda #0
.extract_zero_all:
        sta hmac_key,x
        dex
        bpl .extract_zero_all

.extract_key_done:
        ; Step 2: Copy IKM to hmac_data_buf
        lda hkdf_ikm_ptr
        sta zp_ptr
        lda hkdf_ikm_ptr+1
        sta zp_ptr+1
        ldy #0
        lda hkdf_ikm_len
        beq .extract_ikm_done
.extract_copy_ikm:
        lda (zp_ptr),y
        sta hmac_data_buf,y
        iny
        cpy hkdf_ikm_len
        bne .extract_copy_ikm
.extract_ikm_done:

        ; Step 3: Set data length and call HMAC
        lda hkdf_ikm_len
        sta hmac_data_len
        jsr hmac_sha256

        ; Step 4: Copy hmac_result to hkdf_prk
        ldx #31
.extract_copy_result:
        lda hmac_result,x
        sta hkdf_prk,x
        dex
        bpl .extract_copy_result
        rts

; =============================================================================
; hkdf_expand - HKDF-Expand(PRK, info, L) -> OKM
; Input: hkdf_prk (32 bytes) = pseudorandom key
;        hkdf_info_buf/hkdf_info_len = info data and length
;        hkdf_out_len = desired output length (must be <= 32)
; Output: hkdf_okm (up to 32 bytes)
; =============================================================================
hkdf_expand:
        ; Since L <= 32 for TLS 1.3 / SHA-256, we only need T(1):
        ;   T(1) = HMAC-SHA256(PRK, info || 0x01)

        ; Step 1: Copy hkdf_prk to hmac_key (32 bytes)
        ldx #31
.expand_copy_prk:
        lda hkdf_prk,x
        sta hmac_key,x
        dex
        bpl .expand_copy_prk

        ; Step 2: Copy hkdf_info_len bytes from hkdf_info_buf to hmac_data_buf
        ldy #0
        lda hkdf_info_len
        beq .expand_info_done
.expand_copy_info:
        lda hkdf_info_buf,y
        sta hmac_data_buf,y
        iny
        cpy hkdf_info_len
        bne .expand_copy_info
.expand_info_done:

        ; Step 3: Append 0x01 byte at end of info
        lda #$01
        sta hmac_data_buf,y

        ; Step 4: Set hmac_data_len = hkdf_info_len + 1
        lda hkdf_info_len
        clc
        adc #1
        sta hmac_data_len

        ; Step 5: Call HMAC-SHA256
        jsr hmac_sha256

        ; Step 6: Copy first hkdf_out_len bytes of hmac_result to hkdf_okm
        ldx hkdf_out_len
        beq .expand_done
        dex
.expand_copy_okm:
        lda hmac_result,x
        sta hkdf_okm,x
        dex
        bpl .expand_copy_okm
.expand_done:
        rts

; =============================================================================
; hkdf_expand_label - TLS 1.3 HKDF-Expand-Label
; Input: hkdf_prk (32 bytes) = secret
;        hkdf_label_ptr/hkdf_label_len = label string (WITHOUT "tls13 " prefix)
;        hkdf_context_ptr/hkdf_context_len = context (usually transcript hash)
;        hkdf_out_len = desired output length
; Output: hkdf_okm (up to 32 bytes)
; =============================================================================
hkdf_expand_label:
        ; Build HkdfLabel structure into hkdf_info_buf:
        ;   [0]      = 0x00 (high byte of output length)
        ;   [1]      = hkdf_out_len (low byte)
        ;   [2]      = 6 + label_len (label opaque length)
        ;   [3..8]   = "tls13 " prefix
        ;   [9..N]   = label bytes
        ;   [N+1]    = context_len
        ;   [N+2..M] = context bytes
        ;
        ; Uses X as absolute write index into hkdf_info_buf.
        ; Uses zp_count as source index for indirect copies.

        ; [0] = 0x00 (high byte of output length)
        lda #0
        sta hkdf_info_buf

        ; [1] = hkdf_out_len (low byte)
        lda hkdf_out_len
        sta hkdf_info_buf+1

        ; [2] = 6 + hkdf_label_len (label opaque length)
        lda hkdf_label_len
        clc
        adc #6
        sta hkdf_info_buf+2

        ; [3..8] = "tls13 " prefix (6 bytes)
        ldy #0
.elabel_copy_prefix:
        lda hkdf_tls13_prefix,y
        sta hkdf_info_buf+3,y
        iny
        cpy #6
        bne .elabel_copy_prefix

        ; X = 9 (next write position, absolute index into hkdf_info_buf)
        ldx #9

        ; Copy label_len bytes from (hkdf_label_ptr)
        lda hkdf_label_ptr
        sta zp_ptr
        lda hkdf_label_ptr+1
        sta zp_ptr+1
        lda hkdf_label_len
        beq .elabel_label_done
        ldy #0                      ; source index
.elabel_copy_label:
        lda (zp_ptr),y
        sta hkdf_info_buf,x
        iny
        inx
        cpy hkdf_label_len
        bne .elabel_copy_label
.elabel_label_done:

        ; Store context_len at current position
        lda hkdf_context_len
        sta hkdf_info_buf,x
        inx

        ; Copy context_len bytes from (hkdf_context_ptr)
        lda hkdf_context_ptr
        sta zp_ptr
        lda hkdf_context_ptr+1
        sta zp_ptr+1
        lda hkdf_context_len
        beq .elabel_ctx_done
        ldy #0                      ; source index
.elabel_copy_ctx:
        lda (zp_ptr),y
        sta hkdf_info_buf,x
        iny
        inx
        cpy hkdf_context_len
        bne .elabel_copy_ctx
.elabel_ctx_done:

        ; hkdf_info_len = X (total bytes written)
        stx hkdf_info_len

        ; Fall through to hkdf_expand
        jmp hkdf_expand

; =============================================================================
; tls_derive_secret - Derive-Secret(Secret, Label, Messages)
;   = HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), 32)
; Input: hkdf_prk = secret, label set, transcript hash in tls_transcript
; Output: hkdf_okm (32 bytes)
; =============================================================================
tls_derive_secret:
        ; Set context = transcript hash (32 bytes)
        lda #<tls_transcript
        sta hkdf_context_ptr
        lda #>tls_transcript
        sta hkdf_context_ptr+1
        lda #32
        sta hkdf_context_len
        sta hkdf_out_len
        jsr hkdf_expand_label
        rts

; =============================================================================
; Constant: "tls13 " prefix for labels
; =============================================================================
hkdf_tls13_prefix:
        !text "tls13 "          ; 6 bytes, no null terminator
