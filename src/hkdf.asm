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
        ;
        ; TODO:
        ; 1. Copy salt to hmac_key (or zero-fill if empty)
        ; 2. Copy IKM to hmac_data_buf, set hmac_data_len
        ; 3. jsr hmac_sha256
        ; 4. Copy hmac_result to hkdf_prk
        rts

; =============================================================================
; hkdf_expand - HKDF-Expand(PRK, info, L) -> OKM
; Input: hkdf_prk (32 bytes) = pseudorandom key
;        hkdf_info_ptr/hkdf_info_len = context info
;        hkdf_out_len = desired output length (must be <= 32)
; Output: hkdf_okm (up to 32 bytes)
; =============================================================================
hkdf_expand:
        ; Since L <= 32 for TLS 1.3 / SHA-256, we only need T(1):
        ;   T(1) = HMAC-SHA256(PRK, info || 0x01)
        ;
        ; TODO:
        ; 1. Copy PRK to hmac_key
        ; 2. Copy info to hmac_data_buf
        ; 3. Append 0x01 byte
        ; 4. Set hmac_data_len = info_len + 1
        ; 5. jsr hmac_sha256
        ; 6. Copy first hkdf_out_len bytes of hmac_result to hkdf_okm
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
        ;   uint16 length          (hkdf_out_len, big-endian)
        ;   opaque label<7..255>   ("tls13 " || label)
        ;   opaque context<0..255> (context)
        ;
        ; Then call hkdf_expand(PRK, HkdfLabel, length)
        ;
        ; TODO:
        ; 1. hkdf_info_buf[0..1] = hkdf_out_len (big-endian)
        ; 2. hkdf_info_buf[2] = 6 + label_len (length of "tls13 " + label)
        ; 3. Copy "tls13 " (6 bytes) + label
        ; 4. hkdf_info_buf[next] = context_len
        ; 5. Copy context
        ; 6. Set hkdf_info_len = total constructed length
        ; 7. jsr hkdf_expand
        rts

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
