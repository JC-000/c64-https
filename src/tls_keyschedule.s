; tls_keyschedule.s — TLS 1.3 HKDF key derivation
; Converted from ACME to ca65 in Phase 3 Batch B.
;
; Implements RFC 8446 §7.1 key schedule:
;   - tls_derive_handshake_keys: ECDHE → handshake traffic keys
;   - tls_derive_traffic_keys: handshake secret → application traffic keys
;   - tls_compute_finished: compute Finished verify_data
;   - tls_verify_finished: verify server's Finished message
;
; Dependencies: hkdf.s (hkdf_extract, hkdf_expand_label, tls_derive_secret)
;               hmac_sha256 from crypto/hmac_drbg.s
;               data.asm (all BSS buffer labels)

.include "constants.inc"

.export tls_derive_handshake_keys
.export tls_derive_traffic_keys
.export tls_compute_finished
.export tls_verify_finished
.export tls_verify_data
.export tls_c_hs_secret

; HKDF primitives (hkdf.s)
.import hkdf_extract
.import hkdf_expand_label
.import tls_derive_secret

; HMAC primitive (crypto/hmac_drbg.s)
.import hmac_sha256

; HKDF BSS state (data.asm)
.import hkdf_prk
.import hkdf_okm
.import hkdf_salt_ptr
.import hkdf_salt_len
.import hkdf_ikm_ptr
.import hkdf_ikm_len
.import hkdf_label_ptr
.import hkdf_label_len
.import hkdf_context_ptr
.import hkdf_context_len
.import hkdf_out_len

; TLS state / buffers (data.asm)
.import tls_shared_secret
.import tls_transcript
.import tls_early_secret
.import tls_handshake_secret
.import tls_master_secret
.import tls_hs_write_key
.import tls_hs_write_iv
.import tls_hs_read_key
.import tls_hs_read_iv
.import tls_app_write_key
.import tls_app_write_iv
.import tls_app_read_key
.import tls_app_read_iv
.import tls_rec_buf
.import input_buffer

; HMAC BSS state (data.asm)
.import hmac_key
.import hmac_data_buf
.import hmac_data_len
.import hmac_result

; =============================================================================
; tls_derive_handshake_keys
; Derive handshake traffic keys from ECDH shared secret
;
; Input: tls_shared_secret (32 bytes) = x25519 result
;        tls_transcript (32 bytes) = hash of ClientHello || ServerHello
; Output: tls_hs_write_key/iv, tls_hs_read_key/iv filled
;         tls_handshake_secret saved for later use
;         tls_early_secret saved for reference
;
; Key schedule (RFC 8446 §7.1):
;   1. early_secret = HKDF-Extract(salt=0x00*32, IKM=0x00*32)
;   2. derived = Derive-Secret(early_secret, "derived", empty_hash)
;   3. handshake_secret = HKDF-Extract(salt=derived, IKM=shared_secret)
;   4. c_hs_traffic = Derive-Secret(hs_secret, "c hs traffic", transcript)
;   5. s_hs_traffic = Derive-Secret(hs_secret, "s hs traffic", transcript)
;   6. client_hs_key = HKDF-Expand-Label(c_hs_traffic, "key", "", 32)
;   7. client_hs_iv  = HKDF-Expand-Label(c_hs_traffic, "iv", "", 12)
;   8. server_hs_key = HKDF-Expand-Label(s_hs_traffic, "key", "", 32)
;   9. server_hs_iv  = HKDF-Expand-Label(s_hs_traffic, "iv", "", 12)
; =============================================================================
.segment "TLS_CODE"

tls_derive_handshake_keys:
        ; --- Step 1: early_secret = HKDF-Extract(salt=zeros, IKM=zeros) ---
        ; Write 32 zero bytes to input_buffer (salt) and input_buffer+32 (IKM)
        ldx #31
        lda #0
@dhk_z1:
        sta input_buffer,x
        sta input_buffer+32,x
        dex
        bpl @dhk_z1

        ; Set salt ptr/len
        lda #<input_buffer
        sta hkdf_salt_ptr
        lda #>input_buffer
        sta hkdf_salt_ptr+1
        lda #32
        sta hkdf_salt_len

        ; Set IKM ptr/len
        lda #<(input_buffer+32)
        sta hkdf_ikm_ptr
        lda #>(input_buffer+32)
        sta hkdf_ikm_ptr+1
        lda #32
        sta hkdf_ikm_len

        jsr hkdf_extract

        ; Copy hkdf_prk → tls_early_secret
        ldx #31
@dhk_c1:
        lda hkdf_prk,x
        sta tls_early_secret,x
        dex
        bpl @dhk_c1

        ; --- Step 2: derived = Derive-Secret(early_secret, "derived", empty_hash) ---
        ; hkdf_prk already contains early_secret from step 1
        ; Set label = "derived"
        lda #<lbl_derived
        sta hkdf_label_ptr
        lda #>lbl_derived
        sta hkdf_label_ptr+1
        lda #7                          ; "derived" = 7 bytes
        sta hkdf_label_len

        ; Set context = empty_hash (SHA-256 of empty string)
        lda #<empty_hash
        sta hkdf_context_ptr
        lda #>empty_hash
        sta hkdf_context_ptr+1
        lda #32
        sta hkdf_context_len
        sta hkdf_out_len

        jsr hkdf_expand_label
        ; hkdf_okm now has "derived" value

        ; --- Step 3: handshake_secret = HKDF-Extract(salt=derived, IKM=shared_secret) ---
        ; Copy derived (hkdf_okm) to tls_derived_tmp for use as salt
        ldx #31
@dhk_c2:
        lda hkdf_okm,x
        sta tls_derived_tmp,x
        dex
        bpl @dhk_c2

        ; Set salt = derived
        lda #<tls_derived_tmp
        sta hkdf_salt_ptr
        lda #>tls_derived_tmp
        sta hkdf_salt_ptr+1
        lda #32
        sta hkdf_salt_len

        ; Set IKM = shared_secret
        lda #<tls_shared_secret
        sta hkdf_ikm_ptr
        lda #>tls_shared_secret
        sta hkdf_ikm_ptr+1
        lda #32
        sta hkdf_ikm_len

        jsr hkdf_extract

        ; Copy hkdf_prk → tls_handshake_secret
        ldx #31
@dhk_c3:
        lda hkdf_prk,x
        sta tls_handshake_secret,x
        dex
        bpl @dhk_c3

        ; --- Step 4: c_hs_traffic = Derive-Secret(hs_secret, "c hs traffic", transcript) ---
        ; hkdf_prk already contains handshake_secret
        lda #<lbl_c_hs_traffic
        sta hkdf_label_ptr
        lda #>lbl_c_hs_traffic
        sta hkdf_label_ptr+1
        lda #12                         ; "c hs traffic" = 12 bytes
        sta hkdf_label_len

        jsr tls_derive_secret
        ; tls_derive_secret uses tls_transcript as context automatically

        ; Save c_hs_traffic secret
        ldx #31
@dhk_c4:
        lda hkdf_okm,x
        sta tls_c_hs_secret,x
        dex
        bpl @dhk_c4

        ; --- Step 5: s_hs_traffic = Derive-Secret(hs_secret, "s hs traffic", transcript) ---
        ; Restore hkdf_prk = handshake_secret (tls_derive_secret clobbered it)
        ldx #31
@dhk_c5a:
        lda tls_handshake_secret,x
        sta hkdf_prk,x
        dex
        bpl @dhk_c5a

        lda #<lbl_s_hs_traffic
        sta hkdf_label_ptr
        lda #>lbl_s_hs_traffic
        sta hkdf_label_ptr+1
        lda #12                         ; "s hs traffic" = 12 bytes
        sta hkdf_label_len

        jsr tls_derive_secret

        ; Save s_hs_traffic secret
        ldx #31
@dhk_c5:
        lda hkdf_okm,x
        sta tls_s_hs_secret,x
        dex
        bpl @dhk_c5

        ; --- Step 6: client_hs_key = HKDF-Expand-Label(c_hs_traffic, "key", "", 32) ---
        ldx #31
@dhk_c6:
        lda tls_c_hs_secret,x
        sta hkdf_prk,x
        dex
        bpl @dhk_c6

        lda #<lbl_key
        sta hkdf_label_ptr
        lda #>lbl_key
        sta hkdf_label_ptr+1
        lda #3                          ; "key" = 3 bytes
        sta hkdf_label_len

        lda #<empty_context
        sta hkdf_context_ptr
        lda #>empty_context
        sta hkdf_context_ptr+1
        lda #0
        sta hkdf_context_len
        lda #32
        sta hkdf_out_len

        jsr hkdf_expand_label

        ; Copy hkdf_okm → tls_hs_write_key
        ldx #31
@dhk_c6b:
        lda hkdf_okm,x
        sta tls_hs_write_key,x
        dex
        bpl @dhk_c6b

        ; --- Step 7: client_hs_iv = HKDF-Expand-Label(c_hs_traffic, "iv", "", 12) ---
        ldx #31
@dhk_c7:
        lda tls_c_hs_secret,x
        sta hkdf_prk,x
        dex
        bpl @dhk_c7

        lda #<lbl_iv
        sta hkdf_label_ptr
        lda #>lbl_iv
        sta hkdf_label_ptr+1
        lda #2                          ; "iv" = 2 bytes
        sta hkdf_label_len

        lda #<empty_context
        sta hkdf_context_ptr
        lda #>empty_context
        sta hkdf_context_ptr+1
        lda #0
        sta hkdf_context_len
        lda #12
        sta hkdf_out_len

        jsr hkdf_expand_label

        ; Copy first 12 bytes of hkdf_okm → tls_hs_write_iv
        ldx #11
@dhk_c7b:
        lda hkdf_okm,x
        sta tls_hs_write_iv,x
        dex
        bpl @dhk_c7b

        ; --- Step 8: server_hs_key = HKDF-Expand-Label(s_hs_traffic, "key", "", 32) ---
        ldx #31
@dhk_c8:
        lda tls_s_hs_secret,x
        sta hkdf_prk,x
        dex
        bpl @dhk_c8

        lda #<lbl_key
        sta hkdf_label_ptr
        lda #>lbl_key
        sta hkdf_label_ptr+1
        lda #3
        sta hkdf_label_len

        lda #<empty_context
        sta hkdf_context_ptr
        lda #>empty_context
        sta hkdf_context_ptr+1
        lda #0
        sta hkdf_context_len
        lda #32
        sta hkdf_out_len

        jsr hkdf_expand_label

        ; Copy hkdf_okm → tls_hs_read_key
        ldx #31
@dhk_c8b:
        lda hkdf_okm,x
        sta tls_hs_read_key,x
        dex
        bpl @dhk_c8b

        ; --- Step 9: server_hs_iv = HKDF-Expand-Label(s_hs_traffic, "iv", "", 12) ---
        ldx #31
@dhk_c9:
        lda tls_s_hs_secret,x
        sta hkdf_prk,x
        dex
        bpl @dhk_c9

        lda #<lbl_iv
        sta hkdf_label_ptr
        lda #>lbl_iv
        sta hkdf_label_ptr+1
        lda #2
        sta hkdf_label_len

        lda #<empty_context
        sta hkdf_context_ptr
        lda #>empty_context
        sta hkdf_context_ptr+1
        lda #0
        sta hkdf_context_len
        lda #12
        sta hkdf_out_len

        jsr hkdf_expand_label

        ; Copy first 12 bytes of hkdf_okm → tls_hs_read_iv
        ldx #11
@dhk_c9b:
        lda hkdf_okm,x
        sta tls_hs_read_iv,x
        dex
        bpl @dhk_c9b

        clc
        rts

; =============================================================================
; tls_derive_traffic_keys
; Derive application traffic keys from master secret
;
; Input: tls_handshake_secret (32 bytes) saved from handshake derivation
;        tls_transcript (32 bytes) = hash of ClientHello..ServerFinished
; Output: tls_app_write_key/iv, tls_app_read_key/iv filled
;         tls_master_secret saved
; =============================================================================
tls_derive_traffic_keys:
        ; --- Step 1: derived = Derive-Secret(handshake_secret, "derived", empty_hash) ---
        ldx #31
@dtk_c1:
        lda tls_handshake_secret,x
        sta hkdf_prk,x
        dex
        bpl @dtk_c1

        lda #<lbl_derived
        sta hkdf_label_ptr
        lda #>lbl_derived
        sta hkdf_label_ptr+1
        lda #7
        sta hkdf_label_len

        lda #<empty_hash
        sta hkdf_context_ptr
        lda #>empty_hash
        sta hkdf_context_ptr+1
        lda #32
        sta hkdf_context_len
        sta hkdf_out_len

        jsr hkdf_expand_label

        ; Save derived to tls_derived_tmp
        ldx #31
@dtk_c1b:
        lda hkdf_okm,x
        sta tls_derived_tmp,x
        dex
        bpl @dtk_c1b

        ; --- Step 2: master_secret = HKDF-Extract(salt=derived, IKM=zeros) ---
        ; Set salt = derived
        lda #<tls_derived_tmp
        sta hkdf_salt_ptr
        lda #>tls_derived_tmp
        sta hkdf_salt_ptr+1
        lda #32
        sta hkdf_salt_len

        ; Write 32 zero bytes for IKM
        ldx #31
        lda #0
@dtk_z1:
        sta input_buffer,x
        dex
        bpl @dtk_z1

        lda #<input_buffer
        sta hkdf_ikm_ptr
        lda #>input_buffer
        sta hkdf_ikm_ptr+1
        lda #32
        sta hkdf_ikm_len

        jsr hkdf_extract

        ; Copy hkdf_prk → tls_master_secret
        ldx #31
@dtk_c2:
        lda hkdf_prk,x
        sta tls_master_secret,x
        dex
        bpl @dtk_c2

        ; --- Step 3: c_ap_traffic = Derive-Secret(master_secret, "c ap traffic", transcript) ---
        ; hkdf_prk already contains master_secret
        lda #<lbl_c_ap_traffic
        sta hkdf_label_ptr
        lda #>lbl_c_ap_traffic
        sta hkdf_label_ptr+1
        lda #12                         ; "c ap traffic" = 12 bytes
        sta hkdf_label_len

        jsr tls_derive_secret

        ; Save c_ap_traffic secret
        ldx #31
@dtk_c3:
        lda hkdf_okm,x
        sta tls_c_hs_secret,x          ; reuse temp buffer for client traffic
        dex
        bpl @dtk_c3

        ; --- Step 4: s_ap_traffic = Derive-Secret(master_secret, "s ap traffic", transcript) ---
        ; Restore hkdf_prk = master_secret
        ldx #31
@dtk_c4a:
        lda tls_master_secret,x
        sta hkdf_prk,x
        dex
        bpl @dtk_c4a

        lda #<lbl_s_ap_traffic
        sta hkdf_label_ptr
        lda #>lbl_s_ap_traffic
        sta hkdf_label_ptr+1
        lda #12                         ; "s ap traffic" = 12 bytes
        sta hkdf_label_len

        jsr tls_derive_secret

        ; Save s_ap_traffic secret
        ldx #31
@dtk_c4:
        lda hkdf_okm,x
        sta tls_s_hs_secret,x          ; reuse temp buffer for server traffic
        dex
        bpl @dtk_c4

        ; --- Step 5: client_app_key = HKDF-Expand-Label(c_ap_traffic, "key", "", 32) ---
        ldx #31
@dtk_c5:
        lda tls_c_hs_secret,x
        sta hkdf_prk,x
        dex
        bpl @dtk_c5

        lda #<lbl_key
        sta hkdf_label_ptr
        lda #>lbl_key
        sta hkdf_label_ptr+1
        lda #3
        sta hkdf_label_len

        lda #<empty_context
        sta hkdf_context_ptr
        lda #>empty_context
        sta hkdf_context_ptr+1
        lda #0
        sta hkdf_context_len
        lda #32
        sta hkdf_out_len

        jsr hkdf_expand_label

        ; Copy hkdf_okm → tls_app_write_key
        ldx #31
@dtk_c5b:
        lda hkdf_okm,x
        sta tls_app_write_key,x
        dex
        bpl @dtk_c5b

        ; --- Step 6: client_app_iv = HKDF-Expand-Label(c_ap_traffic, "iv", "", 12) ---
        ldx #31
@dtk_c6:
        lda tls_c_hs_secret,x
        sta hkdf_prk,x
        dex
        bpl @dtk_c6

        lda #<lbl_iv
        sta hkdf_label_ptr
        lda #>lbl_iv
        sta hkdf_label_ptr+1
        lda #2
        sta hkdf_label_len

        lda #<empty_context
        sta hkdf_context_ptr
        lda #>empty_context
        sta hkdf_context_ptr+1
        lda #0
        sta hkdf_context_len
        lda #12
        sta hkdf_out_len

        jsr hkdf_expand_label

        ; Copy first 12 bytes of hkdf_okm → tls_app_write_iv
        ldx #11
@dtk_c6b:
        lda hkdf_okm,x
        sta tls_app_write_iv,x
        dex
        bpl @dtk_c6b

        ; --- Step 7: server_app_key = HKDF-Expand-Label(s_ap_traffic, "key", "", 32) ---
        ldx #31
@dtk_c7:
        lda tls_s_hs_secret,x
        sta hkdf_prk,x
        dex
        bpl @dtk_c7

        lda #<lbl_key
        sta hkdf_label_ptr
        lda #>lbl_key
        sta hkdf_label_ptr+1
        lda #3
        sta hkdf_label_len

        lda #<empty_context
        sta hkdf_context_ptr
        lda #>empty_context
        sta hkdf_context_ptr+1
        lda #0
        sta hkdf_context_len
        lda #32
        sta hkdf_out_len

        jsr hkdf_expand_label

        ; Copy hkdf_okm → tls_app_read_key
        ldx #31
@dtk_c7b:
        lda hkdf_okm,x
        sta tls_app_read_key,x
        dex
        bpl @dtk_c7b

        ; --- Step 8: server_app_iv = HKDF-Expand-Label(s_ap_traffic, "iv", "", 12) ---
        ldx #31
@dtk_c8:
        lda tls_s_hs_secret,x
        sta hkdf_prk,x
        dex
        bpl @dtk_c8

        lda #<lbl_iv
        sta hkdf_label_ptr
        lda #>lbl_iv
        sta hkdf_label_ptr+1
        lda #2
        sta hkdf_label_len

        lda #<empty_context
        sta hkdf_context_ptr
        lda #>empty_context
        sta hkdf_context_ptr+1
        lda #0
        sta hkdf_context_len
        lda #12
        sta hkdf_out_len

        jsr hkdf_expand_label

        ; Copy first 12 bytes of hkdf_okm → tls_app_read_iv
        ldx #11
@dtk_c8b:
        lda hkdf_okm,x
        sta tls_app_read_iv,x
        dex
        bpl @dtk_c8b

        ; Explicit success carry: tls_connect's `bcc @ok10` branch depends
        ; on the carry flag, and none of the HKDF primitives above set or
        ; clear it deterministically on the success path.
        clc
        rts

; =============================================================================
; tls_compute_finished
; Compute Finished verify_data (RFC 8446 §4.4.4)
;
; Input: hkdf_prk = traffic secret (client or server handshake traffic secret)
;        tls_transcript = current transcript hash (32 bytes)
; Output: tls_verify_data (32 bytes)
;
; Algorithm:
;   finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", 32)
;   verify_data = HMAC-SHA256(finished_key, transcript_hash)
; =============================================================================
tls_compute_finished:
        ; --- Derive finished_key ---
        lda #<lbl_finished
        sta hkdf_label_ptr
        lda #>lbl_finished
        sta hkdf_label_ptr+1
        lda #8                          ; "finished" = 8 bytes
        sta hkdf_label_len

        lda #<empty_context
        sta hkdf_context_ptr
        lda #>empty_context
        sta hkdf_context_ptr+1
        lda #0
        sta hkdf_context_len
        lda #32
        sta hkdf_out_len

        jsr hkdf_expand_label

        ; Save finished_key from hkdf_okm
        ldx #31
@cf_c1:
        lda hkdf_okm,x
        sta tls_finished_key,x
        dex
        bpl @cf_c1

        ; --- Compute verify_data = HMAC-SHA256(finished_key, transcript) ---
        ; Copy finished_key → hmac_key
        ldx #31
@cf_c2:
        lda tls_finished_key,x
        sta hmac_key,x
        dex
        bpl @cf_c2

        ; Copy tls_transcript → hmac_data_buf
        ldx #31
@cf_c3:
        lda tls_transcript,x
        sta hmac_data_buf,x
        dex
        bpl @cf_c3

        ; Set data length = 32 (transcript hash is always 32 bytes)
        lda #32
        sta hmac_data_len

        jsr hmac_sha256

        ; Copy hmac_result → tls_verify_data
        ldx #31
@cf_c4:
        lda hmac_result,x
        sta tls_verify_data,x
        dex
        bpl @cf_c4

        rts

; =============================================================================
; tls_verify_finished
; Verify server's Finished message
;
; Input: tls_s_hs_secret = server handshake traffic secret
;        tls_transcript = transcript hash up to (but not including) Finished
;        tls_rec_buf+4 = received verify_data (32 bytes, after 4-byte HS header)
; Output: C=0 if match (server Finished is valid)
;         C=1 if mismatch (verification failed)
;
; Computes expected verify_data and compares with received (constant-time).
; =============================================================================
tls_verify_finished:
        ; Set hkdf_prk = server handshake traffic secret
        ldx #31
@vf_c1:
        lda tls_s_hs_secret,x
        sta hkdf_prk,x
        dex
        bpl @vf_c1

        ; Compute expected Finished
        jsr tls_compute_finished

        ; Constant-time comparison of tls_verify_data vs tls_rec_buf+4
        ; Accumulate differences in A (OR of all XOR bytes)
        lda #0
        sta zp_tmp1                     ; clear accumulator
        tax                             ; X = index
@vf_cmp:
        lda tls_verify_data,x
        eor tls_rec_buf+4,x
        ora zp_tmp1                     ; accumulate differences
        sta zp_tmp1
        inx
        cpx #32
        bne @vf_cmp

        ; Check result: zp_tmp1 = 0 means match
        lda zp_tmp1
        beq @vf_match

        ; Mismatch
        sec
        rts

@vf_match:
        clc
        rts

; =============================================================================
; Inline data constants
; =============================================================================
.segment "RODATA"

; SHA-256 of empty string (used for Derive-Secret with empty messages)
empty_hash:
        .byte $e3,$b0,$c4,$42,$98,$fc,$1c,$14,$9a,$fb,$f4,$c8,$99,$6f,$b9,$24
        .byte $27,$ae,$41,$e4,$64,$9b,$93,$4c,$a4,$95,$99,$1b,$78,$52,$b8,$55

; Key schedule label strings (without "tls13 " prefix — added by hkdf_expand_label)
lbl_derived:        .byte "derived"
lbl_c_hs_traffic:   .byte "c hs traffic"
lbl_s_hs_traffic:   .byte "s hs traffic"
lbl_c_ap_traffic:   .byte "c ap traffic"
lbl_s_ap_traffic:   .byte "s ap traffic"
lbl_key:            .byte "key"
lbl_iv:             .byte "iv"
lbl_finished:       .byte "finished"

; Empty context pointer (for HKDF-Expand-Label with context="")
; Points here but context_len=0, so no bytes are read
empty_context:

; =============================================================================
; Temporary storage for traffic secrets (not in data.asm to avoid cross-file
; dependencies — these are only needed during key derivation)
; =============================================================================
.segment "BSS"

tls_c_hs_secret:    .res 32        ; client handshake/application traffic secret
tls_s_hs_secret:    .res 32        ; server handshake/application traffic secret
tls_derived_tmp:    .res 32        ; "derived" intermediate value
tls_verify_data:    .res 32        ; computed Finished verify_data
tls_finished_key:   .res 32        ; HKDF-Expand-Label(..., "finished", ...)
