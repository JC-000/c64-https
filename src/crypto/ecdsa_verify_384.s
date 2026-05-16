; =============================================================================
; ecdsa_verify_384.s - Phase 4a TLS-side P-384 verify dispatcher.
;
; Composes the dual-overlay swap dance + SHA-384 hashing + sibling
; ecdsa_verify_384 into a single entry callable from
; src/crypto/ecdsa_verify.s::ecdsa_verify when ecdsa_curve_id = 1.
;
; Call sequence (matches the design template at the top of
; src/crypto/shared/crypto_swap.s):
;
;   1. Parse the DER ECDSA signature out of tls_rec_buf into the BE
;      r/s slots of ecdsa_inputs_384 (48 B each, slots +0 and +48).
;   2. Copy the 48-byte big-endian server pubkey (X then Y) into
;      ecdsa_inputs_384 slots +144 and +192.
;
;      Phase 5 Fix B: src/data.s defines separate 48 B slots
;      ecdsa_pubkey_x_384 and ecdsa_pubkey_y_384 in CRYPTO_BSS;
;      src/tls_cert.s's cert handler dispatches on ecdsa_curve_id and
;      writes the P-384 pubkey into those slots when the leaf cert
;      advertises secp384r1.  The dispatcher reads from the _384 slots
;      for the verify input, leaving the contiguous 32 B P-256 packed
;      struct (r|s|h|Qx|Qy) intact for ecdsa_verify_256.
;   3. Build the TLS 1.3 §4.4.3 signed-content blob (130 bytes) at
;      $CA00 in tcp_recv_buf scratch RAM:
;        [0..63]    64 spaces (0x20)
;        [64..96]   "TLS 1.3, server CertificateVerify" (33 bytes)
;        [97]       0x00 separator
;        [98..129]  transcript hash (32 bytes — SHA-256)
;      tcp_recv_buf is idle during crypto and the chosen window
;      ($CA00..$CA81) sits well above both overlays' resident DATA
;      ranges (SHA overlay ends at $C411, curve overlay at $C9F7) so
;      it survives the swap.
;
;      Phase 5 Fix A: blob length is 130 bytes, not 146.  RFC 8446
;      §4.4.1 specifies the transcript-hash uses the negotiated cipher
;      suite's hash function — c64-https only negotiates
;      TLS_AES_128_GCM_SHA256, so the transcript is always 32 B SHA-256
;      regardless of the signature scheme.  The 46+33+1+32 = 130 layout
;      is what the server signed; padding to 48 B for SHA-384's digest
;      width would feed the verifier a different message than the one
;      the server hashed.  SHA-384(blob) still produces a 48 B digest
;      that is spliced into ecdsa_inputs_384[96..143] (h slot) — the
;      hash function and digest size for the signature itself are
;      independent from the transcript-hash function.
;   4. crypto_swap_to_p384_sha384 -> sha384_init / update / final.
;      sha384_digest (48 B BE) lands at $C3E1 in the SHA overlay's
;      resident DATA.
;   5. Splice digest into ecdsa_inputs_384[96..143] (h slot).
;   6. crypto_swap_to_p384_curve -> ecdsa_verify_384.
;      C=0 valid / C=1 invalid -- propagated to caller.
;
; Phase 5 note: c64-https only negotiates TLS_AES_128_GCM_SHA256, so
; the TLS 1.3 transcript-hash function is always SHA-256 (RFC 8446
; §4.4.1 ties transcript-hash to the cipher suite's hash, not to the
; signature_algorithm).  The signed-content blob therefore embeds a
; 32 B SHA-256 transcript verbatim (no padding), totalling 130 bytes.
; SHA-384 then hashes the 130 B blob and produces a 48 B digest that
; goes into ecdsa_inputs_384's h slot for the P-384 verifier.  The
; previous Phase 4a draft (146 B blob with the 32 B transcript zero-
; padded to 48 B) is superseded by Phase 5 Fix A.
;
; Overlay-resident symbols: the sibling overlay images
; (overlay-p384-sha384.bin / overlay-p384-curve.bin) are NOT linked
; into the c64-https PRG -- they're DMA'd in at runtime via
; crypto_swap_to_p384_*.  Their entry points and resident DATA
; addresses are therefore declared as numeric equates here (sourced
; from build/labels-p384-sha384.txt and build/labels-p384-curve.txt;
; pinned by cfg/p384-overlay-{sha384,curve}.cfg).  If the overlay
; images are rebuilt and the addresses move, this file's equates
; must be re-synced -- there is no link-time check.
;
; ZP usage: $3D-$44 (sha_src $3D/$3E, sha_len $3F/$40, sha_w_ptr
; $41/$42, sha_w_ptr2 $43/$44) -- per Phase 1.5 these slots are
; demonstrably unused by c64-https/ip65/UCI/fe25519/x25519/ECDSA
; bignum across the SHA-384 window, so no save/restore is required.
; Also clobbers $FB-$FC (zp_ptr) for DER walk and $FE-$FF (zp_count)
; via tls_rec_buf indirect access.
; =============================================================================

        .include "constants.inc"

        ; --- TLS-side state we read ---
        .import tls_rec_buf            ; CertificateVerify message buffer
        .import tls_transcript         ; 32 B running SHA-256 transcript
        .import ecdsa_pubkey_x_384     ; 48 B server pubkey X (Phase 5 Fix B)
        .import ecdsa_pubkey_y_384     ; 48 B server pubkey Y (Phase 5 Fix B)

        ; --- Overlay swap entry points (in main PRG, always-resident) ---
        .import crypto_swap_to_p384_sha384
        .import crypto_swap_to_p384_curve

        .export ecdsa_verify_384_tls

; -----------------------------------------------------------------------------
; Overlay-resident symbol equates (NOT linked from the main PRG).
; Sourced from build/labels-p384-sha384.txt + build/labels-p384-curve.txt.
; Both overlays load at $4200; their resident DATA lives at $C000+.
; -----------------------------------------------------------------------------

; SHA-384 overlay (banked into $4200 by crypto_swap_to_p384_sha384):
sha384_init     = $4200
sha384_update   = $4219
sha384_final    = $42D6
; SHA-384 resident DATA (lives at $C000+, survives curve overlay swap-in
; because the curve overlay's resident DATA starts at $C000 too -- the
; sha384_digest bytes are read between sha384_final and the curve swap):
sha384_digest   = $C3E1                ; 48 B BE digest output

; Curve / verify overlay (banked into $4200 by crypto_swap_to_p384_curve):
ecdsa_verify_384 = $5BDD
; Curve resident DATA:
ecdsa_inputs_384 = $C8D1                ; 240 B BE struct r|s|h|Qx|Qy

; -----------------------------------------------------------------------------
; ZP slots dedicated to SHA-384 (Phase 1.5).
; -----------------------------------------------------------------------------
sha_src         = $3D                  ; 2 B pointer to message bytes
sha_len         = $3F                  ; 2 B 16-bit length

; -----------------------------------------------------------------------------
; Signed-content blob staging address.  130 B in tcp_recv_buf scratch
; ($CA00..$CA81).  Phase 5 Fix A: shrunk from 146 B because the TLS 1.3
; transcript-hash is SHA-256 (32 B) not SHA-384 (48 B); see file header.
; -----------------------------------------------------------------------------
SIGNED_BLOB_ADDR = $CA00
SIGNED_BLOB_LEN  = 130                  ; 64 + 33 + 1 + 32 (RFC 8446 §4.4.3)

; Compile-time assertion: 64-space pad + label + sep + SHA-256 transcript = 130.
.assert (64 + 33 + 1 + 32) = SIGNED_BLOB_LEN, error, "P-384 signed-content blob length"


        .segment "CRYPTO_AUX_CODE"

; =============================================================================
; ecdsa_verify_384_tls - dispatcher entry, called from ecdsa_verify
;                        when ecdsa_curve_id = 1.
;
; Inputs (set up by the TLS layer before tls_handle_cert_verify reaches
; the P-384 short-circuit at src/tls_cert.s):
;   tls_rec_buf+0..3    handshake header (type=15, len)
;   tls_rec_buf+4..5    signature_scheme = 0x0503
;   tls_rec_buf+6..7    16-bit signature length (BE; high byte = 0)
;   tls_rec_buf+8..     DER-encoded ECDSA signature (SEQUENCE { r, s })
;   ecdsa_pubkey_x_384  48 B server pubkey X (BE, from cert; Phase 5 Fix B)
;   ecdsa_pubkey_y_384  48 B server pubkey Y (BE, from cert; Phase 5 Fix B)
;   tls_transcript      32 B SHA-256 transcript (Phase 4a placeholder --
;                       see CAVEAT in file header)
;
; Output: C=0 signature VALID, C=1 INVALID/malformed.
; =============================================================================
ecdsa_verify_384_tls:
        ; -----------------------------------------------------------------
        ; Step 0: zero out the full 240 B BE input struct so any failed
        ; intermediate step leaves a deterministic state (helps
        ; post-mortem DMA reads).
        ; -----------------------------------------------------------------
        lda #0
        ldx #0
@clr_struct:
        sta ecdsa_inputs_384,x
        inx
        cpx #240
        bne @clr_struct

        ; -----------------------------------------------------------------
        ; Step 1: parse DER signature into ecdsa_inputs_384[0..47] (r)
        ; and ecdsa_inputs_384[48..95] (s).  Both 48 B BE, right-aligned.
        ; The sig bytes start at tls_rec_buf+8.
        ; -----------------------------------------------------------------
        lda #<(tls_rec_buf+8)
        sta zp_ptr
        lda #>(tls_rec_buf+8)
        sta zp_ptr+1
        jsr parse_der_sig_384
        bcc @sig_parsed
        sec
        rts                             ; malformed DER -> propagate failure
@sig_parsed:

        ; -----------------------------------------------------------------
        ; Step 2: copy pubkey X -> ecdsa_inputs_384+144 (Qx slot, 48 B).
        ;         copy pubkey Y -> ecdsa_inputs_384+192 (Qy slot, 48 B).
        ; -----------------------------------------------------------------
        ldx #47
@copy_qx:
        lda ecdsa_pubkey_x_384,x
        sta ecdsa_inputs_384+144,x
        dex
        bpl @copy_qx

        ldx #47
@copy_qy:
        lda ecdsa_pubkey_y_384,x
        sta ecdsa_inputs_384+192,x
        dex
        bpl @copy_qy

        ; -----------------------------------------------------------------
        ; Step 3: build 146 B signed-content blob at SIGNED_BLOB_ADDR.
        ; -----------------------------------------------------------------
        ; [0..63] 64 spaces
        ldx #63
        lda #$20
@fill_spaces:
        sta SIGNED_BLOB_ADDR,x
        dex
        bpl @fill_spaces

        ; [64..96] 33-byte label "TLS 1.3, server CertificateVerify"
        ldx #32                         ; label is 33 bytes (index 0..32)
@copy_label:
        lda cv_label_384,x
        sta SIGNED_BLOB_ADDR+64,x
        dex
        bpl @copy_label

        ; [97] 0x00 separator
        lda #$00
        sta SIGNED_BLOB_ADDR+97

        ; [98..129] transcript hash (32 B SHA-256).  Phase 5 Fix A:
        ; copy the 32 B SHA-256 tls_transcript verbatim — no padding.
        ; The TLS 1.3 transcript-hash is bound to the cipher suite
        ; (SHA-256 via TLS_AES_128_GCM_SHA256), independent from the
        ; signature_algorithm's hash (SHA-384 here).  Padding to 48 B
        ; would feed the verifier a different message than the server
        ; signed.
        ldx #31
@copy_xcript:
        lda tls_transcript,x
        sta SIGNED_BLOB_ADDR+98,x
        dex
        bpl @copy_xcript

        ; -----------------------------------------------------------------
        ; Step 4: swap in SHA-384 overlay and hash the blob.
        ; -----------------------------------------------------------------
        jsr crypto_swap_to_p384_sha384

        jsr sha384_init

        lda #<SIGNED_BLOB_ADDR
        sta sha_src
        lda #>SIGNED_BLOB_ADDR
        sta sha_src+1
        lda #<SIGNED_BLOB_LEN
        sta sha_len
        lda #>SIGNED_BLOB_LEN
        sta sha_len+1
        jsr sha384_update

        jsr sha384_final                ; sha384_digest := SHA-384(blob)

        ; -----------------------------------------------------------------
        ; Step 5: splice digest into ecdsa_inputs_384[96..143] (h slot).
        ; sha384_digest survives the upcoming curve-overlay swap because
        ; the curve overlay's resident DATA also starts at $C000+ and
        ; doesn't write the $C3E1..$C411 range until ecdsa_verify_384
        ; runs -- and we copy out before triggering the swap.
        ; -----------------------------------------------------------------
        ldx #47
@splice_h:
        lda sha384_digest,x
        sta ecdsa_inputs_384+96,x
        dex
        bpl @splice_h

        ; -----------------------------------------------------------------
        ; Step 6: swap in curve / verify overlay and call ecdsa_verify_384.
        ; -----------------------------------------------------------------
        jsr crypto_swap_to_p384_curve

        lda #<ecdsa_inputs_384
        ldx #>ecdsa_inputs_384
        jmp ecdsa_verify_384            ; tail-call: C return passes through


; =============================================================================
; parse_der_sig_384 - Parse ASN.1 DER ECDSA signature into
; ecdsa_inputs_384[0..47] (r) and ecdsa_inputs_384[48..95] (s).
;
; Mirrors the in-tree ecdsa_parse_der_sig logic from ecdsa_verify.s but
; with 48-byte (P-384) component slots and writes into the absolute BE
; struct rather than the legacy ecdsa_sig_r/s 32 B labels.
;
; Input:  zp_ptr = pointer to SEQUENCE start.
; Output: ecdsa_inputs_384[0..47]   = r (BE, right-aligned, zero-padded)
;         ecdsa_inputs_384[48..95]  = s (BE, right-aligned, zero-padded)
;         C=0 success, C=1 malformed.
;
; DER format: 30 <len> 02 <r_len> <r_bytes> 02 <s_len> <s_bytes>
; INTEGERs may have a leading 0x00 padding byte if the high bit is set.
; =============================================================================

R384_LEN = 48
S384_OFFS = 48                          ; ecdsa_inputs_384[48..95] is s slot

parse_der_sig_384:
        ldy #0

        ; Expect SEQUENCE tag (0x30)
        lda (zp_ptr),y
        cmp #$30
        bne @der_error
        iny

        ; Skip SEQUENCE length byte (assume <= 127 -- short-form DER, true
        ; for any P-384 ECDSA signature whose total payload <= 110 B).
        iny

        ; --- Parse INTEGER r ---
        lda (zp_ptr),y
        cmp #$02
        bne @der_error
        iny
        lda (zp_ptr),y
        sta der_int_len_384
        iny

        ; r slot is already zero (Step 0 cleared all 240 B); just compute
        ; right-align offset and copy.
        jsr parse_int_r
        bcs @der_error

        ; --- Parse INTEGER s ---
        lda (zp_ptr),y
        cmp #$02
        bne @der_error
        iny
        lda (zp_ptr),y
        sta der_int_len_384
        iny
        jsr parse_int_s
        bcs @der_error

        clc
        rts

@der_error:
        sec
        rts


; ---------------------------------------------------------------------------
; parse_int_r - Copy DER INTEGER bytes into ecdsa_inputs_384[0..47].
;               Y advances over the parsed bytes (caller-visible).
;               Returns C=0 ok, C=1 malformed.
; ---------------------------------------------------------------------------
parse_int_r:
        lda der_int_len_384
        cmp #R384_LEN+1                 ; 49: leading-zero pad case
        beq @r_skip_pad
        cmp #R384_LEN+1
        bcs @der_int_too_long
        bcc @r_no_pad
@r_skip_pad:
        ; int_len = 49 -> consume one leading 0x00 padding byte.
        lda (zp_ptr),y
        bne @der_int_too_long           ; pad byte must be zero
        iny
        lda #R384_LEN
        sta der_int_len_384
@r_no_pad:
        ; int_len <= 48: right-align into ecdsa_inputs_384[0..47].
        ; dest start offset = 48 - int_len.
        sec
        lda #R384_LEN
        sbc der_int_len_384
        tax                             ; X = dest offset
        lda der_int_len_384
        sta der_copy_cnt_384
@r_copy:
        lda der_copy_cnt_384
        beq @r_done
        lda (zp_ptr),y
        sta ecdsa_inputs_384+0,x
        iny
        inx
        dec der_copy_cnt_384
        jmp @r_copy
@r_done:
        clc
        rts
@der_int_too_long:
        sec
        rts


; ---------------------------------------------------------------------------
; parse_int_s - Copy DER INTEGER bytes into ecdsa_inputs_384[48..95].
;               Y advances over the parsed bytes.  Returns C=0/1 same as
;               parse_int_r.
; ---------------------------------------------------------------------------
parse_int_s:
        lda der_int_len_384
        cmp #R384_LEN+1
        beq @s_skip_pad
        bcs @der_int_too_long_s
        bcc @s_no_pad
@s_skip_pad:
        lda (zp_ptr),y
        bne @der_int_too_long_s
        iny
        lda #R384_LEN
        sta der_int_len_384
@s_no_pad:
        sec
        lda #R384_LEN
        sbc der_int_len_384
        tax
        lda der_int_len_384
        sta der_copy_cnt_384
@s_copy:
        lda der_copy_cnt_384
        beq @s_done
        lda (zp_ptr),y
        sta ecdsa_inputs_384+S384_OFFS,x
        iny
        inx
        dec der_copy_cnt_384
        jmp @s_copy
@s_done:
        clc
        rts
@der_int_too_long_s:
        sec
        rts


; =============================================================================
; RODATA -- the 33-byte signed-content context string.
; =============================================================================
        .segment "CRYPTO_RODATA"

cv_label_384:
        .byte "TLS 1.3, server CertificateVerify"
.assert (* - cv_label_384) = 33, error, "P-384 CV label must be 33 bytes"


; =============================================================================
; BSS -- DER parser scratch.
; =============================================================================
        .segment "BSS"

der_int_len_384:  .res 1
der_copy_cnt_384: .res 1
