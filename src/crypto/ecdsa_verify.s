; =============================================================================
; ecdsa_verify.s - Thin TLS-facing dispatcher over sibling c64-nist-curves.
;
; Phase C.4 rewrite. The in-tree P-256 primitives
; (ecdsa_{points,fp,mod,curve}.s) have been removed from the link; this file
; now just packs the TLS layer's BE state buffers into the 160-byte flat
; struct expected by the sibling's `ecdsa_verify_256` and forwards its
; carry flag.  DER signature parsing remains in-tree (same format as before).
;
; Inputs provided by TLS cert handler (big-endian, 32 bytes each):
;   ecdsa_hash, ecdsa_sig_r, ecdsa_sig_s, ecdsa_pubkey_x, ecdsa_pubkey_y
; Plus: ecdsa_curve_id (0 = P-256, 1 = P-384), ecdsa_sig_len, ecdsa_hash_len.
;
; Output: C=0 signature VALID, C=1 INVALID or unsupported curve.
;
; Phase 4a: P-384 dispatch jumps to ecdsa_verify_384_tls in
; src/crypto/ecdsa_verify_384.s, which composes the dual-overlay swap
; (sha384 -> curve) plus sibling ecdsa_verify_384.  See that file's
; header for the per-step contract and the SHA-384 transcript caveat.
; =============================================================================

.include "constants.inc"

; --- External sibling (c64-nist-curves) entry points ---
.import ecdsa_verify_256
.import ec_scalar_mul_var
.import ec_gx256, ec_gy256
.import ec_base_x, ec_base_y

; --- c64-lib-contract §1/§5: sibling version floor, checked at link time ---
; Two things depend on the pin being >= v0.9.0 and NEITHER fails loudly by
; itself, which is why this assert exists rather than a comment:
;
;   - v0.7.0's FIPS 186-5 §3.3 public-key validation gate. The Q packed
;     below reaches `ecdsa_verify_256` straight out of an attacker-supplied
;     certificate (src/tls_cert.s -> ecdsa_pubkey_x/y) and c64-https performs
;     no range or on-curve check of its own. Silently dropping back to a
;     pre-v0.7.0 archive would reopen that gap with every test still green,
;     because our KAT vectors all carry well-formed public keys.
;
;   - v0.9.0's per-variant `zp_config_<variant>.o`, which
;     tools/integration/build_nistcurves_p256.sh locates by name in order to
;     re-apply c64-https's ZP overrides. Against an older archive that lookup
;     changes shape.
;
; From v0.9.0 the version equates are exported `:abs` (upstream #95/#96), so
; importing them here costs no `ld65: Warning: Address size mismatch`.
.import LIB_NISTCURVES_VERSION_MAJOR
.import LIB_NISTCURVES_VERSION_MINOR
.assert LIB_NISTCURVES_VERSION_MAJOR = 0, lderror, "libs/nistcurves: expected MAJOR 0"
.assert LIB_NISTCURVES_VERSION_MINOR >= 9, lderror, "libs/nistcurves: pin is older than v0.9.0"

; --- Phase 4a: P-384 TLS dispatcher (src/crypto/ecdsa_verify_384.s) ---
.import ecdsa_verify_384_tls

; --- State buffers (in-tree data.s) ---
.import ecdsa_curve_id
.import ecdsa_hash
.import ecdsa_sig_r
.import ecdsa_sig_s
.import ecdsa_sig_len
.import ecdsa_pubkey_x
.import ecdsa_pubkey_y

; 160-byte packed struct (SHADOW_BSS via CRYPTO_BSS below)
; ev_der_int_len / ev_der_copy_cnt retained for DER parser
.import ev_der_int_len
.import ev_der_copy_cnt

; --- Exports ---
.export ecdsa_verify
.export ecdsa_parse_der_sig
; Under the comb profile the sibling's points256_comb.o provides the
; real Lim-Lee ec_scalar_mul — the shim below (seed G, run the
; variable-base ladder) is only for no-comb archives.
.ifndef USE_NISTCURVES_COMB
.export ec_scalar_mul                   ; shim for sibling's Lim-Lee slot
.endif


.segment "CRYPTO_CODE"

; =============================================================================
; ecdsa_verify - curve dispatch (called from tls_cert.s)
; =============================================================================
ecdsa_verify:
        ; Boot banks out BASIC ROM before any crypto runs (src/boot.s
        ; writes $36 to $01); the legacy defensive re-bank here was
        ; redundant and has been removed to save bytes.
        lda ecdsa_curve_id
        beq @p256
        ; Phase 4a: P-384 dispatcher composes the dual-overlay swap
        ; (sha384 -> curve) + sibling ecdsa_verify_384.  Tail-call so
        ; the dispatcher's carry return propagates as our return.
        jmp ecdsa_verify_384_tls

@p256:
        ; The TLS-populated ecdsa_sig_r, ecdsa_sig_s, ecdsa_hash,
        ; ecdsa_pubkey_x, ecdsa_pubkey_y are laid out contiguously at 32 B
        ; each (see src/data.s), matching the r|s|h|Qx|Qy BE struct that
        ; the sibling's ecdsa_verify_256 ingests.  Just hand it the base.
        lda #<ecdsa_sig_r
        ldx #>ecdsa_sig_r
        jmp ecdsa_verify_256            ; carry = verify result, returns to caller


; =============================================================================
; ec_scalar_mul - shim providing the symbol name the sibling's
; ecdsa_verify_256 uses for fixed-base u1*G.  The sibling ships a real
; Lim-Lee 8-way comb implementation that depends on a 16 KB REU bank-2
; precompute table (built at boot by ec_precompute_256).  That precompute
; is not wired into c64-https; we skip it by redirecting the fixed-base
; call to the variable-base primitive with G pre-loaded as the base point.
; Slower (double-and-add instead of windowed comb), but correct and avoids
; dragging ~22 KB of Lim-Lee infrastructure into the PRG.
;
; ec_gx256/ec_gy256 and ec_base_x/ec_base_y are each declared as
; contiguous 32-byte slots (X then Y) in the sibling's data segments, so
; a single 64-byte copy loop suffices for both coordinates.
; =============================================================================
.ifndef USE_NISTCURVES_COMB
ec_scalar_mul:
        ldy #63
@cp_g:  lda ec_gx256,y                  ; also covers ec_gy256 at +32
        sta ec_base_x,y                 ; also covers ec_base_y at +32
        dey
        bpl @cp_g
        jmp ec_scalar_mul_var
.endif


; =============================================================================
; ecdsa_parse_der_sig - Parse ASN.1 DER ECDSA signature into ecdsa_sig_r/s.
;
; Input:  zp_ptr points at SEQUENCE start of the DER signature.
;         ecdsa_sig_len = 32 (P-256).
; Output: ecdsa_sig_r, ecdsa_sig_s filled (right-aligned, zero-padded BE).
;         C=0 on success, C=1 on malformed DER.
;
; DER format: SEQUENCE { INTEGER r, INTEGER s }
;   30 <len> 02 <r_len> <r_bytes> 02 <s_len> <s_bytes>
; INTEGERs may have a leading 0x00 padding byte if high bit is set.
;
; Body lifted verbatim from the pre-Phase-C.4 file; only `jsr fp_zero`
; calls replaced with an inline 48-byte clear (48 covers both P-256 and
; a future P-384 restore).
; =============================================================================
ecdsa_parse_der_sig:
        ldy #0

        ; Expect SEQUENCE tag (0x30)
        lda (zp_ptr),y
        cmp #$30
        beq :+
        jmp @der_error
:       iny

        ; Skip SEQUENCE length byte
        iny

        ; --- Parse first INTEGER (r) ---
        lda (zp_ptr),y
        cmp #$02
        beq :+
        jmp @der_error
:       iny

        lda (zp_ptr),y
        sta ev_der_int_len
        iny

        ; Clear ecdsa_sig_r (32 bytes).  Preserve Y (DER cursor).
        tya
        pha
        ldx #31
        lda #0
@clr_r: sta ecdsa_sig_r,x
        dex
        bpl @clr_r
        pla
        tay

@parse_r:
        lda ev_der_int_len
        cmp ecdsa_sig_len
        beq @r_no_pad
        bcc @r_short

        ; int_len > sig_len: skip leading zeros
        lda ev_der_int_len
        sec
        sbc ecdsa_sig_len
        tax
@r_skip_pad:
        iny
        dex
        bne @r_skip_pad
        lda ecdsa_sig_len
        sta ev_der_int_len
        jmp @r_no_pad

@r_short:
        ; int_len < sig_len: right-align (handled by dest offset below).

@r_no_pad:
        lda ecdsa_sig_len
        sec
        sbc ev_der_int_len
        tax
        lda ev_der_int_len
        sta ev_der_copy_cnt
@r_copy:
        lda ev_der_copy_cnt
        beq @parse_s_tag
        lda (zp_ptr),y
        sta ecdsa_sig_r,x
        iny
        inx
        dec ev_der_copy_cnt
        jmp @r_copy

@parse_s_tag:
        lda (zp_ptr),y
        cmp #$02
        bne @der_error
        iny

        lda (zp_ptr),y
        sta ev_der_int_len
        iny

        ; Clear ecdsa_sig_s (32 bytes).
        tya
        pha
        ldx #31
        lda #0
@clr_s: sta ecdsa_sig_s,x
        dex
        bpl @clr_s
        pla
        tay

@parse_s:
        lda ev_der_int_len
        cmp ecdsa_sig_len
        beq @s_no_pad
        bcc @s_short

        lda ev_der_int_len
        sec
        sbc ecdsa_sig_len
        tax
@s_skip_pad:
        iny
        dex
        bne @s_skip_pad
        lda ecdsa_sig_len
        sta ev_der_int_len
        jmp @s_no_pad

@s_short:

@s_no_pad:
        lda ecdsa_sig_len
        sec
        sbc ev_der_int_len
        tax
        lda ev_der_int_len
        sta ev_der_copy_cnt
@s_copy:
        lda ev_der_copy_cnt
        beq @der_ok
        lda (zp_ptr),y
        sta ecdsa_sig_s,x
        iny
        inx
        dec ev_der_copy_cnt
        jmp @s_copy

@der_ok:
        clc
        rts

@der_error:
        sec
        rts


; =============================================================================
; The 160-byte packed r|s|h|Qx|Qy struct required by ecdsa_verify_256 is
; composed in-place by the contiguous `ecdsa_sig_r`, `ecdsa_sig_s`,
; `ecdsa_hash`, `ecdsa_pubkey_x`, `ecdsa_pubkey_y` declarations in
; src/data.s (32 bytes each, in that order).  See data.s Phase C.4 note.
; =============================================================================
