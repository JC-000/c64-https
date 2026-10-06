; =============================================================================
; src/session_scrub.s — zero the TLS session's secrets before 'Q' quits.
;
; boot.s's quit path calls this before handing the machine back to BASIC.
; Everything below outlives the connection that wrote it, and after 'Q'
; anything may read it: the next program, a freezer cartridge, or anyone on
; the LAN with the Ultimate's REST readmem. Each span is a session secret or
; scratch that held one:
;
;   tls_ecdhe_privkey..tls_shared_secret  ECDHE private key + shared secret
;                                         (the two public keys between them)
;   tls_hs_write_key..tls_app_read_iv     handshake + application keys/IVs
;   tls_nonce                             last per-record nonce (IV ^ seq)
;   hkdf_prk..hkdf_okm                    HKDF PRK / output
;   tls_early_secret..tls_master_secret   key-schedule secrets
;   tls_c_hs_secret..tls_finished_key     traffic secrets, finished key
;   sha256_h0..mul_src2_buf               SHA-256 state and schedule (keyed
;                                         by HMAC), the HMAC key input (HKDF
;                                         and the Finished MAC key it), DRBG
;                                         V and output, ChaCha20
;                                         key + keystream, Poly1305 r/s,
;                                         AEAD key, last multiply operand
;   tls_rec_buf                           last decrypted record, and the
;                                         X25519 sibling's whole scratch
;                                         (x25_scalar = clamped private key,
;                                         x25_result = shared secret): the
;                                         cfg overlays X25519_SCRATCH on it,
;                                         asserted in src/crypto/x25519_tables.s
;   zp_save_buf                           ip65's copy of crypto ZP $02-$1B
;   poly_prod_lo/hi                       last 8x8 product (Poly1305: key r)
;   mul_dma_lo/hi                         last multiply row: a*b for every b,
;                                         i.e. one operand byte (X25519's on
;                                         a handshake that stopped before
;                                         CertificateVerify)
;
; The multi-buffer spans zero whatever their module declares between the
; two ends, so each length is asserted exactly: a field added inside a span
; fails the link here, and whoever added it decides whether it is session
; state or must survive 'Q'.
;
; The DRBG's K is not in any span: it is private to src/crypto/hmac_drbg.s
; (tools/test_drbg_state_owner.py forbids naming it elsewhere). The tail
; call to drbg_init_entropy is what scrubs it -- instantiate sets K = 0,
; V = 1, then updates both from fresh SID/CIA entropy, exactly as boot does
; -- so it is not redundant with the spans. It is also what keeps a caller
; that SYSes back in after 'Q' (every tools/uci rig that drives http_get)
; from drawing all-zero "random" bytes out of the zeroed V and drbg_output:
; it sets drbg_buf_idx = 32. The state left behind is fresh, and no longer
; a function of the session.
;
; Not scrubbed, because none of it is key material: certificates
; (cert_buf), signature-verify scratch (LIB_NISTCURVES_P256_BSS: every input
; is public), the transcript hash, randoms, public keys, generated tables,
; the TCP ring (ciphertext), and the application data -- http_req_buf (the
; request, with the typed path), http_resp_buf (the response the screen
; shows, and possibly the typed path, which the prompt stages there) and, under
; HTTPS_BODY_TO_REU, the body in REU bank $10.
;
; A secret buffer added OUTSIDE every span below is left unscrubbed, and
; nothing fails: add a SPAN for it (tools/test_quit_basic_exit.py's ZEROED
; list is the test side).
;
; In:  BASIC ROM banked OUT -- the zeroing would reach RAM either way, but
;      the re-seed reads its state back through $A000-$BFFF.
; Out: Clobbers A, X, Y and crypto ZP (zp_ptr, zp_count, SHA temps); the
;      caller zeroes ZP afterwards.
; Segment: CODE (LOADER) -- never under the ROM the caller is about to map in.
; =============================================================================

        .include "constants.inc"

        .export session_scrub

        .import tls_ecdhe_privkey, tls_shared_secret
        .import tls_hs_write_key, tls_app_read_iv
        .import tls_nonce
        .import hkdf_prk, hkdf_okm
        .import tls_early_secret, tls_master_secret
        .import tls_c_hs_secret, tls_finished_key
        .import sha256_h0, mul_src2_buf
        .import tls_rec_buf
        .import zp_save_buf
        .import poly_prod_lo, poly_prod_hi
        .import mul_dma_lo, mul_dma_hi
        .import drbg_init_entropy

; SPAN first, end, len: zero [first, end), which must be len bytes long.
.macro SPAN first, end, len
        .word first
        .word len
        .assert (end) - (first) = len, lderror, .sprintf("session_scrub: span at %s is not %d bytes; review what was added inside it", .string(first), len)
.endmacro

        .segment "CODE"

session_scrub:
        ldx #0
@span:
        lda scrub_spans,x
        sta zp_ptr
        lda scrub_spans+1,x
        sta zp_ptr+1
        lda scrub_spans+2,x
        sta zp_count
        lda scrub_spans+3,x
        sta zp_count+1
        ldy #0
@byte:
        lda #0
        sta (zp_ptr),y
        iny
        bne @count
        inc zp_ptr+1
@count:
        lda zp_count            ; 16-bit decrement; every length is > 0
        bne @lo
        dec zp_count+1
@lo:
        dec zp_count
        lda zp_count
        ora zp_count+1
        bne @byte
        inx
        inx
        inx
        inx
        cpx #scrub_spans_end - scrub_spans
        bne @span
        ; NOT redundant: this is the ONLY scrub of the DRBG's K (drbg_k,
        ; private to hmac_drbg.s, in no span). Re-instantiates K/V from
        ; fresh entropy and sets drbg_buf_idx = 32. See the header.
        jmp drbg_init_entropy

scrub_spans:
        SPAN tls_ecdhe_privkey, tls_shared_secret + 32, 128
        SPAN tls_hs_write_key,  tls_app_read_iv + 12,   176
        SPAN tls_nonce,         tls_nonce + 12,         12
        SPAN hkdf_prk,          hkdf_okm + 32,          64
        SPAN tls_early_secret,  tls_master_secret + 32, 96
        SPAN tls_c_hs_secret,   tls_finished_key + 32,  160
        SPAN sha256_h0,         mul_src2_buf + 35,      1243
        SPAN tls_rec_buf,       tls_rec_buf + 548,      548
        SPAN zp_save_buf,       zp_save_buf + 26,       26
        SPAN poly_prod_lo,      poly_prod_hi + 1,       2
        SPAN mul_dma_lo,        mul_dma_hi + 256,       512
scrub_spans_end:
