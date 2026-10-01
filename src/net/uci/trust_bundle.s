; src/net/uci/trust_bundle.s — check the signed trust bundle (#155 phase 2, L3)
;
; TRUST_BUNDLE=1 (needs TRUST_STORE=1, UCI only). The bundle is a separate
; file, TRUST_STORE_DIR/TRUST.P, in tools/trust_bundle.py's format v1:
;
;   header   8 B   "C6TB", version $01, generation u16 LE, N (0..32)
;   records  N x 64 B, the store's record layout, strictly ascending by
;            host key; mode $10 (BUNDLE_LEAF), flags $01 (WARN_ONLY), uses 0
;   trailer  64 B  ECDSA P-256 r || s (BE) over SHA-256(header || records)
;
; trust_pre (src/net/uci/trust_policy.s) reads it into the TCP ring, before
; the dial and after the store's load has been consumed into ts_rec; then
; do_https_get calls trust_bundle, still before the dial. Checks, in the
; order DECISIONS 10 fixes, each failure printed and the bundle ignored for
; this GET (its pins are warn-only, so a bad bundle never blocks a fetch):
;
;   1. structure        BUNDLE BAD FORMAT
;   2. signature        BUNDLE BAD SIGNATURE   (VERIFYING BUNDLE first)
;   3. generation floor BUNDLE OLD GEN         (gen >= the PRG's floor)
;
; then the record for this attempt's ts_key, if any, goes to tb_spki
; (tb_found = 1): the hook in src/cert_pin.s warns if the server's key
; differs. The public key and the floor come from build/trust_key.inc
; (TRUST_BUNDLE_KEY_INC; the tree's key is TEST-ONLY).
;
; VERIFY ONCE PER BOOT (DECISIONS 11, Q4): the ECDSA verify (16-30 s at
; 48 MHz) runs at the first 'G' that finds the file. Its digest and verdict
; are kept; every later GET re-reads and re-hashes the file and skips the
; verify only if the digest is the one already judged. The digest is
; recomputed from the bytes each time, so a file swapped on disk is
; verified afresh, and a trailer swapped under unchanged content changes
; nothing that is used. The floor is re-checked every time.
;
; SHA-256 borrows the handshake's transcript hash (tls_transcript_*), and
; the verify the ecdsa_* struct: both dead before the dial —
; tls_send_client_hello re-initialises the transcript and CertificateVerify
; rewrites the struct. Nothing here touches the store's on-disk state.
;
; Placement: TRUST_BUNDLE_CODE. Resident on uci / uci-onchip; on comb it
; rides the cold bank's UI group (no DOS: the read is trust_pre's), run
; from cert_buf, which nothing in the verify path touches on UCI. Its state
; is resident (TRUST_POLICY_BSS).

.include "constants.inc"
.include "trust_store.inc"
.include "trust_policy.inc"
.include "trust_key.inc"        ; build/: TRUST_BUNDLE_KEY_INC, content-stamped

.import print_string, print_hex4
.import tls_transcript_init, tls_transcript_update, tls_transcript_hash
.import tls_transcript
.import ecdsa_verify, ecdsa_curve_id
.import ecdsa_sig_r, ecdsa_sig_s, ecdsa_hash, ecdsa_pubkey_x, ecdsa_pubkey_y
.import dos_cnt
.import ts_key
.import tb_found, tb_spki

.export trust_bundle
.export tb_loaded, tb_noted, tb_verdict, tb_digest
.export TB_FILE_MAX

TB_BUF          = tcp_recv_buf
TB_FILE_MAX     = TB_HEADER_LEN + TB_MAX_RECORDS * TB_RECORD_LEN + TB_SIG_LEN
TB_HDR_VER      = 4
TB_HDR_GEN      = 5
TB_HDR_N        = 7

TB_V_NONE       = 0             ; tb_verdict: nothing judged yet
TB_V_GOOD       = 1
TB_V_BAD        = 2

.assert TB_HEADER_LEN = 8 .and TB_RECORD_LEN = TS_REC_SIZE .and TB_SIG_LEN = 64, error, "bundle format v1"
.assert TB_FILE_MAX + 1 <= TCP_RECV_MASK + 1, error, "bundle > TCP ring"
.assert TB_MAX_RECORDS < 64, error, "tb_body_len: N * 64 must fit in 12 bits"
; The verify reads one 160 B struct: r | s | h | Qx | Qy.
.assert ecdsa_sig_s = ecdsa_sig_r + 32, lderror, "ecdsa struct: s"
.assert ecdsa_hash = ecdsa_sig_r + 64, lderror, "ecdsa struct: h"
.assert ecdsa_pubkey_x = ecdsa_sig_r + 96, lderror, "ecdsa struct: Qx"
.assert ecdsa_pubkey_y = ecdsa_sig_r + 128, lderror, "ecdsa struct: Qy"

.ifdef COLD_BANK
.include "cold_bank.inc"
.import cold_call_ui
.export cold_tb_check
.segment "CODE"
trust_bundle:
        ldy #COLD_E_TB_CHECK
        jmp cold_call_ui
.endif

.segment "TRUST_BUNDLE_CODE"

; =============================================================================
; trust_bundle — check the bundle trust_pre read, if it read one.
; Out: tb_found / tb_spki for this host; tb_loaded = 0. No carry contract.
; =============================================================================
.ifdef COLD_BANK
cold_tb_check:
.else
trust_bundle:
.endif
        lda tb_loaded
        bne :+
        rts
:       lda #0
        sta tb_loaded           ; the ring is the dial's from here

        ; --- 1. structure ---------------------------------------------------
        ldx #3
@magic: lda TB_BUF,x
        cmp tb_magic,x
        bne @bad_format
        dex
        bpl @magic
        lda TB_BUF+TB_HDR_VER
        cmp #TB_VERSION
        bne @bad_format
        lda TB_BUF+TB_HDR_N
        cmp #TB_MAX_RECORDS+1
        bcs @bad_format         ; before any arithmetic on N
        jsr tb_body_len         ; zp_count = 8 + 64N; size = that + 64
        clc
        lda zp_count
        adc #<TB_SIG_LEN
        tax
        lda zp_count+1
        adc #>TB_SIG_LEN
        cpx dos_cnt             ; exactly: no slack either way
        bne @bad_format
        cmp dos_cnt+1
        bne @bad_format
        ; Every record: mode, flags and uses as v1 requires; keys strictly
        ; ascending. zp_ptr walks the record BEFORE the one checked, which
        ; sits at +64 (for record 0 that is below the ring: read, unused).
        lda #<(TB_BUF + TB_HEADER_LEN - TB_RECORD_LEN)
        sta zp_ptr
        lda #>(TB_BUF + TB_HEADER_LEN - TB_RECORD_LEN)
        sta zp_ptr+1
        ldx #0
@rec:   cpx TB_BUF+TB_HDR_N
        beq @struct_ok
        ldy #TB_RECORD_LEN + TS_REC_MODE
        lda (zp_ptr),y
        cmp #TB_MODE_BUNDLE_LEAF
        bne @bad_format
        iny
        lda (zp_ptr),y
        cmp #TB_FLAG_WARN_ONLY
        bne @bad_format
        iny
        lda (zp_ptr),y          ; uses, both bytes
        iny
        ora (zp_ptr),y
        bne @bad_format
        txa
        beq @next               ; record 0 has nothing before it
        ldy #0
@key:   lda (zp_ptr),y          ; the previous record's key byte...
        sta tb_tmp
        tya
        ora #TB_RECORD_LEN
        tay
        lda (zp_ptr),y          ; ...and this one's
        cmp tb_tmp
        bcc @bad_format         ; descending
        bne @next               ; ascending: decided
        tya
        and #TB_RECORD_LEN-1
        tay
        iny
        cpy #TS_KEY_SIZE
        bne @key
        beq @bad_format         ; the same key twice
@next:  clc
        lda zp_ptr
        adc #TB_RECORD_LEN
        sta zp_ptr
        bcc :+
        inc zp_ptr+1
:       inx
        bne @rec                ; always (N <= 32)
@bad_format:
        lda #<tb_format_msg
        ldy #>tb_format_msg
        jmp print_string

@struct_ok:
        ; --- 2. signature ---------------------------------------------------
        jsr tls_transcript_init
        jsr tb_body_len
        lda #<TB_BUF
        sta zp_ptr
        lda #>TB_BUF
        sta zp_ptr+1
        jsr tls_transcript_update
        jsr tls_transcript_hash  ; e = SHA-256(header || records)
        ldx #TP_HASH_LEN-1
@cache: lda tls_transcript,x
        cmp tb_digest,x
        bne @fresh
        dex
        bpl @cache
        lda tb_verdict          ; these bytes were judged this boot
        bne @judged
@fresh:
        ldx #TP_HASH_LEN-1
@dig:   lda tls_transcript,x
        sta tb_digest,x
        sta ecdsa_hash,x
        dex
        bpl @dig
        lda #TB_V_NONE          ; not judged until the verify returns
        sta tb_verdict
        lda #<tb_verify_msg
        ldy #>tb_verify_msg
        jsr print_string
        jsr tb_body_len         ; zp_ptr = the trailer (TB_BUF is page-
        lda zp_count            ;  aligned, so only the high byte adds)
        sta zp_ptr
        lda zp_count+1
        clc
        adc #>TB_BUF
        sta zp_ptr+1
        ldy #TB_SIG_LEN-1       ; r || s as stored: the struct's layout
@sig:   lda (zp_ptr),y
        sta ecdsa_sig_r,y
        dey
        bpl @sig
        ldx #63
@key_q: lda tb_pubkey,x
        sta ecdsa_pubkey_x,x
        dex
        bpl @key_q
        lda #0
        sta ecdsa_curve_id      ; P-256
        jsr ecdsa_verify        ; C=0 valid
        lda #TB_V_GOOD
        bcc :+
        lda #TB_V_BAD
:       sta tb_verdict
@judged:
        cmp #TB_V_GOOD
        beq @gen
        lda #<tb_sig_msg
        ldy #>tb_sig_msg
        jmp print_string

        ; --- 3. generation floor ---------------------------------------------
@gen:   lda TB_BUF+TB_HDR_GEN   ; unsigned: gen >= floor
        cmp #<TRUST_BUNDLE_GEN_FLOOR
        lda TB_BUF+TB_HDR_GEN+1
        sbc #>TRUST_BUNDLE_GEN_FLOOR
        bcs @lookup
        lda #<tb_old_msg
        ldy #>tb_old_msg
        jmp print_string

        ; --- this host's pin --------------------------------------------------
@lookup:
        lda #<(TB_BUF + TB_HEADER_LEN)
        sta zp_ptr
        lda #>(TB_BUF + TB_HEADER_LEN)
        sta zp_ptr+1
        ldx TB_BUF+TB_HDR_N
        inx
@find:  dex
        beq @none
        ldy #TS_KEY_SIZE-1
@fk:    lda (zp_ptr),y
        cmp ts_key,y
        bne @skip
        dey
        bpl @fk
        ldy #TS_REC_SPKI + TP_HASH_LEN - 1
@cp:    lda (zp_ptr),y
        sta tb_spki - TS_REC_SPKI,y
        dey
        cpy #TS_REC_SPKI
        bcs @cp
        inc tb_found
        lda #<tb_pin_msg        ; "BUNDLE PIN xxxxxxxx"
        ldy #>tb_pin_msg
        jsr print_string
        lda #<tb_spki
        ldy #>tb_spki
        jsr print_hex4
        lda #$0d
        jmp chrout
@skip:  clc
        lda zp_ptr
        adc #TB_RECORD_LEN
        sta zp_ptr
        bcc @find
        inc zp_ptr+1
        bcs @find               ; always
@none:  rts

; tb_body_len — zp_count = 8 + 64 * N, from the header (N <= 32 checked).
tb_body_len:
        lda TB_BUF+TB_HDR_N
        lsr
        lsr
        sta zp_count+1
        lda TB_BUF+TB_HDR_N
        lsr
        ror
        ror
        and #$C0                ; (N & 3) << 6
        ora #TB_HEADER_LEN
        sta zp_count
        rts

tb_magic:
        TRUST_BUNDLE_MAGIC_BYTES
tb_pubkey:
        TRUST_BUNDLE_PUBKEY_BYTES
        .assert * - tb_pubkey = 64, error, "TRUST_BUNDLE_PUBKEY_BYTES must be 64 bytes"
tb_tmp:         .byte 0         ; written before it is read, every call

tb_format_msg:  .byte "BUNDLE BAD FORMAT", $0d, 0
tb_verify_msg:  .byte "VERIFYING BUNDLE...", $0d, 0
tb_sig_msg:     .byte "BUNDLE BAD SIGNATURE", $0d, 0
tb_old_msg:     .byte "BUNDLE OLD GEN", $0d, 0
tb_pin_msg:     .byte "BUNDLE PIN ", 0

.segment "TRUST_POLICY_BSS"
tb_loaded:  .res 1              ; != 0: trust_pre read TRUST.P into the ring
tb_noted:   .res 1              ; != 0: "NO BUNDLE" already shown this boot
tb_verdict: .res 1              ; TB_V_*, for the bytes hashed to tb_digest
tb_digest:  .res TP_HASH_LEN
