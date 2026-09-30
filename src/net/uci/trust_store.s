; src/net/uci/trust_store.s — the TOFU trust store's on-disk I/O
;
; Issue #155 phase 2, lane L2. This is the storage layer only: it loads,
; validates, looks up, stages and saves records. What to DO with a record
; (first use, key changed, accept) is the trust policy's job, not this
; file's. Format, slot scheme and result codes: src/trust_store.inc.
;
; API (A/X = pointer lo/hi; every entry returns C=1 on failure):
;
;   trust_store_load    A/X = host, zero-terminated ASCII (< 256 B).
;                       Hashes the lowercased host into ts_key, validates
;                       both slots and keeps the record for ts_key, if any.
;                       Out: A = ts_state. C=0 VALID or EMPTY; C=1 FAIL
;                       (ts_reason; ts_slot_st holds each slot's result).
;   trust_store_lookup  Out: C=0 and A/X = ts_rec (64 B) if the loaded
;                       store holds the host; C=1 otherwise. "First use"
;                       is exactly: ts_state = VALID or EMPTY, and C=1.
;   trust_store_stage   A/X = a 64 B record. Copied to ts_rec, with its
;                       host key forced to ts_key. No disk access.
;   trust_store_save    Writes the staged record into a new generation in
;                       the slot NOT loaded, closes it, reads it back and
;                       checks it. Refuses (C=1, ts_reason) unless a load
;                       returned VALID or EMPTY, a record is staged, and
;                       the store on disk is still the one loaded.
;
; Fail-closed (S3 §4.3): the store is usable only if one slot validates or
; BOTH slots are FILE DOESN'T EXIST (EMPTY). Any other combination is FAIL:
; no medium, a DOS error, a bad checksum, an unknown version, a
; generation tie. One valid slot beside a damaged one is VALID: that is
; the torn-write case, and the damaged slot is the one the next save
; overwrites.
;
; TIMING, and the one thing the caller must get right: the file image is
; built in the TCP receive ring at $C000, which holds nothing while no
; socket is open. So call load BEFORE net_tcp_connect and save AFTER
; net_tcp_close. Both refuse with TS_R_BUSY while net_tcp_state is
; CONNECTED. The store costs no resident buffer; lookup works from ts_rec,
; which load fills before the ring is reused.
;
; Both also use the transcript hash state (tls_transcript_*) for SHA-256,
; which is equally dead outside a handshake, and zp_ptr/zp_count.

.include "constants.inc"        ; zp_ptr, zp_count, tcp_recv_buf, TCP_RECV_MASK
.include "net_states.inc"
.include "trust_store.inc"
.include "https_host.inc"       ; TRUST_STORE_PATH_STR

; The firmware's command buffer is 896 B; far below it, but a path is not
; a place to spend RAM. The Makefile enforces the character set.
.assert .strlen(TRUST_STORE_PATH_STR) <= 48, error, "TRUST_STORE_DIR too long"

.import dos_open, dos_close, dos_read, dos_write, dos_len, dos_cnt
.import uci_status_buf, uci_status_len, uci_tod_start
.import net_tcp_state
.import tls_transcript_init, tls_transcript_update, tls_transcript_hash
.import tls_transcript

.export trust_store_load, trust_store_lookup
.export trust_store_stage, trust_store_save
.export ts_state, ts_reason, ts_slot, ts_gen, ts_slot_st, ts_sgen
.export ts_key, ts_rec, ts_found, ts_staged

TS_BUF          = tcp_recv_buf
FA_READ         = $01
FA_WRITE_NEW    = $0A           ; FA_WRITE | FA_CREATE_ALWAYS: empties it

.assert TS_FILE_MAX + 1 <= TCP_RECV_MASK + 1, error, "store image > TCP ring"
; ts_body_len computes 8 + 64 * N with shifts; these are what it assumes.
.assert TS_HDR_SIZE = 8 && TS_SUM_SIZE = 8 && TS_REC_SIZE = 64, error, "ts_body_len"

.segment "TRUST_STORE_CODE"

trust_store_load:
        sta @host+1
        stx @host+2
        lda #$00
        sta ts_found
        sta ts_staged
        jsr ts_guard
        bcc :+
        jmp ts_fail
:       jsr tls_transcript_init
        ldy #$00
@char:
@host:  lda $FFFF,y
        beq @hashed
        cmp #'A'
        bcc @keep
        cmp #'Z'+1
        bcs @keep
        ora #$20                ; lowercase: the key must not depend on case
@keep:  sta ts_char
        tya
        pha
        lda #<ts_char
        sta zp_ptr
        lda #>ts_char
        sta zp_ptr+1
        lda #$01
        sta zp_count
        lda #$00
        sta zp_count+1
        jsr tls_transcript_update
        pla
        tay
        iny
        bne @char
@hashed:
        jsr tls_transcript_hash
        ldx #TS_KEY_SIZE-1
:       lda tls_transcript,x
        sta ts_key,x
        dex
        bpl :-
        jsr ts_scan
        bcs @out
        cmp #TS_ST_VALID
        bne @absent             ; EMPTY: nothing to look up
        jsr ts_find
        bcs @absent
        ldy #TS_REC_SIZE-1
:       lda (zp_ptr),y
        sta ts_rec,y
        dey
        bpl :-
        inc ts_found
@absent:
        lda ts_state
        clc
@out:   rts

trust_store_lookup:
        lda ts_found            ; 0 or 1
        eor #$01
        lsr                     ; C=0 iff found
        lda #<ts_rec
        ldx #>ts_rec
        rts

trust_store_stage:
        sta @src+1
        stx @src+2
        ldy #TS_REC_SIZE-1
@copy:
@src:   lda $FFFF,y
        sta ts_rec,y
        dey
        bpl @copy
        ldy #TS_KEY_SIZE-1
:       lda ts_key,y
        sta ts_rec+TS_REC_KEY,y
        dey
        bpl :-
        lda #$01
        sta ts_staged
        rts

trust_store_save:
        jsr ts_guard
        bcs ts_refuse
        lda ts_staged
        beq @notready
        lda ts_state
        cmp #TS_ST_VALID
        beq @go
        cmp #TS_ST_EMPTY
        beq @go
@notready:
        lda #TS_R_NOTREADY
        bne ts_refuse
@go:
        ; Re-read the store and insist it is the one the load saw: the
        ; image is rebuilt from disk, and a store that moved in between
        ; (another save, a swapped stick) must not be overwritten blind.
        ldx #3                  ; ts_state, ts_slot, ts_gen: contiguous
:       lda ts_state,x
        sta ts_snap,x
        dex
        bpl :-
        jsr ts_scan
        ldx #3
:       lda ts_state,x
        cmp ts_snap,x
        bne @changed
        dex
        bpl :-
        lda ts_state
        cmp #TS_ST_EMPTY
        bne @have
        ldx #TS_HDR_SIZE-1      ; a fresh store: generation 0, no records
:       lda ts_hdr0,x
        sta TS_BUF,x
        dex
        bpl :-
@have:  jsr ts_find             ; zp_ptr -> the host's record, or slot N
        bcc ts_put
        lda TS_BUF+TS_HDR_N
        cmp #TS_MAX_RECS
        bcs @full
        inc TS_BUF+TS_HDR_N
        bcc ts_put              ; always (C=0 from the cmp)
@changed:
        lda #TS_R_CHANGED
        bne ts_refuse
@full:
        lda #TS_R_FULL
ts_refuse:
        sta ts_reason
        sec
        rts

; ts_put — zp_ptr -> the record's place in TS_BUF: fill it, bump the
; generation, checksum, write the other slot, close, read back, commit.
ts_put:
        ldy #TS_REC_SIZE-1
:       lda ts_rec,y
        sta (zp_ptr),y
        dey
        bpl :-
        inc TS_BUF+TS_HDR_GEN   ; wraps: load compares serially
        bne :+
        inc TS_BUF+TS_HDR_GEN+1
:       lda TS_BUF+TS_HDR_GEN
        sta ts_snap+2           ; the generation being written
        lda TS_BUF+TS_HDR_GEN+1
        sta ts_snap+3
        jsr ts_checksum         ; zp_ptr -> trailer, ts_size = file size
        ldy #TS_SUM_SIZE-1
:       lda tls_transcript,y
        sta (zp_ptr),y
        dey
        bpl :-
        lda ts_slot
        eor #$01                ; the slot NOT loaded
        sta ts_target
        tax
        jsr ts_set_name
        lda #<ts_name
        ldx #>ts_name
        ldy #FA_WRITE_NEW
        jsr dos_open
        bcs @write_err
        lda ts_size
        sta dos_len
        lda ts_size+1
        sta dos_len+1
        lda #<TS_BUF
        ldx #>TS_BUF
        jsr dos_write
        ror ts_tmp              ; bit 7 = the write failed
        jsr dos_close           ; always: nothing is durable until close
        bcs @write_err
        bit ts_tmp
        bmi @write_err
        ldx ts_target           ; read it back: a fresh open, a full check
        jsr ts_read_slot
        bne @verify
        lda TS_BUF+TS_HDR_GEN
        cmp ts_snap+2
        bne @verify
        lda TS_BUF+TS_HDR_GEN+1
        cmp ts_snap+3
        bne @verify
        lda ts_target
        sta ts_slot
        lda ts_snap+2
        sta ts_gen
        lda ts_snap+3
        sta ts_gen+1
        lda #TS_ST_VALID
        sta ts_state
        lda #$01
        sta ts_found
        lda #$00
        sta ts_staged
        clc
        rts
@write_err:
        lda #TS_R_WRITE
        bne @refuse
@verify:
        lda #TS_R_VERIFY
@refuse:
        jmp ts_refuse

; ts_guard — C=1, A = TS_R_BUSY while a socket owns the ring. Starts the
; CIA1 TOD, which every bounded UCI wait measures (net_init does too, but
; the store does not rely on having been called after it).
ts_guard:
        jsr uci_tod_start
        lda net_tcp_state
        cmp #NET_TCP_CONNECTED
        bne @free
        lda #TS_R_BUSY
        sec
        rts
@free:  clc
        rts

; ts_fail — A = reason: ts_state = FAIL. Out: A = TS_ST_FAIL, C=1.
ts_fail:
        sta ts_reason
        lda #TS_ST_FAIL
        sta ts_state
        sec
        rts

; ts_scan — read and validate both slots; leave the chosen one in TS_BUF.
; Out: ts_state, ts_slot, ts_gen, ts_slot_st, ts_reason; A = ts_state;
; C=1 iff FAIL. EMPTY sets ts_slot = 1 and ts_gen = 0, so a save of an
; empty store writes slot A with generation 1.
ts_scan:
        jsr dos_close           ; a handle a C64 reset left open; result moot
        ldx #0
        jsr ts_read_slot
        sta ts_slot_st
        ldx #1
        jsr ts_read_slot
        sta ts_slot_st+1
        lda ts_slot_st
        bne @a_bad
        lda ts_slot_st+1
        bne @take_a
        sec                     ; both valid: d = gen(B) - gen(A), serial
        lda ts_sgen+2
        sbc ts_sgen
        sta ts_tmp
        lda ts_sgen+3
        sbc ts_sgen+1
        tax
        and #$7F
        ora ts_tmp
        bne @order              ; d = 0 or $8000: neither is newer
        lda #TS_R_TIE
        bne ts_fail
@order: txa
        bmi @take_a             ; d < 0: A is newer
@take_b:
        ldx #1                  ; TS_BUF holds B already
        bne @valid
@a_bad: lda ts_slot_st+1
        beq @take_b
        lda ts_slot_st          ; neither valid: EMPTY only if both absent
        cmp #TS_SLOT_ABSENT
        bne ts_fail
        lda ts_slot_st+1
        cmp #TS_SLOT_ABSENT
        bne ts_fail
        lda #$00
        sta ts_gen
        sta ts_gen+1
        lda #$01
        sta ts_slot
        lda #TS_ST_EMPTY
        sta ts_state
        clc
        rts
@take_a:
        ldx #0                  ; TS_BUF holds B's attempt: read A again
        jsr ts_read_slot
        beq :+
        lda #TS_R_CHANGED       ; valid a moment ago, not now
        bne ts_fail
:       ldx #0
@valid: stx ts_slot
        txa
        asl
        tay
        lda ts_sgen,y
        sta ts_gen
        lda ts_sgen+1,y
        sta ts_gen+1
        lda #TS_ST_VALID
        sta ts_state
        clc
        rts

; ts_read_slot — X = slot. Reads the slot into TS_BUF and validates it.
; Out: A = TS_SLOT_OK / TS_SLOT_ABSENT / TS_R_* with Z set iff OK;
; ts_sgen[slot] = its generation when OK.
ts_read_slot:
        jsr ts_set_name
        lda #<ts_name
        ldx #>ts_name
        ldy #FA_READ
        jsr dos_open
        bcs @open_failed
        lda #<(TS_FILE_MAX + 1) ; one more than fits: a bigger file shows
        sta dos_len
        lda #>(TS_FILE_MAX + 1)
        sta dos_len+1
        lda #<TS_BUF
        ldx #>TS_BUF
        jsr dos_read
        ror ts_tmp              ; bit 7 = the read failed
        jsr dos_close
        bcs @io
        bit ts_tmp
        bmi @io
        lda dos_cnt+1           ; the count is the only evidence (header)
        bne @hdr
        lda dos_cnt
        cmp #TS_HDR_SIZE + TS_SUM_SIZE
        bcc @format
@hdr:   ldx #3
:       lda TS_BUF,x
        cmp ts_hdr0,x
        bne @format
        dex
        bpl :-
        lda TS_BUF+TS_HDR_VER
        cmp #TS_VERSION
        bne @version
        jsr ts_body_len         ; the size check comes before any hashing:
        lda dos_cnt             ; N is unchecked here, and 64 * N from $C000
        cmp ts_size             ; would reach the I/O area
        bne @format
        lda dos_cnt+1
        cmp ts_size+1
        bne @format
        jsr ts_checksum
        ldy #TS_SUM_SIZE-1
:       lda tls_transcript,y
        cmp (zp_ptr),y
        bne @checksum
        dey
        bpl :-
        ldy ts_cur2
        lda TS_BUF+TS_HDR_GEN
        sta ts_sgen,y
        lda TS_BUF+TS_HDR_GEN+1
        sta ts_sgen+1,y
        lda #TS_SLOT_OK
        rts
@io:    lda #TS_R_IO
        rts
@format:
        lda #TS_R_FORMAT
        rts
@version:
        lda #TS_R_VERSION
        rts
@checksum:
        lda #TS_R_CHECKSUM
        rts
@open_failed:
        ; "FILE DOESN'T EXIST" / "PATH DOESN'T EXIST": [0] and [5] tell
        ; them apart from each other and from every other string in
        ; FileSystem::get_error_string(). No line at all is a timeout.
        lda uci_status_len
        beq @dos
        lda uci_status_buf+5
        cmp #'D'
        bne @dos
        lda uci_status_buf
        cmp #'F'
        beq @absent
        cmp #'P'
        bne @dos
        lda #TS_R_NOPATH
        rts
@absent:
        lda #TS_SLOT_ABSENT
        rts
@dos:   lda #TS_R_DOS
        rts

; ts_set_name — X = slot: name the file, ts_cur2 = 2 * slot.
ts_set_name:
        txa
        clc
        adc #'A'
        sta ts_letter
        txa
        asl
        sta ts_cur2
        rts

; ts_body_len — from TS_BUF's N: zp_count = 8 + 64 * N (the checksummed
; body) and ts_size = zp_count + 8 (the whole file).
ts_body_len:
        lda TS_BUF+TS_HDR_N
        lsr
        lsr
        sta zp_count+1
        sta ts_size+1
        lda TS_BUF+TS_HDR_N
        lsr
        ror
        ror
        and #$C0                ; (N & 3) << 6
        tax
        ora #TS_HDR_SIZE
        sta zp_count
        txa
        ora #TS_HDR_SIZE + TS_SUM_SIZE
        sta ts_size
        rts

; ts_checksum — SHA-256 of TS_BUF's header and records into tls_transcript.
; Out: zp_ptr -> the trailer; ts_size = file size.
ts_checksum:
        jsr tls_transcript_init
        jsr ts_body_len
        lda #<TS_BUF
        sta zp_ptr
        lda #>TS_BUF
        sta zp_ptr+1
        jsr tls_transcript_update
        jmp tls_transcript_hash

; ts_find — look ts_key up in TS_BUF. Out: C=0 found, zp_ptr -> the
; record; C=1 absent, zp_ptr -> where record N would go.
ts_find:
        lda #<(TS_BUF + TS_HDR_SIZE)
        sta zp_ptr
        lda #>(TS_BUF + TS_HDR_SIZE)
        sta zp_ptr+1
        ldx TS_BUF+TS_HDR_N
        inx
@rec:   dex
        beq @absent
        ldy #TS_KEY_SIZE-1
@cmp:   lda (zp_ptr),y
        cmp ts_key,y
        bne @skip
        dey
        bpl @cmp
        clc
        rts
@skip:  lda zp_ptr
        clc
        adc #TS_REC_SIZE
        sta zp_ptr
        bcc @rec
        inc zp_ptr+1
        bcs @rec                ; always
@absent:
        sec
        rts

; A fresh store's header; its first four bytes are also the magic.
ts_hdr0:
        .byte TS_MAGIC_0, TS_MAGIC_1, TS_MAGIC_2, TS_MAGIC_3
        .byte TS_VERSION, $00, $00, $00
; The slot's file name; ts_set_name writes the letter.
ts_name:
        .byte TRUST_STORE_PATH_STR
ts_letter:
        .byte 'A', $00

.segment "TRUST_STORE_BSS"
ts_state:   .res 1              ; TS_ST_*          } contiguous, in this
ts_slot:    .res 1              ; the loaded slot  } order: save
ts_gen:     .res 2              ; its generation   } snapshots all four
ts_reason:  .res 1              ; TS_R_*, valid when FAIL or a call C=1
ts_slot_st: .res 2              ; each slot's TS_SLOT_* / TS_R_* result
ts_sgen:    .res 4              ; each slot's generation, when it was OK
ts_snap:    .res 4
ts_size:    .res 2
ts_tmp:     .res 1
ts_cur2:    .res 1
ts_target:  .res 1
ts_found:   .res 1              ; 1: ts_rec is the loaded host's record
ts_staged:  .res 1              ; 1: ts_rec is staged for save
ts_char:    .res 1
ts_key:     .res TS_KEY_SIZE
ts_rec:     .res TS_REC_SIZE
