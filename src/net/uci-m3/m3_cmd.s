; src/net/uci-m3/m3_cmd.s — UCI command primitives for the M3 adapter
;
; Why not src/net/uci/uci_cmd.s: its waits are a fixed 5 s in 8-bit TOD
; tenths, and M3 needs 45 s / 12 s bounds counted from the PUSH, an ABORT at
; the bound and a post-ABORT wait (ER-1). An 8-bit tenths counter cannot
; hold 45 s (Appendix A says so in as many words). Its status capture is
; sticky-first and 16 B; M3 needs this command's own status line, up to
; 40 B (ER-8). So the M3 adapter has its own, small, set:
;
;   m3_clock_init      start the CIA2 deadline clock (m3.inc, "The deadline
;                      clock")
;   m3_dl_arm          Y = slot, A/X = units: start a deadline now
;   m3_dl_expired      Y = slot: C=1 once the deadline has passed
;   m3_begin           A = command: entry wait for idle, write $03 + command
;   m3_put             A = byte: write one command byte
;   m3_exec            A/X = bound B: PUSH, wait for the reply until PUSH + B;
;                      past it, ABORT and wait for bit 2 (ER-1). A = outcome
;   m3_abort_wait      A/X = units: write ABORT ($04 alone), wait for bit 2
;   m3_abort_wait_ctl  same, Y = the control byte ($0C at startup, ER-2)
;   m3_read_data       up to m3_rd_max reply bytes to (m3_rd_dst)
;   m3_finish          drop the rest of the block, read the status line,
;                      data-accept: the end of every transaction
;
; Every wait is bounded by the CIA2 clock and every caller tests C. No zero
; page: absolute addressing and self-modified operands, like uci_cmd.s.

.include "uci_regs.inc"
.include "uci_errors.inc"
.include "m3.inc"

.import net_last_error

.export m3_clock_init
.export m3_dl_arm
.export m3_dl_expired
.export m3_begin
.export m3_put
.export m3_exec
.export m3_abort_wait
.export m3_abort_wait_ctl
.export m3_read_data
.export m3_discard_data
.export m3_read_status
.export m3_accept
.export m3_finish
.export m3_settle
.export m3_discarded
.export m3_rd_dst
.export m3_rd_max
.export m3_rd_count
.export m3_status
.export m3_status_len
.export m3_status_seen
.export m3_code
.export m3_wedged
.export m3_dl

CIA2_TA_LO  = $DD04
CIA2_TA_HI  = $DD05
CIA2_TB_LO  = $DD06
CIA2_TB_HI  = $DD07
CIA2_ICR    = $DD0D
CIA2_CRA    = $DD0E
CIA2_CRB    = $DD0F

UCI_STAT_DATA_MORE = $30        ; state "11": another block follows

.segment "UCI_CODE"

; =============================================================================
; m3_clock_init — CIA2 timer A = M3_UNIT_CYCLES-cycle divider, timer B counts
; its underflows down from $FFFF: one tick per unit, 655 s to wrap, which is
; far beyond any bound here. Timer B is read as a 16-bit "now"; elapsed is
; start - now (mod 65536), so no tick can be missed between two samples.
; CIA2's interrupt mask is cleared, so the underflows raise no NMI.
; Clobbers: A
; =============================================================================
m3_clock_init:
        lda #$7F
        sta CIA2_ICR                ; mask every CIA2 interrupt source
        lda #<(M3_UNIT_CYCLES - 1)
        sta CIA2_TA_LO
        lda #>(M3_UNIT_CYCLES - 1)
        sta CIA2_TA_HI
        lda #$FF
        sta CIA2_TB_LO
        sta CIA2_TB_HI
        lda #%01010001              ; TB: start, force load, count TA underflows
        sta CIA2_CRB
        lda #%00010001              ; TA: start, force load, continuous, PHI2
        sta CIA2_CRA
        rts

; m3_now — A = timer B lo, X = hi, a consistent pair. Preserves Y.
m3_now:
        ldx CIA2_TB_HI
        lda CIA2_TB_LO
        cpx CIA2_TB_HI
        bne m3_now                  ; the high byte moved under us: again
        rts

; =============================================================================
; m3_dl_arm — Y = slot (M3_DL_CMD / M3_DL_APP), A/X = length in units.
; Clobbers: A, X. Preserves Y.
; =============================================================================
m3_dl_arm:
        sta m3_dl+2,y
        txa
        sta m3_dl+3,y
        jsr m3_now
        sta m3_dl+0,y
        txa
        sta m3_dl+1,y
        rts

; =============================================================================
; m3_dl_expired — Y = slot. C=1 once (start - now) >= length.
; Clobbers: A, X. Preserves Y.
; =============================================================================
m3_dl_expired:
        jsr m3_now
        sta m3_tmp
        stx m3_tmp+1
        lda m3_dl+0,y
        sec
        sbc m3_tmp
        sta m3_tmp
        lda m3_dl+1,y
        sbc m3_tmp+1
        sta m3_tmp+1                ; elapsed units
        lda m3_tmp
        cmp m3_dl+2,y
        lda m3_tmp+1
        sbc m3_dl+3,y               ; C=1 iff elapsed >= length
        rts

; m3_settle — one fence as a subroutine (preserves A, X, Y; clobbers flags).
m3_settle:
        uci_fence
        rts

; m3_get_status — A = $DF1C, read and settled.
m3_get_status:
        lda UCI_STATUS
        jmp m3_settle

; =============================================================================
; m3_wait_clear / m3_wait_set — A = mask. Spin until ($DF1C & mask) is zero
; (clear) / non-zero (set), or the M3_DL_CMD deadline passes.
; C=0 condition met, C=1 deadline. Clobbers: A, X, Y.
; =============================================================================
m3_wait_clear:
        sta @wc_mask+1
@wc_loop:
        jsr m3_get_status
@wc_mask:
        and #$00                    ; SMC: the mask
        beq @wc_ok
        ldy #M3_DL_CMD
        jsr m3_dl_expired
        bcc @wc_loop
        rts                         ; C=1
@wc_ok:
        clc
        rts

m3_wait_set:
        sta @ws_mask+1
@ws_loop:
        jsr m3_get_status
@ws_mask:
        and #$00                    ; SMC: the mask
        bne @ws_ok
        ldy #M3_DL_CMD
        jsr m3_dl_expired
        bcc @ws_loop
        rts                         ; C=1
@ws_ok:
        clc
        rts

; =============================================================================
; m3_abort_wait — write ABORT ($04, alone: never with a PUSH, Appendix A) and
; wait for $DF1C bit 2 to clear, for A/X units from the ABORT (ER-1).
; m3_abort_wait_ctl — the same with Y = the control byte; net_init uses $0C,
; ABORT + clear error (ER-2: error bit 3 survives even a C64 reset).
; Bit 2 is cleared only by the Nios's HANDSHAKE_RESET, in the same write that
; forces state "00", so "clear" means the interface is idle again.
; Out: C=0 idle. C=1 wedged: m3_wedged = $80 and net_last_error = $89; from
;      then on m3_begin refuses, so nothing more is written (ER-11).
; Clobbers: A, X, Y
; =============================================================================
m3_abort_wait:
        ldy #UCI_CTRL_ABORT
m3_abort_wait_ctl:
        sta m3_tmp2
        stx m3_tmp2+1
        sty UCI_CONTROL
        jsr m3_settle
        lda m3_tmp2
        ldx m3_tmp2+1
        ldy #M3_DL_CMD
        jsr m3_dl_arm               ; counted from the ABORT
        lda #UCI_STAT_ABORT_PENDING
        jsr m3_wait_clear
        bcc @aw_ok
        lda #$80
        sta m3_wedged
        lda #UCI_ERR_WAIT_TIMEOUT
        sta net_last_error
        sec
        rts
@aw_ok:
        clc
        rts

; =============================================================================
; m3_begin — A = command byte. Waits for the interface to be idle, then
; writes the target ($03) and the command.
;
; Every transaction here ends in a data-accept or an ABORT whose reset was
; waited for, so idle is expected at once. If it is not (something we did
; not start), the PUSH time is unknown: ABORT and wait up to ABORT + 45 s
; (ER-1), then go on. A wedged interface (m3_wedged) gets nothing written.
; Out: C=0 command started; C=1 nothing written (net_last_error = $89).
; Clobbers: A, X, Y
; =============================================================================
m3_begin:
        sta m3_cmd
        bit m3_wedged
        bmi @b_wedged
        lda #<M3_B_TLS
        ldx #>M3_B_TLS
        ldy #M3_DL_CMD
        jsr m3_dl_arm
        lda #(UCI_STAT_STATE | UCI_STAT_ABORT_PENDING | UCI_STAT_CMD_BUSY)
        jsr m3_wait_clear
        bcc @b_idle
        lda #<M3_B_UNKNOWN_PUSH
        ldx #>M3_B_UNKNOWN_PUSH
        jsr m3_abort_wait
        bcs @b_fail
@b_idle:
        lda #UCI_TARGET_NETWORK
        jsr m3_put
        lda m3_cmd
        jsr m3_put
        clc
        rts
@b_wedged:
        lda #UCI_ERR_WAIT_TIMEOUT
        sta net_last_error
@b_fail:
        sec
        rts

; m3_put — A = command byte. Clobbers: nothing (flags).
m3_put:
        sta UCI_CMD_DATA
        jmp m3_settle

; =============================================================================
; m3_exec — PUSH the command, wait for its reply, bounded (ER-1).
;   In:  A/X = B in units, counted from the PUSH (M3_B_OPEN / M3_B_TLS).
;   Out: A = M3_EXEC_*, C=0 only for M3_EXEC_REPLY.
;        REPLY     the reply is valid (state "1x"); read it, then m3_finish.
;        REJECTED  ERROR bit: the push was refused, the command never ran.
;        ABORTED   no reply by PUSH + B: ABORT written, bit 2 cleared within
;                  ABORT + 12 s. The command is an ABORTed command and the
;                  caller applies that command's rule (S 1.1, Appendix A).
;                  net_last_error = $89.
;        WEDGED    bit 2 still set at ABORT + 12 s (m3_wedged, $89).
; The error bit is cleared BEFORE the push, so in the wait it can only mean
; this push. The PUSH is its own write, never combined with ABORT.
; Clobbers: A, X, Y
; =============================================================================
m3_exec:
        sta m3_tmp2
        stx m3_tmp2+1
        lda #UCI_CTRL_CLR_ERR
        sta UCI_CONTROL
        jsr m3_settle
        lda #UCI_CTRL_PUSH_CMD
        sta UCI_CONTROL
        jsr m3_settle
        lda m3_tmp2
        ldx m3_tmp2+1
        ldy #M3_DL_CMD
        jsr m3_dl_arm               ; PUSH + B
        lda #(UCI_STAT_REPLY_VALID | UCI_STAT_ERROR)
        jsr m3_wait_set
        bcs @x_timeout
        jsr m3_get_status
        and #UCI_STAT_ERROR
        beq @x_reply
        lda #UCI_CTRL_CLR_ERR
        sta UCI_CONTROL
        jsr m3_settle
        lda #M3_EXEC_REJECTED
        sec
        rts
@x_reply:
        lda #M3_EXEC_REPLY
        clc
        rts
@x_timeout:
        lda #UCI_ERR_WAIT_TIMEOUT
        sta net_last_error
        lda #<M3_B_POST_ABORT
        ldx #>M3_B_POST_ABORT
        jsr m3_abort_wait
        bcs @x_wedged
        lda #M3_EXEC_ABORTED
        sec
        rts
@x_wedged:
        lda #M3_EXEC_WEDGED
        sec
        rts

; =============================================================================
; m3_read_data — read reply bytes into (m3_rd_dst), at most m3_rd_max (1..255),
; testing DATA_AV ($DF1C bit 7) before every byte: an empty reply reads as
; $00 bytes, never as "no data" (ER-12). The queue advances on the read.
; Out: m3_rd_count = Y = bytes stored. Clobbers: A, Y.
; =============================================================================
m3_read_data:
        lda m3_rd_dst
        sta @rd_store+1
        lda m3_rd_dst+1
        sta @rd_store+2
        ldy #0
@rd_loop:
        cpy m3_rd_max
        bcs @rd_done
        jsr m3_get_status
        and #UCI_STAT_DATA_AV
        beq @rd_done
        lda UCI_RESP_DATA
        jsr m3_settle
@rd_store:
        sta $FFFF,y                 ; SMC: m3_rd_dst
        iny
        bne @rd_loop
@rd_done:
        sty m3_rd_count
        rts

; =============================================================================
; m3_discard_data — read and drop what is left of this block (at most 1024
; bytes: a block is 896, so a DATA_AV that never drops cannot hold us).
; Out: m3_discarded = 1 if any byte was dropped. Clobbers: A, X, Y.
; =============================================================================
m3_discard_data:
        lda #0
        sta m3_discarded
        ldx #4
        ldy #0
@dd_loop:
        jsr m3_get_status
        and #UCI_STAT_DATA_AV
        beq @dd_done
        lda UCI_RESP_DATA
        jsr m3_settle
        lda #1
        sta m3_discarded
        dey
        bne @dd_loop
        dex
        bne @dd_loop
@dd_done:
        rts

; =============================================================================
; m3_read_status — read this command's status line into m3_status.
;   m3_status_len  = bytes kept (<= M3_STATUS_MAX: every M3 line fits, ER-8)
;   m3_status_seen = bytes read (a longer line is read out and dropped, which
;                    is harmless: the next result resets the pointer)
;   m3_code        = the two leading digits as a number (0..99), $FF if the
;                    line does not start with two digits (e.g. no line).
; Clobbers: A, Y
; =============================================================================
m3_read_status:
        ldy #0
@rs_loop:
        jsr m3_get_status
        and #UCI_STAT_STAT_AV
        beq @rs_done
        lda UCI_STATUS_DATA
        jsr m3_settle
        cpy #M3_STATUS_MAX
        bcs @rs_skip
        sta m3_status,y
@rs_skip:
        iny
        bne @rs_loop                ; at most 255 bytes, then stop
@rs_done:
        sty m3_status_seen
        cpy #M3_STATUS_MAX
        bcc :+
        ldy #M3_STATUS_MAX
:       sty m3_status_len
        lda #$FF
        sta m3_code
        cpy #2
        bcc @rs_out
        lda m3_status+0
        sec
        sbc #'0'
        cmp #10
        bcs @rs_out
        sta m3_tmp
        asl
        asl
        adc m3_tmp                  ; x5 (C clear: x <= 9)
        asl                         ; x10
        sta m3_tmp
        lda m3_status+1
        sec
        sbc #'0'
        cmp #10
        bcs @rs_out
        adc m3_tmp                  ; C clear from the cmp
        sta m3_code
@rs_out:
        rts

; m3_accept — the data-accept that ends a transaction (UCI_CTRL_DATA_ACC).
m3_accept:
        lda #UCI_CTRL_DATA_ACC
        sta UCI_CONTROL
        jmp m3_settle

; m3_finish — drop the rest of the block, read the status line, accept.
; The status is read BEFORE the accept, which empties both queues.
m3_finish:
        jsr m3_discard_data
        jsr m3_read_status
        jmp m3_accept

.segment "UCI_BSS"

m3_dl:          .res 8          ; two deadline slots: start(2), length(2)
m3_tmp:         .res 2
m3_tmp2:        .res 2
m3_cmd:         .res 1
m3_wedged:      .res 1          ; bit 7: the interface is wedged (ER-11)
m3_rd_dst:      .res 2
m3_rd_max:      .res 1
m3_rd_count:    .res 1
m3_discarded:   .res 1
m3_status:      .res M3_STATUS_MAX
m3_status_len:  .res 1
m3_status_seen: .res 1
m3_code:        .res 1
