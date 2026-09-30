; src/net/uci/uci_dos.s — file I/O through the Ultimate's UCI DOS target
;
; Issue #155 phase 2 (L2). The S1 spike's glue, made product code: open,
; read, write and close one file on the Ultimate's own filesystem (/USB1,
; /Temp, ...) over the command interface every UCI build already drives.
; Linked only under TRUST_STORE=1; no zero page.
;
; Command layout (1541ultimate software/filemanager/dos.cc):
;   OPEN_FILE   $01 $02 mode name...   FA_READ=$01; FA_WRITE|FA_CREATE_ALWAYS
;                                       =$0A empties an existing file
;   CLOSE_FILE  $01 $03
;   READ_DATA   $01 $04 len_lo len_hi  reply in 512 B parts; state "11" =
;                                       another part follows the accept
;   WRITE_DATA  $01 $05 x x data...
; Success status is "00,OK", which uci_drain_status does not commit; a
; failure is get_error_string() text ("FILE DOESN'T EXIST"), un-numbered,
; and is committed, so C=1 <=> a line reached uci_status_len.
;
; Hazards measured by S1 on the U64E, each handled here or by the caller:
;   * One WRITE_DATA stores at most 891 B, not the 892 the 896 B command
;     buffer suggests: dos_write sends <= 256 B per command.
;   * A READ_DATA that fails never assigns the status line (dos.cc
;     get_more_data), so the previous "00,OK" stands. Only the byte count
;     is evidence: dos_read returns it and the caller must check it.
;   * A handle left open across a C64 reset stays open in the firmware.
;     Callers close on every path and close once before their first open.
;
; Every wait is a CIA1-TOD-bounded uci_cmd.s primitive (5 s, C=1 and
; net_last_error = $89 on expiry). No iteration-counted waits.
;
; A DOS call re-arms the sticky status slot (uci_status_len = 0) so that
; it can classify its OWN result; a network line held from before the
; call is gone afterwards. Read it first if you need it.

.include "uci_regs.inc"

.import uci_wait_idle, uci_begin_cmd, uci_put_byte, uci_push_wait
.import uci_wait_reply, uci_check_err, uci_drain_resp, uci_drain_status
.import uci_ack, uci_settle
.import uci_status_len

.export dos_open, dos_close, dos_read, dos_write
.export dos_len, dos_cnt

DOS_TARGET      = $01
DOS_CMD_OPEN    = $02
DOS_CMD_CLOSE   = $03
DOS_CMD_READ    = $04
DOS_CMD_WRITE   = $05
DOS_WCHUNK_PAGES = 1            ; 256 B per WRITE_DATA (S1: 891 B max)

.segment "TRUST_STORE_CODE"

; dos_open — A/X = zero-terminated name (< 256 B), Y = mode.
; Out: C=0 opened; C=1 failed (reason line in uci_status_buf) or timed out.
dos_open:
        sta @name+1
        stx @name+2
        tya
        pha
        lda #DOS_CMD_OPEN
        jsr dos_hdr
        pla
        bcs dos_rts
        jsr uci_put_byte
        ldy #$00
@next:
@name:  lda $FFFF,y
        beq dos_finish
        jsr uci_put_byte
        iny
        bne @next
        beq dos_finish          ; always: a 256 B name is sent truncated

; dos_close — C=0 closed; C=1 nothing to close, or timed out.
dos_close:
        lda #DOS_CMD_CLOSE
        jsr dos_hdr
        bcc dos_finish
dos_rts:
        rts

; dos_read — A/X = destination, dos_len = bytes wanted (1..65535).
; Out: dos_cnt = bytes received and stored (never more than dos_len);
;      it survives the dos_close that must follow.
;      C=1: timeout, a failure line, or the firmware sent MORE than
;      dos_len (nothing past dos_len is stored). C=0 does NOT mean the
;      whole request arrived — compare dos_cnt (see the header).
dos_read:
        sta dos_store+1
        stx dos_store+2
        lda #DOS_CMD_READ
        jsr dos_hdr
        bcs dos_rts
        lda dos_len
        sta dos_cap
        jsr uci_put_byte
        lda dos_len+1
        sta dos_cap+1
        jsr uci_put_byte
        lda #$00                ; only a read counts: a close after it must
        sta dos_cnt             ; leave dos_cnt for the caller to check
        sta dos_cnt+1           ; falls through into dos_finish

; dos_finish — push, then take every reply part, storing at most dos_cap
; bytes at dos_store. dos_hdr zeroes dos_cap, so a command whose reply
; should be empty fails if the firmware sends it data.
dos_finish:
        lda #$00
        sta uci_status_len      ; capture THIS command's status line
        jsr uci_push_wait
        bcs dos_rts             ; 5 s timeout
        jsr uci_check_err
        bcs dos_reject          ; push rejected (interface not idle)
dos_part:
        lda UCI_STATUS
        jsr uci_settle
        bpl dos_status             ; DATA_AV clear
        lda dos_cap                ; not a read (dos_hdr zeroed the cap):
        ora dos_cap+1              ; the reply must be empty, and dos_cnt
        beq dos_reject             ; and dos_store are stale, so refuse
        lda dos_cnt
        cmp dos_cap
        bne @store
        lda dos_cnt+1
        cmp dos_cap+1
        beq dos_reject          ; one byte more than asked for
@store:
        lda UCI_RESP_DATA
        jsr uci_settle
dos_store:
        sta $FFFF
        inc dos_store+1
        bne :+
        inc dos_store+2
:       inc dos_cnt
        bne dos_part
        inc dos_cnt+1
        jmp dos_part
dos_status:
        jsr uci_drain_status
        bcs dos_rts
        lda UCI_STATUS
        jsr uci_settle
        and #UCI_STAT_STATE
        cmp #UCI_STAT_STATE     ; "11": another part follows the accept
        bne dos_last
        jsr uci_ack             ; DATA_ACC -> firmware get_more_data
        jsr uci_wait_reply      ; next part staged; TOD-bounded
        bcc dos_part
        rts
dos_last:
        jsr uci_ack
        lda uci_status_len      ; "00,OK" is filtered out, failures are not
        cmp #$01                ; C=1 iff a failure line was captured
        rts

dos_reject:
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack
        sec
        rts

; dos_write — A/X = source, dos_len = byte count (0 is a no-op).
; Out: C=0 every chunk acknowledged "00,OK"; C=1 otherwise. dos_len is
; consumed.
dos_write:
        sta @src+1
        stx @src+2
@chunk:
        lda dos_len
        ora dos_len+1
        beq @done
        lda #DOS_CMD_WRITE
        jsr dos_hdr
        bcs @out
        jsr uci_put_byte        ; two ignored bytes: data starts at +4
        jsr uci_put_byte
        ldx dos_len+1
        beq @tail
        dec dos_len+1           ; a whole page: X = 0 sends 256
        ldx #$00
        beq @send
@tail:  ldx dos_len             ; the last, partial chunk
        lda #$00
        sta dos_len
@send:  ldy #$00
@byte:
@src:   lda $FFFF,y
        jsr uci_put_byte
        iny
        dex
        bne @byte
        inc @src+2              ; only a whole page is ever followed by more
        jsr dos_finish
        bcc @chunk
@out:   rts
@done:  clc
        rts

; dos_hdr — wait idle, then send target + command A. C=1: timed out.
dos_hdr:
        pha
        lda #$00
        sta dos_cap
        sta dos_cap+1
        jsr uci_wait_idle
        pla
        bcs @x
        pha
        lda #DOS_TARGET
        jsr uci_begin_cmd
        pla
        jsr uci_put_byte
        clc
@x:     rts

.segment "TRUST_STORE_BSS"
dos_len:  .res 2
dos_cnt:  .res 2
dos_cap:  .res 2
