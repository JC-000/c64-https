; src/net/uci/uci_cmd.s — shared UCI command primitives
;
; Plain JSR-callable helpers for driving the Ultimate 64 Elite's host-visible
; Command Interface at $DF1B-$DF1F. None of these touch zero page — everything
; is absolute or abs,Y — so the crypto / ip65 ZP save/restore dance is not
; required around calls. Matches the hand-emitted pattern in
; c64-test-harness/scripts/test_uci_tcp_echo.py.
;
; Exported primitives (see the per-routine headers for calling conventions):
;
;   uci_abort          — flush the state machine (write ABORT + short delay)
;   uci_wait_idle      — spin until (STATE==0 AND CMD_BUSY==0)
;   uci_wait_not_busy  — spin until CMD_BUSY==0
;   uci_begin_cmd      — A = target id; writes target to UCI_CMD_DATA
;   uci_put_byte       — A = parameter byte; writes to UCI_CMD_DATA
;   uci_push_wait      — writes PUSH_CMD, then uci_wait_not_busy
;   uci_check_err      — returns C=1 if error bit set, clears it; C=0 otherwise
;   uci_read_resp_bytes— drain DATA_AV bytes to caller-provided buffer
;                        (caller fills uci_resp_dst/uci_resp_max beforehand;
;                         uci_resp_count returned; Y = count)
;   uci_drain_resp     — drain remaining DATA_AV bytes to nowhere, ACKing each
;   uci_drain_status   — drain remaining STAT_AV bytes to nowhere, ACKing each
;   uci_ack            — single NEXT_DATA pulse
;
; Phase 2 only needs enough machinery for GET_IPADDR (12-byte response,
; one interface-index parameter). Later phases will extend as needed.

.include "uci_regs.inc"

.export uci_abort
.export uci_wait_idle
.export uci_wait_not_busy
.export uci_begin_cmd
.export uci_put_byte
.export uci_push_wait
.export uci_check_err
.export uci_read_resp_bytes
.export uci_drain_resp
.export uci_drain_status
.export uci_ack

.export uci_resp_dst
.export uci_resp_max
.export uci_resp_count

.segment "UCI_CODE"

; =============================================================================
; uci_abort — force the UCI FIFO back to idle
; Writes ABORT to UCI_CONTROL, then burns ~$20 iterations as a settle delay.
; Clobbers: A, X
; =============================================================================
uci_abort:
        lda #UCI_CTRL_ABORT
        sta UCI_CONTROL
        lda UCI_STATUS          ; bus fence — let FPGA latch the write
        ldx #$20
@spin:
        dex
        bne @spin
        rts

; =============================================================================
; uci_wait_idle — spin until STATE==0 AND CMD_BUSY==0
; UCI_STAT_STATE ($30) covers the state field; CMD_BUSY ($01) is bit 0.
; ORing them (MASK $31) and looping while nonzero gives "fully idle".
; Clobbers: A
; =============================================================================
uci_wait_idle:
        lda UCI_STATUS
        and #(UCI_STAT_STATE | UCI_STAT_CMD_BUSY)   ; $31
        bne uci_wait_idle
        rts

; =============================================================================
; uci_wait_not_busy — spin until CMD_BUSY==0 (ignore STATE)
; Called after writing PUSH_CMD while response data / status is still being
; prepared — STATE is allowed to be nonzero here.
; Clobbers: A
; =============================================================================
uci_wait_not_busy:
        lda UCI_STATUS
        and #UCI_STAT_CMD_BUSY
        bne uci_wait_not_busy
        rts

; =============================================================================
; uci_begin_cmd — entry: A = target id (e.g. UCI_TARGET_NETWORK = $03)
; Writes A to UCI_CMD_DATA. Caller continues pushing the command byte and
; any parameters (via uci_put_byte or direct STA UCI_CMD_DATA).
; Clobbers: none beyond A
; =============================================================================
uci_begin_cmd:
        sta UCI_CMD_DATA
        lda UCI_STATUS          ; bus fence
        rts

; =============================================================================
; uci_put_byte — entry: A = parameter byte
; Thin wrapper around STA UCI_CMD_DATA for readability at call sites.
; Clobbers: none beyond A
; =============================================================================
uci_put_byte:
        sta UCI_CMD_DATA
        lda UCI_STATUS          ; bus fence
        rts

; =============================================================================
; uci_push_wait — commit pushed bytes as a command, then wait for CMD_BUSY=0
; Clobbers: A
; =============================================================================
uci_push_wait:
        lda #UCI_CTRL_PUSH_CMD
        sta UCI_CONTROL
        lda UCI_STATUS          ; bus fence
        jmp uci_wait_not_busy

; =============================================================================
; uci_check_err — test UCI_STAT_ERROR
; Output: C=1 if error bit was set (error has been cleared); C=0 otherwise.
; Clobbers: A
; =============================================================================
uci_check_err:
        lda UCI_STATUS
        and #UCI_STAT_ERROR
        beq @no_err
        ; clear the latched error
        lda #UCI_CTRL_CLR_ERR
        sta UCI_CONTROL
        lda UCI_STATUS          ; bus fence
        sec
        rts
@no_err:
        clc
        rts

; =============================================================================
; uci_ack — single NEXT_DATA pulse (advance response/status FIFO by one byte)
; Clobbers: A
; =============================================================================
uci_ack:
        lda #UCI_CTRL_NEXT_DATA
        sta UCI_CONTROL
        lda UCI_STATUS          ; bus fence
        rts

; =============================================================================
; uci_read_resp_bytes — drain DATA_AV bytes into caller-provided buffer.
;
; Caller must set:
;   uci_resp_dst (2 bytes) — destination pointer
;   uci_resp_max (1 byte)  — max bytes to store
;
; On return:
;   uci_resp_count         — actual bytes stored
;   Y                      — same value (convenience for callers)
;
; Reads while DATA_AV is set AND count < max, storing each byte via a
; self-modified `STA uci_resp_dst,Y`, ACKing each byte with NEXT_DATA.
; If DATA_AV clears before max is reached, returns early. If max is reached
; while DATA_AV is still set, the excess is left for uci_drain_resp.
;
; Clobbers: A, Y. X preserved.
; =============================================================================
uci_read_resp_bytes:
        ; Patch the dst pointer into the STA abs,Y instruction below.
        ; The inner loop mirrors the SOCKET_READ read pattern in
        ; c64-test-harness/scripts/test_uci_tcp_echo.py (lines ~350-362):
        ; tight-poll DATA_AV and read $DF1E directly — the UCI response
        ; FIFO auto-advances on read, so no per-byte NEXT_DATA is needed
        ; inside the loop. NEXT_DATA acknowledgment happens once at the
        ; end via uci_drain_resp / uci_ack.
        lda uci_resp_dst
        sta @rd_store+1
        lda uci_resp_dst+1
        sta @rd_store+2
        ldy #$00
@rd_loop:
        cpy uci_resp_max
        bcs @rd_done
        lda UCI_STATUS
        and #UCI_STAT_DATA_AV
        beq @rd_done
        lda UCI_RESP_DATA
@rd_store:
        sta $FFFF,y             ; SMC: dst low/high patched above
        iny
        jmp @rd_loop
@rd_done:
        sty uci_resp_count
        rts

; =============================================================================
; uci_drain_resp — ACK remaining response bytes until DATA_AV is clear.
; Used after uci_read_resp_bytes when the caller only wanted the first N bytes
; of a potentially longer response. Reads UCI_RESP_DATA (forcing the FIFO to
; advance on firmwares that require a read), then pulses NEXT_DATA.
; Clobbers: A
; =============================================================================
uci_drain_resp:
        lda UCI_STATUS
        and #UCI_STAT_DATA_AV
        beq @drn_done
        lda UCI_RESP_DATA
        lda #UCI_CTRL_NEXT_DATA
        sta UCI_CONTROL
        lda UCI_STATUS          ; bus fence
        jmp uci_drain_resp
@drn_done:
        rts

; =============================================================================
; uci_drain_status — ACK remaining status string bytes until STAT_AV is clear.
; Phase 2 discards the status string; later phases may want to capture it.
; Clobbers: A
; =============================================================================
uci_drain_status:
        lda UCI_STATUS
        and #UCI_STAT_STAT_AV
        beq @dst_done
        lda UCI_STATUS_DATA
        lda #UCI_CTRL_NEXT_DATA
        sta UCI_CONTROL
        lda UCI_STATUS          ; bus fence
        jmp uci_drain_status
@dst_done:
        rts

; =============================================================================
; Control block for uci_read_resp_bytes — lives in UCI_BSS so no ZP is needed
; and the block persists across backend calls.
; =============================================================================
.segment "UCI_BSS"

uci_resp_dst:    .res 2         ; destination pointer (lo, hi)
uci_resp_max:    .res 1         ; max bytes to store
uci_resp_count:  .res 1         ; actual bytes stored (filled on return)
