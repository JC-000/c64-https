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
;   uci_wait_idle      — spin until (STATE==0 AND CMD_BUSY==0); TOD-bounded
;   uci_wait_not_busy  — spin until CMD_BUSY==0; TOD-bounded
;   uci_begin_cmd      — A = target id; writes target to UCI_CMD_DATA
;   uci_put_byte       — A = parameter byte; writes to UCI_CMD_DATA
;   uci_push_wait      — writes PUSH_CMD, then uci_wait_not_busy
;   uci_check_err      — returns C=1 if error bit set, clears it; C=0 otherwise
;   uci_read_resp_bytes— drain DATA_AV bytes to caller-provided buffer
;                        (caller fills uci_resp_dst/uci_resp_max beforehand;
;                         uci_resp_count returned; Y = count)
;   uci_drain_resp     — drain remaining DATA_AV bytes to nowhere, ACKing
;                        each; TOD-bounded (5 s wall-clock)
;   uci_drain_status   — drain remaining STAT_AV bytes to nowhere, ACKing
;                        each; TOD-bounded (5 s wall-clock)
;   uci_ack            — single NEXT_DATA pulse
;
; Phase 2 only needs enough machinery for GET_IPADDR (12-byte response,
; one interface-index parameter). Later phases will extend as needed.

.include "uci_regs.inc"
.include "uci_errors.inc"

; net_last_error lives in net.s's BSS — we set it on wait timeout
; (#37 for uci_wait_idle; Phase 5 wedge for uci_wait_not_busy).
.import net_last_error

.export uci_abort
.export uci_tod_start
.export uci_status_buf
.export uci_status_len
.export uci_status_seen
.export uci_status_force
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
        uci_fence
        ldx #$20
@spin:
        dex
        bne @spin
        rts

; =============================================================================
; uci_tod_start — start CIA1's Time-of-Day clock (issue #145)
;
; Every bounded wait below measures wall-clock time by watching CIA1's
; TENTHS register advance. The CIA's TOD does NOT run out of reset: it
; stays halted until TENTHS is written. Nothing in the KERNAL writes it
; (the jiffy clock is Timer A, not TOD), and until this routine landed
; nothing here did either — so on real hardware every "5 s bounded" wait
; was in fact unbounded, `cmp last_tenths` comparing a frozen value
; forever. The bound was decorative, not real.
;
; Measured on a U64E (fw 3.15) by the c64-wireguard lane, which ports
; this adapter's design: with the machine hung inside a wait, 207 IRQ
; samples over 3 s read TOD 00:00:00.0 every time, hour byte $91 (the
; untouched reset value). Writing TENTHS once from the IRQ hook started
; the clock and the hung wait expired within 2 s with C=1. VICE's CIA
; runs the TOD from reset, which is exactly why no emulator test here
; ever caught it, and why the regression guard for this is a hardware
; rig (tools/uci/boot_check.py) rather than a VICE suite.
;
; Write order is the datasheet's: writing HOURS halts the clock and
; writing TENTHS starts it, so tenths goes last. CRB bit 7 selects
; whether these writes land in the clock or the alarm — clear it,
; preserving Timer B's control bits.
;
; Called from net_init, which every entry path runs before the first
; bounded wait (do_net_init reaches net_init before net_dhcp_acquire),
; and a C64 reset halts the TOD again — so this belongs in init, not in
; a one-off boot hook.
;
; Measured once the clock actually runs (U64E @ 48 MHz, 2026-08-28,
; instrumented high-water mark over four full github.com handshakes): the
; longest bounded wait observed is ONE tenth, 0.1 s, against a 5 s budget.
; The budget is ~50x the worst real wait, so it fires only on a genuine
; wedge — which is what it is for. One UCI_ERR_WAIT_TIMEOUT ($89) has been
; seen in the field on an otherwise PASSING run, so the ceiling is not
; purely theoretical; do not tighten it without re-measuring.
;
; The TOD counts its own 60 Hz input rather than CPU cycles, which is the
; whole point: turbo cannot shrink it. Measured on the U64E at 48 MHz,
; TOD-elapsed / wall-elapsed = 0.996 over a 10 s window, i.e. the "5 s"
; budget really is 5.02 s. On a PAL machine the 50 Hz input
; against the default CRA bit 7 = 0 runs the clock at 5/6 rate, stretching
; a 5 s budget to 6 s — harmless for a timeout, and not worth detecting.
;
; Clobbers: A
; =============================================================================
uci_tod_start:
        lda CIA_CRB
        and #$7F                    ; CRB bit 7 = 0 → writes set clock, not alarm
        sta CIA_CRB
        lda #$00
        sta CIA_TOD_HOUR            ; writing HOURS halts the TOD
        sta CIA_TOD_MIN
        sta CIA_TOD_SEC
        sta CIA_TOD_TENTHS          ; writing TENTHS starts it running
        rts

; =============================================================================
; uci_wait_idle — spin until STATE==0 AND CMD_BUSY==0, with wall-clock cap
; UCI_STAT_STATE ($30) covers the state field; CMD_BUSY ($01) is bit 0.
; ORing them (MASK $31) and looping while nonzero gives "fully idle".
;
; Issue #37 — the historical unbounded spin converts an FPGA wedge into a
; 600 s test sentinel timeout. The cap below uses CIA1 TOD (CIA_TOD_TENTHS,
; ticks at 10 Hz) — the only clock that runs at the same wall-clock rate
; regardless of CPU turbo speed. Cycle-counted budgets do NOT work here:
; the per-iteration cost scales with turbo (each fence is ~38 us of FPGA
; wall time but only a few CPU cycles at 48 MHz), so a budget tuned at
; 1 MHz collapses at 48 MHz (and vice versa). A prior attempt on
; feat/net-drain-abi shipped cycle-counted budgets and broke turbo DHCP
; for exactly this reason.
;
; CIA TOD read protocol: reading the HOUR register latches the four
; registers atomically; reading the TENTHS register unlatches them.
; We only need TENTHS for our 5-second budget, but we still latch+unlatch
; properly so we don't disturb other code that might be reading TOD.
;
; Budget: UCI_WAIT_IDLE_BUDGET_TENTHS (50 = 5 s). On expiry: set
; net_last_error = UCI_ERR_WAIT_TIMEOUT, return C=1.
;
; Output: C=0 on idle, C=1 on timeout.
; Clobbers: A
; =============================================================================
CIA_TOD_TENTHS = $DC08
CIA_TOD_SEC    = $DC09
CIA_TOD_MIN    = $DC0A
CIA_TOD_HOUR   = $DC0B
CIA_CRB        = $DC0F
UCI_WAIT_IDLE_BUDGET_TENTHS = 50      ; 5 seconds at 10 Hz

uci_wait_idle:
        ; Sample initial TENTHS for delta-tracking. Latch via HOUR,
        ; release via TENTHS. We don't care about the HOUR value itself.
        lda CIA_TOD_HOUR
        lda CIA_TOD_TENTHS
        sta @wi_last_tenths
        lda #$00
        sta @wi_elapsed
@wi_loop:
        lda UCI_STATUS
        uci_fence                   ; settle read before testing bits
        and #(UCI_STAT_STATE | UCI_STAT_CMD_BUSY)   ; $31
        beq @idle_done

        ; Check TOD for elapsed tenths. Latch (HOUR) then read TENTHS.
        lda CIA_TOD_HOUR
        lda CIA_TOD_TENTHS
        cmp @wi_last_tenths
        beq @wi_loop                ; no change — keep spinning
        sta @wi_last_tenths
        inc @wi_elapsed
        lda @wi_elapsed
        cmp #UCI_WAIT_IDLE_BUDGET_TENTHS
        bcc @wi_loop                ; under budget — continue
        ; Timeout
        lda #UCI_ERR_WAIT_TIMEOUT
        sta net_last_error
        sec
        rts
@idle_done:
        clc
        rts
@wi_last_tenths: .byte 0
@wi_elapsed:     .byte 0

; =============================================================================
; uci_wait_not_busy — spin until CMD_BUSY==0 (ignore STATE), wall-clock bounded
; Called after writing PUSH_CMD while response data / status is still being
; prepared — STATE is allowed to be nonzero here.
;
; Phase 5 wedge (CertVerify recv on U64E at 10.43.23.81, May 2026) — the
; historical unbounded spin converted an FPGA wedge into a 1843 s test
; sentinel timeout. Per the parent CLAUDE.md "Design note — bounded
; timeouts must use wall-clock time", convert to the same CIA1 TOD pattern
; used by uci_wait_idle (issue #37). Same 5 s budget, same error code,
; same SMC-byte state convention (no ZP).
;
; Output: C=0 on not-busy, C=1 on timeout (net_last_error = UCI_ERR_WAIT_TIMEOUT).
; Clobbers: A
; =============================================================================
uci_wait_not_busy:
        ; Sample initial TENTHS for delta-tracking. Latch via HOUR,
        ; release via TENTHS. We don't care about the HOUR value itself.
        lda CIA_TOD_HOUR
        lda CIA_TOD_TENTHS
        sta @wnb_last_tenths
        lda #$00
        sta @wnb_elapsed
@wnb_loop:
        lda UCI_STATUS
        uci_fence                   ; settle read before testing bits
        and #UCI_STAT_CMD_BUSY
        beq @wnb_done

        ; Check TOD for elapsed tenths. Latch (HOUR) then read TENTHS.
        lda CIA_TOD_HOUR
        lda CIA_TOD_TENTHS
        cmp @wnb_last_tenths
        beq @wnb_loop_long          ; no change — keep spinning
        sta @wnb_last_tenths
        inc @wnb_elapsed
        lda @wnb_elapsed
        cmp #UCI_WAIT_IDLE_BUDGET_TENTHS
        bcc @wnb_loop_long          ; under budget — continue
        ; Timeout
        lda #UCI_ERR_WAIT_TIMEOUT
        sta net_last_error
        sec
        rts
@wnb_loop_long:
        jmp @wnb_loop               ; long branch: fence too wide for BCC/BEQ
@wnb_done:
        clc
        rts
@wnb_last_tenths: .byte 0
@wnb_elapsed:     .byte 0

; =============================================================================
; uci_begin_cmd — entry: A = target id (e.g. UCI_TARGET_NETWORK = $03)
; Writes A to UCI_CMD_DATA. Caller continues pushing the command byte and
; any parameters (via uci_put_byte or direct STA UCI_CMD_DATA).
; Clobbers: none beyond A
; =============================================================================
uci_begin_cmd:
        sta UCI_CMD_DATA
        uci_fence
        rts

; =============================================================================
; uci_put_byte — entry: A = parameter byte
; Thin wrapper around STA UCI_CMD_DATA for readability at call sites.
; Clobbers: none beyond A
; =============================================================================
uci_put_byte:
        sta UCI_CMD_DATA
        uci_fence
        rts

; =============================================================================
; uci_push_wait — commit pushed bytes as a command, then wait for CMD_BUSY=0
;
; At turbo speeds the FPGA may not have latched PUSH_CMD by the time the
; CPU starts polling CMD_BUSY. A plain uci_fence after the write gives only
; ≈ 2 µs at 48 MHz — insufficient for the FPGA to assert CMD_BUSY. We add
; a short delay loop ($40 iterations ≈ 6 µs at 48 MHz, ≈ 300 µs at 1 MHz)
; before polling, ensuring CMD_BUSY has been asserted by the time we check.
;
; Clobbers: A, X
; =============================================================================
uci_push_wait:
        lda #UCI_CTRL_PUSH_CMD
        sta UCI_CONTROL
        uci_fence
        ; Fixed settle delay — at turbo speeds the FPGA may not have
        ; latched PUSH_CMD and asserted CMD_BUSY by the time the CPU
        ; starts polling. $FF iterations × 5 cycles ≈ 27 µs at 48 MHz,
        ; ≈ 1.3 ms at 1 MHz — sufficient for the FPGA to latch the
        ; command without using inline NOP fences that bloat code size.
        ldx #$FF
@pw_settle:
        dex
        bne @pw_settle
        jmp uci_wait_not_busy

; =============================================================================
; uci_check_err — test UCI_STAT_ERROR
; Output: C=1 if error bit was set (error has been cleared); C=0 otherwise.
; Clobbers: A
; =============================================================================
uci_check_err:
        lda UCI_STATUS
        uci_fence                   ; settle before testing error bit
        and #UCI_STAT_ERROR
        bne @has_err
        clc
        rts
@has_err:
        ; Re-arm the status capture. The passive filter in uci_drain_status
        ; drops the routine "00,OK" and "02,NO DATA: 11" lines so they cannot
        ; squat in the single sticky slot, but that filter would also drop
        ; "02,NO DATA: 9" — errno 9 is EBADF, the firmware's owned-socket
        ; guard (GideonZ/1541ultimate#814), and the one line most worth
        ; having. So an error path takes the slot unconditionally: whatever
        ; the next drain sees belongs to a command that just failed.
        lda #$00
        sta uci_status_len
        sta uci_status_force
        dec uci_status_force        ; $FF — capture the next line regardless
        ; clear the latched error
        lda #UCI_CTRL_CLR_ERR
        sta UCI_CONTROL
        uci_fence
        sec
        rts

; =============================================================================
; uci_ack — single NEXT_DATA pulse (advance response/status FIFO by one byte)
; Clobbers: A
; =============================================================================
uci_ack:
        lda #UCI_CTRL_NEXT_DATA
        sta UCI_CONTROL
        uci_fence
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
        ; At turbo speeds the firmware may not have staged response data
        ; by the time the CPU reaches this point (e.g. TCP_CONNECT takes
        ; a full network round-trip). Use a 16-bit spin-wait on DATA_AV
        ; so we tolerate up to ~150 ms at 48 MHz without bailing early.
        lda uci_resp_dst
        sta @rd_store+1
        lda uci_resp_dst+1
        sta @rd_store+2
        ldy #$00
@rd_loop:
        cpy uci_resp_max
        bcc @rd_not_max
        jmp @rd_done
@rd_not_max:
        ; 16-bit spin-wait for DATA_AV. ~65536 iterations; at 48 MHz
        ; each iteration is ~110 cycles → total ≈ 150 ms, enough for
        ; TCP handshakes over a LAN. X is preserved across the wait.
        stx @rd_save_x
        lda #$00
        sta @rd_ctr_hi
        ldx #$00
@rd_wait:
        lda UCI_STATUS
        uci_fence                   ; settle before testing DATA_AV
        and #UCI_STAT_DATA_AV
        bne @rd_have
        dex
        beq @rd_xzero
        jmp @rd_wait                ; long branch: fence too wide for BNE
@rd_xzero:
        dec @rd_ctr_hi
        beq @rd_timeout
        jmp @rd_wait                ; long branch: fence too wide for BNE
@rd_timeout:
        ; Timeout: DATA_AV never appeared — bail with partial read.
        ldx @rd_save_x
        jmp @rd_done
@rd_have:
        ldx @rd_save_x
        lda UCI_RESP_DATA
        uci_fence                   ; settle before storing/looping
@rd_store:
        sta $FFFF,y             ; SMC: dst low/high patched above
        iny
        jmp @rd_loop
@rd_done:
        sty uci_resp_count
        rts
@rd_save_x: .byte 0
@rd_ctr_hi: .byte 0

; =============================================================================
; uci_drain_resp — ACK remaining response bytes until DATA_AV is clear.
; Used after uci_read_resp_bytes when the caller only wanted the first N bytes
; of a potentially longer response. Reads UCI_RESP_DATA (forcing the FIFO to
; advance on firmwares that require a read), then pulses NEXT_DATA.
;
; Phase 5j — wall-clock-bounded via CIA1 TOD (5 s budget, mirrors
; uci_wait_idle / uci_wait_not_busy from issue #37 and Phase 5b).
; Secondary-risk fix per CLAUDE.md Phase 5j brief: net_tcp_send /
; net_poll / net_tcp_close all call drains after a SOCKET_WRITE or
; POLL_DATA; if firmware ever leaves DATA_AV asserted post-SOCKET_WRITE
; the unbounded `jmp` loop wedges with no wall-clock escape.
;
; Output: C=0 on drain complete, C=1 on timeout
;         (net_last_error = UCI_ERR_WAIT_TIMEOUT).
; Clobbers: A
; =============================================================================
uci_drain_resp:
        ; Sample initial TENTHS for delta-tracking. Latch via HOUR,
        ; release via TENTHS.
        lda CIA_TOD_HOUR
        lda CIA_TOD_TENTHS
        sta @drn_last_tenths
        lda #$00
        sta @drn_elapsed
@drn_loop:
        lda UCI_STATUS
        uci_fence                   ; settle before testing DATA_AV
        and #UCI_STAT_DATA_AV
        bne @drn_have
        clc
        rts
@drn_have:
        lda UCI_RESP_DATA
        uci_fence                   ; settle before NEXT_DATA write
        lda #UCI_CTRL_NEXT_DATA
        sta UCI_CONTROL
        uci_fence

        ; Check TOD for elapsed tenths. Latch (HOUR) then read TENTHS.
        lda CIA_TOD_HOUR
        lda CIA_TOD_TENTHS
        cmp @drn_last_tenths
        beq @drn_loop_long          ; no change — keep draining
        sta @drn_last_tenths
        inc @drn_elapsed
        lda @drn_elapsed
        cmp #UCI_WAIT_IDLE_BUDGET_TENTHS
        bcc @drn_loop_long          ; under budget — continue
        ; Timeout
        lda #UCI_ERR_WAIT_TIMEOUT
        sta net_last_error
        sec
        rts
@drn_loop_long:
        jmp @drn_loop               ; long branch: fence too wide for BEQ/BCC
@drn_last_tenths: .byte 0
@drn_elapsed:     .byte 0

; =============================================================================
; uci_drain_status — drain the status line, and CAPTURE it (#147).
;
; "Later phases may want to capture it" — this is that phase. $DF1F is
; where every UCI target reports its result; the ERROR bit in $DF1C means
; only "a command was sent while not idle" and is NOT a result channel.
; Discarding this line is why every failure collapsed into one UCI_ERR_*
; byte with the firmware's named reason thrown away.
;
; Two things here were learned the hard way in the c64-wireguard lane,
; which ports this adapter's design, and are copied from it:
;
;   * NO PER-BYTE ACK. The FIFO auto-advances on read (the same Phase 2
;     finding net_poll's header read relies on). The NEXT_DATA pulse this
;     loop used to issue per byte popped the whole line, so the drain read
;     byte one and then saw STAT_AV clear and stopped. Measured here
;     before the port: the capture returned "0" where the firmware had
;     sent "02,NO DATA: 9". Every status line this adapter ever drained
;     was truncated after one byte; nobody noticed because the bytes went
;     nowhere.
;   * STICKY-FIRST commit. net_poll drains status several times per
;     cycle; the first drain after a command takes the whole line and the
;     later ones catch at most a stray byte. Publishing the LAST non-empty
;     capture therefore lets a 1-byte remnant overwrite the real line.
;     The first capture wins and stays until a consumer zeroes
;     uci_status_len.
;
; uci_status_seen is NON-sticky — bytes this drain actually saw, rewritten
; (0 included) every call — so a caller can distinguish "the firmware
; refused and said why" from "nothing came back".
;
; Phase 5j — wall-clock-bounded via CIA1 TOD (5 s budget, mirrors
; uci_drain_resp above).
;
; Output: C=0 on drain complete, C=1 on timeout
;         (net_last_error = UCI_ERR_WAIT_TIMEOUT).
; Clobbers: A, X  (X is the capture index; no call site holds it — the
;                  DHCP probe keeps its interface index in memory, and
;                  net_poll already documents clobbering X)
; =============================================================================
uci_drain_status:
        lda #$00
        sta @dst_idx
        ; Sample initial TENTHS for delta-tracking. Latch via HOUR,
        ; release via TENTHS.
        lda CIA_TOD_HOUR
        lda CIA_TOD_TENTHS
        sta @dst_last_tenths
        lda #$00
        sta @dst_elapsed
@dst_loop:
        lda UCI_STATUS
        uci_fence                   ; settle before testing STAT_AV
        and #UCI_STAT_STAT_AV
        bne @dst_have
        jsr @dst_commit
        clc
        rts
@dst_have:
        lda UCI_STATUS_DATA
        uci_fence
        ; Hold the committed line intact. uci_status_len is sticky, but the
        ; BUFFER is shared, so without this a later drain scribbles over the
        ; bytes the length still describes: a held "02,NO DATA: 11" with a
        ; subsequent "00,OK" written across its head reads back as
        ; '00,OK DATA: 11'. Measured on hardware — a plausible-looking string
        ; that never came off the wire, which is worse than no capture at all.
        ldx uci_status_len
        bne @dst_seen_only          ; a line is already held — count only
        ldx @dst_idx
        cpx #UCI_STATUS_MAX
        bcs @dst_seen_only          ; buffer full — count only
        sta uci_status_buf,x
@dst_seen_only:
        inc @dst_idx                ; counts every byte SEEN, stored or not
        ; NO PER-BYTE ACK — see the header. The read advanced the FIFO.

        ; Check TOD for elapsed tenths. Latch (HOUR) then read TENTHS.
        lda CIA_TOD_HOUR
        lda CIA_TOD_TENTHS
        cmp @dst_last_tenths
        beq @dst_loop_long          ; no change — keep draining
        sta @dst_last_tenths
        inc @dst_elapsed
        lda @dst_elapsed
        cmp #UCI_WAIT_IDLE_BUDGET_TENTHS
        bcc @dst_loop_long          ; under budget — continue
        ; Timeout
        lda #UCI_ERR_WAIT_TIMEOUT
        sta net_last_error
        jsr @dst_commit
        sec
        rts
@dst_commit:
        lda @dst_idx
        sta uci_status_seen         ; non-sticky: what THIS drain saw
        beq @dst_commit_done
        ldx uci_status_len
        bne @dst_commit_done        ; one already held — do not clobber it
        ldx uci_status_force
        beq @dst_filter
        ldx #$00
        stx uci_status_force        ; one-shot
        beq @dst_commit_take        ; forced: skip the routine-line filter
@dst_filter:
        ; Skip a success line. We diverge from the c64-wireguard lane here,
        ; deliberately: their consumer reads the line in band and clears the
        ; slot, ours is a post-mortem dump with no consumer to clear it. Plain
        ; sticky-first would therefore park "00,OK" from the run's first drain
        ; in the one slot the first real failure needs. A line shorter than two
        ; bytes cannot be "00,..." and is kept.
        cmp #2
        bcc @dst_commit_take
        lda uci_status_buf+0
        cmp #'0'
        bne @dst_commit_take        ; not "0x," — always interesting
        lda uci_status_buf+1
        cmp #'0'
        beq @dst_commit_done        ; "00,OK"
        cmp #'2'
        beq @dst_commit_done        ; "02,NO DATA: 11" — every idle poll
@dst_commit_take:
        lda @dst_idx
        sta uci_status_len
@dst_commit_done:
        rts
@dst_loop_long:
        jmp @dst_loop               ; long branch: fence too wide for BEQ/BCC
@dst_last_tenths: .byte 0
@dst_elapsed:     .byte 0
; MUST stay above the non-local uci_status_* labels: those close this
; routine's ca65 cheap-local (@) scope, so an @dst_idx declared after them
; is a DIFFERENT symbol from the one this routine references. The
; c64-wireguard lane hit exactly that, and it also presents as capturing
; one byte and looking like the firmware emitting nothing.
@dst_idx:         .byte 0

; =============================================================================
; Control block for uci_read_resp_bytes — lives in UCI_BSS so no ZP is needed
; and the block persists across backend calls.
; =============================================================================
.segment "UCI_BSS"

; Captured status line (ASCII, e.g. "02,NO DATA: 9"). Not NUL-terminated;
; uci_status_len says how many bytes are valid, and is STICKY-FIRST — it
; holds the first non-empty line until a consumer zeroes it. net_init does
; that so a line cannot outlive the run that produced it.
uci_status_buf:  .res UCI_STATUS_MAX
uci_status_len:  .res 1
uci_status_seen: .res 1
uci_status_force: .res 1

uci_resp_dst:    .res 2         ; destination pointer (lo, hi)
uci_resp_max:    .res 1         ; max bytes to store
uci_resp_count:  .res 1         ; actual bytes stored (filled on return)
