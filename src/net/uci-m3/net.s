; src/net/uci-m3/net.s — BACKEND=uci-m3: TLS sockets on the Ultimate's ESP32
;
; The M3 firmware runs the TLS session on the ESP32 and hands the C64 a
; plaintext handle (M3-SPEC v1 + errata v1.1/v1.2; m3.inc names the files).
; This adapter implements the src/net_abi.inc surface on top of it, so the
; "TCP" connection the HTTP layer sees IS the verified TLS session:
;
;   net_init          ER-2 startup: presence check ($DF1D = $C9/$49), $0C
;                     (ABORT + clear error) and a bit-2 wait of up to 45 s,
;                     a CLOSE sweep of handles 0..15, then `03 23 FF` to
;                     detect TLS firmware (21,UNKNOWN COMMAND = none).
;   net_dhcp_acquire  GET_IPADDR per interface, as the plain UCI adapter.
;   net_dns_resolve   stages the host; the firmware resolves it inside
;                     OPEN_TLS, so net_resolved_ip reads the $FF x4 marker.
;   net_tcp_connect   waits for the INFO ready bits (ER-10), then OPEN_TLS
;                     `03 21`, BUNDLE trust (or PIN, HTTPS_PIN_SPKI), bound
;                     45 s. An ABORTed Open is followed by `03 25` (S 1.8).
;   net_tcp_send      READ until nothing is pending first (ER-21), then
;                     WRITE in <= 892 B pieces; all or nothing.
;   net_poll          one READ into the rx ring, the $0000/$FFFF rules of
;                     S 1.6 / Appendix A / ER-7 / ER-12.
;   net_tcp_close     CLOSE only while the handle is still ours.
;
; Handle 0 is a legal handle (ER-9): ownership is the m3_owned flag, never
; the handle's value. Errors use the existing UCI-family codes (m3.inc).

.include "uci_regs.inc"
.include "uci_errors.inc"
.include "constants.inc"
.include "net_states.inc"
.include "m3.inc"

; --- Public ABI: exactly the surface src/net_abi.inc imports -------------
.export net_init
.export net_poll
.export net_dhcp_acquire
.export net_tcp_connect
.export net_tcp_send
.export net_tcp_close
.export net_dns_resolve
.export net_local_ip
.export net_resolved_ip
.export net_last_error
.export net_tcp_state
.export net_recv_byte
.export net_send_len
.export net_banner_str

; --- M3 state, for the front end and the rigs ----------------------------
.export m3_handle
.export m3_owned
.export m3_eof_code
.export m3_poll_result
.export m3_open_reply
.export m3_info
.export m3_open_hint
; The typed-target prompt (src/boot.s) writes the host here, as on the 6510
; TLS build, where src/tls_handshake.s owns it (it is the SNI buffer there).
.export tls_hostname
.export tls_hostname_len

.import m3_clock_init
.import m3_dl_arm
.import m3_dl_expired
.import m3_begin
.import m3_put
.import m3_exec
.import m3_abort_wait
.import m3_abort_wait_ctl
.import m3_read_data
.import m3_discard_data
.import m3_discarded
.import m3_read_status
.import m3_accept
.import m3_finish
.import m3_settle
.import m3_rd_dst
.import m3_rd_max
.import m3_rd_count
.import m3_status
.import m3_status_len
.import m3_status_seen
.import m3_code
.import m3_wedged

.import tcp_recv_head
.import tcp_recv_tail
.import tcp_recv_overflow

; net_last_error values (src/net/uci/uci_errors.inc). The firmware's own
; reason is always in m3_status as well, and the UI prints it.
;   UCI_ERR_OPEN_REFUSED $8D  OPEN_TLS refused with a named status (c64-
;                             wireguard's allocation, mirrored; same meaning)
;   UCI_ERR_CMD_UNKNOWN  $8E  "21,UNKNOWN COMMAND": no M3 TLS firmware (ditto)
;   UCI_ERR_NOT_PRESENT  $81  no UCI, or INFO answered no capability record
;   UCI_ERR_CONNECT_FAIL $84  the Open never ran: push rejected, or a host
;                             the tail grammar refuses (empty, > 253 bytes)

.ifdef HTTPS_PIN_SPKI
.import m3_pin                  ; 32 B, digest order (src/boot.s)
M3_TRUST = M3_TRUST_PIN
M3_READY_NEED = M3_READY_MODULE | M3_READY_ENTROPY      ; PIN needs no time
.else
M3_TRUST = M3_TRUST_BUNDLE
M3_READY_NEED = M3_READY_MODULE | M3_READY_ENTROPY | M3_READY_TIME
.endif
.ifdef M3_ALLOW_TLS12
M3_FLAGS = 0                    ; 1.3 preferred, hardened 1.2 allowed (S 1.7)
.else
M3_FLAGS = M3_FLAG_TLS13_ONLY
.endif

.segment "UCI_CODE"

; =============================================================================
; net_init — the ER-2 startup procedure, then TLS detection.
; Out: C=0 the TLS firmware answered INFO; m3_info holds its record.
;      C=1 net_last_error: $81 no UCI; $8E no TLS firmware (m3_status
;          holds "21,UNKNOWN COMMAND"); $89 with m3_wedged set: bit 2
;          never cleared.
; Clobbers: A, X, Y
; =============================================================================
net_init:
        jsr m3_clock_init
        lda #0
        sta m3_wedged
        sta m3_owned
        sta m3_eof_code
        sta m3_status_len
        sta net_tcp_state           ; NET_TCP_CLOSED
        sta net_last_error
        ldx #3
@zero_ip:
        sta net_local_ip,x
        sta net_resolved_ip,x
        dex
        bpl @zero_ip

        ; Presence first: with the interface disabled $DF1C is open bus,
        ; so do not ABORT and do not wait (ER-2). $49 = $C9 with the UCI
        ; IRQ active.
        lda UCI_ID
        jsr m3_settle
        and #$7F
        cmp #(UCI_ID_VALUE & $7F)
        beq @present
        lda #UCI_ERR_NOT_PRESENT
        sta net_last_error
        sec
        rts
@present:
        ; $0C = ABORT + clear the sticky error bit 3, which survives a C64
        ; reset. The PUSH time of whatever an earlier program left is not
        ; known, so up to ABORT + 45 s (ER-1, ER-2).
        ldy #(UCI_CTRL_ABORT | UCI_CTRL_CLR_ERR)
        lda #<M3_B_UNKNOWN_PUSH
        ldx #>M3_B_UNKNOWN_PUSH
        jsr m3_abort_wait_ctl
        bcs @init_fail

        ; CLOSE sweep 0..15: frees every socket and session the network
        ; target still holds from an earlier program; an unowned number
        ; answers 12,ERROR ON CLOSE: 9 and touches nothing (ER-2). No
        ; `03 25` at boot (ER-2, porting item 7).
        lda #0
        sta m3_sweep
@sweep:
        lda #M3_CMD_CLOSE
        jsr m3_begin
        bcs @init_fail
        lda m3_sweep
        jsr m3_put
        lda #<M3_B_TLS
        ldx #>M3_B_TLS
        jsr m3_exec
        bcc @sweep_reply
        cmp #M3_EXEC_WEDGED
        beq @init_fail
        bne @sweep_next             ; an ABORTed CLOSE completed (S 1.1)
@sweep_reply:
        jsr m3_finish               ; 00,OK or 12,ERROR ON CLOSE: 9
@sweep_next:
        inc m3_sweep
        lda m3_sweep
        cmp #M3_SWEEP_HANDLES
        bcc @sweep

        jsr m3_info_caps
        bcs @init_fail
        lda #0
        sta net_last_error
        clc
        rts
@init_fail:
        sec
        rts

; =============================================================================
; m3_info_caps — `03 23 FF`, exactly 3 bytes (ER-4: a trailing $00 is 81 and
; claims). It claims nothing, so it is the one command allowed between an
; ABORTed Open and `03 25`. Out: C=0 m3_info = the 16-byte record.
; C=1: no TLS firmware ($8E; $81 if no record came back) or the command
; failed ($89 / wedged). Clobbers: A, X, Y
; =============================================================================
m3_info_caps:
        lda #M3_CMD_TLS_INFO
        jsr m3_begin
        bcs @ic_fail
        lda #M3_INFO_CAPS
        jsr m3_put
        lda #<M3_B_TLS
        ldx #>M3_B_TLS
        jsr m3_exec
        bcs @ic_fail                ; an ABORTed INFO needs nothing (S 1.1)
        lda #<m3_info
        sta m3_rd_dst
        lda #>m3_info
        sta m3_rd_dst+1
        lda #M3_INFO_LEN
        sta m3_rd_max
        jsr m3_read_data
        jsr m3_finish
        lda m3_code
        cmp #21
        beq @ic_unknown             ; 21,UNKNOWN COMMAND: no TLS firmware
        cmp #0
        bne @ic_no_record
        lda m3_rd_count
        cmp #M3_INFO_LEN
        bne @ic_no_record
        clc
        rts
@ic_unknown:
        lda #UCI_ERR_CMD_UNKNOWN
        bne @ic_set                 ; always
@ic_no_record:
        lda #UCI_ERR_NOT_PRESENT
@ic_set:
        sta net_last_error
@ic_fail:
        sec
        rts

; =============================================================================
; m3_wait_ready — ER-10: poll `03 23 FF` about once a second, up to 30 s,
; until INFO [4] has M3_READY_NEED (module, entropy, and trusted time unless
; PIN). On expiry it returns C=0 anyway and lets OPEN give the authoritative
; refusal (90/87/92), whose status line the UI prints.
; Out: C=1 only if INFO itself failed. Clobbers: A, X, Y
; =============================================================================
m3_wait_ready:
        lda #<M3_B_READY
        ldx #>M3_B_READY
        ldy #M3_DL_APP
        jsr m3_dl_arm
@wr_poll:
        jsr m3_info_caps
        bcs @wr_out
        lda m3_info+4
        and #M3_READY_NEED
        cmp #M3_READY_NEED
        beq @wr_ready
        ldy #M3_DL_APP
        jsr m3_dl_expired
        bcs @wr_ready               ; budget spent: OPEN decides
        lda #<M3_B_READY_POLL
        ldx #>M3_B_READY_POLL
        ldy #M3_DL_CMD
        jsr m3_dl_arm
@wr_sleep:
        ldy #M3_DL_CMD
        jsr m3_dl_expired
        bcc @wr_sleep
        bcs @wr_poll                ; always
@wr_ready:
        clc
@wr_out:
        rts

; =============================================================================
; m3_release — `03 25`, exactly 2 bytes (ER-4), as the NEXT network command
; after an ABORTed or unreadable Open: it closes that Open's session, if any,
; and nothing else (S 1.8). An ABORTed `03 25` is sent again (Appendix A).
; Clobbers: A, X, Y
; =============================================================================
m3_release:
        lda #2
        sta m3_tries
@rl_again:
        lda #M3_CMD_TLS_RELEASE
        jsr m3_begin
        bcs @rl_out
        lda #<M3_B_TLS
        ldx #>M3_B_TLS
        jsr m3_exec
        bcc @rl_reply
        cmp #M3_EXEC_ABORTED
        bne @rl_out
        dec m3_tries
        bne @rl_again
@rl_out:
        rts
@rl_reply:
        jmp m3_finish

; =============================================================================
; net_dhcp_acquire — the firmware's lease via GET_IPADDR, interfaces 0..3,
; first non-zero address wins (same contract as src/net/uci/net.s).
; Out: C=0 net_local_ip set; C=1 $83 no lease, or $82/$89.
; Clobbers: A, X, Y
; =============================================================================
NET_DHCP_MAX_IFACE = 4

net_dhcp_acquire:
        lda #0
        sta m3_sweep                ; interface index
@dh_next:
        lda #M3_CMD_GET_IPADDR
        jsr m3_begin
        bcs @dh_fail
        lda m3_sweep
        jsr m3_put
        lda #<M3_B_TLS
        ldx #>M3_B_TLS
        jsr m3_exec
        bcc @dh_reply
        cmp #M3_EXEC_REJECTED
        bne @dh_fail                ; aborted / wedged: $89 already set
        lda #UCI_ERR_CMD_FAILED
        sta net_last_error
        bne @dh_advance             ; always
@dh_reply:
        lda #<m3_ipaddr
        sta m3_rd_dst
        lda #>m3_ipaddr
        sta m3_rd_dst+1
        lda #12
        sta m3_rd_max
        jsr m3_read_data
        jsr m3_finish
        lda m3_rd_count
        cmp #4
        bcc @dh_none
        ldx #3
@dh_copy:
        lda m3_ipaddr,x
        sta net_local_ip,x
        dex
        bpl @dh_copy
        lda net_local_ip+0
        ora net_local_ip+1
        ora net_local_ip+2
        ora net_local_ip+3
        bne @dh_ok
@dh_none:
        lda #UCI_ERR_NO_IP
        sta net_last_error
@dh_advance:
        inc m3_sweep
        lda m3_sweep
        cmp #NET_DHCP_MAX_IFACE
        bcc @dh_next
@dh_fail:
        sec
        rts
@dh_ok:
        lda #0
        sta net_last_error
        clc
        rts

; =============================================================================
; net_dns_resolve — A/X = NUL-terminated host. Copies it to m3_host_buf; the
; firmware resolves it inside OPEN_TLS. A host of 0 or more than 253 bytes is
; refused here, as OPEN would refuse it with 81 (S 1.1 tail grammar).
; Out: C=0 staged (net_resolved_ip = $FF x4, the deferral marker);
;      C=1 net_last_error = $84. Clobbers: A, X, Y
; =============================================================================
net_dns_resolve:
        sta @dn_src+1
        stx @dn_src+2
        ldy #0
@dn_copy:
@dn_src:
        lda $FFFF,y                 ; SMC: the caller's host
        beq @dn_end
        sta m3_host_buf,y
        iny
        cpy #M3_HOST_MAX + 1
        bcc @dn_copy
        bcs @dn_bad                 ; 254 bytes and no NUL
@dn_end:
        sty m3_host_len
        tya
        beq @dn_bad
        lda #$FF
        ldx #3
@dn_mark:
        sta net_resolved_ip,x
        dex
        bpl @dn_mark
        lda #0
        sta net_last_error
        clc
        rts
@dn_bad:
        lda #0
        sta m3_host_len
        lda #UCI_ERR_CONNECT_FAIL
        sta net_last_error
        sec
        rts

; =============================================================================
; net_tcp_connect — OPEN_TLS to (m3_host_buf, A/X = port).
;
;   03 21 portLo portHi trust flags [pin32] host       (no trailing $00)
;
; Bound 45 s from the PUSH (ER-1). On success the reply's byte 0 is the
; handle — any value, 0 included (ER-9) — and bytes 1..7 are kept in
; m3_open_reply. On a refusal there is no reply and nothing stays open
; (S 1.1); m3_status holds the firmware's line (e.g. 93,CERTIFICATE NOT
; TRUSTED: 0x00000008). After an ABORTed Open, or a 00,OK with no handle
; byte to read, `03 25` is sent next (S 1.8).
; Out: C=0 NET_TCP_CONNECTED. C=1 NET_TCP_CONNECT_FAIL, net_last_error:
;      $8D refused by the firmware (m3_status names why); $84 push rejected;
;      $88 00,OK without a handle; $89 timeout (ABORTed) or wedged.
; Clobbers: A, X, Y
; =============================================================================
net_tcp_connect:
        sta m3_port
        stx m3_port+1
        lda #M3_HINT_NONE
        sta m3_open_hint
        lda m3_owned
        beq :+
        jsr net_tcp_close           ; one session at a time
        lda m3_owned
        beq :+
        ; The old handle could not be closed. Opening over it would lose
        ; the number and leave its session in the table (91 after two);
        ; refuse instead. 'I' re-runs the startup sweep, which frees it.
        lda #UCI_ERR_CONNECT_FAIL
        sta net_last_error
        jmp @tc_fail
:
        lda m3_host_len
        bne :+
        lda #UCI_ERR_CONNECT_FAIL
        sta net_last_error
        jmp @tc_fail
:
        jsr m3_wait_ready
        bcc :+
        jmp @tc_fail
:
        lda #M3_CMD_OPEN_TLS
        jsr m3_begin
        bcc :+
        jmp @tc_fail
:
        lda m3_port
        jsr m3_put
        lda m3_port+1
        jsr m3_put
        lda #M3_TRUST
        jsr m3_put
        lda #M3_FLAGS
        jsr m3_put
.ifdef HTTPS_PIN_SPKI
        ldy #0
@tc_pin:
        lda m3_pin,y
        jsr m3_put
        iny
        cpy #32
        bcc @tc_pin
.endif
        ldy #0
@tc_host:
        lda m3_host_buf,y
        jsr m3_put
        iny
        cpy m3_host_len
        bcc @tc_host
        lda #<M3_B_OPEN
        ldx #>M3_B_OPEN
        jsr m3_exec
        bcc @tc_reply
        cmp #M3_EXEC_REJECTED
        bne @tc_not_rejected
        lda #UCI_ERR_CONNECT_FAIL   ; push rejected: the Open never ran
        sta net_last_error
        bne @tc_fail_j              ; always
@tc_not_rejected:
        cmp #M3_EXEC_ABORTED
        bne @tc_fail_j              ; wedged: write nothing more
        jsr m3_release              ; ABORTed Open: `03 25` next
        lda #UCI_ERR_WAIT_TIMEOUT
        sta net_last_error
@tc_fail_j:
        jmp @tc_fail
@tc_reply:
        lda #<m3_open_reply
        sta m3_rd_dst
        lda #>m3_open_reply
        sta m3_rd_dst+1
        lda #M3_OPEN_REPLY_LEN
        sta m3_rd_max
        jsr m3_read_data
        jsr m3_finish
        lda m3_code
        bne @tc_refused
        ; S 1.1: success is EXACTLY 8 bytes. Fewer (or more, dropped by the
        ; discard) is a reply we cannot trust any byte of, the handle
        ; included: release the session it may have opened.
        lda m3_rd_count
        cmp #M3_OPEN_REPLY_LEN
        bne @tc_malformed
        lda m3_discarded
        bne @tc_malformed
.ifndef M3_ALLOW_TLS12
        ; Defence in depth: REQUIRE_TLS13 was asked for, so a session that
        ; reports any other version is refused here (reply [1..2], LE).
        lda m3_open_reply+1
        cmp #$04
        bne @tc_not_tls13
        lda m3_open_reply+2
        cmp #$03
        bne @tc_not_tls13
.endif
        lda m3_open_reply+0
        sta m3_handle
        lda #1
        sta m3_owned
        lda #0
        sta m3_eof_code
        sta net_last_error
        sta tcp_recv_overflow
        sta tcp_recv_head+0         ; a new stream: an empty ring
        sta tcp_recv_head+1
        sta tcp_recv_tail+0
        sta tcp_recv_tail+1
        lda #NET_TCP_CONNECTED
        sta net_tcp_state
        clc
        rts
@tc_malformed:
        ; A session exists that we hold no trustworthy handle for: release
        ; it now, while `03 25` is still the next command (S 1.1, "Never
        ; assume"). $88: the open yielded no usable socket id.
        lda #M3_HINT_MALFORMED
        sta m3_open_hint
        jsr m3_release
        lda #UCI_ERR_NO_SOCKET
        sta net_last_error
        bne @tc_fail                ; always
.ifndef M3_ALLOW_TLS12
@tc_not_tls13:
        lda #M3_HINT_NOT_TLS13
        sta m3_open_hint
        jsr m3_release              ; nothing has claimed it: `03 25` closes it
        lda #UCI_ERR_CONNECT_FAIL   ; the client refused the session
        sta net_last_error
        bne @tc_fail                ; always
.endif
@tc_refused:
.ifndef M3_ALLOW_TLS12
        ; Firmware-side rule (errata v1.3, coming): with REQUIRE_TLS13, ANY
        ; 14 during the Open means the server cannot or will not do TLS 1.3
        ; (a 1.2-only server may answer 40, not 70). Do not key on 70.
        cmp #14
        bne :+
        lda #M3_HINT_NO_TLS13
        sta m3_open_hint
:
.endif
        lda #UCI_ERR_OPEN_REFUSED   ; named in m3_status (e.g. 94,...)
        sta net_last_error
@tc_fail:
        lda #NET_TCP_CONNECT_FAIL
        sta net_tcp_state
        sec
        rts

; =============================================================================
; net_poll — one READ into the rx ring.
;
; Request min(ring free - 1, 893): one response block, no Data More (S 1.5).
; Then, by header and status (S 1.6, Appendix A, ER-5/7/12):
;   no header (bit 7 clear)  an empty reply (81/82): a READ of ours that
;                            the firmware refused. ERROR, still owned.
;   n > 0                    data into the ring. A block that is not read
;                            to its end (short, over-long, Data More)
;                            leaves a hole in the stream: ERROR, owned,
;                            so the CLOSE that follows is sent (ER-5).
;   $FFFF + 02,..: 11        nothing yet (M3_POLL_IDLE).
;   $FFFF + anything else    the number is not ours ("02,NO DATA: 9", ER-7):
;                            stop, and do NOT CLOSE it. ERROR, not owned.
;   $0000 + 01 / 05          the stream ended, everything delivered; the
;                            handle is GONE: do NOT CLOSE it. CLOSED, not
;                            owned; m3_eof_code = 1 or 5.
;   $0000 + 12/14/16/17      the session is dead but ours: ERROR, owned.
; A READ with no reply by PUSH + 12 s is ABORTed; its data is lost, so the
; handle is CLOSEd by the caller (ERROR, owned).
; Clobbers: A, X, Y
; =============================================================================
net_poll:
        lda net_tcp_state
        cmp #NET_TCP_CONNECTED
        beq @p_go
        lda #M3_POLL_END
        sta m3_poll_result
        rts
@p_go:
        ; free - 1 = (head - tail - 1) & mask
        lda tcp_recv_head+0
        clc                         ; -1 folded in: head - tail - 1
        sbc tcp_recv_tail+0
        sta m3_req
        lda tcp_recv_head+1
        sbc tcp_recv_tail+1
        and #>TCP_RECV_MASK
        sta m3_req+1
        ora m3_req
        bne :+
        lda #M3_POLL_FULL
        sta m3_poll_result
        rts
:
        lda m3_req
        cmp #<M3_READ_MAX
        lda m3_req+1
        sbc #>M3_READ_MAX           ; C=1 iff req >= MAX
        bcc :+
        lda #<M3_READ_MAX
        sta m3_req
        lda #>M3_READ_MAX
        sta m3_req+1
:
        lda #M3_POLL_END
        sta m3_poll_result
        lda #M3_CMD_READ
        jsr m3_begin
        bcc :+
        jmp @p_dead_owned
:
        lda m3_handle
        jsr m3_put
        lda m3_req
        jsr m3_put
        lda m3_req+1
        jsr m3_put
        lda #<M3_B_TLS
        ldx #>M3_B_TLS
        jsr m3_exec
        bcc @p_reply
        cmp #M3_EXEC_REJECTED
        bne :+
        lda #UCI_ERR_READ_FAIL      ; push rejected at READ
        sta net_last_error
:       jmp @p_dead_owned           ; ABORTed READ: data lost, CLOSE it

@p_reply:
        lda #0
        sta m3_bad                  ; 0, or the code a bad block earns
        ; ER-12: test bit 7 before the header. No data = an empty reply.
        lda UCI_STATUS
        jsr m3_settle
        and #UCI_STAT_DATA_AV
        bne :+
        jsr m3_finish
        jmp @p_dead_hdr             ; no header at all (81/82)
:
        lda #<m3_hdr
        sta m3_rd_dst
        lda #>m3_hdr
        sta m3_rd_dst+1
        lda #2
        sta m3_rd_max
        jsr m3_read_data
        lda m3_rd_count
        cmp #2
        beq :+
        jsr m3_finish               ; a 1-byte reply: no protocol has it
        jmp @p_dead_hdr
:
        lda m3_hdr+0
        and m3_hdr+1
        cmp #$FF
        bne :+
        jmp @p_ffff
:
        lda m3_hdr+0
        ora m3_hdr+1
        bne :+
        jmp @p_0000
:
        ; --- data: n = header, capped at the request ---------------------
        lda m3_req
        cmp m3_hdr+0
        lda m3_req+1
        sbc m3_hdr+1                ; C=1 iff req >= n
        bcs @p_copy_init
        lda #UCI_ERR_BAD_READ_HDR   ; over-claim that is not $FFFF
        sta net_last_error
        sta m3_bad
        lda m3_req
        sta m3_hdr+0
        lda m3_req+1
        sta m3_hdr+1
@p_copy_init:
@p_copy:
        lda m3_hdr+0
        ora m3_hdr+1
        beq @p_copied
        lda UCI_STATUS
        uci_fence
        and #UCI_STAT_DATA_AV
        bne :+
        lda #UCI_ERR_SHORT_READ     ; the block ended short of its header
        sta m3_bad
        jmp @p_copied
:
        clc
        lda tcp_recv_tail+0
        adc #<tcp_recv_buf
        sta @p_store+1
        lda tcp_recv_tail+1
        adc #>tcp_recv_buf
        sta @p_store+2
        lda UCI_RESP_DATA
        uci_fence
@p_store:
        sta $FFFF                   ; SMC: tcp_recv_buf + tail
        inc tcp_recv_tail+0
        bne :+
        inc tcp_recv_tail+1
:       lda tcp_recv_tail+1
        and #>TCP_RECV_MASK
        sta tcp_recv_tail+1
        lda m3_hdr+0
        bne :+
        dec m3_hdr+1
:       dec m3_hdr+0
        jmp @p_copy
@p_copied:
        ; Bytes left in this block, or a Data More block behind it, are a
        ; hole in the TLS stream: the session cannot be trusted (ER-5).
        jsr m3_discard_data
        lda m3_discarded
        beq :+
        lda m3_bad
        bne :+                      ; keep the first reason
        lda #UCI_ERR_BAD_READ_HDR   ; bytes past the header: dropped
        sta m3_bad
:
        lda UCI_STATUS
        jsr m3_settle
        and #UCI_STAT_STATE
        cmp #UCI_STAT_STATE         ; "11": Data More
        bne @p_last
        ; A data-accept would fetch the next block over the hole; ABORT
        ; instead (it drops the pending reply), then CLOSE (ER-5).
        lda #<M3_B_POST_ABORT
        ldx #>M3_B_POST_ABORT
        jsr m3_abort_wait
        jmp @p_dead_hdr
@p_last:
        jsr m3_read_status
        jsr m3_accept
        lda m3_bad
        bne @p_dead_code
        lda #M3_POLL_DATA
        sta m3_poll_result
        rts

@p_ffff:
        jsr m3_finish
        ; Idle is exactly "02,NO DATA: 11" (14 bytes ending "11").
        lda m3_code
        cmp #2
        bne @p_not_ours
        lda m3_status_seen
        cmp #14
        bne @p_not_ours
        lda m3_status+12
        cmp #'1'
        bne @p_not_ours
        lda m3_status+13
        cmp #'1'
        bne @p_not_ours
        lda #M3_POLL_IDLE
        sta m3_poll_result
        rts
@p_not_ours:
        ; "02,NO DATA: 9": the number is no longer ours. Any other $FFFF
        ; status means it now names a socket opened later (ER-7). Either
        ; way: stop, and do not CLOSE it. (No net_last_error code yet: the
        ; status line says which; a code is pending the fleet registry.)
        lda #0
        sta m3_owned
        lda #NET_TCP_ERROR
        sta net_tcp_state
        rts

@p_0000:
        jsr m3_finish
        lda m3_code
        cmp #1
        beq @p_gone
        cmp #5
        bne @p_dead_read            ; 12/14/16/17: dead, still ours
@p_gone:
        sta m3_eof_code
        lda #0
        sta m3_owned                ; GONE: the number may be reused (M10)
        lda #NET_TCP_CLOSED
        sta net_tcp_state
        rts

; The session is dead but the handle is still ours (the caller CLOSEs).
; The status line keeps the firmware's reason. net_last_error, for a READ
; reply the client could not use (finding 7 of the uci-m3 code review):
;   $8F UCI_ERR_SHORT_READ    the block ended short of its header
;                             (c64-wireguard's code, mirrored)
;   $8B UCI_ERR_BAD_READ_HDR  any other shape: no header (81/82), a 1-byte
;                             header, bytes past the header, Data More
; A dead session ($0000 + 12/14/16/17, @p_dead_read) sets no code yet; one
; is pending the fleet registry, and the status line says what happened.
@p_dead_hdr:
        lda m3_bad
        bne @p_dead_code            ; the reason the block was refused
        lda #UCI_ERR_BAD_READ_HDR
@p_dead_code:
        sta net_last_error
@p_dead_read:
@p_dead_owned:
        lda #NET_TCP_ERROR
        sta net_tcp_state
        rts

; =============================================================================
; net_tcp_send — A/X = data, net_send_len = length.
;
; First READ until nothing is pending ($FFFF + 11) or the stream has ended
; (ER-21): a WRITE after the peer's close_notify discards unread plaintext,
; and one after a reset loses it (Appendix A). A full ring stops the drain
; early; its bytes are already safe in the ring.
; Then WRITE in pieces of at most 892 B. A WRITE is all or nothing: header n
; = the whole piece and 00,OK, or $FFFF + a sticky status. A WRITE with no
; reply by PUSH + 12 s is ABORTed and NOT resent (it was carried out in
; full, or the handle is dead; S 1.1).
; Out: C=0 everything written. C=1 NET_TCP_ERROR (the caller CLOSEs if
;      m3_owned), net_last_error $87 refused / short, $85 push rejected,
;      $89 timeout. Clobbers: A, X, Y
; =============================================================================
net_tcp_send:
        sta m3_src
        stx m3_src+1
        lda net_send_len
        sta m3_rem
        lda net_send_len+1
        sta m3_rem+1
@s_drain:
        lda net_tcp_state
        cmp #NET_TCP_CONNECTED
        bne @s_not_open_j
        jsr net_poll
        lda net_tcp_state
        cmp #NET_TCP_CONNECTED
        bne @s_not_open_j
        lda m3_poll_result
        cmp #M3_POLL_DATA
        beq @s_drain
        bne @s_chunk                ; always
@s_not_open_j:
        jmp @s_not_open
@s_chunk:
        lda m3_rem
        ora m3_rem+1
        bne :+
        clc
        rts
:
        ; piece = min(rem, M3_WRITE_MAX)
        lda m3_rem
        cmp #<M3_WRITE_MAX
        lda m3_rem+1
        sbc #>M3_WRITE_MAX
        bcc @s_use_rem
        lda #<M3_WRITE_MAX
        sta m3_piece
        lda #>M3_WRITE_MAX
        sta m3_piece+1
        jmp @s_begin
@s_use_rem:
        lda m3_rem
        sta m3_piece
        lda m3_rem+1
        sta m3_piece+1
@s_begin:
        lda #M3_CMD_WRITE
        jsr m3_begin
        bcc :+
        jmp @s_dead
:
        lda m3_handle
        jsr m3_put
        lda m3_src
        sta @s_load+1
        lda m3_src+1
        sta @s_load+2
        lda m3_piece
        sta m3_cnt
        lda m3_piece+1
        sta m3_cnt+1
        ldy #0
@s_byte:
        lda m3_cnt
        ora m3_cnt+1
        beq @s_push
@s_load:
        lda $FFFF,y                 ; SMC: the source
        jsr m3_put
        iny
        bne :+
        inc @s_load+2
:       lda m3_cnt
        bne :+
        dec m3_cnt+1
:       dec m3_cnt
        jmp @s_byte
@s_push:
        lda #<M3_B_TLS
        ldx #>M3_B_TLS
        jsr m3_exec
        bcc @s_reply
        cmp #M3_EXEC_REJECTED
        bne @s_dead                 ; ABORTed: do not resend; $89 set
        lda #UCI_ERR_SEND_FAIL
        sta net_last_error
        bne @s_dead                 ; always
@s_reply:
        lda #<m3_wresp
        sta m3_rd_dst
        lda #>m3_wresp
        sta m3_rd_dst+1
        lda #2
        sta m3_rd_max
        jsr m3_read_data
        jsr m3_finish
        lda m3_rd_count
        cmp #2
        bne @s_short
        lda m3_code
        bne @s_short                ; $FFFF + 12/14/16/17: sticky
        lda m3_wresp
        cmp m3_piece
        bne @s_short
        lda m3_wresp+1
        cmp m3_piece+1
        bne @s_short
        clc
        lda m3_src
        adc m3_piece
        sta m3_src
        lda m3_src+1
        adc m3_piece+1
        sta m3_src+1
        sec
        lda m3_rem
        sbc m3_piece
        sta m3_rem
        lda m3_rem+1
        sbc m3_piece+1
        sta m3_rem+1
        jmp @s_chunk
@s_not_open:
@s_short:
        lda #UCI_ERR_SHORT_WRITE
        sta net_last_error
@s_dead:
        lda #NET_TCP_ERROR
        sta net_tcp_state
        sec
        rts

; =============================================================================
; net_tcp_close — CLOSE the handle while it is still ours (m3_owned).
; A handle seen GONE (01/05, "02,NO DATA: 9") is never CLOSEd: the number
; may already belong to another socket (S 1.6 M10, ER-7).
; Ownership ends only when the CLOSE RAN: a reply, or an ABORTed CLOSE
; (which completed, S 1.1). A REJECTED push never reached the Nios, so it
; is pushed once more; rejected twice, or a wedge, and the handle stays
; m3_owned, so the next close (net_tcp_connect tries one) or the startup
; sweep can still free its session.
; Out: NET_TCP_CLOSED always. C=0 closed or nothing to close; C=1 not
;      closed (m3_owned still 1 unless the CLOSE was ABORTed).
; Clobbers: A, X, Y
; =============================================================================
net_tcp_close:
        lda m3_owned
        beq @c_ok
        lda #2
        sta m3_tries
@c_again:
        lda #M3_CMD_CLOSE
        jsr m3_begin
        bcs @c_fail                 ; wedged: nothing written, still owned
        lda m3_handle
        jsr m3_put
        lda #<M3_B_TLS
        ldx #>M3_B_TLS
        jsr m3_exec
        bcc @c_reply
        cmp #M3_EXEC_ABORTED
        beq @c_gone_fail            ; an ABORTed CLOSE completed
        cmp #M3_EXEC_REJECTED
        bne @c_fail                 ; wedged
        dec m3_tries
        bne @c_again
        beq @c_fail                 ; rejected twice: still owned
@c_reply:
        jsr m3_finish
        lda #0
        sta m3_owned
@c_ok:
        clc
        bcc @c_out
@c_gone_fail:
        lda #0
        sta m3_owned
@c_fail:
        sec
@c_out:
        lda #NET_TCP_CLOSED
        sta net_tcp_state           ; A store: the carry survives
        rts

; =============================================================================
; net_recv_byte — pop one byte from the rx ring (same as src/net/uci/net.s).
; Out: A = byte, C=0; C=1 the ring is empty.
; =============================================================================
        .include "net_recv_byte.inc"    ; src/net/, shared with uci

.segment "RODATA"

net_banner_str:
        .byte "UCI M3 (TLS ON THE ULTIMATE)"
        .byte $0d, 0

.segment "BSS"

net_local_ip:       .res 4
net_resolved_ip:    .res 4
net_last_error:     .res 1
net_tcp_state:      .res 1
net_send_len:       .res 2

.segment "UCI_BSS"

tls_hostname:       .res 64     ; host, NUL-terminated (<= 63, boot.s)
tls_hostname_len:   .res 1
m3_handle:          .res 1      ; any byte but $FF; 0 is legal (ER-9)
m3_owned:           .res 1      ; 1 while the handle is ours to CLOSE
m3_eof_code:        .res 1      ; 1 or 5 once READ ended the stream
m3_poll_result:     .res 1      ; M3_POLL_*
m3_open_reply:      .res M3_OPEN_REPLY_LEN
m3_open_hint:       .res 1      ; M3_HINT_*: why the last Open was refused
m3_info:            .res M3_INFO_LEN
m3_ipaddr:          .res 12
m3_host_buf:        .res M3_HOST_MAX + 1
m3_host_len:        .res 1
m3_port:            .res 2
m3_sweep:           .res 1
m3_tries:           .res 1
m3_req:             .res 2
m3_hdr:             .res 2
m3_bad:             .res 1
m3_src:             .res 2
m3_rem:             .res 2
m3_piece:           .res 2
m3_cnt:             .res 2
m3_wresp:           .res 2
