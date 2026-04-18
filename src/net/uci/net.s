; src/net/uci/net.s — UCI (Ultimate Command Interface) networking backend
;
; Phase 2: net_init and net_dhcp_acquire are backed by the shared UCI
; command primitives in uci_cmd.s. The rest of the API is still stubbed
; (Phase 3+).
;
; net_init:           abort any stale command state, probe UCI_ID, zero
;                     adapter state, return C=0 on success / C=1 on failure.
; net_dhcp_acquire:   read the U64E firmware's DHCP-assigned IP via the
;                     GET_IPADDR command. Does NOT run DHCP ourselves —
;                     the firmware already did that before the PRG started.
;
; Exports two symbol families:
;
;   (a) net_abi.inc contract — the long-term public names.
;   (b) legacy caller names currently imported by boot.s / http.s /
;       tls_record_io.s — kept as thin aliases until those callers are
;       migrated onto net_abi.inc in a later phase.
;
; Also publishes `net_banner_str`, the backend-specific banner line
; consumed by boot.s's startup print.

.include "uci_regs.inc"
.include "uci_errors.inc"
.include "constants.inc"

; --- net_abi.inc contract ---
.export net_init
.export net_poll
.export net_dhcp_acquire
.export net_tcp_connect
.export net_tcp_send
.export net_tcp_close
.export net_tcp_set_recv_cb
.export net_dns_resolve
.export net_local_ip
.export net_resolved_ip
.export net_last_error
.export net_tcp_state

; --- legacy caller names (still imported by boot.s / http.s / tls_record_io.s) ---
.export net_dhcp
.export net_print_ip
.export net_recv_byte
.export net_send_len

; --- banner label consumed by boot.s ---
.export net_banner_str

; --- UCI-owned state exported for future phases ---
.export uci_host_buf
.export uci_socket_id

; --- primitives from uci_cmd.s ---
.import uci_abort
.import uci_wait_idle
.import uci_wait_not_busy
.import uci_begin_cmd
.import uci_put_byte
.import uci_push_wait
.import uci_check_err
.import uci_read_resp_bytes
.import uci_drain_resp
.import uci_drain_status
.import uci_ack
.import uci_resp_dst
.import uci_resp_max
.import uci_resp_count

; --- ring BSS owned by src/data.s ---
.import tcp_recv_head
.import tcp_recv_tail

; (chrout is provided by constants.inc)

.segment "UCI_CODE"

; =============================================================================
; net_init — initialize UCI networking
;
; 1. Force the UCI state machine back to idle (clears any leftover state
;    from a warm reset where a previous command was in-flight).
; 2. Read UCI_ID. If not $C9 the U64E firmware does not currently expose
;    the command interface (either not enabled, or we are running on a
;    bare C64) — set net_last_error and return C=1.
; 3. Zero adapter state (net_local_ip, net_resolved_ip, net_tcp_state,
;    net_last_error) and return C=0.
;
; Clobbers: A, X
; =============================================================================
net_init:
        jsr uci_abort

        lda UCI_ID
        uci_fence                   ; settle before comparing ID
        cmp #UCI_ID_VALUE
        beq @present

        lda #UCI_ERR_NOT_PRESENT
        sta net_last_error
        sec
        rts

@present:
        lda #$00
        sta net_local_ip+0
        sta net_local_ip+1
        sta net_local_ip+2
        sta net_local_ip+3
        sta net_resolved_ip+0
        sta net_resolved_ip+1
        sta net_resolved_ip+2
        sta net_resolved_ip+3
        sta net_tcp_state
        sta net_last_error
        clc
        rts

; =============================================================================
; net_poll — pump UCI receive into the TCP ring buffer.
;
; If no socket is open (net_tcp_state != UCI_TCP_CONNECTED) we just RTS.
; Otherwise we issue SOCKET_READ(sock, UCI_READ_CHUNK_MAX) and, for each
; data byte returned after the 2-byte actual_len header, store into
; tcp_recv_buf at tcp_recv_tail and advance the masked tail.
;
; We intentionally do NOT honor net_tcp_set_recv_cb here — the HTTP/TLS
; path drains via net_recv_byte, not via a callback. The set-cb call site
; exists only in net_abi.inc and is never actually invoked in-tree
; (Phase 3 grep: 0 `jsr net_tcp_set_recv_cb`), so the UCI backend leaves
; its set-cb entry point as an RTS stub.
;
; Clobbers: A, X, Y
; =============================================================================
net_poll:
        lda net_tcp_state
        cmp #UCI_TCP_CONNECTED
        beq @do_poll
        rts
@do_poll:
        jsr uci_wait_not_busy

        lda #UCI_TARGET_NETWORK
        jsr uci_begin_cmd

        lda #UCI_CMD_SOCKET_READ
        jsr uci_put_byte

        lda uci_socket_id
        jsr uci_put_byte

        ; maxlen — fixed UCI_READ_CHUNK_MAX (512), LE.
        lda #<UCI_READ_CHUNK_MAX
        jsr uci_put_byte
        lda #>UCI_READ_CHUNK_MAX
        jsr uci_put_byte

        jsr uci_push_wait

        jsr uci_check_err
        bcc @no_err

        lda #UCI_ERR_READ_FAIL
        sta net_last_error
        lda #UCI_TCP_ERROR
        sta net_tcp_state
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack
        rts

@no_err:
        ; First two bytes are actual_len (LE).  Read them into scratch.
        ; We use direct reads (not uci_read_resp_bytes) because we then
        ; need to read additional bytes directly into the ring, and mixing
        ; two `uci_read_resp_bytes` calls would require re-patching the
        ; SMC dst. Loop style matches uci_read_resp_bytes — tight-poll
        ; DATA_AV and read UCI_RESP_DATA; the firmware FIFO auto-advances
        ; on read (Phase 2 finding), so NO per-byte NEXT_DATA.
        uci_fence             ; give firmware time to stage response
        ldy #$00
@hdr_loop:
        lda UCI_STATUS
        uci_fence                   ; settle before testing DATA_AV
        and #UCI_STAT_DATA_AV
        bne @hdr_got                ; branch past trampoline
        jmp @hdr_done_short         ; long branch: fence too wide for BEQ
@hdr_got:
        lda UCI_RESP_DATA
        uci_fence                   ; settle before storing header byte
        sta uci_read_hdr,y
        iny
        cpy #2
        bcs @hdr_got2               ; branch past trampoline (inverted BCC)
        jmp @hdr_loop               ; long branch back: fence too wide for BCC
@hdr_got2:
        jmp @hdr_done

@hdr_done_short:
        ; Firmware returned fewer than 2 bytes. Treat as "no data".
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack
        rts

@hdr_done:
        ; actual_len = uci_read_hdr (LE). If zero, drain/ack and return.
        lda uci_read_hdr+0
        sta uci_poll_rem+0
        lda uci_read_hdr+1
        sta uci_poll_rem+1
        ora uci_poll_rem+0
        bne @have_data
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack
        rts

@have_data:
        ; Copy exactly (uci_poll_rem) bytes from UCI_RESP_DATA into the
        ; ring at tcp_recv_buf + tcp_recv_tail, advancing the masked tail.
        ; The store uses SMC on @rb_store so we can hit the full 4 KB
        ; ring without needing a 16-bit Y register. We repatch the store
        ; address after every byte (simple & correct).
@byte_loop:
        ; exit if remaining == 0
        lda uci_poll_rem+0
        ora uci_poll_rem+1
        bne :+
        jmp @done_data
:
        ; Overflow check: if ((tail+1) & TCP_RECV_MASK) == head, stop.
        lda tcp_recv_tail+0
        clc
        adc #$01
        sta uci_next_lo
        lda tcp_recv_tail+1
        adc #$00
        and #>TCP_RECV_MASK
        sta uci_next_hi
        lda uci_next_lo
        cmp tcp_recv_head+0
        bne @not_full
        lda uci_next_hi
        cmp tcp_recv_head+1
        bne @not_full
        jmp @done_data          ; ring full — drop the rest

@not_full:
        ; Wait for DATA_AV — the firmware streams data in bursts; if the
        ; FIFO drained mid-record we bail (shouldn't happen if firmware
        ; honored actual_len but we defend anyway).
        lda UCI_STATUS
        uci_fence                   ; settle before testing DATA_AV
        and #UCI_STAT_DATA_AV
        bne @have_byte
        jmp @done_data

@have_byte:
        ; dest = tcp_recv_buf + tail  (tail already masked)
        clc
        lda tcp_recv_tail+0
        adc #<tcp_recv_buf
        sta @rb_store+1
        lda tcp_recv_tail+1
        adc #>tcp_recv_buf
        sta @rb_store+2

        lda UCI_RESP_DATA
        uci_fence                   ; settle before storing data byte
@rb_store:
        sta $ffff               ; SMC: patched each byte

        ; tail = next (already masked)
        lda uci_next_lo
        sta tcp_recv_tail+0
        lda uci_next_hi
        sta tcp_recv_tail+1

        ; remaining--
        lda uci_poll_rem+0
        sec
        sbc #$01
        sta uci_poll_rem+0
        lda uci_poll_rem+1
        sbc #$00
        sta uci_poll_rem+1
        jmp @byte_loop

@done_data:
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack
        rts

; =============================================================================
; net_dhcp_acquire — read the firmware-assigned IP via UCI GET_IPADDR
;
; The U64E firmware runs DHCP autonomously before the PRG is launched, so
; our job is to READ the result, not to perform DHCP ourselves. Sequence:
;
;   wait_idle -> begin_cmd(NETWORK) -> put(CMD_GET_IPADDR) -> put(iface=0)
;   -> push_wait -> check_err -> read 12 bytes -> drain resp
;   -> drain status -> ack
;
; The 12-byte response layout is IP(4) + Netmask(4) + Gateway(4). We copy
; the first 4 bytes into net_local_ip. If all four are zero we treat the
; call as having failed (no DHCP lease) and return C=1.
;
; Clobbers: A, X, Y
; Output:   C=0 on success (net_local_ip populated), C=1 on failure
;           (net_last_error contains the specific failure code).
; =============================================================================
net_dhcp_acquire:
        jsr uci_wait_idle

        lda #UCI_TARGET_NETWORK
        jsr uci_begin_cmd

        lda #UCI_CMD_GET_IPADDR
        jsr uci_put_byte

        ; Interface index 0 — matches the build_get_ip helper in
        ; c64-test-harness/src/c64_test_harness/uci_network.py.
        lda #$00
        jsr uci_put_byte

        jsr uci_push_wait

        jsr uci_check_err
        bcc @no_err

        lda #UCI_ERR_CMD_FAILED
        sta net_last_error
        sec
        rts

@no_err:
        ; Read the 12-byte response into uci_ipaddr_resp.
        lda #<uci_ipaddr_resp
        sta uci_resp_dst
        lda #>uci_ipaddr_resp
        sta uci_resp_dst+1
        lda #12
        sta uci_resp_max
        jsr uci_read_resp_bytes

        ; Drain anything we didn't consume (should be zero for 12 bytes,
        ; but this is cheap insurance against firmware revisions that
        ; return a longer record).
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack

        ; Copy the first 4 bytes (IP) into net_local_ip.
        ldx #3
@copy_ip:
        lda uci_ipaddr_resp,x
        sta net_local_ip,x
        dex
        bpl @copy_ip

        ; If all four bytes are zero the firmware has no lease yet.
        lda net_local_ip+0
        ora net_local_ip+1
        ora net_local_ip+2
        ora net_local_ip+3
        bne @have_ip

        lda #UCI_ERR_NO_IP
        sta net_last_error
        sec
        rts

@have_ip:
        clc
        rts

; Legacy alias — boot.s still imports `net_dhcp` directly.
net_dhcp:
        jmp net_dhcp_acquire

; =============================================================================
; net_tcp_connect — open a TCP socket to (uci_host_buf, port).
;
; Entry:  A = port_lo, X = port_hi  (http.s convention; matches ip65 adapter)
;         uci_host_buf contains the null-terminated hostname written by
;         a prior net_dns_resolve.
;
; UCI command: target=NETWORK, cmd=CMD_TCP_CONNECT, params = [port_lo,
; port_hi, host_bytes..., 0]. Response = [socket_id].
;
; On success: stores socket_id in uci_socket_id, sets net_tcp_state =
; UCI_TCP_CONNECTED, returns C=0. On failure: sets net_last_error =
; UCI_ERR_CONNECT_FAIL and returns C=1.
; =============================================================================
net_tcp_connect:
        sta uci_connect_port_lo
        stx uci_connect_port_hi

        jsr uci_wait_idle

        lda #UCI_TARGET_NETWORK
        jsr uci_begin_cmd

        lda #UCI_CMD_TCP_CONNECT
        jsr uci_put_byte

        lda uci_connect_port_lo
        jsr uci_put_byte
        lda uci_connect_port_hi
        jsr uci_put_byte

        ; Push hostname bytes until the first $00, mirroring the reference
        ; routine: LDY loop reading uci_host_buf,Y, STA UCI_CMD_DATA, INY;
        ; stop once the loaded byte was 0 (don't push the $00 — that's the
        ; explicit terminator written right after).
        ldy #$00
@host_loop:
        lda uci_host_buf,y
        bne @host_push          ; branch past trampoline
        jmp @host_done          ; long branch: fence too wide for BEQ
@host_push:
        sta UCI_CMD_DATA
        uci_fence         ; heavy fence: hostname bytes at 48 MHz
        iny
        beq @host_done          ; Y wrapped to 0 — stop (bounded by 256 B)
        jmp @host_loop          ; long branch back: fence too wide for BNE
@host_done:
        lda #$00
        sta UCI_CMD_DATA        ; explicit null terminator
        uci_fence

        jsr uci_push_wait

        jsr uci_check_err
        bcc @tc_no_err

        lda #UCI_ERR_CONNECT_FAIL
        sta net_last_error
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack
        sec
        rts

@tc_no_err:
        ; Read 1-byte socket_id response.
        lda #<uci_socket_id
        sta uci_resp_dst
        lda #>uci_socket_id
        sta uci_resp_dst+1
        lda #$01
        sta uci_resp_max
        jsr uci_read_resp_bytes

        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack

        lda #UCI_TCP_CONNECTED
        sta net_tcp_state
        clc
        rts

; =============================================================================
; net_tcp_send — push up to net_send_len bytes from (AX) through SOCKET_WRITE.
;
; Entry: A = data_lo, X = data_hi; net_send_len = 16-bit length.
;
; Strategy: outer loop chunks of UCI_DATA_QUEUE_MAX (800) because the
; firmware caps a single SOCKET_WRITE at DATA_QUEUE_MAX. Inner loop walks
; the source with a 16-bit index via a self-modified `LDA abs,y` — we
; advance the patched base address by 256 every time Y rolls over.
; Response: 2 bytes = written_lo/hi (LE). If written != requested we set
; UCI_ERR_SHORT_WRITE but still return C=0 so the caller can continue
; (mirrors ip65 behaviour that treats short writes as best-effort).
; =============================================================================
net_tcp_send:
        sta uci_send_ptr_lo
        stx uci_send_ptr_hi

        ; Copy remaining total into a 16-bit counter we decrement per chunk.
        lda net_send_len+0
        sta uci_send_rem+0
        lda net_send_len+1
        sta uci_send_rem+1

        ; If length is zero, nothing to do.
        ora uci_send_rem+0
        bne @chunk_loop
        clc
        rts

@chunk_loop:
        ; this_chunk = min(uci_send_rem, UCI_DATA_QUEUE_MAX)
        ; if uci_send_rem+1 > >UCI_DATA_QUEUE_MAX  OR
        ;    uci_send_rem+1 == >UCI_DATA_QUEUE_MAX AND rem+0 > <UCI_DATA_QUEUE_MAX
        ; then this_chunk = UCI_DATA_QUEUE_MAX
        ; else this_chunk = uci_send_rem
        lda uci_send_rem+1
        cmp #>UCI_DATA_QUEUE_MAX
        bcc @use_rem                   ; rem_hi < 3 → rem < 800
        bne @use_cap                   ; rem_hi > 3 → cap
        lda uci_send_rem+0
        cmp #<UCI_DATA_QUEUE_MAX
        bcc @use_rem                   ; rem_lo < $20 → rem < 800
@use_cap:
        lda #<UCI_DATA_QUEUE_MAX
        sta uci_chunk_len+0
        lda #>UCI_DATA_QUEUE_MAX
        sta uci_chunk_len+1
        jmp @begin_chunk
@use_rem:
        lda uci_send_rem+0
        sta uci_chunk_len+0
        lda uci_send_rem+1
        sta uci_chunk_len+1

@begin_chunk:
        jsr uci_wait_idle

        lda #UCI_TARGET_NETWORK
        jsr uci_begin_cmd

        lda #UCI_CMD_SOCKET_WRITE
        jsr uci_put_byte

        lda uci_socket_id
        jsr uci_put_byte

        ; Patch the source base into the LDA abs,Y instruction.
        lda uci_send_ptr_lo
        sta @sb_load+1
        lda uci_send_ptr_hi
        sta @sb_load+2

        ; Inner loop: Y = 0..255 repeatedly; when Y rolls we bump the hi
        ; byte of the patched base. Count down uci_chunk_len each byte.
        ldy #$00
@sb_loop:
        ; done when chunk_len == 0
        lda uci_chunk_len+0
        ora uci_chunk_len+1
        bne :+
        jmp @sb_push
:
@sb_load:
        lda $ffff,y             ; SMC: source base patched above
        sta UCI_CMD_DATA
        uci_fence         ; heavy fence: FIFO overruns at 48 MHz with standard fence
        iny
        bne @sb_nohi
        inc @sb_load+2          ; advance base high byte
@sb_nohi:
        ; chunk_len--
        lda uci_chunk_len+0
        sec
        sbc #$01
        sta uci_chunk_len+0
        lda uci_chunk_len+1
        sbc #$00
        sta uci_chunk_len+1
        jmp @sb_loop

@sb_push:
        jsr uci_push_wait

        jsr uci_check_err
        bcc @sb_no_err

        lda #UCI_ERR_SEND_FAIL
        sta net_last_error
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack
        sec
        rts

@sb_no_err:
        ; Read 2-byte written count into uci_write_resp (LE).
        lda #<uci_write_resp
        sta uci_resp_dst
        lda #>uci_write_resp
        sta uci_resp_dst+1
        lda #$02
        sta uci_resp_max
        jsr uci_read_resp_bytes

        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack

        ; Sanity: if written != requested-for-this-chunk, flag short-write.
        ; We still treat the send as done (MVP semantics).
        ; Recompute the requested chunk — we've zeroed uci_chunk_len inside
        ; the inner loop, so recompute from the delta between pre-chunk
        ; rem and post-chunk rem by using the written count directly.
        ; Simpler: if written_hi/lo both match what we just dec'd off, OK.
        ; For MVP we only flag if written == 0 but we asked for > 0.
        lda uci_write_resp+0
        ora uci_write_resp+1
        bne @sb_had_write
        lda #UCI_ERR_SHORT_WRITE
        sta net_last_error
@sb_had_write:

        ; Advance source pointer by the ACTUAL written count (not the
        ; requested chunk size) so short writes don't drop bytes.
        lda uci_send_ptr_lo
        clc
        adc uci_write_resp+0
        sta uci_send_ptr_lo
        lda uci_send_ptr_hi
        adc uci_write_resp+1
        sta uci_send_ptr_hi

        ; Subtract the actual written count from uci_send_rem.
        lda uci_send_rem+0
        sec
        sbc uci_write_resp+0
        sta uci_send_rem+0
        lda uci_send_rem+1
        sbc uci_write_resp+1
        sta uci_send_rem+1

        ; If we got a zero written back on a nonempty request, bail to
        ; avoid an infinite loop (caller already has UCI_ERR_SHORT_WRITE).
        lda uci_write_resp+0
        ora uci_write_resp+1
        beq @sb_done

        lda uci_send_rem+0
        ora uci_send_rem+1
        beq @sb_done
        jmp @chunk_loop

@sb_done:
        clc
        rts

; =============================================================================
; net_tcp_close — CMD_SOCKET_CLOSE on the open socket. Best-effort; the
; UCI error bit is drained but not surfaced, and net_tcp_state is always
; forced back to UCI_TCP_CLOSED.
; =============================================================================
net_tcp_close:
        jsr uci_wait_idle

        lda #UCI_TARGET_NETWORK
        jsr uci_begin_cmd

        lda #UCI_CMD_SOCKET_CLOSE
        jsr uci_put_byte

        lda uci_socket_id
        jsr uci_put_byte

        jsr uci_push_wait
        jsr uci_check_err       ; clear latched error if any
        jsr uci_drain_resp
        jsr uci_drain_status
        jsr uci_ack

        lda #UCI_TCP_CLOSED
        sta net_tcp_state
        rts

; =============================================================================
; net_tcp_set_recv_cb — RTS stub.
; Phase 3 grep (src/): no `jsr net_tcp_set_recv_cb` call sites exist;
; only the `.import` in net_abi.inc. Keep the entry point so the ABI
; link resolves. If a future caller appears, wire it into net_poll.
; =============================================================================
net_tcp_set_recv_cb:
        rts

; =============================================================================
; net_dns_resolve — stage a hostname for the next net_tcp_connect.
;
; Entry: A/X = pointer to a null-terminated hostname (caller-owned).
; Copies up to 255 bytes into uci_host_buf and guarantees a terminating
; null at offset 255 for safety. UCI firmware does the real DNS inside
; TCP_CONNECT, so this routine performs no I/O and cannot fail.
;
; Sets net_resolved_ip to $FF,$FF,$FF,$FF as a marker ("UCI resolved it
; internally") so a future debug dump can distinguish from "not yet
; resolved" (all-zero). Not load-bearing; callers don't read this field.
;
; Clobbers: A, X, Y
; =============================================================================
net_dns_resolve:
        sta @src+1
        stx @src+2

        ldy #$00
@cp:
@src:
        lda $ffff,y             ; SMC: patched above
        sta uci_host_buf,y
        beq @cp_done            ; copy the null then stop
        iny
        cpy #$ff
        bcc @cp
        ; Hit 255 bytes without seeing a null — force one at offset 255.
        lda #$00
        sta uci_host_buf+255
@cp_done:
        ; Marker IP: $FF.$FF.$FF.$FF
        lda #$ff
        sta net_resolved_ip+0
        sta net_resolved_ip+1
        sta net_resolved_ip+2
        sta net_resolved_ip+3

        lda #$00
        sta net_last_error
        clc
        rts

; =============================================================================
; net_print_ip — print net_local_ip as dotted decimal (PETSCII + CR)
;
; Shared with the ip65 backend in shape: three `.`-separated decimal octets
; plus a trailing carriage return. Implementation is local so the UCI
; backend has no ip65 dependencies.
; =============================================================================
net_print_ip:
        lda net_local_ip+0
        jsr @print_byte
        lda #'.'
        jsr chrout
        lda net_local_ip+1
        jsr @print_byte
        lda #'.'
        jsr chrout
        lda net_local_ip+2
        jsr @print_byte
        lda #'.'
        jsr chrout
        lda net_local_ip+3
        jsr @print_byte
        lda #$0d
        jsr chrout
        rts

@print_byte:
        sta @pb_val
        ; hundreds
        ldx #0
        sec
@pb_100:
        sbc #100
        bcc @pb_100d
        inx
        jmp @pb_100
@pb_100d:
        adc #100
        cpx #0
        beq @pb_tens                    ; skip leading zero
        pha
        txa
        ora #$30
        jsr chrout
        pla
@pb_tens:
        ldx #0
        sec
@pb_10:
        sbc #10
        bcc @pb_10d
        inx
        jmp @pb_10
@pb_10d:
        adc #10
        cpx #0
        bne @pb_t_out
        ldy @pb_val
        cpy #10
        bcc @pb_ones                    ; value < 10, skip tens digit
@pb_t_out:
        pha
        txa
        ora #$30
        jsr chrout
        pla
@pb_ones:
        ora #$30
        jsr chrout
        rts
@pb_val: .byte 0

; =============================================================================
; net_recv_byte — pop one byte from the TCP receive ring.
;
; Mirrors the ip65 adapter (src/net/ip65/net.s:~274). Ring addressing:
; effective = tcp_recv_buf + (head & TCP_RECV_MASK). Uses SMC on @nrb_ld
; to avoid ZP scratch (crypto ZP and ip65 ZP are time-shared; keeping
; this routine ZP-free matches the ip65 backend's contract).
;
; Output: A = byte, C=0 on success, C=1 if buffer empty.
; =============================================================================
net_recv_byte:
        lda tcp_recv_head+0
        cmp tcp_recv_tail+0
        bne @nrb_not_empty
        lda tcp_recv_head+1
        cmp tcp_recv_tail+1
        beq @nrb_empty
@nrb_not_empty:
        clc
        lda tcp_recv_head+0
        adc #<tcp_recv_buf
        sta @nrb_ld+1
        lda tcp_recv_head+1
        adc #>tcp_recv_buf
        sta @nrb_ld+2
@nrb_ld:
        lda $ffff               ; SMC: patched above
        pha
        inc tcp_recv_head+0
        bne @nrb_mask
        inc tcp_recv_head+1
@nrb_mask:
        lda tcp_recv_head+1
        and #>TCP_RECV_MASK
        sta tcp_recv_head+1
        pla
        clc
        rts
@nrb_empty:
        sec
        rts

; =============================================================================
; Banner string — consumed by boot.s's startup print
; =============================================================================
.segment "RODATA"

net_banner_str:
        .byte "UCI NETWORKING"
        .byte $0d, 0

; =============================================================================
; BSS — UCI adapter state
; =============================================================================
.segment "BSS"

net_local_ip:       .res 4          ; local IPv4 address (big-endian)
net_resolved_ip:    .res 4          ; last resolved IPv4 address
net_last_error:     .res 1          ; 0 = OK, nonzero = UCI_ERR_*
net_tcp_state:      .res 1          ; current TCP socket state
net_send_len:       .res 2          ; length argument for net_tcp_send

; =============================================================================
; UCI-owned BSS — reserved here for Phase 4+.
; uci_host_buf is a 256-byte null-terminated hostname buffer staged for the
; next net_tcp_connect. Placed in a UCI-only BSS segment so the cfg can
; map it into the otherwise-idle NET_BSS region under BACKEND=uci.
;
; uci_ipaddr_resp is the 12-byte scratch buffer for the GET_IPADDR response
; (IP(4) + Netmask(4) + Gateway(4)). Phase 2 only consumes the first 4 bytes
; but reserves the full record so future phases can surface netmask / gateway
; without re-issuing the command.
; =============================================================================
.segment "UCI_BSS"

uci_host_buf:       .res 256
uci_ipaddr_resp:    .res 12

; --- Phase 3 TCP state ---
uci_socket_id:        .res 1          ; socket_id returned by TCP_CONNECT
uci_connect_port_lo:  .res 1
uci_connect_port_hi:  .res 1
uci_send_ptr_lo:      .res 1          ; source ptr for SOCKET_WRITE
uci_send_ptr_hi:      .res 1
uci_send_rem:         .res 2          ; 16-bit bytes remaining to send
uci_chunk_len:        .res 2          ; 16-bit bytes remaining in current chunk
uci_write_resp:       .res 2          ; written_lo/hi from SOCKET_WRITE
uci_read_hdr:         .res 2          ; actual_len_lo/hi from SOCKET_READ
uci_poll_rem:         .res 2          ; net_poll per-cycle remaining
uci_next_lo:          .res 1          ; scratch: (tail+1) & mask, low
uci_next_hi:          .res 1          ; scratch: (tail+1) & mask, high
