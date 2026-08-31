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
; Exports exactly the surface src/net_abi.inc imports (c64-lib-contract
; SPEC §13 core/TCP/DNS families, issue #70) plus the two c64-https
; extensions declared there: net_recv_byte (the drain entry) and
; net_banner_str (the backend-specific banner line boot.s prints).
; Error codes live in uci_errors.inc, in the §13.2 UCI range $80-$BF,
; which is ONE namespace shared with c64-wireguard — allocate in SPEC
; §13.2's table first.

.include "uci_regs.inc"
.include "uci_errors.inc"
.include "constants.inc"

.include "net_states.inc"       ; NET_TCP_* (SPEC §13.1)

; --- Public ABI: exactly the surface src/net_abi.inc imports (SPEC §13) ---
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

; --- c64-https extensions (not SPEC §13), imported via src/net_abi.inc ---
.export net_recv_byte           ; the blessed drain entry (#72)
.export net_send_len            ; §13.1 TCP-family data, listed here for the
                                ; UCI file layout only
.export net_banner_str          ; boot banner identity line

; --- UCI-owned state exported for future phases ---
.export uci_host_buf
.export uci_socket_id

; --- primitives from uci_cmd.s ---
.import uci_abort
.import uci_tod_start
.import uci_status_len
.import uci_status_force
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
.import tcp_recv_overflow      ; §13.3: set when the ring fills

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
        ; Start CIA1's TOD before anything that waits on it. The CIA's
        ; TOD is halted out of reset and every bounded wait in uci_cmd.s
        ; measures wall-clock by watching it tick, so without this the
        ; 5 s bounds are infinite on real hardware (#145). uci_abort
        ; below spins on an iteration count, not the TOD, so the order
        ; here is about net_dhcp_acquire and everything after it.
        jsr uci_tod_start

        ; Arm the status capture: uci_status_len is sticky-first, so a line
        ; captured by a previous run on this machine would otherwise be
        ; read as this run's diagnostic (#147).
        lda #$00
        sta uci_status_len
        sta uci_status_force

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
; If no socket is open (net_tcp_state != NET_TCP_CONNECTED) we just RTS.
; Otherwise we issue SOCKET_READ(sock, UCI_READ_CHUNK_MAX) and, for each
; data byte returned after the 2-byte actual_len header, store into
; tcp_recv_buf at tcp_recv_tail and advance the masked tail.
;
; There is no receive callback: the HTTP/TLS path drains the ring via
; net_recv_byte (SPEC §13.3 drain model). The old net_tcp_set_recv_cb
; RTS stub was deleted per §13.1 (issue #70).
;
; Clobbers: A, X, Y
; =============================================================================
net_poll:
        lda net_tcp_state
        cmp #NET_TCP_CONNECTED
        beq @do_poll
        rts
@do_poll:
        ; --- Clamp the SOCKET_READ request to ring free space -----------
        ; THE WIKIPEDIA-STALL BUG (found 2026-08-22 by ring forensics):
        ; requesting a fixed 512 while the ring has less free space makes
        ; the fill loop below hit "ring full" mid-response, and the
        ; response drain then DISCARDS the remainder — bytes the firmware
        ; considers delivered. The TLS stream acquires a permanent hole
        ; exactly one ring-capacity past the wrap origin and the client
        ; parks forever (en.wikipedia.org's 4.7 KB flight; the local
        ; 4.68 KB control missed the razor-edge by phasing). Request
        ; min(free-1, UCI_READ_CHUNK_MAX) instead, and skip the read
        ; entirely when nothing fits — unread bytes stay in the firmware
        ; for a later poll, which is exactly what TCP is for.
        ; free-1 = (head - tail - 1) & TCP_RECV_MASK  (head==tail: empty)
        lda tcp_recv_head+0
        sec
        sbc tcp_recv_tail+0
        sta uci_req_len+0
        lda tcp_recv_head+1
        sbc tcp_recv_tail+1
        and #>TCP_RECV_MASK
        sta uci_req_len+1
        lda uci_req_len+0
        sec
        sbc #$01
        sta uci_req_len+0
        lda uci_req_len+1
        sbc #$00
        and #>TCP_RECV_MASK
        sta uci_req_len+1
        ora uci_req_len+0
        bne :+
        rts                     ; ring effectively full — poll again later
:
        ; clamp to UCI_READ_CHUNK_MAX — full 16-bit compare. The previous
        ; shape (cmp #>MAX / bcc / bne / lda lo / beq) accepted the
        ; equal-high-byte case only when the low byte was zero: correct
        ; for $0200, silently wrong for any other cap (c64-wireguard hit
        ; exactly that at $037D and read the result as firmware
        ; misbehaviour). Written cap-shape-independently so raising the
        ; constant cannot reintroduce it.
        lda uci_req_len+0
        cmp #<UCI_READ_CHUNK_MAX
        lda uci_req_len+1
        sbc #>UCI_READ_CHUNK_MAX    ; C=1 iff req >= MAX
        bcc @len_clamped            ; req < MAX -> keep
        lda #<UCI_READ_CHUNK_MAX
        sta uci_req_len+0
        lda #>UCI_READ_CHUNK_MAX
        sta uci_req_len+1
@len_clamped:
        jsr uci_wait_not_busy
        bcc :+
        ; FPGA wedged before we could push SOCKET_READ — net_last_error is
        ; already UCI_ERR_WAIT_TIMEOUT. Force tcp_state to ERROR so the
        ; HTTP/TLS layer stops polling on this socket.
        lda #NET_TCP_ERROR
        sta net_tcp_state
        rts
:

        lda #UCI_TARGET_NETWORK
        jsr uci_begin_cmd

        lda #UCI_CMD_SOCKET_READ
        jsr uci_put_byte

        lda uci_socket_id
        jsr uci_put_byte

        ; maxlen — min(ring free - 1, UCI_READ_CHUNK_MAX), LE (computed
        ; at @do_poll; see the wikipedia-stall note there).
        lda uci_req_len+0
        jsr uci_put_byte
        lda uci_req_len+1
        jsr uci_put_byte

        jsr uci_push_wait
        bcc :+
        ; FPGA wedged waiting for SOCKET_READ response — net_last_error is
        ; already UCI_ERR_WAIT_TIMEOUT. Force tcp_state to ERROR so the
        ; HTTP/TLS layer stops polling on this socket.
        lda #NET_TCP_ERROR
        sta net_tcp_state
        rts
:

        jsr uci_check_err
        bcc @no_err

        lda #UCI_ERR_READ_FAIL
        sta net_last_error
        lda #NET_TCP_ERROR
        sta net_tcp_state
        jsr uci_drain_resp
        bcs @pe_drain_to            ; drain wedged — tcp_state already ERROR
        jsr uci_drain_status
        bcs @pe_drain_to
        jsr uci_ack
@pe_drain_to:
        rts

@no_err:
        ; First two bytes are actual_len (LE).  Read them into scratch.
        ; We use direct reads (not uci_read_resp_bytes) because we then
        ; need to read additional bytes directly into the ring, and mixing
        ; two `uci_read_resp_bytes` calls would require re-patching the
        ; SMC dst. Loop style matches uci_read_resp_bytes — tight-poll
        ; DATA_AV and read UCI_RESP_DATA; the firmware FIFO auto-advances
        ; on read (Phase 2 finding), so NO per-byte DATA_ACC.
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
        bcs @hds_drain_to           ; drain wedged — surface as ERROR
        jsr uci_drain_status
        bcs @hds_drain_to
        jsr uci_ack
        rts
@hds_drain_to:
        lda #NET_TCP_ERROR
        sta net_tcp_state
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
        bcs @hd0_drain_to           ; drain wedged — surface as ERROR
        jsr uci_drain_status
        bcs @hd0_drain_to
        jsr uci_ack
        rts
@hd0_drain_to:
        lda #NET_TCP_ERROR
        sta net_tcp_state
        rts

@have_data:
        ; --- Bound the copy by the request (#140, SPEC §13.3) --------------
        ; The response header is not a delivered-byte count. On fw 3.14d
        ; $FFFF is the NO-DATA sentinel on both transports (c64-wireguard:
        ; every idle UDP poll; here: the idle polls after ClientHello while
        ; ServerHello is still in flight answer $FFFF to a 512 B request).
        ; The copy below survived it only because it re-checks ring-full
        ; and DATA_AV per byte and so copied zero bytes; a refactor of the
        ; loop would have turned the header into a runaway copy. So the
        ; count is capped at uci_req_len — what this poll actually asked
        ; for, which the ring clamp above may have made smaller than
        ; UCI_READ_CHUNK_MAX. Bytes beyond the request were never delivered
        ; (they stay queued for the next poll), so the cap loses nothing.
        ; A drop-and-error here (the first cut, emitting UCI_ERR_LONG_READ)
        ; aborted every real handshake on its first idle poll — the same
        ; misfiling c64-wireguard carried for four days as a "firmware
        ; quirk". $FFFF MUST be excluded before any over-claim test.
        lda uci_req_len+0
        cmp uci_poll_rem+0
        lda uci_req_len+1
        sbc uci_poll_rem+1          ; C=1 iff req >= header (16-bit)
        bcs @len_bounded
        ; header > request. $FFFF is the no-data sentinel (routine, copied
        ; as zero bytes by the DATA_AV check); anything else above the
        ; request is a header the firmware has no documented mode for.
        ; Leave a breadcrumb for that case ($8B, best-effort: C=0, stream
        ; continues — the cap below makes it safe either way) so a
        ; post-mortem can tell the two apart. Allocated in c64-lib-contract
        ; SPEC §13.2 before use; the datagram-family counterpart is $8A.
        lda uci_poll_rem+0
        and uci_poll_rem+1
        cmp #$FF
        beq @len_cap                ; $FFFF sentinel — routine, no breadcrumb
        lda #UCI_ERR_BAD_READ_HDR
        sta net_last_error
@len_cap:
        lda uci_req_len+0
        sta uci_poll_rem+0
        lda uci_req_len+1
        sta uci_poll_rem+1
@len_bounded:
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
        ; ring full — record it (SPEC §13.3: the backend sets the flag,
        ; then drops) and stop copying this delivery. The clamp at
        ; @do_poll makes this unreachable in practice: the request never
        ; exceeds free-1. If it latches, the request/free-space arithmetic
        ; has regressed — that is the wikipedia-stall bug's signature.
        lda #1
        sta tcp_recv_overflow
        jmp @done_data

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
        bcs @dd_drain_to            ; drain wedged — surface as ERROR
        jsr uci_drain_status
        bcs @dd_drain_to
        jsr uci_ack
        rts
@dd_drain_to:
        lda #NET_TCP_ERROR
        sta net_tcp_state
        rts

; =============================================================================
; net_dhcp_acquire — read the firmware-assigned IP via UCI GET_IPADDR
;
; The Ultimate firmware runs DHCP autonomously before the PRG is launched,
; so our job is to READ the result, not to perform DHCP ourselves. Sequence
; (per interface):
;
;   wait_idle -> begin_cmd(NETWORK) -> put(CMD_GET_IPADDR) -> put(iface)
;   -> push_wait -> check_err -> read 12 bytes -> drain resp
;   -> drain status -> ack
;
; Interface fallback: the U64E has a single interface (index 0), but the
; C64 Ultimate has Ethernet AND WiFi — a box on WiFi returns 0.0.0.0 for
; index 0. We probe indices 0..NET_DHCP_MAX_IFACE-1 and take the first
; one with a non-zero lease. A CMD_FAILED on an out-of-range index is
; cleaned up (drain + ack) and treated like "no lease on this interface".
;
; The 12-byte response layout is IP(4) + Netmask(4) + Gateway(4). We copy
; the first 4 bytes into net_local_ip. If all probed interfaces yield a
; zero IP we return C=1 with net_last_error = UCI_ERR_NO_IP (or
; UCI_ERR_CMD_FAILED if the last probe failed at the command layer).
;
; Clobbers: A, X, Y
; Output:   C=0 on success (net_local_ip populated), C=1 on failure
;           (net_last_error contains the specific failure code).
; =============================================================================
NET_DHCP_MAX_IFACE = 4          ; probe interface indices 0..3

net_dhcp_acquire:
        lda #$00
        sta @iface_idx          ; SMC-style local, no-ZP file convention

@next_iface:
        jsr uci_wait_idle
        bcs @dhcp_wait_to             ; FPGA wedged — bail with C=1

        lda #UCI_TARGET_NETWORK
        jsr uci_begin_cmd

        lda #UCI_CMD_GET_IPADDR
        jsr uci_put_byte

        ; Interface index — 0 first (only iface on U64E; Ethernet on the
        ; C64 Ultimate), then 1.. (C64U WiFi) until one has a lease.
        lda @iface_idx
        jsr uci_put_byte

        jsr uci_push_wait
        bcs @dhcp_wait_to       ; FPGA wedged after PUSH_CMD — bail with C=1
                                ; (net_last_error already UCI_ERR_WAIT_TIMEOUT)

        jsr uci_check_err
        bcc @no_err

        ; Command failed for this interface (e.g. index out of range on
        ; single-interface firmware). Clean up response/status state so
        ; the next probe starts from idle, then advance.
        lda #UCI_ERR_CMD_FAILED
        sta net_last_error
        jsr uci_drain_resp
        bcs @dhcp_wait_to
        jsr uci_drain_status
        bcs @dhcp_wait_to
        jsr uci_ack
        jmp @advance

@dhcp_wait_to:
        sec
        rts

@iface_idx: .byte 0

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
        bcs @dhcp_wait_to           ; drain wedged — surface as DHCP fail
        jsr uci_drain_status
        bcs @dhcp_wait_to
        jsr uci_ack

        ; Copy the first 4 bytes (IP) into net_local_ip.
        ldx #3
@copy_ip:
        lda uci_ipaddr_resp,x
        sta net_local_ip,x
        dex
        bpl @copy_ip

        ; If all four bytes are zero this interface has no lease —
        ; fall through to probe the next one.
        lda net_local_ip+0
        ora net_local_ip+1
        ora net_local_ip+2
        ora net_local_ip+3
        bne @have_ip

        lda #UCI_ERR_NO_IP
        sta net_last_error

@advance:
        inc @iface_idx
        lda @iface_idx
        cmp #NET_DHCP_MAX_IFACE
        bcc @next_iface
        sec                     ; every interface probed, none had a lease
        rts

@have_ip:
        ; Clear any residue from earlier no-lease probes (e.g. iface 0's
        ; UCI_ERR_NO_IP on a WiFi-connected C64U) so diagnostics don't
        ; read a stale error next to a successful acquire.
        lda #$00
        sta net_last_error
        clc
        rts

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
; NET_TCP_CONNECTED, returns C=0. On failure: sets net_last_error =
; UCI_ERR_CONNECT_FAIL and returns C=1.
; =============================================================================
net_tcp_connect:
        sta uci_connect_port_lo
        stx uci_connect_port_hi

        jsr uci_wait_idle
        bcc :+
        ; FPGA wedged before we even queued anything — surface the timeout
        ; (net_last_error already set) with the connect-fail tcp_state.
        lda #NET_TCP_CONNECT_FAIL
        sta net_tcp_state
        sec
        rts
:

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
        bcc :+
        ; FPGA wedged waiting for TCP_CONNECT response — net_last_error is
        ; already UCI_ERR_WAIT_TIMEOUT. Force tcp_state to CONNECT_FAIL so
        ; callers don't try to use a phantom socket.
        lda #NET_TCP_CONNECT_FAIL
        sta net_tcp_state
        sec
        rts
:

        jsr uci_check_err
        bcc @tc_no_err

        lda #UCI_ERR_CONNECT_FAIL
        sta net_last_error
        jsr uci_drain_resp
        bcs @tc_err_drain_to        ; drain wedged — still surface CONNECT_FAIL
        jsr uci_drain_status
        bcs @tc_err_drain_to
        jsr uci_ack
@tc_err_drain_to:
        sec
        rts

@tc_no_err:
        ; Read 1-byte socket_id response.
        ; Pre-zero uci_socket_id so a short-read leaves a known sentinel
        ; (uci_read_resp_bytes only writes the bytes it actually receives).
        lda #$00
        sta uci_socket_id
        lda #<uci_socket_id
        sta uci_resp_dst
        lda #>uci_socket_id
        sta uci_resp_dst+1
        lda #$01
        sta uci_resp_max
        jsr uci_read_resp_bytes

        jsr uci_drain_resp
        bcs @tc_ok_drain_to         ; drain wedged — surface as CONNECT_FAIL
                                    ; (net_last_error already
                                    ;  UCI_ERR_WAIT_TIMEOUT from the drain)
        jsr uci_drain_status
        bcs @tc_ok_drain_to
        jsr uci_ack
        jmp @tc_validate
@tc_ok_drain_to:
        lda #NET_TCP_CONNECT_FAIL
        sta net_tcp_state
        sec
        rts
@tc_validate:

        ; Validate the response: firmware must have returned at least 1
        ; byte (uci_resp_count) AND a non-zero socket_id. Issue #36 — at
        ; least one observed U64E firmware path returns no payload while
        ; clearing the error bit, leaving uci_socket_id = 0 and us writing
        ; into a phantom socket. Convert that into a clean failure.
        lda uci_resp_count
        beq @tc_no_socket
        lda uci_socket_id
        beq @tc_no_socket

        lda #NET_TCP_CONNECTED
        sta net_tcp_state
        clc
        rts

@tc_no_socket:
        lda #UCI_ERR_NO_SOCKET
        sta net_last_error
        lda #NET_TCP_CONNECT_FAIL
        sta net_tcp_state
        sec
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
        bcc :+
        ; FPGA wedged mid-send — surface as send-fail (net_last_error already
        ; set to UCI_ERR_WAIT_TIMEOUT inside uci_wait_idle).
        sec
        rts
:

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
        bcc :+
        ; FPGA wedged waiting for SOCKET_WRITE response — net_last_error is
        ; already UCI_ERR_WAIT_TIMEOUT. Bail with C=1.
        sec
        rts
:

        jsr uci_check_err
        bcc @sb_no_err

        lda #UCI_ERR_SEND_FAIL
        sta net_last_error
        jsr uci_drain_resp
        bcs @sb_err_drain_to        ; drain wedged — preserve SEND_FAIL exit
        jsr uci_drain_status
        bcs @sb_err_drain_to
        jsr uci_ack
@sb_err_drain_to:
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
        bcs @sb_ok_drain_to         ; drain wedged post-SOCKET_WRITE — bail
        jsr uci_drain_status
        bcs @sb_ok_drain_to
        jsr uci_ack
        jmp @sb_continue
@sb_ok_drain_to:
        ; net_last_error already UCI_ERR_WAIT_TIMEOUT from the drain.
        sec
        rts
@sb_continue:

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
; forced back to NET_TCP_CLOSED.
; =============================================================================
net_tcp_close:
        jsr uci_wait_idle
        bcc :+
        ; FPGA wedged on close — force CLOSED state and bail. Best-effort
        ; semantics already match the existing close path (no return code).
        lda #NET_TCP_CLOSED
        sta net_tcp_state
        rts
:

        lda #UCI_TARGET_NETWORK
        jsr uci_begin_cmd

        lda #UCI_CMD_SOCKET_CLOSE
        jsr uci_put_byte

        lda uci_socket_id
        jsr uci_put_byte

        jsr uci_push_wait
        bcc :+
        ; FPGA wedged on close — force CLOSED state and bail. Best-effort
        ; semantics: skip drains (FIFO state is undefined when wedged).
        lda #NET_TCP_CLOSED
        sta net_tcp_state
        rts
:
        jsr uci_check_err       ; clear latched error if any
        jsr uci_drain_resp
        bcs @cl_drain_to            ; drain wedged — still force CLOSED
        jsr uci_drain_status
        bcs @cl_drain_to
        jsr uci_ack

@cl_drain_to:
        lda #NET_TCP_CLOSED
        sta net_tcp_state
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
uci_req_len:          .res 2          ; net_poll: clamped SOCKET_READ maxlen
uci_next_lo:          .res 1          ; scratch: (tail+1) & mask, low
uci_next_hi:          .res 1          ; scratch: (tail+1) & mask, high
