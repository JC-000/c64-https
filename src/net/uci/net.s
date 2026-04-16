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

; --- primitives from uci_cmd.s ---
.import uci_abort
.import uci_wait_idle
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

; --- KERNAL CHROUT for net_print_ip ---
chrout = $FFD2

.segment "CODE"

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
; net_poll — pump the UCI state machine (non-blocking)
; Phase 2: no async state to pump yet (no open sockets). Later phases will
; drive SOCKET_READ polling here.
; =============================================================================
net_poll:
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
; net_tcp_connect — Phase 3+
; =============================================================================
net_tcp_connect:
        sec
        rts

; =============================================================================
; net_tcp_send — Phase 3+
; =============================================================================
net_tcp_send:
        sec
        rts

; =============================================================================
; net_tcp_close — Phase 3+
; =============================================================================
net_tcp_close:
        rts

; =============================================================================
; net_tcp_set_recv_cb — Phase 3+
; =============================================================================
net_tcp_set_recv_cb:
        rts

; =============================================================================
; net_dns_resolve — Phase 4+
; =============================================================================
net_dns_resolve:
        sec
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
; net_recv_byte — Phase 3+ (ring always empty for now)
; =============================================================================
net_recv_byte:
        sec
        rts

; =============================================================================
; Banner string — consumed by boot.s's startup print
; =============================================================================
.segment "RODATA"

net_banner_str:
        .byte "ULTIMATE 64 ELITE (UCI)"
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
