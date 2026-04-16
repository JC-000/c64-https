; src/net/uci/net.s — UCI (Ultimate Command Interface) networking backend
;
; Phase 1b: every entry point is an RTS stub. The goal is to produce a
; UCI-linked PRG that boots on a real U64E. No networking behavior yet.
;
; The adapter exports two symbol families:
;
;   (a) The formal net_abi.inc names — the long-term public contract:
;       net_init, net_poll, net_dhcp_acquire, net_tcp_connect, net_tcp_send,
;       net_tcp_close, net_tcp_set_recv_cb, net_dns_resolve,
;       net_local_ip, net_resolved_ip, net_last_error, net_tcp_state.
;
;   (b) The legacy caller names currently imported by boot.s / http.s /
;       tls_record_io.s — required to satisfy the ld65 link until those
;       callers are migrated onto net_abi.inc in a later phase:
;       net_dhcp, net_print_ip, net_recv_byte, net_send_len.
;
; uci_regs.inc is included purely to validate the header (no code uses
; the equates yet — Phase 2+ will wire the actual UCI state machine).

.include "uci_regs.inc"

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

; --- UCI-owned state exported for future phases ---
.export uci_host_buf

.segment "CODE"

; =============================================================================
; net_init — initialize UCI networking
; Output: C=0 success (always, for now)
; =============================================================================
net_init:
        clc
        rts

; =============================================================================
; net_poll — pump the UCI state machine (non-blocking)
; =============================================================================
net_poll:
        rts

; =============================================================================
; net_dhcp_acquire — obtain IP via DHCP
; Output: C=0 success
; =============================================================================
net_dhcp_acquire:
        clc
        rts

; Legacy alias; boot.s still imports `net_dhcp` directly.
net_dhcp:
        clc
        rts

; =============================================================================
; net_tcp_connect — establish a TCP connection
; Input: A/X = remote port (lo/hi); destination IP taken from prior
;              net_dns_resolve (uci_host_buf in Phase 4+).
; Output: C=1 failure (no UCI command implementation yet)
; =============================================================================
net_tcp_connect:
        sec
        rts

; =============================================================================
; net_tcp_send — send data over TCP
; Input: A/X = buffer pointer, net_send_len = 16-bit length
; Output: C=1 failure
; =============================================================================
net_tcp_send:
        sec
        rts

; =============================================================================
; net_tcp_close — close TCP connection
; =============================================================================
net_tcp_close:
        rts

; =============================================================================
; net_tcp_set_recv_cb — register TCP receive callback
; Input: A/X = callback address (lo/hi)
; =============================================================================
net_tcp_set_recv_cb:
        rts

; =============================================================================
; net_dns_resolve — resolve hostname to IP
; Input: A/X = pointer to null-terminated hostname
; Output: C=1 failure (Phase 4 will memcpy into uci_host_buf)
; =============================================================================
net_dns_resolve:
        sec
        rts

; =============================================================================
; net_print_ip — display current local IP in dotted decimal
; Phase 1b: silent no-op. Phase 2 will print from net_local_ip once the
; UCI GET_IPADDR command is implemented.
; =============================================================================
net_print_ip:
        rts

; =============================================================================
; net_recv_byte — read one byte from the TCP ring buffer
; Output: A = byte, C=0 success, C=1 empty
;
; Phase 1b: ring is always empty (nothing writes to it yet).
; =============================================================================
net_recv_byte:
        sec
        rts

; =============================================================================
; BSS — UCI adapter state
; =============================================================================
.segment "BSS"

net_local_ip:       .res 4          ; local IPv4 address (big-endian)
net_resolved_ip:    .res 4          ; last resolved IPv4 address
net_last_error:     .res 1          ; 0 = OK, nonzero = error code
net_tcp_state:      .res 1          ; current TCP socket state
net_send_len:       .res 2          ; length argument for net_tcp_send

; =============================================================================
; UCI-owned BSS — reserved here for Phase 4+.
; uci_host_buf is a 256-byte null-terminated hostname buffer staged for
; the next net_tcp_connect. Placed in a UCI-only BSS segment so the cfg
; can map it into the otherwise-idle NET_BSS region under BACKEND=uci.
; =============================================================================
.segment "UCI_BSS"

uci_host_buf:       .res 256
