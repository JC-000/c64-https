; =============================================================================
; net.asm - ip65 network wrapper with zero page time-sharing
;
; All ip65 calls go through this wrapper. Before each call:
;   1. Save crypto ZP ($02-$1B) to zp_save_buf
;   2. Call ip65 function
;   3. Restore crypto ZP from zp_save_buf
;
; The ip65 TCP callback fires DURING ip65_process, while ip65's ZP is active.
; The callback must NOT touch crypto state — it only copies received data
; into tcp_recv_buf (a ring buffer) for later processing.
; =============================================================================

; =============================================================================
; net_init - initialize ip65 + ethernet
; Output: C=0 success, C=1 failure
; =============================================================================
net_init:
        jsr net_save_zp
        ; lda #0                ; eth_init_default
        ; jsr ip65_init         ; TODO: enable when ip65 binary is integrated
        ; bcs @fail
        jsr net_restore_zp
        clc
        rts
; @fail:
;         jsr net_restore_zp
;         sec
;         rts

; =============================================================================
; net_dhcp - obtain IP address via DHCP
; Output: C=0 success, C=1 failure
; =============================================================================
net_dhcp:
        jsr net_save_zp
        ; jsr dhcp_init         ; TODO: enable when ip65 binary is integrated
        ; php                   ; save carry
        jsr net_restore_zp
        ; plp                   ; restore carry
        clc
        rts

; =============================================================================
; net_poll - call ip65_process (non-blocking)
; Must be called frequently from main loop.
; =============================================================================
net_poll:
        jsr net_save_zp
        ; jsr ip65_process      ; TODO: enable when ip65 binary is integrated
        jsr net_restore_zp
        rts

; =============================================================================
; net_dns_resolve - resolve hostname
; Input: hostname set in ip65 dns buffer
; Output: C=0 success (IP in dns_ip), C=1 failure
; =============================================================================
net_dns_resolve:
        jsr net_save_zp
        ; jsr dns_resolve       ; TODO
        jsr net_restore_zp
        rts

; =============================================================================
; net_tcp_connect - establish TCP connection
; Input: remote IP and port set in ip65 vars
; Output: C=0 success, C=1 failure
; =============================================================================
net_tcp_connect:
        jsr net_save_zp
        ; set tcp_callback to our internal handler
        ; lda #<@tcp_recv_cb
        ; sta tcp_callback
        ; lda #>@tcp_recv_cb
        ; sta tcp_callback+1
        ; jsr tcp_connect       ; TODO
        jsr net_restore_zp
        rts

; =============================================================================
; net_tcp_send - send data over TCP
; Input: A/X = pointer to data, Y = length (lo byte), net_send_len_hi = hi
; Output: C=0 success, C=1 failure
; =============================================================================
net_tcp_send:
        sta net_send_ptr
        stx net_send_ptr+1
        jsr net_save_zp
        ; lda net_send_ptr
        ; ldx net_send_ptr+1
        ; ... set tcp_send_data_len ...
        ; jsr tcp_send          ; TODO
        jsr net_restore_zp
        rts

; =============================================================================
; net_tcp_close - close TCP connection
; =============================================================================
net_tcp_close:
        jsr net_save_zp
        ; jsr tcp_close         ; TODO
        jsr net_restore_zp
        rts

; =============================================================================
; net_print_ip - display current IP address (placeholder)
; =============================================================================
net_print_ip:
        ; TODO: read cfg_ip from ip65 and print dotted decimal
        lda #<ip_placeholder
        ldy #>ip_placeholder
        jsr print_string
        rts

ip_placeholder:
        !text "0.0.0.0"
        !byte $0d, 0

; =============================================================================
; net_recv_ready - check if data is available in receive ring buffer
; Output: C=0 if data available, C=1 if empty
; =============================================================================
net_recv_ready:
        lda tcp_recv_head
        cmp tcp_recv_tail
        beq @empty
        clc
        rts
@empty:
        sec
        rts

; =============================================================================
; net_recv_byte - read one byte from receive ring buffer
; Output: A = byte, C=0 success, C=1 buffer empty
; =============================================================================
net_recv_byte:
        lda tcp_recv_head
        cmp tcp_recv_tail
        beq @empty
        tax
        lda tcp_recv_buf,x
        inc tcp_recv_head       ; wraps at 256 if buf is 256 bytes
        clc
        rts
@empty:
        sec
        rts

; =============================================================================
; TCP receive callback — called by ip65 DURING ip65_process
; ip65's ZP is active. DO NOT touch crypto state.
; Copies incoming data to tcp_recv_buf ring buffer.
; =============================================================================
; @tcp_recv_cb:
;         ; ip65 provides:
;         ;   tcp_inbound_data_ptr (AX) = pointer to received data
;         ;   tcp_inbound_data_length = number of bytes
;         ;
;         ; Copy to ring buffer
;         ; TODO: implement when ip65 is integrated
;         rts

; =============================================================================
; ZP save/restore — 26 bytes ($02-$1B)
; =============================================================================
net_save_zp:
        ldx #ip65_zp_size - 1
-       lda ip65_zp_start,x
        sta zp_save_buf,x
        dex
        bpl -
        rts

net_restore_zp:
        ldx #ip65_zp_size - 1
-       lda zp_save_buf,x
        sta ip65_zp_start,x
        dex
        bpl -
        rts

; =============================================================================
; net module data
; =============================================================================
net_send_ptr:   !word 0         ; pointer for tcp_send wrapper
net_send_len:   !word 0         ; length for tcp_send wrapper
