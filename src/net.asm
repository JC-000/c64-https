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
; into tcp_recv_buf (a ring buffer) for later processing by the TLS layer.
; =============================================================================

; =============================================================================
; net_init - initialize ip65 + ethernet (RR-Net CS8900a)
; Output: C=0 success, C=1 failure
; =============================================================================
net_init:
        jsr net_save_zp
        lda #0                  ; eth_init_default
        jsr ip65_init
        php                     ; save carry result
        jsr net_restore_zp
        plp                     ; restore carry
        rts

; =============================================================================
; net_dhcp - obtain IP address via DHCP
; Output: C=0 success, C=1 failure
; =============================================================================
net_dhcp:
        jsr net_save_zp
        jsr ip65_dhcp_init
        php
        jsr net_restore_zp
        plp
        rts

; =============================================================================
; net_poll - call ip65_process (non-blocking)
; Must be called frequently from main loop.
; =============================================================================
net_poll:
        jsr net_save_zp
        jsr ip65_process
        jsr net_restore_zp
        rts

; =============================================================================
; net_dns_resolve - resolve hostname to IP address
; Input: A/X = pointer to null-terminated hostname string
; Output: C=0 success (IP in ip65_dns_ip_addr), C=1 failure
; =============================================================================
net_dns_resolve:
        jsr net_save_zp
        jsr ip65_dns_set_host   ; AX = hostname pointer
        jsr ip65_dns_resolve
        php
        jsr net_restore_zp
        plp
        rts

; =============================================================================
; net_tcp_connect - establish TCP connection
; Input: A/X = remote port (lo/hi), dest IP already set via net_set_tcp_dest
; Output: C=0 success, C=1 failure
; =============================================================================
net_tcp_connect:
        pha
        txa
        pha
        jsr net_save_zp
        ; set callback to our ring buffer handler
        lda #<net_tcp_recv_cb
        ldx #>net_tcp_recv_cb
        jsr ip65_set_tcp_cb
        ; connect — AX = port
        pla
        tax
        pla
        jsr ip65_tcp_connect
        php
        jsr net_restore_zp
        plp
        rts

; =============================================================================
; net_set_tcp_dest - set TCP destination IP address
; Input: A/X = pointer to 4-byte IP address
; =============================================================================
net_set_tcp_dest:
        jsr net_save_zp
        jsr ip65_set_tcp_dest   ; AX = pointer to 4-byte IP
        jsr net_restore_zp
        rts

; =============================================================================
; net_tcp_send - send data over TCP
; Input: A/X = pointer to data, net_send_len = 16-bit length
; Output: C=0 success, C=1 failure
; =============================================================================
net_tcp_send:
        sta net_send_ptr
        stx net_send_ptr+1
        jsr net_save_zp
        ; set send length in ip65's variable
        lda net_send_len
        sta ip65_tcp_snd_len
        lda net_send_len+1
        sta ip65_tcp_snd_len+1
        ; send — AX = data pointer
        lda net_send_ptr
        ldx net_send_ptr+1
        jsr ip65_tcp_send
        php
        jsr net_restore_zp
        plp
        rts

; =============================================================================
; net_tcp_close - close TCP connection
; =============================================================================
net_tcp_close:
        jsr net_save_zp
        jsr ip65_tcp_close
        jsr net_restore_zp
        rts

; =============================================================================
; net_print_ip - display current IP address in dotted decimal
; =============================================================================
net_print_ip:
        lda ip65_cfg_ip
        jsr @print_byte
        lda #'.'
        jsr chrout
        lda ip65_cfg_ip+1
        jsr @print_byte
        lda #'.'
        jsr chrout
        lda ip65_cfg_ip+2
        jsr @print_byte
        lda #'.'
        jsr chrout
        lda ip65_cfg_ip+3
        jsr @print_byte
        lda #$0d
        jsr chrout
        rts

; print decimal byte value (0-255)
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
        beq @pb_tens            ; skip leading zero
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
        ; print tens (always if hundreds was printed, otherwise skip leading zero)
        cpx #0
        bne @pb_t_out
        ldy @pb_val
        cpy #10
        bcc @pb_ones            ; value < 10, skip tens
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
@pb_val: !byte 0

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
        inc tcp_recv_head       ; wraps at 256
        clc
        rts
@empty:
        sec
        rts

; =============================================================================
; TCP receive callback — called by ip65 DURING ip65_process
; ip65's ZP ($02-$1B) is active. DO NOT touch crypto state.
; Copies incoming data to tcp_recv_buf ring buffer.
;
; ip65 sets:
;   tcp_inbound_data_ptr (at address read from variable table)
;   tcp_inbound_data_length (at address read from variable table)
;
; Since we know the direct addresses from the link map, we use those.
; =============================================================================
net_tcp_recv_cb:
        ; We can't use indirect ZP pointers here easily since ip65 owns ZP.
        ; Instead, use self-modifying code to copy from the data pointer.
        ;
        ; For now, a simplified version using absolute addressing:
        ; The actual inbound data pointers are ip65 internal addresses
        ; that we'd need to dereference. This requires careful implementation
        ; once we have ip65 running end-to-end.
        ;
        ; TODO: implement full ring buffer copy when testing with real network
        rts

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
