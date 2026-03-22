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
        bcs @init_fail
        ; resolve variable table pointers for TCP callback SMC
        jsr net_init_cb_addrs
        clc
@init_fail:
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
; ip65 sets tcp_inbound_data_ptr and tcp_inbound_data_length before calling.
; net_init_cb_addrs resolves the variable table pointers and patches the
; SMC instructions below so we can read those ip65 variables using absolute
; addressing (no ZP indirection needed).
; =============================================================================
net_tcp_recv_cb:
        ; --- Read inbound data length (16-bit) ---
cb_load_len_lo:
        lda $ffff               ; SMC: patched to addr of tcp_inbound_data_length
        sta cb_remaining
cb_load_len_hi:
        lda $ffff               ; SMC: patched to addr of tcp_inbound_data_length+1
        sta cb_remaining+1
        ; if length == 0, nothing to copy
        ora cb_remaining
        beq cb_done

        ; --- Read inbound data pointer (16-bit), patch copy source ---
cb_load_ptr_lo:
        lda $ffff               ; SMC: patched to addr of tcp_inbound_data_ptr
        sta cb_copy_byte+1      ; patch low byte of LDA abs,x source
cb_load_ptr_hi:
        lda $ffff               ; SMC: patched to addr of tcp_inbound_data_ptr+1
        sta cb_copy_byte+2      ; patch high byte of LDA abs,x source

        ; Copy loop: X = source index, Y = ring buffer tail
        ldx #0
        ldy tcp_recv_tail
cb_loop:
        ; Check 16-bit remaining count
        lda cb_remaining
        ora cb_remaining+1
        beq cb_done

cb_copy_byte:
        lda $ffff,x             ; SMC: patched to ip65 inbound data base address
        sta tcp_recv_buf,y
        iny                     ; tail wraps at 256 (8-bit)
        inx

        ; decrement 16-bit remaining
        lda cb_remaining
        sec
        sbc #1
        sta cb_remaining
        bcs cb_loop
        dec cb_remaining+1
        jmp cb_loop

cb_done:
        sty tcp_recv_tail       ; store updated tail
        rts

cb_remaining: !word 0           ; bytes remaining to copy (callback-local)

; =============================================================================
; net_init_cb_addrs - resolve ip65 variable table pointers for TCP callback
;
; The variable table entries (ip65_vt_tcp_in_ptr, ip65_vt_tcp_in_len) each
; hold a 2-byte address pointing to ip65's internal variable. We read those
; addresses and patch the SMC operands in net_tcp_recv_cb.
;
; Must be called after ip65 binary is loaded (during net_init or before
; first TCP connection). Safe to call with ZP available (not in callback).
; =============================================================================
net_init_cb_addrs:
        ; --- Resolve tcp_inbound_data_ptr address ---
        ; ip65_vt_tcp_in_ptr contains address-of ip65's tcp_inbound_data_ptr
        lda ip65_vt_tcp_in_ptr      ; low byte of addr
        sta cb_load_ptr_lo+1        ; patch SMC operand
        lda ip65_vt_tcp_in_ptr+1    ; high byte of addr
        sta cb_load_ptr_lo+2

        ; ptr+1 is at addr+1
        lda ip65_vt_tcp_in_ptr
        clc
        adc #1
        sta cb_load_ptr_hi+1
        lda ip65_vt_tcp_in_ptr+1
        adc #0
        sta cb_load_ptr_hi+2

        ; --- Resolve tcp_inbound_data_length address ---
        lda ip65_vt_tcp_in_len
        sta cb_load_len_lo+1
        lda ip65_vt_tcp_in_len+1
        sta cb_load_len_lo+2

        ; len+1 is at addr+1
        lda ip65_vt_tcp_in_len
        clc
        adc #1
        sta cb_load_len_hi+1
        lda ip65_vt_tcp_in_len+1
        adc #0
        sta cb_load_len_hi+2

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
