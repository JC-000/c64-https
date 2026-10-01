; src/net/net_recv_byte.inc — net_recv_byte, the rx-ring drain entry
; (src/net_abi.inc, #72), shared by the two UCI adapters (src/net/uci/net.s
; and src/net/uci-m3/net.s), which .include it in their UCI_CODE. Byte for
; byte the routine both carried before it moved here.
;
; Ring addressing: effective = tcp_recv_buf + (head & TCP_RECV_MASK). SMC on
; @nrb_ld, so no zero page (crypto and ip65 time-share it).
; Output: A = byte, C=0 on success, C=1 if the ring is empty.

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
