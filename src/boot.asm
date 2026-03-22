; =============================================================================
; boot.asm - BASIC stub and startup
; =============================================================================

* = $0801

; BASIC stub: 10 SYS 2064
        !word @end              ; pointer to next BASIC line
        !word 10                ; line number
        !byte $9e               ; SYS token
        !text "2064"            ; decimal address of @start
        !byte 0                 ; end of BASIC line
@end:
        !word 0                 ; end of BASIC program

; --- entry point (address $0810) ---
@start:
        ; disable BASIC ROM to free $A000-$BFFF
        lda $01
        and #%11111110          ; clear bit 0 (BASIC ROM off)
        sta $01

        sei                     ; disable interrupts during init

        ; clear screen
        lda #$93
        jsr chrout

        ; print banner
        lda #<banner_msg
        ldy #>banner_msg
        jsr print_string

        cli                     ; re-enable interrupts

        ; initialize hardware entropy sources and seed DRBG
        jsr entropy_init
        jsr drbg_init_entropy

        ; print menu
        lda #<menu_msg
        ldy #>menu_msg
        jsr print_string

        ; enter main loop
        jmp main_loop

; =============================================================================
; main_loop - poll network, process TLS, handle user input
; =============================================================================
main_loop:
        ; only poll network if initialized
        lda net_initialized
        beq @check_keys
        jsr net_poll            ; pump ip65 (handles ZP swap)

@check_keys:
        jsr getin
        beq main_loop           ; no key pressed

        ; 'I' = initialize network
        cmp #$49
        bne @not_i
        jsr do_net_init
        jmp main_loop
@not_i:
        ; 'H' = plain HTTP GET
        cmp #$48
        bne @not_h
        jsr do_http_get
        jmp main_loop
@not_h:
        ; 'G' = HTTPS GET
        cmp #$47
        bne @not_g
        jsr do_https_get
        jmp main_loop
@not_g:
        ; 'Q' = quit
        cmp #$51
        bne main_loop

        ; re-enable BASIC ROM
        lda $01
        ora #%00000001
        sta $01
        rts

; =============================================================================
; do_net_init - initialize network (menu-driven)
; =============================================================================
do_net_init:
        lda #<init_msg
        ldy #>init_msg
        jsr print_string

        jsr net_init
        bcc @init_ok

        lda #<net_fail_msg
        ldy #>net_fail_msg
        jsr print_string
        rts

@init_ok:
        lda #<net_ok_msg
        ldy #>net_ok_msg
        jsr print_string

        ; DHCP
        lda #<dhcp_msg
        ldy #>dhcp_msg
        jsr print_string

        jsr net_dhcp
        bcc @dhcp_ok

        lda #<dhcp_fail_msg
        ldy #>dhcp_fail_msg
        jsr print_string
        rts

@dhcp_ok:
        lda #<dhcp_ok_msg
        ldy #>dhcp_ok_msg
        jsr print_string
        jsr net_print_ip

        lda #1
        sta net_initialized
        rts

net_initialized: !byte 0

; =============================================================================
; print_string - print null-terminated string at A(lo)/Y(hi)
; =============================================================================
print_string:
        sta zp_ptr
        sty zp_ptr+1
        ldy #0
@loop:
        lda (zp_ptr),y
        beq @done
        jsr chrout
        iny
        bne @loop
@done:
        rts

; =============================================================================
; do_http_get - plain HTTP GET (menu-driven)
; =============================================================================
do_http_get:
        ; check network is up
        lda net_initialized
        bne @net_ok
        lda #<no_net_msg
        ldy #>no_net_msg
        jsr print_string
        rts

@net_ok:
        lda #<http_get_msg
        ldy #>http_get_msg
        jsr print_string

        ; set host pointer and length
        lda #<http_host_zimmers
        sta http_host_ptr
        lda #>http_host_zimmers
        sta http_host_ptr+1
        lda #http_host_zimmers_len
        sta http_host_len

        ; set path pointer and length
        lda #<http_path_root
        sta http_path_ptr
        lda #>http_path_root
        sta http_path_ptr+1
        lda #1
        sta http_path_len

        ; set port to 80
        lda #80
        sta http_port
        lda #0
        sta http_port+1

        ; call the all-in-one plain HTTP GET
        jsr http_get_plain
        bcc @http_ok

        lda #<failed_msg
        ldy #>failed_msg
        jsr print_string
        rts

@http_ok:
        lda #<ok_msg
        ldy #>ok_msg
        jsr print_string

        ; display response body
        jsr print_resp_body
        rts

; =============================================================================
; do_https_get - full HTTPS GET flow (menu-driven)
; =============================================================================
do_https_get:
        ; check network is up
        lda net_initialized
        bne @net_ok
        lda #<no_net_msg
        ldy #>no_net_msg
        jsr print_string
        rts

@net_ok:
        lda #<https_get_msg
        ldy #>https_get_msg
        jsr print_string

        ; --- set HTTP host/path/port ---
        lda #<http_host_apple
        sta http_host_ptr
        lda #>http_host_apple
        sta http_host_ptr+1
        lda #http_host_apple_len
        sta http_host_len

        lda #<http_path_root
        sta http_path_ptr
        lda #>http_path_root
        sta http_path_ptr+1
        lda #1
        sta http_path_len

        lda #<443
        sta http_port
        lda #>443
        sta http_port+1

        ; --- copy hostname into tls_hostname for SNI ---
        ldx #0
@copy_host:
        lda http_host_apple,x
        beq @copy_done
        sta tls_hostname,x
        inx
        cpx #63                 ; guard: max 63 chars
        bne @copy_host
@copy_done:
        lda #0
        sta tls_hostname,x      ; null-terminate
        stx tls_hostname_len

        ; --- DNS resolve ---
        lda #<http_host_apple
        ldx #>http_host_apple
        jsr net_dns_resolve
        bcc @dns_ok

        lda #<dns_fail_msg
        ldy #>dns_fail_msg
        jsr print_string
        rts

@dns_ok:
        lda #<dns_ok_msg
        ldy #>dns_ok_msg
        jsr print_string

        ; --- set TCP destination IP ---
        lda #<ip65_dns_ip_addr
        ldx #>ip65_dns_ip_addr
        jsr net_set_tcp_dest

        ; --- TCP connect port 443 ---
        lda #<443               ; port low byte
        ldx #>443               ; port high byte
        jsr net_tcp_connect
        bcc @tcp_ok

        lda #<tcp_fail_msg
        ldy #>tcp_fail_msg
        jsr print_string
        rts

@tcp_ok:
        lda #<tcp_ok_msg
        ldy #>tcp_ok_msg
        jsr print_string

        ; --- TLS handshake ---
        jsr tls_connect
        bcc @tls_ok

        lda #<tls_fail_msg
        ldy #>tls_fail_msg
        jsr print_string
        jsr net_tcp_close
        rts

@tls_ok:
        lda #<tls_ok_msg
        ldy #>tls_ok_msg
        jsr print_string

        ; --- build HTTP GET request ---
        jsr http_build_get

        ; --- send request via TLS ---
        lda #<http_req_buf
        sta tls_app_ptr
        lda #>http_req_buf
        sta tls_app_ptr+1
        lda http_req_len
        sta tls_app_len
        lda http_req_len+1
        sta tls_app_len+1

        jsr tls_send
        bcc @send_ok

        lda #<send_fail_msg
        ldy #>send_fail_msg
        jsr print_string
        jmp @close

@send_ok:
        lda #<send_ok_msg
        ldy #>send_ok_msg
        jsr print_string

        ; --- receive response via TLS ---
@recv_loop:
        jsr net_poll            ; pump network
        jsr tls_recv
        bcs @recv_loop          ; C=1 means no data yet, keep polling

        ; got data -- tls_app_ptr/tls_app_len has decrypted payload
        ; copy into http_resp_buf (up to 512 bytes)
        lda tls_app_ptr
        sta zp_ptr
        lda tls_app_ptr+1
        sta zp_ptr+1

        ldy #0
        ldx tls_app_len         ; low byte of length (assume <256 for first chunk)
@copy_resp:
        cpx #0
        beq @recv_done
        lda (zp_ptr),y
        sta http_resp_buf,y
        iny
        dex
        bne @copy_resp

@recv_done:
        sty http_resp_len       ; store how many bytes we copied
        lda #0
        sta http_resp_len+1

        ; display response
        jsr print_resp_body

@close:
        jsr tls_close
        jsr net_tcp_close

        lda #<done_msg
        ldy #>done_msg
        jsr print_string
        rts

; =============================================================================
; print_resp_body - print up to 200 bytes of http_resp_buf to screen
; =============================================================================
print_resp_body:
        ldx #0
@loop:
        cpx #200
        beq @done
        lda http_resp_buf,x
        beq @done               ; stop at null
        jsr chrout
        inx
        bne @loop
@done:
        lda #$0d                ; trailing carriage return
        jsr chrout
        rts

; =============================================================================
; strings
; =============================================================================
banner_msg:
        !text "C64-HTTPS CLIENT V0.1"
        !byte $0d, $0d
        !text "TLS 1.3 / CHACHA20-POLY1305"
        !byte $0d
        !text "RR-NET (CS8900A) ETHERNET"
        !byte $0d, $0d, 0

menu_msg:
        !text "I=INIT  H=HTTP  G=HTTPS  Q=QUIT"
        !byte $0d, $0d, 0

init_msg:
        !text "INITIALIZING NETWORK..."
        !byte $0d, 0

net_fail_msg:
        !text "NETWORK INIT FAILED"
        !byte $0d, 0

net_ok_msg:
        !text "NETWORK OK"
        !byte $0d, 0

dhcp_msg:
        !text "REQUESTING DHCP..."
        !byte $0d, 0

dhcp_fail_msg:
        !text "DHCP FAILED"
        !byte $0d, 0

dhcp_ok_msg:
        !text "DHCP OK - IP: "
        !byte 0

no_net_msg:
        !text "ERROR: NETWORK NOT INITIALIZED"
        !byte $0d, 0

http_get_msg:
        !text "HTTP GET WWW.ZIMMERS.NET..."
        !byte $0d, 0

https_get_msg:
        !text "HTTPS GET WWW.APPLE.COM..."
        !byte $0d, 0

dns_fail_msg:
        !text "DNS RESOLVE FAILED"
        !byte $0d, 0

dns_ok_msg:
        !text "DNS OK"
        !byte $0d, 0

tcp_fail_msg:
        !text "TCP CONNECT FAILED"
        !byte $0d, 0

tcp_ok_msg:
        !text "TCP CONNECTED"
        !byte $0d, 0

tls_fail_msg:
        !text "TLS HANDSHAKE FAILED"
        !byte $0d, 0

tls_ok_msg:
        !text "TLS HANDSHAKE OK"
        !byte $0d, 0

send_fail_msg:
        !text "TLS SEND FAILED"
        !byte $0d, 0

send_ok_msg:
        !text "REQUEST SENT"
        !byte $0d, 0

ok_msg:
        !text "OK"
        !byte $0d, 0

failed_msg:
        !text "FAILED"
        !byte $0d, 0

done_msg:
        !text "CONNECTION CLOSED"
        !byte $0d, 0

; =============================================================================
; hostname and path data
; =============================================================================
http_host_zimmers:
        !text "www.zimmers.net"
        !byte 0
http_host_zimmers_len = 15

http_host_apple:
        !text "www.apple.com"
        !byte 0
http_host_apple_len = 13

http_path_root:
        !text "/"
        !byte 0
