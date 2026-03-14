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
        !text "I=INIT NETWORK  G=HTTPS GET  Q=QUIT"
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

; =============================================================================
; do_https_get - placeholder for HTTPS GET flow
; =============================================================================
do_https_get:
        lda #<get_msg
        ldy #>get_msg
        jsr print_string
        ; TODO: DNS resolve -> TCP connect -> TLS handshake -> HTTP GET
        rts

get_msg:
        !text "HTTPS GET - NOT YET IMPLEMENTED"
        !byte $0d, 0
