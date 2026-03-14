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

        ; initialize crypto PRNG (SID + CIA entropy)
        ; jsr drbg_init_entropy  ; TODO: enable when crypto modules are integrated

        ; initialize network
        jsr net_init
        bcc @net_ok

        lda #<net_fail_msg
        ldy #>net_fail_msg
        jsr print_string
        jmp @halt

@net_ok:
        lda #<net_ok_msg
        ldy #>net_ok_msg
        jsr print_string

        ; obtain IP via DHCP
        jsr net_dhcp
        bcc @dhcp_ok

        lda #<dhcp_fail_msg
        ldy #>dhcp_fail_msg
        jsr print_string
        jmp @halt

@dhcp_ok:
        lda #<dhcp_ok_msg
        ldy #>dhcp_ok_msg
        jsr print_string

        ; display assigned IP
        jsr net_print_ip

        cli                     ; re-enable interrupts

        ; enter main loop
        jmp main_loop

@halt:
        cli
        jmp @halt               ; spin on error

; =============================================================================
; main_loop - poll network, process TLS, handle user input
; =============================================================================
main_loop:
        jsr net_poll            ; pump ip65 (handles ZP swap)

        ; check for user input
        jsr getin
        beq main_loop           ; no key pressed

        ; 'Q' = quit
        cmp #$51
        beq @quit

        ; 'G' = HTTPS GET
        cmp #$47
        bne main_loop
        jsr do_https_get
        jmp main_loop

@quit:
        ; re-enable BASIC ROM
        lda $01
        ora #%00000001
        sta $01
        rts

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

net_fail_msg:
        !text "NETWORK INIT FAILED"
        !byte $0d, 0

net_ok_msg:
        !text "NETWORK OK"
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
