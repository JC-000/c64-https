; boot.s — Startup, BASIC stub, screen output, phase 3 orchestration
; Converted from ACME to ca65 in Phase 3 Batch D.

        .include "constants.inc"

        ; ---- exports: entry + print helpers ----
        .export start
        .export main_loop
        .export print_string
        .export print_null_terminated
        .export print_resp_body

        ; ---- exports: REU multiply table routines ----
        .export reu_mul_init
        .export reu_fetch_mul_row

        ; ---- exports: menu handlers ----
        .export do_net_init
        .export do_http_get
        .export do_https_get

        ; ---- exports: banner / menu / status strings ----
        .export banner_msg
        .export menu_msg
        .export init_msg
        .export net_fail_msg
        .export net_ok_msg
        .export dhcp_msg
        .export dhcp_fail_msg
        .export dhcp_ok_msg
        .export no_net_msg
        .export http_get_msg
        .export https_get_msg
        .export dns_fail_msg
        .export dns_ok_msg
        .export tcp_fail_msg
        .export tcp_ok_msg
        .export tls_fail_msg
        .export tls_ok_msg
        .export send_fail_msg
        .export send_ok_msg
        .export ok_msg
        .export failed_msg
        .export done_msg

        ; ---- exports: 15 TLS state transition markers (used by tls13.s) ----
        .export ch_sent_msg
        .export sh_recv_msg
        .export hk1_msg
        .export keys_ok_msg
        .export ee_recv_msg
        .export cert_recv_msg
        .export cv_recv_msg
        .export fin_recv_msg
        .export cfin_sent_msg
        .export enc1_msg
        .export rx_msg
        .export got_msg
        .export got2_msg
        .export dec_msg
        .export proc_msg

        ; ---- exports: hostnames / path data ----
        .export http_host_zimmers
        .export http_host_zimmers_len
        .export http_host_foo
        .export http_host_foo_len
        .export http_path_root

        ; ---- exports: local BSS ----
        .export net_initialized

        ; ---- imports: entropy / DRBG / sqtab ----
        .import entropy_init
        .import drbg_init_entropy
        .import sqtab_init

        ; ---- imports: network (backend adapter — ip65 or uci) ----
        .import net_init
        .import net_dhcp
        .import net_poll
        .import net_print_ip
        .import net_dns_resolve
        .import net_tcp_connect
        .import net_tcp_close
        .import net_banner_str

        ; ---- imports: TLS state machine ----
        .import tls_connect
        .import tls_send
        .import tls_recv
        .import tls_close

        ; ---- imports: HTTP ----
        .import http_get_plain
        .import http_build_get

        ; ---- imports: HTTP I/O state (data.asm) ----
        .import http_host_ptr
        .import http_host_len
        .import http_path_ptr
        .import http_path_len
        .import http_port
        .import http_req_buf
        .import http_req_len
        .import http_resp_buf
        .import http_resp_len

        ; ---- imports: TLS app-data pointers (data.asm) ----
        .import tls_app_ptr
        .import tls_app_len
        .import tls_hostname
        .import tls_hostname_len

        ; ---- imports: multiply / REU staging (data.asm) ----
        .import mul_8x8
        .import mul_dma_lo
        .import mul_dma_hi
        .import mul_cached_a
        .import poly_prod_lo
        .import poly_prod_hi

; =============================================================================
; BASIC stub: 10 SYS 2061
; Loaded at $0801 via EXEHDR segment (first bytes of LOADER region).
; =============================================================================
        .segment "EXEHDR"
        .word   bas_end                 ; pointer to next BASIC line
        .word   10                      ; line number
        .byte   $9e                     ; SYS token
        .byte   "2061"                  ; decimal address of `start` ($080D)
        .byte   0                       ; end of BASIC line
bas_end:
        .word   0                       ; end of BASIC program

; =============================================================================
; Code
; =============================================================================
        .segment "CODE"

; --- entry point (address $080D; SYS 2061) ---
start:
        ; disable BASIC ROM to free $A000-$BFFF
        lda $01
        and #%11111110          ; clear bit 0 (BASIC ROM off)
        sta $01

        sei                     ; disable interrupts during init

        ; Zero SHADOW_BSS ($A000-$BFFF, 8 KiB). PRG LOAD does not zero BSS;
        ; ca65 BSS segments in file-less regions start with whatever RAM
        ; happened to contain. Without this, `net_initialized` and similar
        ; boot guards read garbage and send us straight into ip65 code before
        ; ip65 has been initialised, crashing us back to BASIC READY.
        ldy #$00
        ldx #$20                ; 32 pages = $2000 bytes
        lda #$A0
        sta @zbss_store+2       ; reset high byte (idempotent across resets)
        lda #$00
@zbss_page:
@zbss_store:
        sta $A000,y             ; self-modified high byte walks $A0..$BF
        iny
        bne @zbss_store
        inc @zbss_store+2
        dex
        bne @zbss_page

        ; clear screen
        lda #$93
        jsr chrout

        ; print banner (front-matter)
        lda #<banner_msg
        ldy #>banner_msg
        jsr print_string

        ; print backend-specific network identification line
        lda #<net_banner_str
        ldy #>net_banner_str
        jsr print_string

        ; print banner tail (trailing blank line before the menu)
        lda #<banner_msg_tail
        ldy #>banner_msg_tail
        jsr print_string

        cli                     ; re-enable interrupts

        ; initialize hardware entropy sources and seed DRBG
        jsr entropy_init
        jsr drbg_init_entropy

        ; build quarter-square multiply table (needed by Poly1305, fe25519, ECDSA)
        jsr sqtab_init

        ; pre-compute REU multiply rows (depends on sqtab being populated)
        ; Ensure BASIC ROM is off — data buffers and REU DMA targets live at $A000+
        lda $01
        and #%11111110
        sta $01
        jsr reu_mul_init

        ; Auto-initialize networking at boot so the banner shows the
        ; firmware-assigned IP without waiting for the user to press 'I'.
        ; On ip65 this runs the full cs8900a + DHCP handshake; on the
        ; UCI backend it probes the U64E command interface and reads the
        ; firmware's existing DHCP lease via GET_IPADDR. A failure here
        ; is non-fatal — the user can still retry from the menu.
        jsr do_net_init

        ; print menu
        lda #<menu_msg
        ldy #>menu_msg
        jsr print_string

        ; Ensure BASIC ROM stays off for all runtime operation.
        ; Data buffers (fe_wide, x25_*, ECDSA) live at $A000-$BFFF.
        ; The C64 writes to RAM under ROM, but reads hit ROM unless banked out.
        lda $01
        and #%11111110
        sta $01

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

; =============================================================================
; print_string - print null-terminated string at A(lo)/Y(hi)
;
; Also aliased as `print_null_terminated` for the screen_marker macro in
; macros.inc.
; =============================================================================
print_string:
print_null_terminated:
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
        lda #<http_host_foo
        sta http_host_ptr
        lda #>http_host_foo
        sta http_host_ptr+1
        lda #http_host_foo_len
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
        lda http_host_foo,x
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
        lda #<http_host_foo
        ldx #>http_host_foo
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
; print_resp_body - print up to 200 bytes of http_resp_buf to screen.
; Bytes originate from the network as ASCII, so they are fed through
; ascii_chrout (below) which translates ASCII -> PETSCII before CHROUT.
; =============================================================================
print_resp_body:
        ldx #0
@loop:
        cpx #200
        beq @done
        lda http_resp_buf,x
        beq @done               ; stop at null
        jsr ascii_chrout
        inx
        bne @loop
@done:
        lda #$0d                ; trailing carriage return
        jsr chrout
        rts

; =============================================================================
; ascii_chrout - translate ASCII byte in A to PETSCII and print via CHROUT.
;
; Mapping (default uppercase/graphics character set, strategy B):
;   $0A (LF)        -> $0D       (CHROUT advances one line)
;   $0D (CR)        -> $0D       (pass through)
;   $20-$3F         -> pass through (space, digits, punctuation)
;   $40-$5F         -> pass through (@, uppercase A-Z, [\]^_)
;   $61-$7A (a-z)   -> uppercase fold ($41-$5A) so lowercase letters render
;                      as uppercase glyphs instead of graphics characters.
;   everything else -> drop (return without calling CHROUT)
;
; Single entry point used by every render site that takes network-origin
; ASCII bytes.  Preserves X and Y.  Clobbers A (consumed by CHROUT).
; =============================================================================
ascii_chrout:
        cmp #$20
        bcc @ctrl               ; $00-$1F: handle CR/LF, drop rest
        cmp #$7f
        bcs @drop               ; $7F-$FF: drop (DEL + high-bit)
        cmp #$61
        bcc @emit               ; $20-$60: pass through unchanged
        cmp #$7b
        bcs @drop               ; $7B-$7E: drop { | } ~
        sec                     ; $61-$7A: a-z -> A-Z
        sbc #$20
@emit:
        jmp chrout              ; CHROUT preserves X,Y; tail-call
@ctrl:
        cmp #$0d
        beq @emit               ; CR pass through
        cmp #$0a
        bne @drop               ; LF -> CR, anything else drop
        lda #$0d
        jmp chrout
@drop:
        rts

; =============================================================================
; REU multiply table initialization (from c64-x25519 optimizations)
; =============================================================================

; =============================================================================
; reu_mul_init - Generate 256 full multiplication rows and stash in REU
;
; For each a = 0..255, computes a*b for b = 0..255 and stashes:
;   256 lo bytes at REU offset a*512
;   256 hi bytes at REU offset a*512+256
;
; Uses mul_dma_lo/mul_dma_hi as staging buffers.
; Uses mul_8x8 (requires sqtab to be initialized first).
; Clobbers: A, X, Y
; =============================================================================
reu_mul_init:
        lda #0
        sta reu_init_a         ; outer counter (multiplier a)

@outer:
        ; For current a, compute a*b for all b=0..255
        lda #0
        sta reu_init_b         ; inner counter (multiplicand b)

@inner:
        lda reu_init_a
        ldx reu_init_b
        jsr mul_8x8            ; poly_prod_lo/hi = a * b

        ldx reu_init_b
        lda poly_prod_lo
        sta mul_dma_lo,x
        lda poly_prod_hi
        sta mul_dma_hi,x

        inc reu_init_b
        bne @inner             ; loop b = 0..255

        ; Stash lo table (256 bytes) to REU at offset a*512
        lda #<mul_dma_lo
        sta reu_c64_lo
        lda #>mul_dma_lo
        sta reu_c64_hi
        lda #0
        sta reu_reu_lo         ; REU offset low = 0
        lda reu_init_a
        asl                    ; A = a * 2 (high byte of offset)
        sta reu_reu_hi
        lda #0
        adc #0                 ; carry into bank if a >= 128
        sta reu_reu_bank
        lda #0
        sta reu_len_lo
        lda #1
        sta reu_len_hi         ; length = 256
        lda #0
        sta reu_addr_ctrl      ; both addresses increment
        lda #%10110000         ; execute + autoload + STASH (C64->REU)
        sta reu_command

        ; Stash hi table (256 bytes) to REU at offset a*512+256
        lda #<mul_dma_hi
        sta reu_c64_lo
        lda #>mul_dma_hi
        sta reu_c64_hi
        lda #0
        sta reu_reu_lo
        lda reu_init_a
        asl                    ; a*2 (carry = bit 7 of a)
        lda #0
        adc #0                 ; bank = a >> 7
        sta reu_reu_bank
        lda reu_init_a
        asl                    ; a*2
        ora #1                 ; +1 for hi page (a*2 is even, so OR works)
        sta reu_reu_hi
        lda #0
        sta reu_len_lo
        lda #1
        sta reu_len_hi         ; length = 256
        lda #0
        sta reu_addr_ctrl
        lda #%10110000         ; execute + autoload + STASH
        sta reu_command

        inc reu_init_a
        beq @init_done         ; if wrapped to 0, done
        jmp @outer
@init_done:
        ; Pre-configure constant REU registers for fetch routine
        lda #<mul_dma_lo
        sta reu_c64_lo
        lda #>mul_dma_lo
        sta reu_c64_hi
        lda #0
        sta reu_reu_lo
        sta reu_len_lo
        sta reu_addr_ctrl
        lda #2
        sta reu_len_hi         ; length high = 2 (512 bytes)
        rts

; =============================================================================
; reu_fetch_mul_row - DMA a multiplication table row from REU to C64
;
; Input: mul_cached_a = multiplier value (0-255)
; Fetches 512 bytes: 256 lo bytes to mul_dma_lo, 256 hi bytes to mul_dma_hi
; Clobbers: A
; =============================================================================
reu_fetch_mul_row:
        lda mul_cached_a
        asl                    ; A = multiplier * 2, carry = bit 7
        sta reu_reu_hi
        lda #0
        adc #0                 ; bank = carry from shift
        sta reu_reu_bank
        lda #%10110001         ; execute + autoload + FETCH (REU->C64)
        sta reu_command
        rts

; =============================================================================
; Strings (read-only)
; =============================================================================
        .segment "RODATA"

; Banner is split in two so the per-backend `net_banner_str` (imported
; from src/net/<backend>/net.s or net_banner.s) can be slotted between
; the constant front-matter and the trailing blank lines at print time.
banner_msg:
        .byte "C64-HTTPS CLIENT V0.1"
        .byte $0d, $0d
        .byte "TLS 1.3 / CHACHA20-POLY1305"
        .byte $0d, 0

banner_msg_tail:
        .byte $0d, 0

menu_msg:
        .byte "I=INIT  H=HTTP  G=HTTPS  Q=QUIT"
        .byte $0d, $0d, 0

init_msg:
        .byte "INITIALIZING NETWORK..."
        .byte $0d, 0

net_fail_msg:
        .byte "NETWORK INIT FAILED"
        .byte $0d, 0

net_ok_msg:
        .byte "NETWORK OK"
        .byte $0d, 0

dhcp_msg:
        .byte "REQUESTING DHCP..."
        .byte $0d, 0

dhcp_fail_msg:
        .byte "DHCP FAILED"
        .byte $0d, 0

dhcp_ok_msg:
        .byte "DHCP OK - IP: "
        .byte 0

no_net_msg:
        .byte "ERROR: NETWORK NOT INITIALIZED"
        .byte $0d, 0

http_get_msg:
        .byte "HTTP GET WWW.ZIMMERS.NET..."
        .byte $0d, 0

https_get_msg:
        .byte "HTTPS GET WWW.FOO.BAR..."
        .byte $0d, 0

dns_fail_msg:
        .byte "DNS RESOLVE FAILED"
        .byte $0d, 0

dns_ok_msg:
        .byte "DNS OK"
        .byte $0d, 0

tcp_fail_msg:
        .byte "TCP CONNECT FAILED"
        .byte $0d, 0

tcp_ok_msg:
        .byte "TCP CONNECTED"
        .byte $0d, 0

tls_fail_msg:
        .byte "TLS HANDSHAKE FAILED"
        .byte $0d, 0

tls_ok_msg:
        .byte "TLS HANDSHAKE OK"
        .byte $0d, 0

; TLS state transition markers (debug) — imported by tls13.s
ch_sent_msg:    .byte "CH", $0d, 0
sh_recv_msg:    .byte "SH", $0d, 0
hk1_msg:        .byte "HK1", $0d, 0
keys_ok_msg:    .byte "KEYS", $0d, 0
ee_recv_msg:    .byte "EE", $0d, 0
cert_recv_msg:  .byte "CERT", $0d, 0
cv_recv_msg:    .byte "CV", $0d, 0
fin_recv_msg:   .byte "FIN", $0d, 0
cfin_sent_msg:  .byte "CFIN", $0d, 0
enc1_msg:       .byte "ENC1", $0d, 0
rx_msg:         .byte "RX", $0d, 0
got_msg:        .byte "GOT", $0d, 0
got2_msg:       .byte "GOT2", $0d, 0
dec_msg:        .byte "DEC", $0d, 0
proc_msg:       .byte "PROC", $0d, 0

send_fail_msg:
        .byte "TLS SEND FAILED"
        .byte $0d, 0

send_ok_msg:
        .byte "REQUEST SENT"
        .byte $0d, 0

ok_msg:
        .byte "OK"
        .byte $0d, 0

failed_msg:
        .byte "FAILED"
        .byte $0d, 0

done_msg:
        .byte "CONNECTION CLOSED"
        .byte $0d, 0

; =============================================================================
; hostname and path data
; =============================================================================
http_host_zimmers:
        .byte "www.zimmers.net"
        .byte 0
http_host_zimmers_len = 15

http_host_foo:
        .byte "www.foo.bar"
        .byte 0
http_host_foo_len = 11

http_path_root:
        .byte "/"
        .byte 0

; =============================================================================
; Local BSS
; =============================================================================
        .segment "BSS"

net_initialized:        .res 1
reu_init_a:             .res 1
reu_init_b:             .res 1
