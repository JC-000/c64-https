; src/net/uci-m3/m3_https_get.inc — do_https_get for BACKEND=uci-m3.
;
; .included by src/boot.s in place of the 6510-TLS do_https_get, so it uses
; boot.s's own helpers (print_string, ascii_chrout, https_target_prompt)
; and messages. The flow is the plain one, because the "TCP" connection
; net_tcp_connect opens IS the verified TLS session (src/net/uci-m3/net.s):
;
;   prompt -> stage host -> OPEN_TLS -> GET -> READ to the end -> CLOSE
;
; Every refusal prints the firmware's own status line (e.g.
; "94,CERTIFICATE NAME MISMATCH: 0x00000004"): that line IS the reason, and
; it is at most 40 bytes (ER-8). A wedged interface prints PRESS RESET and
; halts, writing nothing more to the UCI (ER-11).

        .import m3_status
        .import m3_status_len
        .import m3_wedged
        .import m3_open_reply

do_https_get:
        lda net_initialized
        bne @net_ok
        lda #<no_net_msg
        ldy #>no_net_msg
        jmp print_string
@net_ok:
        jsr http_resp_init      ; no http_status etc. from the last fetch
        jsr https_target_prompt ; sets tls_hostname + http_host/path, banner
        bcc @target_set
        rts                     ; refused: reported, nothing dialled
@target_set:
        lda #<tls_hostname
        ldx #>tls_hostname
        jsr net_dns_resolve     ; stages the name; OPEN_TLS resolves it
        bcs @open_fail
        lda #<m3_open_msg
        ldy #>m3_open_msg
        jsr print_string
        lda #<HTTPS_PORT
        ldx #>HTTPS_PORT
        jsr net_tcp_connect     ; OPEN_TLS: DNS, connect, handshake, verify
        bcc @open_ok
@open_fail:
        lda #<tls_fail_msg
        ldy #>tls_fail_msg
        jsr print_string
        jmp m3_report_fail

@open_ok:
        lda #<tls_ok_msg
        ldy #>tls_ok_msg
        jsr print_string
        jsr m3_print_version

        jsr http_build_get
        lda http_req_len
        sta net_send_len
        lda http_req_len+1
        sta net_send_len+1
        lda #<http_req_buf
        ldx #>http_req_buf
        jsr net_tcp_send
        bcc @send_ok
        lda #<send_fail_msg
        ldy #>send_fail_msg
        jsr print_string
        jsr m3_print_status
        jmp @close
@send_ok:
        lda #<send_ok_msg
        ldy #>send_ok_msg
        jsr print_string

.ifdef HTTPS_BODY_TO_REU
        lda #1                  ; stream the body into the REU (src/http.s)
        sta http_body_sink
.endif
        jsr http_recv_body
        lda #0
        ror                     ; bit 7 = C: the body is short of its framing
        sta m3_body_short
.ifdef VIEWER_LINKED
        lda http_body_sink
        beq @print_body
        jsr viewer_enter
        jmp @verdict
@print_body:
.endif
        jsr print_resp_body
@verdict:
        bit m3_body_short
        bpl @close
        lda #<m3_short_msg
        ldy #>m3_short_msg
        jsr print_string
        jsr m3_print_status     ; e.g. 05,TLS CLOSED WITHOUT NOTIFY
@close:
        jsr net_tcp_close
        jsr m3_check_wedge
        lda #<done_msg
        ldy #>done_msg
        jmp print_string

; m3_report_fail — print the firmware's status line, then the wedge check.
m3_report_fail:
        jsr m3_print_status
        ; fall through

; m3_check_wedge — if the interface is wedged, say so and halt (ER-11):
; only a hardware reset (button, Ultimate menu, power) reaches the Nios.
m3_check_wedge:
        bit m3_wedged
        bpl @cw_out
        lda #<m3_wedge_msg
        ldy #>m3_wedge_msg
        jsr print_string
@cw_halt:
        jmp @cw_halt
@cw_out:
        rts

; m3_print_status — the last command's status line (ASCII), then CR.
m3_print_status:
        ldx #0
@ps_loop:
        cpx m3_status_len
        bcs @ps_done
        lda m3_status,x
        jsr ascii_chrout        ; preserves X
        inx
        bne @ps_loop
@ps_done:
        lda #$0d
        jmp chrout

; m3_print_version — "TLS 1.3" / "TLS 1.2" from OPEN reply bytes 1..2 (LE).
m3_print_version:
        lda #<m3_tls_msg
        ldy #>m3_tls_msg
        jsr print_string
        lda m3_open_reply+2     ; 0x0304 travels as 04 03: high byte 03
        sec
        sbc #2                  ; 03 -> "1"
        and #$0F
        ora #'0'
        jsr chrout
        lda #'.'
        jsr chrout
        lda m3_open_reply+1     ; low byte: 04 -> "3" (1.3), 03 -> "2" (1.2)
        sec
        sbc #1
        and #$0F
        ora #'0'
        jsr chrout
        lda #$0d
        jmp chrout

        .segment "RODATA"
m3_open_msg:    .byte "OPEN TLS (ULTIMATE)...", $0d, 0
m3_tls_msg:     .byte "PROTOCOL TLS ", 0
m3_short_msg:   .byte "BODY INCOMPLETE:", $0d, 0
m3_wedge_msg:   .byte $0d, "NETWORK INTERFACE NOT RESPONDING", $0d
                .byte "- PRESS RESET", $0d, 0
.ifdef HTTPS_PIN_SPKI
        .export m3_pin
m3_pin:         .byte HTTPS_PIN_SPKI_BYTES      ; trust 2 (S 1.1), digest order
.endif
        .segment "BSS"
m3_body_short:  .res 1
        .segment "CODE"
