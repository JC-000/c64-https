; http.s — HTTP/1.1 client over TLS
; Converted from ACME to ca65 in Phase 3 Batch C.
;
; Builds HTTP requests, parses responses. Operates over the TLS layer
; (tls_send / tls_recv), so all data is encrypted transparently.
;
; For the MVP, supports only GET requests with basic response parsing
; (status line + headers + body).

        .include "constants.inc"

        ; ---- exports ----
        .export http_get
        .export http_build_get
        .export http_recv_response
        .export http_get_plain
        .export http_get_verb
        .export http_version
        .export http_host_hdr
        .export http_conn_hdr
        .export http_crlf
        .export http_bg_idx
        .export http_bg_src

        ; ---- imports: data.asm BSS (HTTP I/O + parser state) ----
        .import http_host_ptr
        .import http_host_len
        .import http_path_ptr
        .import http_path_len
        .import http_port
        .import http_status
        .import http_req_buf
        .import http_req_len
        .import http_resp_buf
        .import http_resp_len
        .import http_parse_state
        .import http_hdr_match
        .import http_line_idx
        .import http_line_buf

        ; ---- imports: data.asm BSS (TLS app data + TCP ring tail) ----
        .import tls_app_ptr
        .import tls_app_len
        .import tcp_recv_tail

        ; ---- imports: TLS handshake layer (SNI buffer + connect/close) ----
        .import tls_hostname
        .import tls_hostname_len
        .import tls_connect
        .import tls_close

        ; ---- imports: TLS record layer (app-data send/recv) ----
        .import tls_send
        .import tls_recv

        ; ---- imports: net.asm wrappers around ip65 ----
        .import net_dns_resolve
        .import net_tcp_connect
        .import net_tcp_close
        .import net_tcp_send
        .import net_send_len
        .import net_poll
        .import net_recv_byte

; =============================================================================
; http_get - perform an HTTPS GET request
; Input: http_host_ptr/http_host_len = hostname (for Host header + SNI)
;        http_path_ptr/http_path_len = path (e.g., "/index.html")
;        http_port = port (default 443)
; Output: C=0 success (response in http_resp_buf), C=1 failure
; =============================================================================
        .segment "CODE"

http_get:
        ; --- 1. DNS resolve hostname ---
        lda http_host_ptr
        ldx http_host_ptr+1
        jsr net_dns_resolve
        bcc @dns_ok
        jmp @error
@dns_ok:

        ; --- 2. TCP connect on http_port ---
        lda http_port
        ldx http_port+1
        jsr net_tcp_connect
        bcc @tcp_ok
        jmp @error
@tcp_ok:

        ; --- 4. Copy hostname to tls_hostname for SNI ---
        lda http_host_ptr
        sta zp_ptr
        lda http_host_ptr+1
        sta zp_ptr+1
        ldy #0
@copy_host:
        cpy http_host_len
        beq @copy_host_done
        lda (zp_ptr),y
        sta tls_hostname,y
        iny
        bne @copy_host          ; always branches (hostname < 256)
@copy_host_done:
        lda #0
        sta tls_hostname,y      ; null-terminate
        sty tls_hostname_len

        ; --- 5. TLS handshake ---
        jsr tls_connect
        bcc @tls_ok
        jmp @tls_error
@tls_ok:

        ; --- 6. Build HTTP GET request ---
        jsr http_build_get

        ; --- 7. Send request via TLS ---
        lda #<http_req_buf
        sta tls_app_ptr
        lda #>http_req_buf
        sta tls_app_ptr+1
        lda http_req_len
        sta tls_app_len
        lda http_req_len+1
        sta tls_app_len+1
        jsr tls_send
        bcc :+
        jmp @close_error
:

        ; --- 8. Receive response via TLS ---
        ; Initialise parser state
        lda #0
        sta http_parse_state
        sta http_line_idx
        sta http_hdr_match
        sta http_resp_len
        sta http_resp_len+1

        ; Poll + receive loop
        lda #0
        sta @recv_timeout
        sta @recv_timeout+1
@recv_loop:
        jsr net_poll
        jsr tls_recv
        bcs @recv_no_data

        ; Got decrypted data in tls_app_ptr / tls_app_len
        ; Copy tls_app_ptr to ZP for indirect addressing
        lda tls_app_ptr
        sta zp_ptr
        lda tls_app_ptr+1
        sta zp_ptr+1

        ; Feed decrypted bytes into the TCP ring buffer.
        ; Ring is 1024 bytes with 16-bit masked head/tail. We compute the
        ; destination absolute address per-byte via SMC on @feed_store.
        ldy #0
@feed_loop:
        cpy tls_app_len         ; low byte only (TLS records < 256)
        beq @feed_done
        lda (zp_ptr),y
        pha
        ; dest = tcp_recv_buf + tail
        clc
        lda tcp_recv_tail+0
        adc #<tcp_recv_buf
        sta @feed_store+1
        lda tcp_recv_tail+1
        adc #>tcp_recv_buf
        sta @feed_store+2
        pla
@feed_store:
        sta $ffff               ; SMC: patched above
        ; tail = (tail + 1) & TCP_RECV_MASK
        inc tcp_recv_tail+0
        bne @feed_mask
        inc tcp_recv_tail+1
@feed_mask:
        lda tcp_recv_tail+1
        and #>(TCP_RECV_MASK)
        sta tcp_recv_tail+1
        iny
        bne @feed_loop          ; always branches (tls_app_len < 256)
@feed_done:
        ; Parse from ring buffer
        jsr http_recv_response
        bcc @recv_complete      ; C=0 means parsing complete
        ; Reset timeout counter on progress
        lda #0
        sta @recv_timeout
        sta @recv_timeout+1
        jmp @recv_loop

@recv_no_data:
        inc @recv_timeout
        bne @recv_loop
        inc @recv_timeout+1
        bne @recv_loop
        ; Timeout — accept whatever we have

@recv_complete:
        jsr tls_close
        jsr net_tcp_close
        clc
        rts

@recv_timeout: .word 0

@tls_error:
        jsr net_tcp_close
@error:
        sec
        rts

@close_error:
        jsr tls_close
        jsr net_tcp_close
        sec
        rts

; =============================================================================
; http_build_get - construct HTTP/1.1 GET request in http_req_buf
; Input: http_host_ptr/len, http_path_ptr/len
; Output: http_req_buf contains request, http_req_len = length
; Clobbers: A, X, Y, zp_ptr, zp_count
; =============================================================================
http_build_get:
        ; Initialise write cursor
        lda #0
        sta http_bg_idx

        ; --- "GET " (4 bytes) ---
        ldx #0
@cv_loop:
        lda http_get_verb,x
        stx http_bg_src          ; save source index
        ldx http_bg_idx
        sta http_req_buf,x
        inc http_bg_idx
        ldx http_bg_src
        inx
        cpx #4
        bne @cv_loop

        ; --- path (variable length, from pointer) ---
        lda http_path_ptr
        sta zp_ptr
        lda http_path_ptr+1
        sta zp_ptr+1
        lda http_path_len
        sta zp_count
        jsr bg_copy_indirect

        ; --- " HTTP/1.1\r\n" (11 bytes) ---
        ldx #0
@cv_ver:
        lda http_version,x
        stx http_bg_src
        ldx http_bg_idx
        sta http_req_buf,x
        inc http_bg_idx
        ldx http_bg_src
        inx
        cpx #11
        bne @cv_ver

        ; --- "Host: " (6 bytes) ---
        ldx #0
@cv_host_hdr:
        lda http_host_hdr,x
        stx http_bg_src
        ldx http_bg_idx
        sta http_req_buf,x
        inc http_bg_idx
        ldx http_bg_src
        inx
        cpx #6
        bne @cv_host_hdr

        ; --- hostname (variable length, from pointer) ---
        lda http_host_ptr
        sta zp_ptr
        lda http_host_ptr+1
        sta zp_ptr+1
        lda http_host_len
        sta zp_count
        jsr bg_copy_indirect

        ; --- \r\n after Host value (2 bytes) ---
        ldx #0
@cv_crlf1:
        lda http_crlf,x
        stx http_bg_src
        ldx http_bg_idx
        sta http_req_buf,x
        inc http_bg_idx
        ldx http_bg_src
        inx
        cpx #2
        bne @cv_crlf1

        ; --- "Connection: close\r\n" (19 bytes) ---
        ldx #0
@cv_conn:
        lda http_conn_hdr,x
        stx http_bg_src
        ldx http_bg_idx
        sta http_req_buf,x
        inc http_bg_idx
        ldx http_bg_src
        inx
        cpx #19
        bne @cv_conn

        ; --- final \r\n (2 bytes) ---
        ldx #0
@cv_crlf2:
        lda http_crlf,x
        stx http_bg_src
        ldx http_bg_idx
        sta http_req_buf,x
        inc http_bg_idx
        ldx http_bg_src
        inx
        cpx #2
        bne @cv_crlf2

        ; --- store total length ---
        lda http_bg_idx
        sta http_req_len
        lda #0
        sta http_req_len+1
        rts

; -----------------------------------------------------------------------------
; bg_copy_indirect - copy zp_count bytes from (zp_ptr) into http_req_buf
;   at offset http_bg_idx.  Advances http_bg_idx.
;   Clobbers: A, X, Y
; (Was a cheap local @copy_indirect under ACME; promoted to a module-local
;  label so it is reachable from http_build_get without scope games.)
; -----------------------------------------------------------------------------
bg_copy_indirect:
        ldy #0
@ci_loop:
        cpy zp_count
        beq @ci_done
        lda (zp_ptr),y
        ldx http_bg_idx
        sta http_req_buf,x
        inc http_bg_idx
        iny
        jmp @ci_loop
@ci_done:
        rts

; =============================================================================
; http_recv_response - receive and parse HTTP response (polling-based)
;
; Call repeatedly while C=1.  Returns C=0 when complete.
;
; State machine:
;   0 - reading status line
;   1 - skipping headers (looking for \r\n\r\n)
;   2 - reading body into http_resp_buf
;
; Output: http_status  = numeric status code (e.g. 200)
;         http_resp_buf = response body
;         http_resp_len = body length
;         C=0 complete, C=1 not done yet
; =============================================================================
http_recv_response:
        lda http_parse_state
        cmp #0
        beq @state_status
        cmp #1
        beq @jmp_headers
        jmp @state_body
@jmp_headers:
        jmp @state_headers

; ----- state 0: accumulate status line until \n -----
@state_status:
        jsr net_recv_byte
        bcc @status_have_data
        jmp @not_done           ; no data yet, try again later
@status_have_data:
        cmp #$0a                ; \n ?
        beq @parse_status_line
        ; accumulate into line buffer
        ldx http_line_idx
        cpx #31                 ; guard overflow
        bcs @state_status       ; drop bytes if line too long
        sta http_line_buf,x
        inc http_line_idx
        jmp @state_status       ; keep reading this call

@parse_status_line:
        ; Status line: "HTTP/1.1 200 OK\r\n"
        ; Digits at offsets 9, 10, 11
        ; Convert 3 ASCII digits to a 16-bit number in http_status
        ;   status = (d0-'0')*100 + (d1-'0')*10 + (d2-'0')
        lda http_line_buf+9     ; hundreds digit
        sec
        sbc #$30
        sta http_status+1       ; temp: hundreds
        ; multiply by 100: x*100 = x*64 + x*32 + x*4
        ; simpler: use a loop or lookup.  Use successive addition.
        tax
        lda #0
        sta http_status
        sta http_status+1
@mul100:
        cpx #0
        beq @add_tens
        clc
        lda http_status
        adc #100
        sta http_status
        lda http_status+1
        adc #0
        sta http_status+1
        dex
        jmp @mul100

@add_tens:
        lda http_line_buf+10    ; tens digit
        sec
        sbc #$30
        tax
@mul10:
        cpx #0
        beq @add_ones
        clc
        lda http_status
        adc #10
        sta http_status
        lda http_status+1
        adc #0
        sta http_status+1
        dex
        jmp @mul10

@add_ones:
        lda http_line_buf+11    ; ones digit
        sec
        sbc #$30
        clc
        adc http_status
        sta http_status
        lda http_status+1
        adc #0
        sta http_status+1

        ; advance to state 1 (skip headers). Fall through to @state_headers
        ; instead of returning — one http_recv_response call is dispatched
        ; per successfully decrypted TLS record, so returning here would
        ; defer all header parsing until the next TLS record arrived.  With
        ; the current UCI server the status line and the entire headers
        ; block fit inside the same TLS record, so we want to consume both
        ; within the same call.
        lda #1
        sta http_parse_state
        lda #0
        sta http_hdr_match
        jmp @state_headers

; ----- state 1: skip headers until \r\n\r\n -----
@state_headers:
        jsr net_recv_byte
        bcs @not_done
        ; We track a match index into the pattern \r\n\r\n
        ; Pattern bytes: $0d, $0a, $0d, $0a
        ldx http_hdr_match
        cpx #0
        bne @hm_check1
        ; expecting $0d
        cmp #$0d
        bne @hm_reset
        inc http_hdr_match
        jmp @state_headers
@hm_check1:
        cpx #1
        bne @hm_check2
        cmp #$0a
        bne @hm_reset
        inc http_hdr_match
        jmp @state_headers
@hm_check2:
        cpx #2
        bne @hm_check3
        cmp #$0d
        bne @hm_reset
        inc http_hdr_match
        jmp @state_headers
@hm_check3:
        ; idx == 3, expecting $0a
        cmp #$0a
        bne @hm_reset
        ; matched full \r\n\r\n -> body starts.  Fall through to
        ; @state_body in the same call so that any body bytes already in
        ; the ring from the current TLS record get consumed immediately.
        ; Returning @not_done here would strand the body bytes until the
        ; next TLS record arrived — and if the body was short enough to
        ; fit alongside the headers in one record (as in our 21 B local
        ; test) no further TLS record would come, so http_recv_response
        ; would stall in state 1 forever and http_get would spin until
        ; its poll-timeout gave up with http_resp_len == 0.
        lda #2
        sta http_parse_state
        lda #0
        sta http_resp_len
        sta http_resp_len+1
        jmp @state_body

@hm_reset:
        lda #0
        sta http_hdr_match
        jmp @state_headers

; ----- state 2: read body bytes -----
; RFC 7230 behaviour: we treat an empty ring as "body still arriving"
; (return @not_done, letting the caller poll for more TLS records) instead
; of declaring the response complete.  Only two events end body reads:
;   1. buffer full (512 B safety cap — http_resp_buf is 512 B), or
;   2. caller-side poll-timeout in http_get's @recv_loop (the caller gives
;      up after ~65 k empty ticks with no data).
; Previously this state treated "ring empty this instant" as "body done",
; which clipped the response to zero bytes whenever the HTTP response
; arrived in a second TLS record after the headers — a real situation
; under UCI because the server emits NewSessionTicket handshake records
; (app-key phase) ahead of the actual HTTP response record, so the very
; first post-handshake TLS record the parser sees contains only the
; status line + headers and the body lands in the next record.
@state_body:
        jsr net_recv_byte
        bcs @not_done           ; no byte right now -> poll more
        ; store byte using zp_ptr = http_resp_buf + http_resp_len
        pha                     ; save received byte
        clc
        lda #<http_resp_buf
        adc http_resp_len
        sta zp_ptr
        lda #>http_resp_buf
        adc http_resp_len+1
        sta zp_ptr+1
        pla                     ; restore byte
        ldy #0
        sta (zp_ptr),y
        ; increment 16-bit length
        inc http_resp_len
        bne @body_check_full
        inc http_resp_len+1
@body_check_full:
        ; check if buffer full (512 bytes = $0200)
        lda http_resp_len+1
        cmp #$02
        bcs @done               ; high byte >= 2 means >= 512
        jmp @state_body         ; keep reading

@not_done:
        sec
        rts
@done:
        clc
        rts

; =============================================================================
; http_get_plain - perform a plain HTTP (no TLS) GET request
; Input: http_host_ptr/http_host_len = hostname
;        http_path_ptr/http_path_len = path
;        http_port = port (typically 80)
; Output: C=0 success (response in http_resp_buf), C=1 failure
; =============================================================================
http_get_plain:
        ; --- 1. DNS resolve hostname ---
        lda http_host_ptr
        ldx http_host_ptr+1
        jsr net_dns_resolve
        bcs @plain_error

        ; --- 2. TCP connect on http_port ---
        lda http_port
        ldx http_port+1
        jsr net_tcp_connect
        bcs @plain_error

        ; --- 4. Build GET request ---
        jsr http_build_get

        ; --- 5. Send request ---
        lda http_req_len
        sta net_send_len
        lda http_req_len+1
        sta net_send_len+1
        lda #<http_req_buf
        ldx #>http_req_buf
        jsr net_tcp_send
        bcs @plain_close_err

        ; --- 6. Initialise response parser ---
        lda #0
        sta http_parse_state
        sta http_line_idx
        sta http_hdr_match
        sta http_resp_len
        sta http_resp_len+1

        ; --- 7. Poll + parse loop (with timeout) ---
        lda #0
        sta @poll_timeout
        sta @poll_timeout+1
@plain_poll:
        jsr net_poll
        jsr http_recv_response
        bcc @plain_done         ; C=0 means complete
        ; reset timeout on any progress (data was consumed)
        inc @poll_timeout
        bne @plain_poll
        inc @poll_timeout+1
        bne @plain_poll
        ; timeout: accept whatever we got so far
@plain_done:

        ; --- 8. Close TCP ---
        jsr net_tcp_close
        clc
        rts

@poll_timeout: .word 0

@plain_close_err:
        jsr net_tcp_close
@plain_error:
        sec
        rts

; =============================================================================
; HTTP request/response string constants
; =============================================================================
        .segment "RODATA"

http_get_verb:
        .byte "GET "
http_version:
        .byte " HTTP/1.1", $0d, $0a
http_host_hdr:
        .byte "Host: "
http_conn_hdr:
        .byte "Connection: close", $0d, $0a
http_crlf:
        .byte $0d, $0a

; =============================================================================
; Module-local scratch (build_get temporaries only; parser state is in
; data.asm). These were ACME `!byte 0` slots; under ca65 they live in the
; zero-initialised BSS segment.
; =============================================================================
        .segment "BSS"

http_bg_idx:    .res 1          ; build_get write cursor
http_bg_src:    .res 1          ; build_get source index temp
