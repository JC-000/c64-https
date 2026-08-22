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
        .export http_recv_body
        .export http_recv_response
        .export http_get_plain
        .export http_get_verb
        .export http_version
        .export http_host_hdr
        .export http_conn_hdr
        .export http_ua_hdr
        .export http_crlf
        .export http_bg_idx
        .export http_bg_src
        ; W4 body-termination fix (see @state_body / HTTP_AUX_CODE):
        .export http_body_append
        .export http_in_mode
        .export http_in_ptr
        .export http_in_len
        ; W4 chunked transfer-decoding (see http_chunk_dispatch):
        .export http_te_chunked
        .export http_chunk_rem

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
        .import http_content_length
        .import http_cl_valid
        .import http_body_total

        ; ---- imports: data.asm BSS (TLS app data) ----
        ; (tcp_recv_head/tail imports dropped in the issue #72 redesign —
        ; the parser no longer touches the ciphertext ring on the TLS
        ; path; ring access is via net_recv_byte on the plain path only.)
        .import tls_app_ptr
        .import tls_app_len

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
        ; Extracted to http_recv_body (issue #72) so the boot.s HTTPS demo
        ; can share the exact production receive/parse path instead of its
        ; old first-record-only copy loop. Closes stay here: the demo does
        ; its own close sequence with progress prints.
        jsr http_recv_body

        jsr tls_close
        jsr net_tcp_close
        clc
        rts

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
; http_recv_body - receive + parse the HTTP response over TLS
;
; The production receive path shared by http_get and the boot.s HTTPS demo.
; Polls the network and hands each decrypted TLS application record to
; http_recv_response as a linear span (status line + headers + body with
; Content-Length termination). Plaintext never touches the TCP ring —
; see the span-input comment at the record handoff below.
;
; Input:  TLS session established, request already sent
; Output: C=0; http_status / http_resp_buf (body) / http_resp_len populated.
;         Returns on parse-complete OR on the poll-timeout fallback
;         ("accept whatever we have" — preserves the historical http_get
;         behaviour for chunked/streaming responses with no Content-Length).
;         Caller closes the connection.
; Clobbers: A, X, Y, zp_ptr
; =============================================================================
http_recv_body:
        ; Initialise parser state. http_content_length / _known are reset
        ; at the status-line -> headers transition (see @parse_status_line).
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

        ; Got decrypted data in tls_app_ptr / tls_app_len.
        ; Hand the decrypted record to the parser as a linear span
        ; (issue #72 redesign). The historical approach fed plaintext
        ; back into the shared TCP ring, which breaks whenever ciphertext
        ; for later records (body record #2, the peer's close_notify) is
        ; already queued between head and tail — on ip65 the rx callback
        ; queues eagerly, so the parser ate ciphertext as HTTP text
        ; (garbage http_status) or lost the body to a discard. Span input
        ; keeps the ring pure ciphertext: no feed, no discard, and
        ; multi-record bodies parse correctly on both backends.
        lda tls_app_ptr
        sta http_in_ptr
        lda tls_app_ptr+1
        sta http_in_ptr+1
        lda tls_app_len
        sta http_in_len
        lda tls_app_len+1
        sta http_in_len+1
        lda #1
        sta http_in_mode        ; input mode 1: parser reads this span
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
        clc
        rts

@recv_timeout: .word 0

; =============================================================================
; http_in_byte - fetch the next input byte for http_recv_response
;
; Dual-source input (issue #72): the parser is shared between the plain
; HTTP path (input = the TCP ring, which holds plaintext there) and the
; TLS path (input = the current decrypted record span; plaintext must
; NEVER be fed through the ciphertext ring — see http_recv_body).
;
; http_in_mode: 0 = ring (delegates to net_recv_byte)
;               1 = span (http_in_ptr / http_in_len, 16-bit)
; Output: C=0 + byte in A, or C=1 = input exhausted.
; Preserves X, Y (matches net_recv_byte's contract).
; =============================================================================
http_in_byte:
        lda http_in_mode
        beq @ring               ; mode 0: plain path reads the ring
        ; span mode: exhausted?
        lda http_in_len
        ora http_in_len+1
        beq @span_empty
        ; SMC-patch the load address (module convention: no-ZP, the
        ; parser's body state owns zp_ptr)
        lda http_in_ptr
        sta @in_ld+1
        lda http_in_ptr+1
        sta @in_ld+2
@in_ld: lda $ffff               ; SMC: patched above
        pha
        inc http_in_ptr
        bne :+
        inc http_in_ptr+1
:       lda http_in_len
        bne :+
        dec http_in_len+1
:       dec http_in_len
        pla
        clc
        rts
@span_empty:
        sec
        rts
@ring:
        jmp net_recv_byte

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

        ; --- "User-Agent: c64-https/0.1\r\n" (27 bytes) ---
        ; Wikipedia's robot policy 403s a UA-less request (measured live,
        ; lane H recon 2026-08-21); a short honest UA gets a 200.
        ldx #0
@cv_ua:
        lda http_ua_hdr,x
        stx http_bg_src
        ldx http_bg_idx
        sta http_req_buf,x
        inc http_bg_idx
        ldx http_bg_src
        inx
        cpx #27
        bne @cv_ua

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
        cmp #2
        beq @jmp_body
        jmp http_chunk_dispatch ; states 3..6: chunked transfer-decoding
@jmp_body:
        jmp @state_body
@jmp_headers:
        jmp @state_headers

; ----- state 0: accumulate status line until \n -----
@state_status:
        jsr http_in_byte
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
        sta http_line_idx
        ; Content-Length is "absent until seen": http_cl_valid = 0.  The
        ; historical $FFFF magic sentinel went away with the 24-bit
        ; Content-Length extension — a separate valid-flag byte cannot
        ; collide with any real length value.  Transfer-Encoding likewise
        ; resets to "not chunked".
        sta http_cl_valid
        sta http_te_chunked
        jmp @state_headers

; ----- state 1: read header lines into http_line_buf until an empty line -----
; Each header line is accumulated (CR stripped) and on LF we call
; check_content_length to pick up Content-Length.  An empty accumulated
; line (idx == 0 on LF) signals end-of-headers (the \r\n\r\n terminator).
; This replaces the earlier 4-byte \r\n\r\n pattern matcher — one state
; machine is smaller than two running in parallel.
@state_headers:
        jsr http_in_byte
        bcc @hdr_got_byte
        jmp @not_done
@hdr_got_byte:
        cmp #$0a                ; LF ends a line
        beq @hl_eol
        cmp #$0d                ; CR is discarded
        beq @state_headers
        ldx http_line_idx
        cpx #31                 ; cap buffer at 31 bytes (32-byte buf)
        bcs @state_headers
        sta http_line_buf,x
        inc http_line_idx
        jmp @state_headers

@hl_eol:
        lda http_line_idx
        beq @hdr_end            ; empty line -> end of headers
        jsr check_header_line   ; Content-Length + Transfer-Encoding
        lda #0
        sta http_line_idx
        jmp @state_headers
@hdr_end:
        ; Transition to state 2.  Body bytes that share this TLS record
        ; will be consumed in the same http_recv_response call by the
        ; fallthrough below — returning @not_done here would strand a
        ; short body until the next record, and for a response that
        ; fits entirely in one record no further record ever arrives.
        jsr http_body_begin     ; zero counters + pick body state:
                                ;   2 = identity, 3 = chunked
        jmp http_recv_response  ; re-dispatch into the selected state

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
        ; W4 termination fix: terminate on body bytes CONSUMED, not
        ; stored.  The old check compared http_resp_len against
        ; Content-Length, but resp_len freezes at the 512 B buffer cap,
        ; so for any body > 512 B the Content-Length match could never
        ; fire and only the connection-close / poll-timeout fallback
        ; ended the read — against a server that holds the connection
        ; open (observed live: browserleaks.com), http_get never
        ; returned.  http_body_total (24-bit, HTTP_AUX_CODE routines)
        ; now counts every consumed byte; bytes past the 512 B cap are
        ; consumed and discarded instead of ending the parse.
        jsr http_body_done_check
        bcc @body_done          ; C=0 -> body complete
        jsr http_in_byte
        bcs @not_done           ; no byte right now -> poll more
        jsr http_body_append    ; count + store/sink the byte
        jmp @state_body         ; keep reading (re-checks termination)

@body_done:
        jmp @done

@not_done:
        sec
        rts
@done:
        clc
        rts

; =============================================================================
; check_content_length - inspect http_line_buf[0..http_line_idx) for the
;   header  "Content-Length: <digits>"  (case-insensitive on the name, a
;   single SP after the colon).  On match, the decimal value is stored in
;   http_content_length (24-bit little-endian — real-server bodies exceed
;   64 KB) and http_cl_valid is set to 1.  No-op otherwise (http_cl_valid
;   stays 0 from the status-line reset).
;   Clobbers: A, X, Y, zp_ptr, zp_temp
;
; Lives in the HTTP_AUX_CODE segment (reachable via JSR from CODE in
; LOADER): the W4 24-bit extension no longer fits the packed
; LOADER_OVERFLOW/NET_CODE tail on either backend, so the whole W4 HTTP
; body machinery rides a dedicated segment — LOADER slack under UCI,
; CRYPTO_OVERLAY under ip65 (see the cfgs).
; =============================================================================
        .segment "HTTP_AUX_CODE"
check_content_length:
        ; Need at least len("content-length: ") = 16 bytes in the line.
        lda http_line_idx
        cmp #16
        bcs :+                  ; line too short -> no-op
        rts
:
        ; Case-insensitive compare against lowercase pattern.  Each line
        ; byte is OR'd with $20, which folds A..Z to a..z and leaves ':'
        ; and ' ' unchanged.
        ldx #15
@ccl_cmp:
        lda http_line_buf,x
        ora #$20
        cmp cl_pattern,x
        beq :+
        rts                     ; name mismatch -> no-op
:       dex
        bpl @ccl_cmp
        ; Matched.  Zero the accumulator, mark the header seen, and parse
        ; digits starting at idx 16.
        lda #0
        sta http_content_length
        sta http_content_length+1
        sta http_content_length+2
        lda #1
        sta http_cl_valid
        ldx #16
@ccl_digit_loop:
        ; (branch-inverted exits: the 24-bit loop body outgrew the
        ;  127-byte relative-branch reach to @ccl_rts)
        cpx http_line_idx
        bcc :+
        jmp @ccl_rts
:       lda http_line_buf,x
        cmp #$30                ; '0'
        bcs :+
        jmp @ccl_rts
:       cmp #$3a                ; '9'+1
        bcc :+
        jmp @ccl_rts
:       sec
        sbc #$30                ; A = digit 0..9
        pha
        ; old *= 10  =  old*8 + old*2 (need THREE ASLs to reach *8; tmp
        ; holds *2 after the first shift).  24-bit: tmp = zp_ptr(2)+zp_temp.
        asl http_content_length
        rol http_content_length+1
        rol http_content_length+2
        lda http_content_length
        sta zp_ptr              ; tmp = old*2
        lda http_content_length+1
        sta zp_ptr+1
        lda http_content_length+2
        sta zp_temp
        asl http_content_length
        rol http_content_length+1
        rol http_content_length+2
        asl http_content_length
        rol http_content_length+1
        rol http_content_length+2
        clc
        lda http_content_length
        adc zp_ptr
        sta http_content_length
        lda http_content_length+1
        adc zp_ptr+1
        sta http_content_length+1
        lda http_content_length+2
        adc zp_temp
        sta http_content_length+2
        pla
        clc
        adc http_content_length
        sta http_content_length
        bcc @ccl_nc
        inc http_content_length+1
        bne @ccl_nc
        inc http_content_length+2
@ccl_nc:
        inx
        jmp @ccl_digit_loop
@ccl_rts:
        rts

; Lowercase "content-length: " — each incoming header byte is OR'd with
; $20 before compare, which folds A..Z to a..z and leaves ':' and ' '
; unchanged.  The trailing SP is part of the match so we don't need a
; separate whitespace-skip loop.
cl_pattern:
        .byte "content-length: "

; =============================================================================
; http_body_begin - reset per-response body state at the end-of-headers
;   transition and select the body parse state: 2 (identity) normally,
;   3 (chunk-size line) when a Transfer-Encoding: chunked header was
;   seen.  Living here (not in the recv-loop inits) guarantees the reset
;   runs on every parse walk regardless of entry path (http_recv_body,
;   http_get_plain, or a test driving http_recv_response directly).
;   Clobbers: A
; =============================================================================
http_body_begin:
        lda #0
        sta http_resp_len
        sta http_resp_len+1
        sta http_body_total
        sta http_body_total+1
        sta http_body_total+2
        sta http_chunk_rem
        sta http_chunk_rem+1
        sta http_chunk_skip
        lda http_te_chunked
        beq @identity
        lda #3                  ; chunked: start at the chunk-size line
        sta http_parse_state
        rts
@identity:
        lda #2
        sta http_parse_state
        rts

; =============================================================================
; check_header_line - run all per-header-line matchers on the line
;   accumulated in http_line_buf.  Called once per non-empty header
;   line from @hl_eol.
;   Clobbers: A, X, Y, zp_ptr, zp_temp
; =============================================================================
check_header_line:
        jsr check_content_length
        ; fall through to check_transfer_encoding

; =============================================================================
; check_transfer_encoding - match "Transfer-Encoding: chunked" (case-
;   insensitive name and value, single SP after the colon — the same
;   shape check_content_length matches).  Sets http_te_chunked = 1 on
;   match.  A prefix match suffices: "chunked" is by spec the final
;   coding, and Wikipedia (the stretch-goal target) sends exactly this
;   line.
;   Clobbers: A, X
; =============================================================================
check_transfer_encoding:
        lda http_line_idx
        cmp #26                 ; len("transfer-encoding: chunked")
        bcs :+
        rts
:       ldx #25
@cte_cmp:
        lda http_line_buf,x
        ora #$20
        cmp te_pattern,x
        beq :+
        rts
:       dex
        bpl @cte_cmp
        lda #1
        sta http_te_chunked
        rts

; Lowercase pattern; incoming bytes are OR'd with $20 (folds A..Z,
; leaves '-', ':', ' ' unchanged).
te_pattern:
        .byte "transfer-encoding: chunked"

; =============================================================================
; http_body_done_check - is the body complete?
;   C=0 -> complete; C=1 -> keep reading.
;
;   Content-Length seen (http_cl_valid=1): complete exactly when the
;     24-bit consumed count http_body_total equals http_content_length.
;     Works whether or not the stored copy was truncated at 512 B —
;     that is the W4 fix.
;   Content-Length absent: legacy behaviour — the 512 B buffer cap ends
;     the read (chunked/streaming fallback preserved).
;   Clobbers: A
; =============================================================================
http_body_done_check:
        lda http_cl_valid
        beq @no_cl
        lda http_body_total
        cmp http_content_length
        bne @more
        lda http_body_total+1
        cmp http_content_length+1
        bne @more
        lda http_body_total+2
        cmp http_content_length+2
        bne @more
        clc
        rts
@no_cl:
        lda http_resp_len+1
        cmp #$02
        bcs @full               ; high byte >= 2 means >= 512
@more:
        sec
        rts
@full:
        clc
        rts

; =============================================================================
; http_body_append - consume one body byte (in A).
;
;   Always increments the 24-bit http_body_total (bytes CONSUMED).
;   Stores into http_resp_buf while resp_len < 512; bytes past the cap
;   are counted and discarded.
;   Clobbers: A, Y, zp_ptr.  Preserves X.
; =============================================================================
http_body_append:
        pha
        ; http_body_total++ (24-bit)
        inc http_body_total
        bne @stored_count
        inc http_body_total+1
        bne @stored_count
        inc http_body_total+2
@stored_count:
        ; room in http_resp_buf?  (resp_len < 512)
        lda http_resp_len+1
        cmp #$02
        bcs @discard            ; buffer-mode overflow: count only
        ; store byte at http_resp_buf + resp_len
        clc
        lda #<http_resp_buf
        adc http_resp_len
        sta zp_ptr
        lda #>http_resp_buf
        adc http_resp_len+1
        sta zp_ptr+1
        pla
        ldy #0
        sta (zp_ptr),y
        inc http_resp_len
        bne @rts
        inc http_resp_len+1
@rts:
        rts
@discard:
        pla                     ; byte counted, not stored
        rts

; =============================================================================
; Chunked transfer-decoding (RFC 7230 §4.1).  Wikipedia — the stretch-
; goal target — serves the article chunked with NO Content-Length
; (measured live 2026-08-21: 4 data chunks of 26,931-32,768 B, body
; 125,235 B), so on that path the terminal 0-chunk is the termination
; signal, not a Content-Length match.
;
; parse_state values (3..6 dispatch here from http_recv_response):
;   3 - chunk-size line: hex digits, optional ";extension" skipped,
;       terminated by LF
;   4 - chunk payload: http_chunk_rem bytes handed to http_body_append
;   5 - the CRLF that closes a chunk's payload
;   6 - trailer section after the 0-chunk: lines until an empty one,
;       then the body is complete (C=0)
;
; Only payload bytes (state 4) reach http_body_append, so
; http_body_total counts de-chunked payload — never framing — and the
; http_resp_buf first-512 / REU-sink contracts hold unchanged.
;
; http_chunk_rem is 16-bit: chunks >= 64 KB would mis-parse, but no
; observed server sends them (Wikipedia's max is 32,768 B) and RFC 7230
; sets no minimum chunking granularity a client may rely on.
;
; Lives in its own HTTP_CHUNK_CODE segment: CRYPTO_RESIDENT slack under
; ip65 (CRYPTO_OVERLAY is full there once HTTP_AUX_CODE lands),
; CRYPTO_OVERLAY under UCI.
; =============================================================================
        .segment "HTTP_CHUNK_CODE"
http_chunk_dispatch:
        lda http_parse_state
        cmp #4
        bcc @st_size            ; state 3
        beq @jd_data            ; state 4
        cmp #5
        bne @jd_trailer         ; state 6+
        jmp @st_crlf            ; state 5
@jd_data:
        jmp @st_data
@jd_trailer:
        jmp @st_trailer

@not_done:                      ; near exit for the early states (the
        sec                     ; machine outgrew one branch's reach)
        rts

; ----- state 3: chunk-size line -----
@st_size:
        jsr http_in_byte
        bcs @not_done
        cmp #$0a                ; LF ends the size line
        beq @size_eol
        ldy http_chunk_skip
        bne @st_size            ; already skipping extension/junk
        cmp #$0d                ; CR discarded
        beq @st_size
        jsr chunk_hex_digit
        bcs @size_ext           ; not a hex digit: ";ext" etc.
        ; http_chunk_rem = rem*16 + digit
        asl http_chunk_rem
        rol http_chunk_rem+1
        asl http_chunk_rem
        rol http_chunk_rem+1
        asl http_chunk_rem
        rol http_chunk_rem+1
        asl http_chunk_rem
        rol http_chunk_rem+1
        ora http_chunk_rem
        sta http_chunk_rem
        jmp @st_size
@size_ext:
        inc http_chunk_skip     ; ignore the rest of the line (reached at
        jmp @st_size            ;  most once per line: the skip check above
                                ;  short-circuits every later byte)
@size_eol:
        lda #0
        sta http_chunk_skip
        lda http_chunk_rem
        ora http_chunk_rem+1
        beq @last_chunk
        lda #4
        sta http_parse_state
        jmp @st_data
@last_chunk:
        lda #6                  ; 0-chunk -> trailer section
        sta http_parse_state
        lda #0
        sta http_line_idx       ; trailer-line char count
        jmp @st_trailer

; ----- state 4: chunk payload -----
@st_data:
        lda http_chunk_rem
        ora http_chunk_rem+1
        beq @data_done
        jsr http_in_byte
        bcs @not_done2
        jsr http_body_append    ; count + store/sink (payload bytes only)
        lda http_chunk_rem
        bne :+
        dec http_chunk_rem+1
:       dec http_chunk_rem
        jmp @st_data
@data_done:
        lda #5
        sta http_parse_state
        ; fall through into the CRLF eater

; ----- state 5: CRLF closing the chunk payload -----
@st_crlf:
        jsr http_in_byte
        bcs @not_done2
        cmp #$0a
        bne @st_crlf            ; eat the CR (and tolerate junk) until LF
        lda #3                  ; next chunk-size line (rem is 0 — state 4
        sta http_parse_state    ;  counted it down — and skip is 0 too, so
        jmp @st_size            ;  the size parser starts fresh)

; ----- state 6: trailer lines until an empty one -----
@st_trailer:
        jsr http_in_byte
        bcs @not_done2
        cmp #$0d
        beq @st_trailer         ; CR never counts toward the line
        cmp #$0a
        beq @tr_eol
        inc http_line_idx
        jmp @st_trailer
@tr_eol:
        lda http_line_idx
        beq @tr_done            ; empty line -> body complete
        lda #0
        sta http_line_idx
        jmp @st_trailer
@tr_done:
        clc
        rts

@not_done2:                     ; far exit for the late states
        sec
        rts

; -----------------------------------------------------------------------------
; chunk_hex_digit - ASCII hex digit in A -> C=0 + A=0..15, else C=1
;   (case-insensitive).  Clobbers: A.
; Rides HTTP_AUX_CODE (jsr'd from the chunk machine): the ip65-onchip
; profile's CRYPTO_RESIDENT is too tight for it to sit with
; HTTP_CHUNK_CODE.
; -----------------------------------------------------------------------------
        .segment "HTTP_AUX_CODE"
chunk_hex_digit:
        cmp #$30                ; '0'
        bcc @nothex
        cmp #$3a                ; '9'+1
        bcs @alpha
        and #$0f
        clc
        rts
@alpha:
        ora #$20                ; fold A-F to a-f
        cmp #$61                ; 'a'
        bcc @nothex
        cmp #$67                ; 'f'+1
        bcs @nothex
        sec
        sbc #$57                ; 'a' ($61) -> 10
        clc
        rts
@nothex:
        sec
        rts

; =============================================================================
; http_get_plain - perform a plain HTTP (no TLS) GET request
; Input: http_host_ptr/http_host_len = hostname
;        http_path_ptr/http_path_len = path
;        http_port = port (typically 80)
; Output: C=0 success (response in http_resp_buf), C=1 failure
; =============================================================================
        .segment "CODE"
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
        ; (Content-Length state is reset at the status-line -> headers
        ; transition — see @parse_status_line.)
        lda #0
        sta http_parse_state
        sta http_line_idx
        sta http_hdr_match
        sta http_resp_len
        sta http_resp_len+1
        sta http_in_mode        ; input mode 0: parser reads the TCP ring
                                ; (plain HTTP — ring holds plaintext)

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
http_ua_hdr:
        .byte "User-Agent: c64-https/0.1", $0d, $0a
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
; Parser input source (issue #72 span-input redesign — see http_in_byte)
http_in_mode:   .res 1          ; 0 = TCP ring (plain HTTP), 1 = span (TLS)
http_in_ptr:    .res 2          ; span read cursor
http_in_len:    .res 2          ; span bytes remaining (16-bit)
; Chunked transfer-decoding state (see http_chunk_dispatch)
http_te_chunked: .res 1         ; 1 = "Transfer-Encoding: chunked" seen
http_chunk_rem: .res 2          ; 16-bit payload bytes left in this chunk
http_chunk_skip: .res 1         ; 1 = skipping rest of the chunk-size line
