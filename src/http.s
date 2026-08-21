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
        .import http_content_length

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
        jmp http_state_body
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
        ; Reset the per-response header-derived state (Content-Length
        ; sentinel to $FFFF "unknown", chunked flag + chunk parser state
        ; to 0).  Lives in HTTP_AUX_CODE — LOADER is packed on ip65.
        jsr http_hdr_init
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
        jsr check_content_length
        jsr check_transfer_encoding
        lda #0
        sta http_line_idx
        jmp @state_headers
@hdr_end:
        ; Transition to state 2.  Body bytes that share this TLS record
        ; will be consumed in the same http_recv_response call by the
        ; fallthrough below — returning @not_done here would strand a
        ; short body until the next record, and for a response that
        ; fits entirely in one record no further record ever arrives.
        lda #2
        sta http_parse_state
        lda #0
        sta http_resp_len
        sta http_resp_len+1
        jmp http_state_body

@not_done:
        sec
        rts

; =============================================================================
; W4: body state + chunked-transfer support.
;
; Everything below lives in HTTP_AUX_CODE, NOT in CODE: the ip65
; LOADER region is packed (8 B free pre-W4), so the body-state handler
; was moved out of CODE and the chunked machinery added alongside it.
; The segment maps to LOADER under UCI (588 B free) and to the
; resident CRYPTO_OVERLAY slot under ip65 (see the cfgs).
; =============================================================================
        .segment "HTTP_AUX_CODE"

; -----------------------------------------------------------------------------
; http_hdr_init - reset per-response header-derived parser state.
; Called at the status-line -> headers transition.
; -----------------------------------------------------------------------------
http_hdr_init:
        ; Content-Length sentinel $FFFF = "unknown"
        lda #$ff
        sta http_content_length
        sta http_content_length+1
        lda #0
        sta http_chunked
        sta http_chunk_state
        sta http_chunk_rem
        sta http_chunk_rem+1
        rts

; -----------------------------------------------------------------------------
; check_transfer_encoding - inspect http_line_buf[0..http_line_idx) for
;   "Transfer-Encoding: chunked" (case-insensitive, single SP after the
;   colon — mirrors check_content_length).  Sets http_chunked=1 on match.
;   Lenient on trailing bytes: real servers send exactly "chunked".
;   Clobbers: A, X
; -----------------------------------------------------------------------------
check_transfer_encoding:
        lda http_line_idx
        cmp #26                 ; len("transfer-encoding: chunked")
        bcc @cte_rts
        ldx #25
@cte_cmp:
        lda http_line_buf,x
        ora #$20                ; fold A..Z -> a..z (':',' ','-' unchanged)
        cmp te_pattern,x
        bne @cte_rts
        dex
        bpl @cte_cmp
        lda #1
        sta http_chunked
@cte_rts:
        rts

te_pattern:
        .byte "transfer-encoding: chunked"

; -----------------------------------------------------------------------------
; body_append - append byte in A to http_resp_buf if there is room.
;   http_resp_buf is 512 B; once http_resp_len reaches 512 the byte is
;   discarded and the length no longer advances (truncate-at-capacity:
;   http_resp_len reports the captured prefix length).
;   Clobbers: A, Y, zp_ptr.  Preserves X.
; -----------------------------------------------------------------------------
body_append:
        ldy http_resp_len+1
        cpy #$02
        bcs @ba_full            ; >= 512: discard
        ; store byte at http_resp_buf + http_resp_len
        pha
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
        bne @ba_done
        inc http_resp_len+1
@ba_done:
@ba_full:
        rts

; -----------------------------------------------------------------------------
; hex_digit - convert ASCII hex digit in A to its value.
;   Output: C=0 + value 0..15 in A, or C=1 if A is not a hex digit.
;   Preserves X, Y.
; -----------------------------------------------------------------------------
hex_digit:
        cmp #'0'
        bcc @hd_no
        cmp #'9'+1
        bcc @hd_num
        ora #$20                ; fold A-F -> a-f
        cmp #'a'
        bcc @hd_no
        cmp #'f'+1
        bcs @hd_no
        sbc #'a'-11             ; C=0 here: A - ('a'-10)
        clc
        rts
@hd_num:
        and #$0f
        clc
        rts
@hd_no:
        sec
        rts

; ----- state 2: read body bytes -----
; RFC 7230 behaviour: we treat an empty input as "body still arriving"
; (return C=1, letting the caller poll for more TLS records) instead
; of declaring the response complete.  Termination events:
;   1. http_resp_len reaches Content-Length (identity encoding), or
;   2. the terminal chunk 0\r\n\r\n is consumed (chunked encoding), or
;   3. buffer full at 512 B (identity encoding only — chunked keeps
;      consuming/discarding so it can find the terminal chunk), or
;   4. caller-side poll-timeout in http_recv_body's @recv_loop (the
;      caller gives up after ~65 k empty ticks with no data — the
;      "accept whatever we have" fallback for responses with neither
;      Content-Length nor chunked framing; we send Connection: close,
;      so the peer's close ends those).
http_state_body:
        lda http_chunked
        beq @plain
        jmp http_state_body_chunked

@plain:
        ; Content-Length termination: http_content_length defaults to $FFFF
        ; ("unknown"), overwritten by check_content_length if the header
        ; was seen.  $FFFF will never match because the buffer-full check
        ; below bails at 512 bytes.  For a real Content-Length value we
        ; finish the instant resp_len matches — handles Content-Length: 0
        ; on entry and the post-append case below.
        lda http_resp_len
        cmp http_content_length
        bne @body_read
        lda http_resp_len+1
        cmp http_content_length+1
        beq @sb_done
@body_read:
        jsr http_in_byte
        bcs @sb_not_done        ; no byte right now -> poll more
        jsr body_append
        ; check if buffer full (512 bytes = $0200)
        lda http_resp_len+1
        cmp #$02
        bcs @sb_done            ; high byte >= 2 means >= 512
        jmp @plain              ; keep reading (also re-checks Content-Length)

@sb_not_done:
        sec
        rts
@sb_done:
        clc
        rts

; -----------------------------------------------------------------------------
; http_state_body_chunked - strip Transfer-Encoding: chunked framing.
;
; Sub-state in http_chunk_state:
;   0 = accumulating hex chunk-size digits (http_chunk_rem, 16-bit)
;   1 = skipping the rest of the size line (chunk extensions) until LF
;   2 = copying chunk payload (http_chunk_rem bytes) via body_append
;   3 = skipping the CRLF that follows chunk payload, until LF
;   4 = terminal chunk seen: skipping trailer lines; an empty line ends
;       the response (http_line_idx is reused as a line-nonempty flag —
;       header parsing is over, so the buffer index is free)
;
; A chunk larger than 65535 B would wrap http_chunk_rem and desync the
; framing; real servers chunk at their buffer size (8-32 KB).  A desync
; degrades to the caller's poll-timeout fallback, never to a hang.
; -----------------------------------------------------------------------------
http_state_body_chunked:
        jsr http_in_byte
        bcc @cb_have
        rts                     ; C=1 from http_in_byte: no data -> not done
@cb_have:
        ldx http_chunk_state
        beq @cs_size
        dex
        beq @cs_skip
        dex
        beq @cs_data
        dex
        beq @cs_crlf
        jmp @cs_final

@cs_size:
        cmp #$0a                ; LF ends the size line
        beq @size_eol
        jsr hex_digit
        bcs @to_skip            ; non-hex (CR, ';', extension) -> state 1
        ; http_chunk_rem = http_chunk_rem*16 + digit
        pha
        asl http_chunk_rem
        rol http_chunk_rem+1
        asl http_chunk_rem
        rol http_chunk_rem+1
        asl http_chunk_rem
        rol http_chunk_rem+1
        asl http_chunk_rem
        rol http_chunk_rem+1
        pla
        ora http_chunk_rem
        sta http_chunk_rem
        jmp http_state_body_chunked
@to_skip:
        lda #1
        sta http_chunk_state
        jmp http_state_body_chunked

@cs_skip:
        cmp #$0a
        bne @cb_loop
@size_eol:
        ; size line complete: 0 -> terminal chunk, else payload follows
        lda http_chunk_rem
        ora http_chunk_rem+1
        beq @final_enter
        lda #2
        sta http_chunk_state
        jmp http_state_body_chunked
@final_enter:
        lda #4
        sta http_chunk_state
        lda #0
        sta http_line_idx       ; trailer-line-nonempty flag
        jmp http_state_body_chunked

@cs_data:
        jsr body_append         ; append-if-room (discards past 512)
        ; 16-bit decrement of http_chunk_rem
        lda http_chunk_rem
        bne :+
        dec http_chunk_rem+1
:       dec http_chunk_rem
        lda http_chunk_rem
        ora http_chunk_rem+1
        bne @cb_loop
        lda #3
        sta http_chunk_state
        jmp http_state_body_chunked

@cs_crlf:
        cmp #$0a
        bne @cb_loop
        lda #0                  ; back to size parsing (rem is already 0)
        sta http_chunk_state
        jmp http_state_body_chunked

@cs_final:
        cmp #$0a
        beq @fin_eol
        cmp #$0d
        beq @cb_loop            ; CR ignored
        inc http_line_idx       ; trailer line has content
        jmp http_state_body_chunked
@fin_eol:
        lda http_line_idx
        beq @cb_done            ; empty line after terminal chunk -> done
        lda #0
        sta http_line_idx
@cb_loop:
        jmp http_state_body_chunked

@cb_done:
        clc
        rts

; =============================================================================
; check_content_length - inspect http_line_buf[0..http_line_idx) for the
;   header  "Content-Length: <digits>"  (case-insensitive on the name, a
;   single SP after the colon).  On match, the decimal value is stored in
;   http_content_length (16-bit) — which the caller pre-loaded with the
;   $FFFF "unknown" sentinel.  No-op otherwise.
;   Clobbers: A, X, Y
;
; Lives in the LOADER_OVERFLOW segment (reachable via JSR from CODE in
; LOADER) because the LOADER region is packed; see c64-https-ip65.cfg.
; =============================================================================
        .segment "LOADER_OVERFLOW"
check_content_length:
        ; Need at least len("content-length: ") = 16 bytes in the line.
        lda http_line_idx
        cmp #16
        bcc @ccl_rts            ; line too short -> no-op
        ; Case-insensitive compare against lowercase pattern.  Each line
        ; byte is OR'd with $20, which folds A..Z to a..z and leaves ':'
        ; and ' ' unchanged.
        ldx #15
@ccl_cmp:
        lda http_line_buf,x
        ora #$20
        cmp cl_pattern,x
        bne @ccl_rts
        dex
        bpl @ccl_cmp
        ; Matched.  Zero the accumulator and parse digits starting at idx 16.
        lda #0
        sta http_content_length
        sta http_content_length+1
        ldx #16
@ccl_digit_loop:
        cpx http_line_idx
        bcs @ccl_rts
        lda http_line_buf,x
        cmp #$30                ; '0'
        bcc @ccl_rts
        cmp #$3a                ; '9'+1
        bcs @ccl_rts
        sec
        sbc #$30                ; A = digit 0..9
        pha
        ; old *= 10  =  old*8 + old*2 (need THREE ASLs to reach *8; tmp
        ; holds *2 after the first shift).
        asl http_content_length
        rol http_content_length+1
        lda http_content_length
        sta zp_ptr              ; tmp_lo = old*2
        lda http_content_length+1
        sta zp_ptr+1            ; tmp_hi = old*2
        asl http_content_length
        rol http_content_length+1
        asl http_content_length
        rol http_content_length+1
        clc
        lda http_content_length
        adc zp_ptr
        sta http_content_length
        lda http_content_length+1
        adc zp_ptr+1
        sta http_content_length+1
        pla
        clc
        adc http_content_length
        sta http_content_length
        bcc @ccl_nc
        inc http_content_length+1
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
; Exported so tools/test_http.py can drive the parser in span mode,
; the same input mode the TLS path uses.
        .export http_in_mode
        .export http_in_ptr
        .export http_in_len
http_in_mode:   .res 1          ; 0 = TCP ring (plain HTTP), 1 = span (TLS)
http_in_ptr:    .res 2          ; span read cursor
http_in_len:    .res 2          ; span bytes remaining (16-bit)
; W4 chunked-transfer state (see http_state_body_chunked)
        .export http_chunked
        .export http_chunk_state
        .export http_chunk_rem
http_chunked:      .res 1       ; 1 = Transfer-Encoding: chunked seen
http_chunk_state:  .res 1       ; chunk parser sub-state (0..4)
http_chunk_rem:    .res 2       ; bytes remaining in current chunk
