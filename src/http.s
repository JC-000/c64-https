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
        ; W4 REU body sink (see HTTP_SINK_CODE; UCI-only — ip65 gets
        ; inert stubs, the backend cannot fit the sink and the knob is
        ; UCI-only anyway):
        .export http_body_finish
.ifdef BACKEND_UCI
        .export http_reu_body_base
        .export http_sink_blit
.endif

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
        ; W4 body-termination fix + REU sink state (src/data.s):
        .import http_cl_valid
        .import http_body_total
        .import http_body_sink
        .import http_reu_cursor
.ifndef USE_X25519_SIBLING
        .import mul_dma_lo      ; REU-latch restore in http_body_finish
.endif

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
        ; Sink finalize is idempotent (http_sink_flushed latch): on the
        ; parse-complete path it already ran inside http_recv_response;
        ; this call covers the poll-timeout fallback so a sink body cut
        ; short still gets its final blit + first-512 restore.
        jsr http_body_finish
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
        jsr http_body_begin     ; zero resp_len + consumed count + sink state
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
        ; Content-Length is "absent until seen": http_cl_valid = 0.  The
        ; historical $FFFF magic sentinel went away with the W4 24-bit
        ; Content-Length extension — a separate valid-flag byte cannot
        ; collide with any real length value.
        lda #0
        sta http_cl_valid
        sta http_chunked
        sta http_chunk_state
        sta http_chunk_rem
        sta http_chunk_rem+1
        rts

; -----------------------------------------------------------------------------
; http_body_begin - reset per-response body state at the end-of-headers
;   transition (headers -> state 2).  Living here (not in the recv-loop
;   inits) guarantees the reset runs on every parse walk regardless of
;   entry path (http_recv_body, http_get_plain, or a test driving
;   http_recv_response directly).
;   Clobbers: A
;
; HTTP_AUX_CODE2 (this routine + http_body_done_check + hex_digit):
; jsr-only helpers split out of HTTP_AUX_CODE because ip65's
; CRYPTO_OVERLAY cannot hold the whole W4 body machinery — this slice
; rides CRYPTO_RESIDENT there (CRYPTO_OVERLAY under UCI, same slot as
; the rest).
; -----------------------------------------------------------------------------
        .segment "HTTP_AUX_CODE2"
http_body_begin:
        lda #0
        sta http_resp_len
        sta http_resp_len+1
        sta http_body_total
        sta http_body_total+1
        sta http_body_total+2
        sta http_reu_cursor
        sta http_reu_cursor+1
        sta http_reu_cursor+2
        sta http_sink_flushed
        rts

; -----------------------------------------------------------------------------
; http_body_done_check - is the identity body complete?
;   C=0 -> complete; C=1 -> keep reading.  (The chunked path terminates
;   on the terminal chunk instead and never calls this.)
;
;   Content-Length seen (http_cl_valid=1): complete exactly when the
;     24-bit consumed count http_body_total equals http_content_length.
;     Works whether or not the stored copy was truncated at 512 B —
;     that is the W4 fix.
;   Content-Length absent: legacy behaviour — the 512 B buffer cap ends
;     the read in buffer mode (streaming fallback preserved); in sink
;     mode there is no cap and the caller's poll-timeout is the bound.
;   Clobbers: A
; -----------------------------------------------------------------------------
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
.ifdef BACKEND_UCI
        lda http_body_sink
        bne @more               ; sink mode: no 512 B cap
.endif
        lda http_resp_len+1
        cmp #$02
        bcs @full               ; high byte >= 2 means >= 512
@more:
        sec
        rts
@full:
        clc
        rts
        .segment "HTTP_AUX_CODE"

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

        ; (pattern rides HTTP_AUX_CODE2 with the other jsr-only/data
        ;  pieces — absolute indexed reads work cross-segment, and the
        ;  ip65 CRYPTO_OVERLAY is at capacity.)
        .segment "HTTP_AUX_CODE2"
te_pattern:
        .byte "transfer-encoding: chunked"
        .segment "HTTP_AUX_CODE"

; -----------------------------------------------------------------------------
; body_append - consume one body byte (in A).
;   Always increments the 24-bit http_body_total (bytes CONSUMED — this
;   is what the W4 termination fix compares against Content-Length, and
;   what the viewer reads as the de-chunked document length).
;   Buffer mode (http_body_sink=0): stores into http_resp_buf while
;     resp_len < 512; past the cap the byte is counted and discarded
;     (truncate-at-capacity: http_resp_len reports the captured prefix).
;   Sink mode (http_body_sink=1, BACKEND=uci): http_resp_buf is a 512 B
;     bounce buffer — on fill it is REU-DMA-blitted to
;     http_reu_body_base + http_reu_cursor and reused (HTTP_SINK_CODE).
;   Both the identity and chunked body paths feed every payload byte
;   (and only payload bytes) through here.
;   Clobbers: A, Y, zp_ptr.  Preserves X.
; -----------------------------------------------------------------------------
body_append:
        pha
        ; http_body_total++ (24-bit)
        inc http_body_total
        bne @ba_counted
        inc http_body_total+1
        bne @ba_counted
        inc http_body_total+2
@ba_counted:
        ldy http_resp_len+1
        cpy #$02
        bcs @ba_discard         ; >= 512 (buffer mode): count only
        ; store byte (still on the stack) at http_resp_buf + http_resp_len
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
        bne @ba_check_sink
        inc http_resp_len+1
@ba_check_sink:
.ifdef BACKEND_UCI
        lda http_body_sink
        beq @ba_done
        lda http_resp_len+1     ; sink mode: bounce full at 512?
        cmp #$02
        bcc @ba_done
        jsr http_sink_blit      ; blit the bounce, advance the cursor
        lda #0                  ; reuse the bounce buffer
        sta http_resp_len
        sta http_resp_len+1
.endif
@ba_done:
        rts
@ba_discard:
        pla                     ; byte counted, not stored
        rts

; -----------------------------------------------------------------------------
; hex_digit - convert ASCII hex digit in A to its value.
;   Output: C=0 + value 0..15 in A, or C=1 if A is not a hex digit.
;   Preserves X, Y.
;   (HTTP_AUX_CODE2 — see the http_body_begin header for the split.)
; -----------------------------------------------------------------------------
        .segment "HTTP_AUX_CODE2"
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
        .segment "HTTP_AUX_CODE"

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
        ; W4 termination fix: terminate on body bytes CONSUMED, not
        ; stored.  The old check compared http_resp_len against
        ; Content-Length, but resp_len freezes at the 512 B buffer cap,
        ; so for any identity body > 512 B the Content-Length match
        ; could never fire and only the connection-close / poll-timeout
        ; fallback ended the read — against a server that holds the
        ; connection open (observed live: browserleaks.com), http_get
        ; never returned.  http_body_done_check compares the 24-bit
        ; consumed count http_body_total against the 24-bit
        ; Content-Length (http_cl_valid replaces the $FFFF sentinel);
        ; bytes past the 512 B cap are consumed and discarded (or
        ; streamed to the REU under http_body_sink=1) instead of
        ; ending the parse.
        jsr http_body_done_check
        bcc @sb_done_fin        ; C=0 -> body complete
        jsr http_in_byte
        bcs @sb_not_done        ; no byte right now -> poll more
        jsr body_append         ; count + store/sink the byte
        jmp @plain              ; keep reading (re-checks termination)

@sb_done_fin:
        jmp sink_finish_done    ; sink finalize (no-op in buffer mode), C=0
@sb_not_done:
        sec
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
        jmp sink_finish_done    ; sink finalize (no-op in buffer mode), C=0

; =============================================================================
; check_content_length - inspect http_line_buf[0..http_line_idx) for the
;   header  "Content-Length: <digits>"  (case-insensitive on the name, a
;   single SP after the colon).  On match, the decimal value is stored in
;   http_content_length (24-bit little-endian — real-server bodies exceed
;   64 KB) and http_cl_valid is set to 1.  No-op otherwise (http_cl_valid
;   stays 0 from the http_hdr_init reset).
;   Clobbers: A, X, Y, zp_ptr, zp_temp
;
; W4: moved from LOADER_OVERFLOW to HTTP_AUX_CODE — the 24-bit extension
; outgrew the packed NET_CODE tail; the vacated LOADER_OVERFLOW bytes
; are slack again.
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
; separate whitespace-skip loop.  (HTTP_AUX_CODE2 — see te_pattern.)
        .segment "HTTP_AUX_CODE2"
cl_pattern:
        .byte "content-length: "

; =============================================================================
; W4 REU body sink (HTTP_SINK_CODE segment: NET_CODE tail under ip65,
; CRYPTO_OVERLAY under UCI).
;
; With http_body_sink = 1, http_resp_buf acts as a 512 B bounce buffer:
; body_append fills it, and each time it fills http_sink_blit
; REU-DMA-STASHes the whole bounce to http_reu_body_base +
; http_reu_cursor and resets it.  At completion http_body_finish blits
; the final partial bounce, then re-FETCHes the FIRST min(512, total)
; body bytes from the REU back into http_resp_buf — the host-side
; verification contract: after a sunk body, http_resp_buf holds the
; first 512 body bytes, http_resp_len = min(512, total), and
; http_body_total the full de-chunked size.
;
; The default base is bank 16 ($10:0000 — 16 MB REU, the stretch-goal
; config); see HTTP_REU_BODY_BASE in constants.inc for the override
; story.  Register programming mirrors src/boot.s::reu_mul_init.
;
; UCI-ONLY: the sink is a turbo/UCI stretch feature (the build knob is
; UCI-only) and ip65's memory map cannot fit it.  The ip65 arm below
; provides 3-byte inert stubs so the shared jmp/jsr sites link;
; http_body_sink is then a dead flag on ip65 (the .ifdef BACKEND_UCI
; guards in body_append / http_body_done_check compile the sink
; branches out).
; =============================================================================
        .segment "HTTP_SINK_CODE"
.ifndef BACKEND_UCI
sink_finish_done:               ; ip65: no sink — complete the parse
http_body_finish:               ;  and finalize nothing
        clc
        rts
.else

; -----------------------------------------------------------------------------
; sink_reu_setup - common $DF00 programming for blit + fetch-back:
;   C64 addr = http_resp_buf, len = http_resp_len, both addrs increment.
;   Clobbers: A.
; -----------------------------------------------------------------------------
sink_reu_setup:
        lda #<http_resp_buf
        sta reu_c64_lo
        lda #>http_resp_buf
        sta reu_c64_hi
        lda http_resp_len
        sta reu_len_lo
        lda http_resp_len+1
        sta reu_len_hi
        lda #0
        sta reu_addr_ctrl
        rts

; -----------------------------------------------------------------------------
; http_sink_blit - STASH http_resp_len bytes of http_resp_buf to
;   http_reu_body_base + http_reu_cursor; cursor += resp_len.
;   No-op when resp_len = 0.  Clobbers: A.
; -----------------------------------------------------------------------------
http_sink_blit:
        lda http_resp_len
        ora http_resp_len+1
        beq @rts
        jsr sink_reu_setup
        clc                     ; REU addr = 24-bit base + cursor
        lda http_reu_body_base
        adc http_reu_cursor
        sta reu_reu_lo
        lda http_reu_body_base+1
        adc http_reu_cursor+1
        sta reu_reu_hi
        lda http_reu_body_base+2
        adc http_reu_cursor+2
        sta reu_reu_bank
        lda #%10110000          ; execute + autoload + STASH (C64->REU)
        sta reu_command
        clc                     ; cursor += resp_len
        lda http_reu_cursor
        adc http_resp_len
        sta http_reu_cursor
        lda http_reu_cursor+1
        adc http_resp_len+1
        sta http_reu_cursor+1
        bcc @rts
        inc http_reu_cursor+2
@rts:
        rts

; -----------------------------------------------------------------------------
; sink_finish_done - shared completion tail for both body paths
;   (identity @sb_done_fin, chunked @cb_done): finalize the sink and
;   return C=0 (parse complete).
; -----------------------------------------------------------------------------
sink_finish_done:
        jsr http_body_finish
        clc
        rts

; -----------------------------------------------------------------------------
; http_body_finish - finalize the REU sink at body completion (or the
;   poll-timeout fallback).  Idempotent via the http_sink_flushed
;   latch; a no-op in buffer mode.  Steps: final partial blit;
;   http_resp_len = min(512, http_body_total); FETCH the first
;   resp_len body bytes from the REU back into http_resp_buf; restore
;   the reu_fetch_mul_row register latch this sink clobbered.
;   Clobbers: A.
; -----------------------------------------------------------------------------
http_body_finish:
        lda http_body_sink
        beq @rts
        lda http_sink_flushed
        bne @rts
        inc http_sink_flushed
        jsr http_sink_blit      ; final partial bounce (may be 0 bytes)
        ; http_resp_len = min(512, http_body_total)
        lda http_body_total+2
        bne @cap
        lda http_body_total+1
        cmp #$02
        bcs @cap
        lda http_body_total
        sta http_resp_len
        lda http_body_total+1
        sta http_resp_len+1
        jmp @fetch
@cap:
        lda #$00
        sta http_resp_len
        lda #$02
        sta http_resp_len+1
@fetch:
        lda http_resp_len
        ora http_resp_len+1
        beq @restore
        jsr sink_reu_setup
        lda http_reu_body_base
        sta reu_reu_lo
        lda http_reu_body_base+1
        sta reu_reu_hi
        lda http_reu_body_base+2
        sta reu_reu_bank
        lda #%10110001          ; execute + autoload + FETCH (REU->C64)
        sta reu_command
@restore:
.ifndef USE_NISTCURVES_ONCHIP
.ifndef USE_X25519_SIBLING
        ; Re-latch the reu_fetch_mul_row register state that
        ; reu_mul_init pre-set at boot (this sink clobbered it).  A
        ; REU-profile build doing a SECOND handshake in the same
        ; session would otherwise DMA multiply rows to the wrong C64
        ; address with no diagnostic.  Onchip/comb profiles never use
        ; the latch (guard mirrors boot.s's reu_fetch_mul_row guard;
        ; the comb library programs its own registers per fetch —
        ; verified against libs/nistcurves points256_comb.s).
        lda #<mul_dma_lo
        sta reu_c64_lo
        lda #>mul_dma_lo
        sta reu_c64_hi
        lda #0
        sta reu_reu_lo
        sta reu_len_lo
        sta reu_addr_ctrl
        lda #2
        sta reu_len_hi          ; 512 B row fetches
.endif
.endif
@rts:
        rts
.endif                          ; BACKEND_UCI (REU sink)

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
        jsr http_body_finish    ; sink finalize (idempotent; no-op unless
                                ;  http_body_sink=1 — see @recv_complete)

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

; The two W4 data items below ride HTTP_AUX_CODE2, not RODATA:
; CRYPTO_HOT is within ~15 B of full on the UCI plain/onchip builds and
; cannot absorb them (absolute indexed reads work from any segment).
        .segment "HTTP_AUX_CODE2"
http_ua_hdr:
        .byte "User-Agent: c64-https/0.1", $0d, $0a

.ifdef BACKEND_UCI
; W4 REU body sink: runtime copy of the REU destination base (24-bit
; LE).  Initialised from the HTTP_REU_BODY_BASE equate (constants.inc;
; default bank 16 = $10:0000, -D-overridable at build).  File-backed
; but RAM at runtime, so tests and rigs can retarget it by DMA without
; a rebuild (e.g. VICE's 512 KB REU cannot hold bank 16; the harness
; pokes bank 3 here).
http_reu_body_base:
        .byte <HTTP_REU_BODY_BASE, >HTTP_REU_BODY_BASE, ^HTTP_REU_BODY_BASE
.endif


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
; W4 REU sink finalize-once latch (see http_body_finish)
http_sink_flushed: .res 1       ; 1 = finish already ran for this body
