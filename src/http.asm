; =============================================================================
; http.asm - HTTP/1.1 client over TLS
;
; Builds HTTP requests, parses responses. Operates over the TLS layer
; (tls_send / tls_recv), so all data is encrypted transparently.
;
; For the MVP, supports only GET requests with basic response parsing
; (status line + headers + body).
; =============================================================================

; =============================================================================
; http_get - perform an HTTPS GET request
; Input: http_host_ptr/http_host_len = hostname (for Host header + SNI)
;        http_path_ptr/http_path_len = path (e.g., "/index.html")
;        http_port = port (default 443)
; Output: C=0 success (response in http_resp_buf), C=1 failure
; =============================================================================
http_get:
        ; 1. DNS resolve hostname
        ; jsr net_dns_resolve
        ; bcs @error

        ; 2. TCP connect to resolved IP on port 443
        ; jsr net_tcp_connect
        ; bcs @error

        ; 3. TLS handshake
        ; jsr tls_connect
        ; bcs @error

        ; 4. Build GET request
        jsr http_build_get
        ; bcs @error

        ; 5. Send via TLS
        ; lda #<http_req_buf
        ; ldx #>http_req_buf
        ; ... set length ...
        ; jsr tls_send
        ; bcs @error

        ; 6. Receive response via TLS
        ; jsr http_recv_response
        ; bcs @error

        ; 7. Close TLS + TCP
        ; jsr tls_close

        clc
        rts

; @error:
;         jsr tls_close
;         sec
;         rts

; =============================================================================
; http_build_get - construct HTTP/1.1 GET request in http_req_buf
; Input: http_host_ptr/len, http_path_ptr/len
; Output: http_req_buf contains request, http_req_len = length
; =============================================================================
http_build_get:
        ; Build:
        ;   GET <path> HTTP/1.1\r\n
        ;   Host: <hostname>\r\n
        ;   Connection: close\r\n
        ;   \r\n
        ;
        ; TODO: implement string concatenation into http_req_buf
        rts

; =============================================================================
; http_recv_response - receive and parse HTTP response
; Output: http_status = status code (e.g., 200)
;         http_resp_buf = response body
;         http_resp_len = body length
; =============================================================================
http_recv_response:
        ; TODO:
        ; 1. Read status line: "HTTP/1.1 200 OK\r\n"
        ; 2. Parse status code
        ; 3. Read headers until empty line (\r\n\r\n)
        ; 4. Check Content-Length or read until connection close
        ; 5. Read body into http_resp_buf
        rts

; =============================================================================
; HTTP request/response string constants
; =============================================================================
http_get_verb:
        !text "GET "
http_version:
        !text " HTTP/1.1", $0d, $0a
http_host_hdr:
        !text "Host: "
http_conn_hdr:
        !text "Connection: close", $0d, $0a
http_crlf:
        !byte $0d, $0a
