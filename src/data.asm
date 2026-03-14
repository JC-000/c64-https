; =============================================================================
; data.asm - Mutable data buffers
; =============================================================================

; =============================================================================
; Zero page save buffer (for ip65 time-sharing)
; =============================================================================
zp_save_buf:    !fill 26, 0     ; saves $02-$1B during ip65 calls

; =============================================================================
; Network layer buffers
; =============================================================================
tcp_recv_buf:   !fill 256, 0    ; TCP receive ring buffer (256 bytes, wraps)
tcp_recv_head:  !byte 0         ; read position
tcp_recv_tail:  !byte 0         ; write position (updated by ip65 callback)

; =============================================================================
; TLS state
; =============================================================================
tls_state:              !byte 0         ; current TLS state machine state
tls_client_random:      !fill 32, 0     ; client random (32 bytes)
tls_server_random:      !fill 32, 0     ; server random (32 bytes)

; ECDHE key exchange
tls_ecdhe_privkey:      !fill 32, 0     ; our ephemeral private key
tls_ecdhe_pubkey:       !fill 65, 0     ; our ephemeral public key (uncompressed)
tls_server_pubkey:      !fill 65, 0     ; server's ephemeral public key
tls_shared_secret:      !fill 32, 0     ; ECDHE shared secret (x-coordinate)

; Transcript hash (running SHA-256 state)
tls_transcript:         !fill 32, 0     ; current transcript hash output
tls_transcript_h0:      !fill 4, 0      ; saved SHA-256 state for cloning
tls_transcript_h1:      !fill 4, 0
tls_transcript_h2:      !fill 4, 0
tls_transcript_h3:      !fill 4, 0
tls_transcript_h4:      !fill 4, 0
tls_transcript_h5:      !fill 4, 0
tls_transcript_h6:      !fill 4, 0
tls_transcript_h7:      !fill 4, 0

; Handshake keys (derived from ECDHE via HKDF)
tls_hs_write_key:       !fill 32, 0     ; client handshake write key
tls_hs_write_iv:        !fill 12, 0     ; client handshake write IV
tls_hs_read_key:        !fill 32, 0     ; server handshake read key
tls_hs_read_iv:         !fill 12, 0     ; server handshake read IV

; Application traffic keys (derived after Finished)
tls_app_write_key:      !fill 32, 0     ; client application write key
tls_app_write_iv:       !fill 12, 0     ; client application write IV
tls_app_read_key:       !fill 32, 0     ; server application read key
tls_app_read_iv:        !fill 12, 0     ; server application read IV

; Sequence numbers (64-bit, big-endian)
tls_write_seq:          !fill 8, 0      ; write sequence number
tls_read_seq:           !fill 8, 0      ; read sequence number

; Record layer buffers
tls_rec_header:         !fill 5, 0      ; 5-byte record header
tls_rec_type:           !byte 0         ; content type of current record
tls_rec_len:            !word 0         ; length of current record payload
tls_rec_buf:            !fill 548, 0    ; record payload (512 + 1 inner type + 16 tag + padding)

; AEAD nonce construction
tls_nonce:              !fill 12, 0     ; constructed nonce for AEAD

; Handshake message buffer
tls_hs_buf:             !fill 256, 0    ; handshake message assembly/parsing
tls_hs_len:             !word 0         ; handshake message length

; =============================================================================
; HKDF buffers
; =============================================================================
hkdf_prk:               !fill 32, 0    ; pseudorandom key
hkdf_okm:               !fill 32, 0    ; output keying material
hkdf_info_buf:          !fill 80, 0    ; HkdfLabel construction buffer
hkdf_info_len:          !byte 0
hkdf_salt_ptr:          !word 0
hkdf_salt_len:          !byte 0
hkdf_ikm_ptr:           !word 0
hkdf_ikm_len:           !byte 0
hkdf_label_ptr:         !word 0
hkdf_label_len:         !byte 0
hkdf_context_ptr:       !word 0
hkdf_context_len:       !byte 0
hkdf_out_len:           !byte 0

; TLS key schedule intermediate values
tls_early_secret:       !fill 32, 0    ; HKDF-Extract(0, 0) for PSK=0
tls_handshake_secret:   !fill 32, 0    ; HKDF-Extract(derived, shared_secret)
tls_master_secret:      !fill 32, 0    ; HKDF-Extract(derived, 0)

; =============================================================================
; HTTP buffers
; =============================================================================
http_host_ptr:          !word 0
http_host_len:          !byte 0
http_path_ptr:          !word 0
http_path_len:          !byte 0
http_port:              !word 443       ; default HTTPS port
http_status:            !word 0         ; HTTP status code (e.g., 200)
http_req_buf:           !fill 256, 0    ; HTTP request buffer
http_req_len:           !word 0
http_resp_buf:          !fill 512, 0    ; HTTP response body buffer
http_resp_len:          !word 0

; =============================================================================
; Application data pointers (for tls_send)
; =============================================================================
tls_app_ptr:            !word 0
tls_app_len:            !word 0

; =============================================================================
; Crypto module buffers — will be filled in when crypto sources are integrated
; (SHA-256 state, HMAC-SHA256, ChaCha20 state, Poly1305 state, ECDH temps)
; =============================================================================
; TODO: import from c64-aes256-ecdsa and c64-wireguard data sections
