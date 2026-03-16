; =============================================================================
; main.asm - c64-https: HTTPS client for the Commodore 64
;
; TLS 1.3 (TLS_CHACHA20_POLY1305_SHA256) over TCP/IP
; RR-Net (CS8900a) ethernet via ip65
;
; Build: acme -f cbm -o ../build/c64-https.prg --vicelabels ../build/labels.txt main.asm
; =============================================================================

!to "../build/c64-https.prg", cbm

; --- system constants and zero page ---
!source "constants.asm"

; --- boot stub and main loop ---
!source "boot.asm"

; --- network wrapper (ip65 ZP time-sharing) ---
!source "net.asm"

; --- TLS 1.3 engine ---
!source "tls13.asm"
!source "tls_record.asm"
!source "tls_record_io.asm"
!source "tls_handshake.asm"
!source "tls_transcript.asm"

; --- entropy initialization ---
!source "entropy.asm"

; --- HKDF key derivation + key schedule ---
!source "hkdf.asm"
!source "tls_keyschedule.asm"

; --- HTTP/1.1 client ---
!source "http.asm"

; =============================================================================
; ip65 binary blob — built with ca65/ld65, placed at $2000
; Jump table at $2000, code $2000-$3B26, BSS at $4000+
; =============================================================================
* = $2000
!binary "../ip65-build/ip65-c64.bin"

; =============================================================================
; Crypto modules (from c64-wireguard and c64-aes256-ecdsa)
; =============================================================================
!source "crypto/word32.asm"
!source "crypto/chacha20.asm"
!source "crypto/poly1305.asm"
!source "crypto/aead.asm"
!source "crypto/sha256.asm"
!source "crypto/hmac_drbg.asm"
!source "crypto/fe25519.asm"
!source "crypto/x25519.asm"

; --- TLS ECDH wrapper (x25519-based key exchange) ---
!source "tls_ecdh.asm"

; --- mutable data buffers (must come after all code) ---
!source "data.asm"
