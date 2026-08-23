; tls_handshake.s — TLS 1.3 handshake messages
; Converted from ACME to ca65 in Phase 3 Batch C.
;
; Builds ClientHello, parses ServerHello and EncryptedExtensions.

.include "constants.inc"

; --- Externals (data.asm BSS / scratch) ---
.import tls_rec_buf
.import tls_rec_len
.import tls_client_random
.import tls_ecdhe_pubkey
.import tls_server_random
.import tls_server_pubkey

; --- Exports ---
.export tls_build_client_hello
.export tls_parse_server_hello
.export tls_parse_encrypted_extensions
.export tls_hostname
.export tls_hostname_len

; x25519 named group is defined in constants.inc; no local equate needed.

.segment "CODE"

; =============================================================================
; tls_build_client_hello - construct ClientHello message
;
; Input:  tls_client_random (32 bytes) already filled
;         tls_ecdhe_pubkey (32 bytes) already computed (x25519)
;         tls_hostname / tls_hostname_len set (for SNI)
; Output: tls_rec_buf contains complete handshake message
;         tls_rec_len = total length (16-bit)
; Clobbers: A, X, Y, zp_ptr, zp_count
; =============================================================================
tls_build_client_hello:
        ldy #0

        ; --- [0] Handshake type ---
        lda #TLS_HS_CLIENT_HELLO        ; 0x01
        sta tls_rec_buf,y
        iny                             ; Y=1

        ; --- [1-3] Length placeholder (24-bit, filled at end) ---
        lda #0
        sta tls_rec_buf+1
        sta tls_rec_buf+2
        sta tls_rec_buf+3
        iny                             ; Y=2
        iny                             ; Y=3
        iny                             ; Y=4

        ; --- [4-5] legacy_version = 0x0303 ---
        lda #$03
        sta tls_rec_buf,y
        iny                             ; Y=5
        sta tls_rec_buf,y
        iny                             ; Y=6

        ; --- [6-37] client_random (32 bytes) ---
        ldx #0
@copy_random:
        lda tls_client_random,x
        sta tls_rec_buf,y
        iny
        inx
        cpx #32
        bne @copy_random
        ; Y=38

        ; --- [38] session_id_length = 0x00 ---
        lda #$00
        sta tls_rec_buf,y
        iny                             ; Y=39

        ; --- [39-40] cipher_suites_length = 0x0002 ---
        lda #$00
        sta tls_rec_buf,y
        iny                             ; Y=40
        lda #$02
        sta tls_rec_buf,y
        iny                             ; Y=41

        ; --- [41-42] cipher_suite = TLS_CHACHA20_POLY1305_SHA256 = 0x1303 ---
        lda #$13
        sta tls_rec_buf,y
        iny                             ; Y=42
        lda #$03
        sta tls_rec_buf,y
        iny                             ; Y=43

        ; --- [43] compression_methods_length = 0x01 ---
        lda #$01
        sta tls_rec_buf,y
        iny                             ; Y=44

        ; --- [44] compression_method = 0x00 (null) ---
        lda #$00
        sta tls_rec_buf,y
        iny                             ; Y=45

        ; --- [45-46] extensions_length placeholder (filled at end) ---
        lda #$00
        sta tls_rec_buf,y
        iny                             ; Y=46
        sta tls_rec_buf,y
        iny                             ; Y=47

        ; =================================================================
        ; Extensions start at offset 47
        ; =================================================================

        ; --- Extension 1: supported_versions (0x002B) ---
        ; 00 2b 00 03 02 03 04
        lda #$00
        sta tls_rec_buf,y
        iny
        lda #$2b
        sta tls_rec_buf,y
        iny
        lda #$00
        sta tls_rec_buf,y
        iny
        lda #$03
        sta tls_rec_buf,y
        iny
        lda #$02
        sta tls_rec_buf,y
        iny
        lda #$03
        sta tls_rec_buf,y
        iny
        lda #$04
        sta tls_rec_buf,y
        iny                             ; 7 bytes written

        ; --- Extension 2: supported_groups (0x000A) ---
        ; 00 0a 00 04 00 02 00 1d
        lda #$00
        sta tls_rec_buf,y
        iny
        lda #$0a
        sta tls_rec_buf,y
        iny
        lda #$00
        sta tls_rec_buf,y
        iny
        lda #$04
        sta tls_rec_buf,y
        iny
        lda #$00
        sta tls_rec_buf,y
        iny
        lda #$02
        sta tls_rec_buf,y
        iny
        lda #$00
        sta tls_rec_buf,y
        iny
        lda #$1d
        sta tls_rec_buf,y
        iny                             ; 8 bytes written

        ; --- Extension 3: signature_algorithms (0x000D) ---
        ; 00 0d 00 04 00 02 04 03
        ; ONE scheme advertised: ecdsa_secp256r1_sha256 (0x0403). Inner list
        ; length = 2 (one 2-byte scheme); extension data length = 4. See the
        ; table for why 0x0503 is gone. Every outer length (extensions_length,
        ; handshake length, tls_rec_len) is computed from Y at the end of this
        ; routine, so shrinking the table needs no other edit. Table-driven to
        ; keep LOADER from overflowing.
        ldx #0
@sig_algs_ext_loop:
        lda sig_algs_ext_data,x
        sta tls_rec_buf,y
        iny
        inx
        cpx #8
        bne @sig_algs_ext_loop          ; 8 bytes written

        ; --- Extension 4: key_share (0x0033) ---
        ; 00 33 00 26 00 24 00 1d 00 20 [32 bytes pubkey]
        lda #$00
        sta tls_rec_buf,y
        iny
        lda #$33
        sta tls_rec_buf,y
        iny
        lda #$00
        sta tls_rec_buf,y
        iny
        lda #$26                        ; ext data length = 38
        sta tls_rec_buf,y
        iny
        lda #$00
        sta tls_rec_buf,y
        iny
        lda #$24                        ; entries length = 36
        sta tls_rec_buf,y
        iny
        lda #$00
        sta tls_rec_buf,y
        iny
        lda #$1d                        ; group = x25519
        sta tls_rec_buf,y
        iny
        lda #$00
        sta tls_rec_buf,y
        iny
        lda #$20                        ; key length = 32
        sta tls_rec_buf,y
        iny

        ; Copy 32 bytes of x25519 public key
        ldx #0
@copy_pubkey:
        lda tls_ecdhe_pubkey,x
        sta tls_rec_buf,y
        iny
        inx
        cpx #32
        bne @copy_pubkey
        ; 10 + 32 = 42 bytes written

        ; --- Extension 5: server_name / SNI (0x0000) ---
        ; Only include if tls_hostname_len > 0
        lda tls_hostname_len
        beq @skip_sni

        ; Type 00 00
        lda #$00
        sta tls_rec_buf,y
        iny
        sta tls_rec_buf,y
        iny

        ; Ext data length = hostname_len + 5 (big-endian)
        lda #$00
        sta tls_rec_buf,y
        iny
        lda tls_hostname_len
        clc
        adc #5
        sta tls_rec_buf,y
        iny

        ; Server name list length = hostname_len + 3 (big-endian)
        lda #$00
        sta tls_rec_buf,y
        iny
        lda tls_hostname_len
        clc
        adc #3
        sta tls_rec_buf,y
        iny

        ; Host name type = 0 (host_name)
        lda #$00
        sta tls_rec_buf,y
        iny

        ; Host name length (2 bytes big-endian)
        lda #$00
        sta tls_rec_buf,y
        iny
        lda tls_hostname_len
        sta tls_rec_buf,y
        iny

        ; Copy hostname bytes
        ldx #0
@copy_hostname:
        lda tls_hostname,x
        sta tls_rec_buf,y
        iny
        inx
        cpx tls_hostname_len
        bne @copy_hostname
@skip_sni:

        ; --- Extension 6: max_fragment_length (0x0001) ---
        ; 00 01 00 01 01
        lda #$00
        sta tls_rec_buf,y
        iny
        lda #$01
        sta tls_rec_buf,y
        iny
        lda #$00
        sta tls_rec_buf,y
        iny
        lda #$01
        sta tls_rec_buf,y
        iny
        lda #$01                        ; value 1 = 512 bytes
        sta tls_rec_buf,y
        iny                             ; 5 bytes written

        ; =================================================================
        ; Fill in length fields. Y = total bytes written.
        ; =================================================================

        ; extensions_length at [45-46] = Y - 47 (big-endian)
        tya
        sec
        sbc #47
        sta tls_rec_buf+46              ; low byte of extensions length
        lda #0
        sta tls_rec_buf+45              ; high byte (always 0, msg < 256)

        ; handshake length at [1-3] = Y - 4 (24-bit big-endian)
        tya
        sec
        sbc #4
        sta tls_rec_buf+3               ; low byte
        lda #0
        sta tls_rec_buf+2               ; mid byte
        sta tls_rec_buf+1               ; high byte

        ; tls_rec_len = Y (16-bit)
        sty tls_rec_len
        lda #0
        sta tls_rec_len+1

        rts


; =============================================================================
; tls_parse_server_hello - parse ServerHello message
;
; Input:  tls_rec_buf contains raw ServerHello (including handshake header)
;         tls_rec_len = length
; Output: C=0 success, C=1 parse error or unsupported
;         tls_server_random (32 bytes) filled
;         tls_server_pubkey (32 bytes) filled from key_share extension
; Clobbers: A, X, Y, zp_ptr, zp_tmp1, zp_tmp2, zp_temp, zp_count
; =============================================================================
tls_parse_server_hello:
        ldy #0

        ; --- [0] Verify handshake type = 0x02 ---
        lda tls_rec_buf
        cmp #TLS_HS_SERVER_HELLO
        beq @sh_type_ok
        jmp @sh_error
@sh_type_ok:
        iny                             ; Y=1

        ; --- [1-3] Length (24-bit) — skip past ---
        iny                             ; Y=2
        iny                             ; Y=3
        iny                             ; Y=4

        ; --- [4-5] legacy_version — skip (should be 0x0303) ---
        iny                             ; Y=5
        iny                             ; Y=6

        ; --- [6-37] server_random — copy 32 bytes ---
        ldx #0
@copy_server_random:
        lda tls_rec_buf,y
        sta tls_server_random,x
        iny
        inx
        cpx #32
        bne @copy_server_random
        ; Y=38

        ; --- [38] session_id_echo_length — skip that many bytes ---
        lda tls_rec_buf,y
        iny                             ; past length byte
        tax
        beq @sh_no_session_id
@sh_skip_session_id:
        iny
        dex
        bne @sh_skip_session_id
@sh_no_session_id:

        ; --- cipher_suite (2 bytes) — verify = 0x1303 ---
        lda tls_rec_buf,y
        cmp #$13
        bne @sh_error_jmp
        iny
        lda tls_rec_buf,y
        cmp #$03
        bne @sh_error_jmp
        iny

        ; --- compression_method (1 byte) — verify = 0x00 ---
        lda tls_rec_buf,y
        cmp #$00
        bne @sh_error_jmp
        iny

        ; --- extensions_length (2 bytes, big-endian) ---
        lda tls_rec_buf,y               ; high byte
        sta zp_tmp2                     ; extensions remaining (high)
        iny
        lda tls_rec_buf,y               ; low byte
        sta zp_tmp1                     ; extensions remaining (low)
        iny

        ; Reset flags for required extensions
        lda #0
        sta sh_found_ver        ; supported_versions found?
        sta sh_found_ks         ; key_share found?
        jmp @sh_ext_loop

@sh_error_jmp:
        jmp @sh_error

        ; =================================================================
        ; Extension parsing loop
        ; zp_tmp1 = remaining extension bytes (low)
        ; zp_tmp2 = remaining extension bytes (high)
        ; =================================================================
@sh_ext_loop:
        ; Check if we've consumed all extension bytes
        lda zp_tmp1
        ora zp_tmp2
        bne @sh_ext_continue
        jmp @sh_done
@sh_ext_continue:

        ; Read extension type (2 bytes, big-endian)
        lda tls_rec_buf,y               ; type high byte
        sta zp_ptr                      ; save type_hi
        iny
        lda tls_rec_buf,y               ; type low byte
        sta zp_ptr+1                    ; save type_lo
        iny

        ; Read extension data length (2 bytes, big-endian)
        lda tls_rec_buf,y               ; ext_len high
        sta zp_count                    ; save ext_len_hi
        iny
        lda tls_rec_buf,y               ; ext_len low
        sta zp_temp                     ; save ext_len_lo
        iny

        ; Subtract 4 (type+length headers) from remaining
        lda zp_tmp1
        sec
        sbc #4
        sta zp_tmp1
        bcs :+
        dec zp_tmp2
:
        ; Subtract ext data length from remaining
        lda zp_tmp1
        sec
        sbc zp_temp
        sta zp_tmp1
        bcs :+
        dec zp_tmp2
:
        lda zp_tmp1
        sec
        sbc zp_count
        sta zp_tmp1
        bcs :+
        dec zp_tmp2
:

        ; --- Check: supported_versions (type 0x002B)? ---
        lda zp_ptr                      ; type_hi
        bne @sh_not_sup_ver             ; high byte != 0
        lda zp_ptr+1                    ; type_lo
        cmp #$2b
        bne @sh_not_sup_ver

        ; supported_versions: expect 2 bytes = 03 04
        lda tls_rec_buf,y
        cmp #$03
        bne @sh_error
        iny
        lda tls_rec_buf,y
        cmp #$04
        bne @sh_error
        iny
        inc sh_found_ver        ; mark supported_versions found
        jmp @sh_ext_loop

@sh_not_sup_ver:
        ; --- Check: key_share (type 0x0033)? ---
        lda zp_ptr                      ; type_hi
        bne @sh_skip_ext                ; high byte != 0
        lda zp_ptr+1                    ; type_lo
        cmp #$33
        bne @sh_skip_ext

        ; key_share: group(2) + key_len(2) + key_data
        ; Verify group = 0x001D (x25519)
        lda tls_rec_buf,y
        bne @sh_error                   ; high byte must be 0
        iny
        lda tls_rec_buf,y
        cmp #$1d
        bne @sh_error
        iny

        ; Verify key_len = 0x0020
        lda tls_rec_buf,y
        bne @sh_error                   ; high byte must be 0
        iny
        lda tls_rec_buf,y
        cmp #$20
        bne @sh_error
        iny

        ; Copy 32 bytes to tls_server_pubkey
        ldx #0
@copy_server_key:
        lda tls_rec_buf,y
        sta tls_server_pubkey,x
        iny
        inx
        cpx #32
        bne @copy_server_key
        inc sh_found_ks         ; mark key_share found
        jmp @sh_ext_loop

        ; --- Unknown extension: skip ext data ---
@sh_skip_ext:
        ; zp_count = ext_len_hi, zp_temp = ext_len_lo
        ; For ServerHello extensions, length should be small (<256)
        lda zp_count
        bne @sh_error                   ; can't handle >255 byte ext here
        ldx zp_temp
        bne @sh_skip_bytes             ; has data to skip
        jmp @sh_ext_loop               ; zero-length: nothing to skip
@sh_skip_bytes:
        iny
        dex
        bne @sh_skip_bytes
        jmp @sh_ext_loop

@sh_done:
        ; Verify required extensions were found
        lda sh_found_ver
        beq @sh_error           ; supported_versions is mandatory
        lda sh_found_ks
        beq @sh_error           ; key_share is mandatory
        clc
        rts

@sh_error:
        sec
        rts


; =============================================================================
; tls_parse_encrypted_extensions - parse EncryptedExtensions
;
; Input:  tls_rec_buf contains decrypted handshake message
; Output: C=0 success (MVP: accept any), C=1 wrong type
; =============================================================================
tls_parse_encrypted_extensions:
        ; Verify handshake type byte
        lda tls_rec_buf
        cmp #TLS_HS_ENCRYPTED_EXT
        bne @ee_error
        clc
        rts
@ee_error:
        sec
        rts


; =============================================================================
; Extension tracking flags (module-local BSS; moved out of CODE so they don't
; break relative-branch reachability, and so CODE stays pure instructions).
; =============================================================================
.segment "BSS"

sh_found_ver:  .res 1
sh_found_ks:   .res 1


; =============================================================================
; Inline data: hostname for SNI extension
; =============================================================================
.segment "BSS"

tls_hostname:      .res 64
tls_hostname_len:  .res 1


; =============================================================================
; signature_algorithms extension payload (TLS 1.3, two ECDSA schemes).
; Lives in RODATA to keep the LOADER segment from overflowing — emitting
; ten LDA/STA/INY triples in CODE costs 60 B vs ~24 B (table + 7-insn
; copy loop).
; =============================================================================
.segment "RODATA"

sig_algs_ext_data:
        .byte $00, $0d                  ; extension type = signature_algorithms
        .byte $00, $04                  ; extension data length = 4
        .byte $00, $02                  ; supported_signature_algorithms length = 2
        .byte $04, $03                  ; ecdsa_secp256r1_sha256
        ; ecdsa_secp384r1_sha384 (0x0503) is NOT advertised. It was, and the
        ; client cannot perform it: the P-384 verify path swaps in an overlay
        ; image no shipped build ever stages, corrupting live resident code
        ; (see the gate in src/crypto/ecdsa_verify.s). Advertising a scheme we
        ; answer destructively hands a server the choice of breaking us.
        ; Parked as roadmap work; restore this line together with
        ; ENABLE_P384_VERIFY and a P-384 overlay that builds.
