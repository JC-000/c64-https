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
.ifdef CH_SECTIONED
.export tls_ch_ks_ptr
.export tls_ch_ks_len
.export tls_ch_split
.endif
.export tls_sh_err
.export tls_sh_chk_hrr

; x25519 named group is defined in constants.inc; no local equate needed.

.segment "CODE"

; =============================================================================
; tls_build_client_hello - construct ClientHello message (sectioned, #P3)
;
; Input:  tls_client_random (32 bytes) already filled
;         tls_ecdhe_pubkey (32 bytes) already computed (x25519)
;         tls_hostname / tls_hostname_len set (for SNI)
;         tls_ch_ks_ptr / tls_ch_ks_len: OPTIONAL bulk key-share section
;           (16-bit length; 0 = none = the classic X25519-only ClientHello,
;           byte-identical to the pre-sectioned builder).
; Output: tls_rec_buf = the STAGED bytes of the handshake message;
;         tls_rec_len = number of staged bytes (16-bit).
;         With tls_ch_ks_len = 0 the staged bytes ARE the whole message.
;         With tls_ch_ks_len = B != 0 the message on the wire is
;             tls_rec_buf[0 .. tls_ch_split)   head, through the 11EC entry
;                                              header (group, 16-bit length)
;             B bytes at (tls_ch_ks_ptr)       bulk (the ML-KEM ek)
;             tls_rec_buf[tls_ch_split .. tls_rec_len)  tail: the x25519
;                                              share that completes the 11EC
;                                              entry, the 001D entry, SNI, MFL
;         i.e. wire length = tls_rec_len + B, and every length field in the
;         message (extensions_length, handshake length, key_share ext, list
;         and 11EC entry) already carries B. The staging buffer never holds
;         more than ~230 B, so the 8-bit Y cursor is safe for the STAGED
;         bytes; only the lengths are 16-bit.
; Clobbers: A, X, Y, zp_tmp1
; =============================================================================
tls_build_client_hello:
        ldy #0
        ldx #CHT_HEAD                   ; 01 00 00 00 03 03
        jsr ch_put
        ldx #0
@copy_random:
        lda tls_client_random,x
        sta tls_rec_buf,y
        iny
        inx
        cpx #32
        bne @copy_random                ; Y=38

        ; sid_len 0, cipher_suites (1303), compression (null),
        ; extensions_length placeholder [45-46], supported_versions
        ldx #CHT_MID
        jsr ch_put                      ; Y=54

        ; --- supported_groups (0x000A) ---
        ldx #CHT_GROUPS
.ifdef CH_SECTIONED
        lda tls_ch_ks_len
        ora tls_ch_ks_len+1
        beq :+
        ldx #CHT_GROUPS_H               ; 11EC, 001D
:
.endif
        jsr ch_put

        ; --- signature_algorithms (one scheme, 0x0403) ---
        ldx #CHT_SIGALGS
        jsr ch_put

        ; --- key_share (0x0033) ---
.ifdef CH_SECTIONED
        lda tls_ch_ks_len
        ora tls_ch_ks_len+1
        bne @ks_hybrid
.endif
        ldx #CHT_KS
        jsr ch_put                      ; 00 33 00 26 00 24 00 1d 00 20
.ifdef CH_SECTIONED
        jmp @ks_pub
@ks_hybrid:
        ldx #CHT_KS_H                   ; 00 33
        jsr ch_put
        lda #74                         ; ext data  = B + 2 + 4 + 32 + 4 + 32
        jsr ch_put_sum
        lda #72                         ; list      = B + 4 + 32 + 4 + 32
        jsr ch_put_sum
        ldx #CHT_GRP11EC                ; 11 ec
        jsr ch_put
        lda #32                         ; entry     = B + 32
        jsr ch_put_sum
        sty tls_ch_split                ; bulk goes here
@ks_pub:
.endif
        jsr ch_put_pub                  ; x25519 share (completes 11EC entry)
.ifdef CH_SECTIONED
        lda tls_ch_ks_len
        ora tls_ch_ks_len+1
        beq @sni
        ldx #CHT_ENT1D                  ; 00 1d 00 20
        jsr ch_put
        jsr ch_put_pub
.endif

@sni:
        ; --- server_name / SNI (0x0000), only if tls_hostname_len > 0 ---
        ldx tls_hostname_len
        beq @skip_sni
        stx zp_tmp1
        ldx #CHT_SNI0                   ; 00 00 00
        jsr ch_put
        lda zp_tmp1
        clc
        adc #5                          ; ext data length
        jsr ch_put_a
        lda #0
        jsr ch_put_a
        lda zp_tmp1
        clc
        adc #3                          ; server name list length
        jsr ch_put_a
        ldx #CHT_SNI1                   ; 00 (host_name) 00 (len hi)
        jsr ch_put
        lda zp_tmp1
        jsr ch_put_a
        ldx #0
@copy_hostname:
        lda tls_hostname,x
        sta tls_rec_buf,y
        iny
        inx
        cpx zp_tmp1
        bne @copy_hostname
@skip_sni:
        ldx #CHT_MFL                    ; max_fragment_length = 512
        jsr ch_put

        ; =================================================================
        ; Fill in length fields. Y = staged bytes; B = tls_ch_ks_len.
        ; =================================================================
.ifdef CH_SECTIONED
        ; extensions_length at [45-46] = (Y - 47) + B
        tya
        sec
        sbc #47
        clc
        adc tls_ch_ks_len
        sta tls_rec_buf+46
        lda tls_ch_ks_len+1
        adc #0
        sta tls_rec_buf+45

        ; handshake length at [1-3] = (Y - 4) + B (24-bit big-endian)
        tya
        sec
        sbc #4
        clc
        adc tls_ch_ks_len
        sta tls_rec_buf+3
        lda tls_ch_ks_len+1
        adc #0
        sta tls_rec_buf+2
        lda #0
        adc #0
        sta tls_rec_buf+1
.else
        ; no bulk section: the whole message is < 256 B; the high bytes
        ; [45], [1], [2] are already 0 from the templates
        tya
        sec
        sbc #47
        sta tls_rec_buf+46              ; extensions_length
        tya
        sec
        sbc #4
        sta tls_rec_buf+3               ; handshake length
.endif

        ; tls_rec_len = Y (staged bytes, 16-bit)
        sty tls_rec_len
        lda #0
        sta tls_rec_len+1
        rts

; ch_put - append template at ch_tmpl+X (length-prefixed) at tls_rec_buf+Y.
; Out: Y advanced. Clobbers A, X, zp_count (NOT zp_tmp1: SNI keeps its
; hostname length there).
ch_put:
        lda ch_tmpl,x
        sta zp_count
:       inx
        lda ch_tmpl,x
        sta tls_rec_buf,y
        iny
        dec zp_count
        bne :-
        rts

; ch_put_a - append A at tls_rec_buf+Y.
ch_put_a:
        sta tls_rec_buf,y
        iny
        rts

.ifdef CH_SECTIONED
; ch_put_sum - append the big-endian 16-bit value (tls_ch_ks_len + A).
ch_put_sum:
        clc
        adc tls_ch_ks_len
        pha
        lda tls_ch_ks_len+1
        adc #0
        jsr ch_put_a
        pla
        jmp ch_put_a
.endif

; ch_put_pub - append the 32-byte x25519 public key.
ch_put_pub:
        ldx #0
:       lda tls_ecdhe_pubkey,x
        sta tls_rec_buf,y
        iny
        inx
        cpx #32
        bne :-
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

        ; HelloRetryRequest is a ServerHello whose random is a fixed magic
        ; (RFC 8446 4.1.3). We never send a second ClientHello, so it is a
        ; clean refusal (tls_sh_err = SH_ERR_HRR), not a misparse.
        jsr tls_sh_chk_hrr
        bcs @sh_error_jmp

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
; tls_sh_chk_hrr - is tls_server_random the HelloRetryRequest magic?
; Out: C=1 and tls_sh_err = SH_ERR_HRR if so, else C=0 and tls_sh_err = 0.
; Preserves Y. Clobbers A, X. TLS_CODE: jsr-only, off the ip65 LOADER.
; =============================================================================
SH_ERR_HRR = $01

.segment "TLS_CODE"
tls_sh_chk_hrr:
        lda #0
        sta tls_sh_err
        ldx #31
:       lda tls_server_random,x
        cmp hrr_magic,x
        bne @not_hrr
        dex
        bpl :-
        lda #SH_ERR_HRR
        sta tls_sh_err
        sec
        rts
@not_hrr:
        clc
        rts
.segment "CODE"

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

; Optional bulk key-share section for the ClientHello (see
; tls_build_client_hello). BSS is zeroed at boot, so the default is
; "none" = X25519-only. tls_send_client_hello clears the length after one
; use: a caller that wants a hybrid hello sets ptr/len before EACH connect.
.ifdef CH_SECTIONED
tls_ch_ks_ptr: .res 2
tls_ch_ks_len: .res 2
tls_ch_split:  .res 1                   ; staged offset where the bulk goes
.endif
tls_sh_err:    .res 1                   ; SH_ERR_* of the last SH parse (0 = none)


; =============================================================================
; Inline data: hostname for SNI extension
; =============================================================================
.segment "BSS"

tls_hostname:      .res 64
tls_hostname_len:  .res 1


; =============================================================================
; ClientHello templates: length-prefixed byte runs, copied by ch_put. RODATA
; keeps LOADER small (a table + one copy loop is far cheaper than the
; LDA/STA/INY triple per byte the builder used to spend).
; signature_algorithms offers ONE scheme, ecdsa_secp256r1_sha256 (0x0403):
; only P-256 is verified (P-384 is retired) and tls_handle_cert_verify
; refuses any other. Every length field is derived from the staged byte
; count, so the tables need no companion edit.
; =============================================================================
; The tables ride CODE (LOADER) on every backend. Measured: LOADER has room
; (the table-driven builder is ~250 B smaller than the LDA/STA/INY one it
; replaced), while the crypto pools do not -- ip65's CRYPTO_OVERLAY+RESIDENT
; are one tight pool and uci-comb-demo-store has 70 B of CRYPTO_HOT.
.segment "CODE"

; SHA-256("HelloRetryRequest"), RFC 8446 4.1.3
hrr_magic:
        .byte $cf, $21, $ad, $74, $e5, $9a, $61, $11, $be, $1d, $8c, $02, $1e, $65, $b8, $91
        .byte $c2, $a2, $11, $16, $7a, $bb, $8c, $5e, $07, $9e, $09, $e2, $c8, $a8, $33, $9c

ch_tmpl:
CHT_HEAD     = * - ch_tmpl
        .byte 6, $01, $00, $00, $00, $03, $03   ; type, len24 (patched), legacy_version
CHT_MID      = * - ch_tmpl
        .byte 16
        .byte $00                               ; session_id_length
        .byte $00, $02, $13, $03                ; cipher_suites: CHACHA20_POLY1305
        .byte $01, $00                          ; compression: null
        .byte $00, $00                          ; extensions_length (patched)
        .byte $00, $2b, $00, $03, $02, $03, $04 ; supported_versions: TLS 1.3
CHT_GROUPS   = * - ch_tmpl
        .byte 8, $00, $0a, $00, $04, $00, $02, $00, $1d
.ifdef CH_SECTIONED
CHT_GROUPS_H = * - ch_tmpl
        .byte 10, $00, $0a, $00, $06, $00, $04, $11, $ec, $00, $1d
.endif
CHT_SIGALGS  = * - ch_tmpl
        .byte 8, $00, $0d, $00, $04, $00, $02, $04, $03
CHT_KS       = * - ch_tmpl
        .byte 10, $00, $33, $00, $26, $00, $24, $00, $1d, $00, $20
.ifdef CH_SECTIONED
CHT_KS_H     = * - ch_tmpl
        .byte 2, $00, $33
CHT_GRP11EC  = * - ch_tmpl
        .byte 2, $11, $ec
CHT_ENT1D    = * - ch_tmpl
        .byte 4, $00, $1d, $00, $20
.endif
CHT_SNI0     = * - ch_tmpl
        .byte 3, $00, $00, $00
CHT_SNI1     = * - ch_tmpl
        .byte 2, $00, $00
CHT_MFL      = * - ch_tmpl
        .byte 5, $00, $01, $00, $01, $01        ; max_fragment_length = 512
