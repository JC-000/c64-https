; =============================================================================
; src/handoff.s — HANDOFF=1: run one HTTPS GET for a host program and go
; back to it (UCI only). Mailbox, REU map and codes: src/handoff.inc;
; host-side contract: docs/handoff.md.
;
; boot.s calls, in order:
;   handoff_pre_probe  before reu_probe_size: read the byte the probe is
;                      about to overwrite at offset 0 of banks 0,1,2,4..128.
;   handoff_boot       right after it, before anything else writes the REU:
;                      puts those bytes back, then
;                        * REU < 1 MB, or no request in the mailbox: says so,
;                          waits for a key, returns to the default host
;                          (HO_DEF_*) -- never reaches reu_mul_init, so the
;                          host's REU (CD64's RAM drive) is left as it was;
;                        * else saves banks 0-2 to HO_SAVE, marks the mailbox
;                          RUNNING, and validates the request: a bad one is
;                          answered HO_R_BAD_REQ at once (handoff_finish);
;                          a good one sets ho_active and returns to boot.
;   handoff_run        instead of the menu once the network is up: one
;                      do_https_get against the request, then handoff_finish.
; do_https_get calls ho_target (instead of the typed-target prompt),
; HO_STAGE (boot.s) before each step, ho_hdr_reset before the receive and
; ho_recv_verdict after it; http.s calls ho_hdr_byte for every byte of the
; status line and headers.
;
; handoff_finish writes the reply, marks the mailbox DONE, restores banks
; 0-2, scrubs the session (session_scrub + zero page + stack, as 'Q'), and
; loads the host program back with a stub copied to $C000 -- the TCP ring,
; dead once the socket is closed. A failed LOAD resets the machine.
;
; Placement: HANDOFF_CODE / HANDOFF_BSS in NET_BSS_TAIL's free tail
; (cfg/c64-https-uci.cfg). cert_buf is the 2 KB bounce for the bank copies
; and the request read: nothing else uses it at boot or after the close.
; =============================================================================

.ifdef HANDOFF

        .include "constants.inc"
        .include "handoff.inc"

        .import reu_execute, reu_dma_timeout
        .import reu_size_ok, reu_top_bank
        .import cert_buf
        .import print_string, ascii_chrout
        .import session_scrub
        .import net_initialized, do_https_get
        .import tls_hostname, tls_hostname_len, tls_reached_connected
        .import http_host_ptr, http_host_len, http_path_ptr, http_path_len
        .import http_status, http_reu_cursor, http_body_total, http_sink_full
        .import net_last_error
.if .defined(HTTPS_PIN_SPKI) .or .defined(TRUST_STORE)
        .import cert_pin_status
.endif
.ifdef PQ_HYBRID
        .import tls_kex_group
.endif

        .export handoff_pre_probe, handoff_boot, handoff_run
        .export ho_target, ho_hdr_reset, ho_hdr_byte, ho_recv_verdict
        .export ho_active, ho_result, ho_port

.assert HTTP_REU_BODY_BASE = HO_BODY, error, "HANDOFF: the body sink must start at HO_BODY"

HOST_MAX = 63
PATH_MAX = 100
NAME_MAX = 16
STUB     = $C000
NDX      = $c6                  ; KERNAL keyboard buffer count
NMINV    = $0318
NMI_EXIT = $FEBC                ; KERNAL: pla/tay/pla/tax/pla/rti

        .segment "HANDOFF_CODE"

; -----------------------------------------------------------------------------
; ho_dma - A = REU command; ho_c64 / ho_reu (24-bit) / ho_len. X, Y kept.
; -----------------------------------------------------------------------------
ho_dma:
        pha
        lda ho_c64
        sta reu_c64_lo
        lda ho_c64+1
        sta reu_c64_hi
        lda ho_reu
        sta reu_reu_lo
        lda ho_reu+1
        sta reu_reu_hi
        lda ho_reu+2
        sta reu_reu_bank
        lda ho_len
        sta reu_len_lo
        lda ho_len+1
        sta reu_len_hi
        lda #0
        sta reu_addr_ctrl
        pla
        jmp reu_execute

CMD_STASH = $90
CMD_FETCH = $91

; ho_at - ho_c64 = A/Y, ho_len = X (1..255), ho_reu = HO_MBOX + offset in
; ho_off. Shared setup for the small mailbox transfers.
ho_at:
        sta ho_c64
        sty ho_c64+1
        stx ho_len
        lda #0
        sta ho_len+1
        lda ho_off
        sta ho_reu
        lda ho_off+1
        sta ho_reu+1
        lda #^HO_MBOX
        sta ho_reu+2
        rts

; -----------------------------------------------------------------------------
; handoff_pre_probe - FETCH offset 0 of each bank reu_probe_size writes.
; -----------------------------------------------------------------------------
handoff_pre_probe:
        lda #CMD_FETCH
        bne ho_probe_bytes      ; always

; handoff_boot's first act: STASH them back, last bank first, so on a REU
; that aliases (bank 8 = bank 0 on 512 KB) the lowest bank's own byte wins.
ho_probe_restore:
        lda #CMD_STASH
ho_probe_bytes:
        sta ho_cmd
        lda #0
        sta ho_reu
        sta ho_reu+1
        sta ho_len+1
        lda #1
        sta ho_len
        ldx #PROBE_N-1
@b:     lda probe_bank,x
        sta ho_reu+2
        txa
        clc
        adc #<ho_probe_save
        sta ho_c64
        lda #>ho_probe_save
        adc #0
        sta ho_c64+1
        lda ho_cmd
        jsr ho_dma
        dex
        bpl @b
        rts

probe_bank:     .byte 0, 1, 2, 4, 8, 16, 32, 64, 128
PROBE_N = * - probe_bank

; -----------------------------------------------------------------------------
; handoff_boot - see the header. Returns only with a valid request
; (ho_active = 1); every other path leaves through ho_exit.
; -----------------------------------------------------------------------------
handoff_boot:
        jsr ho_probe_restore
        lda #<NMI_EXIT          ; RESTORE must not reach the host's
        sta NMINV               ;  $C000 return stub: the TCP ring is
        lda #>NMI_EXIT          ;  there now
        sta NMINV+1
        jsr ho_default_ret
        lda #HO_R_BAD_REQ
        sta ho_result

        lda reu_size_ok
        beq @no_reu
        lda reu_dma_timeout
        bne @no_reu
        lda reu_top_bank
        cmp #HO_MIN_TOP_BANK
        bcs @reu_ok
@no_reu:
        lda #<msg_no_reu
        ldy #>msg_no_reu
        bne @refuse             ; always
@reu_ok:
        ; the request, whole, into cert_buf
        lda #0
        sta ho_off
        sta ho_off+1
        lda #<cert_buf
        ldy #>cert_buf
        ldx #0
        jsr ho_at
        lda #>$0200             ; 512 B >= HO_REQ_LEN
        sta ho_len+1
        lda #CMD_FETCH
        jsr ho_dma
        ldx #7
@magic: lda cert_buf+HO_O_MAGIC,x
        cmp ho_magic,x
        bne @no_req
        dex
        bpl @magic
        lda cert_buf+HO_O_STATE
        cmp #HO_ST_REQUEST
        beq @have_req
@no_req:
        lda #<msg_no_req
        ldy #>msg_no_req
@refuse:
        ; Nothing was saved and nothing else has written the REU: say why,
        ; wait for a key, go back. No reply: the mailbox is not ours.
        jsr print_string
        cli
        lda #0
        sta NDX
@key:   jsr getin
        beq @key
        jmp ho_exit_quiet

@have_req:
        ; From here on the mailbox is ours. Everything is read out of
        ; cert_buf first (the bank save below bounces through it), then
        ; banks 0-2 are saved and the mailbox says RUNNING -- good request
        ; or bad, since handoff_finish restores them either way.
        lda cert_buf+HO_O_RET_DEV       ; the return first: a bad request
        cmp #8                          ;  still goes back to its host
        bcc @ret_done
        cmp #31
        bcs @ret_done
        tax
        ldy cert_buf+HO_O_RET_NLEN
        beq @ret_done
        cpy #NAME_MAX+1
        bcs @ret_done
        lda cert_buf+HO_O_RET_ENTRY+1
        beq @ret_done                   ; entry in page 0: not a program
        stx ho_rdev
        sty ho_rnlen
        sta ho_rentry+1
        lda cert_buf+HO_O_RET_ENTRY
        sta ho_rentry
        dey
@rn:    lda cert_buf+HO_O_RET_NAME,y
        sta ho_rname,y
        dey
        bpl @rn
@ret_done:
        lda cert_buf+HO_O_VERSION
        cmp #HO_VERSION
        bne @bad_far
        ldx #7                  ; "https://", letters case-folded
@sch:   lda cert_buf+HO_O_URL,x
        ora #$20                ; (':' and '/' already have bit 5)
        cmp ho_scheme,x
        bne @bad_far
        dex
        bpl @sch

        ; host: [a-z0-9.-] (A-Z folded), 1..63, no empty label; ends at
        ; ':', '/', '?' or the NUL. X walks the URL, Y the host.
        ldx #8
        ldy #0
        lda #'.'
        sta ho_prev
@h:     lda cert_buf+HO_O_URL,x
        beq @h_end
        cmp #':'
        beq @h_end
        cmp #'/'
        beq @h_end
        cmp #'?'
        beq @h_end
        cpy #HOST_MAX
        bcs @bad_far
        cmp #'.'
        bne @h_nd
        cmp ho_prev
        beq @bad_far            ; leading '.' or ".."
        bne @h_ok
@h_nd:  cmp #'-'
        beq @h_ok
        cmp #'0'
        bcc @bad_far
        cmp #'9'+1
        bcc @h_ok
        ora #$20
        cmp #'a'
        bcc @bad_far
        cmp #'z'+1
        bcs @bad_far
@h_ok:  sta ho_host,y
        sta ho_prev
        inx
        iny
        bne @h                  ; always
@bad_far:
        jmp @bad
@h_end: sta ho_term
        lda ho_prev
        cmp #'.'
        beq @bad_far            ; empty or trailing '.'
        lda #0
        sta ho_host,y
        sty ho_host_len

        ; port: ":digits", 1..65535; none = 443
        lda #<443
        sta ho_port
        lda #>443
        sta ho_port+1
        lda ho_term
        cmp #':'
        bne @path
        lda #0
        sta ho_port
        sta ho_port+1
        tay                     ; digits seen
        inx
@pd:    lda cert_buf+HO_O_URL,x
        sec
        sbc #'0'
        cmp #10
        bcs @pd_end
        sta ho_term             ; the digit
        lda ho_port             ; port = port * 10 + digit, refusing a carry
        sta ho_c64              ;  (scratch: the DMA block is idle here)
        lda ho_port+1
        sta ho_c64+1
        asl ho_port
        rol ho_port+1
        bcs @bad_far
        asl ho_port
        rol ho_port+1           ; * 4
        bcs @bad_far
        clc
        lda ho_port
        adc ho_c64
        sta ho_port
        lda ho_port+1
        adc ho_c64+1
        sta ho_port+1           ; * 5
        bcs @bad_far
        asl ho_port
        rol ho_port+1           ; * 10
        bcs @bad_far
        clc
        lda ho_port
        adc ho_term
        sta ho_port
        bcc :+
        inc ho_port+1
        beq @bad_p
:       inx
        iny
        cpy #6
        bcc @pd
        bcs @bad_p            ; six digits
@pd_end:
        tya
        beq @bad_p            ; ":" with no digits
        lda ho_port
        ora ho_port+1
        beq @bad_p            ; port 0

        ; path: the rest, '/' prepended when it starts with '?' or is
        ; empty; printable ASCII without space, 1..100. Anything else (CR,
        ; LF, space) could end the request line early.
@path:  ldy #0
        lda cert_buf+HO_O_URL,x
        cmp #'/'
        beq @p
        lda #'/'
        sta ho_path
        iny
@p:     lda cert_buf+HO_O_URL,x
        beq @p_end
        cpy #PATH_MAX
        bcs @bad_p
        cmp #'!'
        bcc @bad_p
        cmp #$7f
        bcs @bad_p
        sta ho_path,y
        inx
        iny
        bne @p                  ; always
@bad_p: jmp @bad
@p_end: sta ho_path,y
        sty ho_path_len
        lda #1
        sta ho_active           ; (a bad request leaves it 0)
@bad:
        lda #0
        sta ho_bank
        lda #HO_SAVE_BANK
        sta ho_bank2
        jsr ho_copy_banks       ; banks 0-2 -> 8-10
        lda #HO_ST_RUNNING
        jsr ho_set_state
        lda ho_active
        beq @bad_msg
        rts
@bad_msg:
        lda #<msg_bad_req
        ldy #>msg_bad_req
        jsr print_string
        jmp handoff_finish

; -----------------------------------------------------------------------------
; ho_copy_banks - copy HO_SAVE_BANKS banks from ho_bank to ho_bank2 through
; cert_buf, 2 KB at a time.
; -----------------------------------------------------------------------------
ho_copy_banks:
        lda #<cert_buf
        sta ho_c64
        lda #>cert_buf
        sta ho_c64+1
        lda #0
        sta ho_len
        lda #>2048
        sta ho_len+1
        ldx #HO_SAVE_BANKS
@bank:  lda #0
        sta ho_reu
        sta ho_reu+1
@chunk: lda ho_bank
        sta ho_reu+2
        lda #CMD_FETCH
        jsr ho_dma
        lda ho_bank2
        sta ho_reu+2
        lda #CMD_STASH
        jsr ho_dma
        clc
        lda ho_reu+1
        adc #>2048
        sta ho_reu+1
        bne @chunk              ; 32 chunks, then the page wraps to 0
        inc ho_bank
        inc ho_bank2
        dex
        bne @bank
        rts

; ho_set_state - A = HO_ST_*, written to the mailbox's state byte.
ho_set_state:
        sta ho_state
        lda #<HO_O_STATE
        sta ho_off
        lda #>HO_O_STATE
        sta ho_off+1
        lda #<ho_state
        ldy #>ho_state
        ldx #1
        jsr ho_at
        lda #CMD_STASH
        jmp ho_dma

; ho_default_ret - the return target when the request names none usable.
ho_default_ret:
        lda #HO_DEF_DEV
        sta ho_rdev
        lda #<HO_DEF_ENTRY
        sta ho_rentry
        lda #>HO_DEF_ENTRY
        sta ho_rentry+1
        ldx #ho_def_name_len
        stx ho_rnlen
        dex
@n:     lda ho_def_name,x
        sta ho_rname,x
        dex
        bpl @n
        rts

; -----------------------------------------------------------------------------
; handoff_run - boot's last act with a valid request (does not return).
; -----------------------------------------------------------------------------
handoff_run:
        lda #HO_R_NO_NET
        sta ho_result
        lda net_initialized
        beq handoff_finish
        jsr do_https_get
        ; fall through

; -----------------------------------------------------------------------------
; handoff_finish - reply, DONE, restore banks 0-2, scrub, load the host.
; -----------------------------------------------------------------------------
handoff_finish:
        jsr ho_hdr_flush
        lda ho_result
        sta ho_reply+0
        lda http_status
        sta ho_reply+1
        lda http_status+1
        sta ho_reply+2
        ldx #2
@len:   lda http_reu_cursor,x
        sta ho_reply+3,x
        lda http_body_total,x
        sta ho_reply+6,x
        dex
        bpl @len
        lda ho_flags
        ldx http_sink_full
        beq :+
        ora #HO_F_SINK_FULL
:       ldx tls_reached_connected
        beq :+
        ora #HO_F_HANDSHAKE
:
.ifdef PQ_HYBRID
        ldx tls_kex_group
        cpx #$EC
        bne :+
        ora #HO_F_HYBRID
:
.endif
        sta ho_reply+9
        lda ho_hpage            ; head length = pages * 256 + index
        sta ho_reply+11
        lda ho_hidx
        sta ho_reply+10
        lda net_last_error
        sta ho_reply+12
.if .defined(HTTPS_PIN_SPKI) .or .defined(TRUST_STORE)
        lda cert_pin_status
        sta ho_reply+13
.endif
        lda #<HO_O_RESULT
        sta ho_off
        lda #>HO_O_RESULT
        sta ho_off+1
        lda #<ho_reply
        ldy #>ho_reply
        ldx #HO_REPLY_LEN
        jsr ho_at
        lda #CMD_STASH
        jsr ho_dma
        lda #HO_SAVE_BANK       ; banks 8-10 -> 0-2
        sta ho_bank
        lda #0
        sta ho_bank2
        jsr ho_copy_banks
        lda #HO_ST_DONE
        jsr ho_set_state
        sei
        jsr session_scrub
        ; fall through

; -----------------------------------------------------------------------------
; ho_exit_quiet - copy the stub to $C000, zero our zero page and the stack
; page (as quit_to_basic does after session_scrub), and run the stub.
; -----------------------------------------------------------------------------
ho_exit_quiet:
        sei
        lda #<msg_return
        ldy #>msg_return
        jsr print_string
        ldx #ho_stub_len-1
@cp:    lda ho_stub_src,x
        sta STUB,x
        dex
        bpl @cp
        lda ho_rdev
        sta s_dev
        lda ho_rentry
        sta s_entry
        lda ho_rentry+1
        sta s_entry+1
        ldx ho_rnlen
        stx s_nlen
        dex
@nm:    lda ho_rname,x
        sta s_name,x
        dex
        bpl @nm
        lda #0
        ldx #$7F - $02
@zp:    sta $02,x
        dex
        bpl @zp
        ldx #$FF - zp_ptr
@zp_hi: sta zp_ptr,x
        dex
        bpl @zp_hi
        inx                     ; X = 0
@st:    sta $0100,x
        inx
        bne @st
        jmp STUB

; The return stub, run at $C000: KERNAL and BASIC in, LOAD name,dev,1, jump.
ho_stub_src:
        .org STUB
        sei
        ldx #$FF
        txs
        lda #$37
        sta $01
        lda #0
        sta $9d                 ; no KERNAL messages
        lda s_nlen
        ldx #<s_name
        ldy #>s_name
        jsr $FFBD               ; SETNAM
        lda #1
        ldx s_dev
        ldy #1
        jsr $FFBA               ; SETLFS
        lda #0
        jsr $FFD5               ; LOAD
        bcs @fail
        jmp (s_entry)
@fail:  jmp $FCE2               ; cold reset: nothing left to go back to
s_entry: .word 0
s_dev:   .byte 0
s_nlen:  .byte 0
s_name:  .res NAME_MAX
s_end:
        .reloc
ho_stub_len = s_end - STUB
.assert ho_stub_len <= 128, error, "handoff stub grew past $C07F"

        .segment "HANDOFF_RODATA"       ; resident, jsr-only: room is here
; -----------------------------------------------------------------------------
; ho_target - do_https_get's target, from the request. C=0 always.
; -----------------------------------------------------------------------------
ho_target:
        ldx #HOST_MAX           ; the validated host, NUL and all
@cp:    lda ho_host,x
        sta tls_hostname,x
        dex
        bpl @cp
        lda ho_host_len
        sta tls_hostname_len
        lda #0
        sta tls_reached_connected
        lda #<tls_hostname
        sta http_host_ptr
        lda #>tls_hostname
        sta http_host_ptr+1
        lda tls_hostname_len
        sta http_host_len
        lda #<ho_path
        sta http_path_ptr
        lda #>ho_path
        sta http_path_ptr+1
        lda ho_path_len
        sta http_path_len
        lda #<msg_get
        ldy #>msg_get
        jsr print_string
        ldx #0
@h:     lda tls_hostname,x
        beq @done
        jsr ascii_chrout
        inx
        bne @h
@done:  lda #$0d
        jsr chrout
        clc
        rts

; -----------------------------------------------------------------------------
; ho_recv_verdict - after http_recv_body: C=0 complete -> HO_R_OK.
; -----------------------------------------------------------------------------
ho_recv_verdict:
        lda #HO_R_RECV
        bcs @inc
        lda ho_flags
        ora #HO_F_COMPLETE
        sta ho_flags
        lda #HO_R_OK
        beq @set                ; always
@inc:   ldx http_sink_full
        beq @set
        lda #HO_R_TOO_BIG
@set:   sta ho_result
        rts

        .segment "HANDOFF_CODE"

; -----------------------------------------------------------------------------
; Response head capture: every byte http.s reads before the body, raw, into
; HO_HDR through a 256 B page. Past HO_HDR_PAGES it is counted as truncated.
; ho_hdr_byte keeps A, X, Y.
; -----------------------------------------------------------------------------
ho_hdr_reset:
        lda #0
        sta ho_hidx
        sta ho_hpage
        lda ho_flags
        and #<~HO_F_HDR_TRUNC
        sta ho_flags
        rts

ho_hdr_byte:
        pha
        lda ho_hpage
        cmp #HO_HDR_PAGES
        bcs @full
        stx ho_tmpx
        ldx ho_hidx
        pla
        pha
        sta ho_hbuf,x
        inc ho_hidx
        bne @out
        jsr ho_hdr_page         ; 256 bytes: stash them, next page
        inc ho_hpage
@out:   ldx ho_tmpx
        pla
        rts
@full:  lda ho_flags
        ora #HO_F_HDR_TRUNC
        sta ho_flags
        pla
        rts

; ho_hdr_flush - the partial last page (handoff_finish).
ho_hdr_flush:
        lda ho_hidx
        beq ho_rts
ho_hdr_page:                    ; ho_len = ho_hidx (0 = 256)
        lda #<ho_hbuf
        sta ho_c64
        lda #>ho_hbuf
        sta ho_c64+1
        lda ho_hidx
        sta ho_len
        lda #0
        sta ho_len+1
        lda ho_hidx
        bne :+
        inc ho_len+1            ; 0 -> 256
:       lda #<HO_HDR
        sta ho_reu
        lda ho_hpage
        clc
        adc #>HO_HDR
        sta ho_reu+1
        lda #^HO_HDR
        sta ho_reu+2
        lda #CMD_STASH
        jmp ho_dma
ho_rts: rts

        .segment "HANDOFF_RODATA"     ; CRYPTO_OVERLAY: NET_BSS_TAIL is full
ho_magic:       .byte "C64HTTPS"
ho_scheme:      .byte "https://"
ho_def_name:    .byte "CD64"
ho_def_name_len = * - ho_def_name
msg_no_reu:     .byte $0d, "HTTPS NEEDS A REU OF 1 MB OR MORE.", $0d
                .byte "PRESS A KEY.", $0d, 0
msg_no_req:     .byte $0d, "NO HTTPS REQUEST IN THE REU.", $0d
                .byte "PRESS A KEY.", $0d, 0
msg_bad_req:    .byte $0d, "BAD HTTPS REQUEST", $0d, 0
msg_get:        .byte "HTTPS GET ", 0
msg_return:     .byte $0d, "RETURNING...", $0d, 0

        .segment "HANDOFF_BSS"
ho_active:      .res 1
ho_result:      .res 1
ho_flags:       .res 1
ho_port:        .res 2
ho_cmd:         .res 1
ho_c64:         .res 2
ho_reu:         .res 3
ho_len:         .res 2
ho_off:         .res 2
ho_bank:        .res 1
ho_bank2:       .res 1
ho_state:       .res 1
ho_prev:        .res 1
ho_term:        .res 1
ho_tmpx:        .res 1
ho_hidx:        .res 1
ho_hpage:       .res 1
ho_rdev:        .res 1
ho_rentry:      .res 2
ho_rnlen:       .res 1
ho_rname:       .res NAME_MAX
ho_host_len:    .res 1
ho_host:        .res HOST_MAX + 1
ho_path_len:    .res 1
ho_path:        .res PATH_MAX + 1
ho_probe_save:  .res 9
ho_reply:       .res HO_REPLY_LEN
ho_hbuf:        .res 256

.endif ; HANDOFF
