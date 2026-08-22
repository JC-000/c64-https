; =============================================================================
; viewer.s — REU-backed scrolling text viewer (Lane G stretch goal)
;
; Lets a human scroll through a large ASCII document stored in the REU
; (sunk there by the HTTP body-sink lane) on the 40x25 screen.
;
; UCI-only: the whole file is gated on BACKEND_UCI so the ip65 build
; stays byte-identical (this TU assembles to an empty object there).
;
; Document contract (agreed with the body-sink lane):
;   - raw ASCII bytes, LF line endings, arbitrary line length, in the
;     REU at HTTP_REU_BODY_BASE (default $10:0000 = bank 16)
;   - 24-bit little-endian length in `http_body_total`
;
; Display model:
;   - row 0      : status line  "OOOOOO/TTTTTT  Q=QUIT" (hex offset/total)
;   - rows 1-24  : 24 content rows, hard-wrapped at 40 columns
;   - LF starts a new row; a single LF immediately after a 40-column
;     hard wrap is consumed (no phantom blank row); CR is ignored;
;     TAB renders as a space; ASCII $20-$5F map to screen codes
;     directly, a-z fold to the uppercase glyphs, everything else is
;     a space. Mirrors boot.s::ascii_chrout strategy B, but writes
;     screen RAM ($0400) directly for speed.
;
; Keys (KERNAL GETIN):
;   CRSR-DOWN ($11) scroll down one row     CRSR-UP ($91) up one row
;   SPACE     ($20) page down (24 rows)     F1      ($85) page up
;   HOME      ($13) top                     Q ($51/$71)   quit (rts)
;
; Scrolling model: a 24-bit document offset of the top displayed row
; (`viewer_offset`). Every render DMAs a 3,584 B window from the REU
; into tcp_recv_buf ($C000 — dead ring after the connection closes)
; positioned 1,024 B before the top offset, and re-renders the full
; screen. Scroll-down / page-down take the next row start from a
; 25-entry row-start table recorded during the render (at $CE00,
; inside the reclaimed ring — zero BSS). Scroll-up scans backward in
; the window for the previous LF and derives the previous display-row
; start as P + 40*floor((n-1)/40) (P = previous logical line start,
; n = its length), which reproduces exactly the row starts forward
; rendering would produce. If no LF exists within the ~1 KB of back
; window (a logical line longer than 1 KB), it falls back to top-40,
; which is still forward-consistent for any line that long unless the
; line *ends* inside that kilobyte (rare; display re-syncs at the
; next LF).
;
; REU discipline: the viewer only FETCHes (REU->C64); document banks
; and the crypto banks 0-2 are never written. The REU address/length
; shadow registers ARE clobbered by our DMAs, and reu_fetch_mul_row
; relies on the latched values reu_mul_init leaves behind — so entry
; saves $DF02-$DF08/$DF0A and exit restores them (slot at $CEF0/$CEF8,
; inside the reclaimed ring page).
;
; Zero-page: reuses zp_ptr ($FB-$FC). The viewer only runs while no
; TLS/HTTP/crypto is in flight, so the time-share is safe.
; =============================================================================

.ifdef BACKEND_UCI

        .include "constants.inc"
        .macpack cbm

        .export viewer_enter
        .export viewer_render_at
        .export viewer_offset

        ; --- body-sink lane contract -------------------------------------
        ; The REU base of the document. -D-overridable for tests (VICE
        ; uses a 512 KB REU, so tests build with a base inside it, e.g.
        ; make HTTP_REU_BODY_BASE=196608 = $03:0000). The body-sink lane
        ; exports the canonical equate; this .ifndef merges cleanly with
        ; a -D from the command line either way.
        .ifndef HTTP_REU_BODY_BASE
        HTTP_REU_BODY_BASE = $100000
        .endif

        ; http_body_total (24-bit LE de-chunked body length) is owned
        ; by the W4 body sink: defined + exported in src/data.s,
        ; maintained by src/http.s.  (The pre-merge PROVISIONAL
        ; fallback block and its VIEWER_EXTERNAL_SINK guard were
        ; deleted at merge resolution, as its header prescribed.)
        .import http_body_total

; -----------------------------------------------------------------------------
; Constants
; -----------------------------------------------------------------------------
SCREEN          = $0400
STATUS_ROW      = SCREEN                ; row 0
CONTENT_ROW0    = SCREEN + 40           ; row 1
COLOR_RAM       = $d800
VW_ROWS         = 24                    ; content rows
VW_COLS         = 40

VW_WIN_BUF      = tcp_recv_buf          ; $C000 bounce buffer
VW_WIN_SIZE     = $0e00                 ; 3,584 B window
VW_WIN_BACK     = $0400                 ; keep 1 KB before top for back-scans

VW_TBL          = $ce00                 ; 25 row starts x 3 B (in dead ring)
VW_REU_SAVE1    = $cef0                 ; 9 B REU shadow save (viewer_enter)
VW_REU_SAVE2    = $cefa                 ; 9 B REU shadow save (viewer_render_at)

KEY_CRSR_DOWN   = $11
KEY_CRSR_UP     = $91
KEY_SPACE       = $20
KEY_F1          = $85
KEY_HOME        = $13
KEY_Q           = $51
KEY_Q_LC        = $71

; -----------------------------------------------------------------------------
; BSS  (NET_BSS_TAIL — 20 bytes production)
; -----------------------------------------------------------------------------
        .segment "NET_BSS_TAIL"

viewer_offset:                          ; 24-bit doc offset of top row
vw_top:         .res 3
vw_win:         .res 3                  ; doc offset of window start
vw_wok:         .res 1                  ; window-valid flag
vw_cur:         .res 3                  ; render cursor (doc offset)
vw_req:         .res 3                  ; ensure_window request offset
vw_tmp:         .res 3                  ; scratch (24-bit / scan counter)
vw_cnt:         .res 2                  ; scratch (16-bit index)
vw_row:         .res 1                  ; current content row
vw_tbi:         .res 1                  ; row-table byte index

        .ifdef VIEWER_TEST_HELPERS
        .export viewer_blit_off
viewer_blit_off: .res 3                 ; test blit: doc offset of chunk
        .endif

; -----------------------------------------------------------------------------
        .segment "VIEWER_CODE"

; =============================================================================
; viewer_enter — interactive viewer. Returns (rts) on Q.
; =============================================================================
viewer_enter:
        jsr reu_save1
        lda #0
        sta vw_wok                      ; document may have changed
        jsr top_zero
        jsr fill_color
        jsr render_core
@key:
        jsr getin
        cmp #0
        beq @key
        cmp #KEY_Q
        beq @quit
        cmp #KEY_Q_LC
        beq @quit
        cmp #KEY_CRSR_DOWN
        beq @down
        cmp #KEY_CRSR_UP
        beq @up
        cmp #KEY_SPACE
        beq @pgdn
        cmp #KEY_F1
        beq @pgup
        cmp #KEY_HOME
        bne @key
        jsr top_zero                    ; HOME -> top
        jmp @redraw
@down:
        ldx #(3*1)                      ; next row start = table entry 1
        jsr take_tbl_entry
        jmp @redraw
@up:
        jsr scroll_up_one
        jmp @redraw
@pgdn:
        ldx #(3*VW_ROWS)                ; entry 24 = next screen top
        jsr take_tbl_entry
        jmp @redraw
@pgup:
        lda #VW_ROWS
        sta vw_row
@pgup_l:
        jsr scroll_up_one
        dec vw_row
        bne @pgup_l
@redraw:
        jsr render_core
        jmp @key
@quit:
        jsr reu_restore1
        rts

; =============================================================================
; viewer_render_at — non-interactive: render one screen at viewer_offset.
; Preserves the REU shadow registers around its own DMAs.
; =============================================================================
viewer_render_at:
        ldx #8                          ; save shadows $DF02..$DF0A to slot 2
@sv:    lda reu_c64_lo,x
        sta VW_REU_SAVE2,x
        dex
        bpl @sv
        lda #0
        sta vw_wok                      ; test may have re-blitted the doc
        jsr render_core
        ldx #8
@rs:    lda VW_REU_SAVE2,x
        sta reu_c64_lo,x
        dex
        bpl @rs
        rts

; -----------------------------------------------------------------------------
; reu_save1 / reu_restore1 — shadow-register save around a viewer session.
; reu_fetch_mul_row (REU profile) relies on the latched C64 addr/len that
; reu_mul_init leaves behind; our FETCHes clobber them. The whole
; contiguous $DF02-$DF0A span is saved (the $DF09 interrupt-mask
; readback/writeback is a no-op, and including it makes the copy a
; plain indexed loop).
; -----------------------------------------------------------------------------
reu_save1:
        ldx #8
@l:     lda reu_c64_lo,x
        sta VW_REU_SAVE1,x
        dex
        bpl @l
        rts

reu_restore1:
        ldx #8
@l:     lda VW_REU_SAVE1,x
        sta reu_c64_lo,x
        dex
        bpl @l
        rts

; -----------------------------------------------------------------------------
top_zero:
        lda #0
        sta vw_top
        sta vw_top+1
        sta vw_top+2
        rts

; -----------------------------------------------------------------------------
; take_tbl_entry — X = byte index of a row-start table entry. Copies it to
; vw_top unless it would land at/after http_body_total (clamp at bottom).
; -----------------------------------------------------------------------------
take_tbl_entry:
        lda VW_TBL,x                    ; entry >= total ? -> no move
        cmp http_body_total
        lda VW_TBL+1,x
        sbc http_body_total+1
        lda VW_TBL+2,x
        sbc http_body_total+2
        bcs @no
        lda VW_TBL,x
        sta vw_top
        lda VW_TBL+1,x
        sta vw_top+1
        lda VW_TBL+2,x
        sta vw_top+2
@no:    rts

; =============================================================================
; render_core — render status + 24 content rows from vw_top.
; Records the 24 row-start offsets plus the next-screen top in VW_TBL.
; =============================================================================
render_core:
        lda http_body_total
        ora http_body_total+1
        ora http_body_total+2
        bne @go
        jmp @empty
@go:
        lda vw_top
        sta vw_cur
        sta vw_req
        lda vw_top+1
        sta vw_cur+1
        sta vw_req+1
        lda vw_top+2
        sta vw_cur+2
        sta vw_req+2
        jsr ensure_window
        jsr draw_status

        lda #<CONTENT_ROW0
        sta row_store+1
        lda #>CONTENT_ROW0
        sta row_store+2
        lda #0
        sta vw_row
        sta vw_tbi
@rowloop:
        ldx vw_tbi                      ; record row start
        lda vw_cur
        sta VW_TBL,x
        lda vw_cur+1
        sta VW_TBL+1,x
        lda vw_cur+2
        sta VW_TBL+2,x
        inx
        inx
        inx
        stx vw_tbi
        jsr render_row
        clc                             ; store base += 40
        lda row_store+1
        adc #VW_COLS
        sta row_store+1
        lda row_store+2
        adc #0
        sta row_store+2
        inc vw_row
        lda vw_row
        cmp #VW_ROWS
        bne @rowloop
        ldx vw_tbi                      ; entry 24 = next-screen top
        lda vw_cur
        sta VW_TBL,x
        lda vw_cur+1
        sta VW_TBL+1,x
        lda vw_cur+2
        sta VW_TBL+2,x
        rts
@empty:
        jsr clear_screen
        ldx #(empty_txt_end - empty_txt - 1)
@el:    lda empty_txt,x
        sta STATUS_ROW,x
        dex
        bpl @el
        rts

; -----------------------------------------------------------------------------
; render_row — render one 40-column row at the SMC base in row_store,
; advancing vw_cur. Blank-fills after LF / EOF. Consumes a single LF
; that immediately follows a 40-column hard wrap.
; -----------------------------------------------------------------------------
render_row:
        ldx #0
@loop:
        jsr at_eof
        bcs @fill
        jsr getbyte
        cmp #$0a
        beq @lf
        cmp #$0d
        beq @cr
        cmp #$09
        bne @conv
        lda #$20
@conv:
        jsr conv_ascii
        jsr row_store
        jsr inc_cur
        inx
        cpx #VW_COLS
        bne @loop
        jsr at_eof                      ; wrapped: eat one trailing LF
        bcs @done
        jsr getbyte
        cmp #$0a
        bne @done
        jsr inc_cur
@done:  rts
@cr:
        jsr inc_cur                     ; CR: skip, no column advance
        jmp @loop
@lf:
        jsr inc_cur                     ; LF: consume, blank rest of row
@fill:
        lda #$20
@fl:    cpx #VW_COLS
        beq @done
        jsr row_store
        inx
        bne @fl

row_store:
        sta CONTENT_ROW0,x              ; operand patched by render_core
        rts

; -----------------------------------------------------------------------------
; at_eof — C=1 when vw_cur >= http_body_total.
; -----------------------------------------------------------------------------
at_eof:
        lda vw_cur
        cmp http_body_total
        lda vw_cur+1
        sbc http_body_total+1
        lda vw_cur+2
        sbc http_body_total+2
        rts

inc_cur:
        inc vw_cur
        bne @r
        inc vw_cur+1
        bne @r
        inc vw_cur+2
@r:     rts

; -----------------------------------------------------------------------------
; conv_ascii — ASCII in A -> screen code in A (uppercase/graphics set).
; $20-$3F direct; $40-$5F -> $00-$1F; a-z -> $01-$1A (uppercase glyphs);
; everything else -> space. Preserves X/Y.
; -----------------------------------------------------------------------------
conv_ascii:
        cmp #$20
        bcc @sp
        cmp #$40
        bcc @ok                         ; $20-$3F
        cmp #$60
        bcc @upper                      ; $40-$5F
        cmp #$61
        bcc @sp                         ; $60 backtick
        cmp #$7b
        bcs @sp                         ; $7B-$FF
        sec
        sbc #$60                        ; a-z -> $01-$1A
        rts
@upper:
        sec
        sbc #$40                        ; @A-Z[\]^_ -> $00-$1F
        rts
@sp:    lda #$20
@ok:    rts

; -----------------------------------------------------------------------------
; getbyte — byte at doc offset vw_cur from the window, refreshing the
; window if vw_cur is outside it. Preserves X. Clobbers Y, zp_ptr.
; -----------------------------------------------------------------------------
getbyte:
        sec                             ; t = vw_cur - vw_win
        lda vw_cur
        sbc vw_win
        sta zp_ptr
        lda vw_cur+1
        sbc vw_win+1
        sta zp_ptr+1
        lda vw_cur+2
        sbc vw_win+2
        bne @refresh                    ; t >= 64 KB
        lda vw_wok
        beq @refresh
        lda zp_ptr+1
        cmp #>VW_WIN_SIZE
        bcs @refresh                    ; t >= window size
        clc
        adc #>VW_WIN_BUF
        sta zp_ptr+1
        ldy #0
        lda (zp_ptr),y
        rts
@refresh:
        lda vw_cur
        sta vw_req
        lda vw_cur+1
        sta vw_req+1
        lda vw_cur+2
        sta vw_req+2
        jsr ensure_window
        jmp getbyte

; -----------------------------------------------------------------------------
; ensure_window — make the bounce window cover vw_req with ~1 KB of
; back-coverage. Skips the DMA when the desired window is already
; loaded. Window start = max(vw_req - VW_WIN_BACK, 0).
; Clobbers A. Preserves X/Y.
; -----------------------------------------------------------------------------
ensure_window:
        sec
        lda vw_req
        sbc #<VW_WIN_BACK
        sta vw_tmp
        lda vw_req+1
        sbc #>VW_WIN_BACK
        sta vw_tmp+1
        lda vw_req+2
        sbc #0
        sta vw_tmp+2
        bcs @have_ws
        lda #0                          ; clamp to document start
        sta vw_tmp
        sta vw_tmp+1
        sta vw_tmp+2
@have_ws:
        lda vw_wok
        beq @load
        lda vw_tmp                      ; same window already loaded?
        cmp vw_win
        bne @load
        lda vw_tmp+1
        cmp vw_win+1
        bne @load
        lda vw_tmp+2
        cmp vw_win+2
        beq @done
@load:
        lda vw_tmp
        sta vw_win
        lda vw_tmp+1
        sta vw_win+1
        lda vw_tmp+2
        sta vw_win+2
        lda #1
        sta vw_wok
        clc                             ; REU addr = base + window start
        lda vw_win
        adc #<HTTP_REU_BODY_BASE
        sta reu_reu_lo
        lda vw_win+1
        adc #>HTTP_REU_BODY_BASE
        sta reu_reu_hi
        lda vw_win+2
        adc #^HTTP_REU_BODY_BASE
        sta reu_reu_bank
        lda #<VW_WIN_BUF
        sta reu_c64_lo
        lda #>VW_WIN_BUF
        sta reu_c64_hi
        lda #<VW_WIN_SIZE
        sta reu_len_lo
        lda #>VW_WIN_SIZE
        sta reu_len_hi
        lda #0
        sta reu_addr_ctrl
        lda #%10110001                  ; execute + autoload + FETCH (REU->C64)
        sta reu_command
@done:  rts

; =============================================================================
; scroll_up_one — move vw_top to the previous display-row start.
; See the header for the derivation. No-op at offset 0.
; =============================================================================
scroll_up_one:
        lda vw_top
        ora vw_top+1
        ora vw_top+2
        beq @done
        lda vw_top
        sta vw_req
        lda vw_top+1
        sta vw_req+1
        lda vw_top+2
        sta vw_req+2
        jsr ensure_window
        sec                             ; idx_top = vw_top - vw_win (16-bit)
        lda vw_top
        sbc vw_win
        sta vw_cnt
        lda vw_top+1
        sbc vw_win+1
        sta vw_cnt+1
        sec                             ; zp_ptr -> window byte idx_top-1
        lda vw_cnt
        sbc #1
        sta zp_ptr
        lda vw_cnt+1
        sbc #0
        clc
        adc #>VW_WIN_BUF
        sta zp_ptr+1
        ldy #0
        lda (zp_ptr),y
        cmp #$0a
        beq @at_line_start
@sub40:
        sec                             ; mid logical line: top -= 40
        lda vw_top
        sbc #40
        sta vw_top
        lda vw_top+1
        sbc #0
        sta vw_top+1
        lda vw_top+2
        sbc #0
        sta vw_top+2
        bcs @done
        jmp top_zero                    ; underflow guard -> 0
@done:  rts

@at_line_start:
        lda vw_cnt+1                    ; idx_top < 2 -> top = 0
        bne @scan
        lda vw_cnt
        cmp #2
        bcs @scan
        jmp top_zero
@scan:
        sec                             ; zp_ptr -> idx_top-2, scan back for LF
        lda vw_cnt
        sbc #2
        sta zp_ptr
        lda vw_cnt+1
        sbc #0
        clc
        adc #>VW_WIN_BUF
        sta zp_ptr+1
        lda #0                          ; c = 0 (16-bit in vw_tmp)
        sta vw_tmp
        sta vw_tmp+1
@sloop:
        lda (zp_ptr),y                  ; Y still 0
        cmp #$0a
        beq @found
        lda zp_ptr                      ; at window index 0?
        bne @dec
        lda zp_ptr+1
        cmp #>VW_WIN_BUF
        beq @floor
@dec:
        lda zp_ptr
        bne @d1
        dec zp_ptr+1
@d1:    dec zp_ptr
        inc vw_tmp
        bne @sloop
        inc vw_tmp+1
        jmp @sloop
@floor:
        lda vw_win                      ; window start = doc start?
        ora vw_win+1
        ora vw_win+2
        beq @mod                        ; doc start: m = c
        jmp @sub40                      ; >1 KB logical line: fallback top-40
@found:
        lda vw_tmp                      ; c == 0 -> empty prev line: top -= 1
        ora vw_tmp+1
        bne @have_m
        sec
        lda vw_top
        sbc #1
        sta vw_top
        lda vw_top+1
        sbc #0
        sta vw_top+1
        lda vw_top+2
        sbc #0
        sta vw_top+2
        rts
@have_m:
        lda vw_tmp                      ; m = c - 1
        bne @m1
        dec vw_tmp+1
@m1:    dec vw_tmp
@mod:
        lda vw_tmp+1                    ; r = m mod 40
        bne @msub
        lda vw_tmp
        cmp #40
        bcc @modok
@msub:
        sec
        lda vw_tmp
        sbc #40
        sta vw_tmp
        lda vw_tmp+1
        sbc #0
        sta vw_tmp+1
        jmp @mod
@modok:
        lda vw_tmp                      ; top -= (r + 2)
        clc
        adc #2
        sta vw_tmp
        sec
        lda vw_top
        sbc vw_tmp
        sta vw_top
        lda vw_top+1
        sbc #0
        sta vw_top+1
        lda vw_top+2
        sbc #0
        sta vw_top+2
        rts

; -----------------------------------------------------------------------------
; draw_status — row 0: "OOOOOO/TTTTTT  Q=QUIT" + space padding.
; -----------------------------------------------------------------------------
draw_status:
        ldy #0
        lda vw_top+2
        jsr hex_byte
        lda vw_top+1
        jsr hex_byte
        lda vw_top
        jsr hex_byte
        lda #$2f                        ; '/'
        sta STATUS_ROW,y
        iny
        lda http_body_total+2
        jsr hex_byte
        lda http_body_total+1
        jsr hex_byte
        lda http_body_total
        jsr hex_byte
        ldx #0
@txt:
        cpx #(status_txt_end - status_txt)
        bcs @pad
        lda status_txt,x
        inx
        bne @put
@pad:
        lda #$20
@put:
        sta STATUS_ROW,y
        iny
        cpy #VW_COLS
        bne @txt
        rts

hex_byte:
        pha
        lsr
        lsr
        lsr
        lsr
        jsr hex_dig
        pla
        and #$0f
hex_dig:
        cmp #10
        bcc @num
        sbc #9                          ; 10..15 -> $01-$06 (screen A-F)
        bne @sta
@num:
        ora #$30                        ; 0..9 -> $30-$39
@sta:
        sta STATUS_ROW,y
        iny
        rts

; -----------------------------------------------------------------------------
; clear_screen / fill_color
; -----------------------------------------------------------------------------
clear_screen:
        ldx #0
        lda #$20
@l:     sta SCREEN,x
        sta SCREEN+250,x
        sta SCREEN+500,x
        sta SCREEN+750,x
        inx
        cpx #250
        bne @l
        rts

fill_color:
        ldx #0
        lda $0286                       ; current text colour
@l:     sta COLOR_RAM,x
        sta COLOR_RAM+250,x
        sta COLOR_RAM+500,x
        sta COLOR_RAM+750,x
        inx
        cpx #250
        bne @l
        rts

; -----------------------------------------------------------------------------
; rodata (rides VIEWER_CODE)
; -----------------------------------------------------------------------------
status_txt:
        scrcode "  Q=QUIT"
status_txt_end:
empty_txt:
        scrcode "EMPTY"
empty_txt_end:

; =============================================================================
; Test helpers — assembled only with -D VIEWER_TEST_HELPERS=1.
; =============================================================================
        .ifdef VIEWER_TEST_HELPERS
        .export viewer_test_blit
        .export viewer_scroll_up

; viewer_test_blit — STASH 4,096 B from tcp_recv_buf ($C000) to the REU
; at HTTP_REU_BODY_BASE + viewer_blit_off. Lets the VICE harness build
; a multi-KB document in the REU 4 KB at a time.
viewer_test_blit:
        clc
        lda viewer_blit_off
        adc #<HTTP_REU_BODY_BASE
        sta reu_reu_lo
        lda viewer_blit_off+1
        adc #>HTTP_REU_BODY_BASE
        sta reu_reu_hi
        lda viewer_blit_off+2
        adc #^HTTP_REU_BODY_BASE
        sta reu_reu_bank
        lda #<VW_WIN_BUF
        sta reu_c64_lo
        lda #>VW_WIN_BUF
        sta reu_c64_hi
        lda #0
        sta reu_len_lo
        sta reu_addr_ctrl
        lda #$10
        sta reu_len_hi                  ; 4,096 B
        lda #%10110000                  ; execute + autoload + STASH (C64->REU)
        sta reu_command
        lda #0
        sta vw_wok                      ; document changed under the window
        rts

; viewer_scroll_up — one scroll-up step from viewer_offset (updates it,
; no render). Exposes the backward-scan logic to the VICE harness.
viewer_scroll_up:
        jmp scroll_up_one
        .endif

.endif ; BACKEND_UCI
