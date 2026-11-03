; =============================================================================
; tools/uci/handoff_rig.s - the 6502 half of tools/uci/rig_https_handoff.py.
; Assembled by the rig (ca65 + ld65, cfgs written by the rig), never linked
; into the product. Two images:
;
;   -D STUB  page 3 ($0334, the rigs' scratch), run by "SYS0820" instead of
;            the helper's own SYS2061: fill REU banks 0-7 with FILL_n (a
;            stand-in RAM drive), STASH the request's fixed fields (appended
;            by the rig as request.bin) and the URL (the rig writes it to
;            $02A7-$02FF, the other rig scratch, NUL-terminated) to the
;            mailbox, then JMP $080D -- the helper's entry, as a host
;            launches it.
;   -D HOST  "HOST", the program the request names to return to (entry
;            $0810). Checks banks 0-7 byte by byte against FILL_n, then
;            copies the mailbox, the response head and the first 16 KB of
;            the body into C64 RAM, where the rig reads them over REST:
;              $C000-$C1FF  mailbox ($0B0000)
;              $2000-$2FFF  head    ($0B0200)
;              $3000-$6FFF  body    ($0C0000, first 16 KB)
;              $C3F0-$C3F2  bytes in banks 0-7 that differ (24-bit)
;              $C3F8-$C3FB  "DONE"
;
; Every REU execute waits for END OF BLOCK (bit 6), bounded: on a turbo
; Ultimate the REU finishes after the CPU (c64-lib-contract SPEC 8.2).
; =============================================================================

REU_STATUS  = $DF00
REU_CMD     = $DF01
REU_C64     = $DF02
REU_REU     = $DF04
REU_BANK    = $DF06
REU_LEN     = $DF07
REU_CTRL    = $DF0A
URL_AT      = $02A7             ; the URL (STUB), up to $02FF
URL_MAX     = $0300 - URL_AT

        .segment "CODE"

.ifdef STUB
stub:   sei
        ldx #7
@fill:  stx REU_BANK
        txa
        clc
        adc #<fill_tab
        sta REU_C64
        lda #>fill_tab
        adc #0
        sta REU_C64+1
        lda #0
        sta REU_REU
        sta REU_REU+1
        sta REU_LEN             ; length 0 = 64 KB
        sta REU_LEN+1
        lda #$80                ; fixed C64 address: fill
        sta REU_CTRL
        lda #$90
        sta REU_CMD
        jsr wait
        dex
        bpl @fill
        lda #<req
        sta REU_C64
        lda #>req
        sta REU_C64+1
        lda #0
        sta REU_REU
        sta REU_REU+1
        sta REU_CTRL
        lda #$0B
        sta REU_BANK
        lda #<(req_end - req)
        sta REU_LEN
        lda #>(req_end - req)
        sta REU_LEN+1
        lda #$90
        sta REU_CMD
        jsr wait
        lda #<URL_AT            ; the URL: REU address and control as left
        sta REU_C64             ;  above, so $0B0000 + 32 = HO_O_URL
        lda #>URL_AT
        sta REU_C64+1
        lda #$20
        sta REU_REU
        lda #0
        sta REU_REU+1
        lda #$0B
        sta REU_BANK
        lda #URL_MAX
        sta REU_LEN
        lda #0
        sta REU_LEN+1
        lda #$90
        sta REU_CMD
        jsr wait
        cli
        jmp $080D
.endif

.ifdef HOST
        .segment "LOADADDR"
        .word $0801
        .segment "CODE"
        .res $0810 - $0801, $00 ; the request's entry is $0810
host:   sei
        lda #0
        sta errs
        sta errs+1
        sta errs+2
        sta bank
@bank:  ldx bank
        lda fill_tab,x
        sta want
        lda #0
        sta page
@page:  lda #$00                ; 256 B of bank:page00 -> $C000
        sta REU_C64
        lda #$C0
        sta REU_C64+1
        lda #0
        sta REU_REU
        sta REU_LEN
        sta REU_CTRL
        lda page
        sta REU_REU+1
        lda bank
        sta REU_BANK
        lda #1
        sta REU_LEN+1
        lda #$91
        sta REU_CMD
        jsr wait
        ldy #0
@cmp:   lda $C000,y
        cmp want
        beq @ok
        inc errs
        bne @ok
        inc errs+1
        bne @ok
        inc errs+2
@ok:    iny
        bne @cmp
        inc page
        bne @page
        inc bank
        lda bank
        cmp #8
        bne @bank
        ldx #0                  ; the three copies, from copy_tab
@copy:  ldy #0
@reg:   lda copy_tab,x
        sta REU_C64,y
        inx
        iny
        cpy #7
        bne @reg
        lda #0
        sta REU_CTRL
        lda #$91
        sta REU_CMD
        jsr wait
        cpx #copy_end - copy_tab
        bne @copy
        ldx #2
@res:   lda errs,x
        sta $C3F0,x
        dex
        bpl @res
        ldx #3
@done:  lda done_txt,x
        sta $C3F8,x
        dex
        bpl @done
@park:  jmp @park

copy_tab:                       ; C64, REU (3), length
        .word $C000
        .faraddr $0B0000
        .word $0200
        .word $2000
        .faraddr $0B0200
        .word $1000
        .word $3000
        .faraddr $0C0000
        .word $4000
copy_end:
done_txt: .byte "DONE"
errs:   .res 3
bank:   .res 1
page:   .res 1
want:   .res 1
.endif

; wait - END OF BLOCK, at most 256 status reads (the CPU is held during the
; transfer itself; this covers the restore after it). X kept, Y clobbered.
wait:   ldy #0
@w:     bit REU_STATUS
        bvs @r
        dey
        bne @w
@r:     rts

; FILL_n: what bank n holds; distinct per bank, never $00 or $FF (the
; values a no-op DMA or an unbacked read would leave).
fill_tab: .byte $5A, $4B, $78, $69, $1E, $0F, $3C, $2D

.ifdef STUB
req:    .incbin "request.bin"
req_end:
.endif
