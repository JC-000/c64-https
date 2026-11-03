#importonce
//========================================================
// apps/web/web_tls.asm - https:// via het HTTPS-hulpprogramma
// Commodore Desk 64
//
// Een C64 kan wel TLS 1.3: het programma HTTPS (c64-https, gebouwd met
// HANDOFF=1) doet de verbinding. WEB zet het adres in een REU-postbus,
// start HTTPS, en HTTPS laadt CD64 terug als de pagina in de REU staat.
// Contract: c64-https docs/handoff.md / src/handoff.inc (postbus v1).
//
// WEB zelf bevat alleen hx_Fetch / hx_Init / hx_Load (de overlay is vol);
// de rest staat in WEBTLS ($7000, het gebied van de F1-help, die dan niet
// open kan zijn) en wordt geladen als hij nodig is.
//
//   hx_Fetch  vanuit nt_Fetch voor een https-adres: staat er een antwoord
//             klaar (hxPend), dan gaat het door nt_Rx zoals van het
//             netwerk; anders: verzoek schrijven en HTTPS starten.
//   hx_Init   aan het eind van wb_Init: komt CD64 net terug van HTTPS
//             ($02FF = HX_FLAG), dan het adres uit de postbus terug in
//             WB_NEW en nv_Go (die via nt_Fetch het antwoord laat zien).
// Nodig: Ultimate (UCI) en een REU van 1 MB of meer. Een https-pagina
// kost een volledige TLS-verbinding (ca. 45 s op 48 MHz).
//========================================================
.const HX_FLAG  = $a5
.label HX_MARK  = $02ff          // vrij in de KERNAL en in CD64
.label HX_BOX   = WB_HREF        // postbus $0B0000-$0B018F (400 bytes)
.label HX_BUF   = mnLine         // 128 bytes per keer uit de REU
.const HX_CHUNK = 128

// ---- in WEB ------------------------------------------------------
hx_Fetch: {
        jsr hx_Load
        bcs f
        jmp HXT_FETCH
f:      lda #$39                 // geen WEBTLS: code 99
        sta sHxN
        sta sHxN+1
        ldx #<sWbHttps
        ldy #>sWbHttps
        clc
        rts
}

hx_Init: {
        lda HX_MARK
        cmp #HX_FLAG
        bne r
        jsr hx_Load
        bcs r
        jmp HXT_INIT
r:      rts
}

// hx_Load - WEBTLS van drive 8 naar $7000. Carry=1: niet gelukt.
hx_Load: {
        jsr cfg_io_begin
        lda #6
        ldx #<nm
        ldy #>nm
        jsr K_SETNAM
        lda #1
        ldx #8
        ldy #1
        jsr K_SETLFS
        lda #0
        jsr K_LOAD
        php
        jsr cfg_io_end
        plp
        rts
.encoding "ascii"
nm:     .text "WEBTLS"
.encoding "screencode_upper"
}
hxPend: .byte 0                  // er staat een antwoord klaar (hx_Init)

// ---- in WEBTLS ($7000) -------------------------------------------
.segment WebTls
.label HXT_FETCH = *
        jmp hxt_Fetch
.label HXT_INIT = *
        jmp hxt_Init

hxt_Fetch: {
        lda hxPend
        bne rp
        ldx #hxTTpl-hxT          // verzoek: vaste kop + het adres
        lda #$90
        jsr hx_Dma
        ldx #hxTUrl-hxT
        lda #$90
        jsr hx_Dma
        lda #HX_FLAG
        sta HX_MARK
        ldx #4                   // PRG "HTTPS" van drive 8
n:      lda hxPrg,x
        sta $03c0,x
        dex
        bpl n
        lda #5
        sta $03bf
        lda #8
        sta $03be
        lda #<hxDisp
        sta r0
        lda #>hxDisp
        sta r0+1
        jsr launch_Screen
        jmp launchCommon         // keert niet terug
rp:     lda #0
        sta hxPend
        ldx #hxTBox-hxT          // postbus lezen, daarna leeg (IDLE)
        lda #$91
        jsr hx_Dma
        ldx #hxTSt-hxT
        lda #$90
        jsr hx_Dma
        lda #1                   // geen antwoord (geen REU, of HTTPS
        ldx HX_BOX+$09           //  kwam niet zo ver): code 1
        cpx #3                   // DONE?
        bne f
        lda HX_BOX+$180          // uitslag; WB_HREF is straks van de HTML
        sta hxRes
        lda HX_BOX+$183          // inhoud: lengte bewaren
        sta hxBody
        lda HX_BOX+$184
        sta hxBody+1
        lda HX_BOX+$185
        sta hxBody+2
        lda HX_BOX+$18a          // kop: $0B0200, lengte HX_BOX+$18A
        ldx HX_BOX+$18b
        ldy #0
        jsr hx_Len
        lda #$02
        ldx #$0b
        jsr hx_Feed
        lda hxBody               // inhoud: $0C0000
        ldx hxBody+1
        ldy hxBody+2
        jsr hx_Len
        lda #$00
        ldx #$0c
        jsr hx_Feed
        lda hxRes                // 0 = alles ontvangen
        bne f
        lda hdSt                 // (een antwoord met een kop)
        beq f
        sec
        rts
f:                               // "HTTPS FAILED, CODE nn"
        ldx #$2f
        sec
d:      inx
        sbc #10
        bcs d
        adc #$3a
        stx sHxN
        sta sHxN+1
        ldx #<sWbHttps
        ldy #>sWbHttps
        clc
        rts
}

// hxt_Init - via hx_Init: het adres terug in WB_NEW en erheen.
hxt_Init: {
        lda #0
        sta HX_MARK
        sta ntPush
        ldx #hxTUrlB-hxT
        lda #$91
        jsr hx_Dma
        inc hxPend
        jmp nv_Go
}

// hx_Len - A/X/Y = 24-bits lengte -> hxN.
hx_Len: {
        sta hxN
        stx hxN+1
        sty hxN+2
        rts
}

// hx_Feed - hxN bytes vanaf REU X:A00 (bank X, pagina A) door nt_Rx,
//           tot de pagina vol is of de link gevonden (zoals nt_Fetch).
hx_Feed: {
        stx hxTBuf+4
        sta hxTBuf+3
        lda #0
        sta hxTBuf+2
lp:     lda hxN
        ora hxN+1
        ora hxN+2
        beq r
        lda htFull
        ora htFound
        bne r
        ldx #hxTBuf-hxT
        lda #$91
        jsr hx_Dma
        ldy #0
b:      sty hxY
        lda HX_BUF,y
        jsr nt_Rx
        lda hxN                  // hxN - 1
        bne d1
        lda hxN+1
        bne d2
        dec hxN+2
d2:     dec hxN+1
d1:     dec hxN
        lda hxN                  // op: klaar (niet verder dan de lengte)
        ora hxN+1
        ora hxN+2
        beq r
        ldy hxY
        iny
        cpy #HX_CHUNK
        bne b
        lda hxTBuf+2             // volgende 128 bytes
        eor #HX_CHUNK
        sta hxTBuf+2
        bne lp
        inc hxTBuf+3
        bne lp
        inc hxTBuf+4
        jmp lp
r:      rts
}

// hx_Dma - REU-opdracht A met blok X uit hxT (C64, REU, lengte).
hx_Dma: {
        pha
        ldy #0
l:      lda hxT,x
        sta $df02,y
        inx
        iny
        cpy #7
        bne l
        lda #0
        sta $df0a
        pla
        sta $df01
        ldy #0                   // klaar (bit 6): op een Ultimate met turbo
w:      bit $df00                //  loopt de REU na de CPU; zonder REU
        bvs r                    //  niet eindeloos wachten
        dey
        bne w
r:      rts
}

// REU-blokken: C64-adres, REU-adres (3), lengte.
hxT:
hxTTpl: .word hxTpl
        .byte $00, $00, $0b
        .word hxTplE-hxTpl
hxTUrl: .word WB_NEW
        .byte $20, $00, $0b
        .word 320
hxTUrlB: .word WB_NEW
        .byte $20, $00, $0b
        .word 320
hxTBox: .word HX_BOX
        .byte $00, $00, $0b
        .word $190
hxTSt:  .word hxZero
        .byte $09, $00, $0b
        .word 1
hxTBuf: .word HX_BUF
        .byte $00, $00, $00
        .word HX_CHUNK

// vaste kop van het verzoek: "C64HTTPS", versie 1, REQUEST, drive 8,
// naam 4 lang, terug naar $0810, naam "CD64"
.encoding "ascii"
hxTpl:  .text "C64HTTPS"
        .byte 1, 1, 8, 4
        .word $0810
        .text "CD64"
hxTplE:
hxPrg:  .text "HTTPS"
.encoding "screencode_upper"
hxDisp: .text "HTTPS"
        .byte $ff
hxZero: .byte 0
hxY:    .byte 0
hxN:    .fill 3, 0
hxRes:  .byte 0
hxBody: .fill 3, 0

.segment Web
