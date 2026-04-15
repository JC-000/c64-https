; src/macros.inc — shared assembly macros for c64-https
;
; Scope rule: a pattern lives here only if it appears 3+ times AND
; hides nothing load-bearing. When in doubt, inline.

.macro ldax addr
    lda addr
    ldx addr+1
.endmacro

.macro stax addr
    sta addr
    stx addr+1
.endmacro

.macro setptr zp, addr
    lda #<(addr)
    sta zp
    lda #>(addr)
    sta zp+1
.endmacro

.macro add16 dst, src
    clc
    lda dst
    adc src
    sta dst
    lda dst+1
    adc src+1
    sta dst+1
.endmacro

.macro sub16 dst, src
    sec
    lda dst
    sbc src
    sta dst
    lda dst+1
    sbc src+1
    sta dst+1
.endmacro

.macro inc16 addr
    inc addr
    bne :+
    inc addr+1
:
.endmacro

.macro dec16 addr
    lda addr
    bne :+
    dec addr+1
:   dec addr
.endmacro

.macro screen_marker msg
    lda #<msg
    ldx #>msg
    jsr print_null_terminated
.endmacro
