; =============================================================================
; entropy.s - SID voice 3 + CIA1 timer initialization for hardware entropy
;
; Must be called before drbg_init_entropy. Sets SID voice 3 to noise
; waveform at maximum frequency, starts CIA1 Timer A in continuous mode.
;
; Converted from entropy.asm (ACME) to ca65. Pure code, no ACME directives
; other than the implicit segment — the whole file is a single routine.
; =============================================================================

.include "constants.inc"

.export entropy_init

.segment "CODE"

; =============================================================================
; entropy_init - Initialize hardware entropy sources
; Clobbers: A
; =============================================================================
entropy_init:
        ; SID voice 3: maximum frequency for fastest oscillation
        lda #$ff
        sta sid_v3_freq_lo      ; $D40E
        sta sid_v3_freq_hi      ; $D40F
        ; Noise waveform (bit 7 = 1, all others 0)
        lda #$80
        sta sid_v3_ctrl         ; $D412
        ; Start CIA1 Timer A in continuous mode
        lda cia1_cra
        ora #$01                ; set start bit
        and #$f7                ; clear one-shot bit (continuous)
        sta cia1_cra
        rts
