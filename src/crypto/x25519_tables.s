; =============================================================================
; x25519_tables.s — lookup tables for the libs/x25519 sibling, generated
; at runtime instead of shipped as RODATA (issue #245).
;
; Upstream's src/data.s declares these as `.repeat`-built RODATA: 2 KB of
; initialized bytes. No shipped profile has 2 KB of free code/RODATA space,
; but every one has room for 2 KB of zero-fill BSS below TABLES_BSS in
; CRYPTO_COLD_SHADOW, so c64-https owns the storage and fills it here.
; The byte values are exactly upstream's:
;
;   mul38_lo_tab[i] / mul38_hi_tab[i]   = lo / hi of i * 38
;   sqr_lo[i] / sqr_hi[i]               = lo / hi of i * i
;   a24_b0..a24_b3[i]                   = byte 0..3 of i * 121665
;
; Every table is page-aligned: the sibling indexes them `abs,x` / `abs,y`
; by a secret byte, and a page-aligned 256-entry table is what keeps each
; access fixed-cycle (upstream docs/CT_ANALYSIS.md).
;
; x25519_tables_init must run before the first x25519_scalarmult /
; x25519_base. src/tls_ecdh.s calls it ahead of both scalar mults, so the
; tables never depend on anything surviving from boot or from an earlier
; handshake. It computes by running sums only (no multiply, no sqtab), so
; it has no ordering dependency on sqtab_init either. Public data only:
; nothing here is secret-dependent.
;
; Cost: 256 iterations of a handful of adds, ~20k cycles (~20 ms at 1 MHz).
; =============================================================================

.setcpu "6502"

.export x25519_tables_init
.export mul38_lo_tab, mul38_hi_tab
.export sqr_lo, sqr_hi
.export a24_b0, a24_b1, a24_b2, a24_b3

A24 = 121665                    ; (486662 - 2) / 4, RFC 7748 §5

.segment "X25519_TABLES"

        .align 256
mul38_lo_tab:   .res 256
mul38_hi_tab:   .res 256
sqr_lo:         .res 256
sqr_hi:         .res 256
a24_b0:         .res 256
a24_b1:         .res 256
a24_b2:         .res 256
a24_b3:         .res 256

.assert (mul38_lo_tab & $FF) = 0, lderror, "mul38_lo_tab must be page-aligned"
.assert (sqr_lo & $FF) = 0, lderror, "sqr_lo must be page-aligned"
.assert (a24_b0 & $FF) = 0, lderror, "a24_b0 must be page-aligned"

.segment "CRYPTO_CODE"

; -----------------------------------------------------------------------------
; x25519_tables_init — fill all eight tables for i = 0..255.
;
; Three running sums, each stored before it is advanced:
;   m   (16 bit) = 38 * i          m += 38
;   s   (16 bit) = i * i           s += 2i + 1
;   t   (32 bit) = 121665 * i      t += 121665
; Clobbers: A, X
; -----------------------------------------------------------------------------
x25519_tables_init:
        lda #0
        ldx #7
@clr:   sta xt_sums,x
        dex
        bpl @clr
        ; X = $FF here; the loop wants X = 0.
        inx

@loop:
        lda xt_m
        sta mul38_lo_tab,x
        lda xt_m+1
        sta mul38_hi_tab,x
        lda xt_s
        sta sqr_lo,x
        lda xt_s+1
        sta sqr_hi,x
        lda xt_t
        sta a24_b0,x
        lda xt_t+1
        sta a24_b1,x
        lda xt_t+2
        sta a24_b2,x
        lda xt_t+3
        sta a24_b3,x

        ; m += 38
        clc
        lda xt_m
        adc #38
        sta xt_m
        bcc :+
        inc xt_m+1
:
        ; s += i, then s += i + 1  (sec folds in the +1)
        txa
        clc
        adc xt_s
        sta xt_s
        bcc :+
        inc xt_s+1
:       txa
        sec
        adc xt_s
        sta xt_s
        bcc :+
        inc xt_s+1
:
        ; t += 121665
        clc
        lda xt_t
        adc #<A24
        sta xt_t
        lda xt_t+1
        adc #>A24
        sta xt_t+1
        lda xt_t+2
        adc #^A24
        sta xt_t+2
        lda xt_t+3
        adc #0
        sta xt_t+3

        inx
        bne @loop
        rts

.segment "CRYPTO_BSS"

xt_sums:
xt_m:   .res 2
xt_s:   .res 2
xt_t:   .res 4

; -----------------------------------------------------------------------------
; Placement asserts for the unions the cfgs build around these buffers.
; ld65 does not check that two memory areas overlap the way we intend, so
; the intent is written down here and checked at link time.
; -----------------------------------------------------------------------------
.import tls_rec_buf
.import __X25519_SCRATCH_START__, __X25519_SCRATCH_SIZE__

; X25519_SCRATCH (the sibling's field buffers) must sit exactly on
; tls_rec_buf and not run past its 548 B.
.assert __X25519_SCRATCH_START__ = tls_rec_buf, lderror, "X25519_SCRATCH must start at tls_rec_buf (cfg BSS_TAIL start= and X25519_SCRATCH start= disagree)"
.assert __X25519_SCRATCH_SIZE__ <= 548, lderror, "X25519_SCRATCH is larger than tls_rec_buf"

.ifdef BACKEND_IP65
.import cert_buf
.import __X25519_TABLES_UNION_START__, __X25519_TABLES_UNION_SIZE__
; ip65: the tables overlay cert_buf, and tls_rec_buf (live during verify)
; must start at or past the union's end.
.assert __X25519_TABLES_UNION_START__ = cert_buf, lderror, "X25519_TABLES_UNION must start at cert_buf"
.assert tls_rec_buf >= __X25519_TABLES_UNION_START__ + __X25519_TABLES_UNION_SIZE__, lderror, "tls_rec_buf overlaps X25519_TABLES_UNION"
.endif
