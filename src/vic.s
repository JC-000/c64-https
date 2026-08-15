; =============================================================================
; src/vic.s — VIC-II blanking around the CPU-bound crypto primitives.
;
; Clearing DEN (bit 4 of $D011) stops the VIC-II fetching character and
; sprite data, which removes the badline DMA that steals the 6510's bus for
; 40-43 cycles on every eighth raster line.
;
; c64-https shipped without any blanking at all until this file landed, so
; every consumer PRG was paying that tax across a handshake that runs for
; 82 s on a U64E at 48 MHz and ~36 minutes on a stock C64 over ip65.
;
; ---------------------------------------------------------------------
; WHAT IT IS ACTUALLY WORTH — 6.3%, NOT 20-25%
; ---------------------------------------------------------------------
; The figure repeated across this fleet is wrong and this file is where
; that gets corrected. `c64-nist-curves` and `c64-x25519` both ship their
; own vic_blank/vic_unblank and label every benchmark table "VIC blanked";
; c64-https's own tools/bench_x25519.py carried the comment "for ~20-25%
; speedup". Measured, the number is **6.3%**.
;
; VICE, NTSC, stock 1 MHz, x25519_base, same PRG, only the trampoline's
; blank flag varying (tools/bench_x25519.py, with and without --no-blank):
;
;   blanked     12,637 jiffies   <- reproduced exactly on a re-run
;   unblanked   13,494 jiffies
;   reduction   6.35%   (speedup 6.78%)
;
; That matches first-principles badline cost almost exactly, which is why
; it is believable at n=1 (VICE's simulated cycle counter is deterministic,
; and the repeat confirmed it): a 25-row display has 25 badlines per frame,
; each stealing ~43 cycles, against a 17,045-cycle NTSC frame —
;
;   25 x 43 / 17,045 = 6.31% predicted
;   measured                1,083 cycles/frame vs 1,075 predicted (+0.7%)
;
; The 20-25% figure is roughly what you would get if sprite DMA were also
; in play; for a text-mode display with no sprites — which is every screen
; c64-https draws — it overstates the win by about 3.5x.
;
; Confirmed on real hardware, U64E, ecdsa_verify, n=3 (`make VIC_BLANK=0`
; builds the control):
;
;   profile   MHz   blanked     unblanked   reduction
;   onchip     48   28.433 s    30.502 s    6.78%
;   REU        48   56.844 s    60.859 s    6.60%
;
; Neither turbo nor the REU profile's DMA floor dilutes it, because the
; badline steal is a tax on the BUS, not on the CPU — REU DMA pays it too.
; See CLAUDE.md's "VIC-II blanking" section for the two predictions that
; got this wrong before it was measured.
;
; This does not make blanking not worth doing: 6.3% of a 36-minute stock-C64
; handshake is still over two minutes, for 18 bytes and no risk. It does
; mean nobody should plan around it as though it were a quarter of runtime.
;
; ---------------------------------------------------------------------
; WHY THIS IS SCOPED, NOT WRAPPED AROUND THE WHOLE HANDSHAKE
; ---------------------------------------------------------------------
; The obvious implementation — blank once around `tls_connect` — is a
; couple of bytes smaller and marginally faster, and it was deliberately
; not chosen. `src/tls13.s` prints a progress marker at each handshake
; phase (CH / SH / HK1 / KEYS / ENC1 / RX / GOT2), and those markers are
; the primary field diagnostic for this project: CLAUDE.md's triage
; procedure for a stalled handshake is "read the last marker on screen,
; then read net_last_error". Blanking across the whole handshake would
; leave a stock-C64 user staring at a black screen for 36 minutes with no
; way to tell a slow run from a wedged one.
;
; So blanking is applied only inside the three calls that actually dominate
; wall-clock, all of which run with no screen output of their own:
;
;   src/tls_ecdh.s          x25519_base         (keypair generation)
;   src/tls_ecdh.s          x25519_scalarmult   (shared secret)
;   src/crypto/ecdsa_verify.s  ecdsa_verify_256 / ecdsa_verify_384_tls
;
; Those are >90% of the handshake's CPU time, so this captures nearly all
; of the available win while every marker still prints between phases.
;
; ---------------------------------------------------------------------
; PLACEMENT
; ---------------------------------------------------------------------
; These bodies live in LOADER_OVERFLOW, not in CODE and not in
; CRYPTO_CODE, and the choice was forced by measurement rather than taste:
;
;   - CODE/LOADER looks roomy under UCI (602 B free) but is the wrong
;     read. Under ip65 the same segment carries boot + TLS + HTTP + the
;     net wrapper and has essentially no slack — putting 30 bytes there
;     overflows `LOADER` by 10 (`ld65: Warning: cfg/c64-https-ip65.cfg(90):
;     Segment 'CODE' overflows memory area 'LOADER' by 10 bytes`).
;   - CRYPTO_CODE would fit, but CRYPTO_HOT / CRYPTO_RESIDENT had 68 bytes
;     free at the v0.10.2 pin and is the region that has twice overflowed
;     on a library bump. Spending its margin on display control would be
;     a poor trade.
;
; LOADER_OVERFLOW is the sanctioned outlet for exactly this — it is where
; http.s's Content-Length parser went for the same reason — and it rides
; in the NET_CODE tail under both backends, so it is resident whenever
; crypto runs. CRYPTO_CODE therefore pays only the two JSRs in
; ecdsa_verify.s.
;
; ---------------------------------------------------------------------
; ASSUMPTIONS
; ---------------------------------------------------------------------
;   - The display is enabled when vic_blank is called. Restore is
;     `ORA #DEN` rather than a saved-byte restore, matching the sibling
;     libraries' convention; c64-https never blanks the screen for any
;     other reason and runs no raster effects, so there is no state to
;     preserve beyond the DEN bit itself.
;   - Blanking does not disturb timekeeping. The jiffy clock is driven by
;     a CIA timer IRQ and the UCI adapter's bounded waits read CIA1 TOD;
;     neither depends on the VIC, so `uci_wait_idle` and friends keep
;     their 5 s wall-clock budgets while the screen is off.
;   - Not re-entrant, and does not need to be: the three call sites are
;     sequential, never nested.
; =============================================================================

        .export vic_blank
        .export vic_unblank

VIC_CTRL1       = $d011                 ; VIC-II control register 1
VIC_DEN         = $10                   ; bit 4 — display enable

        .segment "LOADER_OVERFLOW"

.ifdef NO_VIC_BLANK

; -----------------------------------------------------------------------------
; `make VIC_BLANK=0` — the measurement control. Both entries degrade to a
; bare RTS so an A/B pair differs only in whether DEN is touched: the call
; sites, their JSR overhead, and every other byte of the image stay put.
; Never ship this; it exists so the badline tax can be measured on real
; hardware without the harness-side control that c64-test-harness#150 asks
; for.
; -----------------------------------------------------------------------------
vic_blank:
vic_unblank:
        rts

.else

; -----------------------------------------------------------------------------
; vic_blank - clear DEN, stopping badline DMA.
; Clobbers: A. Preserves X, Y, C.
; -----------------------------------------------------------------------------
vic_blank:
        lda VIC_CTRL1
        and #<(~VIC_DEN)
        sta VIC_CTRL1
        rts

; -----------------------------------------------------------------------------
; vic_unblank - set DEN, restoring the display.
; Clobbers: A. Preserves X, Y, C.
; -----------------------------------------------------------------------------
vic_unblank:
        lda VIC_CTRL1
        ora #VIC_DEN
        sta VIC_CTRL1
        rts

.endif
