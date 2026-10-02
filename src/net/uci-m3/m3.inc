; src/net/uci-m3/m3.inc — constants for the BACKEND=uci-m3 adapter.
;
; The M3 firmware runs TLS on the Ultimate's ESP32 and exposes it on the UCI
; network target (target 3). Normative text: M3-SPEC v1 (= r7.7, sha256
; c265fdfc...) with errata v1.1 (f9a39ff3...) and v1.2 (a6802f40...); the
; errata win where they say so. "S:n" / "ER-n" below cite those files.

.ifndef M3_INC_INCLUDED
M3_INC_INCLUDED = 1

; --- M3 commands on target 3 (S 0) ----------------------------------------
M3_CMD_CLOSE        = $09
M3_CMD_GET_IPADDR   = $05
M3_CMD_READ         = $10
M3_CMD_WRITE        = $11
M3_CMD_OPEN_TLS     = $21
M3_CMD_TLS_INFO     = $23
M3_CMD_TLS_RELEASE  = $25

M3_INFO_CAPS        = $FF       ; `03 23 FF`: the capability record (S 1.3)
M3_INFO_LEN         = 16
M3_OPEN_REPLY_LEN   = 8         ; handle, version, suite, group, flags (S 1.1)

; INFO [4] ready bits (S 1.3, ER-16): b0 module, b1 entropy, b2 trusted time.
M3_READY_MODULE     = $01
M3_READY_ENTROPY    = $02
M3_READY_TIME       = $04

; OPEN_TLS trust modes and flags (S 1.1).
M3_TRUST_BUNDLE     = 0
M3_TRUST_PIN        = 2
M3_FLAG_TLS13_ONLY  = $01       ; REQUIRE_TLS13; bits 1-7 must be 0 (82)

; Sizes (S 1.5, ER-8, ER-9).
M3_HOST_MAX         = 253       ; host 1..253 bytes, no $00 (S 1.1 tail grammar)
M3_WRITE_MAX        = 892       ; WRITE_SOCKET plaintext per command
M3_READ_MAX         = 893       ; one response block: 2-byte header + 893
M3_STATUS_MAX       = 40        ; every M3 status line is <= 40 B (ER-8)
M3_SWEEP_HANDLES    = 16        ; this firmware's handle range 0..15 (ER-9)

; --- The deadline clock (ER-1 "Clock") ------------------------------------
; CIA2 timer A divides PHI2 by M3_UNIT_CYCLES; timer B counts its underflows.
; One unit is 10.0 ms at NTSC's 1.0227 MHz and 10.4 ms at PAL's 0.985 MHz,
; so every bound below errs LONG on PAL and is exact on NTSC — never short.
; CIA timers count the real bus clock under U64 turbo (CLAUDE.md, "CIA timers
; are realtime under turbo"), and this needs no 50/60 Hz setting, which is
; why it is used here instead of the TOD the plain UCI adapter uses (ER-1
; warns that a TOD with the wrong 50/60 Hz bit runs 20% fast).
M3_UNIT_CYCLES      = 10227

; Bounds, in units (ER-1). B counts from the PUSH; the post-ABORT wait runs
; to the LATER of PUSH + B and ABORT + 12 s. Every ABORT here is written at
; PUSH + B, so that is simply ABORT + 12 s — except at startup and on an
; entry that finds the interface busy, where the PUSH time is unknown and
; ER-1 says ABORT + 45 s.
M3_B_OPEN           = 4500      ; OPEN_TLS: 45 s (worst case 41.1 s, S 4.3)
M3_B_TLS            = 1200      ; every other command here: 12 s (<= 11.1 s)
M3_B_POST_ABORT     = 1200      ; ABORT + 12 s
M3_B_UNKNOWN_PUSH   = 4500      ; ABORT + 45 s
M3_B_READY          = 3000      ; ER-10 ready-bit polling budget: 30 s
M3_B_READY_POLL     = 100       ; ...polled once a second
M3_B_HTTP_IDLE      = 6000      ; http_recv_body: 60 s with no byte arrived

; Deadline slots (offsets into m3_dl).
M3_DL_CMD           = 0
M3_DL_APP           = 4

; m3_exec outcomes (A on return; C=1 for all but REPLY).
M3_EXEC_REPLY       = 0         ; the reply is valid: read it, then m3_finish
M3_EXEC_REJECTED    = 1         ; ERROR bit: the push never reached the Nios
M3_EXEC_ABORTED     = 2         ; no reply by PUSH + B: ABORTed, interface idle
M3_EXEC_WEDGED      = 3         ; bit 2 still set at the post-ABORT deadline

; m3_poll_result: what the last net_poll saw.
M3_POLL_DATA        = 0         ; bytes went into the ring
M3_POLL_IDLE        = 1         ; $FFFF + "02,NO DATA: 11"
M3_POLL_FULL        = 2         ; no READ: the ring had no room
M3_POLL_END         = 3         ; anything else: the state says what

.endif
