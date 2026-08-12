; src/net/uci/net_tuning.inc — UCI backend tuning constants.
;
; Resolved per-backend via the `-I src/net/$(BACKEND)` include path, so
; backend-agnostic consumers (src/tls13.s) can size backend-sensitive
; loops without knowing which adapter they were linked against.
;
; NET_SH_DRAIN_{OUTER,INNER}: poll budget for the post-ServerHello drain
; in tls13.s (issues #71, #73).
;
; The drain's PURPOSE does not apply to this backend: UCI firmware ACKs
; inbound TCP data autonomously, regardless of whether the C64 polls —
; which is exactly why the unACKed-flight-tail bug that motivated the
; drain (#71) was never observable on Ultimate hardware, only on ip65.
;
; Its COST, by contrast, is severe here: a UCI net_poll is not a cheap
; NIC pump but a full firmware command round-trip (SOCKET_READ:
; uci_wait_not_busy, uci_begin_cmd, 4x uci_put_byte, uci_push_wait,
; uci_check_err, header read, uci_drain_resp + uci_drain_status +
; uci_ack — ~25 fenced register accesses plus FPGA turnaround).
; Measured on a C64 Ultimate at 48 MHz: ~37 ms per poll, of which only
; ~2.8 ms is fence time — the remainder is clock-invariant firmware
; turnaround, so turbo does not help. ip65's 2000-poll budget therefore
; cost ~70 s and regressed the shipped handshake from 51.0 s to 125.4 s
; (issue #73).
;
; 16 polls (~0.6 s at 48 MHz) is a deliberate small hedge rather than 0:
; it still pulls anything already queued into the ring before the long
; stalls, at negligible cost, without relying on firmware autonomy being
; absolute. Keep it non-zero — the drain loop's `dex`/`bne` shape turns
; an INNER of 0 into 256 iterations.
NET_SH_DRAIN_OUTER = 1
NET_SH_DRAIN_INNER = 16
