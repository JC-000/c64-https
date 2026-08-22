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
; Measured on a C64 Ultimate at 48 MHz: ~40 ms per poll, of which only
; ~3 ms is fence time — the remainder is clock-invariant firmware
; turnaround, so turbo does not help. ip65's 2000-poll budget therefore
; cost ~80 s and regressed the shipped handshake from 51.0 s to 125.4 s
; (issue #73).
;
; REVISED 2026-08-21 (the wikipedia stall): firmware ACK autonomy has a
; LIMIT — its socket buffer holds ~4.3 KB, and bytes beyond that are
; silently dropped, not flow-controlled. en.wikipedia.org's 4,659 B
; flight is the first target to exceed it: with only 16 drain polls the
; C64 entered the ~8 s X25519 stall pulling nothing, the firmware
; buffer overflowed, and the stream had a permanent hole at record 9
; (tls_read_seq=8, mid-header, ~4.3 KB consumed — measured, U64E
; 48 MHz). github's 3.2 KB flight squeaked under, which is why every
; earlier live run passed. The drain therefore DOES have something to
; buy on UCI for large flights: moving ~4 KB firmware->ring before the
; crypto stall frees the firmware buffer for the flight tail. 128
; polls ≈ 5.2 s at the ~40 ms clock-invariant poll cost — client
; silence grows to ~30 s against 45 s (browserleaks) / 90 s (github) /
; 120 s (wikipedia) tolerances. Keep INNER non-zero — the drain loop's
; `dex`/`bne` shape turns an INNER of 0 into 256 iterations.
NET_SH_DRAIN_OUTER = 8
NET_SH_DRAIN_INNER = 16

; CERT_BUF_SIZE: capacity of cert_buf (src/der_decode.s, CERT_BUF_BSS).
;
; 2048 under UCI so en.wikipedia.org's 1636 B leaf certificate fits —
; the last blocker for Wikipedia as a real-server HTTPS target. The
; segment rides CRYPTO_OVERLAY under both UCI cfgs (it no longer fits
; CRYPTO_COLD_SHADOW at this size); ip65 keeps 1536, pinned at $A000
; and unioned with LIB_NISTCURVES_P256_BSS (see cfg/c64-https-ip65.cfg
; SCRATCH_UNION — its $600 cap is a link-time assert and MUST NOT
; grow). The deframer's leaf cap check requires the low byte to be
; zero (asserted in src/tls_deframe.s).
CERT_BUF_SIZE = 2048
