; src/net/ip65/net_tuning.inc — ip65 backend tuning constants.
;
; Resolved per-backend via the `-I src/net/$(BACKEND)` include path, so
; backend-agnostic consumers (src/tls13.s) can size backend-sensitive
; loops without knowing which adapter they were linked against.
;
; NET_SH_DRAIN_{OUTER,INNER}: poll budget for the post-ServerHello drain
; in tls13.s (issues #71, #73). ip65 ACKs inbound TCP data only when the
; consumer pumps net_poll, so the drain is load-bearing here: without it
; the server's post-SH flight tail sits unACKed through the multi-minute
; ECDHE/verify stalls and impatient peers drop the connection (macOS:
; hard drop after 13 retransmits ≈ 54 s on a LAN).
;
; An ip65 net_poll is a cheap NIC pump (no command round-trip), so a
; generous budget is affordable: 8*250 = 2000 polls ≈ 10-20 s at 1 MHz,
; trivial against a ~20 min verify, and long enough to cover the peer's
; first retransmission of the flight tail if it had not reached the chip
; yet. This is the validated ip65 figure (VICE e2e, both profiles) —
; do not shrink it without re-running tests/test_vice_https_macos.py.
NET_SH_DRAIN_OUTER = 8
NET_SH_DRAIN_INNER = 250

; CERT_BUF_SIZE: capacity of cert_buf (src/der_decode.s, CERT_BUF_BSS).
;
; 1536 under ip65 — cert_buf is pinned at $A000 and time-shared with
; LIB_NISTCURVES_P256_BSS via the #68 SCRATCH_UNION, whose $600 cap is
; a link-time assert (src/net/ip65/exports.s + the cfg). Growing this
; would break the union; the UCI backend carries the 2048 B variant
; (Wikipedia's 1636 B leaf) in CRYPTO_OVERLAY instead.
CERT_BUF_SIZE = 1536
