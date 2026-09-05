; src/net_abi.inc — the networking ABI consumed by TLS/HTTP/boot.
;
; This header IS the build-enforced boundary between the protocol layers
; and the network backend (c64-lib-contract SPEC §13, issue #70).
;
; CITATION ANCHOR. §13 was RETIRED at contract v1.0.0 (2026-09-03), on the
; grounds that a network backend is source in its consumer's own tree and so
; never crossed a library boundary. Every §13.x number in this file resolves
; at tag `v0.17.1` and nowhere else: `show v0.17.1:SPEC.md`, run in a
; c64-lib-contract checkout — that repo is not a submodule here, so the
; command fails from this tree.
;
; No §13 assert has a contract-derived counterparty (§13 defined no numeric
; value we import), so no contract release can break a build. THIS FILE is
; the normative source for the surface now, not a restatement of one; change
; it here first. The ONE thing that did not stay home is the §13.2 error-code
; allocation table, which spanned two consumers: it now lives in
; `c64-wireguard/src/net_abi.inc`, which declares itself canonical for both
; family ranges. Allocate a new net_last_error code THERE first (#184).
;
; Every consumer TU that touches the network `.include`s it, and every symbol
; below is `.import`ed — so a backend that stops exporting one fails the
; link by name, on both backends, in every profile. Nothing else in the
; consumer layer may `.import` a `net_*` symbol directly.
;
; Both backends export the full surface:
;   src/net/ip65/net.s   — ip65/RR-Net (cs8900a), position-linked blob at $2000
;   src/net/uci/net.s    — Ultimate 64 / C64 Ultimate command interface
;
; Families implemented (src/net/<backend>/net_manifest.s, asserted by
; src/net_abi_asserts.s): NET_FAMILY_CORE | NET_FAMILY_TCP | NET_FAMILY_DNS
; on both backends. UCI's DNS is by deferral (§13.0): firmware resolves the
; name inside TCP_CONNECT; `net_resolved_ip` then reads $FF,$FF,$FF,$FF.
;
; Calling conventions follow SPEC §13.1 exactly; C=0 ok / C=1 fail with
; `net_last_error` set (§13.2). Error code namespaces: ip65 backend
; $40-$7F (src/net/ip65/ip65_errors.inc), UCI backend $80-$BF
; (src/net/uci/uci_errors.inc).

.ifndef NET_ABI_INC_INCLUDED
NET_ABI_INC_INCLUDED = 1

.include "net_states.inc"       ; NET_TCP_* values for net_tcp_state

; --- Core family (§13.1, required) ---------------------------------------
.import net_init                ; no args. C=0 ok; C=1 + net_last_error
.import net_dhcp_acquire        ; no args. Populates net_local_ip. C per §13.2
.import net_poll                ; pump one unit of driver work. C=0 carries
                                ; no "data arrived" meaning — observe the
                                ; rx ring instead. Clobbers A/X/Y.
.import net_local_ip            ; 4 B, zero until net_dhcp_acquire succeeds
.import net_last_error          ; 1 B, $00 = no error

; --- TCP family (§13.1) ---------------------------------------------------
.import net_tcp_connect         ; A = port lo, X = port hi; host staged by
                                ; the prior net_dns_resolve. On failure
                                ; net_tcp_state = NET_TCP_CONNECT_FAIL
.import net_tcp_send            ; A/X = data ptr, net_send_len = 16-bit length
.import net_send_len            ; 2 B, set by the caller before net_tcp_send
.import net_tcp_close           ; no args; always leaves NET_TCP_CLOSED
.import net_tcp_state           ; 1 B, NET_TCP_* (net_states.inc)

; TCP rx ring (§13.3) — CONSUMER-owned: placed by the cfg, defined in
; src/data.s / src/constants.inc, imported by the backend. Declared here so
; the shape is visible next to the drain entry point that reads it.
; `tcp_recv_buf` and `TCP_RECV_MASK` are equates from constants.inc.
.import tcp_recv_head           ; 2 B, consumer read position (masked)
.import tcp_recv_tail           ; 2 B, backend write position (masked)
.import tcp_recv_overflow       ; 1 B, set by the backend when the ring fills

; --- DNS family (§13.1) ---------------------------------------------------
.import net_dns_resolve         ; A/X = NUL-terminated hostname (dotted-quad
                                ; literals pass through). May be lazy.
.import net_resolved_ip         ; 4 B: zero = unresolved; $FF x4 = resolved
                                ; by the device (deferral marker — NOT an
                                ; address); anything else = the address

; --- c64-https extensions (NOT part of SPEC §13) --------------------------
; Both backends export these; they are this consumer's conventions, kept
; out of the contract's tables on purpose.
.import net_recv_byte           ; the blessed drain entry (#72): A = byte,
                                ; C=0 ok, C=1 ring empty. Consumers use
                                ; this rather than reading the ring raw.
.import net_banner_str          ; backend identity line for the boot banner
                                ; ("rr-net" / "UCI NETWORKING");
                                ; tools/uci/boot_check.py asserts on it

; Deliberately absent (SPEC §13.1 "deliberately not in the contract"):
;   net_tcp_set_recv_cb  — RTS stub with no callers; deleted from both backends
;   net_print_ip         — consumer UI; now `print_local_ip` in src/boot.s,
;                          reading net_local_ip, one copy for both backends
;   net_recv_ready       — retired; net_recv_byte's C flag is the same test
;   net_save_zp / net_restore_zp / net_tcp_recv_cb — adapter-internal (§13.5)

.endif
