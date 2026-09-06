; src/net/net_families.inc — c64-lib-contract SPEC §13.0 family bits.
;
; These bits were copied verbatim from the contract's §13.0 block. **§13 was
; retired at contract v1.0.0 (2026-09-03)**, so there is no longer an
; upstream to copy from: this file is the normative source for c64-https and
; the original text resolves at tag `v0.17.1`, in a c64-lib-contract
; checkout. The values MUST NOT change — c64-wireguard holds an independent
; copy of the same bits and nothing checks the two agree. Allocating a NEW
; bit is a cross-repo agreement, not a local edit: do it with the wireguard
; lane, whose `src/net_abi.inc` is the fleet registry for the neighbouring
; net_last_error ranges and the obvious home for these too (#184).
;
; Plain assemble-time equates, never .export'ed:
; both the backend manifest (src/net/<backend>/net_manifest.s) and every
; family-asserting consumer (src/net_abi_asserts.s) include this header,
; and only exported symbols can collide at link time.
;
; Bits are append-only and never reused (§8.0 discipline).

.ifndef NET_FAMILIES_INC_INCLUDED
NET_FAMILIES_INC_INCLUDED = 1

NET_FAMILY_CORE = $0001         ; net_init, net_dhcp_acquire, net_poll,
                                ; net_local_ip, net_last_error
NET_FAMILY_TCP  = $0002         ; net_tcp_connect/send/close, net_tcp_state,
                                ; consumer-owned rx ring (§13.3)
NET_FAMILY_UDP  = $0004         ; net_udp_listen/send, UDP rx buffer
NET_FAMILY_DNS  = $0008         ; net_dns_resolve, net_resolved_ip

.endif
