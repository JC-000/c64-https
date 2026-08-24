; src/net/net_families.inc — c64-lib-contract SPEC §13.0 family bits.
;
; Copied VERBATIM from the contract (like the §8.x bit constants); do not
; derive or extend locally. Plain assemble-time equates, never .export'ed:
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
