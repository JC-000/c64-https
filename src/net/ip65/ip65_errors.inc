; src/net/ip65/ip65_errors.inc — ip65 backend error codes.
;
; Values stored in net_last_error by the ip65 adapter; $00 = OK.
; Allocated from the ip65-family range $40-$7F that c64-lib-contract SPEC
; §13.2 reserves (UCI-family codes live in $80-$BF, see
; src/net/uci/uci_errors.inc). The ip65 driver itself reports only a carry,
; so each code names the adapter entry point that failed rather than a
; driver-level cause; ip65's own `ip65_error` byte is not surfaced.
;
; **WHERE TO ALLOCATE A NEW CODE — this changed.** SPEC §13.2 was retired
; at c64-lib-contract v1.0.0 (text permanent at tag v0.17.1), so the
; instruction that stood here — "allocate in the §13.2 table first" — no
; longer resolves. The registry moved, it did not vanish:
; **`c64-wireguard/src/net_abi.inc`** now carries the reconstituted table
; and declares itself canonical. Allocate THERE first, then here. A
; published value is never reassigned.
;
; The range above $45 is NOT free. Codes owned by c64-wireguard's ip65
; backend, listed so nobody here mints over them (this repo emits none):
;
;   $46  NET_ERR_IP65_UDP_LISTEN   theirs; udp_add_listener refused the bind
;   $47  NET_ERR_IP65_UDP_SEND     theirs, RESERVED and never emitted — they
;                                  export the equate + asserts so it cannot
;                                  be quietly reused (wg#120)
;   $48  NET_ERR_IP65_WAIT_TIMEOUT theirs, minted AFTER the retirement (wg#120)
;   $49  NET_ERR_IP65_UDP_UNBIND   theirs, minted AFTER the retirement (wg#120)
;
; That range is why this matters: wg#120's FIRST commit minted $40-$44 by
; picking free-looking bytes, and $41-$45 were already ours — a second live
; collision, caught in review three weeks after the $88 one. Remapped before
; merge. Comments only, deliberately: an equate here would imply we emit
; them. Their registry is the authority, not this snapshot (#184).

.ifndef IP65_ERRORS_INC_INCLUDED
IP65_ERRORS_INC_INCLUDED = 1

NET_ERR_IP65_INIT       = $41   ; ip65_init failed (no RR-Net / cs8900a found)
NET_ERR_IP65_DHCP       = $42   ; ip65_dhcp_init failed (no lease)
NET_ERR_IP65_DNS        = $43   ; ip65_dns_resolve failed
NET_ERR_IP65_CONNECT    = $44   ; ip65_tcp_connect failed
NET_ERR_IP65_SEND       = $45   ; ip65_tcp_send failed

.endif
