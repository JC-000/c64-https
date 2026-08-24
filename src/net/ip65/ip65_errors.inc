; src/net/ip65/ip65_errors.inc — ip65 backend error codes.
;
; Values stored in net_last_error by the ip65 adapter; $00 = OK.
; Allocated from the ip65-family range $40-$7F that c64-lib-contract SPEC
; §13.2 reserves (UCI-family codes live in $80-$BF, see
; src/net/uci/uci_errors.inc). The ip65 driver itself reports only a carry,
; so each code names the adapter entry point that failed rather than a
; driver-level cause; ip65's own `ip65_error` byte is not surfaced.
;
; The allocation is recorded in SPEC §13.2's table. Allocate a new code
; THERE first, then here — the range is shared with every ip65-family
; backend in the fleet.

.ifndef IP65_ERRORS_INC_INCLUDED
IP65_ERRORS_INC_INCLUDED = 1

NET_ERR_IP65_INIT       = $41   ; ip65_init failed (no RR-Net / cs8900a found)
NET_ERR_IP65_DHCP       = $42   ; ip65_dhcp_init failed (no lease)
NET_ERR_IP65_DNS        = $43   ; ip65_dns_resolve failed
NET_ERR_IP65_CONNECT    = $44   ; ip65_tcp_connect failed
NET_ERR_IP65_SEND       = $45   ; ip65_tcp_send failed

.endif
