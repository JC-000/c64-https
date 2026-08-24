; src/net/net_states.inc — c64-lib-contract SPEC §13.1 `net_tcp_state` values.
;
; The values are normative: they are the original UCI_TCP_* values,
; name-promoted by the contract. Included by both backends (which store
; them) and by src/net_abi.inc (so consumers can compare against them).
; Never .export'ed — same reasoning as net_families.inc.

.ifndef NET_STATES_INC_INCLUDED
NET_STATES_INC_INCLUDED = 1

NET_TCP_CLOSED        = $00     ; no active socket
NET_TCP_CONNECTED     = $01     ; connected; reads/writes valid
NET_TCP_ERROR         = $02     ; backend saw an error on the socket — stop polling
NET_TCP_CONNECT_FAIL  = $03     ; net_tcp_connect did not yield a usable socket

.endif
