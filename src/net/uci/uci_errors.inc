; src/net/uci/uci_errors.inc — UCI backend error codes
;
; Values stored in net_last_error by the UCI adapter. 0 = OK.
;
; $80-$BF is the UCI-family range c64-lib-contract SPEC §13.2 grandfathers,
; and it is ONE namespace shared by every UCI-family adapter in the fleet
; (c64-https and c64-wireguard today). The allocation table in SPEC §13.2
; is the authority: allocate a new code THERE first, then here, so the two
; adapters cannot hand out the same value with different meanings.
; ip65-family codes live in $40-$7F (src/net/ip65/ip65_errors.inc).

.include "net_states.inc"       ; NET_TCP_* (SPEC §13.1) — the primary names

UCI_ERR_OK             = $00    ; no error
UCI_ERR_NOT_PRESENT    = $81    ; $DF1D did not read back UCI_ID_VALUE ($C9)
UCI_ERR_CMD_FAILED     = $82    ; UCI reported an error bit after PUSH_CMD
UCI_ERR_NO_IP          = $83    ; GET_IPADDR returned all-zero IP
UCI_ERR_CONNECT_FAIL   = $84    ; TCP_CONNECT returned an error bit
UCI_ERR_SEND_FAIL      = $85    ; SOCKET_WRITE returned an error bit
UCI_ERR_READ_FAIL      = $86    ; SOCKET_READ returned an error bit
UCI_ERR_SHORT_WRITE    = $87    ; SOCKET_WRITE wrote fewer bytes than requested
UCI_ERR_NO_SOCKET      = $88    ; socket-open response yielded no socket_id
UCI_ERR_WAIT_TIMEOUT   = $89    ; a bounded wait exceeded its wall-clock budget
UCI_ERR_LONG_READ      = $8A    ; UDP path (c64-wireguard, 2026-08-24):
                                ; SOCKET_READ reported a datagram length
                                ; exceeding the request; the datagram is
                                ; dropped. Reserved here, NEVER emitted: on
                                ; the TCP path the header is not a delivered
                                ; count (fw 3.14d answers a 512 B request with
                                ; $FFFF on every session), so net_poll caps the
                                ; copy at the request instead (#140).
UCI_ERR_BAD_READ_HDR   = $8B    ; SOCKET_READ header exceeded the request and
                                ; was NOT the $FFFF sentinel — a value the
                                ; firmware has no documented mode for. Best-
                                ; effort breadcrumb (§13.1 short-write pattern):
                                ; the copy is still capped at the request and
                                ; net_poll returns normally; the code stays in
                                ; net_last_error for post-mortems. Allocated in
                                ; SPEC §13.2's table first (c64-lib-contract#139).

; TCP state values stored in net_tcp_state. The NET_TCP_* spellings in
; net_states.inc are the contract's (§13.1); these aliases keep the
; historical names readable in diagnostics and in c64-wireguard's copy.
UCI_TCP_CLOSED         = NET_TCP_CLOSED
UCI_TCP_CONNECTED      = NET_TCP_CONNECTED
UCI_TCP_ERROR          = NET_TCP_ERROR
UCI_TCP_CONNECT_FAIL   = NET_TCP_CONNECT_FAIL

; UCI firmware data queue max per SOCKET_WRITE push (see uci_network.py)
UCI_DATA_QUEUE_MAX     = 800

; SOCKET_READ max-length cap we ask for per net_poll cycle.
; 512 bytes is well under the 4 KB ring and the firmware data queue,
; and matches the conservative Phase 3 MVP choice.
UCI_READ_CHUNK_MAX     = 512
