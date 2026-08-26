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
UCI_ERR_LONG_READ      = $8A    ; Datagram family (c64-wireguard): the
                                ; SOCKET_READ header claimed more than the
                                ; request and was NOT the $FFFF no-data
                                ; sentinel; the datagram is dropped. Reserved
                                ; here, NEVER emitted: on a stream the same
                                ; observation is $8B below. $FFFF is the
                                ; firmware's no-data sentinel on BOTH
                                ; transports and must be excluded before any
                                ; length arithmetic (#140; both adapters got
                                ; this wrong independently). No non-sentinel
                                ; over-claim has been observed on either
                                ; transport; both codes are reserved
                                ; defensively.
UCI_ERR_BAD_READ_HDR   = $8B    ; Stream family: SOCKET_READ header exceeded
                                ; the request and was NOT the $FFFF no-data
                                ; sentinel — a value the firmware has no
                                ; documented mode for. Best-
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
;
; 512 is a CONSUMER choice, not the firmware's limit — it was c64-wireguard's
; Phase 3 MVP constant, and both repos carried it as a hardware ceiling
; because nothing larger had ever been requested. The real ceiling is 894
; (= CMD_MAX_REPLY_LEN 896 - the 2-byte header; GideonZ/1541ultimate#802,
; re-measured on a U64E: 512-893 B arrive whole in one poll). NEVER request
; exactly 894 on fw 3.14d: the reply exactly fills the response queue and
; the FPGA repeats it forever with DATA_AV asserted (guard only in 3.15,
; not downloadable). Raising this toward 893 is a measured follow-up, not a
; free win: every byte read carries a uci_fence (~5.45 ms at 1 MHz), and
; net_poll's clamp is written cap-shape-independently so the change is one
; constant.
UCI_READ_CHUNK_MAX     = 512
