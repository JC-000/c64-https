; src/net/uci/uci_errors.inc — UCI backend error codes
;
; Values stored in net_last_error by the UCI adapter. 0 = OK.
;
; $80-$BF is the UCI-family range c64-lib-contract SPEC §13.2 grandfathers,
; and it is ONE namespace shared by every UCI-family adapter in the fleet
; (c64-https and c64-wireguard today). ip65-family codes live in $40-$7F
; (src/net/ip65/ip65_errors.inc).
;
; **WHERE TO ALLOCATE A NEW CODE — this changed.** SPEC §13.2 was retired
; at c64-lib-contract v1.0.0 (its text is permanent at tag v0.17.1), so the
; instruction that stood here — "allocate in the §13.2 table first" — no
; longer resolves. The registry moved, it did not vanish:
; **`c64-wireguard/src/net_abi.inc`** now carries the reconstituted table
; and declares itself canonical for the whole fleet range. Allocate THERE
; first, then here. The one rule is unchanged and is the only one that ever
; mattered: a published value is never reassigned.
;
; The range above $8B is NOT free. Codes owned by c64-wireguard, listed so
; nobody here mints over them (this repo emits none of them):
;
;   $8A  UCI_ERR_LONG_READ      theirs, datagram-only — see below
;   $8C  UCI_ERR_SEND_TOO_LONG  theirs; net_udp_send_len over NET_UDP_SEND_MAX
;   $8D  UCI_ERR_OPEN_REFUSED   theirs; firmware refused the open, with a
;                               named refusal on the $DF1F STATUS channel
;   $8E  UCI_ERR_CMD_UNKNOWN    theirs; minted 2026-09-03 (wg#112), i.e.
;                               after v0.17.1 froze the §13.2 table and
;                               ~4 h BEFORE §13 was retired — outside the
;                               table while the table was still the rule
;   $8F  UCI_ERR_SHORT_READ     theirs, minted after the retirement (wg#130)
;
; $8C/$8D were allocated in the retired table and this file never recorded
; them. Comments only, deliberately — an equate here would imply we emit
; them. Re-read their registry before allocating; this list is a snapshot,
; not the authority (#184).
;
; One inconsistency, called out rather than hidden: $8A below IS a real
; equate, and is likewise reserved-never-emitted. It predates this block and
; stays — a published value is never reassigned, and removing the equate
; would break nothing but would lose the name. c64-wireguard goes further
; for their reserved $47, protecting it with .export plus asserts
; (their src/net/ip65/net.s), which is the more durable shape. If a code
; here ever needs that strength, copy their form; the comment list above is
; for codes we neither emit nor name.

.include "net_states.inc"       ; NET_TCP_* (SPEC §13.1) — the primary names

UCI_ERR_OK             = $00    ; no error
UCI_ERR_NOT_PRESENT    = $81    ; $DF1D did not read back UCI_ID_VALUE ($C9)
; $82/$84/$85/$86 all report the SAME observation, distinguished only by
; which command we were pushing: uci_check_err saw UCI_STAT_ERROR ($DF1C
; bit 3) set. That bit is NOT a command-failure report. In the FPGA it is
; `error_busy` (command_protocol.vhd), and it has exactly one setter: a
; PUSH_CMD arriving while the command interface is not in the idle state,
; i.e. OUR push was rejected and never reached the firmware. The names
; below are historical; read every one of them as "push rejected, interface
; not idle" — usually a missing/short uci_fence, a previous command left
; un-drained, or a device still busy.
;
; The protocol has no command-failure bit at all. Firmware-side failures
; arrive only as an ASCII status line on $DF1F ("02,NO DATA: 9",
; "85,ERROR OPENING SOCKET", "01,CONNECTION CLOSED BY HOST") — see the
; status-line capture block at the end of this file. In particular a normal
; end-of-fetch is the CONNECTION CLOSED status line and sets no status bit,
; so a $86 is always a genuine rejected push, never the tail of a clean
; transfer.
UCI_ERR_CMD_FAILED     = $82    ; push rejected (not idle) at PUSH_CMD
UCI_ERR_NO_IP          = $83    ; GET_IPADDR returned all-zero IP
UCI_ERR_CONNECT_FAIL   = $84    ; push rejected (not idle) at TCP_CONNECT
UCI_ERR_SEND_FAIL      = $85    ; push rejected (not idle) at SOCKET_WRITE
UCI_ERR_READ_FAIL      = $86    ; push rejected (not idle) at SOCKET_READ
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
                                ; SPEC §13.2's table first (c64-lib-contract#139)
                                ; — the last code allocated that way before
                                ; §13 was retired.

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
; because nothing larger had ever been requested. The FIRMWARE ceiling is
; version-dependent; 893 is OURS on every version.
;
;   fw 3.14d        894 = CMD_MAX_REPLY_LEN 896 - the 2-byte header
;                   (GideonZ/1541ultimate#802, re-measured on a U64E:
;                   512-893 B arrive whole in one poll). NEVER request
;                   exactly 894: the reply exactly fills the response queue
;                   and the FPGA repeats it forever with DATA_AV asserted.
;   fw 3.15 + #806  accepts up to 1472 and the 894 hang is gone, but a reply
;                   over 893 payload bytes comes back SPLIT across response
;                   blocks (the command interface's Data More mechanism), and
;                   the 2-byte header is then the total for the whole command
;                   rather than the count in the first block. net_poll reads
;                   ONE block, so a request above 893 would silently drop the
;                   continuation.
;
; So 893 is the number to raise toward on either firmware, and going past it
; needs a multi-block reader first. Not a free win either: every byte read
; carries a uci_fence (~5.45 ms at 1 MHz). net_poll's clamp is written
; cap-shape-independently so the change is one constant.
UCI_READ_CHUNK_MAX     = 512

; =============================================================================
; Status-line capture (#147)
;
; $DF1F is where every UCI target reports its result, in ASCII: "00,OK",
; "02,NO DATA: 9", "85,ERROR OPENING SOCKET", and on fw 3.15
; "04,DATAGRAM TRUNCATED: <real length>". The adapter used to drain this
; without reading it, collapsing every failure into a single UCI_ERR_*
; value.
;
; That namespace is OURS and is unrelated to the digits the firmware
; sends: our $86 and the firmware's "86,INTERNAL ERROR" are a coincidence.
; Never map one onto the other.
;
; 16 bytes holds "12,SEND ERROR: 9" exactly — the shape worth keeping,
; since errno 9 is EBADF, which the firmware's owned-socket guard sets on
; READ/WRITE (GideonZ/1541ultimate#814). Longer lines truncate to a still
; diagnostic prefix.
UCI_STATUS_MAX = 16
