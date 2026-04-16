; src/net/uci/uci_regs.inc — UCI (Ultimate Command Interface) register map
;
; The Ultimate 64 / 1541 Ultimate exposes a host-visible command interface
; in the $DFxx IO region. Commands are pushed into a FIFO via writes to
; UCI_CMD_DATA, the host issues control bits via UCI_CONTROL, and reads
; response bytes from UCI_RESP_DATA. Status bits drive a non-blocking
; state machine in the UCI adapter.
;
; Phase 1b: equates only — no code references these yet. Including this
; file into net.s validates that the headers compile cleanly and exposes
; the constants for Phase 2+.

; =============================================================================
; Register addresses
; =============================================================================
UCI_DEVICE        = $DF1B       ; r/w  device number (select target device)
UCI_STATUS        = $DF1C       ; r    status bits (see below)
UCI_CONTROL       = $DF1C       ; w    control bits (see below)
UCI_CMD_DATA      = $DF1D       ; w    command / parameter byte FIFO
UCI_ID            = $DF1D       ; r    identification byte ($C9 when present)
UCI_RESP_DATA     = $DF1E       ; r    response data FIFO
UCI_STATUS_DATA   = $DF1F       ; r    status string FIFO

; Expected value of UCI_ID when the command interface is available
UCI_ID_VALUE      = $C9

; =============================================================================
; Status register bits (read from UCI_STATUS)
; =============================================================================
UCI_STAT_DATA_AV  = $80         ; response data available
UCI_STAT_STAT_AV  = $40         ; status string available
UCI_STAT_STATE    = $30         ; state field mask
UCI_STAT_ERROR    = $08         ; command returned an error
UCI_STAT_CMD_BUSY = $01         ; command FIFO busy / command in flight

; =============================================================================
; Control register bits (write to UCI_CONTROL)
; =============================================================================
UCI_CTRL_PUSH_CMD = $01         ; commit pushed bytes as a command
UCI_CTRL_NEXT_DATA= $02         ; advance response data FIFO
UCI_CTRL_ABORT    = $04         ; abort in-flight command
UCI_CTRL_CLR_ERR  = $08         ; clear error state

; =============================================================================
; Device numbers (select target of a pushed command)
; =============================================================================
UCI_TARGET_NETWORK = $03        ; network stack

; =============================================================================
; Command IDs (issued as the first command byte after selecting the target)
; Phase 2+ will use these; Phase 1b keeps them here purely as equates.
; =============================================================================
UCI_CMD_IDENTIFY        = $01
UCI_CMD_GET_IFACE_COUNT = $02
UCI_CMD_GET_NETADDR     = $04
UCI_CMD_GET_IPADDR      = $05
UCI_CMD_SET_IPADDR      = $06
UCI_CMD_TCP_CONNECT     = $07
UCI_CMD_UDP_CONNECT     = $08
UCI_CMD_SOCKET_CLOSE    = $09
UCI_CMD_SOCKET_READ     = $10
UCI_CMD_SOCKET_WRITE    = $11
UCI_CMD_LISTEN_START    = $12
UCI_CMD_LISTEN_ACCEPT   = $13
UCI_CMD_LISTEN_STOP     = $14
UCI_CMD_LISTEN_STATUS   = $15
