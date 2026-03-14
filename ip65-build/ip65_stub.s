; =============================================================================
; ip65_stub.s - ip65 TCP + RR-Net wrapper with fixed jump table at $2000
;
; Assembled with ca65, linked with ld65 against ip65_tcp.lib + ip65_c64.lib.
; Produces a raw binary at $2000 for inclusion in ACME via !binary.
;
; Jump table at $2000 with 3-byte JMP entries at fixed offsets.
; Variable table follows at $2030 with addresses of ip65 state we expose.
; =============================================================================

.include "../ip65/inc/common.inc"

; --- Imports from ip65 ---
.import ip65_init
.import ip65_process
.import ip65_error

.import dhcp_init

.import dns_set_hostname
.import dns_resolve
.import dns_ip

.import tcp_connect
.import tcp_connect_ip
.import tcp_send
.import tcp_send_data_len
.import tcp_close
.import tcp_callback
.import tcp_inbound_data_ptr
.import tcp_inbound_data_length
.import tcp_send_keep_alive

.import cfg_mac
.import cfg_ip
.import cfg_netmask
.import cfg_gateway
.import cfg_dns

.importzp eth_init_default
.importzp ptr1

; keep ld65 happy — cc65 runtime segments
.segment "INIT"
.segment "ONCE"

; =============================================================================
; Jump table at $2000 — 3-byte JMP entries, called from ACME code
; =============================================================================
.segment "JUMPTAB"

; Function jump table (each 3 bytes = JMP xxxx)
jmp ip65_init               ; $2000 +0   A=0 for default; C=0 ok, C=1 err
jmp ip65_process            ; $2003 +3   poll packets; C=0 packet, C=1 idle
jmp dhcp_init               ; $2006 +6   DHCP; C=0 ok, C=1 err
jmp dns_resolve             ; $2009 +9   resolve; C=0 ok, C=1 err
jmp tcp_connect             ; $200C +12  AX=port; C=0 ok, C=1 err
jmp tcp_send                ; $200F +15  AX=data ptr; C=0 ok, C=1 err
jmp tcp_close               ; $2012 +18  close TCP connection
jmp tcp_send_keep_alive     ; $2015 +21  send keepalive
jmp wrap_dns_set_hostname   ; $2018 +24  AX=hostname ptr
jmp wrap_set_tcp_callback   ; $201B +27  AX=callback addr
jmp wrap_set_tcp_dest       ; $201E +30  set dest IP+port from AX ptr

; Variable address table follows immediately
; Each entry is a 2-byte address (lo/hi) — ACME reads from known offsets
.word cfg_mac               ; +33  -> 6 bytes MAC
.word cfg_ip                ; +35  -> 4 bytes IP
.word cfg_netmask           ; +37  -> 4 bytes netmask
.word cfg_gateway           ; +39  -> 4 bytes gateway
.word cfg_dns               ; +41  -> 4 bytes DNS server
.word dns_ip                ; +43  -> 4 bytes resolved IP
.word tcp_inbound_data_ptr  ; +45  -> 2 bytes ptr to received data
.word tcp_inbound_data_length ; +47 -> 2 bytes received length
.word tcp_send_data_len     ; +49  -> 2 bytes send length
.word ip65_error            ; +51  -> 1 byte error code
.word tcp_connect_ip        ; +53  -> 4 bytes dest IP for tcp_connect

; =============================================================================
; Wrapper routines
; =============================================================================

.segment "STARTUP"
  rts     ; no standalone entry point

.code

; wrap_dns_set_hostname - set hostname for DNS resolution
; Input: AX = pointer to null-terminated hostname string
wrap_dns_set_hostname:
  jsr dns_set_hostname
  rts

; wrap_set_tcp_callback - set TCP receive callback vector
; Input: AX = callback function address
wrap_set_tcp_callback:
  stax tcp_callback
  rts

; wrap_set_tcp_dest - set TCP destination IP from 4-byte buffer
; Input: AX = pointer to 4-byte IP address
; Also sets the port in tcp_connect_ip area
wrap_set_tcp_dest:
  sta ptr1
  stx ptr1+1
  ldy #0
  lda (ptr1),y
  sta tcp_connect_ip
  iny
  lda (ptr1),y
  sta tcp_connect_ip+1
  iny
  lda (ptr1),y
  sta tcp_connect_ip+2
  iny
  lda (ptr1),y
  sta tcp_connect_ip+3
  rts
