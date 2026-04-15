; src/net/ip65/ip65_symbols.inc — ca65 equates for ip65 symbols used by net.s
;
; The ip65 blob (ip65-build/ip65-c64.bin) is pre-linked at $2000 and exposes
; a fixed jump table plus a variable-address table. Symbols here are derived
; from ip65-build/ip65-c64.map and ip65-build/ip65_stub.s.
;
; Only symbols actually referenced by src/net/ip65/net.s are defined here —
; do not dump the full map. Add more symbols as the backend grows.
;
; Phase 7: this file is the single source of truth for ip65_* equates.
; src/constants.inc no longer defines them, so the earlier `.ifndef`
; guard has been removed.

; --- ip65 ZP overlap zone (26 bytes: $02-$1B) ---
ip65_zp_start   = $02
ip65_zp_end     = $1b
ip65_zp_size    = ip65_zp_end - ip65_zp_start + 1

; --- ip65 jump table at $2000 (fixed offsets from ip65-build/ip65_stub.s) ---
ip65_base           = $2000
ip65_init           = ip65_base + 0
ip65_process        = ip65_base + 3
ip65_dhcp_init      = ip65_base + 6
ip65_dns_resolve    = ip65_base + 9
ip65_tcp_connect    = ip65_base + 12
ip65_tcp_send       = ip65_base + 15
ip65_tcp_close      = ip65_base + 18
ip65_tcp_keepalive  = ip65_base + 21
ip65_dns_set_host   = ip65_base + 24
ip65_set_tcp_cb     = ip65_base + 27
ip65_set_tcp_dest   = ip65_base + 30

; --- ip65 variable-pointer table at ip65_base+33 ---
; Each entry holds a 2-byte address pointing at the real ip65 variable.
ip65_vt             = ip65_base + 33
ip65_vt_cfg_mac     = ip65_vt + 0
ip65_vt_cfg_ip      = ip65_vt + 2
ip65_vt_cfg_netmask = ip65_vt + 4
ip65_vt_cfg_gateway = ip65_vt + 6
ip65_vt_cfg_dns     = ip65_vt + 8
ip65_vt_dns_ip      = ip65_vt + 10
ip65_vt_tcp_in_ptr  = ip65_vt + 12
ip65_vt_tcp_in_len  = ip65_vt + 14
ip65_vt_tcp_snd_len = ip65_vt + 16
ip65_vt_ip65_error  = ip65_vt + 18
ip65_vt_tcp_dest_ip = ip65_vt + 20

; --- Direct variable addresses (from ip65-build/ip65-c64.map) ---
ip65_cfg_ip         = $3a8a            ; 4 bytes: our IP address
ip65_cfg_mac        = $3a84            ; 6 bytes: our MAC address
ip65_tcp_snd_len    = $4f48            ; 2 bytes: tcp_send_data_len
ip65_dns_ip_addr    = $4073            ; 4 bytes: resolved DNS IP
ip65_error          = $4cea            ; 1 byte: last error code
