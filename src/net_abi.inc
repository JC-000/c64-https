; src/net_abi.inc — INTENDED public networking API for TLS/HTTP.
;
; !! THIS FILE IS NOT IN THE BUILD. !!
;
; No translation unit `.include`s it (verified 2026-08-14:
; `grep -rn 'net_abi' src/ tools/ cfg/ Makefile` returns only comments),
; so not one of the `.import`s below is checked by the assembler or the
; linker. It reads like a drop-in contract and is not one. Three
; measured consequences, all of which someone planning work here needs:
;
;   1. The ip65 backend provides only six of the twelve. It has no
;      `net_dhcp_acquire` (it exports `net_dhcp`), no
;      `net_tcp_set_recv_cb`, no `net_local_ip`, no `net_resolved_ip`,
;      no `net_last_error` and no `net_tcp_state` — see
;      src/net/ip65/net.s:28. `net_last_error` exists ONLY under UCI, so
;      ip65 has no error channel at all.
;   2. Five symbols TLS/HTTP genuinely depend on are missing here:
;      `net_dhcp`, `net_print_ip`, `net_send_len`, `net_recv_byte`,
;      `net_banner_str`. Declared and used surfaces overlap in 6 of 17.
;   3. `net_tcp_set_recv_cb` is an RTS stub with zero callers;
;      c64-lib-contract SPEC §13.1 retires it outright.
;
; Making this real (or deleting it) is item P1 of the plan on issue #70.
; Until then: adding a symbol here changes nothing but this comment
; block's neighbours — put it in the backend adapters instead.
;
; Original intent, preserved: any backend (ip65/RR-Net, UCI/U64E) should
; export these exact symbols, so swapping backend is a link-time choice
; via a different ld65 cfg + different net/<backend>/*.o files, with no
; changes to TLS or HTTP sources.

.import net_init
.import net_dhcp_acquire
.import net_poll

.import net_tcp_connect
.import net_tcp_send
.import net_tcp_close
.import net_tcp_set_recv_cb

.import net_dns_resolve

.import net_local_ip
.import net_resolved_ip
.import net_last_error
.import net_tcp_state
