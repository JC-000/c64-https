# src/net/ip65 — ip65 / RR-Net backend

The default networking backend for c64-https. Provides `net_*` entry
points on top of the ip65 TCP/IP stack with the RR-Net ethernet driver.

**It does not implement all of `src/net_abi.inc`, and nothing checks
that it does.** That header is `.include`d by no translation unit, so
it is documentation rather than an enforced interface. This backend
exports six of its twelve symbols (`net_init`, `net_poll`,
`net_dns_resolve`, `net_tcp_connect`, `net_tcp_send`, `net_tcp_close`)
and omits `net_dhcp_acquire`, `net_tcp_set_recv_cb`, `net_local_ip`,
`net_resolved_ip`, `net_last_error` and `net_tcp_state` — see `net.s:28`
("deferred to Phase 7", which shipped). It exports `net_dhcp` in place
of `net_dhcp_acquire`. Alignment is tracked in issue #70; see the
"Networking backend ABI" section of `CLAUDE.md` for the measured
declared-vs-used surface.
