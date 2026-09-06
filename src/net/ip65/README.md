# src/net/ip65 — ip65 / RR-Net backend

The default networking backend for c64-https. Provides the `net_*` entry
points on top of the ip65 TCP/IP stack with the RR-Net ethernet driver.

It implements the full surface `src/net_abi.inc` imports, aligned with
c64-lib-contract SPEC §13 (issue #70): core, TCP and DNS families —
`net_manifest.s` declares `NET_BACKEND_FAMILIES = CORE|TCP|DNS` plus the
§13.7 footprint of the position-linked blob (`$2000`, `$1B27` bytes,
BSS `$4000-$4F8B`), and the blob size is link-asserted against the bytes
actually `.incbin`'d.

§13 was retired at c64-lib-contract v1.0.0; the §13.x numbers here resolve
at tag `v0.17.1`, in a c64-lib-contract checkout. See `src/net_abi.inc`.

Error channel: `net_last_error` carries `NET_ERR_IP65_*` codes from
`ip65_errors.inc`, allocated in the §13.2 ip65-family range `$40-$7F` —
one namespace shared with c64-wireguard, whose `src/net_abi.inc` is now the
registry and owns `$46-$49`. Allocate there first.
ip65 itself reports only a carry, so each code names the adapter entry
point that failed. `net_tcp_state` follows `NET_TCP_*`
(`src/net/net_states.inc`); `net_local_ip` / `net_resolved_ip` are copies
of `ip65_cfg_ip` / `ip65_dns_ip_addr` taken on success.

Adapter-internal and deliberately not exported (§13.5): the TCP receive
callback and the crypto-ZP save/restore around every ip65 call. The
save/restore is load-bearing — the callback fires inside `ip65_process`
while ip65's ZP `$02-$1B` is live.
