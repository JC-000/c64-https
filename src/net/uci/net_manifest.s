; src/net/uci/net_manifest.s — c64-lib-contract SPEC §13.0 manifest for the
; UCI (Ultimate 64 / C64 Ultimate) backend. Emits no bytes: equates only.
;
; DNS is implemented BY DEFERRAL (§13.0): the firmware resolves the hostname
; inside TCP_CONNECT, so net_dns_resolve only stages the name and
; net_resolved_ip reads the $FF,$FF,$FF,$FF deferral marker. The bit is
; still set — the consumer-visible behaviour ("pass a hostname, connect to
; it") is what the bit declares. No §13.7 equates: the UCI adapter is
; ordinary relocatable code in UCI_CODE, not a fixed-address blob.
;
; CITATION ANCHOR: §13 retired at contract v1.0.0; §13.x resolves at tag
; `v0.17.1` only. See src/net_abi.inc.

.include "net_families.inc"

.export NET_BACKEND_FAMILIES : absolute   ; :abs — a byte-sized value would otherwise infer zeropage (contract #74)
NET_BACKEND_FAMILIES = NET_FAMILY_CORE | NET_FAMILY_TCP | NET_FAMILY_DNS
