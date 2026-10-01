; src/net/uci-m3/net_manifest.s — §13.0 manifest for BACKEND=uci-m3.
; Emits no bytes. Same families as the plain UCI backend: DNS by deferral
; (the firmware resolves the name inside OPEN_TLS). CITATION ANCHOR: §13
; retired at contract v1.0.0; §13.x resolves at tag `v0.17.1` only.

.include "net_families.inc"

.export NET_BACKEND_FAMILIES : absolute
NET_BACKEND_FAMILIES = NET_FAMILY_CORE | NET_FAMILY_TCP | NET_FAMILY_DNS
