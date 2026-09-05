; src/net/ip65/net_manifest.s — c64-lib-contract SPEC §13.0 / §13.7 manifest
; for the ip65/RR-Net backend. Emits no bytes: equates only.
;
; CITATION ANCHOR: §13 retired at contract v1.0.0; §13.x resolves at tag
; `v0.17.1` only. The asserts below are self-hosted (both sides of each
; comparison come from this repo) and are unaffected. See src/net_abi.inc.

.include "net_families.inc"

; --- §13.0 family declaration --------------------------------------------
.export NET_BACKEND_FAMILIES : absolute   ; :abs — a byte-sized value would otherwise infer zeropage (contract #74)
NET_BACKEND_FAMILIES = NET_FAMILY_CORE | NET_FAMILY_TCP | NET_FAMILY_DNS

; --- §13.7 fixed-address blob footprint ----------------------------------
; ip65 is a position-linked blob (`ip65-build/ip65-c64.bin`, .incbin'd by
; ip65_blob.s into NET_CODE), not a relocatable §4 library. Its footprint is
; declared so consumer cfgs can compose around it; relocating it is a
; relink of the blob (`make ip65-blob` against a different base), not a
; cfg edit.
;
; BLOB_SIZE is asserted against the bytes actually .incbin'd, so a blob
; rebuild that changes size fails the link here instead of silently
; drifting from the declaration. The BSS span comes from
; ip65-build/ip65-c64.map (occupancy stops at $4F8B) and is not visible to
; ld65 — it is reserved by the blob image, not by a segment — so it cannot
; be asserted the same way; refresh it by hand on a blob relink.
.export LIB_NET_IP65_BLOB_BASE, LIB_NET_IP65_BLOB_SIZE
.export LIB_NET_IP65_BLOB_BSS_BASE, LIB_NET_IP65_BLOB_BSS_SIZE
LIB_NET_IP65_BLOB_BASE     = $2000
LIB_NET_IP65_BLOB_SIZE     = $1B27          ; 6,951 B — refreshed per blob rebuild
LIB_NET_IP65_BLOB_BSS_BASE = $4000
LIB_NET_IP65_BLOB_BSS_SIZE = $0F8C

.import ip65_blob_start, ip65_blob_end
.assert ip65_blob_end - ip65_blob_start = LIB_NET_IP65_BLOB_SIZE, lderror, "LIB_NET_IP65_BLOB_SIZE no longer matches ip65-c64.bin — refresh src/net/ip65/net_manifest.s (SPEC §13.7)"
.assert ip65_blob_start = LIB_NET_IP65_BLOB_BASE, lderror, "ip65 blob is not linked at LIB_NET_IP65_BLOB_BASE (SPEC §13.7)"
