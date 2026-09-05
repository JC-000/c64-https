; src/net_abi_asserts.s — c64-lib-contract SPEC §13.8 consumer intake asserts.
;
; CITATION ANCHOR: §13 was retired at contract v1.0.0; its §13.x numbers
; resolve at tag `v0.17.1` only (`git show v0.17.1:SPEC.md`). The asserts
; below are unaffected — every symbol they touch is defined in this repo
; (NET_BACKEND_FAMILIES from src/net/<backend>/net_manifest.s, NET_FAMILY_*
; from src/net/net_families.inc, TCP_RECV_MASK from src/constants.inc) and
; the contract has never been a build input. See src/net_abi.inc.
;
; Assembled into every build, both backends, every profile; emits no bytes.
; Companion to src/lib_contract_asserts.s (§1/§3/§5/§8), which carried the
; §13.3 ring-mask check before this TU existed — it now lives here with the
; rest of §13.
;
; NET_BACKEND_FAMILIES is exported by src/net/<backend>/net_manifest.s and
; is the sole §13.0 export; the NET_FAMILY_* bits are assemble-time equates
; from the copied-verbatim net_families.inc. It is `.import`ed, so its
; value is unknown until link — hence `lderror`, as §13.0/§13.8 specify.
;
; What this consumer needs: TCP client + a way to hand the backend a
; hostname. Under UCI the DNS family is satisfied by deferral (§13.0), which
; still sets the bit — the consumer-visible behaviour is what is declared.

.include "constants.inc"        ; TCP_RECV_MASK
.include "net_families.inc"

.import NET_BACKEND_FAMILIES

NET_REQUIRED_FAMILIES = NET_FAMILY_CORE | NET_FAMILY_TCP | NET_FAMILY_DNS

.assert (NET_BACKEND_FAMILIES & NET_FAMILY_CORE) = NET_FAMILY_CORE, lderror, "network backend missing the core family (c64-lib-contract SPEC §13.0)"

.assert (NET_BACKEND_FAMILIES & NET_REQUIRED_FAMILIES) = NET_REQUIRED_FAMILIES, lderror, "network backend missing a family c64-https needs: CORE|TCP|DNS (SPEC §13.8)"

; §13.3: the backends mask head/tail with `and #>TCP_RECV_MASK`, which is
; only a ring wrap when the mask is 2^n - 1. Assemble-time (`error`) because
; TCP_RECV_MASK is a local equate, not an import.
.assert (TCP_RECV_MASK & (TCP_RECV_MASK + 1)) = 0, error, "TCP_RECV_MASK must be 2^n - 1 (c64-lib-contract SPEC §13.3)"
