; src/net/ip65/ip65_errors.inc — ip65 backend error codes.
;
; Values stored in net_last_error by the ip65 adapter; $00 = OK.
; Allocated from the ip65-family range $40-$7F that c64-lib-contract SPEC
; §13.2 reserves (UCI-family codes live in $80-$BF, see
; src/net/uci/uci_errors.inc). The ip65 driver itself reports only a carry,
; so each code names the adapter entry point that failed rather than a
; driver-level cause; ip65's own `ip65_error` byte is not surfaced.
;
; **WHERE TO ALLOCATE A NEW CODE — this changed.** SPEC §13.2 was retired
; at c64-lib-contract v1.0.0 (text permanent at tag v0.17.1), so the
; instruction that stood here — "allocate in the §13.2 table first" — no
; longer resolves. The registry moved, it did not vanish:
; **`c64-wireguard/src/net_abi.inc`** now carries the reconstituted table
; and declares itself canonical. Allocate THERE first, then here. A
; published value is never reassigned.
;
; The range above $45 is NOT free. Codes owned by c64-wireguard's ip65
; backend, listed so nobody here mints over them (this repo emits none):
;
;   $46  NET_ERR_IP65_UDP_LISTEN   theirs; udp_add_listener refused the bind
;   $47  NET_ERR_IP65_UDP_SEND     theirs, RESERVED and never emitted — they
;                                  export the equate + asserts so it cannot
;                                  be quietly reused (wg#120)
;   $48  NET_ERR_IP65_WAIT_TIMEOUT theirs, minted AFTER the retirement (wg#120)
;   $49  NET_ERR_IP65_UDP_UNBIND   theirs, minted AFTER the retirement (wg#120)
;
; That range is why this matters: wg#120's FIRST commit minted $40-$44 by
; picking free-looking bytes, and $41-$45 were already ours — a second live
; collision, caught in review three weeks after the $88 one. Remapped before
; merge. Comments only, deliberately: an equate here would imply we emit
; them. Their registry is the authority, not this snapshot (#184).
;
; THAT SNAPSHOT IS NOW MACHINE-CHECKED (#184). The list above is prose, and
; prose does not fail a build, so two guards stand behind it:
;
;   src/net_err_registry_asserts.s   assembles into EVERY build, both
;       backends, every profile, and emits no bytes. It `.assert`s that no
;       code defined here lands on a peer-owned value, that each is in the
;       $40-$7F family range, and that no published value has been
;       reassigned; NET_ERR_CLAIM_VALUE additionally makes two of our own
;       names on one byte a ca65 redefinition error. Minting $46 fails the
;       build with a named message instead of linking clean.
;   tools/test_net_err_registry.py   parses THIS file rather than the
;       asserts TU, so a new code that never gets registered there is still
;       caught, and diffs our snapshot's values AND names against the live
;       c64-wireguard/src/net_abi.inc.
;
; Adding a code: allocate in c64-wireguard/src/net_abi.inc, add the equate
; here, then register it in src/net_err_registry_asserts.s.
;
; WHAT THAT PAIR DOES NOT COVER — the guarantee is real but narrow:
;   - **Write the value as a literal.** The suite recognises `NAME = $hh`,
;     `NAME = ddd` and `.define NAME $hh` and nothing else. An expression —
;     say `NET_ERR_IP65_NEW = NET_ERR_IP65_SEND + 1` — is invisible to it.
;     ca65 evaluates such a code fine ONCE REGISTERED, so the gap is the
;     narrow one: an expression-valued code that is also never registered
;     in src/net_err_registry_asserts.s escapes both halves. Every code
;     below is a literal; keep it that way.
;   - An inline immediate (`lda #$46 / sta net_last_error`) with no equate
;     behind it is invisible to both. No such site exists today.
;   - The cross-repo half needs a c64-wireguard checkout. Without one those
;     checks FAIL — an involuntary skip is a failure — rather than passing
;     quietly; `C64_NO_PEER_REGISTRY=1` is the loud opt-out.
;   - It can also go red the OTHER way: the suite reads this whole file, so
;     an ordinary constant that happens to land in $40-$7F would look like
;     an allocation. It is kept out by the `_ERR_` infix every code here
;     uses — so name a new code `NET_ERR_IP65_*`, and expect no help from
;     the suite if you do not.
;   - Nothing here re-verifies c64-wireguard. A collision found against
;     their registry is a cross-repo finding for a human, not something
;     either repo may renumber unilaterally.

.ifndef IP65_ERRORS_INC_INCLUDED
IP65_ERRORS_INC_INCLUDED = 1

NET_ERR_IP65_INIT       = $41   ; ip65_init failed (no RR-Net / cs8900a found)
NET_ERR_IP65_DHCP       = $42   ; ip65_dhcp_init failed (no lease)
NET_ERR_IP65_DNS        = $43   ; ip65_dns_resolve failed
NET_ERR_IP65_CONNECT    = $44   ; ip65_tcp_connect failed
NET_ERR_IP65_SEND       = $45   ; ip65_tcp_send failed

.endif
