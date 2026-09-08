; src/net_err_registry_asserts.s — mechanical guard over the fleet's shared
; `net_last_error` number space (issue #184).
;
; WHAT THIS IS FOR. The ip65 family ($40-$7F) and the UCI family ($80-$BF)
; are ONE namespace each, shared by every adapter in the fleet — c64-https
; and c64-wireguard today. c64-lib-contract SPEC §13.2 used to hold the
; cross-repo allocation table; it was retired wholesale at contract v1.0.0
; and the registry moved to `c64-wireguard/src/net_abi.inc`, which declares
; itself canonical for BOTH ranges. That file is the authority. This one is
; a machine-checked snapshot of it.
;
; Until this TU existed, the shared codes were asserted NOWHERE: our two
; headers listed the peer's allocations in prose only, so minting over one
; produced a clean build and a byte that meant two different things in two
; products. That has already happened twice in the fleet — $88 (four days
; live) and wg#120's first commit, which minted $40-$44 over our $41-$45 and
; was caught only by a human reviewer. Prose caught the second one. Nothing
; caught the first.
;
; WHAT IT COSTS. Nothing. Every symbol below is an assemble-time equate and
; every check is a `.assert`; this TU emits no bytes and claims no segment.
; It is picked up by the Makefile's `$(wildcard src/*.s)`, so it assembles
; into EVERY build, both backends, every profile — an ip65 build checks the
; UCI codes and vice versa, which is the point: the collision this guards
; against is cross-product, not cross-profile.
;
; WHY EQUATES HERE WHEN THE HEADERS DELIBERATELY USE COMMENTS. #185 kept the
; peer's codes as comments in src/net/{uci/uci_errors.inc,ip65/ip65_errors.inc}
; because an equate in OUR error namespace would read as "we emit this". The
; `NET_ERR_PEER_*` names below are a separate, obviously-foreign namespace
; whose only consumer is the assertions in this file; nothing emits them and
; nothing may. This is the shape c64-wireguard already uses for their own
; reserved $47 (`.export` + asserts, src/net/ip65/net.s), which
; uci_errors.inc names as "the more durable shape" to copy.
;
; SCOPE, honestly — this file is NOT a complete guard on its own, and the
; pair is not complete either. What each half cannot do:
;
;   - This file cannot see a code that is not written into it. Registration
;     is manual, and a code with no NET_ERR_ASSERT_* line is simply not
;     checked here. tools/test_net_err_registry.py covers that by parsing
;     the HEADERS instead of this file.
;   - Two of OUR names on one byte IS caught here, by NET_ERR_CLAIM_VALUE
;     below — but only for codes that go through the macros. The literal
;     pins give distinctness only among the codes that existed when they
;     were written, and the peer-collision asserts do not look at our own
;     set at all, so a new duplicate passes both of those; the claim is
;     what catches it. An UNREGISTERED duplicate is still the suite's
;     test_our_codes_are_pairwise_distinct.
;   - This file cannot see the peer repository. Value and name drift there
;     are covered by the suite, and only when a checkout is present — a
;     missing one is an involuntary skip, so those checks FAIL rather than
;     pass quietly (tools/_skip_policy.py; C64_NO_PEER_REGISTRY=1 to
;     opt out).
;   - EXPRESSION-valued equates: this file handles them FINE — ca65
;     evaluates whatever the macro is handed, so a registered
;     `UCI_ERR_NEW = UCI_ERR_NO_SOCKET + 4` fires the $8C collision assert
;     like any literal (measured, not assumed). The suite is the half that
;     cannot: it recognises `NAME = $hh`, `NAME = ddd` and
;     `.define NAME $hh` only. So the residual gap is narrow and specific —
;     an expression-valued code that is ALSO never registered here is
;     invisible to both, because the suite's registration check is what
;     would otherwise have caught it. Declare codes as literals and the
;     question does not arise; every code in both headers does.
;
; MAINTENANCE. Adding a code: allocate it in c64-wireguard/src/net_abi.inc
; FIRST, then in the emitting header here, then register it below. Never
; reassign a published value — the whole registry rests on that one rule.

.include "uci/uci_errors.inc"           ; -I src/net; UCI_ERR_*   ($80-$BF)
.include "ip65/ip65_errors.inc"         ; -I src/net; NET_ERR_IP65_* ($40-$7F)

; --- Family range bounds (retired SPEC §13.2, now the peer registry) -------
NET_ERR_IP65_FAMILY_LO = $40
NET_ERR_IP65_FAMILY_HI = $7F
NET_ERR_UCI_FAMILY_LO  = $80
NET_ERR_UCI_FAMILY_HI  = $BF

; --- Codes owned by c64-wireguard. We emit NONE of these. -----------------
; Snapshot of c64-wireguard/src/net_abi.inc @ cf7b41e (2026-09-07).
;
; MAINTENANCE: adding a row here is TWO edits. The macros below reference
; these names one `.assert` at a time — they are hand-written, and ca65
; cannot iterate a table — so a row added here with no matching assert line
; is a peer code the assembler silently does not check. That pairing is
; itself checked, by test_every_snapshot_entry_is_asserted_by_a_macro in
; tools/test_net_err_registry.py; the suite goes red, not the build.
NET_ERR_PEER_IP65_UDP_LISTEN   = $46
NET_ERR_PEER_IP65_UDP_SEND     = $47   ; reserved there, never emitted
NET_ERR_PEER_IP65_WAIT_TIMEOUT = $48
NET_ERR_PEER_IP65_UDP_UNBIND   = $49
NET_ERR_PEER_UCI_LONG_READ     = $8A   ; we mirror this one — see below
NET_ERR_PEER_UCI_SEND_TOO_LONG = $8C
NET_ERR_PEER_UCI_OPEN_REFUSED  = $8D
NET_ERR_PEER_UCI_CMD_UNKNOWN   = $8E
NET_ERR_PEER_UCI_SHORT_READ    = $8F

; --- Assertions -----------------------------------------------------------
; `error` scope, not `lderror`: every operand is a local assemble-time
; equate, so ca65 settles these before ld65 is reached and a collision fails
; the build at the offending object rather than at the link.

; ONE VALUE, ONE NAME — enforced at assemble time, O(n), no list to keep.
; Each claimed value defines a symbol named after the value itself, so a
; second claim on the same byte is a ca65 redefinition error:
;
;   Error: Symbol 'NET_ERR_TAKEN_88' is already defined
;
; That message names the BYTE, not the pair, so read it as "something else
; already owns $88" and grep both headers for it. The symbol is a constant
; equate, so this costs no bytes like everything else here.
;
; This covers every code passed through the two macros below, plus the $8A
; mirror which claims its byte explicitly. It does NOT cover a code that was
; never registered at all — that stays
; tools/test_net_err_registry.py::test_every_code_is_registered_in_the_asserts_tu.
.macro NET_ERR_CLAIM_VALUE val
    .ident(.sprintf("NET_ERR_TAKEN_%02X", val)) = 1
.endmacro

.macro NET_ERR_ASSERT_IP65 val, name
    NET_ERR_CLAIM_VALUE val
    .assert (val) >= NET_ERR_IP65_FAMILY_LO && (val) <= NET_ERR_IP65_FAMILY_HI, error, .concat(name, ": outside the ip65 family range $40-$7F (c64-wireguard/src/net_abi.inc registry, #184)")
    .assert (val) <> NET_ERR_PEER_IP65_UDP_LISTEN,   error, .concat(name, ": collides with c64-wireguard's $46 NET_ERR_IP65_UDP_LISTEN - allocate in c64-wireguard/src/net_abi.inc first (#184)")
    .assert (val) <> NET_ERR_PEER_IP65_UDP_SEND,     error, .concat(name, ": collides with c64-wireguard's $47 NET_ERR_IP65_UDP_SEND (reserved, never emitted) - allocate in c64-wireguard/src/net_abi.inc first (#184)")
    .assert (val) <> NET_ERR_PEER_IP65_WAIT_TIMEOUT, error, .concat(name, ": collides with c64-wireguard's $48 NET_ERR_IP65_WAIT_TIMEOUT - allocate in c64-wireguard/src/net_abi.inc first (#184)")
    .assert (val) <> NET_ERR_PEER_IP65_UDP_UNBIND,   error, .concat(name, ": collides with c64-wireguard's $49 NET_ERR_IP65_UDP_UNBIND - allocate in c64-wireguard/src/net_abi.inc first (#184)")
.endmacro

.macro NET_ERR_ASSERT_UCI val, name
    NET_ERR_CLAIM_VALUE val
    .assert (val) >= NET_ERR_UCI_FAMILY_LO && (val) <= NET_ERR_UCI_FAMILY_HI, error, .concat(name, ": outside the UCI family range $80-$BF (c64-wireguard/src/net_abi.inc registry, #184)")
    .assert (val) <> NET_ERR_PEER_UCI_LONG_READ,     error, .concat(name, ": collides with c64-wireguard's $8A UCI_ERR_LONG_READ - allocate in c64-wireguard/src/net_abi.inc first (#184)")
    .assert (val) <> NET_ERR_PEER_UCI_SEND_TOO_LONG, error, .concat(name, ": collides with c64-wireguard's $8C UCI_ERR_SEND_TOO_LONG - allocate in c64-wireguard/src/net_abi.inc first (#184)")
    .assert (val) <> NET_ERR_PEER_UCI_OPEN_REFUSED,  error, .concat(name, ": collides with c64-wireguard's $8D UCI_ERR_OPEN_REFUSED - allocate in c64-wireguard/src/net_abi.inc first (#184)")
    .assert (val) <> NET_ERR_PEER_UCI_CMD_UNKNOWN,   error, .concat(name, ": collides with c64-wireguard's $8E UCI_ERR_CMD_UNKNOWN - allocate in c64-wireguard/src/net_abi.inc first (#184)")
    .assert (val) <> NET_ERR_PEER_UCI_SHORT_READ,    error, .concat(name, ": collides with c64-wireguard's $8F UCI_ERR_SHORT_READ - allocate in c64-wireguard/src/net_abi.inc first (#184)")
.endmacro

; ip65 family — every code src/net/ip65/ip65_errors.inc defines.
NET_ERR_ASSERT_IP65 NET_ERR_IP65_INIT,    "NET_ERR_IP65_INIT"
NET_ERR_ASSERT_IP65 NET_ERR_IP65_DHCP,    "NET_ERR_IP65_DHCP"
NET_ERR_ASSERT_IP65 NET_ERR_IP65_DNS,     "NET_ERR_IP65_DNS"
NET_ERR_ASSERT_IP65 NET_ERR_IP65_CONNECT, "NET_ERR_IP65_CONNECT"
NET_ERR_ASSERT_IP65 NET_ERR_IP65_SEND,    "NET_ERR_IP65_SEND"

; UCI family — every code src/net/uci/uci_errors.inc defines EXCEPT
; UCI_ERR_LONG_READ, handled immediately below.
NET_ERR_ASSERT_UCI UCI_ERR_NOT_PRESENT,  "UCI_ERR_NOT_PRESENT"
NET_ERR_ASSERT_UCI UCI_ERR_CMD_FAILED,   "UCI_ERR_CMD_FAILED"
NET_ERR_ASSERT_UCI UCI_ERR_NO_IP,        "UCI_ERR_NO_IP"
NET_ERR_ASSERT_UCI UCI_ERR_CONNECT_FAIL, "UCI_ERR_CONNECT_FAIL"
NET_ERR_ASSERT_UCI UCI_ERR_SEND_FAIL,    "UCI_ERR_SEND_FAIL"
NET_ERR_ASSERT_UCI UCI_ERR_READ_FAIL,    "UCI_ERR_READ_FAIL"
NET_ERR_ASSERT_UCI UCI_ERR_SHORT_WRITE,  "UCI_ERR_SHORT_WRITE"
NET_ERR_ASSERT_UCI UCI_ERR_NO_SOCKET,    "UCI_ERR_NO_SOCKET"
NET_ERR_ASSERT_UCI UCI_ERR_WAIT_TIMEOUT, "UCI_ERR_WAIT_TIMEOUT"
NET_ERR_ASSERT_UCI UCI_ERR_BAD_READ_HDR, "UCI_ERR_BAD_READ_HDR"

; THE ONE DELIBERATE OVERLAP. UCI_ERR_LONG_READ = $8A is c64-wireguard's
; allocation, mirrored here as a reserved-never-emitted equate so the name
; is readable in our diagnostics (see the block in uci_errors.inc). It is
; therefore the one code that must EQUAL a peer value instead of differing
; from one — checked in that direction, and named so nobody mistakes it for
; a missed collision.
;
; SCOPE of that check: it pins the VALUE against this file's snapshot. It
; cannot see a change in the peer repo at all — neither a renumber (which
; the snapshot would have to be updated for anyway) nor a RENAME, which
; moves nothing here and would leave our diagnostics printing a name that
; no longer exists upstream. Both are caught only by
; tools/test_net_err_registry.py, against a live checkout:
; test_snapshot_values_match_the_peer_registry and
; test_snapshot_names_match_the_peer_registry respectively.
.assert UCI_ERR_LONG_READ = NET_ERR_PEER_UCI_LONG_READ, error, "UCI_ERR_LONG_READ must mirror c64-wireguard's $8A exactly; it is their allocation, reserved and never emitted here (#184)"

; It still claims its byte. It cannot go through the macro above: that one
; asserts the value differs from every peer code, and $8A IS a peer code —
; the whole point of this entry.
;
; WHY KEEP THIS LINE, since it changes no outcome. It was checked: a second
; name of ours on $8A trips the macro's own $8A peer-collision assert first
; if it is registered, and test_our_codes_are_pairwise_distinct if it is
; not, so deleting this claim would fail exactly nothing and no check would
; notice. It stays because it makes the invariant total — EVERY code this
; repo defines claims its byte, with no exceptions to carry in your head —
; and a rule with one silent exception is the kind that rots. It is also
; the one hand-maintained claim site, so if you add another code that
; cannot go through a macro, it goes here beside this note.
NET_ERR_CLAIM_VALUE UCI_ERR_LONG_READ

; PUBLISHED VALUES, PINNED. The registry's single rule is that a published
; value is never reassigned — not renumbered to close a gap, not reused
; because a code turned out unreachable. These literals are that rule made
; mechanical, and they also give the set pairwise distinctness for free.
; Changing one of these numbers is not a refactor; it is a fleet-wide
; incompatibility, and it must fail here.
.assert NET_ERR_IP65_INIT    = $41, error, "NET_ERR_IP65_INIT is published as $41 and must never be reassigned (#184)"
.assert NET_ERR_IP65_DHCP    = $42, error, "NET_ERR_IP65_DHCP is published as $42 and must never be reassigned (#184)"
.assert NET_ERR_IP65_DNS     = $43, error, "NET_ERR_IP65_DNS is published as $43 and must never be reassigned (#184)"
.assert NET_ERR_IP65_CONNECT = $44, error, "NET_ERR_IP65_CONNECT is published as $44 and must never be reassigned (#184)"
.assert NET_ERR_IP65_SEND    = $45, error, "NET_ERR_IP65_SEND is published as $45 and must never be reassigned (#184)"
.assert UCI_ERR_NOT_PRESENT  = $81, error, "UCI_ERR_NOT_PRESENT is published as $81 and must never be reassigned (#184)"
.assert UCI_ERR_CMD_FAILED   = $82, error, "UCI_ERR_CMD_FAILED is published as $82 and must never be reassigned (#184)"
.assert UCI_ERR_NO_IP        = $83, error, "UCI_ERR_NO_IP is published as $83 and must never be reassigned (#184)"
.assert UCI_ERR_CONNECT_FAIL = $84, error, "UCI_ERR_CONNECT_FAIL is published as $84 and must never be reassigned (#184)"
.assert UCI_ERR_SEND_FAIL    = $85, error, "UCI_ERR_SEND_FAIL is published as $85 and must never be reassigned (#184)"
.assert UCI_ERR_READ_FAIL    = $86, error, "UCI_ERR_READ_FAIL is published as $86 and must never be reassigned (#184)"
.assert UCI_ERR_SHORT_WRITE  = $87, error, "UCI_ERR_SHORT_WRITE is published as $87 and must never be reassigned (#184)"
.assert UCI_ERR_NO_SOCKET    = $88, error, "UCI_ERR_NO_SOCKET is published as $88 and must never be reassigned (#184)"
.assert UCI_ERR_WAIT_TIMEOUT = $89, error, "UCI_ERR_WAIT_TIMEOUT is published as $89 and must never be reassigned (#184)"
.assert UCI_ERR_LONG_READ    = $8A, error, "UCI_ERR_LONG_READ is published as $8A and must never be reassigned (#184)"
.assert UCI_ERR_BAD_READ_HDR = $8B, error, "UCI_ERR_BAD_READ_HDR is published as $8B and must never be reassigned (#184)"

; $00 is "no error" in every family, fleet-wide, and is not allocatable.
.assert UCI_ERR_OK = $00, error, "UCI_ERR_OK must stay $00 - 'no error' is fleet-wide, not a UCI allocation (#184)"
