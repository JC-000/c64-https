# Phase F Part 1 — x25519 REU-overlay hang under BACKEND=uci

## Status (2026-04-20)

Investigation in progress — **root cause narrowed but not fully
identified**. Hang bisected to inside `x25519_scalarmult`
(sibling-provided ladder) during TLS handshake. Isolated x25519
(`tools/test_x25519.py`) passes, so the defect is stateful /
context-dependent.

## Reproducer

```
BACKEND=uci make clean && make
python3 tools/uci/test_https_local.py    # ~10 min timeout
```

Expected: ~110 s handshake, body = "HELLO FROM TLS SERVER".
Observed: 605 s timeout, `progress=0x03`, `tls_state=0x00`
(IDLE); `http_get`'s call to `tls_connect` never returns.

HEAD at time of investigation: `7bb64e8`.

## What was confirmed

Three runs with progressively deeper instrumentation, all using
a single-byte sub-progress beacon in `tls_last_state` ($95D2
SHADOW_BSS):

| Probe value           | Meaning                                  | Observed |
|-----------------------|------------------------------------------|----------|
| `$82`                 | pre `jsr tls_ecdh_generate_keypair`      | reached  |
| `$91`                 | inside keypair, post privkey-copy        | reached  |
| `$92`, `$93`          | pre fe25519_copy(basepoint), pre clamp   | reached  |
| **`$94`**             | **pre `jsr x25519_scalarmult`**          | **stuck**|
| `$9E`                 | post x25519_scalarmult (never seen)      | never    |

So the Montgomery ladder enters and never returns. 605 s is
~1200x a healthy 500 ms scalarmult at 48 MHz — not merely
slow, genuinely stuck.

Debug artifacts of the last probe run:
- `/tmp/uci_https_debug/20260420_*/tls_state_dump.json` —
  `tls_last_state=0x94`, other TLS state zeroed.
- `/tmp/uci_https_debug/20260420_*/tail.txt` — last 2000
  CPU cycles captured; PC hotspots inside capture filter
  ($2000-$3FFF, $6000-$9FFF, $DF1B-$DF1F) show stride-$2F
  reads through the crypto tables region.
- Server side logs a successful TCP accept
  (`client_addr = (..., 192.168.1.81:PORT)`) and an empty
  request buffer — TCP is up; TLS never ClientHello'd.

## What was ruled out

- Not a DNS / TCP connect hang — `net_tcp_state = $01`
  (UCI_TCP_CONNECTED) at hang; the local listener saw the
  inbound connection.
- Not a DRBG hang — two `drbg_fill_bytes` calls complete
  (probe `$82` reached).
- Not `fe25519_copy` / `x25519_clamp` — both complete
  (probe `$94` reached).
- Not overlay-image rot — Phase E `tools/test_crypto_init.py`
  still verifies overlay-slot-vs-PRG byte match at boot and
  was passing as of the last green run.
- Not the UCI register polling pattern seen in
  `uci_accesses.txt` — that's the **host-side bridge**
  reading $DF1B-$DF1F for the test harness's memory-read
  API, not CPU code polling. Confirmed by the 5-consecutive-
  cycle stride (5 reads in 5 cycles cannot be CPU `lda abs`
  which is 4 cycles each, capture filter only keeps the data
  read cycle — 5 cpu `lda`s would be ~20 cycles apart).

## Why test_x25519 passes but TLS hangs

`tools/test_x25519.py` drives `x25519_scalarmult` directly
after boot's `crypto_init`. TLS runs scalarmult *after*:

1. Boot's `sqtab_init` (legacy in-tree poly1305
   quarter-square init — runs **unconditionally**, not gated
   by `USE_X25519_SIBLING`, see `src/boot.s:211`). The
   sibling's sqtab was already built in `crypto_init` at
   `$7800/$7A00`; the legacy routine rebuilds the same
   quarter-square values to the same addresses. Redundant
   but should be harmless.
2. Boot's `do_net_init` (UCI probe + DHCP read).
3. Menu SYS trigger.
4. `http_get` → DNS memcpy → `net_tcp_connect` (issues a
   UCI TCP_CONNECT command, reads socket_id).
5. Hostname copy (32-byte memcpy).
6. `tls_connect` → two `drbg_fill_bytes`
   (calls into HMAC-DRBG → SHA-256).

## Promising next leads

1. **ZP corruption from the legacy `sqtab_init` at boot
   line 211.** The legacy routine uses module-local BSS
   `sq_acc/sh/ad/i` (no exports), so it shouldn't collide
   symbol-wise. However, if the ca65 linker places the
   legacy's private BSS at addresses that happen to overlap
   sibling data OR REU table backing regions, boot would
   silently corrupt a 1 KB range. **Check the `.map` file
   for `sq_acc`/`sq_sh` (legacy) placement vs sibling
   tables.** If they overlap, the fix is to gate the legacy
   call with `.ifndef USE_X25519_SIBLING` (same pattern as
   `reu_mul_init` at line 218).

2. **REU register state left in a bad config by something
   between `crypto_overlay_stash_x25519` and the first
   ladder mul.** The sibling's `fe25519_mul` relies on
   `reu_clear_wide` re-establishing the mul-row fetch
   config at entry, then issues bare `sta reu_command` DMAs
   that inherit `reu_c64_lo/hi` + `reu_len_lo/hi` from the
   clear-wide prelude. If SHA-256 or DRBG or HMAC touched
   `$DFxx` (they shouldn't, but check), or if an interrupt
   handler does, the first `fe25519_mul`'s REU fetch lands
   in the wrong C64 RAM region, corrupting `fe_wide`
   ($40-$7F). The ladder then multiplies indefinitely
   with garbage — the ladder loop counter (`x25_byte_idx`,
   `x25_bit_mask` in ZP $39-$3A) terminates correctly, but
   each fe25519_mul may itself never terminate if `fe_mul_j`
   ends up reading a table cell that doesn't decrement X to
   32.

3. **IRQ running during scalarmult, clobbering ZP $33
   (`fe_loop`) or $34 (`fe_mul_i`).** `crypto_swap_to_x25519`
   SEIs around its DMA but nothing in the crypto runtime
   SEIs around the ladder. On U64E the default IRQ handler
   is still KERNAL; at 48 MHz the per-frame IRQ fires with
   a LOT of cycles between — but if it interrupts between
   an `ldx fe_mul_i` and an `inx`/`cpx #32/bcc` group, the
   handler could stomp ZP. **Look at whether
   `src/boot.s` or `main.s` explicitly disables IRQs for
   the handshake.**

4. **UCI firmware is dispatching an async event (interrupt
   or bus-stall) that corrupts the REU mid-DMA.** Less
   likely because Phase E verified REU integrity at boot,
   but worth ruling out with a mid-handshake overlay-byte
   re-check (DMA-read `$4200-$5FFF` and compare against the
   prg image).

## Recommended immediate experiment

**Gate the boot-level legacy `sqtab_init` call the same way
`reu_mul_init` is gated:**

```diff
 jsr crypto_init

-        ; build quarter-square multiply table (needed by Poly1305, fe25519, ECDSA)
-        jsr sqtab_init
+        ; build quarter-square multiply table (needed by Poly1305, fe25519, ECDSA)
+        .ifndef USE_X25519_SIBLING
+        jsr sqtab_init
+        .endif
```

If the hang clears, the legacy routine was either stomping
sibling state or running against stale assumptions about
table contents. If the hang persists, move to lead #2 —
re-check REU registers before x25519_scalarmult.

## Reverted instrumentation

All `tls_last_state` probes added during this session have
been removed (`git diff --stat` returns clean). The probe
recipe is preserved above — reapply by patching
`src/tls13.s:123-143` and `src/tls_ecdh.s:49-70` as needed.

## Budget used

~60 minutes. Three U64E runs (10+ min each) consumed most
of the wall-clock. Follow-up agent should start from the
"Recommended immediate experiment" above.
