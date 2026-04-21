# Phase F Part 1 — trace.bin analysis

## TL;DR

**The captured `trace.bin` artifacts from runs 20260420_151301, _152431,
_154548 and _160911 do NOT contain sufficient signal to pinpoint the
exact instruction where `x25519_scalarmult` hangs.** The 6510 bus tap,
as filtered by `test_https_local.py::_keep_cycle`, is a periodic sampler
(one sample every ~1/48th of a CPU cycle at 48 MHz turbo); what surfaces
in the PC histogram is a *cadence* artifact, not a hot-loop fingerprint.

The hang itself is real and reproducible (handoff-doc probe byte
`tls_last_state = $94`, `tls_ecdhe_pubkey = 00...` in every snapshot),
but the trace *data* is not what will identify the specific loop.

## What the trace actually shows

1. **All captured cycles have PHI2 = 1** (CPU-phase), by construction.
   `_keep_cycle` in `tools/uci/test_https_local.py:134` drops PHI2 = 0
   samples. Every window I sampled (cyc 0, 10k, 50k, 200k, 1M, …, 13M)
   reports `CPU: 100%  VIC: 0%`.
2. **A dominant address stride of exactly $2F** (47 bytes) across the
   entire $2000-$9FFF filter window, for the entire 605 s duration.
   Sample (cycles 13105079-13105200, late in the run, from
   `20260420_154548/tail.txt`):

   ```
   13105079 R $6ACB=1E   13105080 R $6AFA=25   13105081 R $6B29=91
   13105082 R $6B58=40   13105083 R $6B87=31   ...
   ```

   Each consecutive sample is exactly $2F bytes further into memory,
   one per reported cycle. A 6510 cannot walk memory at 1 byte per
   cycle, let alone by $2F per cycle — this is **the sampling pattern
   of the bus tap, not instruction flow**.
3. **PC-histogram ceiling artifact**: `summary.txt` shows 20 distinct
   PCs all tied at exactly 3553 hits in the last-2M-cycle window
   (`$2012, $2041, $2070, $209F, $20CE, $20FD, ...` — stride $2F,
   covering the entire NET_CODE region). A genuine tight loop would
   produce a handful of PCs with much higher counts; a uniform sweep
   at 3553 hits across dozens of addresses is the packet cadence:

   ```
   packets: 1738174 over 605.4 s  →  2871 pkts/s at 48 MHz
   pkt → 360 cycles × 4 B  →  one sample every ~48 CPU cycles @48MHz
   window 2M samples / 530 unique kept addresses ≈ 3800 per addr,
     clamped by 2M / 563 ≈ 3553 per-addr cap (matches summary)
   ```
4. **All 124,270 `$DF1B-$DF1F` hits in `uci_accesses.txt` are
   5-consecutive-cycle $DF1B→$DF1C→$DF1D→$DF1E→$DF1F reads**, repeating
   every ~570 cycles. Five absolute-mode loads in five *consecutive*
   cycles is impossible for `lda abs` (4 cycles per op), so these are
   the *host bridge* polling its own identification registers, not the
   6510 polling UCI status. Confirms the handoff doc's note that the
   CPU is not executing UCI polling at all in the final seconds.
5. **No REU register accesses (`$DF00-$DF0F`) in the final 10,000
   cycles** (decoded window). The filter does not cover `$DFxx` outside
   UCI, so this is expected, not evidence by itself.
6. The 16:09:11 run's `server_result.json` shows
   `"error": "TimeoutError: timed out"` on accept — **that run failed
   before the 6510 ever opened a TCP socket**, which matches the
   handoff-doc note that Lead #1 (gating `sqtab_init`) regressed the
   failure mode. Runs 15:13-15:56 (pre-regression, with probe) show
   successful TCP accept (`client_addr = (..., 192.168.1.81:PORT)`),
   no bytes received — TLS never sent ClientHello, consistent with
   the hang inside `tls_ecdh_generate_keypair`'s `x25519_base` call.

## What the trace does NOT show

- **No identifiable hot-loop PC**. If the 6510 were stuck in a tight
  8-instruction loop inside `fe25519_mul`, I would expect those 8 PCs
  to dominate the histogram by orders of magnitude. They do not.
- **No REU DMA command writes** in the tail. If `reu_clear_wide` or
  `fe25519_mul`'s inline REU DMA were looping forever, we would see
  writes to `$DF01` in the captured window. We do not — but the
  filter excludes `$DF00-$DF0F`, so absence of REU writes in the
  capture is not probative either way.
- **No jammed-CPU signature**. A KIL opcode would freeze the bus and
  the tap would go silent; instead the tap reports continuous
  samples. So the CPU is doing *something* — but the filter and
  sampling rate don't tell us *what*.

## Why the trace cannot settle the question

The `_keep_cycle` filter (CPU cycles only, three address ranges) + the
360-cycle packet quantization + ~48:1 CPU-to-sample ratio at 48 MHz
means each packet provides **one sample per ~17,280 CPU cycles of
wall-clock**. A `fe25519_mul` run over 32 outer iterations × 32 inner
is on the order of ~10,000 cycles at 48 MHz — so a single mul lives
inside *one* sample. We cannot resolve finer-grained state from this
stream.

To actually identify the hang, the investigation needs either:

- **A cycle-accurate trace** (unfiltered, all PHI2 cycles in the hot
  regions, written at the host bridge's native rate), or
- **In-ROM instrumentation**: add a set of `tls_last_state` bumps
  *inside* `fe25519_mul` / `fe25519_sqr` (e.g., at entry, at outer-loop
  top, at inner-loop top, at exit) and re-run once, then inspect the
  post-hang byte to see which loop level is the offender, or
- **A jsr-level bisection harness** on the U64E at 48 MHz (drive
  `x25519_scalarmult` directly from a 6502 stub after boot, like
  `bench_ecdsa_u64e.py` does for ECDSA) to confirm whether the hang
  reproduces in isolation or only after the full pre-handshake
  sequence (DRBG × 2 + net init + DNS + TCP connect).

## Evidence anchoring the prior agent's narrowed fault

Independent of what the trace does not show, the `tls_state_dump.json`
snapshot itself is conclusive on *some* points:

| Field                 | Value                   | Inference                                    |
|-----------------------|-------------------------|----------------------------------------------|
| `tls_state`           | `$00` (IDLE)            | tls_connect never returned                    |
| `tls_last_state`      | `$94` (probe beacon)    | Execution reached the `jsr x25519_scalarmult` site but never the post-return beacon $9E |
| `tls_ecdhe_privkey`   | populated (non-zero)    | DRBG + clamp completed                        |
| `tls_ecdhe_pubkey`    | `00 00 ...` (32 zero B) | `x25519_base` / `x25519_scalarmult` never wrote the result |
| `tls_client_random`   | populated               | Both DRBG calls completed                     |
| `net_tcp_state`       | `$01` (CONNECTED)       | UCI TCP_CONNECT returned a socket             |
| `server_result.json`  | `client_addr = (..., :)` (in probe runs) | TCP was established, never received a byte |

All consistent with: **6510 entered `x25519_scalarmult` and did not
return within 605 s**, but the captured bus trace cannot differentiate
between "genuine 500× slowdown", "infinite loop at some PC", or
"periodic crash-into-BRK-handler-into-KERNAL" from what was captured.

## Candidate root causes (leads unchanged from prior handoff)

Given the trace does not distinguish them, the prior agent's leads
#2-4 remain open, with #1 already disproven:

- **~~Lead #1 (sqtab gate)~~**: confirmed regressive (see run
  20260420_160911 — TCP connect never happened).
- **Lead #2 (REU register state)**: most plausible. `fe25519_mul` in
  `libs/x25519/src/fe25519.s:357` relies on `reu_clear_wide` restoring
  mul-row FETCH config at line 329-336, then 32 inline DMAs with a
  short `asl / sta reu_reu_hi / adc #0 / sta reu_reu_bank / lda
  #%10110001 / sta reu_command` sequence at lines 391-397. If any
  intervening code between `crypto_overlay_stash_x25519` (boot) and
  the first ladder iteration writes to any `$DF00-$DF0F` register,
  the bare `sta reu_command` DMAs land in the wrong C64 RAM region
  and `mul_dma_lo/mul_dma_hi` contain garbage, but each DMA still
  terminates deterministically. **This alone would not cause an
  infinite loop** — so either lead #2 needs refining (e.g., `fe_mul_i
  / fe_mul_j` ZP clobber), or the true cause is a different axis.
- **Lead #3 (IRQ during ladder)**: no SEI around the ladder; KERNAL
  IRQ handler runs; at 48 MHz the IRQ fires every ~20 ms wall-clock,
  which over 605 s = 30,000+ IRQ events. Any single one that corrupts
  ZP $33 `fe_loop` or $34 `fe_mul_i` during a critical window could
  wedge the outer `cmp #32 / bcs @mul_done` comparison. This is
  plausible but not verifiable from the current trace.
- **Lead #4 (UCI firmware async event)**: not supported by the
  absence of CPU-issued UCI commands in `uci_accesses.txt`, and the
  harness-side $DF1B-$DF1F polling (5 cycles / 570 cycles interval)
  is host-originated bridge traffic, not 6510.

## No fix applied

I did not modify any source, and I did not run `test_https_local.py`.
Running one more 10-minute U64E test without a sharper hypothesis
would consume the hardware time without adding a single new signal
beyond what the four existing captures already show. The next step
needs in-ROM instrumentation (probe bytes inside `fe25519_mul`
itself) rather than another bus-tap capture — that is the only way
to move from "hang is somewhere inside the ladder" to "hang is on
outer iteration N, inner iteration M, at PC X".

## Budget used

~60 minutes. No U64E runs. No source modifications. Tree is at
`5d2d469`, clean.
