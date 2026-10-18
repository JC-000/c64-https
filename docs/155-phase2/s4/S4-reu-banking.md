# S4 — REU code banking (spike, #155 phase 2, DECISIONS item 8)

Tree: master `ac7099d`, worktree `p2-s4`. **M** = measured, **E** = estimate.
Maps (M): uci-onchip `eb348698…` (`cfg/c64-https-uci.cfg`), uci-comb `ed681de1…`,
wiki-comb `7bccb256…` (`HTTPS_HOST=en.wikipedia.org HTTPS_PATH=/wiki/Commodore_64
HTTPS_BODY_TO_REU=1`; both comb builds link `cfg/c64-https-uci-onchip.cfg`). Sizes
come from each map's Modules list. Sizes are pre-S2: R2 shrinks `der_decode`, R3
gates `viewer`.

## 1. Phase map (bytes of code+rodata, M)

| phase | code (segment / object) | onchip | comb |
|---|---|---|---|
| boot | `reu_mul_init`, sqtab, banner (LOADER); comb precompute runs the **P-256 lib** | — | — |
| key exchange | **X25519 image**: `fe25519` 2,692 (CRYPTO_CODE) + `LIB_X25519_CODE` 719 + `X25519_GLUE_CODE` 148 + `X25519_RODATA` 64; `hmac_drbg` 831 (keygen) | 3,623 | 3,623 |
| record/AEAD (EE → end of body) | chacha20 602, poly1305 734, aead 398, word32 549, sha256 1,859, hkdf, tls_record* | resident | resident |
| cert parse + name | tls_cert (TLS_CODE 874), der_decode 694, x509_name 491, CERT_BUF_BSS 2,048 | | |
| ECDSA verify | **P-256 image**: `LIB_NISTCURVES_P256_CODE` + `_RODATA` 192 + `MUL_CODE` 162 | **8,716** (code 8,362) | **9,849** (code 9,495) |
| Finished / keys | tls_keyschedule 1,277 (TLS_CODE 973), hkdf, sha256 | | |
| HTTP body | http.o (CODE 850, AUX 520+204, SINK 190) | | |
| viewer (after close) | VIEWER_CODE 1,189 (live only in wiki after R3) | | |

X25519 runs at CH (keygen) and after SH (shared). P-256 runs only at CertificateVerify
(and the comb boot precompute, and the future signed-bundle check). **The two never overlap.**
Call stack during verify (M, from source): `tls_deframe` pump (TLS_DEFRAME_CODE) →
`tls_handle_cert_verify` (TLS_CODE) → `ecdsa_verify` (CRYPTO_CODE) → lib. All other
crypto has returned by then.
Outward imports (M, map Imports list): the P-256 and X25519 objects depend only on
`poly1305.o` (`ct_mul_8x8`, `poly_prod_lo/hi`, `smc_*_imm` SMC operands), `data.o`/`mul_tables.o`
BSS, the REU register equates and ZP. **`poly1305.o` must stay resident.** Nothing
imports from the two libraries except `ecdsa_verify.o`, `boot.o` (comb precompute),
`tls_ecdh.o` and `x25519_tables.o`.
Free today (M, `measure_margins.py`, wiki-comb): 94+49+43+265+183 B tail + 101 B hole ≈ **0.7 KB total**.

## 2. Swap cost (M, U64E "Ultimate 64 Elite", REU 16 MB, DeviceLock)

Probe: `s4/probe_reu_dma.py`; raw data: `s4/reu_dma.json`. Each timed DMA is followed by a
clone of `reu_execute`'s REU_CONFIRM_LONG confirm + settle, and CIA2 timer A is
stopped before it is read. The setup was 3×3 at 48 MHz and 4×3 at 1 MHz. A CPU-loop
control confirms turbo: 273 ticks at 48 MHz against 13,677 at 1 MHz. The confirm
never expired.

| bytes | 48 MHz REU→C64 | 48 MHz C64→REU | 1 MHz (either way) |
|---|---|---|---|
| 3,623 (X25519, interp.) | ~1.1 ms | ~0.8 ms | ~3.8 ms |
| 7,680 | 2.41 ms | 1.62 ms | 8.1 ms |
| 10,240 | 3.19 ms | 2.16 ms | 10.8 ms |
| 32,768 | 9.93 ms | 6.84 ms | 34.3 ms |

At 48 MHz: about 3.3 MB/s REU→C64 and 4.8 MB/s C64→REU. At 1 MHz: 0.95 MB/s,
unblanked. The fixed overhead per transfer is 7 µs. **Contradiction:** the `crypto_swap.s` header and the
engineering notes say "~1 MB/s regardless of turbo"; on this U64E that is wrong by
about 3× at 48 MHz (n=1 device and firmware; I have not measured the cause).
Instrument trap: the first pass after `SYS` ran the CPU at 1 MHz (ctrl 13,634), while
its DMAs already ran at turbo rates. That pass is excluded.

**Per handshake:** at most ~11 ms at 48 MHz and ~45 ms at 1 MHz. Against a 38–45 s
handshake, that is noise.

**No-REU `/USB1` path (E):** `dos_read` (S1) pays two `uci_fence`s per byte (status +
data). That is 5 × 217 × 5 cy ≈ 114 µs each at 48 MHz, so ≈ 4.4 KB/s, plus ~40 ms per
512 B part (the SOCKET_READ round-trip figure). A P-256 image then costs ≈ 2.6 s and
X25519 ≈ 1.1 s. That adds 3.7–5.5 s per handshake (+8–12 % on 45.5 s). The image
reloads mid-handshake as DOS traffic while the TLS socket is open, which is an
interleave nobody has tested.

## 3. Constraints

- **Mechanism.** `crypto_swap.s` is P-384-shaped: one fixed `OVERLAY_SIZE=$1E00`
  slot at `__CRYPTO_OVERLAY_START__`, and it DMAs through `reu_execute` (SPEC §8.2
  confirm + settle, already covered). S2's R1 deletes it (no importer). A banking
  build would re-arm a leaner dispatcher (~80 B, E), gated as DECISIONS 2 requires.
- **REU banks (M, source).** Every profile's boot writes banks 0–1 (`reu_mul_init`).
  Comb claims bank 2 `$0000-$3FFF`. P-384 reserves banks 6–7. Wiki writes from
  `$10:0000` up (754 KB page ⇒ banks 16–27). **Trap:** `reu_layout.inc`'s
  `REU_OVERLAY_P256[_VERIFY]=$22100` and `REU_OVERLAY_STORE_BASE=$20100` sit
  *inside* comb's Lim-Lee table, so they must not be reused. Put the images in
  bank 3 (reservation only; no writer since #245) or at bank 2 `$4000+`. That fits a
  512 KB REU.
- **Library segments.** No archive member needs editing (§6.1). `LIB_NISTCURVES_P256_*`
  and `LIB_X25519_CODE` are whole segments that ld65 can place with `load=`/`run=`
  plus `define=yes`. `fe25519` already goes through the wrapper knob
  `X25519_SEG_FE25519` (`build_x25519.sh`), so it can get its own segment. The
  constraint is granularity: a segment moves whole (9,495 B for comb's P-256 code).
- **Staging.** The PRG must carry the banked image somewhere free *at load time*. The
  P-256 image (8.7–9.8 KB) does not fit `$E000-$FDFF` (7,680 B) or `$C000-$CFFF`.
  It does fit if loaded over `$A000-$CFFF` (runtime BSS + TCP ring) and stashed
  before boot zeroes `$A000`. The cost is a PRG that is ~10 KB longer.
- **SMC.** `fp256`, `mod256`, `points256_*`, `fe25519` and `x25519` are heavily
  self-modifying (hundreds of `sta label+n`), and nobody has audited whether any of
  it is written once at init. The safe design is to **stash the outgoing image
  before fetching the incoming one**, which costs about 2 ms extra. It is also why
  the `/USB1` variant (pristine images only) needs that audit first.
- **Resident floor.** These stay resident: ZP (the libraries already time-share it),
  all BSS (sqtab/TABLES_BSS, `LIB_NISTCURVES_P256_BSS`, LIMLEE_BSS for the comb
  anchor state), `poly1305.o`, `reu_execute`, and every routine on the call stack
  above, including the whole deframer.
- **uci-onchip has no REU.** On U64/C64U the REU is a built-in *config toggle*, not
  extra hardware: `_device_prep` already sets it. For UCI, then, "require an REU"
  costs a menu setting plus the product's "no REU" claim, whereas `/USB1` costs
  seconds per handshake (§2). The ip65 product is the only one where an REU is real
  hardware.

## 4. Candidate sets and recommendation

| design | slot | bytes freed (E, from M sizes) | swaps / handshake |
|---|---|---|---|
| **D1: X25519 ⇄ P-256, one slot** at P-256's home | 8,716 / 9,849 | **≈3.5 KB** (3,623 − dispatcher) | 2 (≤6 ms) |
| **D2: verify-eviction.** State A holds everything off-stack during verify (X25519 3,623 + sha256 1,859 + hmac_drbg 831 + tls_keyschedule 973 + chacha 602 + word32 549 + x509_name 491 + aead 398 = 9,326; + der 694). State B is P-256. | same | **≈8.6 KB onchip / ≈9.7 KB comb** (≈ the P-256 image) | 2 exchanges (≤11 ms) |
| D3: + viewer / boot-only code | — | +1.2 KB on wiki. A viewer doesn't need REU banking; boot code can just be reused as BSS after boot. | — |

**Recommendation.** Build only when a phase-2 tenant is actually refused a link. When
that happens, build **D1 first, for uci-comb** (including the wiki demo). Comb already
requires an REU, has free banks, and has only ~0.7 KB left. D1 moves three segments,
adds one small dispatcher and has a single call site per library. It gives 5× today's
total headroom for about 6 ms per handshake. D2 roughly triples that, but it relinks
about 10 objects into one contiguous 9.8 KB range in CRYPTO_HOT. Its correctness then
rests on an "off-stack during verify" invariant that the bundle-signature path
(DECISIONS 4) will exercise a second time, so hold it until D1 has shipped and an SMC
audit exists. **One slot, not several.** X25519 and P-256 are the only large, disjoint
pair; everything else is either live across the whole session (record layer) or too
small to pay for a second slot. **Do not bank uci-onchip via `/USB1`:** it is slower
by seconds, untested mid-handshake, and the REU toggle is free. **ip65** would gain the
most (it is "essentially full"), but only by becoming a new REU-required product.
That is a product decision, not a spike result.
