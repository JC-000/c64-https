# c64-https

An HTTPS client for the Commodore 64 in 6502 assembly. Implements TLS 1.3 over TCP/IP, with two interchangeable networking backends:

- **ip65** (default) — RR-Net (CS8900a) ethernet adapter via the [ip65](https://github.com/cc65/ip65) networking stack.
- **uci** — Ultimate 64 Elite (U64E) and C64 Ultimate onboard ethernet via the UCI command interface.

**For demonstration and educational purposes only — not cryptographically secure.**

> **Real-server milestone (2026-08-21/22).** The client now completes TLS 1.3
> handshakes and HTTP GETs against real public servers on the open internet —
> **github.com, browserleaks.com and lwn.net** all return HTTP 200 — and, as a
> demonstration, fetches the full 125 KB **Wikipedia article about the
> Commodore 64** over TLS into a 16 MB REU and scrolls it on the C64's own
> screen. Requires the UCI backend at turbo (comb profile). See the Project
> Status section and the "End-to-end HTTPS status" notes in `CLAUDE.md`.

## I just want to run it

Grab a release — latest is
[**v0.4.1**](https://github.com/JC-000/c64-https/releases/tag/v0.4.1).
**If you have v0.4.0, replace it**: a server presenting a P-384 certificate
could corrupt resident code and hang the machine (no real server triggered
it — see the v0.4.1 notes).
Every build is prebuilt, as a `.prg` and as a bootable `.d64`.
No assembler, no cc65, no Python packages, no build step. **Three products,
one disk each** — the label is the whole contents, and `MANIFEST.txt` in the
release walks you through the choice:

| image | for | note |
|---|---|---|
| `c64-https-ip65-onchip` | bone-stock C64 + RR-Net cartridge | maximum compatibility: no REU, no turbo, nothing optional. If you are not sure what you have, this is the one that runs. ~36 min per handshake at 1 MHz. |
| `c64-https-uci-onchip` | Ultimate 64 / C64 Ultimate at turbo, REU off | boots straight to the menu |
| `c64-https-uci-comb` | Ultimate 64 / C64 Ultimate at turbo, REU **on** | fastest — 1.73x quicker verify (16.4 s vs 28.4 s, U64E at 48 MHz). Builds a 16 KB table into REU bank 2 at each boot first: ~34 s at 64 MHz, ~45 s at 48 MHz. |

The screen blanks during the slow crypto on every image — that is deliberate,
it stops the VIC-II stealing bus cycles and buys ~6.5%. The progress line
returns between handshake phases, so a blank screen for minutes at a time is
the crypto running, not a hang.

`c64-https-listener.py` in the same release is a single self-extracting file
that stands up the server side to point the C64 at: it mints its own
certificate and needs nothing installed, only a `python3` whose `ssl` has
TLS 1.3. Run `python3 c64-https-listener.py --selftest` to check that before
involving a C64.

To build these yourself: `make package && make package-verify`.

## Before you build or test

Skip this if you took a release above — it is only for building from source.

Two prerequisites are not vendored here, and missing either fails with an error
that does not name it. Both are one-time, per clone:

```bash
git submodule update --init --recursive

# ip65 backend only — `make` builds the blob itself, but not these
make ip65-libs

# any test script, VICE or hardware — separate public repo, not in requirements.txt
git clone https://github.com/JC-000/c64-test-harness    # sibling of this repo
python3 -m pip install -e ../c64-test-harness
```

Skipping the first gives `ld65: Error: Input file
'../ip65/ip65/ip65_tcp.lib' not found`, from the blob link step that plain
`make` runs for you. (Issue #89 originally reported a different symptom from
the same missing step — `ip65_blob.s(22): Error: Cannot open include file` —
because make could assemble that object before building the blob; a
dependency edge in the Makefile now orders it correctly, so the ld65 message
above is what you get today.) Skipping the second gives
`ModuleNotFoundError: No module named 'c64_test_harness'` (#90). Use
`python3 -m pip` so the package lands in the interpreter that runs the scripts —
a venv mismatch reproduces #90 exactly after an install that appeared to succeed.

## Architecture

```
 ┌─────────────────────────────────────────┐
 │             HTTP/1.1 Client             │  http.s
 ├─────────────────────────────────────────┤
 │          TLS 1.3 Engine                 │  tls13.s (state machine)
 │  ┌──────────────┬──────────────────┐    │
 │  │ Record Layer │ Handshake Proto  │    │  tls_record.s, tls_handshake.s
 │  └──────┬───────┴────────┬─────────┘    │
 │         │                │              │
 │  ┌──────┴───────┐ ┌──────┴─────────┐    │
 │  │   AEAD       │ │  Key Schedule  │    │  (crypto modules)
 │  │ ChaCha20-    │ │  HKDF-SHA256   │    │  hkdf.s
 │  │ Poly1305     │ │  ECDHE X25519  │    │
 │  └──────────────┘ └────────────────┘    │
 ├─────────────────────────────────────────┤
 │        Network backend boundary         │  net_init / net_poll / net_tcp_*
 ├──────────────────────┬──────────────────┤
 │  ip65 backend        │  UCI backend     │  src/net/ip65/  |  src/net/uci/
 │  (TCP/UDP/DNS/       │  (firmware-level │
 │   DHCP/ARP)          │   TCP/UDP/DNS)   │
 ├──────────────────────┼──────────────────┤
 │  RR-Net CS8900a      │  Ultimate 64     │  original C64    |  U64E
 │  Ethernet Driver     │  Elite UCI I/O   │  ($DE00-$DE0F)   |  ($DF1B-$DF1F)
 └──────────────────────┴──────────────────┘
   make BACKEND=ip65       make BACKEND=uci
```

The TLS, HTTP, and crypto layers are backend-agnostic: switching backend
is a link-line change (different cfg + different `src/net/<backend>/*.o`),
not a call-site change.

`src/net_abi.inc` is **documentation, not an enforced interface**. No
translation unit `.include`s it (`grep -rn net_abi src/ tools/ cfg/ Makefile`
returns only comments), so none of its twelve `.import`s is checked by
the assembler or the linker. The symbols it declares and the
symbols TLS/HTTP/boot actually import overlap in 6 of 17, and the ip65
adapter exports neither `net_dhcp_acquire`, `net_tcp_set_recv_cb`,
`net_local_ip`, `net_resolved_ip`, `net_last_error` nor `net_tcp_state`
(`net_last_error` exists only under UCI, so ip65 has no error channel).
Making the header real, or deleting it, is item P1 of issue #70.

### TLS 1.3 Cipher Suite

**TLS_CHACHA20_POLY1305_SHA256** (0x1303) — the only suite the
ClientHello offers (`src/tls_handshake.s:85`), and the ServerHello echo
is checked against it (`:380`). There is no AES anywhere in `src/crypto/`.

- **AEAD:** ChaCha20-Poly1305 — in-tree `src/crypto/{chacha20,poly1305,aead}.s`, originally from [c64-wireguard](https://github.com/JC-000/c64-wireguard)
- **Hash:** SHA-256 — in-tree `src/crypto/sha256.s`, originally from [c64-aes256-ecdsa](https://github.com/JC-000/c64-aes256-ecdsa)
- **Key exchange:** ECDHE with X25519 only — `supported_groups` and `key_share` carry the single group 0x001D (`src/tls_handshake.s:204`); in-tree `src/crypto/{x25519,fe25519}.s`
- **Certificate signatures:** ECDSA P-256 (`ecdsa_secp256r1_sha256`, 0x0403) from the [c64-nist-curves](https://github.com/JC-000/c64-nist-curves) submodule at `libs/nistcurves`, via the thin dispatcher `src/crypto/ecdsa_verify.s`. P-384 (0x0503) is **no longer advertised** and is rejected — parked as roadmap work, see Known Issues.
- **Key derivation:** HKDF-SHA256, built from HMAC-SHA256 (`src/hkdf.s`)
- **PRNG:** HMAC-DRBG seeded from SID voice 3 noise + CIA timer entropy (`src/entropy.s`, `src/crypto/hmac_drbg.s`)

### What this client does NOT authenticate

Worth stating plainly, because "TLS 1.3 / HTTPS client" reasonably implies
otherwise, and nothing here said it before:

- **No certificate chain validation.** There is no trust store, no root CAs,
  no issuer check — `src/der_decode.s:271` skips the issuer field outright.
- **No hostname / SAN check.** The name you built with is sent as SNI and in
  the `Host:` header; nothing verifies the certificate matches it.

What the client *does* prove is that the peer holds the private key for the
leaf certificate it presented (the CertificateVerify signature is genuinely
checked against the transcript, and a forged server Finished is genuinely
rejected — see `tools/test_finished_verify.py`). What it does not prove is
that anyone vouches for that certificate. **A self-signed certificate for any
hostname is accepted**, so an active network attacker can impersonate any
server.

That is a deliberate scope decision for a 1 MHz machine — a chain walk means
more ECDSA verifies at ~16-30 s each, and a root store means kilobytes of
resident keys — not an oversight. Treat the transport as confidential against
passive observers, not authenticated against active ones.

### Zero Page Time-Sharing (ip65 backend)

Under the ip65 backend, the crypto modules and ip65 overlap on zero page $02-$1B. Rather than relocating ip65's ZP (which would cost performance in the networking hot path), we time-share: save crypto ZP before calling ip65, restore after. Crypto and networking never run simultaneously. The UCI backend uses absolute addressing throughout and needs no ZP swap.

```
$02-$03   Shared tmp (save/restore around ip65 calls)
$04-$09   word32 pointers (ChaCha20 / Poly1305)
$0A-$12   SHA-256 accumulators
$14-$17   mult66 pointers (fe25519) / ChaCha20 vars (time-shared)
$18-$1D   ChaCha20 + Poly1305 vars
$1E-$21   TLS record layer (record pointer, index, direction)
$22-$2B   ECDSA bignum pointers (fp_src1..fp_loop)
$2C-$37   fe25519 field arithmetic
$38-$3A   x25519 ladder state (shares $39-$3A with fp_mul_i/j)
$3B-$3C   ec_scalar_ptr
$FB-$FF   General pointers (save/restore around ip65 calls)
```

The authoritative list is `src/constants.inc`; the table above is a
summary of it.

The ip65 TCP callback (fired during `ip65_process`) copies received data into a ring buffer using only ip65's ZP context. After `ip65_process` returns and crypto ZP is restored, buffered data is processed through TLS.

## Memory Map

The two backends do **not** share a layout. Each is defined by its own
ld65 config, and the tables below were read back from
`build/c64-https.map` after `make clean && make [BACKEND=uci]`.

Common to both:

```
$0000-$00FF  Zero page (time-shared, see above)
$0100-$01FF  CPU stack
$0200-$03FF  KERNAL/BASIC work area + test-harness trampoline scratch
$DE00-$DE0F  RR-Net CS8900a I/O registers (ip65 backend)
$DF1B-$DF1F  UCI command/data registers (UCI backend, U64E / C64U only)
```

ip65 backend — `cfg/c64-https-ip65.cfg`:

```
$0801-$1FFF  LOADER              BASIC stub + boot + HTTP + most of TLS
$2000-$3FFF  NET_CODE            ip65 blob (6,951 B) + LOADER_OVERFLOW
                                 + CRYPTO_AUX_CODE2
$4000-$4F8B  NET_BSS             ip65 blob's BSS
$4F8C-$5FFF  CRYPTO_OVERLAY      4,212 B; holds TLS_CODE + CRYPTO_AUX_CODE
$6000-$9FFF  CRYPTO_RESIDENT     16 KB code + rodata, incl. the
                                 libs/nistcurves P-256 verify path
$A000-$BFFF  CRYPTO_COLD_SHADOW  8 KB BSS under the BASIC ROM shadow
                                 (cert_buf $A000, tls_rec_buf $A600,
                                  tables $BA00, sqtab_lo $BC00)
$C000-$CFFF  TCP_BUF             tcp_recv_buf, 4 KB ring
```

UCI backend — `cfg/c64-https-uci.cfg`:

```
$0801-$1FFF  LOADER              BASIC stub + boot + HTTP + most of TLS
$2000-$3B65  NET_CODE            UCI adapter (~2 KB) + LOADER_OVERFLOW
                                 + TLS_CODE + CRYPTO_AUX_CODE(2)
$3B66-$41FF  NET_BSS_TAIL        LIB_NISTCURVES_P256_BSS spill
$4200-$5FFF  CRYPTO_OVERLAY      7.5 KB overlay slot — empty in the
                                 shipped build; claimed by the X25519
                                 sibling / P-384 / P-256-embed flags
$6000-$9FFF  CRYPTO_HOT          16 KB code + rodata + UCI_BSS
$A000-$BFFF  CRYPTO_COLD_SHADOW  8 KB BSS (same tenants as ip65)
$C000-$DFFF  OVERLAY_FILE_PAD    zero-pad in the PRG; at runtime the
                                 4 KB TCP_BUF ring lives at $C000
$E000-$FDFF  OVERLAY_BLOB_CURVE  P-384 curve overlay blob slot (empty
                                 by default — P-384 is not built)
```

No segment may cross $A000: boot zeroes $A000-$BFFF as BSS, so anything
executable there would be wiped on first call.

TLS 1.3 records can be up to 16,384 bytes. The ClientHello negotiates
`max_fragment_length` (RFC 6066) with value 1 = **512 bytes**
(`src/tls_handshake.s:281`), and `TLS_RECORD_MAX = 512` in
`src/constants.inc` sizes the buffers to match.

## Building

**Requirements:**
- [cc65 toolchain](https://cc65.github.io/) — ca65 + ld65 (ACME is no longer used)
- GNU Make
- VICE (`x64sc`) — only for `make run` and the test harness

```bash
git clone --recursive https://github.com/JC-000/c64-https.git
cd c64-https
make                          # build/c64-https.prg (default BACKEND=ip65, REU profile)
make BACKEND=uci              # the Ultimate 64 / C64 Ultimate (UCI) variant
make USE_NISTCURVES_ONCHIP=1  # the no-REU "onchip" P-256 verify profile
make VIC_BLANK=0              # measurement control only: VIC blanking off (never ship)
make run                      # build and launch in VICE (x64sc)
make clean                    # remove build artifacts
make package                  # the three release products into dist/
```

**Run `make clean` whenever you change `BACKEND=` or any flag.** make
tracks source timestamps, not the command line, and `BACKEND=` selects
an include path (`-I src/net/$(BACKEND)`) rather than a `-D` define, so
an object built for the other backend counts as up to date. Both failure
modes are silent and exit 0: a mixed link that is the correct size but
carries the wrong backend's tuning constants, or no relink at all,
leaving the other backend's PRG in `build/`. Neither the exit code nor
the file size distinguishes them — compare the **PRG's** sha256 if a
build matters. (Object hashes cannot serve: ca65 stamps build time into
every `.o`, so no two builds agree; ld65 does not propagate it, which is
what makes the PRG deterministic.)

### ip65 Build (ip65 backend only)

ip65 is built from the submodule into a flat binary blob at $2000, using
a custom ld65 linker config (`ip65-build/ip65.cfg`), and linked into the
ca65 build via `.incbin`. **A plain `make` produces that blob for you** —
`$(IP65_BIN)` is a real prerequisite of the PRG, and a dependency edge on
`build/net/ip65/ip65_blob.o` forces it to be built before the object that
`.incbin`s it. Verified from a genuinely fresh `git clone` on 2026-08-15:
submodule init, `make ip65-libs`, then plain `make` yields the 47,105 B PRG
with no intermediate step.

What `make` cannot do for you is build the ip65 `.lib` archives the blob
links against, so run `make ip65-libs` once per clone, as in "Before you
build or test" above; `make ip65-blob` exists only to force a rebuild. The
build is deterministic: 6,951 B, sha256 `cf1a5ff7809af4e4655e385b378b936054f41046ff2b7604828af3240c2d90dd`.
`make clean` does not remove it, which is why the step is normally
invisible. The UCI backend does not use the blob at all.

One measurement trap, since it has already produced a wrong conclusion once:
ca65 also resolves `.incbin` relative to the current directory, and
`../../../` from a repo root escapes three levels up — which is exactly the
depth of a git worktree under `.claude/worktrees/<name>/`. Such a worktree
with no blob of its own silently assembles the parent checkout's blob and
appears to build fine. Check blob behaviour in a real clone, not a worktree.

## Project Status

Current status (measured 2026-08-14 with cc65 from Homebrew;
`ls -l build/c64-https.prg` and `grep -c '^al ' build/labels.txt` after
`make clean && make [BACKEND=uci]`):

- ip65 build: 47,105 B PRG, 2292 labels
- uci build:  62,977 B PRG, 2400 labels

Much of both PRGs is deliberate zero fill — the ld65 configs mark the
inter-region gaps `fill = yes` so the load addresses stay right — so
neither figure is a code-size measurement.

Progress:

- [x] Project structure and build system
- [x] ip65 submodule integration — 6.8 KB binary blob at $2000 (TCP/UDP/DNS/DHCP/ARP + RR-Net CS8900a)
- [x] Network wrapper with ZP time-sharing — save/restore $02-$1B around ip65 calls
- [x] Crypto primitives — ChaCha20, Poly1305, AEAD (from c64-wireguard), SHA-256, HMAC-DRBG (from c64-aes256-ecdsa)
- [x] Optimized X25519/fe25519 — REU DMA multiply tables, mult66 quarter-square, self-mod code, 4x-unrolled cswap. `tools/bench_x25519.py` measures one basepoint scalar multiply at **12,637 jiffies = 211 s (3.5 min)** of C64 time (NTSC, VIC-II blanked, ~21 s wall clock under VICE warp); the same multiply costs 13,494 jiffies unblanked
- [x] VIC-II blanking during the CPU-bound crypto — `src/vic.s`, scoped to the two X25519 scalar multiplies and the ECDSA verify so the on-screen handshake progress markers stay visible between phases. Worth **6.3-6.8%**, measured both in VICE at 1 MHz and on a U64E at 8/16/48 MHz; see the VIC-II blanking section of `CLAUDE.md`
- [x] HKDF-SHA256 — Extract, Expand, Expand-Label, Derive-Secret (RFC 5869 + TLS 1.3)
- [x] TLS 1.3 record layer — encrypt/decrypt with ChaCha20-Poly1305, nonce construction, sequence numbers
- [x] TLS 1.3 handshake — ClientHello builder (x25519 key_share, SNI), ServerHello parser, streaming transcript hash
- [x] TLS 1.3 key schedule — early/handshake/master secrets, traffic key derivation, Finished MAC (RFC 8446 §7.1)
- [x] ECDHE x25519 key exchange — generate keypair, compute shared secret
- [x] TLS 1.3 key schedule integration testing — all 9 HKDF steps verified against RFC 8448 + Finished MAC
- [x] Entropy/DRBG initialization — SID voice 3 noise + CIA timer seeding at boot, DRBG fills for TLS random values
- [x] X.509 certificate parsing — DER parser extracts TBS, public key, signature (r,s), curve ID for P-256 and P-384
- [x] ECDSA P-256 signature verification — supplied by the `libs/nistcurves` submodule (`ecdsa_verify_256`), always resident under both backends; `src/crypto/ecdsa_verify.s` is a thin dispatcher that packs the big-endian input struct. P-384 verify is **not** built — see Known Issues.
- [x] HTTP/1.1 GET request — build GET, parse response (status + headers + body), plain HTTP end-to-end
- [x] **End-to-end HTTPS GET demo (both backends)** — TLS 1.3 handshake + HTTP GET completes against a local Python TLS listener (ECDSA-P256 cert). Returns `http_status=200`, body `"HELLO FROM TLS SERVER"`.
  - UCI: real Ultimate 64 Elite hardware at both 48 MHz turbo and stock 1 MHz. See `tools/uci/rig_https_local.py` (supports `TURBO_MHZ` env var).
  - ip65: VICE + RR-Net at stock 1 MHz, no warp. The bridge-rig script is `tests/rig_phase3_https_1mhz.py`; the hardware-free macOS feth/pcap rig is `tests/rig_vice_https_macos.py`, and that is where the wall-clock below was taken.
- [x] **Real public-internet HTTPS (UCI/comb, turbo)** — github.com, browserleaks.com and lwn.net all return `http_status=200` on real U64E hardware at 48 MHz. Needed three pieces of work over the local-listener path: a streaming handshake-message deframer (`src/tls_deframe.s`) for flights where handshake messages don't align with TLS records; a 2048 B `cert_buf` under UCI so larger real leaves fit; and — the last blocker — clamping the UCI adapter's `SOCKET_READ` request to the receive ring's free space, without which any flight over ~4 KB lost its tail to a ring-wrap drop. Build-time target is `make HTTPS_HOST=<host>` / `HTTPS_PATH=<path>`; the rig is `tools/uci/rig_https_live.py`.
- [x] **Wikipedia article into REU + on-screen viewer (stretch goal, UCI/comb)** — `make HTTPS_HOST=en.wikipedia.org HTTPS_PATH='/w/index.php?title=Commodore_64&action=raw' HTTPS_BODY_TO_REU=1` streams the 125,235 B article body into REU bank 16 (`$10:0000`) and drops into a scroll viewer (`src/viewer.s`, CRSR/SPACE/F1/HOME/Q). Verified on U64E @ 48 MHz, body byte-checked against a host-side reference fetch. Rig: `tools/uci/rig_https_wiki.py`.

### Known Issues

- **The handshake is slow, and the ECDSA P-256 verify dominates it.** Every figure here is quoted from the measurement record in `CLAUDE.md`. Except where noted they were taken at the **`libs/nistcurves` v0.6.0 pin**, and the pin is now v0.11.2, so treat them as a baseline rather than as current. The one profile re-measured at the current pin is comb: 46.986 / 24.440 / 16.402 s verify at 16 / 32 / 48 MHz (U64E, n=3, VIC blanking active). End-to-end handshake + GET against the local listener, U64E, master 2ceb5b1: **80.8 s** (REU profile, 48 MHz), **45.5 s** (onchip profile, 48 MHz), **1,157.7 s** (REU, stock 1 MHz). One point of that sweep has been carried forward: 48 MHz REU measures **82.1 s** at v0.9.1 and **82.4 s** at v0.10.1 (n=1 each, so the 0.4% step between them is noise; the 1.6% from v0.6.0 is the FIPS 186-5 public-key validation gate v0.7.0 added). No other clock or profile has been re-measured. On the REU-less stock-C64 path (ip65 + onchip, no REU, honest 1 MHz in VICE) the whole run measured **2,159.7 s = 36.0 min**, of which the verify stretch alone was 1,416.7 s. That is fine for the local listener, which holds the connection open; it exceeds a typical 10-30 s real-world server handshake window.
- **P-384** ECDSA is stubbed at the TLS layer. The dispatcher advertises `ecdsa_secp384r1_sha384` (0x0503) and routes to `src/crypto/ecdsa_verify_384.s`, but no P-384 build target completes. Measured 2026-08-14: `make p384-overlay` from a clean tree stops at `No rule to make target 'build/labels.txt'`, and after a main build has produced that file it stops at `Segment 'LIB_NISTCURVES_SHA384_TABLES' overflows memory area 'OVERLAY_REGION' by 1536 bytes`. Cert chains requiring P-384 will not verify.
- **`USE_X25519_SIBLING=1` now links under UCI, and still does not under ip65.** The duplicate-symbol failure this entry used to record — `ld65: Error: Duplicate external identifier: 'reu_mul_tables_init'`, on **both** backends — was closed by the `libs/nistcurves` v0.10.1 / `libs/x25519` v0.11.0 bump plus one line of archive surgery: `tools/integration/build_nistcurves_p256.sh` now also drops `reu_mul_init.o`, the SPEC §8.2 `reu_mul` provider that `src/boot.s` supplies itself. Re-measured at the current v0.11.2 pins, unchanged: `make clean && make BACKEND=uci USE_X25519_SIBLING=1` produces a 62,977 B PRG, and ip65 stops instead at `Segment 'X25519_RODATA' overflows memory area 'CRYPTO_OVERLAY' by 3584 bytes` — a placement problem (ip65's overlay slot is 4,212 B against UCI's 7,680 B), not a symbol collision. The flag remains **off by default** and no shipped artifact contains the sibling; the in-tree X25519 in `src/crypto/{x25519,fe25519}.s` is what every release PRG is built from. Flipping the default is a separate decision that wants a hardware handshake behind it.
- **Real-server reach is UCI/comb + turbo only, and has size limits.** The public-internet HTTPS above works on the comb profile at turbo; the stock-C64 ip65 path is far too slow for a real server's connection window (~36 min/handshake). Among real leaves, en.wikipedia.org's 1636 B leaf needs the 2048 B UCI `cert_buf` (fits); anything larger, or a server that ignores `max_fragment_length` and sends >548 B records (e.g. Cloudflare), is out of scope. Cloudflare additionally enforces a ~15 s connect-to-first-request deadline the C64 cannot meet and is deliberately unsupported.
- **The wikipedia stall was a client bug, now fixed.** Historical note for anyone bisecting: TLS flights larger than the ~4 KB UCI receive ring used to stall permanently, because `net_poll` requested a fixed 512 B and its fill loop dropped bytes past the ring's current free space (discarded as "delivered"). Fixed by clamping the `SOCKET_READ` request to ring free space (`src/net/uci/net.s`). It was never a firmware bug; github/browserleaks/lwn flights are under 4 KB and were unaffected.
- **VICE 3.9** previously appeared to crash on chained HMAC-SHA256 calls (backend-independent — affects the crypto-only test suites), but this was caused by hardcoded port numbers bypassing the test harness port allocator. With proper `ViceInstanceManager` usage (no hardcoded ports), all N=1..10 chained calls succeed reliably.

## Test Automation

**266 assertions across 11 suites**, plus several standalone scripts the
parallel runner does not cover, using the
[`c64-test-harness`](https://github.com/JC-000/c64-test-harness) package
to drive VICE via its binary monitor protocol. VICE runs the **ip65
backend by default** (the UCI backend targets real U64E hardware — see
the Ultimate 64 Elite Hardware Tests section below). The parallel runner
allocates a fresh VICE instance per suite (with REU, which the sibling
P-256 code requires) to avoid state contamination. All tests log VICE
PID and port for multi-agent safety.

Suite counts below were taken from a `tools/run_all_tests.py` run on
2026-08-14 (266/266, 2 min 5 s wall clock on an M-series Mac).

```bash
python3 -m pip install -e ../c64-test-harness

# Run all 11 suites in parallel (one VICE instance per suite, ~2 min)
python3 tools/run_all_tests.py
python3 tools/run_all_tests.py --skip-slow   # Skip the x509/ECDSA suite: 255 assertions, ~45 s
python3 tools/run_all_tests.py --workers 6   # Limit concurrent VICE instances

# Individual suites (the 11 the runner aggregates)
python3 tools/test_net.py           # 60 tests: ip65 integration, ZP save/restore, ring buffer, TCP recv callback
python3 tools/test_sha256.py        # 7 tests: NIST vectors, boundary cases, random inputs
python3 tools/test_crypto.py        # 22 tests: ChaCha20/Poly1305/AEAD RFC 7539 vectors + random
python3 tools/test_hkdf.py          # 12 tests: RFC 5869 vectors, TLS 1.3 key schedule, random
python3 tools/test_tls_record.py    # 17 tests: nonce, seq increment, encrypt/decrypt, roundtrips
python3 tools/test_x509.py          # 11 tests: DER parse P-256/P-384, ECDSA verify (valid+tampered+boundary)
python3 tools/test_tls_handshake.py # 21 tests: transcript hash, ClientHello, ServerHello, key schedule (RFC 8448), Finished MAC
python3 tools/test_keyschedule_steps.py # 9 tests: key schedule step-by-step (RFC 8448 vectors)
python3 tools/test_entropy.py          # 7 tests: SID/CIA hardware init, DRBG seeding, output quality
python3 tools/test_http.py            # 27 tests: HTTP/1.1 GET builder, response parser, status codes
python3 tools/test_x25519.py          # 73 tests: fe25519 field ops, x25519_clamp, scalarmult + RFC 7748 vectors

# Standalone scripts, not aggregated by run_all_tests.py
python3 tools/test_chained_hmac.py     # 10 cases: chained HMAC-SHA256 stability (N=1..10)
python3 tools/test_finished_verify.py  # 18 cases: the server-Finished REJECTION path, driven over DMA
python3 tools/test_ecdsa_kat_oracle.py # 6 vectors: ECDSA P-256 KAT, 3 valid + 3 negative CAVP
python3 tools/test_package_verify.py   # 31 cases: pure-logic tests for the release gate (no VICE, no build)
python3 tools/test_pytest_boundary.py  # 5 checks: the pytest collection boundary below is intact

# Benchmark
python3 tools/bench_x25519.py         # X25519 basepoint multiply: 12,637 jiffies / 211 s C64 time (VIC blanked)
python3 tools/bench_x25519.py --no-blank  # same multiply unblanked: 13,494 jiffies — the badline A/B

# Integration tests (require the bridge/TAP rig + dnsmasq; see scripts/setup-bridge-tap.sh below)
python3 tools/test_dns.py             # 4 tests: DNS resolution via ip65 over TAP (label, known host, second host, unknown host)
python3 tools/test_http_integration.py # 5 tests: end-to-end plain HTTP GET over TAP (DNS + TCP + request/response)

# End-to-end bridge tests (require br-c64 bridge, RR-Net; see below)
sudo PYTHONPATH=tools python3 tests/rig_phase1_dhcp.py   # DHCP over RR-Net bridge
sudo PYTHONPATH=tools python3 tests/rig_phase2_http.py   # Plain HTTP GET over bridge
```

### `pytest` is not the runner here

Almost nothing in this repo is a pytest test, and the file names hide
that. The suites above are dispatched by `tools/run_all_tests.py`, which
allocates a VICE instance per suite and calls
`run_tests(transport, labels, seed)`; their `test_*` functions take
positional arguments rather than fixtures, so pytest can only ever report
`fixture 'transport' not found`. The scripts in `tests/`, `tools/uci/` and
several under `tools/` are `main()` programs with no `def test_` at all,
so pytest collects zero from them and says nothing about it.

The two rig directories are named `rig_*.py` for exactly that reason —
`tests/` since #111, `tools/uci/` since its follow-up. A rename is what
holds no matter which directory pytest is invoked from; `norecursedirs`
is what keeps a root-level run out of them. Both halves are pinned by the
guard.

`pytest.ini` therefore pins `testpaths` to the three modules that really
are pure-logic and pytest-runnable, and `conftest.py` prints the scope of
the run in both the header and the summary. A bare `pytest` at the repo
root reports **31 passed** (exit 0), and says in the same breath that this
is not a statement about the C64 suites or the rig scripts. `pytest tests/`
and `pytest tools/uci/` both exit 5, "no tests ran", with an explanation
naming the right README.

`testpaths` applies only when pytest is invoked from the rootdir, so from
a subdirectory you get that subdirectory instead — measured from `tools/`:
31 passed, 74 `fixture 'transport' not found` errors, exit 1. That is the
honest signal (pytest genuinely cannot run those modules) and it is loud,
which is the opposite of the problem being fixed here.

`tools/test_pytest_boundary.py` fails if the boundary drifts in any
direction — a pure-logic module missing from `testpaths`, a listed module
pytest cannot run, a `test_*.py` reappearing in `tests/` or `tools/uci/`,
or a rig directory dropping out of `norecursedirs`. See issue #109.

### End-to-End Bridge Tests (ip65 backend)

Full end-to-end tests that drive the real c64-https binary in VICE over a Linux bridge with RR-Net ethernet (the same pattern used by [`c64-test-harness` bridge networking](https://github.com/JC-000/c64-test-harness/blob/master/docs/bridge_networking.md)). These exercise the **ip65/RR-Net path only**: DHCP (phase1), plain HTTP (phase2), and HTTPS (phase3 via `tests/rig_phase3_https_1mhz.py`). VICE runs at **normal speed** (warp breaks RR-Net DHCP), so these tests need generous timeouts (~90-120s per phase).

The HTTPS phase is long. The nearest measured figure is from the
hardware-free macOS rig rather than this Linux bridge:
`tests/rig_vice_https_macos.py`, ip65 + onchip profile with no REU,
honest 1 MHz, **2,159.7 s = 36.0 min** from `G` to `CONNECTION CLOSED`.
Budget accordingly; do not assume the bridge rig matches it exactly.

On macOS the equivalent rig uses a feth pair plus pcap instead of a
Linux bridge — `sudo bash tools/rig-up-macos.sh`, and a VICE built with
the pcap driver's `geteuid()==0` gate patched out, because stock macOS
VICE binaries reject unprivileged `-ethernetiodriver pcap`. See the
"VICE ip65 rig" section of `CLAUDE.md`.

**Setup:**

```bash
# Create the bridge, TAP interfaces, and start dnsmasq (DHCP + DNS)
sudo ./scripts/setup-bridge-tap.sh

# Tear down (also handles stale VICE processes, legacy tap-c64, vicerc files)
sudo ./scripts/cleanup-bridge-tap.sh
```

The setup script creates `br-c64` with `tap-c64-0`/`tap-c64-1`, assigns `10.0.65.1/24` to the bridge, and starts dnsmasq providing DHCP (pool 10.0.65.50-150) with DNS overrides (`zimmers.net` and `foo.bar` → `10.0.65.1`). The `BridgeEnv` context manager in `tools/https_e2e/env.py` wraps both scripts for use in tests.

**Library:** `tools/https_e2e/` exposes a reusable public API:

| Module | Public API |
|--------|-----------|
| `env.py` | `BridgeEnv` (context manager), `check_prerequisites()` |
| `vice_on_bridge.py` | `launch_vice_on_bridge()` → `ViceHandle`, `shutdown_vice()` |
| `c64_menu.py` | `press_key()`, `wait_for_screen_text()`, `get_screen_text()` |
| `http_listener.py` | `start_http_listener()` → `HttpListenerHandle`, `stop_http_listener()` |
| `https_listener.py` | `start_https_listener()` → `HttpsListenerHandle`, `stop_https_listener()` |

### Ultimate 64 Elite Hardware Tests (UCI backend)

Scripts under `tools/uci/` drive a real Ultimate 64 Elite over the network (default `192.168.1.81`, overridable via the `U64_HOST` environment variable), exercising the **UCI backend only** (built with `make BACKEND=uci`). They DMA the PRG into RAM, run the boot, and snapshot UCI/TLS state on completion or timeout. These scripts do not run under VICE.

**Prerequisite — `c64-test-harness` (same as the VICE suites above).** It is a separate public package, not vendored here; `requirements.txt` carries only `cryptography`. Without it every script in this directory dies at import with `ModuleNotFoundError: No module named 'c64_test_harness'`:

```bash
git clone https://github.com/JC-000/c64-test-harness    # sibling of this repo
pip install -e ../c64-test-harness
```

Install it into the **same interpreter you run the scripts with** — if you use a virtualenv, `pip` and `python3` must both be that venv's, or the import fails despite the install appearing to succeed.

```bash
python3 tools/uci/boot_check.py          # UCI firmware detection
python3 tools/uci/phase2_check.py        # DHCP + local IP readback
python3 tools/uci/phase3_tcp_echo.py     # TCP connect/send/recv
python3 tools/uci/rig_http_local.py     # HTTP GET against local listener
python3 tools/uci/rig_https_local.py    # HTTPS GET (TLS 1.3 + ECDSA-P256)
python3 tools/uci/rig_https_bad_finished.py  # client must ABORT on a forged server Finished
```

These are `rig_*.py`, not `test_*.py`, for the same reason as `tests/`: a
hardware `main()` script named the pytest way gets walked by pytest, collects
zero, and reports nothing — which reads as coverage it does not have (issue
#109). `tools/uci/README.md` lists all of them; `tools/test_pytest_boundary.py`
fails if a `test_*.py` file reappears in either rig directory.

**Prerequisite — the REU, unless you build the on-chip profile.** The default
`make BACKEND=uci` image is the *REU profile*: X25519's field multiply and the
P-256 archive both fetch their multiply rows from REU banks by DMA. On a device
with **Settings → C64 and Cartridge Settings → RAM Expansion Unit → Disabled**
(the C64 Ultimate's factory setting) that DMA silently no-ops, the handshake
derives a wrong shared secret, and the client spins ~44 minutes on a screen
ending `KEYS ENC1 RX` — which reads as a lockup (issue #97). Either enable the
REU, or build the profile that needs none:

```bash
make clean && make BACKEND=uci USE_NISTCURVES_ONCHIP=1
```

Every script that exercises the crypto path (`rig_https_local.py`,
`rig_https_bad_finished.py`, `rig_https_print_body.py`,
`rig_https_local_p384.py`, `bench_ecdsa_u64e.py`) now **preflights this in one
REST call and exits 4 in seconds** if a REU-profile build meets a device with no
REU. On-chip builds skip the check entirely. The preflight never writes device
config — the U64E is queue-shared and config writes persist until power cycle,
so enabling the REU is yours to do. `C64_SKIP_REU_PREFLIGHT=1` bypasses it.

`rig_https_bad_finished.py` is the negative path: it talks to
`tools/https_e2e/evil_listener.py`, a hand-rolled TLS 1.3 server that
flips one bit of the server Finished `verify_data` before encryption
(corrupting the ciphertext instead would be caught by Poly1305 and never
reach the Finished comparison). Run `FINISHED_MODE=good` first as the
control. `tools/test_finished_verify.py` is the VICE-only equivalent.

`rig_https_local.py` is the end-to-end HTTPS demo (UCI backend only): it boots the U64E at 48 MHz turbo, connects to a local Python TLS listener using the test cert under `tools/https_e2e/certs/`, and confirms a full TLS 1.3 handshake + HTTP GET. That cert is gitignored throwaway material — the directory is empty in a fresh clone and the pair is generated on first use, with no dependency beyond the standard library (`python3 tools/https_e2e/ensure_certs.py` mints it by hand). With `DEBUG_CAPTURE=1`, each run writes a timestamped artifact directory under `$UCI_DEBUG_DIR` (default `/tmp/uci_https_debug/`) with raw 6510 bus trace, TLS state snapshot, and listener result.

Environment variables honored by `rig_https_local.py`:

- `U64_HOST` (default `192.168.1.81`) — U64E address
- `TURBO_MHZ` (default `48`) — C64 CPU speed. `TURBO_MHZ=1` runs the test at stock 1 MHz with every wall-clock budget auto-scaled, and is validated end-to-end on real U64E hardware; the handshake + GET itself measured 1,157.7 s (~19 min) there, not the full budget.
- `HTTPS_PORT` (default `443`, falls back to `4433` if the bind fails)
- `SENTINEL_POLL_TIMEOUT`, `ACCEPT_TIMEOUT` — per-test overrides in seconds; default to `600 * max(1, 48 / TURBO_MHZ)`.
- `EXTERNAL_LISTENER=1` (plus `EXTERNAL_HOST`, `EXTERNAL_PORT`, default `4433`) — skip the inline listener and point the C64 at an out-of-band server, e.g. the `c64-https-listener.py` from a release.
- `DEBUG_CAPTURE` (default `1`) — set to `0` to disable the bounded 6510 bus stream.
- `KEEP_DEBUG_ON_PASS` (default `0`) — set to `1` to preserve artifacts on PASS runs.
- `UCI_DEBUG_DIR` (default `/tmp/uci_https_debug`) — base directory for run artifacts.

## Related Projects

Vendored as submodules and linked into the PRG:

- [c64-nist-curves](https://github.com/JC-000/c64-nist-curves) — `libs/nistcurves`, the ECDSA P-256 verify used for CertificateVerify
- [c64-x25519](https://github.com/JC-000/c64-x25519) — `libs/x25519`, an alternative X25519 behind `USE_X25519_SIBLING=1` (not currently linkable — see Known Issues)
- [ip65](https://github.com/cc65/ip65) — the TCP/IP stack behind the ip65 backend

Not vendored — origin of code that now lives in-tree, or tooling:

- [c64-wireguard](https://github.com/JC-000/c64-wireguard) — ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD
- [c64-aes256-ecdsa](https://github.com/JC-000/c64-aes256-ecdsa) — AES-256, SHA-256, ECDSA P-256, HMAC-DRBG
- [c64-test-harness](https://github.com/JC-000/c64-test-harness) — VICE test automation framework
- [c64-lib-contract](https://github.com/JC-000/c64-lib-contract) — the segment-naming / manifest contract the two crypto submodules follow

## License

See repository for license terms.
