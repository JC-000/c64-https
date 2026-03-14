# c64-https

An HTTPS client for the Commodore 64 in 6502 assembly. Implements TLS 1.3 over TCP/IP using the RR-Net (CS8900a) ethernet adapter, built on the [ip65](https://github.com/cc65/ip65) networking stack.

**For demonstration and educational purposes only — not cryptographically secure.**

## Architecture

```
 ┌─────────────────────────────────────────┐
 │             HTTP/1.1 Client             │  http.asm
 ├─────────────────────────────────────────┤
 │          TLS 1.3 Engine                 │  tls13.asm (state machine)
 │  ┌──────────────┬──────────────────┐    │
 │  │ Record Layer │ Handshake Proto  │    │  tls_record.asm, tls_handshake.asm
 │  └──────┬───────┴────────┬─────────┘    │
 │         │                │              │
 │  ┌──────┴───────┐ ┌─────┴──────────┐   │
 │  │   AEAD       │ │  Key Schedule  │   │  (crypto modules)
 │  │ ChaCha20-    │ │  HKDF-SHA256   │   │  hkdf.asm
 │  │ Poly1305     │ │  ECDHE P-256   │   │
 │  └──────────────┘ └────────────────┘   │
 ├─────────────────────────────────────────┤
 │        Network Wrapper (ZP swap)        │  net.asm
 ├─────────────────────────────────────────┤
 │     ip65  (TCP/UDP/DNS/DHCP/ARP)        │  ip65 binary blob
 ├─────────────────────────────────────────┤
 │     RR-Net CS8900a Ethernet Driver      │  ip65 driver
 └─────────────────────────────────────────┘
```

### TLS 1.3 Cipher Suite

Target: **TLS_CHACHA20_POLY1305_SHA256** (0x1303)

- **AEAD:** ChaCha20-Poly1305 (from [c64-wireguard](../c64-wireguard))
- **Hash:** SHA-256 (from [c64-aes256-ecdsa](../c64-aes256-ecdsa))
- **Key exchange:** ECDHE with secp256r1 / P-256 (from c64-aes256-ecdsa)
- **Key derivation:** HKDF-SHA256 (new, built from HMAC-SHA256)
- **PRNG:** HMAC-DRBG seeded from SID+CIA entropy (from c64-aes256-ecdsa)

### Zero Page Time-Sharing

The crypto modules and ip65 overlap on zero page $02-$1B. Rather than relocating ip65's ZP (which would cost performance in the networking hot path), we time-share: save crypto ZP before calling ip65, restore after. Crypto and networking never run simultaneously.

```
$02-$03   Shared tmp (save/restore around ip65 calls)
$04-$09   word32 pointers (ChaCha20)
$0A-$12   SHA-256 accumulators
$14-$1D   ChaCha20 + Poly1305 vars
$22-$3C   ECDSA bignum / field arithmetic
$FB-$FE   General pointers (save/restore around ip65 calls)
```

The ip65 TCP callback (fired during `ip65_process`) copies received data into a ring buffer using only ip65's ZP context. After `ip65_process` returns and crypto ZP is restored, buffered data is processed through TLS.

## Memory Map

```
$0000-$00FE  Zero page (time-shared, see above)
$0100-$01FF  CPU stack
$0200-$033F  KERNAL/BASIC work area
$0334-$03FF  Scratch / test harness trampoline
$0801-$08FF  BASIC stub + boot
$0900-$1FFF  TLS 1.3 engine + HTTP client + net wrapper (~6 KB)
$2000-$3FFF  ip65 code + BSS (~8 KB)
$4000-$5FFF  Crypto: ChaCha20, Poly1305, AEAD (~8 KB)
$6000-$6FFF  Crypto: SHA-256, HMAC-SHA256, HKDF (~4 KB)
$7000-$77FF  Crypto: ECDSA/ECDH P-256 (~2 KB)
$7800-$7BFF  Quarter-square multiply table (1 KB, runtime-generated)
$7C00-$9FFF  Data buffers: TLS state, record buffers (~9 KB)
$A000-$BFFF  BASIC ROM (banked out for RAM if needed)
$C000-$CFFF  Free RAM (4 KB, overflow buffers)
$DE00-$DE0F  RR-Net CS8900a I/O registers (directly accessed by ip65)
```

TLS 1.3 records can be up to 16,384 bytes, but we negotiate `max_fragment_length` (RFC 6066) to limit records to 512 or 1024 bytes, fitting within C64 RAM constraints.

## Building

**Requirements:**
- [ACME cross-assembler](https://sourceforge.net/projects/acme-crossass/) (our code)
- [cc65 toolchain](https://cc65.github.io/) — ca65 + ld65 (ip65 build)
- GNU Make

```bash
git clone --recursive https://github.com/JC-000/c64-https.git
cd c64-https
make            # Build build/c64-https.prg
make run        # Build and launch in VICE (x64sc)
make clean      # Remove build artifacts
```

### ip65 Build

The Makefile automatically builds ip65 from the submodule into a flat binary blob at $2000, using a custom ld65 linker config (`ip65-build/ip65.cfg`). The blob is then included in the ACME build via `!binary`.

## Project Status

Current status (22 KB binary, 406 labels):

- [x] Project structure and build system
- [x] ip65 submodule integration — 6.8 KB binary blob at $2000 (TCP/UDP/DNS/DHCP/ARP + RR-Net CS8900a)
- [x] Network wrapper with ZP time-sharing — save/restore $02-$1B around ip65 calls
- [x] Crypto primitives — ChaCha20, Poly1305, AEAD (from c64-wireguard), SHA-256, HMAC-DRBG (from c64-aes256-ecdsa)
- [x] HKDF-SHA256 — Extract, Expand, Expand-Label, Derive-Secret (RFC 5869 + TLS 1.3)
- [ ] TLS 1.3 record layer — encrypt/decrypt with ChaCha20-Poly1305
- [ ] TLS 1.3 handshake — ClientHello, ServerHello, key exchange, Finished
- [ ] TLS 1.3 application data encryption/decryption
- [ ] ECDHE P-256 key exchange (import from c64-aes256-ecdsa)
- [ ] X.509 certificate parsing and validation
- [ ] HTTP/1.1 GET request
- [ ] End-to-end HTTPS GET demo

## Test Automation

97 tests across 4 suites, using the [`c64-test-harness`](../c64-test-harness) package to drive VICE via its remote text monitor.

```bash
pip install -e ../c64-test-harness
python3 tools/test_net.py           # 56 tests: ip65 integration, ZP save/restore, ring buffer
python3 tools/test_sha256.py        # 7 tests: NIST vectors, boundary cases, random inputs
python3 tools/test_crypto.py        # 22 tests: ChaCha20/Poly1305/AEAD RFC 7539 vectors + random
python3 tools/test_hkdf.py          # 12 tests: RFC 5869 vectors, TLS 1.3 key schedule, random
```

## Related Projects

- [c64-aes256-ecdsa](../c64-aes256-ecdsa) — AES-256, SHA-256, ECDSA P-256, HMAC-DRBG
- [c64-wireguard](../c64-wireguard) — ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD
- [c64-test-harness](../c64-test-harness) — VICE test automation framework

## License

See repository for license terms.
