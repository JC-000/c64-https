# c64-https

An HTTPS client for the Commodore 64 in 6502 assembly. Implements TLS 1.3 over TCP/IP, with two interchangeable networking backends:

- **ip65** (default) — RR-Net (CS8900a) ethernet adapter via the [ip65](https://github.com/cc65/ip65) networking stack.
- **uci** — Ultimate 64 Elite (U64E) onboard ethernet via the UCI command interface.

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
 │     Network ABI  (src/net_abi.inc)      │  net_init / net_tcp_* / net_dns_*
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

The TLS, HTTP, and crypto layers are backend-agnostic; they consume
networking only through `src/net_abi.inc`. Switching backend is a
link-line change (different cfg + different `src/net/<backend>/*.o`),
not a call-site change.

### TLS 1.3 Cipher Suite

Target: **TLS_CHACHA20_POLY1305_SHA256** (0x1303)

- **AEAD:** ChaCha20-Poly1305 (from [c64-wireguard](../c64-wireguard))
- **Hash:** SHA-256 (from [c64-aes256-ecdsa](../c64-aes256-ecdsa))
- **Key exchange:** ECDHE with X25519 (optimized: REU DMA multiply, self-mod code, ~3.6 min/op)
- **Key derivation:** HKDF-SHA256 (new, built from HMAC-SHA256)
- **PRNG:** HMAC-DRBG seeded from SID+CIA entropy (from c64-aes256-ecdsa)

### Zero Page Time-Sharing (ip65 backend)

Under the ip65 backend, the crypto modules and ip65 overlap on zero page $02-$1B. Rather than relocating ip65's ZP (which would cost performance in the networking hot path), we time-share: save crypto ZP before calling ip65, restore after. Crypto and networking never run simultaneously. The UCI backend uses absolute addressing throughout and needs no ZP swap.

```
$02-$03   Shared tmp (save/restore around ip65 calls)
$04-$09   word32 pointers (ChaCha20)
$0A-$12   SHA-256 accumulators
$14-$17   mult66 pointers (fe25519) / ChaCha20 vars (time-shared)
$18-$1D   ChaCha20 + Poly1305 vars
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
$7C00-$8DFF  Code: ECDSA verify, DER decode, TLS cert, ECDH (~4.5 KB)
$8E00-$93FF  Optimization tables: REU DMA, sqtab2, mul38 (~1.5 KB, below ROM)
$9400-$BFFF  Data buffers: TLS state, crypto state, record buffers (~11 KB)
              ($A000-$BFFF under BASIC ROM, banked out at boot)
$C000-$CFFF  Free RAM (4 KB, overflow buffers)
$DE00-$DE0F  RR-Net CS8900a I/O registers (ip65 backend)
$DF1B-$DF1F  UCI command/data registers (UCI backend, U64E only)
```

TLS 1.3 records can be up to 16,384 bytes, but we negotiate `max_fragment_length` (RFC 6066) to limit records to 512 or 1024 bytes, fitting within C64 RAM constraints.

## Building

**Requirements:**
- [cc65 toolchain](https://cc65.github.io/) — ca65 + ld65 (ACME is no longer used)
- GNU Make
- VICE (`x64sc`) — only for `make run` and the test harness

```bash
git clone --recursive https://github.com/JC-000/c64-https.git
cd c64-https
make                    # Build build/c64-https.prg (default BACKEND=ip65)
make BACKEND=uci        # Build the Ultimate 64 Elite (UCI) variant
make run                # Build and launch in VICE (x64sc)
make clean              # Remove build artifacts
```

### ip65 Build

The Makefile automatically builds ip65 from the submodule into a flat binary blob at $2000, using a custom ld65 linker config (`ip65-build/ip65.cfg`). The blob is then included in the ACME build via `!binary`.

## Project Status

Current status (40 KB binary, 537 labels):

- [x] Project structure and build system
- [x] ip65 submodule integration — 6.8 KB binary blob at $2000 (TCP/UDP/DNS/DHCP/ARP + RR-Net CS8900a)
- [x] Network wrapper with ZP time-sharing — save/restore $02-$1B around ip65 calls
- [x] Crypto primitives — ChaCha20, Poly1305, AEAD (from c64-wireguard), SHA-256, HMAC-DRBG (from c64-aes256-ecdsa)
- [x] Optimized X25519/fe25519 — REU DMA multiply tables, mult66 quarter-square, self-mod code, 4x-unrolled cswap (~30% faster, 12,782 jiffies / 3.6 min per keygen)
- [x] HKDF-SHA256 — Extract, Expand, Expand-Label, Derive-Secret (RFC 5869 + TLS 1.3)
- [x] TLS 1.3 record layer — encrypt/decrypt with ChaCha20-Poly1305, nonce construction, sequence numbers
- [x] TLS 1.3 handshake — ClientHello builder (x25519 key_share, SNI), ServerHello parser, streaming transcript hash
- [x] TLS 1.3 key schedule — early/handshake/master secrets, traffic key derivation, Finished MAC (RFC 8446 §7.1)
- [x] ECDHE x25519 key exchange — generate keypair, compute shared secret
- [x] TLS 1.3 key schedule integration testing — all 9 HKDF steps verified against RFC 8448 + Finished MAC
- [x] Entropy/DRBG initialization — SID voice 3 noise + CIA timer seeding at boot, DRBG fills for TLS random values
- [x] X.509 certificate parsing — DER parser extracts TBS, public key, signature (r,s), curve ID for P-256 and P-384
- [x] ECDSA signature verification — P-256 and P-384, full verify (s⁻¹, scalar mul, point add, Jacobian→affine)
- [x] HTTP/1.1 GET request — build GET, parse response (status + headers + body), plain HTTP end-to-end
- [x] **End-to-end HTTPS GET demo** — TLS 1.3 handshake + HTTP GET completes against a local Python TLS listener (ECDSA-P256 cert) on real Ultimate 64 Elite hardware at 48 MHz turbo. Returns `http_status=200`, body `"HELLO FROM TLS SERVER"`. See `tools/uci/test_https_local.py`.

### Known Issues

- **ECDSA P-256 verify** runs ~85 s/op at 48 MHz turbo on the U64E. Sufficient for the local listener (which holds the connection open), but exceeds typical 10-30 s real-world server handshake windows. Real-internet ECDSA-P256 targets need a sibling-style optimized P-256 implementation (parallel to the `c64-x25519` work).
- **P-384** ECDSA is currently stubbed. Cert chains requiring P-384 will not verify until restored.
- **VICE 3.9** previously appeared to crash on chained HMAC-SHA256 calls, but this was caused by hardcoded port numbers bypassing the test harness port allocator. With proper `ViceInstanceManager` usage (no hardcoded ports), all N=1..10 chained calls succeed reliably.

## Test Automation

253 tests across 11 suites (+ 1 standalone diagnostic), using the [`c64-test-harness`](../c64-test-harness) package to drive VICE via its binary monitor protocol. The parallel runner allocates a fresh VICE instance per suite (with REU support for x25519) to avoid state contamination. All tests log VICE PID and port for multi-agent safety.

```bash
pip install -e ../c64-test-harness

# Run all 11 suites in parallel (one VICE instance per suite, ~5 min with ECDSA)
python3 tools/run_all_tests.py
python3 tools/run_all_tests.py --skip-slow   # Skip x509/ECDSA (~5s wall time)
python3 tools/run_all_tests.py --workers 6   # Limit concurrent VICE instances

# Individual suites
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
python3 tools/test_x25519.py          # 71 tests: fe25519 field ops, x25519_clamp, scalarmult (--slow for RFC 7748 vectors)
python3 tools/test_chained_hmac.py    # 10 tests: chained HMAC-SHA256 stability (N=1..10, standalone)

# Benchmark
python3 tools/bench_x25519.py         # X25519 key generation (~3.6 min C64 time, ~8s warp)

# Integration tests (require tap-c64 interface, dnsmasq; see scripts/setup-tap-networking.sh in c64-test-harness)
python3 tools/test_dns.py             # 4 tests: DNS resolution via ip65 over TAP (known host, second host, unknown host)
python3 tools/test_http_integration.py # 5 tests: end-to-end plain HTTP GET over TAP (DNS + TCP + request/response)

# End-to-end bridge tests (require br-c64 bridge, RR-Net; see below)
sudo PYTHONPATH=tools python3 tests/test_phase1_dhcp.py   # DHCP over RR-Net bridge
sudo PYTHONPATH=tools python3 tests/test_phase2_http.py   # Plain HTTP GET over bridge
```

### End-to-End Bridge Tests

Full end-to-end tests that drive the real c64-https binary in VICE over a Linux bridge with RR-Net ethernet (the same pattern used by [`c64-test-harness` bridge networking](../c64-test-harness/docs/bridge_networking.md)). VICE runs at **normal speed** (warp breaks RR-Net DHCP), so these tests need generous timeouts (~90-120s per phase).

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

### Ultimate 64 Elite Hardware Tests

Scripts under `tools/uci/` drive a real Ultimate 64 Elite over the network (default `192.168.1.81`). They DMA the PRG into RAM, run the boot, and snapshot UCI/TLS state on completion or timeout.

```bash
python3 tools/uci/boot_check.py          # UCI firmware detection
python3 tools/uci/phase2_check.py        # DHCP + local IP readback
python3 tools/uci/phase3_tcp_echo.py     # TCP connect/send/recv
python3 tools/uci/test_http_local.py     # HTTP GET against local listener
python3 tools/uci/test_https_local.py    # HTTPS GET (TLS 1.3 + ECDSA-P256)
```

`test_https_local.py` is the end-to-end HTTPS demo: it boots the U64E at 48 MHz turbo, connects to a local Python TLS listener using the test cert under `tools/https_e2e/certs/`, and confirms a full TLS 1.3 handshake + HTTP GET. With `DEBUG_CAPTURE=1`, each run writes a timestamped artifact directory under `$UCI_DEBUG_DIR` (default `/tmp/uci_https_debug/`) with raw 6510 bus trace, TLS state snapshot, and listener result.

## Related Projects

- [c64-aes256-ecdsa](../c64-aes256-ecdsa) — AES-256, SHA-256, ECDSA P-256, HMAC-DRBG
- [c64-wireguard](../c64-wireguard) — ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD
- [c64-test-harness](../c64-test-harness) — VICE test automation framework

## License

See repository for license terms.
