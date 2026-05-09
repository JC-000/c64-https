# c64-https — Project Overview

HTTPS client for the Commodore 64, written in 6502 assembly. Implements **TLS 1.3** over TCP/IP using the RR-Net (CS8900a) ethernet cartridge, built on top of the **ip65** networking stack.

> **Status:** educational / demonstration — not cryptographically secure.

## Goal
End-to-end HTTPS GET from a real C64 (or VICE emulator with RR-Net) to a real HTTPS server, using only authentic 6502 assembly code plus the ip65 library.

## Cipher suite
`TLS_CHACHA20_POLY1305_SHA256` (0x1303) — the only suite supported.

- AEAD: ChaCha20-Poly1305 (ported from c64-wireguard)
- Hash: SHA-256 (ported from c64-aes256-ecdsa)
- Key exchange: ECDHE X25519 (optimized: REU DMA multiply tables, self-modifying code, ~3.6 min/op on real C64)
- Key derivation: HKDF-SHA256 (built from HMAC-SHA256)
- PRNG: HMAC-DRBG seeded from SID voice-3 noise + CIA timer entropy
- Cert verification: X.509 DER parser + ECDSA P-256 / P-384 verify

## Progress (from README)
Most of the cryptographic and TLS state machine is done. The remaining milestone is the full end-to-end HTTPS GET demo. Completed: record layer, handshake builder/parser, key schedule (RFC 8448 verified), X25519 key exchange, X.509 cert parsing + ECDSA verification, HTTP/1.1 request/response, entropy/DRBG init.

## Architecture highlights
- **Zero-page time sharing**: crypto modules and ip65 both use $02–$1B. Rather than relocating ip65 ZP, crypto saves its ZP before each ip65 call and restores it after. Crypto and networking never run simultaneously.
- **TCP receive callback**: fired during `ip65_process`, copies data into a ring buffer using only ip65 ZP. Buffered data is handed to TLS after restoration.
- **Max fragment length (RFC 6066)** negotiated to 512 or 1024 bytes to fit C64 RAM.
- **Memory map** is tight — total code + data ≈ 40 KB, with BASIC ROM banked out for $A000-$BFFF buffers.

## Related projects (sibling directories)
- `../c64-wireguard` — ChaCha20/Poly1305 source
- `../c64-aes256-ecdsa` — SHA-256, ECDSA, HMAC-DRBG source
- `../c64-test-harness` — VICE automation framework (pip-installable, used by the test runners)
