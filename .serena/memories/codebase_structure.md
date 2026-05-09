# Codebase structure

```
c64-https/
├── Makefile                  # ACME build for main + ca65/ld65 build for ip65 blob
├── README.md                 # Full project documentation
├── src/                      # ACME 6502 assembly — main PRG
│   ├── main.asm              # Entry point
│   ├── boot.asm              # Boot / init
│   ├── constants.asm         # Shared constants
│   ├── data.asm              # Static data
│   ├── net.asm               # ip65 wrapper + ZP save/restore + TCP ring buffer
│   ├── entropy.asm           # SID/CIA entropy init for DRBG
│   ├── hkdf.asm              # HKDF-SHA256
│   ├── http.asm              # HTTP/1.1 GET builder + response parser
│   ├── der_decode.asm        # DER parser (for X.509)
│   ├── tls13.asm             # Top-level TLS 1.3 state machine
│   ├── tls_record.asm        # Record layer (encrypt/decrypt)
│   ├── tls_record_io.asm     # Record layer I/O wiring
│   ├── tls_handshake.asm     # ClientHello / ServerHello / Finished
│   ├── tls_keyschedule.asm   # Key schedule (early/handshake/master)
│   ├── tls_transcript.asm    # Streaming transcript hash
│   ├── tls_cert.asm          # X.509 cert handling
│   ├── tls_ecdh.asm          # ECDHE integration
│   └── crypto/               # Crypto primitives
│       ├── chacha20.asm      # ChaCha20 stream cipher
│       ├── poly1305.asm      # Poly1305 MAC
│       ├── aead.asm          # ChaCha20-Poly1305 AEAD
│       ├── sha256.asm        # SHA-256
│       ├── hmac_drbg.asm     # HMAC-DRBG PRNG
│       ├── word32.asm        # 32-bit word helpers
│       ├── fe25519.asm       # Field arithmetic for X25519
│       ├── x25519.asm        # X25519 scalar multiply
│       ├── ecdsa_*.asm       # P-256 ECDSA verify (curve, points, fp, mod)
│       └── ecdsa_*_384.asm   # P-384 ECDSA verify
│
├── ip65/                     # git submodule — cc65/ip65 TCP/IP stack
├── ip65-build/               # Custom ld65 config to emit flat ip65 blob at $2000
│   ├── ip65_stub.s
│   └── ip65.cfg
├── build/                    # Output: c64-https.prg, labels.txt
│
├── tools/                    # Python test suites + e2e bridge helpers
│   ├── run_all_tests.py      # Parallel runner for all 11 suites
│   ├── test_*.py             # Per-module test suites (VICE-driven)
│   ├── bench_x25519.py       # X25519 keygen benchmark
│   └── https_e2e/            # Reusable e2e bridge library
│       ├── env.py            # BridgeEnv, check_prerequisites()
│       ├── vice_on_bridge.py # launch_vice_on_bridge()
│       ├── c64_menu.py       # keyboard + screen helpers
│       └── http_listener.py  # start_http_listener()
│
├── tests/                    # End-to-end bridge tests (require sudo + dnsmasq)
│   ├── test_phase1_dhcp.py
│   └── test_phase2_http.py
│
├── scripts/
│   ├── setup-bridge-tap.sh   # Create br-c64 bridge + tap + dnsmasq
│   └── cleanup-bridge-tap.sh
│
└── docs/
    └── c64-zero-page-reference.md
```

## Build outputs
- `build/c64-https.prg` — the final C64 program (~40 KB)
- `build/labels.txt` — VICE label file (used by the test harness via `--vicelabels`)
- `ip65-build/ip65-c64.bin` — flat ip65 blob at $2000 (included via ACME `!binary`)

## Source counts (approx)
~30 `.asm` files total. 537 labels in the final binary.
