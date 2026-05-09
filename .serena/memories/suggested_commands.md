# Suggested commands

All commands are run from the project root `/Users/someone/Documents/c64-https` unless noted. System is macOS (Darwin) — most commands are standard zsh/BSD userland.

## Prerequisites (install before building)
```bash
brew install cc65    # provides ca65 + ld65 (needed for ip65 blob)
brew install acme    # ACME cross-assembler (main source)
brew install make    # GNU Make (usually already present via Xcode CLT)
```
VICE (`x64sc`) is needed only for `make run` and tests.

The Python test harness must also be installed in editable mode from the sibling checkout:
```bash
pip install -e ../c64-test-harness
```

## Build
```bash
make                   # Build build/c64-https.prg (assembles ip65 blob first if missing)
make run               # Build and launch in VICE x64sc
make clean             # Remove build/ artifacts and ip65-build/*.o|.bin|.map
make ip65-libs         # Rebuild ip65 object libraries from submodule (only needed if the ip65 submodule changes)
make ip65-blob         # Rebuild ip65-build/ip65-c64.bin from those libraries (committed blob is normally reused)
```

## Tests — parallel runner (recommended)
```bash
python3 tools/run_all_tests.py                 # Run all 11 suites in parallel (~5 min with ECDSA)
python3 tools/run_all_tests.py --skip-slow     # Skip x509/ECDSA (~5s wall time)
python3 tools/run_all_tests.py --workers 6     # Limit concurrent VICE instances
```

## Tests — individual suites
```bash
python3 tools/test_net.py                  # 60  ip65, ZP save/restore, ring buffer, TCP recv callback
python3 tools/test_sha256.py               # 7   NIST vectors, boundary, random
python3 tools/test_crypto.py               # 22  ChaCha20/Poly1305/AEAD RFC 7539 + random
python3 tools/test_hkdf.py                 # 12  RFC 5869 + TLS 1.3 key schedule
python3 tools/test_tls_record.py           # 17  nonce, seq, encrypt/decrypt, roundtrips
python3 tools/test_x509.py                 # 11  DER parse P-256/P-384 + ECDSA verify
python3 tools/test_tls_handshake.py        # 21  transcript hash, CH/SH, key schedule, Finished MAC
python3 tools/test_keyschedule_steps.py    # 9   RFC 8448 step-by-step
python3 tools/test_entropy.py              # 7   SID/CIA hardware, DRBG seeding
python3 tools/test_http.py                 # 27  HTTP/1.1 GET + response parser
python3 tools/test_x25519.py               # 71  fe25519, clamp, scalarmult (--slow for RFC 7748)
python3 tools/test_chained_hmac.py         # 10  standalone chained HMAC-SHA256 stability
python3 tools/bench_x25519.py              # X25519 keygen benchmark (~3.6 min C64, ~8s warp)
```

## Tests — integration (require TAP + dnsmasq)
```bash
python3 tools/test_dns.py                  # DNS via ip65 over TAP
python3 tools/test_http_integration.py     # End-to-end plain HTTP GET over TAP
```

## Tests — end-to-end bridge (require sudo + RR-Net bridge)
```bash
sudo ./scripts/setup-bridge-tap.sh                              # Create br-c64 + tap + dnsmasq
sudo PYTHONPATH=tools python3 tests/test_phase1_dhcp.py         # DHCP over RR-Net bridge
sudo PYTHONPATH=tools python3 tests/test_phase2_http.py         # Plain HTTP GET over bridge
sudo ./scripts/cleanup-bridge-tap.sh                            # Teardown
```

> VICE runs at **normal speed** for bridge tests (warp breaks RR-Net DHCP). Expect ~90–120s per phase.

## Git / submodule
```bash
git submodule update --init --recursive   # Initialize/refresh ip65 submodule
git submodule update --remote ip65        # Bump submodule to upstream HEAD (rare)
```

## macOS / Darwin notes
- Default shell is `zsh`. BSD `find`, `sed`, `grep` differ from GNU; use `rg` (ripgrep) and prefer the Grep/Glob Claude tools.
- `brew --prefix` usually `/opt/homebrew` on Apple Silicon, `/usr/local` on Intel.
- `sudo` is required for the bridge/TAP scripts (they create interfaces and start dnsmasq).
