# Task completion checklist

Run these whenever you finish a code change, before reporting the task done.

## 1. Build
```bash
make            # Assemble src/ via acme, link ip65 via ca65/ld65
```
Any warning or error from `acme` or `ld65` blocks completion. If the ip65 blob didn't rebuild but you changed `ip65-build/ip65_stub.s` or `ip65-build/ip65.cfg`, run `make clean && make`.

## 2. Run the relevant test suite(s)
Match the change to the suite:

| Change area | Suite |
|-------------|-------|
| `src/net.asm`, ring buffer, ip65 wrapper | `python3 tools/test_net.py` |
| `src/crypto/sha256.asm`, HMAC | `python3 tools/test_sha256.py` + `python3 tools/test_chained_hmac.py` |
| `src/crypto/chacha20.asm`, `poly1305.asm`, `aead.asm` | `python3 tools/test_crypto.py` |
| `src/hkdf.asm` | `python3 tools/test_hkdf.py` |
| `src/tls_record*.asm` | `python3 tools/test_tls_record.py` |
| `src/tls_cert.asm`, `der_decode.asm`, `ecdsa_*.asm` | `python3 tools/test_x509.py` |
| `src/tls_handshake.asm`, `tls_transcript.asm`, `tls_keyschedule.asm` | `python3 tools/test_tls_handshake.py` + `python3 tools/test_keyschedule_steps.py` |
| `src/entropy.asm`, `hmac_drbg.asm` | `python3 tools/test_entropy.py` |
| `src/http.asm` | `python3 tools/test_http.py` |
| `src/crypto/x25519.asm`, `fe25519.asm`, `word32.asm` | `python3 tools/test_x25519.py` |
| Cross-cutting / touching multiple | `python3 tools/run_all_tests.py` (full parallel run) |

## 3. For networking-path changes (end-to-end verification)
If you touched `net.asm`, the TCP path, DNS, DHCP, or anything that talks to ip65, also run:

```bash
python3 tools/test_dns.py                    # TAP integration
python3 tools/test_http_integration.py       # End-to-end HTTP over TAP
```

For RR-Net driver changes, also run the bridge tests (require sudo):
```bash
sudo ./scripts/setup-bridge-tap.sh
sudo PYTHONPATH=tools python3 tests/test_phase1_dhcp.py
sudo PYTHONPATH=tools python3 tests/test_phase2_http.py
sudo ./scripts/cleanup-bridge-tap.sh
```

## 4. No linting / formatting tools
There is no linter or formatter configured for the assembly source (nor for the Python test code beyond what's in `c64-test-harness`). Assemble-cleanly and tests-pass are the only gates.

## 5. Commit hygiene
- `build/` and `ip65-build/*.{o,bin,map}` are gitignored — never commit them.
- `.claude/` and `.serena/` are gitignored — never commit them.
- Submodule bumps (changes in `ip65/`) are rare; if you do bump, commit the new submodule SHA explicitly.
