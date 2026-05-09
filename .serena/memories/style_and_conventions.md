# Style and conventions

## Assembly dialects (two!)
- **Main source (`src/**/*.asm`)**: ACME syntax (`!binary`, `!byte`, labels without colons allowed, etc.). Built with `acme -f cbm`.
- **ip65 glue (`ip65-build/ip65_stub.s`)**: ca65 syntax. Built with `ca65 -I ../ip65`.

The two worlds meet at a **flat binary blob**: ca65/ld65 emits `ip65-c64.bin` at $2000, and ACME pulls it in with `!binary`. Don't try to unify the two — it's intentional.

## Zero-page discipline (critical)
Crypto and ip65 share $02–$1B. The invariant is:

1. Before calling any `ip65_*` routine, crypto ZP ($02–$1B, plus $FB–$FE pointers) is **saved**.
2. After `ip65_process` (or other ip65 calls) returns, crypto ZP is **restored**.
3. The TCP receive callback that fires inside `ip65_process` may only touch ip65 ZP and a ring buffer — it must not call any crypto.

Any new code that bridges networking and crypto must respect this contract. See `src/net.asm` for the wrapper pattern and `docs/c64-zero-page-reference.md` for the full map.

## Memory map discipline
The memory layout in the README is load-bearing — every region has a purpose, and several crypto tables are placed below ROM ($8E00–$93FF) or under banked-out BASIC ROM ($A000–$BFFF). Before adding new data, check the map; don't blindly append.

## Naming
- Labels use `snake_case`.
- Module-level labels are typically prefixed with the module name (`tls_`, `hkdf_`, `chacha20_`, `ecdsa_`, `x25519_`, `sha256_`, `net_`, `http_`).
- Constants live in `src/constants.asm`.

## Test conventions
- Tests are Python, driven via `c64-test-harness` (installed editable from `../c64-test-harness`).
- Each suite gets a **fresh VICE instance** via `ViceInstanceManager`, with auto-allocated binary monitor and serial ports — **never** hardcode ports. Hardcoded ports previously caused mysterious "VICE crashes" (actually port collisions).
- The parallel runner (`tools/run_all_tests.py`) runs all suites concurrently; tests must be safe to run alongside others.
- REU is enabled for suites that need x25519 (the DMA multiply optimization).
- Assertions reference the `build/labels.txt` symbol file to set breakpoints / read memory at named addresses.

## When adding new .asm files
1. Add under `src/` (or `src/crypto/` for primitives). The Makefile picks them up via `$(wildcard $(SRC_DIR)/*.asm)`, but **only top-level `src/*.asm`** is in that wildcard — files under `src/crypto/` are included transitively from main.asm via ACME `!source`.
2. Include the new file from the appropriate parent with `!source "relative/path.asm"`.
3. Rebuild: `make clean && make`.
4. If the file introduces new labels a test needs, re-run the relevant test suite so it picks up the new `build/labels.txt`.
