# Build gotchas and environment notes

## Toolchain (must be on PATH)
- `acme` — ACME cross-assembler. Install: `brew install acme`.
- `ca65` + `ld65` — cc65 toolchain. Install: `brew install cc65`.
- `x64sc` — VICE C64 emulator (required for `make run` and all tests).

**As of the first session in this working directory, neither `acme` nor `cc65` was installed.** A `brew install cc65 acme` is required before `make` will work. This should be re-verified at the start of any fresh environment.

## Submodules
`ip65` is a git submodule (`https://github.com/cc65/ip65.git`). After a fresh clone, run:
```bash
git submodule update --init --recursive
```
The Makefile's `ip65-libs` target assumes the submodule is present and populated.

## ip65 build quirks
- The ip65 blob is built by `ca65 + ld65` using a custom linker config `ip65-build/ip65.cfg`, producing a flat binary at fixed address `$2000`.
- The Makefile runs `make -C ip65 && make -C drivers` inside the submodule only via the `ip65-libs` phony target. If you change ip65 source, you must either run `make ip65-libs` explicitly or `make clean && make`.
- The `.lib` files it links against are `ip65/ip65/ip65_tcp.lib` and `ip65/drivers/ip65_c64.lib` plus `c64.lib` from cc65.

## Python test harness
- Lives in a sibling directory: `../c64-test-harness`. Install editable: `pip install -e ../c64-test-harness`.
- Tests will fail with import errors if that package isn't installed.
- Most tests require the `x64sc` binary to be on PATH.
- **Never hardcode VICE ports** in tests — always go through `ViceInstanceManager`. A previously suspected "VICE crash on chained HMAC" turned out to be a port collision caused by hardcoded ports.

## VICE warp mode and RR-Net
- Bridge/RR-Net tests MUST run at **normal speed**. Warp mode breaks RR-Net DHCP timing. The bridge helpers in `tools/https_e2e/` already account for this — expect 90–120s per phase.

## Gitignore
The following are intentionally gitignored and should never be committed:
```
__pycache__/
*.pyc
ip65-build/*.o
ip65-build/*.bin
ip65-build/*.map
.claude/
.serena/
```

## Known issues (from README)
- `ecdsa_verify` (P-256) rejects a known-good signature — `tools/test_x509.py` group 3 subtest 3c, surfaced 2026-05-06. Rejection path (subtest 3d) is fine; inputs are staged correctly. Affects TLS CertificateVerify; ECDHE/X25519 handshake is unaffected. See CLAUDE.md `### Known issues` for the full entry (CLAUDE.md is the source of truth).
- End-to-end HTTPS GET demo is the remaining unchecked milestone.

## macOS / BSD-sed portability
GNU sed accepts `sed -i 's/foo/bar/' file`; BSD sed (macOS default) requires `sed -i '' 's/foo/bar/' file` (empty backup-suffix string). Use the BSD form — it works on both. The Makefile and `tools/integration/build_nistcurves_p256.sh` were corrected for this on 2026-05-06.
