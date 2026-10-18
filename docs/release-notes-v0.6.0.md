# c64-https v0.6.0

**For demonstration and educational purposes only. It is not cryptographically secure.**

Built from the commit tagged `v0.6.0`. Submodule pins (`tools/check_upstream_pins.py`):
- `libs/mlkem` v0.6.0 (new);
- `libs/nistcurves` v0.15.0 (unchanged);
- `libs/x25519` v0.16.0 (unchanged);
- ip65 `25a9c5a` (untagged, unchanged).

The headline: **both UCI images now offer the post-quantum hybrid key exchange X25519MLKEM768**, and have completed a fetch of the Wikipedia Commodore 64 article over it on hardware. `ip65-onchip` stays classic.

---

## Assets

| image | for | PRG sha256 |
|---|---|---|
| `c64-https-ip65-onchip` | stock C64 + RR-Net, no REU, no turbo | `e69bfce7b552e765df02cb253b4ff12cecaca3e978669376b7af5ffad9343dce` |
| `c64-https-uci-onchip` | U64E / C64 Ultimate, turbo, no REU | `3b4dd718cbdc296f2083c90ce4d89a25e1fbd032e849c66f25227ef4d0ac4d5a` |
| `c64-https-uci-comb` | U64E / C64 Ultimate, turbo + REU (fastest) | `41202de9fa6b9da769fce87a3223e7d1c74630f873b4b64a940afacddb7cbeb6` |
| `c64-https-uci-m3-demo` | U64E with the TLS-socket (ESP32) firmware | `916d41628a17b9436bbf58a71f7350c721a06e459cf5c33e5baeb1ad61af9a24` (carried forward from v0.5.1, unchanged) |

Each image also ships as a bootable `.d64` (hashes: the release's `SHA256SUMS`, written when the assets are attached). The 1541 filenames are unchanged (`ip65-noreu`, `uci-noreu`, `uci-comb`).

The `.prg`/`.d64` names, 1541 filenames and sizes are the same as v0.5.1 (47,105 B, 47,105 B, 51,201 B).

---

## Post-quantum hybrid key exchange

- `make` argument `PQ_HYBRID=1` is now part of the `uci-onchip` and `uci-comb` products (`tools/package/_common.sh`). The ClientHello offers `X25519MLKEM768` (0x11EC) first and `X25519` (0x001D) as well; the server picks. Against a server that picks 11EC the handshake secret is extracted from `mlkem_ss || x25519_ss` (draft-ietf-tls-ecdhe-mlkem: ML-KEM first); against one that picks X25519 nothing differs from v0.5.1.
- ML-KEM-768 comes from `libs/mlkem` (c64-mlkem v0.6.0). Its code is loaded at `$A000` and copied to `$E000` at boot; the polynomial area is `$D000-$DFFF` and is scrubbed after KeyGen and after Decaps, as are the shared secrets after the key schedule. `PQ_HYBRID` is refused on ip65, uci-m3 and the uci REU profile.
- Cost, measured on a U64E at 48 MHz, comb image, n=1: trigger to client Finished 43.7 s hybrid vs 42.0 s X25519-only, about +1.7 s (local OpenSSL listener). Against Wikipedia the release PRGs took 191-192 s (onchip) and 220-222 s (comb) for the 760 KB page, and the X25519-only control comb image 218 s.
- **What it does and does not buy.** The hybrid secret needs an attacker to break both X25519 and ML-KEM-768. This client's entropy is still weak (the DRBG is seeded from SID voice 3 and CIA1 timer A), so the ML-KEM seed and the X25519 key are not strong secrets; this is a demonstration of the protocol path, not a security claim.
- Servers: OpenSSL 3.6.5 `s_server` and en.wikipedia.org negotiate 11EC with our hello (tables below); browserleaks.com did in the P5 live run. github.com and lwn.net do not offer 11EC; a `uci-comb` fetch of github.com/robots.txt falls back to X25519 and completes (below).

## Other changes since v0.5.1

- ClientHello is built in sections with 16-bit lengths and a HelloRetryRequest is refused (#312); the hybrid ServerHello is read as a stream across records (#314); the key schedule is hybrid (#315).
- The linker output no longer depends on the build locale (#311): the PRG hashes reproduce under any `LANG`.
- A linker-config edit relinks the PRG (#306); pytest is green on a uci or an ip65 build (#308); the rig trampolines set the trust-store mode (#307).
- README and M3 demo provenance fixes (#303, #310).

## M3 demo

Carried forward from v0.5.1 unchanged (PRG, `.d64`, README, checksum file). The M3 build does not link the 6510 TLS or crypto code, and building `BACKEND=uci-m3 HTTPS_HOST=en.wikipedia.org HTTPS_PATH=/wiki/Commodore_64` at this release reproduces the v0.5.1 PRG byte for byte (`916d4162...`), so the hardware validation recorded for it still describes these bytes. It was not re-run for this release and `tools/package/build_m3_demo.sh` was not used: it would rewrite the README around this commit and re-quote firmware provenance that nobody re-verified.

---

## Validated

Built on macOS 27.0.1, GNU Make 3.81, ca65/ld65 V2.18, `LANG=en_US.UTF-8`. `make package-verify` passed **14/14** with no SKIP (PRG reproducibility from a second clean build, load ranges off the I/O page, `.d64` read-back byte-compare and VICE boot to the banner for all three images, listener selftest).

**Hardware, exact release PRGs** (U64E 10.43.23.81, fw 3.15 branch build, 48 MHz, `rig_https_banner.py`: menu path, `G`, typed host `en.wikipedia.org`, path `/wiki/Commodore_64`; completeness by the response's own framing; `REQUIRE_KEX=EC` makes any other group a failure). Every run is listed:

| # | image (PRG sha256 prefix) | tls_kex_group | HTTP | body | elapsed |
|---|---|---|---|---|---|
| 1 | `uci-comb` (41202de9) | $EC | 200 | 760,609 B == Content-Length, PASS | 220 s |
| 2 | `uci-comb` (41202de9) | $EC | 200 | 760,609 B == Content-Length, PASS | 222 s |
| 3 | `uci-comb` (41202de9) | $EC | 200 | 760,609 B == Content-Length, PASS | 222 s |
| 4 | `uci-onchip` (3b4dd718) | $EC | 200 | 760,609 B == Content-Length, PASS | 191 s |
| 5 | `uci-onchip` (3b4dd718) | $EC | 200 | 760,609 B == Content-Length, PASS | 192 s |
| control | v0.5.1-equivalent classic `uci-comb` (`BACKEND=uci USE_NISTCURVES_ONCHIP_COMB=1 TRUST_STORE=1 TRUST_RELEASE=1`, fee4d5b1) | n/a | 200 | 760,609 B == Content-Length, PASS | 218 s |
| fallback | `uci-comb` (41202de9), github.com /robots.txt | $1D | 200 | 14,489 B == Content-Length, PASS | 101 s |

All 7 runs completed (5 hybrid Wikipedia, 1 classic control, 1 github fallback); no truncation was seen (#211 is intermittent, so 7 clean runs bound it, they do not remove it). The Wikipedia article is now 760,609 B (759,171 B at v0.5.1). Elapsed is the whole rig run including boot (comb adds its ~45 s table build).

**Local OpenSSL 3.6.5 listener** (`tools/uci/rig_https_local.py`, `EXTERNAL_LISTENER=1`; it needs a name the listener's certificate carries, so the images were built with the release arguments plus `HTTPS_SNI=www.foo.invalid`: `uci-onchip` `46398f0b…`, `uci-comb` `fdb7386e…`):

| image | server `-groups` | tls_kex_group | result | oracle (C64 app traffic secrets vs the server's keylog) |
|---|---|---|---|---|
| uci-onchip | X25519MLKEM768 | $EC | full HTTPS PASS | MATCH |
| uci-onchip | X25519 | $1D | full HTTPS PASS | n/a (not hybrid) |
| uci-comb | X25519MLKEM768 | $EC | full HTTPS PASS | MATCH |
| uci-comb | X25519 | $1D | full HTTPS PASS | n/a (not hybrid) |

`boot_check.py` passed on the release `uci-onchip` and `uci-comb` PRGs.

**Memory** (`tools/measure_margins.py --build`, the exact release arguments, free bytes): `uci-onchip` LOADER 157, NET_CODE 105, CRYPTO_OVERLAY 372, CRYPTO_HOT 196; `uci-comb` LOADER 342, NET_CODE 134, **CRYPTO_OVERLAY 55**, CRYPTO_HOT 379, COLD_IMAGE 1,697, COLD_RUN_TRUST 75.

**Suites**, on this tree: `BACKEND=uci python3 tools/run_all_tests.py` 455/455 (the `net` and `ip65_exports` suites are accounted skips: they test the ip65 adapter); bare `python3 -m pytest -q` 510 passed; the PQ suites listed in PR #315 and the mutant set (72 mutants, per the review of #315) all pass.

**`ip65-onchip`** is byte-identical to master's knob-off build (`e69bfce7…`) and was checked by the package-verify VICE boot only; no network fetch was run for this release. It is not hybrid.

## What this release does NOT do

- **No certificate chain validation on the three 6510 images** (unchanged). The UCI images pin by trust-on-first-use in `/USB1`; `ip65-onchip` accepts any certificate whose signature verifies.
- **Server name validation is UCI-only.**
- **Entropy is weak** (see above).
- **The Wikipedia REU viewer demo does not link with `PQ_HYBRID=1`.** `make BACKEND=uci USE_NISTCURVES_ONCHIP_COMB=1 PQ_HYBRID=1 HTTPS_HOST=en.wikipedia.org HTTPS_PATH=/wiki/Commodore_64 HTTPS_BODY_TO_REU=1` overflows CRYPTO_HOT by 507 B. Build it without `PQ_HYBRID`.
- **A server that sends its whole hybrid ServerHello as one record cannot be read** (the record buffer is 548 B); the client refuses it at once. Servers that honour max_fragment_length (OpenSSL, Wikipedia, browserleaks) split it.
- **The C64 Ultimate was not validated for this release.**
