# c64-https — architecture notes

TLS 1.3 / HTTPS client for the Commodore 64, assembled with ca65/ld65 and
delivered as a single PRG. Networking is provided by the ip65/RR-Net stack
(prebuilt blob at $2000). All crypto is hand-written 6502 tuned to fit
under the BASIC ROM shadow at $A000.

This file is the load-bearing "how does this hang together" reference.
Keep it terse.

## Build

Dependencies:
  - `ca65`, `ld65` from cc65 (ACME is no longer required)
  - GNU make
  - VICE (`x64sc`) only for `make run` / the test harness

Targets:
  - `make`              — default, produces `build/c64-https.prg`,
                          `build/labels.txt` (VICE label format), and
                          `build/c64-https.dbg` (cc65 debug info,
                          consumable by VICE's monitor + diagnostic
                          agents; P-384 overlays get `.dbg` sidecars too)
  - `make clean`        — remove build artifacts
  - `make run`          — autostart the PRG in VICE
  - `make ip65-libs`    — rebuild ip65 object libraries from the submodule
                          (only needed if the ip65 submodule changes)
  - `make ip65-blob`    — rebuild `ip65-build/ip65-c64.bin` from those
                          libraries (the committed blob is normally reused)

Variables:
  - `BACKEND=ip65|uci`  — select networking backend cfg
                          (`cfg/c64-https-$(BACKEND).cfg`; default ip65)
  - `USE_X25519_SIBLING=1` — swap the in-tree X25519 for the
                          `libs/x25519@v0.6.0` sibling (UCI only — ip65
                          has a tracked code/rodata overflow; see
                          "Known issues")
  - `EMBED_P256_OVERLAY=1` — stage the P-256 verify image into the
                          CRYPTO_OVERLAY slot at PRG-load (UCI; mutually
                          exclusive with USE_X25519_SIBLING /
                          USE_OVERLAY_P384_EMBED)
  - `USE_NISTCURVES_ONCHIP=1` — link the libs/nistcurves
                          FP_ONCHIP_MUL turbo-profile P-256 verify
                          archive (no REU row-fetch DMA; ~22 MHz
                          crossover vs the default REU profile at
                          v0.6.0 — see the ECDSA wall-clock section).
                          Mutually exclusive with USE_X25519_SIBLING
                          and both overlay-embed flags (MUL_CODE
                          occupies CRYPTO_OVERLAY).
  - `USE_NISTCURVES_ONCHIP_COMB=1` — comb-accelerated onchip profile
                          (implies USE_NISTCURVES_ONCHIP): Lim-Lee
                          fixed-base u1*G + ec_precompute_256 boot
                          pass into REU bank 2. Fastest verify above
                          ~7 MHz; boot costs ~50 s at 64 MHz (test
                          scripts: set C64_INIT_WAIT). Uses
                          cfg/c64-https-$(BACKEND)-onchip.cfg.
  - `CA65`, `LD65`      — toolchain overrides
  - `VICE`              — override the `make run` emulator

Test harness expectations:
  - Most `tools/test_*.py` scripts run `make clean && make` themselves
    before launching VICE. Set `C64_SKIP_BUILD=1` in the environment to
    reuse the already-built PRG (7 scripts currently honor the var —
    see the "Honor C64_SKIP_BUILD" commit for the list).
  - Use the `c64-test-harness` Python package to launch VICE; never run
    `x64sc` directly from tests.

## Crypto ABI

Public crypto API is fronted by `src/crypto_abi.inc`. TLS/HTTP sources
consume crypto only through the symbols listed there. The intent is
that any implementation (in-tree today, vendored sibling library
tomorrow) can fulfil the contract by providing the same `.export`s;
swapping implementations is a link-line change, not a call-site change.

Public symbols (calling conventions are AX=pointer-low/high-byte except
where noted, buffers provided by caller, keys/IVs passed via fixed
buffers in the crypto BSS — see per-module headers for details):

  X25519 / field arithmetic
    Default: in-tree `src/crypto/{x25519,fe25519}.s`.
    Opt-in: sibling `libs/x25519@v0.6.0` via `make USE_X25519_SIBLING=1`
    (UCI backend only — see Known issues for the ip65 fit limitation).
    The v0.6.0 pin is c64-lib-contract-aligned (SPEC §8.1) and adds the
    bank-2 drop + RAM-reclaim work; older v0.4.0 pin is historical only.
    Sibling and in-tree both expose the same ABI:
    x25519_scalarmult     — X25519 scalar × point, 32-byte buffers
    fe25519_mul, fe25519_sqr, fe25519_inv

  ChaCha20-Poly1305         (in-tree, permanent)
    chacha20_encrypt
    poly1305_init, poly1305_update, poly1305_final
    aead_encrypt, aead_decrypt

  SHA-256                   (in-tree; no sibling)
    sha256_init, sha256_update, sha256_final

  ECDSA P-256                (`libs/nistcurves@v0.3.0` sibling,
                              c64-lib-contract SPEC §1-§8.1 aligned)
    ecdsa_verify_256      — TLS dispatcher in src/crypto/ecdsa_verify.s
                            packs the BE struct + calls the sibling entry
    ec_scalar_mul_var     — variable-base scalar multiplication
    (in-tree ecdsa_{curve,fp,mod,points}.s were deleted in Phase G;
    archive built via `make -C libs/nistcurves lib-p256-verify` — see
    `tools/integration/build_nistcurves_p256.sh` for the wrapper.)

P-384 is *stubbed at the TLS layer* (see `project_p384_stubbed` memory
note). The sibling `libs/nistcurves` P-384 primitives were meant to be
buildable as an external overlay image (Phase C.3b, `make
p384-overlay`) but every P-384 build target is broken at the v0.6.0
pin — see "Known issues" for the current failure chain. Fix the build
before wiring P-384 into the TLS path.

MEMORY requirements for a drop-in sibling library (see "Memory layout"
below for the post-W1 hot/cold split):
  - Code + rodata must load into the `CRYPTO_HOT` region at
    **$6000-$9FFF** (UCI) / `CRYPTO_RESIDENT` (ip65, same span). No
    segment may cross $A000 — boot zeroes $A000-$BFFF as BSS, so any
    executable straddling that boundary gets wiped on first call.
  - Large BSS (page-aligned tables etc.) lands in `CRYPTO_COLD_SHADOW`
    at **$A000-$BFFF** (file-backed zero-fill, CPU port $01 = $36
    selects RAM under BASIC ROM).
  - Sibling-library segments follow the c64-lib-contract SPEC §8.1
    naming (`LIB_NISTCURVES_P256_CODE`, `LIB_NISTCURVES_P256_RODATA`,
    `LIB_NISTCURVES_P256_BSS`, etc.); the consumer cfg places them by
    name. See [c64-lib-contract](https://github.com/JC-000/c64-lib-contract)
    for the contract spec and `docs/library-ingestion-architecture.md`
    for the c64-https rollout plan.
  - Zero-page usage is defined in `src/constants.inc` — fe25519 lives at
    `$2C-$37`, x25519 state at `$38-$3A`, ECDSA bignum at `$22-$3C`.
    These ranges are time-shared (fe25519 and ChaCha20 never overlap).
  - REU Profile B is the baseline. Under the default build the in-tree
    x25519 implementation uses a smaller on-chip squaring table in
    `TABLES_BSS` and leaves REU banks 0-1 free. Under
    `USE_X25519_SIBLING=1` the v0.6.0 sibling's `reu_mul_init` dropped
    the bank-2 squaring table (RAM-reclaim work, c64-lib-contract
    §8.1 adoption); banks 6-7 stay reserved for the
    `make p384-overlay` external-image smoke test.
  - `crypto_init` currently bootstraps `mul_tables_init` only. X25519
    state and any per-run setup happens from the boot path in
    `src/boot.s`. The overlay swap dispatcher
    (`src/crypto/shared/crypto_swap.s`) is present but idle under the
    shipped build.

## Networking backend ABI

Public net API is fronted by `src/net_abi.inc`. TLS/HTTP sources consume
networking only through those symbols. Switching backend = picking a
different `cfg/c64-https-$(BACKEND).cfg` and linking different
`src/net/<backend>/*.o` files.

Current backends:
  - `src/net/ip65/` — ip65/RR-Net (cs8900a driver). The ip65 blob is
    prebuilt to `ip65-build/ip65-c64.bin` and loaded at $2000 via
    `src/net/ip65/ip65_blob.s` (`.incbin`). `src/net/ip65/net.s`
    is the ABI adapter. `src/net/ip65/ip65_symbols.inc` is the single
    source of truth for the `ip65_*` jump-table / variable-table
    equates (Phase 7 consolidated these out of `constants.inc`).
  - `src/net/uci/`  — Ultimate 64 Elite (U64E) UCI backend. See the
    "UCI backend" section below for details. `make BACKEND=uci`
    produces a working PRG; `cfg/c64-https-uci.cfg` defines the
    UCI-specific memory map.

Public symbols (see `src/net_abi.inc`):
  net_init, net_poll, net_dhcp_acquire
  net_tcp_connect, net_tcp_send, net_tcp_close, net_tcp_set_recv_cb
  net_dns_resolve
  net_local_ip, net_resolved_ip, net_last_error, net_tcp_state

## UCI backend

`make BACKEND=uci` builds the UCI variant. Default is still `BACKEND=ip65`;
both backends coexist and share the same TLS/HTTP/crypto code.

### UCI register map

UCI I/O registers live at **$DF1B-$DF1F**; firmware identification byte
is **$C9**. See `src/net/uci/uci_regs.inc` for the full equate list
(CMD_PUSH, CMD_CTRL, STAT, DATA, ID).

### UCI command primitives

`src/net/uci/uci_cmd.s` provides shared subroutines used by `net.s`:
`uci_wait_idle`, `uci_wait_not_busy`, `uci_begin_cmd`, `uci_push_wait`,
`uci_read_resp_bytes`, etc. No zero-page usage — all absolute
addressing and self-modifying code.

`uci_wait_idle`, `uci_wait_not_busy`, `uci_drain_resp`, and
`uci_drain_status` are all wall-clock-bounded (5 s budget via CIA1
TOD) per the design note below. On timeout they return C=1 with
`net_last_error = UCI_ERR_WAIT_TIMEOUT`. All `uci_wait_idle` callers
(`net_dhcp_acquire`, `net_tcp_connect`, `net_tcp_send`,
`net_tcp_close`) and all `uci_wait_not_busy` / `uci_push_wait`
callers (`net_poll`, `net_dhcp_acquire`, `net_tcp_connect`,
`net_tcp_send`, `net_tcp_close`) `bcs` out to surface the failure
rather than letting the C64 hang indefinitely on a wedged FPGA. All
13 `uci_drain_resp` / `uci_drain_status` call sites in `net.s` also
`bcs` out — on timeout the routine skips its companion drain + ack,
forces the appropriate `net_tcp_state` (ERROR for poll paths,
CONNECT_FAIL for connect, CLOSED for close, untouched for DHCP/send
which use C=1 as their fail sentinel), and returns. `uci_push_wait`
inherits the bound via its tail-call to `uci_wait_not_busy`. The
`uci_wait_not_busy` conversion was driven by a Phase 5 wedge observed
in CertVerify recv on real U64E hardware that converted a wedge into
a 1843 s test sentinel timeout; the drain conversion (Phase 5j)
closed the secondary risk that `net_tcp_send` / `net_poll` /
`net_tcp_close` could still wedge in `uci_drain_resp` /
`uci_drain_status` post-SOCKET_WRITE if firmware ever left DATA_AV /
STAT_AV asserted.

### UCI error codes

`src/net/uci/uci_errors.inc` enumerates the values surfaced via
`net_last_error` and `net_tcp_state`. The most load-bearing:

  - `UCI_ERR_NO_SOCKET` — `net_tcp_connect` got a short-read on the
    OPEN_TCP response (no socket-id byte), so the firmware never
    actually opened the TCP connection. `net_tcp_state` is set to
    `UCI_TCP_CONNECT_FAIL` and C=1 is returned. Without this check
    the C64 would commit to a phantom socket and push TLS bytes
    into nowhere (see issue #36).
  - `UCI_ERR_WAIT_TIMEOUT` — `uci_wait_idle` exhausted its 5 s budget
    (see issue #37).

### DNS

UCI firmware resolves hostnames internally during `TCP_CONNECT`. There
is no DNS code in the adapter. `net_dns_resolve` memcpies the hostname
into `uci_host_buf` (256 bytes in UCI_BSS); `net_tcp_connect` passes
it to firmware. Dotted-quad IP literals work because firmware passes
them through.

### Firmware quirk — FPGA register timing (delay-loop fence)

The U64E's UCI FPGA needs **~38 us** between consecutive register
accesses regardless of CPU clock speed. At stock 1 MHz the bus cycle
time naturally satisfies this. At turbo speeds (4-48 MHz) the CPU
outruns the FPGA, causing double-latched writes and stale reads that
corrupt the UCI command protocol.

**Fix:** A nested delay-loop macro `uci_fence` (defined in
`src/net/uci/uci_regs.inc`) is inserted after every read/write to UCI
registers `$DF1C-$DF1F`. Parameters: `UCI_FENCE_OUTER = 5`,
`UCI_FENCE_INNER = 217`, yielding ~5450 cycles (85.2 us at 64 MHz —
35% margin over the C64 Ultimate's empirically-bracketed floor;
113.5 us at 48 MHz). 14 bytes per fence site, 24 fence sites total
(11 write + 13 read). At 1 MHz the same loop costs ~5.5 ms per
access — negligible for networking.

The C64 Ultimate (firmware 1.1.0, core 1.49) needs MORE inter-access
time than the U64E's ~38 us, and the tighter floor only bites under
sustained CMD_DATA bursts: at 51.6 us spacing DHCP/GET_IPADDR works
but TCP_CONNECT's ~15-byte hostname push is silently lost
(UCI_ERR_NO_SOCKET, firmware never opens the socket). Floor bracketed
at 64 MHz: 51.6 us FAIL / 62.9 us PASS — see the tuning matrix in
`uci_regs.inc`. The U64E-era INNER=100 (52.6 us at 48 MHz) was never
observed failing on U64E but sits below the C64U floor; INNER=217 is
safe on both devices at every speed.

48 MHz turbo is fully supported and verified on real U64E hardware;
64 MHz is supported and verified on the C64 Ultimate (see "C64
Ultimate notes" below).

### C64 Ultimate notes

A second UCI-capable device joined the bench 2026-07-19: a **C64
Ultimate "Starlight Edition"** (product "C64 Ultimate", firmware
1.1.0, FPGA 122, core 1.49, NTSC mode, WiFi-connected) at
10.53.21.158 — `U64_HOST=10.53.21.158`. Differences from the U64E
that this codebase now handles:

  - **64 MHz turbo** — the C64U's CPU Speed enum adds "64" (and drops
    " 5"). c64-test-harness's `CPU_SPEED_BY_MHZ` carries the superset.
    E2e verified at 64 MHz (see benchmarks below).
  - **Runtime speed-switch quirk** — changing CPU speed via the REST
    config API while the PRG is running can glitch the UCI bridge so
    the NEXT pushed command is silently lost (reproduced 2x as
    UCI_ERR_NO_SOCKET on the first TCP_CONNECT after a 1→64 switch,
    even with a 100 us fence; a 1→48 switch happened to survive).
    `tools/uci/test_https_local.py` now sets turbo BEFORE
    reset/run_prg so the machine boots at target speed and never
    switches mid-session. Mirror that pattern in new scripts
    (`test_https_local_p384.py` still uses the old late-switch order —
    fix when the P-384 build unblocks).
  - **Wider fence floor** — see the delay-loop fence section above
    (INNER=217 accommodates both devices).
  - **REU-quiet boot drops the first TCP_CONNECT** — a PRG whose boot
    issues no REU DMA (the original onchip-profile gating skipped
    reu_mul_init) loses its first UCI TCP_CONNECT at the FPGA bridge:
    command accepted, no error bit, DATA_AV never asserts, no SYN on
    the wire (0/8 e2e attempts vs 3/3 for the identical build with
    reu_mul_init retained; interleaved control confirmed). Boot-time
    REU traffic evidently settles shared expansion-I/O state. boot.s
    therefore retains reu_mul_init under BOTH profiles. See
    c64-test-harness#137.
  - **Multiple network interfaces** — Ethernet AND WiFi. GET_IPADDR
    (iface=0) returns 0.0.0.0 on a WiFi-connected box;
    `net_dhcp_acquire` probes iface 0..3 and takes the first lease.
  - **REU ships disabled** — fresh C64U config has `RAM Expansion
    Unit: Disabled`; without it sibling-nistcurves `fp_mul` silently
    computes garbage (same failure mode as the VICE `-reu` gotcha).
    Enable via REST config write. NOTE: the C64U has no `"REU"`
    Cartridge preset (presets list is just `[""]`), so the harness's
    `set_reu()` helper — which also sets `Cartridge: "REU"` — is
    incompatible as written; set `RAM Expansion Unit: Enabled`
    directly. Config writes are runtime-only (revert on power cycle).
  - Same UCI register map, ID byte $C9, command set, and DeviceLock /
    enable_uci flow as the U64E — boot_check/phase2/phase3/e2e scripts
    run unmodified.

### Memory layout under UCI

Post-W1 the UCI cfg is the reference; see the "Memory layout" section
below for the full table. Headline differences from the (similarly
post-W1) ip65 layout:

  - `NET_CODE` ($2000-$3B25) is much smaller because the UCI adapter
    is ~1.7 KB vs ip65's ~6.95 KB blob. The tail carries
    `LOADER_OVERFLOW`, `TLS_CODE`, `CRYPTO_AUX_CODE`.
  - `NET_BSS_TAIL` ($3B26-$3FFF) absorbs UCI_BSS +
    `LIB_NISTCURVES_P256_BSS` spill.
  - `CRYPTO_OVERLAY` is a real 7.5 KB slot ($4200-$5FFF) used for the
    P-384 SHA-384/curve overlays, the W3 P-256 overlay embed, and the
    `USE_X25519_SIBLING=1` X25519 rodata + BSS.
  - `CRYPTO_HOT` + `CRYPTO_COLD_SHADOW` are the W1 hot/cold split of
    the historical `CRYPTO_RESIDENT` (see "Memory layout" below).

### UCI test scripts

Scripts under `tools/uci/` require a U64E (default 192.168.1.81,
overridable via the `U64_HOST` environment variable) and use
`DeviceLock` + `enable_uci`/`disable_uci`:

  - `boot_check.py`       — verify UCI firmware detection and boot banner
  - `phase2_check.py`     — DHCP acquire + local IP readback
  - `phase3_tcp_echo.py`  — TCP connect/send/recv against a local echo server
  - `test_http_local.py`  — HTTP GET against a local test server
  - `test_http_live.py`   — HTTP GET against a real internet host (requires
                            internet access from the U64E)
  - `test_https_local.py` — HTTPS e2e scaffolding against a local TLS 1.3
                            listener (ECDSA-P256 cert from
                            `tools/https_e2e/certs/`). DMAs a 6502 stub
                            that calls `http_get`, flips the U64E to the
                            CPU speed selected by `TURBO_MHZ` (default
                            48; `TURBO_MHZ=1` runs at stock 1 MHz with
                            all wall-clock budgets auto-scaled by 48x
                            and has been validated end-to-end on real
                            U64E hardware), and captures full
                            diagnostics on pass or timeout.
                            `DEBUG_CAPTURE=1` enables a bounded 6510
                            bus stream for post-mortem.
                            `EXTERNAL_LISTENER=1` (+ `EXTERNAL_HOST`,
                            `EXTERNAL_PORT`, default 4433) skips the
                            inline listener + repo-cert load and points
                            the C64 at an out-of-band server — e.g. the
                            packaged `dist/c64-https-listener.zip`
                            listener; pass criteria then come from
                            C64-side state only. Default OFF.
                            Each run writes a timestamped artifact dir
                            under `$UCI_DEBUG_DIR` (default
                            `/tmp/uci_https_debug/<ISO>/`) containing:
                            packed raw trace (`trace.bin` + meta sidecar),
                            derived `summary.txt` / `tail.txt` /
                            `uci_accesses.txt`, the full 4 KB ring
                            (`ring.bin` + `ring_meta.json`), a DMA-read
                            TLS state snapshot (`tls_state_dump.json`),
                            the listener's `server_result.json`, and
                            `run_info.txt`. Rotation keeps the last 5
                            dirs; `UCI_DEBUG_KEEP_ON_PASS=1` preserves
                            PASS runs. The TLS state snapshot now
                            includes the full 548 B `tls_rec_buf`
                            (handshake plaintext is parsed in place
                            there — see Known issues below for the
                            current stall site).

### End-to-end HTTPS status

The TLS 1.3 handshake now completes end-to-end against the local test
listener (ECDSA-P256 cert, `tools/https_e2e/certs/`) on **both** backends:
UCI/U64E at 48 MHz turbo and stock 1 MHz, and ip65/VICE at stock 1 MHz
no-WARP (after the 255-byte TCP RX clamp fix in `src/net/ip65/net.s`;
see `tests/test_phase3_https_1mhz.py`). The flow, identical across both
backends:

**U64E wedge episode (2026-07-27/28, resolved — know the signature):**
the U64E at 10.43.23.81 spent 2026-07-27 in a runtime wedge where
EVERY TLS handshake stalled deterministically at the first encrypted
record (screen `...KEYS ENC1 RX`, never GOT2, `net_last_error=0x86`,
`tls_recv_sub_progress=0x02`), at any clock, while DHCP/TCP/plaintext
kept working; the D64 REST mount also failed (broken pipe). Soft
resets did NOT clear it; the device then hard-crashed (unresponsive
to its power button) and a hard power cycle fixed everything.
Firmware 3.14d was UNCHANGED throughout (same image passed May-2026
e2e) — this is transient device instability, not a firmware update,
not client code (the 2026-05-20 known-good commit failed identically
while wedged; the identical setup passed on the C64U). **If you see
the no-GOT2 signature on healthy-looking transport: do not bisect
code — power cycle the device (hard, at the wall).** Tracked with
full evidence in
[c64-test-harness#141](https://github.com/JC-000/c64-test-harness/issues/141).

  - ClientHello → ServerHello (X25519 key share)
  - EncryptedExtensions, Certificate, CertificateVerify (sibling
    c64-nist-curves P-256 ECDSA verify, Phase C.4 cc182f1; full
    handshake measured at 81.9 s on U64E 48 MHz — see the ECDSA
    benchmark subsection)
  - Server Finished verified
  - Client Finished computed + sent under HS write key
  - Application traffic keys derived; AEAD seq counters reset to 0
  - HTTP/1.1 GET sent under app write key
  - Server NewSessionTicket records (rejected as non-application),
    then the HTTP response record — decrypted, fed into the TCP
    ring, parsed by `http_recv_response`
  - `http_status = 200`, `http_resp_buf = "HELLO FROM TLS SERVER"`,
    `http_resp_len = 21`

**ECDSA P-384 also wired end-to-end (Phase 5).** The TLS dispatcher
now negotiates `ecdsa_secp384r1_sha384` (0x0503) alongside the existing
P-256/SHA-256 path; on a 0x0503 CertificateVerify it routes through
`src/crypto/ecdsa_verify_384.s`, which composes the dual-overlay swap
(SHA-384 overlay → ECDSA-P384 curve overlay) plus the sibling's
`ecdsa_verify_384` to verify the server's signature. The
`tls_handle_certificate` cert handler dispatches on `ecdsa_curve_id`
and writes the 48 B P-384 pubkey into the dedicated
`ecdsa_pubkey_x_384` / `_y_384` slots in CRYPTO_BSS (Phase 5 Fix B).
The CertificateVerify signed-content blob is 130 B (RFC 8446 §4.4.3:
64-space pad + 33 B context + 1 B sep + 32 B SHA-256 transcript;
the transcript-hash function stays SHA-256 because c64-https
offers exactly one cipher suite, TLS_CHACHA20_POLY1305_SHA256
(0x1303, `src/tls_handshake.s:85`, echo-verified at :380), whose
hash is SHA-256 — Phase 5 Fix A). The
end-to-end test is `tools/uci/test_https_local_p384.py` (mirrors
`test_https_local.py` with P-384 cert profile via swapping CERT_PATH
/ KEY_PATH to `tools/https_e2e/certs/server-p384.{pem,key}`); see the
"ECDSA P-384 verify wall-clock" subsection for the wall-clock
expectation. Negotiation plumbing test
`tools/test_tls_p384_negotiation.py` confirms ClientHello advertises
both 0x0403 + 0x0503 and the dispatcher reaches the P-384 path on
0x0503 CertificateVerify (2/2 PASS as of Phase 5).

### Summary of recent fixes (post-PR23 branch)

Five latent bugs and three new ones were cleared to get here:

  1. `tls_transcript_update` 16-bit length fix
     (pre-existing, cherry-picked `2f01c0d`).
  2. CertVerify / Finished transcript ordering — snapshot before
     dispatch, fold after (`2bb014a`).
  3. `fp_zero` clobbering Y across calls in `ecdsa_parse_der_sig`
     (`f006f10`).
  4. Off-by-one SHA-256 length field in CertificateVerify signed
     digest (`4a2c4f3`).
  5. `tls_derive_traffic_keys` not setting CLC on success
     (`cf8d326`).
  6. Client Finished ordering vs. traffic-key derivation, and
     reloading `hkdf_prk` from `tls_c_hs_secret` before computing
     the client Finished HMAC (`4130356`).
  7. AEAD sequence counters reset at handshake→application key
     boundary per RFC 8446 §5.3 (`a18f324`).
  8. `http.s` state_body now polls when ring briefly empty instead
     of declaring the body complete on the first empty tick
     (`7821ffb`) — removed the "http_status parses, body truncated"
     symptom documented previously as a known issue.
  9. `http_recv_response` state transitions fall through instead of
     returning @not_done, so one dispatch walks status + headers +
     body when they all fit in a single TLS record (`fbc7d10`).
 10. ip65 TCP RX callback 255-byte clamp removed (PR #27). The old
     callback truncated `cb_remaining` to 255 when the high byte was
     non-zero while ip65 ACKed the full `tcp_inbound_data_length`,
     silently dropping bytes 256+. Any TLS record &gt;255 B (Certificate
     in particular, ~369 B in the local listener setup) got partially
     delivered and the TLS reassembly buffer ended up gluing a prefix
     of record N onto bytes from record N+1. Replaced with a
     16-bit-safe copy loop that mirrors the UCI adapter.
 11. Phase C.4 (`cc182f1`) — replaced the in-tree P-256 primitives
     (`ecdsa_{curve,fp,mod,points}.s`) with the sibling
     `libs/nistcurves/` P-256 integration (`build/lib/nistcurves-p256.a`,
     always-resident under both backends). `src/crypto/ecdsa_verify.s`
     is now a thin dispatcher that packs the big-endian input struct
     and calls `ecdsa_verify_256`. Handshake wall-clock on U64E 48 MHz
     dropped to **81.9 s** end-to-end. The orphan in-tree primitives
     and legacy ACME-era `ecdsa_*_384.asm` stubs were physically
     deleted in Phase G.

### Known issues

  - `http_recv_response` now terminates body-read on a Content-Length
    match: a 16-bit `http_content_length` sentinel ($FFFF = absent)
    lives in SHADOW_BSS at `$A851`, populated by a case-insensitive
    header match for `Content-Length:` requiring a single SP after
    the colon. Once `http_resp_len` equals `http_content_length`,
    state_body returns C=0 and `http_get` exits cleanly. When the
    header is absent the parser falls back to the previous
    keep-polling behaviour (preserves chunked/streaming paths).
  - `net_tcp_set_recv_cb` is an RTS stub (no callers in-tree).
  - Boot banner line 03 still says "rr-net" under ip65 build even
    though Phase 2 made it backend-aware — this is correct/expected
    behavior. Under UCI it says "ULTIMATE 64 ELITE (UCI)".
  - The delay-loop fence adds ~2.5 ms overhead per UCI register access
    at 1 MHz (negligible for networking, but visible in tight loops).
  - `http_resp_buf` is rendered through `ascii_chrout` (a small
    translator in `src/boot.s` adjacent to `print_resp_body`) before
    being handed to KERNAL CHROUT.  Issue #28 — the original pipeline
    sent raw ASCII straight to CHROUT, which renders ASCII lowercase
    `$61-$7A` as PETSCII graphics characters in the default
    uppercase/graphics character set.  `ascii_chrout` passes
    `$20-$60` unchanged, folds lowercase `a-z` to uppercase (strategy
    B: `sub #$20`), remaps `$0A` LF to `$0D` CR, and drops everything
    else.  Body text therefore renders correctly regardless of case
    (all letters appear as uppercase glyphs; case is dropped).
    Verified end-to-end on U64E at 48 MHz by
    `tools/uci/test_https_print_body.py` with a mixed-case response
    body.  `http_resp_buf` still holds raw ASCII — only the render
    pipeline is translated.
  - **X25519 sibling (`libs/x25519@v0.6.0`)** —
    `make USE_X25519_SIBLING=1` builds against the sibling; default is
    OFF, the in-tree implementation remains the shipped default until
    the flag flip is decided. The v0.6.0 pin landed via PR #55 along
    with the c64-lib-contract alignment; it drops the bank-2 squaring
    table and reclaims RAM under the post-W1 hot/cold split (see
    "Memory layout" below). Earlier-pin caveats (Phase C.1 hang,
    v0.3.0 retry rollback, v0.4.0 H2 defensive REU re-inits) are all
    superseded by v0.6.0; the file-level history lives in the c64-x25519
    repo's CHANGELOG. The ip65-side `LIB_NISTCURVES_P256_BSS` overflow
    that used to be recorded here was the *default* build's overflow
    and is fixed (see the CRYPTO_COLD_SHADOW entry under "Memory
    layout"). `USE_X25519_SIBLING=1` under ip65 still does NOT link,
    but the failure has moved and is now a different problem than the
    old BSS overflow (measured 2026-07-29 post-refit): `X25519_RODATA`
    overflows `CRYPTO_OVERLAY` by 2,048 B and
    `LIB_NISTCURVES_P256_CODE` overflows `CRYPTO_RESIDENT` by 103 B —
    i.e. a code/rodata placement problem, not the BSS one
    c64-nist-curves#54 tracks. ip65's `CRYPTO_OVERLAY` is only 4,212 B
    against UCI's 7.5 KB, which is the root of it. UCI remains the
    supported sibling-on path. See `tools/integration/build_x25519.sh`
    for the
    `make -C libs/x25519 lib-x25519-scalarmult` wrapper.
  - **CRYPTO_OVERLAY collisions are now caught by MemoryPolicy.** All
    `tools/uci/*.py` test scripts derive their scratch DMA addresses
    from a `MemoryArbiter` backed by a c64-https-aware `MemoryPolicy`
    (factory in `tools/uci/_memory_policy.py`, parses ld65 segment
    markers from `build/labels.txt`). The harness's transport-layer
    write guard (c64-test-harness PR #95) raises `MemoryPolicyError`
    before any byte hits the wire on a region collision. New
    `tools/uci/` scripts should reuse `build_policy_and_arbiter()`
    rather than hardcoding addresses. The migration left
    `unknown_policy=WARN` so writes outside declared segments surface
    as `UserWarning`; tightening to `DENY` is a follow-up.
  - **All P-384 build targets are broken at the v0.6.0 pin**
    (verified 2026-07-26): both `make p384-overlay` and `make
    BACKEND=uci USE_OVERLAY_P384_EMBED=1` fail in
    `tools/integration/build_nistcurves_p384.sh` at the `ar65`
    staging step (`nistcurves_p384_staging/curve/ecdsa384.o` never
    produced — the upstream layout drifted under the v0.5.0/v0.6.0
    bumps). Behind that likely still lurk the earlier v0.3.0-era
    SHA-384 LUT overlay overflow (1536 B over the 7.5 KB slot) and
    the historical `ec_base384_x/y` unresolved-symbol bug — neither
    is reachable until the wrapper is fixed. The target has never
    built cleanly. Issues #32 and #45 were closed as stale on this
    basis; file fresh issues against the current failure chain when
    P-384 enablement resumes. TLS-level P-384 verify remains stubbed
    regardless (see `project_p384_stubbed`).
  - **VICE harness gotcha**: any test that exercises sibling
    `libs/nistcurves` P-256 primitives (`fp_mul`, `fp_inv`,
    `ec_scalar_mul_var`, `ecdsa_verify_256`, ...) MUST launch VICE with
    `-reu`. The sibling's `fp_mul` fetches 8x8 multiply rows from REU
    banks 0/1 (populated by `src/boot.s::reu_mul_init`). Without `-reu`,
    the row fetch silently no-ops and `mul_dma_lo/hi` at $BA00/$BB00
    stays stuck at `reu_mul_init`'s final-iteration residue (a=255), so
    every `fp_mul` returns `a*255*b mod p` instead of `a*b mod p`.
    Cascade: wrong `w=s^-1 mod n`, wrong `u1`/`u2`, wrong computed `R`,
    `R.x != r`, verify returns C=1. **Use the helper at
    `tools/_vice_helpers.py::default_vice_config()`** (PR #53) — it
    pre-applies the mandatory `-reu -reusize 512` flags. All in-tree
    VICE-driven tests (`test_x509.py`, `test_ecdsa_kat_oracle.py`,
    `test_x25519.py`, `bench_x25519.py`, `test_p384_symbols.py`) now go
    through it; mirror that pattern in any new VICE test rather than
    spelling out `ViceConfig(extra_args=["-reu", "-reusize", "512"])`
    by hand. The UCI path is unaffected because the U64E hardware has
    REU enabled by default; the symptom was VICE-only.
    The single deliberate exception is `C64_VICE_NO_REU=1`, which makes
    `default_vice_config()` drop the REU flags (and say so on stderr).
    It exists so the shipped onchip PRG's "no REU required" claim has a
    runnable test — see the packaging validation record for the exact
    invocation. Never set it for a REU-profile build: that is precisely
    the silent-garbage case above.

### ECDSA P-256 verify wall-clock

`ecdsa_verify` of the RFC 6979 test vector on a U64E at 48 MHz turbo
runs in ~85 s median in the pre-Phase-C.4 benchmark (see
`tools/uci/bench_ecdsa_u64e.py` for the protocol). The full
`tls_connect` handshake — which does one ECDSA verify over the
CertificateVerify signature — now takes **81.9 s** wall-clock
end-to-end under Phase C.4's sibling `libs/nistcurves` P-256
integration, down from ~110 s pre-integration. The remainder is
network I/O + SHA-256 + X25519 + Finished HMACs + handshake
state-machine overhead.

81.9 s still does not fit a typical 10-30 s real-world server
handshake window, so this is a blocker for arbitrary internet TLS
targets that require ECDSA-P256 CertificateVerify. Note: the earlier
"`ecdsa_verify` rejects a known-good signature" entry in this section
turned out to be a VICE harness misconfiguration (missing `-reu`), not
a verify-path bug — see "VICE harness gotcha" in the Known issues
list. With `-reu` enabled, `tools/test_x509.py` 3c PASSes cleanly in
~60 s wall-clock under VICE warp.

Under the current `libs/nistcurves@v0.3.0` pin (post-PR #55,
c64-lib-contract-aligned) the U64E 48 MHz handshake measures **82.1 s**
end-to-end (verified 2026-05-20 against the local listener; the prior
v0.2.0 measurement was 86.7 s, and the pre-Phase-C.4 in-tree path was
~110 s).

On the **C64 Ultimate** (10.53.21.158, see "C64 Ultimate notes"),
measured 2026-07-19 with the INNER=217 fence and boot-at-speed flow:

  - 48 MHz: **73.0 s** end-to-end (faster than the U64E's 82.1 s at
    the same clock — different FPGA core)
  - 64 MHz: **64.7 s** end-to-end — first >48 MHz datapoint. The
    48→64 ratio (0.89) is well short of the ideal 0.75.

**Why turbo stops paying — and the fix (campaign 2026-07-20):** the
REU's DMA rate is anchored to the ~1 MHz bus clock, so fp_mul's
row fetches put a speed-invariant floor under every verify. Filed as
[c64-nist-curves#69](https://github.com/JC-000/c64-nist-curves/issues/69);
upstream shipped the `FP_ONCHIP_MUL` turbo profile in v0.5.0, consumed
here via `make BACKEND=uci USE_NISTCURVES_ONCHIP=1`. Full 4-point
clock sweeps (`bench_ecdsa_u64e.py`, RFC 6979 vector, n=2 medians,
C64U, fits T(f)=D+C/f, residuals <=4.1%):

  config           16MHz   32MHz   48MHz   64MHz    D(floor)   C
  v0.3.0 REU       72.1    57.9    53.7    47.5     41.8 s     491 MHz*s
  v0.5.0 REU       72.2    57.7    53.7    49.3     42.9 s     471 MHz*s
  v0.5.0 onchip   117.5    59.6    41.2    31.0      2.5 s    1839 MHz*s
  v0.6.0 onchip    88.3    43.3    30.9    22.9      1.1 s    1396 MHz*s
  v0.6.0 onchip+comb 49.4  24.9    16.5    12.4     ~0.2 s     787 MHz*s

  - The REU-profile floor is ~42 s (an earlier 2-point fit said
    28.4 s — that number was ill-conditioned and is superseded; at
    64 MHz the REU verify is ~88% floor).
  - v0.5.0's REU path is performance-identical to v0.3.0.
  - The onchip profile ELIMINATES the floor (D = 2.5 s) at the cost
    of ~3.9x the CPU work; it scales 3.79x for a 4x clock.
  - **Measured crossovers vs the REU profile: ~34 MHz (v0.5.0
    shape-1), ~22 MHz (v0.6.0 shape-2), ~7 MHz (shape-2 + comb)**.
    The comb build (USE_NISTCURVES_ONCHIP_COMB=1) dominates the
    no-comb onchip build at every clock; its costs are the
    ec_precompute_256 boot pass (~50 s at 64 MHz, ~3.5 min at
    16 MHz, ~40 min at stock — scripts need C64_INIT_WAIT) and REU
    bank 2 $0000-$3FFF residency. At stock 1 MHz the REU profile
    remains the right default.

  HTTPS e2e handshake wall-clock (C64U, local listener):

  profile             48 MHz    64 MHz
  v0.3.0 REU          73.0 s    64.7-65.9 s
  v0.5.0 onchip       59.9 s    47.5 s (n=3: 47.0/47.6/47.8)
  v0.6.0 onchip       51.0 s    39.7 s
  v0.6.0 onchip+comb  38.4 s    **31.0 s**

  Those rows are the 2026-07-20 campaign state. **Current HEAD is
  faster** — see "Post-#74 e2e numbers" below; the onchip rows in
  particular improved by ~6 s once #69 landed, because on-chip
  fe25519 rows beat wall-clock-anchored REU DMA above the crossover.

  31.0 s @ 64 MHz sits at the top edge of a typical 10-30 s
  internet-server handshake window — the first configuration where
  a real-server TLS connection is plausible. Remaining spend:
  ~12.4 s verify + ~18.6 s of everything else (X25519, SHA-256
  transcript+HMACs, record I/O, UCI firmware/network latency) —
  the non-verify side is now the bigger half and the next
  profiling target. (Comb has not been re-measured post-#69/#74;
  extrapolating the ~6 s onchip gain and the ~0.65 s residual drain
  it should land meaningfully under 31 s — worth confirming.)

#### Post-#74 e2e numbers (2026-07-29, HEAD)

Two merged changes moved these numbers in opposite directions, so the
2026-07-20 rows above are no longer HEAD:

  - **#69** (`USE_NISTCURVES_ONCHIP` fe25519 rows via `og_common`) is a
    **speedup at turbo**, not a cost. It is easy to get the sign wrong:
    the profile carries a large penalty at 1 MHz, but only because REU
    DMA is cheap relative to the CPU down there. On-chip generation
    scales with the clock while REU DMA stays anchored to the ~1 MHz
    bus, so above the crossover it wins — the same mechanism behind
    FP_ONCHIP_MUL's ~22 MHz P-256 crossover. Worth ~6 s at 48-64 MHz.
    It only affects onchip builds (the change is inside
    `.ifdef USE_NISTCURVES_ONCHIP`), which is what makes the REU rows
    below a clean control.
  - **#71's post-ServerHello drain**, unconditional at 2000 `net_poll`
    calls, cost UCI **~80 s** — see the drain note in "Design note"
    below. **#74** made the budget per-backend and restored it.

Measured end-to-end (handshake + GET, local listener):

  device  profile  clock   pre-#71   post-#71   post-#74   baseline
  C64U    onchip   48 MHz   51.0 s    125.4 s    **44.6 s**   51.0 s
  C64U    onchip   64 MHz   39.7 s    (unmeas.)  **33.7 s**   39.7 s
  U64E    REU      48 MHz   82.1 s    161.0 s    **82.1 s**   82.1 s

  - Both onchip rows land **below** their pre-regression baselines
    (-6.4 s @48, -6.0 s @64) — that is #69.
  - The REU row lands **exactly at** baseline, because a REU build
    cannot contain #69. Two profiles, one with the change and one
    without, behaving as the model predicts: this is the cleanest
    confirmation of #69's sign we have.
  - Drain cost cross-checks to a clock- and device-invariant
    **~40 ms per UCI `net_poll`** from three directions: 80.8 s/1984
    polls (C64U onchip), 78.9 s/1984 (U64E REU), and an independent
    per-poll derivation. See `uci_net_poll_cost` in memory.

#### ip65 / stock-C64 wall-clock (hardware-free VICE rig)

First measurements of the ip65 backend end-to-end, from the macOS
feth/pcap rig (see "VICE ip65 rig" under Smoke tests). These are the
**REU-less stock-C64 story** — no REU, no turbo, RR-Net networking:

  build                    mode              G -> CONNECTION CLOSED
  ip65 + onchip, no REU    honest 1 MHz      **2,159.7 s (36.0 min)**
  ip65 + onchip, no REU    ~1.2x accelerated 1,813.9 s
  ip65 + REU profile       ~1.2x accelerated   988.9 s

  Honest-1 MHz phase breakdown (seconds after 'G'):
  TCP CONNECTED 3.0 | CH 329.2 | SH 700.7 | PROC 718.9 |
  FIN 2,135.5 | REQUEST SENT 2,153.6 | CLOSED 2,159.7

  - The verify stretch measured **1,416.7 s** against the v0.6.0
    onchip fit's 1,397 s prediction (+1.4%) — the T(f)=D+C/f model
    holds at 1 MHz, three orders of magnitude from where it was fit.
  - X25519 scalarmults measured 326 s / ~356 s vs ~324 s analytical.
  - ip65's drain budget is **unchanged by #74** (the ip65 PRG is
    byte-identical across it), so these numbers stand at HEAD.
  - VICE 3.10 SDL2 has no usable runtime warp: its `Speed` resource
    caps at ~1.2x and `WarpMode` is gone, so "accelerated" runs are
    only ~1.2x. Divide accelerated figures by ~1.2 for honest 1 MHz.

**U64E lane (2026-07-25)** — same sweep protocol on the U64E
(10.43.23.81), 16/32/48 MHz only (no 64 MHz enum on the U64E), all
three v0.6.0 profiles at HEAD, n=2 medians of the RFC 6979 vector,
72/72 runs correctness-PASS (fits T(f)=D+C/f; REU/onchip residuals
<=0.4%, comb <=3.8%):

  config              16MHz   32MHz   48MHz    D(floor)   C
  v0.6.0 REU           81.6    65.2    59.2     48.2 s     535 MHz*s
  v0.6.0 onchip        87.6    44.9    30.5      2.0 s    1370 MHz*s
  v0.6.0 onchip+comb   49.1    24.6    18.4      2.2 s     747 MHz*s

  Device delta vs the C64U at the same clocks (the C64U's
  v0.3.0/v0.5.0 REU rows are the comparable REU baseline — the REU
  path is performance-identical across those pins):

  - **REU profile: U64E is +10-13% slower at every clock** (floor
    48.2 s vs 41.8 s) — consistent with the 82.1 vs 73.0 s e2e
    split first seen at 48 MHz. Different FPGA core, slower
    REU/expansion-bus DMA.
  - **onchip profile: parity** (-1.3% to +3.6%, within n=2 noise)
    at all three clocks. The CPU-bound path is device-independent,
    so the whole device delta is localized to REU DMA, not the CPU
    core.
  - **comb profile: parity at 16/32 MHz, +12% at 48 MHz** (18.4 vs
    16.5 s). The U64E side is confirmed: a 2026-07-26 rerun at n=6
    per positive vector gave median 18.39 s, spread 18.31-18.45 s
    (±0.4%) across all three vectors. Plausibly the Lim-Lee table
    fetches from REU bank 2 — a DMA-anchored cost whose share grows
    with clock. The residual uncertainty is the C64U's 16.5 s
    (itself n=2); re-measure that side before treating the gap as
    exactly 12%.
  - Crossovers vs REU shift down on the U64E because its REU floor
    is higher: onchip wins above ~18 MHz (C64U: ~22), comb above
    ~5 MHz (C64U: ~7). Comb still dominates no-comb onchip at
    every clock. Best U64E verify: **18.4 s @ 48 MHz** (comb).

v0.3.0's hot-path code is essentially unchanged from v0.2.0;
the small wall-clock improvement is within measurement noise across
runs. It is fine for the local listener used by the e2e harness (600 s
budget, ample headroom). Further speedups live in the sibling
`libs/nistcurves` repo — any drop through the Crypto ABI lands
here as a submodule bump without touching TLS call sites.

### ECDSA P-384 verify wall-clock

Not yet measured end-to-end, and currently UNMEASURABLE: the P-384
embed build does not build at the v0.6.0 pin (fails in the sibling
wrapper's `ar65` staging step — see "Known issues"), so
`tools/uci/test_https_local_p384.py` has no P-384 PRG to run and
would just boot the default P-256 image. The May-2026 hw attempts
that predate the build breakage died at EncryptedExtensions decrypt
(issue #45, closed 2026-07-26 as stale — the suspect commit window
was buried by the W1/v0.5.0/v0.6.0 rework; restart from a fresh
build + fresh repro). Once the build is fixed, run the script from a
host with U64E LAN access to capture the number; it defaults to a
30 minute wall-clock budget (`SENTINEL_POLL_TIMEOUT=1800` /
`ACCEPT_TIMEOUT=1800`) — expect 4-7 minutes per handshake at 48 MHz
turbo, dominated by:

  - one ECDSA-P384 verify (sibling `libs/nistcurves`
    `ecdsa_verify_384`); P-256 measures 81.9 s, the P-384 cost is
    ~5x because the field is 1.5x wider and the scalar mul does
    proportionally more `fp_mul` / `fp_sqr` calls — extrapolate
    ~400 s = ~7 min ceiling
  - one SHA-384 hash over the 130 B signed-content blob (negligible
    vs the verify)
  - the dual-overlay swap dance (sha384 overlay swap-in →
    sha384_init/update/final → curve overlay swap-in → verify); each
    swap is 2 REU DMAs at ~16 ms wallclock — also negligible
  - X25519 + Finished HMACs + state-machine overhead (~6-7 s
    across the rest of the handshake, per the P-256 baseline)

Once measured, drop the wall-clock here. Phase 4 cert-profile flag
in the local listener (`HTTPS_LISTENER_CERT_PROFILE=p384` or the
`cert_profile="p384"` kwarg to `start_https_listener`) is the
upstream selector; `tools/uci/test_https_local_p384.py` inlines its
own listener (matching `test_https_local.py`'s pattern) and points it
at `tools/https_e2e/certs/server-p384.{pem,key}`.

### Design note — bounded timeouts must use wall-clock time

Robustness work on the UCI adapter's spin-wait helpers (`uci_wait_idle`,
`uci_wait_not_busy`, `uci_drain_resp`, `uci_drain_status`, etc.) MUST
use a wall-clock time source — CIA timer
on stock C64, TOD clock on U64E — rather than a cycle-counted iteration
budget. The fences around every UCI register access make per-iteration
cost scale with CPU speed: a budget that is ample at 1 MHz collapses
to far too short at 48 MHz because turbo scales CPU cycles but not the
FPGA's wire-level operation durations. A prior attempt on branch
`feat/net-drain-abi` split waits into fast/long tiers with cycle-count
budgets and broke DHCP at turbo for exactly this reason; the branch
was abandoned.

`uci_wait_idle` was the first helper to follow this pattern (issue #37).
At entry it samples CIA1 TOD ($DC08-$DC0B) — read order is HOUR
(latch) → MIN → SEC → TENTHS (unlatch) — and on each spin pass re-reads
TENTHS, bailing with C=1 + `net_last_error = UCI_ERR_WAIT_TIMEOUT`
after 50 transitions (~5 s wall-clock, independent of CPU turbo). State
lives in two SMC bytes inside the routine to match the file's no-ZP
convention. Use this as the template for any future bounded helper.

`uci_wait_not_busy` was converted to the same pattern after a Phase 5
wedge in CertVerify recv on real U64E hardware — the unbounded spin
turned an FPGA wedge into a 1843 s test sentinel timeout. Same 5 s
budget, same error code, same SMC-byte state convention. All six
caller sites (`net_poll`, `net_dhcp_acquire`, `net_tcp_connect`,
`net_tcp_send`, `net_tcp_close` direct + via `uci_push_wait`) `bcs`
out on C=1 to surface the timeout. `uci_push_wait` inherits the bound
via its tail-`jmp` into `uci_wait_not_busy` and needs no separate
conversion.

`uci_drain_resp` and `uci_drain_status` followed in Phase 5j to close
the symmetric risk on the response-drain side: `net_tcp_send` /
`net_poll` / `net_tcp_close` all call drains after their respective
SOCKET_WRITE / POLL_DATA / SOCKET_CLOSE responses, and if firmware
ever leaves DATA_AV / STAT_AV asserted post-response the old
unbounded `jmp <self>` loops would wedge the C64 with no wall-clock
escape. Same 5 s budget, same error code, same SMC-byte state
convention. All 13 call sites in `net.s` `bcs` out on C=1 to skip
the companion drain + ack and force the appropriate exit state.

### Design note — the post-ServerHello drain, and why its budget is per-backend

`tls13.s` drains the network right after parsing ServerHello, before
the multi-minute ECDHE + verify stalls. It exists because of an ip65
property: **ip65 sends no MSS option in its SYN** (so peers may segment
small — macOS defaults to 512 B, splitting the ~690 B server flight)
**and ACKs only when the consumer pumps `net_poll`**. Without the
drain, the flight tail sits unACKed while the C64 computes, and an
impatient peer drops the connection (macOS: hard drop after 13
retransmits, ~54 s on a LAN). The failure is nasty to diagnose: the
C64 goes on to verify the *entire buffered flight* correctly, offline,
and only dies minutes later when it sends client Finished into a
socket that was RST long ago (fingerprint: `tls_state=$FF`,
`tls_read_seq=4`). Linux servers hid it (15-30 min of retransmits) and
UCI hid it (firmware ACKs autonomously); **real internet servers sit
between those**, so this is a prerequisite for any real-server story.

The budget lives in a per-backend `src/net/<backend>/net_tuning.inc`
(`NET_SH_DRAIN_OUTER/INNER`), resolved through the existing
`-I src/net/$(BACKEND)` include path so `tls13.s` stays
backend-agnostic. This is load-bearing, not tidiness: **an ip65
`net_poll` is a cheap NIC pump, but a UCI `net_poll` is a full
firmware command round-trip** (SOCKET_READ + waits + drains + ack,
~25 fenced register accesses plus FPGA turnaround) measured at
**~40 ms**, of which only ~3 ms is fence time — the rest is
clock-invariant, so turbo does not amortize it. Shipping ip65's
2000-poll budget unconditionally cost UCI ~80 s and regressed the
handshake 51.0 s -> 125.4 s (#73, fixed by #74). Current values:
ip65 8x250 = 2000 (validated; do not shrink without re-running the
VICE e2e), UCI 1x16 = 16 (~0.6 s hedge — the drain has nothing to buy
where firmware ACKs on its own; keep it non-zero, since the loop's
`dex`/`bne` shape turns an INNER of 0 into 256 iterations).

Two follow-ups are open. Flights larger than the TCP window need
polling *inside* the long crypto, not just before it — that is the
real-server cert-chain case. And the principled version of this
bound is wall-clock/idle-based (poll until the ring stops growing)
rather than iteration-counted, which is exactly what the rule above
says; it needs care around CIA1 TOD latch interaction with the UCI
adapter's own TOD waits.

## Memory layout

Defined in `cfg/c64-https-ip65.cfg` (W1 partial split) and
`cfg/c64-https-uci.cfg` (full W1 hot/cold split). Post-W1 the cfgs
diverge non-trivially; both refactors landed via PR #55 to absorb the
bumped `libs/nistcurves` library without overflowing CRYPTO.

UCI layout (W1 reference — `cfg/c64-https-uci.cfg`):

  $0801-$1FFF  LOADER             BASIC stub + boot + HTTP + net wrapper
  $2000-$3B25  NET_CODE           UCI adapter (~1.7 KB) + LOADER_OVERFLOW
                                  + TLS_CODE + CRYPTO_AUX_CODE
  $3B26-$3FFF  NET_BSS_TAIL       BSS spill carved from NET_CODE tail
                                  (UCI_BSS + LIB_NISTCURVES_P256_BSS
                                  land here when they don't fit in
                                  CRYPTO_HOT)
  $4000-$41FF  UCI_BSS_REGION     Zero-size alias post-W1 (UCI_BSS moved
                                  into NET_BSS_TAIL above)
  $4200-$5FFF  CRYPTO_OVERLAY     7.5 KB swappable overlay slot
                                  (X25519 sibling / P-384 SHA-384 /
                                  P-384 curve / W3 P-256 verify embed)
  $6000-$9FFF  CRYPTO_HOT         16 KB file-backed; resident code +
                                  rodata + small BSS (UCI_BSS, most of
                                  libs/nistcurves P-256). No segment
                                  crosses $A000 — boot's zbss loop wipes
                                  $A000-$BFFF, so anything executable up
                                  there would be zeroed on first run.
  $A000-$BFFF  CRYPTO_COLD_SHADOW 8 KB file-backed (zero-filled); large
                                  BSS chunks (BSS, CRYPTO_BSS,
                                  TABLES_BSS, BSS_TAIL).
  $C000-$DFFF  OVERLAY_FILE_PAD   Zero-pad in the PRG; runtime: TCP_BUF
                                  ring at $C000.
  $E000-$FDFF  OVERLAY_BLOB_CURVE_RAM
                                  P-384 CURVE overlay blob; boot DMAs
                                  it to REU bank 7 then this region is
                                  reusable.

ip65 layout (W1 partial — `cfg/c64-https-ip65.cfg`):

  $0801-$1FFF  LOADER             (same)
  $2000-$3FFF  NET_CODE           ip65 blob + LOADER_OVERFLOW +
                                  CRYPTO_AUX_CODE2
  $4000-$4F8B  NET_BSS            ip65 blob's BSS (occupancy stops at
                                  $4F8B per ip65-c64.map)
  $4F8C-$5FFF  CRYPTO_OVERLAY     4,212 B reclaimed BSS-TAIL slot; holds
                                  TLS_CODE + CRYPTO_AUX_CODE (Phase C.4
                                  placement). Future P-384 / SHA-384 /
                                  X25519 sibling overlay segments
                                  anchored here (`optional = yes`).
  $6000-$9FFF  CRYPTO_RESIDENT    16 KB file-backed code + rodata
                                  (stays below $A000 — see UCI note)
  $A000-$BFFF  CRYPTO_COLD_SHADOW 8 KB file-backed BSS
  $C000-$CFFF  TCP_BUF            tcp_recv_buf, 4 KB ring for ip65 callback

`LOADER_OVERFLOW` is a small segment carrying ~125 B of `http.s` growth
(Content-Length parser + digit pattern) that did not fit in LOADER's
~50 B of slack. It rides in the tail of `NET_CODE`, after the ip65
blob under the ip65 backend and after the UCI adapter under the UCI
backend. Both cfgs declare it. Reachable via JSR from LOADER-resident
CODE.

Tight regions (post-W1):
  - **CRYPTO_HOT / CRYPTO_RESIDENT** carry resident code + rodata.
    Under UCI the W1 split moved big BSS into CRYPTO_COLD_SHADOW,
    opening enough slack to absorb the v0.3.0 nistcurves bump cleanly.
  - **CRYPTO_COLD_SHADOW** ($A000-$BFFF, 8 KB) holds the bulk of BSS.
    Under ip65 the total c64-https + libs/nistcurves BSS claim exceeded
    8 KB, and ld65 refused the link (`BSS overflows CRYPTO_COLD_SHADOW
    by 1406 bytes` at the v0.6.0 pin). **Resolved by the #68 refit**:
    the gap was exactly `LIB_NISTCURVES_P256_BSS` (1,312 B of
    verify-time-only scratch), which now overlays `cert_buf` through
    the `SCRATCH_UNION` region — the two lifetimes are disjoint
    (cert_buf is dead once the Certificate handler has extracted the
    pubkey; the lib scratch is live only inside `ecdsa_verify`).
    `cert_buf` is pinned at $A000 with a link-time `.assert`, the
    union is capped at cert_buf's span so future growth is a link
    error rather than silent corruption, and `TABLES_BSS` is declared
    last so it packs at $BA00 (keeping `sqtab_reserved` at $BC00 for
    the onchip bake invariant). Both backends now link clean, and the
    union is exercised live by `tools/test_x509.py` 3c/3d and by every
    ip65 e2e run. c64-nist-curves#54 (minimal archive) remains open as
    optional headroom, no longer a blocker.
  - **CRYPTO_OVERLAY** under UCI doubles as P-384 SHA-384/curve overlay
    paging slot, the W3 P-256 overlay embed slot, AND the
    USE_X25519_SIBLING=1 X25519 sibling rodata + BSS slot. Mutually
    exclusive at link time across the three flags.

There is a known TODO to restructure the MEMORY map so that all
file-backed regions are physically contiguous in a single ROM-like
run (the LOADER/NET gap is currently zero-filled into the PRG just
to keep offsets right). That cleanup is explicitly **out of scope**
for the ca65-conversion branch — see the Phase 6 commit for the
rationale and follow-up plan.

See `docs/library-ingestion-architecture.md` for the broader plan
(W1-W7 work items, library-side issues A-E filed against
`JC-000/c64-lib-contract` + adopter repos, CI bot design) that this
section is incrementally executing.

### LOADADDR / exports stubs

Two small `src/*.s` files exist as thin wrappers to work around
ld65 and ca65 edge cases; they are intentional and should stay:

  - `src/loadaddr.s` — a single `.word $0801` in the `LOADADDR`
    segment. ld65 needs *some* symbol in that segment for the 2-byte
    PRG load-address header to land at `$07FF`.
  - `src/exports.s`  — promotes the numeric equates `tcp_recv_buf`,
    `ip65_init`, `ip65_process` to linker-visible `.export`s so they
    appear in `build/labels.txt` for the Python test harness. The
    `.export` has to live in exactly one translation unit; doing it
    inside the `.inc` header would duplicate on every include.

## Packaging

`make package` builds the release artifacts into `dist/` (gitignored):

  - `c64-https-uci-reu.prg`    — default REU profile (`make BACKEND=uci`).
                                 Requires REU hardware/enabled; fastest
                                 at stock 1 MHz (the REU profile is the
                                 right default below ~7 MHz).
  - `c64-https-uci-onchip.prg` — `USE_NISTCURVES_ONCHIP=1`. **No REU
                                 required** — for stock machines without
                                 an REU (~3.9x the verify CPU work; at
                                 1 MHz expect ~23 min for the ECDSA
                                 verify alone).
  - `c64-https.d64`            — both PRGs on one 1541 image
                                 (`HTTPS-REU`, `HTTPS-NOREU`), built
                                 with VICE's `c1541`.
  - `c64-https-listener.zip`   — self-contained Python TLS 1.3 test
                                 listener (source: `tools/package/
                                 listener/`): `run.sh` creates a venv,
                                 installs `cryptography`, **generates
                                 fresh P-256 certs** (`gen_certs.py`),
                                 and serves the canonical response.
                                 Requires an OpenSSL 1.1.1+/3.x python
                                 (refuses LibreSSL, e.g. macOS system
                                 python, with a clear error).
  - `MANIFEST.txt`             — sizes, git HEAD, sha256 checksums.

Scripts live in `tools/package/` (`build_prgs.sh`, `build_d64.sh`,
`build_listener_zip.sh`); each variant build does `make clean` first
(flag changes are not tracked by make). Builds are deterministic —
`make package` reproduces the validated hashes at the same HEAD.

**ip65 is not packaged yet, but it now LINKS.** The historical blocker
(`BSS overflows CRYPTO_COLD_SHADOW by 1406 bytes`) was closed by the
#68 refit — the overflow was exactly `LIB_NISTCURVES_P256_BSS`, which
now time-shares `cert_buf`'s RAM via the `SCRATCH_UNION` region (their
lifetimes are disjoint; see the cfg comment block and the lifetime
contract at `cert_buf` in `src/der_decode.s`). Both ip65 profiles
build, and the REU-less ip65+onchip image is validated end-to-end in
VICE (see "ip65 / stock-C64 wall-clock"). Adding it to `make package`
is a live option — it is the only artifact that serves a stock C64 +
RR-Net cartridge, which today has no shipped PRG at all. Note
c64-nist-curves#54 (minimal archive) is now optional headroom rather
than a blocker. The comb profile stays deliberately excluded (REU
bank 2 residency + ~40 min boot precompute at 1 MHz make it wrong for
a general release).

Validation record (2026-07-27, HEAD cb6eab4):
  - onchip PRG passes the 3-vector ECDSA KAT in VICE **without** REU
    (and with, as control) — the no-REU claim is verified, and
    boot.s's unconditional reu_mul_init is harmless with no REU
    attached. Both D64 files boot to banner in VICE.
    Reproduce it with the `C64_VICE_NO_REU` opt-out (no patching, and
    `-reu` stays the default everywhere else):

        make clean && make BACKEND=uci USE_NISTCURVES_ONCHIP=1
        C64_SKIP_BUILD=1 C64_VICE_NO_REU=1 \
            python3 tools/test_ecdsa_kat_oracle.py    # 3/3, exit 0
        C64_SKIP_BUILD=1 python3 tools/test_ecdsa_kat_oracle.py
                                                      # control, 3/3

    The flag is only meaningful on an onchip image. Run it against a
    REU-profile build and all three valid vectors verify as C=1 with
    no error message — that silent-wrong-answer failure mode is why
    `-reu` is the default (see "VICE harness gotcha").
  - Full shipped chain (zip listener + freshly generated certs +
    sha-verified dist PRGs, `EXTERNAL_LISTENER=1`), all HTTP 200 +
    canonical body over TLS_CHACHA20_POLY1305_SHA256:

      device   variant   clock    handshake+GET
      C64U     REU       48 MHz   72.4 s
      C64U     onchip    48 MHz   49.8 s
      C64U     REU       64 MHz   65.2 s
      C64U     onchip    64 MHz   40.1 s
      U64E     REU       48 MHz   79.8 s
      U64E     onchip    48 MHz   51.8 s
      U64E     REU       1 MHz    1142.9 s (~19 min) — the stock-clock
                                  user story, validated end-to-end
    (U64E runs post power-cycle — see the wedge-episode note in
    "End-to-end HTTPS status".)

## Smoke tests

The `tools/test_*.py` scripts cover individual crypto primitives and
the TLS state machine. For a quick sanity check after a build:

  - `tools/test_entropy.py`        — fastest (DRBG seed + fill, 7 tests)
  - `tools/test_hkdf.py`           — HKDF extract/expand
  - `tools/test_chained_hmac.py`   — HMAC chain
  - `tools/test_keyschedule_steps.py` — TLS 1.3 key schedule
  - `tools/test_tls_handshake.py`  — full handshake state machine
  - `tools/test_http.py`           — HTTP request/response build + parse
  - `tools/test_x509.py`           — X.509 parser

All 7 pass as of the ca65-conversion branch (97/97 assertions).

The `tools/uci/` scripts cover the UCI backend on U64E hardware (see
the "UCI test scripts" subsection above).

### VICE ip65 rig (hardware-free e2e)

`tests/test_vice_https_macos.py` runs the **full HTTPS handshake + GET
over the ip65 backend with no hardware at all** — emulated RR-Net
(cs8900a) in VICE talking to a host-side TLS 1.3 listener. This is how
the REU-less stock-C64 numbers above were measured. Knobs:
`E2E_PROFILE=reu|onchip`, `E2E_NO_WARP=1` (honest 1 MHz timing),
`E2E_TIMEOUT`, `HTTPS_PORT` (the PRG's port is a build knob —
`make HTTPS_PORT=4433` — so the listener can run unprivileged).

Two prerequisites that are easy to lose:

  - **An ethernet-capable VICE.** Stock macOS VICE binaries (official
    and Homebrew) compile ethernet in but gate the pcap driver on
    `geteuid()==0`, so unprivileged `-ethernetiodriver pcap` is
    rejected and enabling the cart segfaults on a null driver table.
    This bench uses a patched 3.10 SDL2 build at
    `~/opt/vice-eth/bin/x64sc` (patch + rebuild script alongside it);
    see `vice_eth_build` in memory and c64-test-harness#144.
  - **The rig**: `sudo bash tools/rig-up-macos.sh` creates the feth
    pair, puts the host at 10.0.65.1, opens `/dev/bpf*`, and starts
    dnsmasq. `/dev/bpf*` permissions **reset on every reboot** — a
    "pcap not valid for option" error means re-run the script, not a
    broken binary. The test's preflight checks all of this and says so.

Also worth knowing: macOS's Local Network privacy gate can silently
block the listener's sockets until a one-time GUI prompt is approved;
the test self-probes for that, because the symptom otherwise looks
like a C64-side TCP failure.

End-to-end HTTPS against a real server (`www.foo.bar` via the local
bridge rig — never a real internet domain) was historically blocked on
an "upstream ip65 bug" recorded only in a since-lost memory note. Part
of that story is now understood and fixed: ip65 sends no MSS option and
ACKs only when polled, so peers less patient than Linux drop the
connection during multi-minute crypto stalls (see the drain note in
"Design note — bounded timeouts"). Whether anything else remains needs
a fresh repro rather than trust in the old note.
