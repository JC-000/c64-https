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
  - `make`              — default, produces `build/c64-https.prg`
                          and `build/labels.txt` (VICE label format)
  - `make clean`        — remove build artifacts
  - `make run`          — autostart the PRG in VICE
  - `make ip65-libs`    — rebuild ip65 object libraries from the submodule
                          (only needed if the ip65 submodule changes)
  - `make ip65-blob`    — rebuild `ip65-build/ip65-c64.bin` from those
                          libraries (the committed blob is normally reused)

Variables:
  - `BACKEND=ip65|uci`  — select networking backend cfg
                          (`cfg/c64-https-$(BACKEND).cfg`; default ip65)
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
    Opt-in: sibling `libs/x25519@v0.4.0` via `make USE_X25519_SIBLING=1`
    (UCI backend only — see Known issues for the ip65 fit blocker; Phase
    C.5). Sibling and in-tree both expose the same ABI:
    x25519_scalarmult     — X25519 scalar × point, 32-byte buffers
    fe25519_mul, fe25519_sqr, fe25519_inv

  ChaCha20-Poly1305         (in-tree, permanent)
    chacha20_encrypt
    poly1305_init, poly1305_update, poly1305_final
    aead_encrypt, aead_decrypt

  SHA-256                   (in-tree; no sibling)
    sha256_init, sha256_update, sha256_final

  ECDSA P-256                (libs/nistcurves sibling, Phase C.4)
    ecdsa_verify_256      — TLS dispatcher in src/crypto/ecdsa_verify.s
                            packs the BE struct + calls the sibling entry
    ec_scalar_mul_var     — variable-base scalar multiplication
    (in-tree ecdsa_{curve,fp,mod,points}.s were deleted in Phase G)

P-384 is *stubbed at the TLS layer* (see `project_p384_stubbed` memory
note). The sibling `libs/nistcurves` P-384 primitives are buildable as
an external overlay image (Phase C.3b, `make p384-overlay`) but the
target has a pre-existing unresolved-symbol bug (`ec_base384_x/y` in
points384_raw.s) — fix that before wiring P-384 into the TLS path.

MEMORY requirements for a drop-in sibling library:
  - Code + rodata must load into the `CRYPTO` region at **$6000-$9FFF**
    (below the BASIC ROM shadow at $A000, so it survives ROM banking).
  - `TABLES_BSS` (`x25519` squaring tables etc.) must stay **below $A000**;
    the cfg pins it inside the CRYPTO region with `align = $100`.
  - Zero-page usage is defined in `src/constants.inc` — fe25519 lives at
    `$2C-$37`, x25519 state at `$38-$3A`, ECDSA bignum at `$22-$3C`.
    These ranges are time-shared (fe25519 and ChaCha20 never overlap).
  - REU Profile B is the baseline. Under the default build the in-tree
    x25519 implementation uses a smaller on-chip squaring table in
    `TABLES_BSS` and leaves REU banks 0-1 free. Under
    `USE_X25519_SIBLING=1` (Phase C.5) the sibling's `reu_mul_init`
    populates REU banks 0-5 with mul / doubled / 17-bit-carry tables;
    banks 3-5 nominally collide with the P-256 / P-384 precompute
    reservations in `src/crypto/shared/reu_layout.inc` but the
    collision is theoretical only (P-256 uses `ec_scalar_mul_var` with
    no precompute; P-384 is stubbed at the TLS layer). Banks 6-7 stay
    reserved for the `make p384-overlay` external-image smoke test
    (Phase C.3b).
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
`UCI_FENCE_INNER = 100`, yielding ~2525 cycles (~52 us at 48 MHz,
35% safety margin). 14 bytes per fence site, 24 fence sites total
(11 write + 13 read). At 1 MHz the same loop costs ~2.5 ms per
access — negligible for networking.

48 MHz turbo is fully supported and verified on real U64E hardware.

### Memory layout under UCI

The NET_CODE/NET_BSS regions ($2000-$5FFF) are repurposed:

  $2000-$3FFF  UCI_CODE     UCI adapter code (`net.s`, `uci_cmd.s`)
  $4000-$5FFF  UCI_BSS      `uci_host_buf`, ipaddr scratch, socket
                            state, command control block

All other regions (LOADER, CRYPTO, SHADOW_BSS, TCP_BUF) are identical
to the ip65 layout.

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
negotiates only TLS_AES_128_GCM_SHA256 — Phase 5 Fix A). The
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
  - **X25519 sibling (Phase C.5)** — `make USE_X25519_SIBLING=1` builds
    against `libs/x25519@v0.4.0`. Default is OFF; the in-tree
    implementation remains the shipped default until the flag flip is
    decided. The Phase C.1 hang and v0.3.0 retry rollback are both
    closed by upstream PR #36 + v0.4.0 H2 (defensive REU register init
    at every `x25519_scalarmult` / `fe25519_mul` / `_sqr` / `_mul_a24`
    / `_inv` entry — eliminates the `do_swap` residue confound on
    `$DF04`/`$DF0A` that produced the wrong-result symptom). Verified
    on U64E at 48 MHz: HTTPS handshake completes in ~101 s
    (vs ~87 s under in-tree X25519; the +14 s is consistent with
    v0.4.0's release-notes-documented +27 % scalarmult cost over v0.3.0
    for the L1-L29 CT closures). **ip65 backend overflows
    CRYPTO_RESIDENT by 1 KB under the flag** — UCI is the supported
    path; ip65 fit is a separate cfg-restructure follow-up. See
    `tools/integration/build_x25519.sh` for the staging layout.
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
  - `make p384-overlay` has a pre-existing unresolved-symbol bug:
    `points384_raw.s` references `ec_base384_x` / `ec_base384_y`
    which aren't exported by the current sibling build. Not a Phase C
    regression — the target has never built cleanly — but should be
    fixed before P-384 is actually wired into the TLS path. TLS-level
    P-384 verify remains stubbed regardless (see `project_p384_stubbed`).
  - **VICE harness gotcha**: any test that exercises sibling
    `libs/nistcurves` P-256 primitives (`fp_mul`, `fp_inv`,
    `ec_scalar_mul_var`, `ecdsa_verify_256`, ...) MUST launch VICE with
    `-reu`. The sibling's `fp_mul` fetches 8x8 multiply rows from REU
    banks 0/1 (populated by `src/boot.s::reu_mul_init`). Without `-reu`,
    the row fetch silently no-ops and `mul_dma_lo/hi` at $BA00/$BB00
    stays stuck at `reu_mul_init`'s final-iteration residue (a=255), so
    every `fp_mul` returns `a*255*b mod p` instead of `a*b mod p`.
    Cascade: wrong `w=s^-1 mod n`, wrong `u1`/`u2`, wrong computed `R`,
    `R.x != r`, verify returns C=1. Pattern is fixed in
    `tools/test_x509.py:769` and `tools/test_ecdsa_kat_oracle.py:293`;
    mirror this in any new VICE-driven test for P-256:
    `ViceConfig(..., extra_args=["-reu", "-reusize", "512"])`. The same
    pattern is already in `tools/test_x25519.py:722`,
    `tools/bench_x25519.py:138`, `tools/test_p384_symbols.py:370`. The
    UCI path is unaffected because the U64E hardware has REU enabled by
    default; the symptom was VICE-only.

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

Under the v0.2.0 submodule pin the U64E 48 MHz handshake measures
**86.7 s** end-to-end (re-measured 2026-05-12, `tools/uci/test_https_local`,
local listener). The +4.8 s vs the 81.9 s v0.1.0-10-gdfdfb59 baseline
above is attributable to v0.2.0's defensive REU register inits at
`fp_mul`/`fp_sqr`/`ec_scalar_mul_var`/`fp_inv`/`ecdsa_verify_256` proc
entry (release notes "Security/correctness defences" — +6 cy/call;
the wall-clock impact compounds across the tens of thousands of
field-mul/sqr calls in the scalar mult).
It is fine for the local listener used by the e2e harness (600 s
budget, ample headroom). Further speedups live in the sibling
`libs/nistcurves` repo — any drop through the Crypto ABI lands
here as a submodule bump without
touching TLS call sites.

### ECDSA P-384 verify wall-clock

Not yet measured end-to-end. The U64E test host was unreachable from
the dev machine when Phase 5's e2e wiring landed (DeviceLock
unavailable; ping/TCP both unreachable to the default
192.168.1.81). Run `tools/uci/test_https_local_p384.py` from a host
with U64E LAN access to capture the number; the script defaults to a
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

## Memory layout

Defined in `cfg/c64-https-ip65.cfg`. Physically contiguous file-backed
regions run from $0801 through $9FFF, with SHADOW_BSS at $A000 and the
TCP ring at $C000.

  $0801-$1FFF  LOADER       BASIC stub + boot + TLS + HTTP + net wrapper
  $2000-$3FFF  NET_CODE     ip65 code (as .incbin blob) / UCI adapter,
                            plus LOADER_OVERFLOW tail
  $4000-$5FFF  NET_BSS      ip65 BSS (zero-filled in the PRG)
  $6000-$9FFF  CRYPTO       all crypto code, rodata, and TABLES_BSS
  $A000-$BFFF  SHADOW_BSS   mutable state behind BASIC ROM shadow
                            (CPU port $01 = $36 selects RAM)
  $C000-$CFFF  TCP_BUF      `tcp_recv_buf`, 4KB ring for ip65 callback

`LOADER_OVERFLOW` is a small segment carrying ~125 B of `http.s` growth
(Content-Length parser + digit pattern) that did not fit in LOADER's
~50 B of slack. It rides in the tail of `NET_CODE`, after the ip65
blob under the ip65 backend and after the UCI adapter under the UCI
backend. Both `cfg/c64-https-ip65.cfg` and `cfg/c64-https-uci.cfg`
declare it. Reachable via JSR from LOADER-resident CODE.

Tight regions (after Phase 6 fit-up):
  - **CRYPTO** is **100%** full. Any new crypto byte requires relocation
    or reclamation somewhere.
  - **SHADOW_BSS** was **99.8%** full after Phase 6; ≈258 B was reclaimed
    in the `tls_hs_buf` removal (256 B buffer + 2 B length word), so
    there is a bit more slack now. Still the tightest region after
    CRYPTO — check the linker map before adding anything sizeable.

There is a known TODO to restructure the MEMORY map so that all
file-backed regions are physically contiguous in a single ROM-like
run (the LOADER/NET gap is currently zero-filled into the PRG just
to keep offsets right). That cleanup is explicitly **out of scope**
for the ca65-conversion branch — see the Phase 6 commit for the
rationale and follow-up plan.

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

End-to-end HTTPS against a real server (`www.foo.bar` via the local
bridge rig — never a real internet domain) is still blocked on an
upstream ip65 bug unchanged by this refactor; see
`project_phase3_handoff` in memory.
