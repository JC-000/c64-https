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

  X25519 / field arithmetic  (c64-x25519 sibling)
    x25519_scalarmult     — X25519 scalar × point, 32-byte buffers
    fe25519_mul, fe25519_sqr, fe25519_inv

  ChaCha20-Poly1305         (c64-ChaCha20-Poly1305 sibling)
    chacha20_encrypt
    poly1305_init, poly1305_update, poly1305_final
    aead_encrypt, aead_decrypt

  SHA-256                   (in-tree; no sibling)
    sha256_init, sha256_update, sha256_final

  ECDSA P-256 point ops     (c64-nist-curves sibling)
    ec_point_double, ec_point_add, ec_jacobian_to_affine

P-384 is *stubbed* (see `project_p384_stubbed` memory note). The
`ecdsa_*_384.asm` files exist but are not assembled in the ca65 build
— they must be restored before real cert chains that require P-384.

MEMORY requirements for a drop-in sibling library:
  - Code + rodata must load into the `CRYPTO` region at **$6000-$9FFF**
    (below the BASIC ROM shadow at $A000, so it survives ROM banking).
  - `TABLES_BSS` (`x25519` squaring tables etc.) must stay **below $A000**;
    the cfg pins it inside the CRYPTO region with `align = $100`.
  - Zero-page usage is defined in `src/constants.inc` — fe25519 lives at
    `$2C-$37`, x25519 state at `$38-$3A`, ECDSA bignum at `$22-$3C`.
    These ranges are time-shared (fe25519 and ChaCha20 never overlap).
  - REU Profile B is the baseline. `project_x25519_optimization` notes
    that VICE needs `-reu -reusize 512` for the optimized X25519 tables.

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
`uci_wait_idle`, `uci_begin_cmd`, `uci_push_wait`, `uci_end_cmd`,
`uci_read_data`, etc. No zero-page usage — all absolute addressing
and self-modifying code.

### DNS

UCI firmware resolves hostnames internally during `TCP_CONNECT`. There
is no DNS code in the adapter. `net_dns_resolve` memcpies the hostname
into `uci_host_buf` (256 bytes in UCI_BSS); `net_tcp_connect` passes
it to firmware. Dotted-quad IP literals work because firmware passes
them through.

### Firmware quirk — per-byte NEXT_DATA ACK

Per-byte `NEXT_DATA` ACK truncates multi-byte responses on the current
U64E firmware revision. The read path uses a tight-poll pattern instead
(read `$DF1E` until `DATA_AV` clears). Documented in `uci_cmd.s`.

### Memory layout under UCI

The NET_CODE/NET_BSS regions ($2000-$5FFF) are repurposed:

  $2000-$3FFF  UCI_CODE     UCI adapter code (`net.s`, `uci_cmd.s`)
  $4000-$5FFF  UCI_BSS      `uci_host_buf`, ipaddr scratch, socket
                            state, command control block

All other regions (LOADER, CRYPTO, SHADOW_BSS, TCP_BUF) are identical
to the ip65 layout.

### UCI test scripts

Scripts under `tools/uci/` require a U64E at 192.168.1.81 and use
`DeviceLock` + `enable_uci`/`disable_uci`:

  - `boot_check.py`       — verify UCI firmware detection and boot banner
  - `phase2_check.py`     — DHCP acquire + local IP readback
  - `phase3_tcp_echo.py`  — TCP connect/send/recv against a local echo server
  - `test_http_local.py`  — HTTP GET against a local test server
  - `test_http_live.py`   — HTTP GET against a real internet host (requires
                            internet access from the U64E)

### Known issues

  - `http_status` parsing is garbled on large responses because the
    poll-timeout counter in `http.s` expires before all headers are
    consumed under UCI's slower `net_poll` round-trip. Body arrives
    correctly; status line is mis-parsed. Pre-existing `http.s` issue,
    not UCI-specific.
  - `net_tcp_set_recv_cb` is an RTS stub (no callers in-tree).
  - Boot banner line 03 says "RR-NET (CS8900A) ETHERNET" under ip65
    and "UCI NETWORKING" under UCI — this is correct/expected behavior.
  - **Live HTTP GET to www.zimmers.net**: TCP connection establishes
    (valid socket, no error) but the receive loop intermittently
    receives zero bytes. Diagnosed as a net_poll/SOCKET_READ timing
    issue with large responses from real servers. The local HTTP test
    (small controlled response) passes reliably. Under investigation.

### Resolved issues (follow-up fixes landed)

  - Ring buffer zeroing is now performed inside `http_get_plain`
    (previously required manual zeroing before each call).
  - Legacy symbol names (`net_dhcp`, `net_print_ip`, `net_recv_byte`,
    `net_send_len`) have been cleaned up — only `net_abi.inc` symbols
    are exported now.

## Memory layout

Defined in `cfg/c64-https-ip65.cfg`. Physically contiguous file-backed
regions run from $0801 through $9FFF, with SHADOW_BSS at $A000 and the
TCP ring at $C000.

  $0801-$1FFF  LOADER       BASIC stub + boot + TLS + HTTP + net wrapper
  $2000-$3FFF  NET_CODE     ip65 code (as .incbin blob)
  $4000-$5FFF  NET_BSS      ip65 BSS (zero-filled in the PRG)
  $6000-$9FFF  CRYPTO       all crypto code, rodata, and TABLES_BSS
  $A000-$BFFF  SHADOW_BSS   mutable state behind BASIC ROM shadow
                            (CPU port $01 = $36 selects RAM)
  $C000-$CFFF  TCP_BUF      `tcp_recv_buf`, 4KB ring for ip65 callback

Tight regions (after Phase 6 fit-up):
  - **CRYPTO** is **100%** full. Any new crypto byte requires relocation
    or reclamation somewhere.
  - **SHADOW_BSS** is **99.8%** full — roughly 20 bytes of slack.

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
