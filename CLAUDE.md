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

First build in a fresh clone or worktree (ip65 backend only — the UCI
backend needs none of this):

    git submodule update --init --recursive
    make ip65-libs        # once per clone
    make ip65-blob        # once per clone — `make` will NOT do this for you
    make

`ip65-build/ip65-c64.bin` is a **gitignored local build artifact**
(`.gitignore` line `ip65-build/*.bin`; `git ls-files ip65-build/` returns
only `ip65.cfg` and `ip65_stub.s`), *not* a committed file.

**A plain `make` does not build it and cannot.** `ip65-blob` is a phony
target, and `src/net/ip65/ip65_blob.s` pulls the file in through a ca65
`.incbin` that make's dependency graph never sees — so there is no rule
connecting the two. A fresh clone therefore fails at assembly, before any
link, with:

    src/net/ip65/ip65_blob.s(22): Error: Cannot open include file
    '../../../ip65-build/ip65-c64.bin': No such file or directory

and it fails identically whether or not `make ip65-libs` has been run.
Running `make ip65-blob` *without* the libs is what produces the other
error you may see, since the blob's link step consumes ip65 `.lib`
archives that the submodule ships sources for rather than binaries:

    ld65: Error: Input file '../ip65/ip65/ip65_tcp.lib' not found

Both orderings are recoverable by running the four commands above in
order. Verified end to end on 2026-08-14 from a clean `git clone` of
master: plain `make` fails with the `.incbin` error, still fails after
`make ip65-libs`, and succeeds after `make ip65-blob` — yielding the
6,951 B blob (`cf1a5ff7...`) and a 47,105 B ip65 PRG.

`make clean` only removes `build/`, so once built the blob survives and is
never rebuilt; that persistence, not a committed file, is why the rebuild
targets are normally invisible. The rebuild is deterministic: 6,951 B,
sha256 `cf1a5ff7809af4e4655e385b378b936054f41046ff2b7604828af3240c2d90dd`
— rebuilt byte-identically in three independent worktrees on 2026-08-13,
and identical to a local copy built 2026-05-06. Three months and four
artifacts agree, so a stale blob is not a failure mode worth designing
around; a missing one is.

Targets:
  - `make`              — default, produces `build/c64-https.prg`,
                          `build/labels.txt` (VICE label format), and
                          `build/c64-https.dbg` (cc65 debug info,
                          consumable by VICE's monitor + diagnostic
                          agents; P-384 overlays get `.dbg` sidecars too)
  - `make clean`        — remove build artifacts
  - `make run`          — autostart the PRG in VICE
  - `make ip65-libs`    — build ip65's object libraries from the
                          submodule. Required once per fresh clone (see
                          above), and again whenever the ip65 submodule
                          changes.
  - `make ip65-blob`    — rebuild `ip65-build/ip65-c64.bin` from those
                          libraries. A plain `make` already builds the
                          blob on demand and then reuses it, so this
                          target is only for forcing a rebuild.

**`make clean` when you change `BACKEND=` or any flag.** make tracks
source timestamps, not the command line, so an object built for the
other backend counts as up to date. This is not only about `-D` flags:
`BACKEND=` also selects the `-I src/net/$(BACKEND)` include path, and
`src/tls13.s` pulls `net_tuning.inc` from there. Both failure modes were
observed in one worktree on 2026-08-13:

  - **Mixed link.** An ip65 PRG built from a UCI-compiled `tls13.o`
    carries drain budget 1x16 instead of 8x250 — issue #73's regression,
    silently reintroduced. Same 47,105 B as the clean image; only the
    content differs (`d483d46f…` vs the correct `db311110…`), and the
    build output is a bare `ld65` line.
  - **No link at all.** macOS ships **GNU Make 3.81**, which compares
    mtimes at 1-second resolution. Objects recompiled inside the same
    second as the previous link count as older (measured: 39 ms newer,
    make said "Prerequisite ... is older than target"), so `make`
    exits 0 having left the *other backend's* PRG in place — a
    62,977 B UCI image where an ip65 build was asked for.

So neither exit code nor file size distinguishes a good build from a bad
one here. After any flag or `BACKEND` change, `make clean`; if a build
matters, check the **PRG's** sha256.

Specifically the PRG's, not an object's: **ca65 stamps the build's
wall-clock time into every `.o` header**, so two clean builds of
identical source produce different object hashes and a `.o` hash is not
evidence of anything. `ld65` does not propagate that field, so the PRG
*is* deterministic: `build/c64-https.prg` held at `db31111031e2…` across
every rebuild while every `.o` changed hash each time. That asymmetry is
what makes PRG-hash comparison a usable check — a property of the
toolchain, not a convention.

No byte offset is quoted here on purpose: it is a cc65-version detail,
and three people reading three different offsets out of the same effect
is how a checkable finding turns into a disputed one. The reproduction
is `make clean && make` twice and comparing hashes, which holds whatever
the layout.

Fresh-checkout gotcha: right after `git submodule update --init ip65`,
plain `make` tries to *relink the blob* — the freshly checked-out
`ip65-build/ip65_stub.s` is newer than the committed
`ip65-build/ip65-c64.bin`, so the `$(IP65_BIN)` rule fires and dies on
`ld65: Error: Input file '../ip65/ip65/ip65_tcp.lib' not found`.
`touch ip65-build/ip65-c64.bin` restores the intended "committed blob
is reused" path; `make ip65-libs` is the alternative if you actually
want to rebuild it.

Variables:
  - `BACKEND=ip65|uci`  — select networking backend cfg
                          (`cfg/c64-https-$(BACKEND).cfg`; default ip65).
                          Changing it requires `make clean` — see above.
  - `USE_X25519_SIBLING=1` — swap the in-tree X25519 for the
                          `libs/x25519@v0.6.0` sibling. **Does not link
                          on either backend at present** — both
                          overflow, differently; see "Known issues"
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
    reuse the already-built PRG. 14 scripts honor it as of 2026-08-13
    (13 under `tools/`, plus `tests/test_vice_https_macos.py`); the
    current list is `grep -ln 'environ.*C64_SKIP_BUILD' tools/test_*.py
    tests/test_*.py` rather than a number that goes stale here.
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
    — **currently unbuildable on both backends**, and the pinned
    v0.6.0 additionally carries an upstream correctness bug; see
    Known issues before relying on either fact.
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

  ECDSA P-256                (`libs/nistcurves@v0.9.1` sibling,
                              c64-lib-contract SPEC §1-§8.1 aligned)
    ecdsa_verify_256      — TLS dispatcher in src/crypto/ecdsa_verify.s
                            packs the BE struct + calls the sibling entry
    ec_scalar_mul_var     — variable-base scalar multiplication
    (in-tree ecdsa_{curve,fp,mod,points}.s were deleted in Phase G;
    archive built via `make -C libs/nistcurves lib-p256-verify` — see
    `tools/integration/build_nistcurves_p256.sh` for the wrapper.)

    **From v0.7.0 the sibling validates the public key at entry**
    (FIPS 186-5 §3.3: `Qx,Qy ∈ [0,p-1]` plus on-curve
    `Qy² ≡ Qx³ − 3Qx + b (mod p)`, C=1 returned before any scalar
    multiplication). This matters to c64-https specifically: the `Q`
    handed to `ecdsa_verify_256` comes straight from an
    attacker-supplied certificate via `src/tls_cert.s` →
    `ecdsa_pubkey_x/y`, and c64-https performs no range or on-curve
    check of its own. `src/crypto/ecdsa_verify.s` therefore carries a
    link-time `.assert LIB_NISTCURVES_VERSION_MINOR >= 9` so a silent
    downgrade below that pin is a loud `ld65: Error` rather than a
    quietly reopened gap — every KAT vector we own has a well-formed
    public key, so the tests would not notice. The assert costs zero
    PRG bytes (hashes identical with and without it) and, from v0.9.0,
    zero ld65 warnings, since the version equates are exported `:abs`.

P-384 is *stubbed at the TLS layer* (see `project_p384_stubbed` memory
note). The sibling `libs/nistcurves` P-384 primitives were meant to be
buildable as an external overlay image (Phase C.3b, `make
p384-overlay`) but no P-384 build target has ever completed — see
"Known issues" for the current failure chain. Fix the build
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
  - Sibling-library segments follow the c64-lib-contract SPEC §4
    naming (`LIB_NISTCURVES_P256_CODE`, `LIB_NISTCURVES_P256_RODATA`,
    `LIB_NISTCURVES_P256_BSS`, etc.); the consumer cfg places them by
    name. (§8.1 is the shared `sqtab` table, a different clause — the
    old §8.1 citation here was a miscite.) See
    [c64-lib-contract](https://github.com/JC-000/c64-lib-contract)
    for the contract spec and `docs/library-ingestion-architecture.md`
    for the c64-https rollout plan.
  - **Read `SPEC.md` on `main`, not the latest git tag.** The contract's
    tags lag badly: newest tag is v0.4.0 while `main` is **v0.7.2**
    (checked 2026-08-13). Sections added since v0.4.0 that bind a
    *consumer* rather than an adopter: **§13 Network backend ABI**
    (v0.6.0 — written from c64-https's own net surface; our intake
    issue [#70](https://github.com/JC-000/c64-https/issues/70) is
    OPEN), **§8.0 three-state shared-primitive semantics +
    `LIB_<X>_SHARED_CONSUMES`** with a consumer-side coverage assert
    (v0.5.0; c64-https is the `APP_OWNED` case — `src/boot.s`
    `reu_mul_init`, `src/crypto/shared/mul_tables.s` `mul_tables_init`),
    and **§1/§5 library-prefixed manifest exports** gated on
    `ca65 -D LIB_NO_BARE_EXPORTS=1` (v0.7.0), which is the sanctioned
    replacement for the hand-dropped `lib_version.o` workaround in
    `tools/integration/build_x25519.sh`. c64-https imports **no**
    contract manifest equate today, so none of these are enforced here
    yet.
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

Switching backend = picking a different `cfg/c64-https-$(BACKEND).cfg`
and linking different `src/net/<backend>/*.o` files.

**`src/net_abi.inc` is documentation, not an enforced interface.** This
section used to claim the net API was "fronted by" it and that TLS/HTTP
consume networking "only through those symbols". Both are false, and the
distinction is load-bearing for anyone sizing the §13 work (issue #70):
the starting point is prose, not an interface. Measured 2026-08-14:

  - **Nothing `.include`s it.** `grep -rn 'net_abi' src/ tools/ cfg/
    Makefile` returns only comments. It is not in the build, so none of
    its twelve `.import`s is checked by anything.
  - **Declared and used surfaces overlap in 6 symbols out of 17.** The
    surface TLS/HTTP/boot actually import is `net_init`, `net_dhcp`,
    `net_poll`, `net_print_ip`, `net_dns_resolve`, `net_tcp_connect`,
    `net_tcp_close`, `net_tcp_send`, `net_send_len`, `net_recv_byte`,
    `net_banner_str` (`src/boot.s:107-114`, `src/http.s:61-67`,
    `src/tls_record_io.s:28-30`, `src/tls13.s:96`). Five of those are
    absent from the header; six of the header's are imported by nobody.
  - **The ip65 backend does not provide half of what the header
    declares** — no `net_dhcp_acquire`, `net_tcp_set_recv_cb`,
    `net_local_ip`, `net_resolved_ip`, `net_last_error` or
    `net_tcp_state` (`src/net/ip65/net.s:28` calls them "deferred to
    Phase 7"; Phase 7 shipped). It exports `net_dhcp` instead — the
    exact name c64-lib-contract §13.1 tells c64-wireguard to rename
    away from. The UCI adapter exports both, so the divergence §13
    exists to stop also runs between our own two backends.
  - `net_last_error` in particular exists **only** under UCI, so ip65
    has no error channel at all.

Consequence: the symbol list below describes an intent, not a contract
the linker checks. Treat it as a TODO list until #70's item P1 lands.

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

Symbols declared in `src/net_abi.inc` — aspirational, see the caveat
above. UCI exports all twelve; ip65 exports only the six marked `*`:

  net_init *, net_poll *, net_dhcp_acquire
  net_tcp_connect *, net_tcp_send *, net_tcp_close *, net_tcp_set_recv_cb
  net_dns_resolve *
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
`DeviceLock` + `enable_uci`/`disable_uci`.

They also require the `c64-test-harness` package, which is a **separate
public repo, not vendored here** — `requirements.txt` lists only
`cryptography`. Install it into the same interpreter you run the scripts
with:

    git clone https://github.com/JC-000/c64-test-harness   # sibling dir
    pip install -e ../c64-test-harness

Without it every script here dies at import with `ModuleNotFoundError:
No module named 'c64_test_harness'` (issue #90). The instruction already
existed under the VICE testing section of README.md, but nothing on the
UCI path mentioned it, so anyone who built with `make BACKEND=uci` and
went straight to these scripts never crossed it.

The scripts:

  - `boot_check.py`       — boot the PRG and assert the backend banner
                            (`BACKEND=uci|ip65`, default uci), the
                            absence of any `FAILED` line, and that the
                            menu was reached. `C64_PRG` overrides the
                            image; `BOOT_TIMEOUT` the menu budget.
  - `phase2_check.py`     — DHCP acquire + local IP readback
  - `phase3_tcp_echo.py`  — TCP connect/send/recv against a local echo server
  - `test_http_local.py`  — HTTP GET against a local test server
  - `test_http_live.py`   — HTTP GET against a real internet host (requires
                            internet access from the U64E)
  - `test_https_bad_finished.py` — the client must ABORT on a forged server
                            Finished. Uses the hand-rolled
                            `tools/https_e2e/evil_listener.py` rather than
                            stock `ssl`. `FINISHED_MODE=good` is the control
                            and must be run first. See "Negative-path
                            coverage — the server Finished" under Smoke tests.
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
                            packaged `dist/c64-https-listener.py`
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
    behavior. Under UCI it says "UCI NETWORKING". Those two strings
    are the whole of `net_banner_str`
    (`src/net/ip65/net_banner.s` / `src/net/uci/net.s`), and
    `tools/uci/boot_check.py` asserts against them, so keep the two
    in step. (This entry used to claim the UCI line read
    "ULTIMATE 64 ELITE (UCI)" — it never did.)
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
    repo's release notes. The ip65-side `LIB_NISTCURVES_P256_BSS`
    overflow that used to be recorded here was the *default* build's
    overflow and is fixed (see the CRYPTO_COLD_SHADOW entry under
    "Memory layout").

    **`USE_X25519_SIBLING=1` links on NEITHER backend** (re-measured
    2026-08-13 at f0127a0, fresh submodules, cc65 from homebrew). The
    two failures are different and independent:

      make USE_X25519_SIBLING=1                 # ip65
        X25519_RODATA overflows CRYPTO_OVERLAY by 2048 bytes
        LIB_NISTCURVES_P256_CODE overflows CRYPTO_RESIDENT by 103 bytes

      make BACKEND=uci USE_X25519_SIBLING=1     # UCI
        LIB_NISTCURVES_P256_CODE overflows CRYPTO_HOT by 381 bytes

      make BACKEND=uci                          # control: links clean

    Earlier revisions of this file called UCI "the supported
    sibling-on path"; that was wrong — nothing links the sibling
    today, and no shipped artifact contains it. The UCI overflow is
    simply the sibling's larger code claim: sibling CRYPTO_CODE is
    4,207 B (fe25519 2,711 + x25519 698 + x25519_init 798) against the
    in-tree pair's 2,769 B (fe25519 2,093 + x25519 676), i.e. +1,438 B
    into a CRYPTO_HOT with ~1,057 B of slack. ip65 additionally has
    only a 4,212 B `CRYPTO_OVERLAY` (vs UCI's 7.5 KB) to hold
    `X25519_RODATA` (2,304 B) + `X25519_BSS` (1,536 B) on top of
    TLS_CODE + CRYPTO_AUX_CODE.

    **The pinned v0.6.0 also carries an upstream correctness bug.**
    c64-x25519 #64 (fixed in v0.7.0): `x25519_scalarmult` returns
    deterministically wrong results for a peer u-coordinate with bit
    255 set, across v0.4.0-v0.6.0. v0.4.0 stopped writing the RFC 7748
    `decodeUCoordinate` mask back into `x25_u` but left the ladder's
    `z_3 = x_1 * (DA-CB)^2` site reading the unmasked buffer, so
    x1 = x3 + 19 (mod p). **The in-tree implementation is NOT
    affected** — `src/crypto/x25519.s` still writes the mask back
    (`sta x25_u+31`), so its x_1 read sees the masked value;
    `tools/test_x25519.py --slow` RFC 7748 vector 2 (whose u ends
    `0x93`, bit 255 set) PASSes on the in-tree build, 73/73.
    That same vector would catch the sibling bug the moment the
    sibling links, so **do not flip the sibling default at the v0.6.0
    pin** — bump to >= v0.7.0 first.

    Upstream is at v0.8.0. A bump is not a one-line submodule move:
    v0.8.0 renames `CODE`/`DATA` to `LIB_X25519_CODE`/`LIB_X25519_DATA`
    and adds `LIB_X25519_INIT_CODE`, all three of which the consumer
    cfgs must declare (`LIB_X25519_INIT_CODE` must be the last
    file-emitting segment before any bss-type segment in a file-backed
    area), and v0.7.0's #64 fix adds an `x25_x1` buffer that
    `build_x25519.sh`'s hand-written BSS stub does not yet export.
    v0.8.0 also ships an `X25519_ONCHIP_MUL` profile with no REU
    surface at all (`LIB_X25519_REU_BANKS_USED = 0`, no
    `reu_fetch_mul_row` export) — which would dissolve the
    `USE_NISTCURVES_ONCHIP` / `USE_X25519_SIBLING` mutual exclusion at
    `Makefile:90`, whose stated reason is that both archives export
    that symbol. Note that v0.8.0's headline
    `LIB_X25519_RESIDENT_BYTES` drop (9224 -> 8383) is **not** a
    shrink: 826 B of it simply moved to the reclaimable
    `LIB_X25519_COLD_BYTES`, and our wrapper stages only three of the
    sibling's sources anyway, so upstream manifest deltas do not
    subtract from the overflows above.

    `tools/integration/build_x25519.sh` is the integration wrapper. It
    does **not** call `make -C libs/x25519` — it stages three sibling
    sources, sed-rewrites `.segment "CODE"` to `CRYPTO_CODE`, and
    hand-emits the `X25519_RODATA` / `X25519_BSS` data modules. (An
    earlier revision of this file pointed at a
    `make -C libs/x25519 lib-x25519-scalarmult` target; no such target
    exists upstream at any tag. The real targets are `lib`,
    `lib-verify`, `lib-x25519-1764`, and — from v0.8.0 —
    `lib-x25519-onchip`.) Both the sed rewrite and the hand-written
    data modules are what a version bump has to be migrated through.
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
  - **P-384 build targets are still broken, but one link fewer.**
    The `ar65` staging failure (`nistcurves_p384_staging/curve/
    ecdsa384.o` never produced) was **ours, not upstream's**:
    `build_nistcurves_p384.sh` hardcoded the archive member name
    `ecdsa384.o`, while upstream renamed it to `ecdsa384_nocomb.o` in
    commit `64b313d` (c64-nist-curves issue #61), released in
    **v0.5.0** — i.e. before our own v0.6.0 pin, and unchanged by
    v0.7.0/v0.8.0. Upstream's `Makefile` builds every P-384 archive
    from `LIB_P384_VERIFY_OBJS = ... $(BUILD_DIR)/ecdsa384_nocomb.o`.
    Fixed 2026-08-13; both `nistcurves-p384-sha384.a` and
    `nistcurves-p384-curve.a` now build. The chain then hits the
    **next** blocker, which is exactly the one predicted here:
    `LIB_NISTCURVES_SHA384_TABLES` overflows `OVERLAY_REGION` by
    **1536 B** (`cfg/p384-overlay-sha384.cfg(29)`; the slot is
    $4200-$5FFF = 7,680 B). A third, independent defect blocks the
    embed variant: `make BACKEND=uci USE_OVERLAY_P384_EMBED=1` from
    clean dies with `No rule to make target 'build/labels.txt'` —
    the overlay rules take an order-only `| build/labels.txt` but
    that file is only a side effect of the main link, whose bootstrap
    rule is gated off under this flag. Also now dead: the wrapper's
    `ec_scalar_mul_384_shim` — `od65 --dump-imports` shows
    `ecdsa384_nocomb.o` imports `ec_scalar_mul_var_384`, not
    `ec_scalar_mul_384`, so the `ECDSA_NO_COMB` variant already does
    the variable-base fallback the shim was written to supply (it is
    never pulled, so it is harmless; retire it with the next P-384
    pass). No P-384 target has ever built cleanly end-to-end. Issues
    #32 and #45 were closed as stale; file fresh issues against this
    chain when P-384 enablement resumes. TLS-level P-384 verify
    remains stubbed regardless (see `project_p384_stubbed`).
    The v0.9.1 bump briefly moved this failure *earlier* — upstream
    #90's per-variant manifests renamed `lib_manifest.o` /
    `zp_config.o` to `lib_manifest_sha384.o` / `zp_config_p384verify.o`
    etc., which the wrapper's hardcoded archive list could not find.
    Both P-384 wrappers now **discover** those member names instead, so
    the chain again stops exactly at the SHA-384 `OVERLAY_REGION`
    overflow above — verified, same 1536 B, at the v0.9.1 pin.
  - **Sibling-archive member names are DISCOVERED, never hardcoded —
    and this is load-bearing.** Upstream v0.9.0 gave each of its nine
    archives its own per-variant `zp_config_*.o` /
    `lib_manifest_*.o` / `precalc_manifest_*.o`.
    `tools/integration/build_nistcurves_p256.sh` rebuilds the ZP object
    with c64-https's slot overrides (`zp_ptr2 = $3d`,
    `fp_mul_i = $39`, `fp_mul_j = $3a`) and then re-archives strictly by
    `ar65 t upstream.a`. Writing that rebuild to a hardcoded
    `zp_config.o`, as it did before the v0.9.1 bump, means the override
    object is **silently dropped** and the upstream-default member
    archived in its place — restoring `zp_ptr2 = $fd` (collides with
    c64-https `zp_temp`/`zp_count` during cert parsing) and
    `fp_mul_i/j = $2c/$2d` (inside the fe25519 claim `$2c-$37`). There
    is no link error for this; it is runtime memory corruption several
    layers from its cause. The wrappers now fail loudly on an absent,
    ambiguous or unrecognised member name, apply the matching upstream
    `-D` variant gate (it selects which slots get `.exportzp`), and
    **post-check the emitted object with `od65`** so the override is
    proven rather than assumed. Verify from the link if you ever doubt
    it: `build/labels.txt` must show `fp_mul_i=$39`, `fp_mul_j=$3A`,
    `zp_ptr2=$3D`.
  - **The v0.7.0/v0.8.0 UCI `CRYPTO_HOT` overflow is RESOLVED at
    v0.9.1 — and no cfg change was needed.** Recorded here because the
    obvious remedy was nearly taken and would have been the wrong
    trade. The failure was real: `LIB_NISTCURVES_P256_RODATA` overflowed
    `CRYPTO_HOT` by **207 B** at v0.7.0/v0.8.0, because CRYPTO_HOT sat
    *one byte* from full at the v0.6.0 pin (rodata `009E1F..009FFE`,
    region ends `$9FFF`) and v0.7.0's validation gate adds +208 B of
    **code**. 1 − 208 = −207. Exact.

    v0.9.0 then deleted 288 B of dead RFC 6979 self-test vectors from
    `curve256.o` (upstream #91) — an object our archive ships — and the
    rodata half of the pressure went away:

      segment                     v0.6.0        v0.9.1        delta
      LIB_..._P256_CODE           $1FB4 (8116)  $2084 (8324)  +208
      LIB_..._P256_RODATA         $01E0 (480)   $00C0 (192)   -288
      LIB_..._P256_BSS            $0520 (1312)  $0520 (1312)     0

      UCI CRYPTO_HOT last byte used: $9FFE -> $9FAE (**81 B free**)

    So the shelved remedy (routing `LIB_NISTCURVES_P256_RODATA` to
    `CRYPTO_OVERLAY`) was **not adopted**: `CRYPTO_OVERLAY` stays
    entirely free, the three mutually exclusive flags that contend for
    it keep exactly the contention they had, and
    `tools/uci/_memory_policy.py` sees an unchanged `$4200-$5FFF`.
    Both cfgs are byte-identical across this bump. Note the corollary
    for the next bump: **81 B is the whole margin**, and 288 B of it
    was a one-off recovery of dead weight that cannot be recovered
    twice.

    v0.9.0 is an ABI break upstream (`LIB_ABI_VERSION` 0 → 1, 17
    exports removed). Measured against our tree rather than assumed:
    dumping every export of the staged archive at both pins and every
    import of c64-https's own objects, **31** symbols left the archive
    (upstream's 17 plus 14 more that the new per-variant
    `zp_config_p256verify.o` / `precalc_manifest_p256verify.o` narrow
    away) and the intersection with what c64-https imports is
    **empty**. The whole library surface we consume is four symbols:
    `ec_base_x`, `ec_gx256`, `ec_scalar_mul_var`, `ecdsa_verify_256`.
    The removed ZP slots could not have bitten us either way —
    c64-https contains zero `.importzp` directives and defines every
    slot locally in `src/constants.inc` / `src/crypto/shared/zp_canon.inc`.
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

Under the then-current `libs/nistcurves@v0.3.0` pin (post-PR #55,
c64-lib-contract-aligned) the U64E 48 MHz
handshake measured **82.1 s**
end-to-end (verified 2026-05-20 against the local listener; the prior
v0.2.0 measurement was 86.7 s, and the pre-Phase-C.4 in-tree path was
~110 s).

**Every wall-clock figure below was measured at the v0.6.0 pin; the
pin is now v0.9.1 and none of them has been re-measured.** Treat them
as the v0.6.0 baseline, not as HEAD. The expected drift is small but
its sign is known: v0.7.0's public-key validation gate adds 2 `fp_cmp`
+ 3 mod-p muls + 4 mod-p add/subs to every verify, which is noise
against a multi-second scalar multiplication, and nothing else in
v0.7.0-v0.9.1 touches a hot path (the rest is manifest equates, dead
data removal and export hygiene). So expect a small *regression*, not
a speedup, and do not quote these rows as v0.9.1 numbers until someone
re-runs `bench_ecdsa_u64e.py` on hardware. The v0.3.0 row is kept only
as the REU-profile baseline.

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

  HTTPS e2e handshake wall-clock, local listener. **Device is a column,
  never a caption** — the REU-profile device delta is 10-13%, so a row
  whose device has to be inferred from a heading is not interpretable.
  64 MHz exists only on the C64U (the U64E's CPU Speed enum stops at 48):

  device profile             1 MHz     8 MHz    16 MHz   20 MHz   48 MHz  64 MHz
  C64U   v0.3.0 REU          --        --       --       --       73.0 s  64.7-65.9 s
  C64U   v0.5.0 onchip       --        --       --       --       59.9 s  47.5 s (n=3)
  C64U   v0.6.0 onchip       --        --       --       --       51.0 s  39.7 s
  C64U   v0.6.0 onchip+comb  --        --       --       --       38.4 s  **31.0 s**
  U64E   REU @ 2ceb5b1       1157.7 s  196.5 s  124.0 s  108.9 s  80.8 s  n/a (no enum)
  U64E   onchip @ 2ceb5b1    2120.7 s  264.5 s  131.8 s  103.9 s  45.5 s  n/a (no enum)

  The U64E rows are a 2026-08-13 sweep at master 2ceb5b1. One clean
  build per profile, reused across that profile's clocks, so clock is
  the only variable within a row. Every run PASSes with server-side
  evidence (the listener decrypted the full GET; no TLS error). Times
  are handshake + GET measured C64-side from `run_prg`, not
  whole-script wall-clock (which runs ~35-55% higher: boot, table init
  and turbo setup).

  The onchip 16 MHz entry is the median of two retries (132.4 / 131.2).
  Its first attempt died on `net_last_error = $88 UCI_ERR_NO_SOCKET` —
  the TCP_CONNECT bridge glitch, not a result. Note that failure
  occurred with the REU *enabled*, which is evidence against the
  REU-quiet-boot explanation for this device and in favour of the
  turbo-switch settle race.

  **Footnote — an inactive REU costs nothing.** The onchip rows above
  ran with the device's REU enabled but unused. Re-running that
  byte-identical PRG with `RAM Expansion Unit = Disabled`: 48 MHz
  44.9 s (-1.32%), 8 MHz 262.0 s (-0.95%), 1 MHz 2130.9 s (+0.48%).
  Sub-1.5% and not consistently signed, i.e. noise, not an effect.
  All three PASS with zero `NO_SOCKET` hits, so a REU-quiet boot did
  **not** drop the first TCP_CONNECT on the U64E — behaviour the C64U
  notes record as general. This is also the first confirmation of the
  shipped "no REU required" onchip claim on UCI hardware rather than
  in VICE.

  Fitting T(f) = D + C/f across all five clocks:

    U64E REU     D = 56.4 s   C = 1101 MHz*s   max|resid| 2.35%
    U64E onchip  D = -0.6 s   C = 2121 MHz*s   max|resid| 4.09%

  **The two profiles differ in floor, not just slope**, and that is the
  whole story of the crossover. REU carries a ~56 s floor that no clock
  touches, because `fp_mul`'s row fetches are anchored to the ~1 MHz
  bus; onchip has none, paying instead ~1.9x the clock-scaling work.
  The fits cross at **17.9 MHz** (17.6 from the three-point version),
  against the independently-derived verify-only figure of ~18 MHz.

  That crossover is **measured, not just fitted**: REU wins at 16 MHz
  by 5.9% and onchip wins at 20 MHz by 4.6%, so the sign flips inside
  [16, 20]. There is no 18 in the CPU Speed enum, so that interval is
  the finest bracket this hardware can produce.

  Read the onchip D as *indistinguishable from zero*, never as a
  quantity: the five-point fit returns -0.6 s, a physically impossible
  floor. At 48 MHz the C/f term is ~99% of the total, so D is fitted
  from rounding. This is the same ill-conditioning the turbo campaign
  hit with 2-point fits.

  Two cautions on reading these fits. The onchip D is **poorly
  conditioned** — at 48 MHz the C/f term is ~99% of the total, so D is
  fitted from what little is left; treat it as "under ~2 s", not as
  0.5 s. And an earlier revision of this section claimed the REU floor
  minus the 48.2 s verify floor localised "~10 s of clock-invariant
  non-verify cost". **That was wrong**: a genuinely clock-invariant
  cost would appear in the onchip floor too, and it does not (forcing
  D=10 on the onchip points throws the 8 MHz prediction off by 16%).
  The fixed network cost is instead ~0.6 s — 16 drain polls at ~40 ms,
  matching the onchip floor — and the REU floor is almost entirely DMA.

  Returns diminish steeply on the REU profile: 1->8 MHz (8x clock)
  bought 5.9x, 8->48 MHz (6x clock) bought only 2.4x. Extrapolating it
  to 64 MHz predicts 75.6 s, which is the quantitative case for the REU
  profile being wrong above the crossover — compare the C64U comb rows.

  A cross-validation worth keeping: the onchip fit built from only the
  8 and 48 MHz points predicted 1 MHz at 2104 s before that run
  happened; the measurement came in at 2120.7 s, +0.8% over a 48x
  extrapolation.

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
  ip65 + onchip @ 2ceb5b1  ~1.2x accelerated 1,876.0 s  (2026-08-13)

  Honest-1 MHz phase breakdown (seconds after 'G'):
  TCP CONNECTED 3.0 | CH 329.2 | SH 700.7 | PROC 718.9 |
  FIN 2,135.5 | REQUEST SENT 2,153.6 | CLOSED 2,159.7

  - The verify stretch measured **1,416.7 s** against the v0.6.0
    onchip fit's 1,397 s prediction (+1.4%) — the T(f)=D+C/f model
    holds at 1 MHz, three orders of magnitude from where it was fit.
  - X25519 scalarmults measured 326 s / ~356 s vs ~324 s analytical.
  - ip65's drain budget is **unchanged by #74** (the ip65 PRG is
    byte-identical across it), so those numbers stand at HEAD.
  - **Re-validated at master 2ceb5b1 on 2026-08-13**: PASS,
    `http_status=200`, `resp_len=22`, body match, 1,876.0 s
    accelerated (+3.4% vs the 1,813.9 s reference). Phase shape
    unchanged: TCP 3.0 | CH 276.0 | SH 585.4 | PROC 600.6 |
    FIN 1,823.0 | REQUEST SENT 1,838.2 | CLOSED 1,841.2. This matters
    beyond the number — the ip65 PRG is **no longer** byte-identical
    to the #71-era build (`417c708594...` vs `db31111031e2...`)
    because #75's span-input parser is real code, and until this run
    that change had only ever been exercised on the UCI backend. It
    was also ip65's first end-to-end run since July, so it is the
    first to cover #74, #75 and the ten audit PRs.
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

Not yet measured end-to-end, and still UNMEASURABLE: the `ar65`
staging failure is fixed, but the P-384 build now stops on the
SHA-384 overlay table overflow (and the embed variant on a separate
`build/labels.txt` ordering defect) — see "Known issues", so
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
    ip65 e2e run. c64-nist-curves#54 (verify-path BSS trim) is
    **CLOSED as COMPLETED (2026-07-16)**: the 261 B trim shipped in
    commit `7cb59f7` before upstream v0.4.0, so it has been inside our
    v0.6.0 pin all along and is not available as future headroom.
    `LIB_NISTCURVES_P256_BSS` measures $0520 (1,312 B) at v0.6.0 and
    is **unchanged through v0.9.1** (re-measured at the bump), so the
    union's cap is not threatened. The segment is genuinely
    uninitialised — `libs/nistcurves/src/data_p256.s` is 32 `.res`
    directives with no `.byte`/`.word` — which is what makes our
    `type = bss` declaration safe under c64-lib-contract §4, where a
    `rw`→`bss` flip would drop initialised bytes with no ld65
    diagnostic at all. Re-check that if `data_p256.s` ever grows a
    literal.
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

`make package` builds the release artifacts into `dist/` (gitignored).
**All four backend x profile combinations ship**, `make clean` between
every one:

  - `c64-https-uci-reu.prg`      `make BACKEND=uci`
  - `c64-https-uci-onchip.prg`   `+ USE_NISTCURVES_ONCHIP=1`
  - `c64-https-ip65-reu.prg`     `make BACKEND=ip65`
  - `c64-https-ip65-onchip.prg`  `+ USE_NISTCURVES_ONCHIP=1`

ip65 is now packaged (it was previously excluded on a link failure that
the #68 refit closed) — it is the only artifact that serves a stock C64
+ RR-Net cartridge, and `ip65-onchip` is the only image a bone-stock
machine with no REU can run at all.

The REU-vs-onchip guidance in `MANIFEST.txt` is the measured **~18 MHz**
crossover, not the older ~7 MHz figure: the REU profile carries a
wall-clock floor (DMA anchored to the ~1 MHz bus) that turbo cannot
touch, the onchip profile has none, and on a U64E the sign flips between
the 16 and 20 MHz CPU-speed settings. See the ECDSA wall-clock section.

Disk images:

  - `c64-https-<variant>.d64` x4 — one PRG each, `LOAD"*",8,1`
  - `c64-https-uci.d64`, `c64-https-ip65.d64` — both of that backend's
    profiles on one disk

There is deliberately **no all-in-one image**: the four PRGs total 868
blocks against a .d64's 664 free. Each backend's pair does fit (UCI 496,
ip65 372), which makes the per-backend disk the largest useful bundle.

`c64-https-listener.py` is a **single self-extracting Python file** (was
a zip + `run.sh` + venv + pip). It has **no third-party dependency at
all**: `cryptography` was only ever used to mint the self-signed P-256
cert, and `tools/package/listener/gen_certs.py` now does that in pure
Python (P-256 point arithmetic + minimal DER encoder + ECDSA-SHA256).
TLS was always stdlib `ssl`. What remains is a property of the
*interpreter*, not an installable package — an `ssl` with TLS 1.3
(OpenSSL 1.1.1+); macOS's `/usr/bin/python3` is LibreSSL 2.8.3 and
cannot serve this client at any price. That is detected at startup and
reported in one line (never a traceback, `--debug` restores it), and it
is stated in `MANIFEST.txt` rather than left to be discovered.
`--selftest` proves the whole path with no C64: mint cert, serve on
loopback, drive it with a Python `ssl` client, then again with `openssl
s_client -ciphersuites TLS_CHACHA20_POLY1305_SHA256` — the C64's only
suite, which the stdlib client can never force because CPython exposes
no API to restrict TLS 1.3 suites.

Scripts live in `tools/package/`: `_common.sh` (the variant matrix — one
line per shipped PRG, every other script derives from it),
`build_prgs.sh`, `build_d64.sh`, `build_listener.py`, `write_manifest.sh`.
Nothing is version-specific; re-running `make package` after a submodule
bump regenerates every artifact with zero edits.

`make package-verify` is the acceptance gate (`tools/package/
verify_release.py`): rebuilds every variant and compares **PRG** hashes
(object hashes are not evidence — ca65 stamps build time into every
`.o`), reads each PRG back out of its .d64 with `c1541` and
byte-compares, boots every image in VICE asserting the banner, and runs
the listener selftest. `SKIP_REBUILD` / `SKIP_VICE` / `SKIP_LISTENER`
narrow it.

Booting a .d64 in VICE needs `-trapdevice8 +drive8truedrive`: under true
drive emulation the ~250-block load never completes inside any sane
budget, and the symptom is a screen stuck on `LOADING` that looks like a
bad image rather than a slow one. `verify_release.py` passes both flags.

The comb profile stays deliberately excluded (REU bank 2 residency +
~40 min boot precompute at 1 MHz make it wrong for a general release).

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
  - `tools/test_finished_verify.py` — server-Finished **rejection** path
                                     (18 cases, 2 vector sets; see below)

All 7 pass as of the ca65-conversion branch (97/97 assertions).

### Negative-path coverage — the server Finished

`tools/test_finished_verify.py` and `tools/uci/test_https_bad_finished.py`
exist because an audit found the client's Finished-mismatch abort had **no
test at all**: inverting the mismatch branch (`sec` -> `clc` in
`tls_verify_finished`, `src/tls_keyschedule.s`) left the full hardware e2e
reaching HTTP 200 with the correct body. Every listener the suite talks to
sends a *correct* Finished, so nothing ever exercised the reject.

  - `tools/test_finished_verify.py` (VICE) drives `tls_verify_finished`
    directly over DMA with a 6502 carry-latching stub — no P-register read,
    and an unwritten latch is reported as inconclusive, never a pass. Two
    (secret, transcript) vector sets x 9 cases each, including the two
    realistic attacks: a valid HMAC under the wrong secret, and one over the
    wrong transcript.
  - `tools/uci/test_https_bad_finished.py` (U64E/C64U) is the end-to-end
    version, against `tools/https_e2e/evil_listener.py` — a hand-rolled TLS 1.3
    server (real X25519, real key schedule, real ChaCha20-Poly1305 records,
    real P-256 CertificateVerify) that flips **one bit** of the server
    Finished `verify_data` before encryption. Corrupting the *ciphertext*
    instead would break the Poly1305 tag and get rejected at `aead_decrypt`,
    never reaching the Finished comparison — which is why stock `ssl` cannot
    produce this test case and the server side is written out by hand.
    `FINISHED_MODE=good` runs the identical server with a correct Finished and
    is the mandatory control; `FINISHED_MODE=bad` (default) is the test.
    The oracle uses `tls_last_state`, which `src/tls13.s:@error` stashes on
    abort: `tls_state=$FF` + `tls_last_state=6 (FINISHED)` proves the abort
    happened at Finished rather than earlier at Certificate (4) or
    CertificateVerify (5). Server-side evidence (`client_accepted_finished`)
    is asserted too.

Both flip under the mutant: 18/18 -> 2/18 in VICE, PASS -> FAIL on the U64E.
Note `evil_listener.py` is a test fixture, not a TLS stack — it has no
hardening and belongs nowhere near production.

The `tools/uci/` scripts cover the UCI backend on U64E hardware (see
the "UCI test scripts" subsection above).

### Upstream pin drift — `tools/check_upstream_pins.py`

Reports, for every submodule in `.gitmodules`, which release the pin
corresponds to and what upstream has tagged since. Stdlib + `git`
only, one `git ls-remote --tags` per submodule, so it is fast and
schedulable.

    tools/check_upstream_pins.py                     # table
    tools/check_upstream_pins.py --json              # machine-readable
    tools/check_upstream_pins.py --strict            # exit 1 on drift
    tools/check_upstream_pins.py --submodule libs/x25519

**Do not read pins off `git submodule status`.** It renders versions
via `git describe` *without* `--tags`, which considers annotated tags
only, so a lightweight tag is invisible to it. c64-x25519 tagged
`v0.6.0` lightweight while `v0.5.0` and `v0.7.0` are annotated —
so `git submodule status` renders the exactly-on-`v0.6.0` pin as
`v0.5.0-5-g95fdd70`, which reads as "five commits past a release" and
has already been mistaken for a stale pin. `check_upstream_pins.py`
resolves `refs/tags/<name>^{}` when the peeled ref exists and the bare
ref otherwise, so both tag kinds behave identically. It also reads the
gitlink from `git ls-tree` rather than the working copy, so it is
correct for a submodule that was never `--init`'d.

### VICE ip65 rig (hardware-free e2e)

`tests/test_vice_https_macos.py` runs the **full HTTPS handshake + GET
over the ip65 backend with no hardware at all** — emulated RR-Net
(cs8900a) in VICE talking to a host-side TLS 1.3 listener. This is how
the REU-less stock-C64 numbers above were measured. Knobs:
`E2E_PROFILE=reu|onchip`, `E2E_NO_WARP=1` (honest 1 MHz timing),
`E2E_TIMEOUT`, `HTTPS_PORT` (the PRG's port is a build knob —
`make HTTPS_PORT=4433` — so the listener can run unprivileged).

Three prerequisites that are easy to lose:

  - **An ip65 PRG that builds at all.** This is the one backend that
    needs the ip65 blob, which is a gitignored artifact — on a fresh
    clone `make` fails at the blob link until `make ip65-libs` has run
    once. See "First build in a fresh clone" under Build.
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
