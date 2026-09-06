# c64-https — architecture notes

TLS 1.3 / HTTPS client for the Commodore 64, assembled with ca65/ld65 and
delivered as a single PRG. Networking via ip65/RR-Net (prebuilt blob at
$2000) or the Ultimate 64 UCI bridge. All crypto is hand-written 6502 (plus
the sibling `libs/nistcurves` P-256) tuned to fit under the BASIC ROM shadow
at $A000.

This file is the terse "how does this hang together" reference. **Keep it
terse.** The full measurement record — every sweep, failed hypothesis and
post-mortem — lives verbatim in `docs/engineering-notes.md` under the same
section names used here; cite that file rather than re-growing this one.
Rule of thumb: a fact that changes what you type belongs here; the story of
how it was learned belongs in the notes.

## Build

Dependencies: `ca65`/`ld65` (cc65), GNU make, VICE `x64sc` only for
`make run` / tests. The `c64-test-harness` Python package is a separate
repo (`pip install -e ../c64-test-harness`), not vendored.

Fresh clone (ip65 backend; UCI needs none of the ip65 steps):

    git submodule update --init --recursive
    make ip65-libs        # once per clone — plain `make` will NOT do this
    make                  # builds the ip65 blob on demand, then the PRG

  - `ip65-build/ip65-c64.bin` is a **gitignored artifact** (6,951 B,
    sha256 `cf1a5ff7…`, deterministic). Plain `make` builds it, but it
    cannot build the ip65 `.lib` archives — skip `make ip65-libs` and the
    link dies with `ld65: Input file '../ip65/ip65/ip65_tcp.lib' not found`.
  - **A nested git worktree needs `git submodule update --init --recursive`
    before it can link ip65** — a fresh worktree has no submodule working
    trees, so the link dies by name. It fails LOUDLY; that is the whole
    rule now. The old reason for this bullet is retired: `.incbin` no
    longer carries a CWD-relative path. `src/net/ip65/ip65_blob.s` is a
    bare `.incbin "ip65-c64.bin"` resolved through
    `--bin-include-dir $(abspath $(IP65_BUILD))` in the Makefile (#116), so
    a worktree three levels down assembles **its own** blob, not the parent
    checkout's. Re-proven 2026-08-31 in that exact geometry: flipping one
    byte of the worktree's blob moved the PRG hash, and restoring it moved
    it back.
  - To test blob provenance, **flip a byte** — never move the blob aside.
    `make` regenerates it deterministically, reproducing the baseline hash,
    which reads exactly like a live trap. That false positive has been hit.
  - **`libs/nistcurves` must be >= v0.11.2** (`CONTRACT_ZP_DEFINES`,
    knob-staleness guard). A stale checkout is caught in ~0.05 s by a
    source probe in `tools/integration/build_nistcurves_p256.sh` (#124);
    `tools/check_upstream_pins.py --worktree` reports checkout-vs-gitlink.

**A flag change no longer needs `make clean` (#159).** make tracks source
mtimes, not the command line, so this used to be a discipline you only had
to forget once. It is now an enforced invariant: `build/flags.stamp` holds
the fully expanded `CA65FLAGS`/`LD65FLAGS` (`LD65FLAGS` carries `$(CFG)`, so
`BACKEND=` and the profile cfg variants ride along), is content-compared
**at Makefile parse time**, and on any change deletes every `.o` and the
PRG. Absence, not an mtime — which is what macOS GNU Make 3.81's 1-second
resolution cannot defeat. Both silent failure modes the old rule guarded
against are closed, and `tools/test_build_flags_stamp.py` pins each against
a `make clean` oracle: the mixed link (`HTTPS_SNI=` invalidating `boot.o`
but not `http.o`, which cost a false negative on #141) and no link at all
(a same-second backend flip leaving the *other* backend's PRG in place at
exit 0). Because the stamp holds the expanded command lines rather than a
list of knob names, a new flag is covered the day it is added. The suite
also pins the inverse — an unchanged flag set must still rebuild nothing.

Parse time includes a dry run, so `make -n` used to delete the tree while
answering "what would this build?". **`-n`/`-q`/`-t` are now exempt
(#174)**: they still run the compare and `$(warning)` what a real build
would delete, but they write nothing — not the stamp, not the objects.
`-q` and the `make -npq` completion idiom matter as much as `-n`. The
guard has to find the single-letter options in `MAKEFLAGS`, and
`$(firstword ...)` is **not** where they are: a long option arrives as
its own `--word` and pushes the letters elsewhere, so
`make -n --no-print-directory` reads `[ --no-print-directory -n]` — last,
and dash-prefixed. Worse, `--no-print-directory` itself contains an `n`
and a `t`, so searching the first word calls a *real* build a dry run and
skips an invalidation it needed. The guard therefore takes every word
that is neither `--`-prefixed nor a `VAR=value` assignment and strips one
leading dash; the option matrix behind that is in the Makefile comment
and pinned by two tests. Real builds are byte-for-byte unchanged.

The target *strings* `HTTPS_HOST`/`HTTPS_PATH`/`HTTPS_SNI` keep their own
narrower stamp, the generated `build/https_host.inc` (#128): it invalidates
`boot.o` + `http.o` only, so retargeting stays cheap. Only the strings are
outside `flags.stamp`; a non-empty `HTTPS_SNI` still moves `CA65FLAGS` (it
adds `-D HTTPS_SNI_OVERRIDE=1`), so the override's presence is stamped even
though the name in it is not.

Still true, and still how you prove a build: `.o` hashes are never evidence
— ca65 stamps build time into every object; ld65 does not propagate it, so
the PRG is deterministic and **its sha256 is the check**. One consequence
of the stamp: `CA65FLAGS` carries two `$(abspath ...)` `.incbin` roots, so
moving a checkout forces exactly one rebuild.

Also: `$(PRG)`'s recipe `rm -f`s the target first, because ld65 writes
nothing on a memory-area overflow and every rig loads the PRG by path — an
absent PRG is the honest state after a failed link. Keep prose out of recipe
bodies; make echoes recipe comments and scripts grep build output for words
like "overflows".

Targets: `make` (PRG + `build/labels.txt` + `build/c64-https.dbg`),
`make clean` (removes `build/` only; the blob survives), `make run`,
`make ip65-libs`, `make ip65-blob` (force rebuild), `make package`,
`make package-verify`.

Variables:
  - `BACKEND=ip65|uci` — selects `cfg/c64-https-$(BACKEND).cfg`,
    `src/net/$(BACKEND)/`, and the `-I src/net/$(BACKEND)` include path
    that resolves `net_tuning.inc`. Default ip65.
  - `USE_NISTCURVES_ONCHIP=1` — libs/nistcurves FP_ONCHIP_MUL profile: no
    REU row-fetch DMA, wins above ~18-22 MHz. Keeps the **base**
    `cfg/c64-https-$(BACKEND).cfg` — it only adds a `-D` and swaps the
    archive. `$(error)`-guarded against `USE_X25519_SIBLING` and the
    overlay-embed flags.
  - `USE_NISTCURVES_ONCHIP_COMB=1` — implies ONCHIP; Lim-Lee comb + boot
    precompute into REU bank 2 (**needs an REU**; ~45 s boot at 48 MHz,
    ~36 min at 1 MHz — rigs need `C64_INIT_WAIT`). Fastest above ~5-7 MHz.
    This is the **only** flag that retargets `$(CFG)`, to
    `cfg/c64-https-$(BACKEND)-onchip.cfg` — which exists for uci only, so
    there is no ip65 comb build. Confirm from the `ld65 -C` line, not from
    the profile name.
  - `USE_X25519_SIBLING=1` — links under **neither** backend today (see
    Known issues). Off by default, ships in nothing.
  - `EMBED_P256_OVERLAY=1` — **retired, `$(error)`-guarded (#118)**: the
    P-256 verify image is 644 B larger than the 7,680 B slot at every pin
    since v0.7.0, and `CRYPTO_OVERLAY` now holds ~5 KB of resident
    deframer/`cert_buf`/name-check code that the swap would DMA over. The
    plumbing (`p256_overlay_blobs.s`, `crypto_swap_to_p256_verify`,
    `cfg/p256-overlay-verify.cfg`, `make p256-overlay`) stays in tree.
  - `USE_OVERLAY_P384_EMBED=1` — broken: from a clean tree the overlay
    `.bin` rules order-only depend on `build/labels.txt`, which only the
    (gated-off) main link produces; past that, the SHA-384 tables overflow
    the slot by 1,536 B.
  - `ENABLE_P384_VERIFY=1` — re-arms the P-384 verify arm. **Unsafe on its
    own** (overwrites live code — see Crypto ABI); exists so
    `tools/test_p384_overlay_hazard.py` can be mutation-tested.
  - `HTTPS_HOST` / `HTTPS_PATH` / `HTTPS_SNI` / `HTTPS_PORT` /
    `HTTPS_BODY_TO_REU=1` — build-time target. Hosts >63 chars are a build
    error. The strings live in their own `HTTPS_TARGET_RODATA` segment
    (#126): `CRYPTO_OVERLAY` under UCI, `NET_CODE` tail (186 B, a joint
    budget) under ip65 — a longer target used to overflow an unrelated
    library segment in `CRYPTO_HOT`. Do not read ld65's `NET_BSS … EMPTY`
    as headroom; that span is the ip65 blob's own BSS.
  - `TLS_STREAM_DEFRAME` — streaming handshake deframer; ON under uci, OFF
    (compiled out) under ip65.
  - `VIC_BLANK=0` — degrade `vic_blank`/`vic_unblank` to `RTS` (A/B control).
  - `X509_VERIFY_NAME` — set automatically under uci only (see Memory layout).
  - `CA65`, `LD65`, `VICE` — toolchain overrides.

Test harness expectations:
  - Most `tools/test_*.py` run `make clean && make` themselves;
    `C64_SKIP_BUILD=1` reuses the built PRG (list them with
    `grep -ln 'environ.*C64_SKIP_BUILD' tools/test_*.py tests/rig_*.py`).
  - Launch VICE only through `c64-test-harness`; never run `x64sc` directly.
  - Any test touching the sibling P-256 path **must** launch VICE with
    `-reu -reusize 512` — see "VICE harness gotcha" under Known issues.

## Crypto ABI

`src/crypto_abi.inc` fronts the public crypto API; TLS/HTTP consume crypto
only through it, so swapping an implementation is a link-line change.
Conventions: AX = pointer lo/hi, caller-provided buffers, keys/IVs via
fixed buffers in crypto BSS.

  X25519 / fe25519      in-tree `src/crypto/{x25519,fe25519}.s` (default);
                        sibling `libs/x25519@v0.11.2` opt-in, same ABI:
                        `x25519_scalarmult`, `fe25519_mul/sqr/inv`
  ChaCha20-Poly1305     in-tree, permanent: `chacha20_encrypt`,
                        `poly1305_init/update/final`, `aead_encrypt/decrypt`
  SHA-256               in-tree: `sha256_init/update/final`
  ECDSA P-256           sibling `libs/nistcurves@v0.11.2`:
                        `ecdsa_verify_256`, `ec_scalar_mul_var` (plus the
                        `ec_base_x`, `ec_gx256` data — that is the whole
                        surface we import). Dispatcher:
                        `src/crypto/ecdsa_verify.s`. Archive built by
                        `tools/integration/build_nistcurves_p256.sh`.

  - The sibling validates the public key at entry from v0.7.0 (FIPS 186-5
    range + on-curve check); c64-https does none of its own, and `Q` comes
    straight from the attacker-supplied certificate, so `ecdsa_verify.s`
    carries `.assert LIB_NISTCURVES_VERSION_MINOR >= 9`.
  - Zero page: fe25519 `$2C-$37`, x25519 `$38-$3A`, ECDSA bignum `$22-$3C`,
    time-shared; sibling slots `fp_mul_i=$39`, `fp_mul_j=$3A`,
    `nistcurves_zp_ptr2=$3D` (verify in `build/labels.txt`). All defined
    locally (`src/constants.inc`, `src/crypto/shared/zp_canon.inc`); no
    `.importzp` anywhere.
  - c64-lib-contract is a **prose dependency, not a submodule** — nothing
    in `make` reads it, so a contract release can never break a build.
    Always cite a **tag** (newest: v1.1.0). v1.0.0 cut the SPEC by 7/8 and
    retired §9, §12, §13, §14, §15, §6.3, §6.6, §6.7: those resolve only
    at **v0.17.1**, in a c64-lib-contract checkout (it is not a submodule
    here); survivors keep their numbers against the current SPEC. Note
    §6.1/§6.2/§6.4/§6.5 survive while §6.3/§6.6/§6.7 do not — §6 is split.
    §8.0 APP_OWNED shape is requested
    via `CONTRACT_DEFINES` — no archive member is edited (§6.1) — and the
    manifest attests it, so the asserts in `src/lib_contract_asserts.s`
    are live. §13 (network ABI) **is** adopted (#70, merged #142); see
    Networking backend ABI for what its retirement did and did not change.

**P-384 is PARKED, and deliberately gated.** The wire path used to be fully
live while the overlay image was a stub: a P-384 certificate made
`crypto_swap_to_p384_sha384` DMA `$1E00` bytes of nothing over resident
code and hung the machine (measured on v0.4.0 images). Closed by two
independent changes: the ClientHello no longer advertises `0x0503`, **and**
`ecdsa_verify`'s P-384 arm is a `sec` reject unless `ENABLE_P384_VERIFY=1`.
The curve comes from the certificate, so the gate is what makes the
advertisement change safe. No P-384 build target has ever completed (see
Known issues); fix the build before re-wiring.

Sibling-library memory requirements: code + rodata in `CRYPTO_HOT` /
`CRYPTO_RESIDENT` ($6000-$9FFF), never crossing $A000 (boot zeroes
$A000-$BFFF); big BSS in `CRYPTO_COLD_SHADOW`; segments named per contract
§4 (`LIB_NISTCURVES_P256_CODE` etc.). REU Profile B baseline; comb claims
bank 2; banks 6-7 reserved for the P-384 overlay experiment.

## Networking backend ABI

Switching backend = a different cfg + different `src/net/<backend>/*.o`.

**`src/net_abi.inc` is the build-enforced boundary** (c64-lib-contract
SPEC §13, issue #70). **§13 was retired at contract v1.0.0; every §13.x
number in this section resolves at tag `v0.17.1`, nowhere else.** No §13
assert has a contract-derived counterparty, so no contract release can
break a build — but the error codes below are asserted NOWHERE, and that
is the live hazard (see the allocation note). `src/net_abi.inc` is the
normative source now. `boot.s`, `http.s`, `tls_record_io.s` and `tls13.s`
`.include` it and import no `net_*` symbol directly, so a backend that
drops a symbol fails the link by name on both backends. Surface:

  core   net_init, net_dhcp_acquire, net_poll, net_local_ip (4 B),
         net_last_error (1 B)
  TCP    net_tcp_connect (A/X = port), net_tcp_send (+ net_send_len),
         net_tcp_close, net_tcp_state (NET_TCP_* in src/net/net_states.inc),
         consumer-owned rx ring tcp_recv_{buf,head,tail,overflow} (§13.3)
  DNS    net_dns_resolve, net_resolved_ip ($FF x4 = resolved by the device)
  ours   net_recv_byte (the drain entry, #72), net_banner_str

  - `src/net/<backend>/net_manifest.s` exports `NET_BACKEND_FAMILIES`
    (CORE|TCP|DNS on both; UCI's DNS is by deferral); ip65's also carries
    the §13.7 blob footprint, link-asserted against the `.incbin`'d size.
    `src/net_abi_asserts.s` (§13.8) asserts the families and the ring
    mask. The `NET_FAMILY_*` bits are `src/net/net_families.inc`, copied
    verbatim from the contract and never exported.
  - Error codes: ip65 `$40-$7F` (`ip65_errors.inc`, `NET_ERR_IP65_*`),
    UCI `$80-$BF` (`uci_errors.inc`, `UCI_ERR_*`). The UCI range is ONE
    namespace shared with c64-wireguard — `$8A UCI_ERR_LONG_READ` is theirs
    and datagram-only. **`$FFFF` is the SOCKET_READ no-data sentinel on both
    transports** (idle polls answer it) and must be excluded before any
    over-claim test — both fleet adapters misfiled it independently (#140).
    `net_poll` caps the copy at the request and never emits `$8A`; a header
    above the request that is NOT `$FFFF` leaves `$8B UCI_ERR_BAD_READ_HDR`
    (C=0, stream continues) — the stream-family counterpart of `$8A`.
    **SPEC §13.2's allocation table moved, it did not vanish**: allocate a
    new code in `c64-wireguard/src/net_abi.inc`, which declares itself
    canonical for both ranges, then here. It owns `$8C-$8F` and `$46-$49`,
    which our two error headers used to present as free (#184).
  - Gone, per §13.1: `net_tcp_set_recv_cb` (stub), `net_recv_ready`,
    `net_dhcp` (alias), and `net_print_ip` — IP printing is consumer UI and
    is now `print_local_ip` in `boot.s`, one copy for both backends.
  - Byte accounting on ip65 (the tight one): LOADER went from 16 B free to
    58 B; `print_local_ip` rides LOADER_OVERFLOW, so the NET_CODE tail that
    is `HTTPS_HOST`/`HTTPS_PATH`'s ip65 budget shrank from 170 to ~60 B
    beyond the default strings (wikipedia's +46 B still builds on both ip65
    profiles; the theoretical 165 B host+path maximum no longer does).

  - `src/net/ip65/` — ip65/RR-Net (cs8900a). Blob loaded at $2000 via
    `.incbin`; `net.s` is the adapter; `ip65_symbols.inc` is the single
    source of jump-table equates.
  - `src/net/uci/` — Ultimate 64 Elite / C64 Ultimate UCI bridge.

## UCI backend

Registers `$DF1B-$DF1F`, ID byte `$C9` (`src/net/uci/uci_regs.inc`).
`uci_cmd.s` holds the shared primitives (no zero page — absolute + SMC).
Error codes in `uci_errors.inc`; the load-bearing ones are
`UCI_ERR_NO_SOCKET` (`$88`, OPEN_TCP short-read: firmware never opened the
socket — issue #36) and `UCI_ERR_WAIT_TIMEOUT` (5 s wall-clock bound, #37).
DNS is done by firmware inside TCP_CONNECT; the adapter only copies the
hostname to `uci_host_buf`.

**Every spin-wait is wall-clock bounded** (5 s via CIA1 TOD) and every
caller `bcs` out — see "Design note — bounded timeouts" below. Never add an
iteration-counted wait. The bound is only real because `net_init` calls
`uci_tod_start` first: the CIA's TOD is **halted out of reset** and nothing
in the KERNAL starts it, so until #145 every one of these waits was
unbounded on hardware. VICE runs the TOD from reset, so no emulator test
can catch a regression here — the guard is `tools/uci/boot_check.py`.

### Firmware quirk — FPGA register timing (delay-loop fence)

The UCI FPGA needs a minimum gap between register accesses regardless of
CPU clock. `uci_fence` (`uci_regs.inc`, OUTER=5, INNER=217, ~85 us at
64 MHz) follows every access to `$DF1C-$DF1F`. INNER=217 covers both the
U64E (~38 us floor) and the C64 Ultimate (floor bracketed 51.6 FAIL /
62.9 PASS us at 64 MHz; the symptom below the floor is a silently lost
TCP_CONNECT push → `NO_SOCKET`). 48 MHz (U64E) and 64 MHz (C64U) verified.

### C64 Ultimate notes

Second device: C64 Ultimate "Starlight", `U64_HOST=10.53.21.158`, fw 1.1.0,
64 MHz enum, WiFi. Handled differences:
  - **Set turbo BEFORE reset/run_prg** and settle ~3 s; a runtime speed
    switch (even a redundant config write) loses the next UCI command.
  - Boot must issue some REU DMA or the first TCP_CONNECT is dropped —
    `boot.s` keeps `reu_mul_init` under both profiles.
  - Multiple interfaces: `net_dhcp_acquire` probes iface 0..3.
  - REU ships disabled and there is no `"REU"` cartridge preset — set
    `RAM Expansion Unit: Enabled` directly (runtime-only).

### UCI rig scripts

`tools/uci/` (README there). Need a device (`U64_HOST`, default
192.168.1.81), `c64-test-harness`, and go through `DeviceLock` +
`enable_uci`. Named `rig_*.py`, not `test_*.py`, on purpose (#109/#111).
Scratch DMA addresses come from `build_policy_and_arbiter()`
(`_memory_policy.py`, parses `build/labels.txt`) — never hardcode them.

  boot_check.py / phase2_check.py / phase3_tcp_echo.py — boot, DHCP, TCP
  rig_http_local.py / rig_http_live.py      — plaintext HTTP
  rig_https_local.py                        — HTTPS vs local TLS 1.3 listener
                                              (DMA'd `http_get` trampoline;
                                              `TURBO_MHZ`, `EXTERNAL_LISTENER=1`,
                                              `DEBUG_CAPTURE`, artifacts under
                                              `$UCI_DEBUG_DIR`)
  rig_https_print_body.py / rig_https_local_p384.py — wrappers (P-384 has no PRG)
  rig_https_live.py / rig_https_wiki.py      — real servers (github, wikipedia)
  rig_https_banner.py                       — the ONLY rig that executes
                                              `do_https_get` (walks the menu,
                                              reads $0400) — every other HTTPS
                                              rig enters via the trampoline
  rig_https_bad_finished.py                 — forged server Finished must abort
                                              (`FINISHED_MODE=good` control first)
  bench_ecdsa_u64e.py                       — verify wall-clock sweeps

Traps: `decode_screen()` returns **lowercase** rows (only `screen_text()`
uppercases); at 48 MHz the handshake scrolls the screen, so read it
immediately. Crypto-path rigs call `preflight_reu()` (#97): a REU-profile
build on a REU-disabled device exits 4 in ~2 s instead of spinning ~44 min;
it never writes device config. `C64_SKIP_REU_PREFLIGHT=1` bypasses.
**It fails closed (#179)**: a REU setting that cannot be read — a raise, an
unrecognised shape, an empty value — exits 4 too, not a warning.
`c64-test-harness` is an **editable** install from a sibling working tree,
so their merges are our regressions; audit every `get_config_*` call
against their tree, not against memory. Pinned by
`tools/test_reu_preflight.py` (faked client, no hardware). Story in
engineering-notes.

### Device gotchas (read before diagnosing a "wedge")

  - **The `…KEYS ENC1 RX` screen is not diagnostic.** Two causes look
    identical: a real device wedge (`net_last_error=$86`, power cycle at the
    wall) and a REU-profile build with no REU (`net_last_error=$00` — the
    row-fetch DMA no-ops, the X25519 secret is wrong, the first AEAD tag
    fails, and it *spins* for ~44 min). Check `net_last_error`; the REU half
    is now excluded by the preflight above. `$86` is not by itself a wedge —
    it has been seen on PASSING runs (github.com HTTP 200, 2026-08-28) — but
    it is never noise either: the `$DF1C` bit 3 it reports has exactly one
    setter in the FPGA (`command_protocol.vhd`, the `PUSH_CMD`-while-not-idle
    branch), so it always means *our* push was rejected, and a passing run
    that carries one recovered from a real rejected push. A normal
    end-of-fetch cannot set it: the firmware closes on `lwip_recvmsg` == 0 and
    reports `01,CONNECTION CLOSED BY HOST` on the `$DF1F` status channel,
    which touches no status bit.
  - **Lease poisoning**: resetting the C64 with a live firmware socket makes
    `GET_IPADDR` return 0.0.0.0 forever ("REQUESTING DHCP" loop). Only a
    wall power cycle clears it. Rigs therefore let fetches finish and send
    'Q'. Probe DHCP with a fast-boot (onchip) image, never comb.
  - **writemem exhaustion wedge** (fw 3.14d, GideonZ/1541ultimate#686):
    each REST `writemem` leaks a `/Temp` file; after ~15 loads REST and the
    UCI bridge wedge together. `tools/uci/_temp_gc.py` FTP-deletes them;
    wired into the live/wiki rigs.
  - The U64E is a shared device: trust `DeviceLock`, never kill other
    sessions' processes or force-reboot it.

## End-to-end HTTPS status

**Real servers work** (2026-08-21/22, U64E @ 48 MHz, comb): github.com,
browserleaks.com, lwn.net all HTTP 200 (~32-39 s to Finished), and
en.wikipedia.org's C64 article — 125,235 B, chunked, into REU `$10:0000`
via `HTTPS_BODY_TO_REU=1`, byte-verified, shown by `src/viewer.s`. The
local-listener handshake works on both backends (UCI at 48 MHz and 1 MHz;
ip65 in VICE at honest 1 MHz, ~36 min).

Pieces that made real servers possible, each of which the local listener
never exercised:
  - W1 streaming deframer (`src/tls_deframe.s`) for 11-14 record flights;
    W2 streaming Certificate consumer into a 2048 B `cert_buf` (UCI).
  - 512-content records hit a page-dispatch bug in `src/tls_record.s`
    (every local fixture was one byte short of the trigger).
  - Bodies past the 512 B `http_resp_buf` terminate on a 24-bit consumed
    count (`http_body_total`), with `Content-Length` and chunked support.
  - **The wikipedia stall was ours** (commit d9cd021): `net_poll` asked for
    512 B per SOCKET_READ and dropped bytes past the ring's free space —
    a permanent hole on any flight over 4 KB. Now clamped to
    `min(ring_free-1, 512)`. Not a firmware bug.
  - Post-ServerHello drain (see design note) so impatient peers do not RST
    during the multi-minute crypto stall.
  - Cloudflare is out of scope: ignores MFL and enforces a ~15 s deadline.

Handshake flow, both backends: CH → SH (X25519) → EE, Certificate,
CertificateVerify (P-256 via sibling) → server Finished verified → client
Finished → traffic keys, seq counters reset (§5.3) → GET → response.
Single suite: `TLS_CHACHA20_POLY1305_SHA256`, so the transcript hash is
always SHA-256. The eleven bugs fixed getting here are listed in
engineering-notes ("Summary of recent fixes").

That arrow order is **enforced, not assumed** (#152). Both dispatchers
expand `TLS_HS_SEQ_CHECK` from `src/tls_hs_seq.inc` — the UCI streaming arm
at `@hdr_complete` in `src/tls_deframe.s` and the ip65 arm in `src/tls13.s`
— so they cannot diverge; the macro derives the one legal message type from
`tls_state` (no parallel "expected" byte to drift), and rejects before the
transcript fold. The deframer error codes are `DF_ERR_*` at the top of
`src/tls_deframe.s`, reported in `df_last_err`; the sequence rejection is
**`DF_ERR_SEQ = $07`**. A CertificateRequest is the only RFC 8446-legal
message the gate turns away (this client cannot answer one, so it was
already refused a step later, as `DF_ERR_TYPE = $04`). Test:
`tools/test_hs_sequence.py`.

## Known issues

  - **`USE_X25519_SIBLING=1` links under neither backend.** ip65:
    `X25519_RODATA` overflows `CRYPTO_OVERLAY` by 3,584 B (structural —
    4,212 B slot). UCI: by 1,280 B since `CERT_BUF_BSS` moved into
    `CRYPTO_OVERLAY` for wikipedia (accepted casualty). The earlier
    `Duplicate external identifier: 'reu_mul_tables_init'` collision is
    handled by **deferral through `CONTRACT_DEFINES`** (`-D
    SHARED_REU_MUL_INIT -D SHARED_REU_MUL_FETCH`), not by dropping
    `reu_mul_init.o` — the wrapper does no member surgery at all any more
    (§6.1), it `cp`s the upstream archive. `reu_mul` is APP_OWNED here.
    Flag stays off; the in-tree X25519 is correct (RFC 7748
    vector 2 passes) and ships.
  - **P-384 build is broken**, one link deeper than before: the `ar65`
    member-name bug was ours (fixed), and the chain now stops at
    `LIB_NISTCURVES_SHA384_TABLES` overflowing `OVERLAY_REGION` by 1,536 B
    (`cfg/p384-overlay-sha384.cfg`); the embed variant dies on the
    `build/labels.txt` ordering defect. `ec_scalar_mul_384_shim` is
    unreferenced by any shipped PRG, but it is the only provider of
    `ec_scalar_mul_384` in the P-384 curve archive (upstream's
    `lib-p384-verify` excludes `points384_comb.s`) — retire it with the
    P-384 lane, not separately. Issues #32/#45 closed stale; file fresh
    ones.
  - **Sibling archive member names are discovered, never hardcoded.**
    Upstream v0.9.0 made them per-variant; a hardcoded `zp_config.o` means
    the ZP-override object is silently dropped and `zp_ptr2` reverts to
    `$fd` (collides with `zp_temp`/`zp_count`) — runtime corruption, no
    link error. The wrappers `od65`-check the emitted object; confirm in
    `build/labels.txt` if in doubt. The canonical slot name is
    `nistcurves_zp_ptr2` (v0.10.0).
  - **`poly_prod_lo/hi` is a rendezvous, and c64-https owns it** (§8.3:
    whoever provides `ct_mul_8x8` owns its product scratch). If both sides
    define the pair the link *succeeds* with two disjoint pairs and every
    on-chip multiply row is wrong. Guarded behaviourally only: run
    `tools/test_ecdsa_kat_oracle.py` against an **onchip or comb** PRG
    after any change here (REU builds pass regardless).
  - **VICE harness gotcha**: anything touching sibling P-256 primitives
    must launch VICE with `-reu -reusize 512`, or `fp_mul` returns
    `a*255*b` and verify fails with no diagnostic. Use
    `tools/_vice_helpers.py::default_vice_config()` (eight suites do;
    `tools/run_all_tests.py` and ~15 others still spell the flags by hand).
    `C64_VICE_NO_REU=1` is the deliberate opt-out for proving the onchip
    image's no-REU claim — never set it on a REU-profile build.
  - **CRYPTO_OVERLAY vs rig scratch**: new resident tenants in
    `$4200-$5FFF` shrink what the rigs' `MemoryArbiter` can hand out
    (server-name validation took the comb tail from 714 to 223 B and broke
    `rig_https_wiki.py`, which now drives the menu instead). The harness
    write guard raises `MemoryPolicyError` before the wire.
  - `CRYPTO_HOT` margin under UCI is **81 B** at v0.9.1+ and was one byte at
    v0.6.0; 288 B of that was a one-off dead-data recovery upstream. Watch
    it on every pin bump.
  - `http_recv_response`: `Content-Length` (single-SP matcher, 16-bit
    sentinel `$FFFF`) and chunked (`http_state_body_chunked`,
    `HTTP_AUX_CODE`; chunks >64 KB desync) supported; body rendered via
    `ascii_chrout` (case folded, #28); `http_resp_buf` keeps raw ASCII.
  - `net_tcp_set_recv_cb` is an RTS stub. Boot banner: `rr-net` under ip65,
    `UCI NETWORKING` under UCI — `boot_check.py` asserts both.

### VIC-II blanking — worth 6.3%, not the fleet's "20-25%"

`src/vic.s` `vic_blank`/`vic_unblank` wrap the two X25519 scalar mults, the
`ecdsa_verify` dispatch, and (comb only) the `ec_precompute_256` boot pass
— nothing else, so the CH/SH/HK1/KEYS/ENC1/RX progress markers stay visible
(they are the field diagnostic). The dispatch arms are `jsr` + `php`/`plp`
so the verify carry survives the unblank; the precompute needs no such
guard (no return value). The precompute is the one blank long enough to
look like a hang, so `boot.s` recolours the border ($D020 = $0B dark grey,
restored to the $0E constant) across it: with DEN clear the whole display
is border colour, so that — not the banner it prints first — is the
persistent "working" signal. Both writes are at the call site, not in
`vic.s`, so the mid-handshake blanks keep the markers untouched, and they
run under `VIC_BLANK=0` too, which keeps that A/B control clean.

Measured: 6.35% (VICE, 1 MHz), 6.60% (U64E 48 MHz, REU profile), 6.78%
(U64E 48 MHz, onchip, n=3), vs 6.31% from first principles (25 badlines ×
~43 cyc / 17,045-cyc NTSC frame). **Badline DMA taxes the bus, not the
CPU**: the fraction is flat across clock and profile — turbo does not
shrink it and the REU DMA floor does not dilute it. The sibling repos'
"20-25%" is a sprite-DMA figure and is wrong ~3.5x for text mode. Full
sweep tables in engineering-notes.

### ECDSA P-256 verify wall-clock

Model: `T(f) = D + C/f`. The REU profile has a ~42-56 s floor (row-fetch
DMA anchored to the ~1 MHz bus, ~16 KB per `fp_mul`); onchip has none but
~1.9x the CPU work; comb halves the CPU work again but needs REU bank 2
and a boot precompute. **Read the pin, not the commit** — almost every
figure was taken at `libs/nistcurves` v0.6.0; the pin is v0.11.2 and the
only re-measured points are 48 MHz UCI REU (80.8 → 82.1 → 82.4 s, n=1; the
+1.6% is v0.7.0's public-key validation, worth paying) and comb.

  verify only (RFC 6979 vector)     16 MHz   48 MHz   64 MHz   crossover vs REU
  REU (U64E)                         81.6     59.2     n/a      —
  onchip (U64E)                      87.6     30.5     n/a      ~18 MHz (C64U ~22)
  comb, current pin, blanked (U64E)  47.0     16.4    ~12.8*    ~5 MHz (C64U ~7)
  * extrapolated; C64U comb @64 measured 12.4 s at v0.6.0

  handshake + GET, local listener   1 MHz    48 MHz   64 MHz
  U64E REU                          1157.7   80.8     n/a
  U64E onchip                       2120.7   45.5     n/a
  C64U onchip (post-#74)            —        44.6     33.7
  C64U comb (v0.6.0)                —        38.4     31.0

  ip65 + onchip, no REU, VICE honest 1 MHz: **2,159.7 s (36.0 min)**,
  verify stretch 1,416.7 s (+1.4% vs the model), X25519 ~326 s each.

Best verify today: **16.4 s @ 48 MHz on the U64E (comb)**, 1.73x faster
than onchip at that clock. The U64E's REU DMA is 10-13% slower than the
C64U's; the CPU path is at parity. `tools/uci/bench_ecdsa_u64e.py` is the
protocol; n=1 rows bracket, n>=3 rows measure; 2-point fits are
ill-conditioned. A "+12% comb gap" between devices recorded earlier closed
on re-measurement — do not attach mechanisms to deltas without checking
magnitude first.

### ECDSA P-384 verify wall-clock

Unmeasured and unmeasurable until the P-384 build is fixed. **Every figure
here is an extrapolation, not a measurement** — treat it as a rig budget, not
a result.

Scale the **onchip** P-256 verify, not the REU one: the REU profile's
42-56 s floor is row-fetch DMA anchored to the ~1 MHz bus and does not grow
with field width, so multiplying it mis-shapes the estimate. Onchip is
CPU-bound and structurally the same code path — `ec_scalar_mul_384_shim`
runs the variable-base ladder for u1*G exactly as the no-comb P-256
`ec_scalar_mul` shim does. From operation counts: 48-byte vs 32-byte limbs
make each schoolbook `fp_mul` ~(48/32)^2 = 2.25x, and a 384-bit scalar is
1.5x the ladder steps, so ~3-4x the onchip P-256 verify — **~1.5-2.5 min at
48 MHz** against the 30.5 s onchip row above. SHA-384 is excluded as
negligible beside two variable-base scalar mults. `rig_https_local_p384.py`
keeps its 90-minute budget (it also has to cover 1 MHz).

### Design note — bounded timeouts must use wall-clock time

Fences make per-iteration cost scale with CPU clock while the FPGA does
not, so an iteration budget ample at 1 MHz collapses at 48 MHz (branch
`feat/net-drain-abi` broke DHCP exactly this way). `uci_wait_idle` is the
template: sample CIA1 TOD (HOUR $DC0B latch → TENTHS $DC08 unlatch), bail
after 50 tenths transitions with C=1 + `UCI_ERR_WAIT_TIMEOUT`, state in
two SMC bytes. `uci_wait_not_busy`, `uci_drain_resp`, `uci_drain_status`
and `uci_push_wait` all follow it; all 22+ call sites `bcs` out.

A wall-clock bound needs a wall clock that is *running*: `uci_tod_start`
(#145). Measured on the U64E at 48 MHz once it does — TOD/wall rate 0.996
(the "5 s" budget is 5.02 s, and turbo does not shrink it, which is the
whole point), and the longest bounded wait observed across four full
github.com handshakes is **one tenth**. The budget is ~50x the worst real
wait, but a `$89` has been seen in the field on a passing run, so it is
reachable; re-measure before tightening it.

### Design note — the post-ServerHello drain, and why its budget is per-backend

`tls13.s` drains the network after ServerHello because ip65 sends no MSS
option and ACKs only when polled: without it the flight tail sits unACKed
through minutes of crypto and impatient peers (macOS: ~54 s) RST, which
surfaces minutes later as client Finished into a dead socket
(`tls_state=$FF`, `tls_read_seq=4`). Budget lives in
`src/net/<backend>/net_tuning.inc` (`NET_SH_DRAIN_OUTER/INNER`): ip65
8×250 (validated; do not shrink without the VICE e2e), UCI 1×16 — a UCI
`net_poll` is a full firmware round-trip costing **~40 ms** regardless of
clock, and #71's unconditional 2000 polls cost UCI 80 s (#73/#74). Keep
INNER non-zero (0 means 256). Open: polling *inside* long crypto for
flights larger than the TCP window, and an idle-based bound.

## Memory layout

UCI (`cfg/c64-https-uci.cfg`, W1 hot/cold split — the reference):

  $0801-$1FFF  LOADER              BASIC stub + boot + HTTP + net wrapper
  $2000-$3B65  NET_CODE            UCI adapter + LOADER_OVERFLOW + TLS_CODE
                                   + CRYPTO_AUX_CODE
  $3B66-$41FF  NET_BSS_TAIL        NET_BSS_TAIL segment (deframer/viewer BSS)
                                   + LIB_NISTCURVES_P256_BSS. NOT `BSS_TAIL`
                                   and NOT `UCI_BSS` — both are elsewhere
                                   (below, and CRYPTO_HOT). Read the map.
  $4200-$5FFF  CRYPTO_OVERLAY      7.5 KB. Resident tenants in every UCI
                                   build: TLS_DEFRAME_CODE (~1.4 KB),
                                   CERT_BUF_BSS (2,048 B), HTTPS_TARGET_RODATA,
                                   x509_name; comb adds RODATA/LIMLEE_BSS
                                   (~223 B tail free). Also the slot for the
                                   (broken) overlay-embed flags.
  $6000-$9FFF  CRYPTO_HOT          resident code + rodata + small BSS
  $A000-$BFFF  CRYPTO_COLD_SHADOW  large BSS (RAM under BASIC ROM, $01=$36);
                                   BSS_TAIL packs first, so `tls_rec_buf`
                                   (548 B) sits at $A000; TABLES_BSS pinned
                                   at $BA00 so sqtab lands at $BC00
                                   (LIB_SHARED_SQTAB_BASE, asserted
                                   post-link)
  $C000-$DFFF  OVERLAY_FILE_PAD    zero-pad; runtime TCP ring at $C000
  $E000-$FDFF  OVERLAY_BLOB_CURVE_RAM  P-384 curve blob staging (unused)

ip65 (`cfg/c64-https-ip65.cfg`):

  $0801-$1FFF  LOADER
  $2000-$3FFF  NET_CODE            ip65 blob + LOADER_OVERFLOW +
                                   CRYPTO_AUX_CODE2 + HTTPS_TARGET_RODATA
  $4000-$4F8B  NET_BSS             blob's BSS (live at runtime, EMPTY to ld65)
  $4F8C-$5FFF  CRYPTO_OVERLAY      4,212 B: TLS_CODE + CRYPTO_AUX_CODE
  $6000-$9FFF  CRYPTO_RESIDENT     code + rodata, never crossing $A000
  $A000-$BFFF  CRYPTO_COLD_SHADOW  BSS; `cert_buf` (1,536 B) pinned at $A000
                                   and unioned with LIB_NISTCURVES_P256_BSS
                                   (`SCRATCH_UNION`, #68 — disjoint lifetimes,
                                   capped so growth is a link error)
  $C000-$CFFF  TCP_BUF             4 KB ring for the ip65 callback

ip65 is essentially full: largest free block ~170-186 B (NET_CODE tail),
40 B CRYPTO_RESIDENT, 22 B CRYPTO_OVERLAY, 16 B LOADER. PRG size is not a
headroom gauge. A contiguous-region cfg restructure is a known TODO.

  - `LOADER_OVERFLOW` carries ~125 B of `http.s` that outgrew LOADER.
  - `src/loadaddr.s` (PRG load address) and `src/exports.s` (promotes
    equates to `labels.txt`, incl. `cert_buf_size` — rigs must read it, not
    hardcode 2048/1536) are intentional stubs; ip65-only exports live in
    `src/net/ip65/exports.s`.
  - **Server name validation is UCI-only** (`src/x509_name.s`, 491 B, SAN
    dNSName only, leftmost-label wildcards, no-SAN rejects). It tail-calls
    from `x509_extract_pubkey`'s success exit so its carry *is* the result.
    ip65 has nowhere to put 491 B, and dropping wildcards would break
    wikipedia; ip65 cannot reach a real server anyway. Verified on hardware
    at 48 MHz on both UCI profiles.

## Packaging

`make package` → `dist/` (gitignored). Three products, `make clean`
between each, matrix in `tools/package/_common.sh`:

  c64-https-ip65-onchip.prg   stock C64 + RR-Net, no REU, no turbo
  c64-https-uci-onchip.prg    turbo, no REU
  c64-https-uci-comb.prg      turbo + REU, fastest (needs bank 2 + boot precompute)

REU-profile images were retired (curation: still fastest below ~18 MHz,
one line in `PACKAGE_VARIANTS` to restore). One product per .d64. The
listener `c64-https-listener.py` is a single self-extracting file with no
third-party deps; it needs an `ssl` with TLS 1.3 (macOS `/usr/bin/python3`
is LibreSSL and cannot serve this client) and `--selftest` proves the path
with `openssl s_client -ciphersuites TLS_CHACHA20_POLY1305_SHA256`.

`make package-verify` rebuilds and compares **PRG** hashes, reads each PRG
back out of its .d64 with `c1541`, boots each image in VICE
(`-trapdevice8 +drive8truedrive`, or the load never finishes), and runs the
listener selftest. A failed variant yields a partial release with an
`!! INCOMPLETE RELEASE !!` MANIFEST block, and the gate cannot pass
vacuously (zero checks = fail; any `SKIP_*` = `PARTIAL VERIFICATION`).

## Smoke tests

  tools/test_entropy.py, test_hkdf.py, test_chained_hmac.py,
  test_keyschedule_steps.py, test_tls_handshake.py, test_http.py,
  test_x509.py, test_x509_name.py (**its vector count is conditional —
  never quote one without the condition.** 11 synthetic vectors always run
  (5 accept / 6 reject); +6 against live CA leaves fetched from wikipedia /
  github / lwn, which `X509_NAME_OFFLINE=1` or being offline drops; +6
  against `tools/https_e2e/certs/server.pem`, which a fresh clone does not
  have — it is gitignored listener output, minted on demand by
  `tools/https_e2e/ensure_certs.py`. So **17 / 9 on a fresh clone with
  network, 23 / 12 once the certs exist**, 11 / 6 with neither (all three
  measured 2026-08-31). The trap: both optional sets have the *same*
  3-accept/3-reject shape, so 17 / 9 is produced two different ways —
  fresh clone + network, and certs-present + `X509_NAME_OFFLINE=1` — and
  the printed total tells you neither which sets ran nor whether the
  real-cert path was covered. Read the per-vector lines. The suite also
  reports a missing *cert* as "openssl unavailable" even with openssl on
  PATH, which is how an earlier miscount survived. On a non-uci build it
  exits **2** with a CANNOT RUN message, not 0 — that is the behaviour to
  copy, along with `test_x509.py` (missing labels counted as failures) and
  `test_finished_verify.py` (missing label = FATAL)),
  test_p384_overlay_hazard.py (fails under
  ENABLE_P384_VERIFY=1 by design; needs a well-formed DER sig to reach the
  swap), test_finished_verify.py (18 cases), test_ecdsa_kat_oracle.py
  (6 vectors incl. 3 negative), test_tls_deframer.py, test_x25519.py.

`tools/run_all_tests.py` is the aggregate runner, and **its suite list
lives in `SUITE_ORDER` in that file, not here** — the sentence that used
to stand in this spot named two omissions when there were four, both
security suites among them (#169). Pinned rather than restated: every
`tools/test_*.py` with a module-level `run_tests()` is either in
`SUITE_ORDER` or in the same file's commented `UNDISPATCHED_SUITES`, and
`tools/test_runner_coverage.py` asserts that by AST (5 checks, no build,
no VICE). It is still not an "all pass" runner — a suite that is a
standalone `main()` with no `run_tests()` cannot be dispatched as written
and the guard does not reach it (`grep -n '^def run_tests' tools/test_*.py`
separates the two); run those individually. `hs_sequence` needs
`tls_deframe_pump`, so it is an accounted SKIP unless you run the runner
as `BACKEND=uci python3 tools/run_all_tests.py`. **`pytest` is not the
runner**: suites take
`(transport, labels, seed)` positionally. `pytest.ini` pins `testpaths` to
the pure-logic modules — **that list is the enumeration; read it there, not
here** — and `tools/test_pytest_boundary.py` proves it is exactly the set
pytest can run, in both directions. Both rig dirs (`tests/`, `tools/uci/`)
are `rig_*.py` and in `norecursedirs`, and each exits 5 on its own. A bare
`pytest` at the root is green; the total is not quotable, because it tracks
`testpaths` *and* the build state. Run it rather than citing a number, and
**build `BACKEND=uci` first**: `test_uci_data_acc.py` does not *skip*
without a UCI PRG in `build/`, it **fails** 3 cases (#178's gap, not a
regression).

Negative-path coverage exists because an audit found the Finished-mismatch
abort had no test: `test_finished_verify.py` (VICE, carry-latching stub)
and `rig_https_bad_finished.py` against `tools/https_e2e/evil_listener.py`
(hand-rolled TLS 1.3 server flipping one bit of `verify_data` *before*
encryption; stock `ssl` cannot produce this). Oracle: `tls_last_state=6`.
Test-suite blind spots found by mutation are listed in the notes.

`tools/check_upstream_pins.py [--json|--strict|--worktree]` reports pin
drift per submodule. **Never read pins off `git submodule status`** — it
ignores lightweight tags (c64-x25519's v0.6.0) and reads as "N commits past
a release".

### VICE ip65 rig (hardware-free e2e)

`tests/rig_vice_https_macos.py`: full HTTPS over emulated RR-Net in VICE
against a host listener (`E2E_PROFILE=reu|onchip`, `E2E_NO_WARP=1`,
`HTTPS_PORT`). Needs an ip65 PRG, a pcap-capable VICE
(`~/opt/vice-eth/bin/x64sc`, patched 3.10 — stock macOS builds gate pcap on
euid 0 and segfault), and `sudo bash tools/rig-up-macos.sh` (feth pair,
10.0.65.1, `/dev/bpf*` perms — **reset every reboot** — dnsmasq). VICE
3.10 SDL2 warp caps at ~1.2x. macOS Local Network privacy can silently
block the listener; the preflight probes for it.

### Physical RR-Net rig (real CS8900a silicon)

`tests/rig_ip65_rrnet_hw.py`: the same fetch over a REAL RR-Net cartridge
in the U64E's cartridge port, cabled straight to the Mac's `en4`. The PRG
is loaded over the U64's REST interface; nothing about the network path
goes through the Ultimate. Segment is **10.0.66.0/24** (`sudo bash
tools/rig-up-rrnet-macos.sh en4`), deliberately not the feth rig's
10.0.65.0/24 so both can be up at once; dnsmasq pins
`00:0e:3a:64:64:64 -> 10.0.66.200` and answers for `www.foo.invalid`
only. The capture is hand-started (`sudo tcpdump -i en4 -n -s0 -U -w …` —
both flags load-bearing). Stock 1 MHz, ~40-80 min.

  - **Every wire and memory verdict is a pure function** in
    `tools/ip65_hw_checks.py`; `tools/test_ip65_hw_checks_unit.py`
    (pytest testpaths, no hardware, ms) proves each alarms on a known-bad
    input, and `tools/mutate_ip65_hw_checks.py` breaks each one to prove
    the suite goes red. Adding a `check_*` without a red case fails that
    suite by introspection. **The rig is not judgment-free, though**: 15
    delegated verdicts against 19 of its own `RES.check()` assertions
    (screen scrapes, config writes, the clock assertion, the listener
    probe, the selftests), which have no red case. Do not attribute a
    run's whole check count to the cartridge — 8 of the 24 in the first
    passing run touched neither the cartridge nor the 6510. **A stock
    re-run reports 25, not 24**: the clock assertion arrived with
    `TURBO_MHZ` and fires at 1 MHz too, landing in that host-side group.
    The first run's decomposition is history and stays as written.
  - Two stations on the cable and the Mac is one of them, so every wire
    assertion discriminates by **Ethernet source address**; a third MAC
    is a hard failure. The cleartext-absence check needs a positive
    control (the SNI hostname, which TLS 1.3 leaves in the clear) or it
    reports INCONCLUSIVE, and the rig exits 78 for that, never 0.
  - **Load the PRG chunked and verify it before SYS.** A single
    `write_memory` of the 47 kB image lands in 0.22 s and comes back with
    one wrong byte at a random offset (measured n=2, U64E fw 3.15 fork);
    `write_bytes` takes ~33 s and is exact. Also: $0801/$0802 are zeroed
    by the device ~2-5 s after READY. with no write involved. And
    `client.run_prg` would deselect the cartridge (harness #217).
  - Only $0801-$9FFF is verifiable from the host — the image's
    $A000-$BFFF tail is BSS zero fill and reads back as the BASIC ROM
    until `boot.s` banks it out. `check_shadow_ram_readable` is what
    tells a ROM read from a RAM read; run it before believing any $A000+
    value.
  - This rig does NOT call `enable_uci` (the only one that does not): the
    UCI command interface is a second consumer of the same expansion bus,
    and an RR-Net run does not need it. Its value is read and reported,
    never written.
  - **A green run here does NOT mean the ip65 product validates server
    names.** `src/x509_name.s` is UCI-only (see Memory layout), so the
    ip65 image accepts any certificate that chains-free-verifies,
    whatever name it carries — this rig fetches from a local listener
    presenting a self-signed leaf and asserts nothing about the name in
    it. Do not cite this run as coverage of that gap; it is the gap.
  - What one passing run covers: one clock, one device, one cartridge,
    one local listener, and an image differing from the shipped one only
    in `HTTPS_PORT`.
  - `TURBO_MHZ=48` runs the same image at turbo — an experiment, not a
    product check; the default stays 1 MHz because that is the clock the
    product ships at. **Measured 2026-09-06: 43.1 s 'G' to close against
    1,979 s at 1 MHz (46x), CS8900a fine, DHCP on the automatic
    attempt.** One check goes red there and must stay red:
    `check_tls_connected` samples `tls_state`, which lives only between
    `tls13.s:303-304` and `tls_close` (`:382-383`), and at 48 MHz that
    window fits inside
    one poll (`tls_last_state` is written only on the ERROR path, so it
    is no fallback). A turbo run's handshake verdict is inference.
  - **CIA timers are realtime under turbo** — 1023.2 ticks/wall-s at
    1 MHz vs 1022.9 at 48 MHz, ratio 1.000, both within 0.05% of NTSC
    phi2/1000. So ip65's `timer_read` (CIA2 timer B, 1000-cycle cascade)
    keeps its ~15 s DHCP budget at any clock, and no 1 MHz assist is
    needed for that. Do NOT re-derive this from the CIA1 TOD figure in
    the bounded-timeouts design note: different clock domain.
    Reproducer: `tools/probe_cia_timer_rate.py`.
