# c64-https library-ingestion architecture

This document proposes a structural refactor of c64-https so that future library updates can be ingested by a cron / CI bot instead of by manual cfg surgery. The work is co-designed with c64-wireguard (which independently filed library-side issues on the same day, 2026-05-20: c64-x25519 #43/#44, c64-ChaCha20-Poly1305 #26) so the contract presented to upstream libraries is a *cross-consumer* contract, not c64-https-private.

## 1. Current state analysis

### 1.1 Memory map (both backends)

`cfg/c64-https-ip65.cfg:25-61` and `cfg/c64-https-uci.cfg:39-78` are the load-bearing regions. After Phase C.4 + Phase 5, the maps diverge non-trivially:

| Region (c64-https) | ip65 cfg lines | UCI cfg lines | Notes |
|---|---|---|---|
| LOADER | 31 ($0801, 6 KB) | 44 (identical) | BASIC stub + boot + TLS state machine + HTTP + net wrapper |
| NET_CODE | 32 ($2000, 8 KB) | 45 (identical span, different content) | ip65: ip65 blob ($4.8 KB) + LOADER_OVERFLOW + CRYPTO_AUX_CODE2 (hmac_drbg). UCI: ~2 KB UCI adapter + LOADER_OVERFLOW + TLS_CODE + CRYPTO_AUX_CODE + CRYPTO_AUX_CODE2 |
| NET_BSS / NET_BSS_TAIL | 41–42 (split: $0F8C blob BSS + $1074 tail used for TLS_CODE + CRYPTO_AUX_CODE) | 46 (UCI_BSS_REGION, 512 B at $4000) | ip65 splits the ip65 blob BSS away from headroom because Phase C.4 needed to relocate code |
| CRYPTO_OVERLAY | 49 ($6000, **0 B alias**) | 47 ($4200, **7.5 KB**, $1E00) | ip65 has no overlay slot. UCI's slot is the only spare for X25519_RODATA/BSS under USE_X25519_SIBLING=1 |
| CRYPTO_RESIDENT | 43 ($6000, **24 KB**) | 48 (identical) | The pressure point — Phase C.4 already moved TLS_CODE + sha256/hmac_drbg out to fit P-256 sibling. CLAUDE.md:570 records "**CRYPTO is 100% full**" |
| SHADOW_BSS | folded into CRYPTO_RESIDENT (43) | folded into CRYPTO_RESIDENT (48) | ip65 cfg comment line 6: "covers old CRYPTO + SHADOW_BSS span" |
| TCP_BUF | 60 ($C000, 4 KB) | repurposed as OVERLAY_FILE_PAD (62); runtime equate-only | UCI fills $C000–$DFFF with zeros at PRG load only to make the under-KERNAL CURVE_RAM image land at $E000 |
| OVERLAY_BLOB_CURVE_RAM | 58 (zero-size alias) | 68 ($E000, 7.5 KB; DMA'd to REU bank 7 at boot) | P-384 staging — ip65 has no room for the embedded blob |

Already-existing fragility points the bot would hit:

- **CRYPTO_OVERLAY** is *simultaneously* the P-384 SHA-384/Curve overlay-paging slot (Phase 5), the test-time scratch slot for `tools/test_p384_symbols.py`, AND the resident home for sibling X25519 rodata under USE_X25519_SIBLING=1. The collision is documented in `cfg/c64-https-uci.cfg:127-128` and `src/crypto/shared/crypto_swap.s:166-171`: once a P-384 swap occurs, the X25519 sibling rodata is *gone* (no stash). c64-https gets away with it today only because the production TLS path never uses P-384.
- **ip65 backend** is structurally incapable of holding the X25519 sibling: `cfg/c64-https-ip65.cfg:100-109` and `CLAUDE.md:400-402` confirm the 1 KB overflow.
- **CRYPTO_RESIDENT is 100% full** today (CLAUDE.md:569-570), and any upstream bump that adds bytes — even a 10-byte defensive REU register init — will overflow. The nistcurves v0.2.0 → v0.3.0 bump triggered exactly this on 2026-05-19.
- The MEMORY layout has historic dead zones (`$C000-$DFFF` zero-filled into the PRG just for the file offset) that the Phase 6 commit explicitly defers as "follow-up".

### 1.2 Integration friction — the sed problem

`tools/integration/build_nistcurves_p256.sh`, `build_nistcurves_p384.sh`, and `build_x25519.sh` each *patch the library's own source files mid-build* via `sed -i ''`. Inventory:

- `build_nistcurves_p256.sh` — **14** `sed -i ''` calls, including a line-range delete of `sm256_reu_stash_affine` … `ec_scalar_mul_var` to strip Lim-Lee bodies. Lines 95-117 themselves carry a CHANGELOG entry explaining how this *broke* when upstream PR #34 inserted `ec_point_add_jj` at line 800 and shifted the line numbers (the script was rewritten from numeric ranges to landmark anchors as a result).
- `build_nistcurves_p384.sh` — **17** `sed -i ''` calls including segment rerouting (`.segment "CODE"` → `.segment "OVERLAY_P384_CURVE"`), import deletion, and a deletion of `ecdsa_verify_with_message_384` (because c64-https drives `sha384_init/update/final` itself for TLS-style streaming).
- `build_x25519.sh` — fewer sed sites (3 segment rewrites) but emits ~250 lines of hand-written `data_x25519_{rodata,bss}_raw.s` to side-step the library's own `data.s`.
- `build_nistcurves_p256.sh:144-150` carries a sanity grep that runs *after* the sed to catch leftover symbol refs — explicit acknowledgment the strip is brittle.

Every library tag bump risks breaking these scripts at line-anchor level. The Phase G nistcurves bump on 2026-05-20 (the one that motivated this work) hit a cfg overflow that masked an additional `sed` landmark drift.

The integration scripts are also doing the *cfg's* job: assigning segments. `sed -i '' 's/^\.segment "CODE"/.segment "CRYPTO_CODE"/'` is the consumer rewriting how the library names its segments because there is no link-time renaming primitive in ld65. A library that emitted neutral segment names by convention (e.g., `LIB_NISTCURVES_P256_CODE` instead of `CODE`) would let the cfg do the placement decision instead of a sed pass.

### 1.3 Hot vs cold paths

Per-handshake call counts (from `src/tls_handshake.s`, `src/tls_ecdh.s`, `src/crypto/ecdsa_verify.s`):

| Primitive | Call frequency in one HTTPS request | Bucket |
|---|---|---|
| X25519 scalarmult | 1 (key share) | cold (once-per-handshake) |
| ECDSA P-256 verify | 1 (CertificateVerify) | cold (once-per-handshake) |
| ECDSA P-384 verify | 0 today, 1 if negotiated | cold (once-per-handshake) |
| SHA-256 init/update/final | many — every transcript update, every HKDF derivation, every HMAC | hot (per-record context-dependent) |
| ChaCha20 encrypt | every TLS record (handshake + app) | **hot** |
| Poly1305 init/update/final | every TLS record | **hot** |
| AEAD encrypt / decrypt | every TLS record | **hot** |
| HKDF / HMAC-DRBG | boot + key schedule | warm (handshake-time, but per-key not per-record) |

The cold-path crypto (X25519 + P-256/P-384 verify) is what currently fills CRYPTO_RESIDENT — and it's exactly what *could* be overlay-paged without per-record performance impact. The hot path (ChaCha20-Poly1305 + SHA-256 + AEAD) is what *must* remain always-resident. Today the cfg makes no such distinction: under UCI, only P-384 is overlay-resident; X25519 (when sibling) and P-256 are always-resident.

### 1.4 Inventory of consumed libraries

| Library | Source | Pin | Manifest exports today | REU usage | ZP usage |
|---|---|---|---|---|---|
| `libs/nistcurves` | github.com/JC-000/c64-nist-curves (submodule) | v0.2.0 | `LIB_VERSION_{MAJOR,MINOR,PATCH}` in `src/lib_version.s`; per-slot `.exportzp` of all ZP equates in `src/zp_config.s` (~16 slots); `.ifndef`-guarded ZP overrides; package contract documented in `API.md` §4–§8 | Banks 0-1 (mul tables, 128 KB); Bank 2 ($0000-$3FFF P-256 anchors; $4000-$9F9F P-384 anchors); Phase 5 adds Banks 6-7 for P-384 overlay halves | `~$22-$3C` ECDSA bignum; `$3D-$44` SHA-384 streaming pointers; `$04-$0B` SHA-256 |
| `libs/x25519` | github.com/JC-000/c64-x25519 (submodule) | v0.4.0 | No `.exportzp` of ZP slots (only `.ifndef` guards); no `LIB_VERSION_*`; no archive manifest; integration via "vendor as source", `make lib` builds `libx25519.a` for downstream use | Banks 0-5 (mul + doubled + 17-bit-carry tables, 384 KB; CT-clean post-v0.4.0); page-aligned C64 tables at $7800-$7BFF; under sibling integration ZP gets relocated via `--asm-define` from consumer | `$14-$16`, `$1C`, `$1E-$2A`, `$24-$25`, `$2C-$2F`, `$40-$7F` (87 B total). All `.ifndef`-guarded in `src/constants.s`; *not* `.exportzp` (today this is wireguard issue #44) |
| `c64-ChaCha20-Poly1305` | github.com/JC-000/c64-ChaCha20-Poly1305 (project at `/Users/someone/Documents/c64-ChaCha20-Poly1305`; **NOT yet vendored** in c64-https) | n/a — in-tree fork at `src/crypto/{chacha20,poly1305,aead}.s` | `aead_encrypt`, `aead_decrypt`, `poly1305_init/update/final`, `chacha20_encrypt`. No `LIB_VERSION_*`. No `.exportzp`. `.ifndef` ZP overrides present in `src/lib/constants_lib.s` (per inspection it's not yet on par with nistcurves' export discipline) | Profile A: bank 0 offset $0000 (1 KB sqtab backup) — **configurable** via `POLY1305_REU_BANK` / `POLY1305_REU_OFFSET` as of #19. Profile B: no REU | `$02-$03` zp_tmp; `$04-$09` w32; `$1A-$1D` poly_i/j/carry/tmp; `cc20_*` family |

In addition the project consumes `ip65` (sibling submodule, prebuilt blob) and the U64E UCI adapter (in-tree under `src/net/uci/`). Both are out of scope for this plan — they sit behind `src/net_abi.inc` and the manifest contract is already cleaner there.

### 1.5 Library-side precedent for the manifest contract

The libraries have already taken the first two steps that c64-https needs to lean on:

- **`libs/nistcurves/src/zp_config.s`** is the canonical example. Every ZP slot is `.ifndef`-guarded with the upstream default, then `.exportzp`-ed once. Consumer overrides via `ca65 --asm-define fp_src1=$22` (see `tools/integration/build_nistcurves_p256.sh:64-81` — that's exactly what c64-https does today for nistcurves' bigint ZP slots). The pattern is documented in `libs/nistcurves/API.md` §8.3.
- **`libs/nistcurves/src/lib_version.s`** exports `LIB_VERSION_{MAJOR,MINOR,PATCH}` as integer equates. Consumers can `.import LIB_VERSION_MAJOR / .if LIB_VERSION_MINOR < 2 ; .error ...` at assemble time. `API.md` §8.5 documents this.
- **c64-ChaCha20-Poly1305 issue #19 (CLOSED)** shipped `POLY1305_REU_BANK` / `POLY1305_REU_OFFSET` as `--asm-define`-able equates — the first piece of the REU-layout-as-symbol contract.
- The **c64-wireguard agent has filed three open issues TODAY (2026-05-20)** asking for the *missing* halves of the same contract: c64-x25519 #43 (REU bank base via `--asm-define`), c64-x25519 #44 (publish `.exportzp` ZP-config header modelled on nistcurves), c64-ChaCha20-Poly1305 #26 (same `.exportzp` ZP-config header for chacha20/poly1305). These are not c64-https issues, but **c64-https endorses all three verbatim** — they fix the asymmetry that today makes c64-https's `build_x25519.sh` ship 0 `-D` defines while `build_nistcurves_p256.sh` ships 18.

The library-side direction is already set by these existing precedents; c64-https-side just needs to *consume* the contract once it's complete.

## 2. Target architecture

### 2.1 Hot/cold partition

Under both backends:

| Bucket | Always-resident (CRYPTO_HOT) | Overlay-paged (CRYPTO_COLD_*) |
|---|---|---|
| ChaCha20-Poly1305 (encrypt, AEAD, poly init/update/final) | ✓ | — |
| SHA-256 (init/update/final) | ✓ | — |
| HKDF, HMAC-DRBG, transcript | ✓ | — |
| TLS state machine, record I/O, HTTP | ✓ | — |
| X25519 scalarmult + fe25519 multiply tables (C64-side) | optionally cold under UCI (overlay slot has the room); always-resident under ip65 (no slot today; see §2.4 for the new ip65 slot) | OV_X25519_SIBLING |
| ECDSA P-256 verify (sibling): fp256, mod256, points256-stripped, ecdsa256, curve256 | — | **new** OV_P256_VERIFY |
| ECDSA P-384 verify (sibling): fp384/mod384/points384/ecdsa384 | — | OV_P384_CURVE (exists) |
| SHA-384 (sibling) | — | OV_P384_SHA384 (exists) |

Criterion: **anything called more than once per TLS record is hot; anything called once per handshake or once per cert profile is cold**. The current cfg conflates the two; the new architecture separates them.

Concrete CRYPTO_HOT estimate (sizes from `build/labels.txt` snapshots — rebuild to confirm):

- ChaCha20 + Poly1305 + AEAD ≈ 2.3 KB
- SHA-256 + HKDF + HMAC-DRBG ≈ 2.5 KB
- AEAD glue, transcript, key schedule ≈ 1 KB
- TLS record I/O, handshake state machine, HTTP ≈ 6 KB
- ECDSA-verify dispatcher (`src/crypto/ecdsa_verify.s`), TLS adapters, X25519 ECDH glue ≈ 1 KB
- BSS (TLS state, HTTP state, transcript hash state) ≈ 2 KB

CRYPTO_HOT target: **~15 KB resident** (vs today's 24 KB CRYPTO_RESIDENT that the cold path is also eating into). Of the 9 KB freed:

- ~5 KB becomes a new resident "shadow" region used for any non-paged BSS that the cold-path overlays need to keep alive across swaps (per-curve scratch buffers, current_overlay state byte, ecdsa_inputs_256, sha256_state).
- ~4 KB becomes the new overlay slot (or grows the existing 7.5 KB slot — see §2.4).

This is the same trick that today's Phase 5 P-384 split (sha384/curve halves) used at 7.5 KB; we're generalizing it to four overlays under a single discipline.

### 2.2 Library memory manifest

Each library exports a uniform set of integer equates and segment names. Consumers reference these via `.import` and `--asm-define`; the cfg references the segment names directly. Proposal:

| Manifest symbol | Type | Set by | Read by |
|---|---|---|---|
| `LIB_VERSION_{MAJOR,MINOR,PATCH}` | integer equate (already in nistcurves) | library's `lib_version.s` | consumer assemble-time `.if` guards |
| `LIB_ABI_VERSION` | integer equate (new) | library | consumer; bumped on any breaking export change |
| `LIB_<X>_ZP_USAGE_BYTES` | integer equate (new) | library aggregates from zp_config | consumer assemble-time fit-check |
| `LIB_<X>_REU_BANKS_USED` | bit-mask integer equate (new) | library | consumer assemble-time fit-check + reu_layout collision detect |
| ZP slot equates | `.exportzp` per slot, `.ifndef`-guarded | library `zp_config.{s,inc}` | consumer cfg + consumer code via `.importzp` |
| REU bank/offset equates (`<LIB>_REU_BANK`, `<LIB>_REU_OFFSET`) | integer equate, `.ifndef`-guarded | library | consumer overrides via `--asm-define` |
| Segment names | `.segment "LIB_<X>_CODE"`, `"LIB_<X>_RODATA"`, `"LIB_<X>_BSS"` (and `"LIB_<X>_HOT_CODE"` / `"LIB_<X>_COLD_CODE"` for hot/cold partition) | library source | consumer cfg `SEGMENTS{}` block places them anywhere |

Consumer-side, ld65 already publishes `__<MEMORY_REGION>_START__`, `__<MEMORY_REGION>_SIZE__`, and `__<MEMORY_REGION>_LAST__` for any region declared with `define = yes`. `src/crypto/shared/crypto_swap.s:138` already uses `__CRYPTO_OVERLAY_START__` this way. We extend that pattern to expose `__CRYPTO_HOT_FREE__` (region size minus segment fill) computed by ld65 (`define = yes` plus `__<SEGMENT>_SIZE__` per-segment) and surface it in the build's diagnostic output so the CI bot sees "CRYPTO_HOT has 1284 B free" without grepping the linker map.

The manifest is **a cross-consumer contract**. It is endorsed equally by c64-https and c64-wireguard (and by any future c64-tls-ish consumer — c64-aes256-ecdsa is the obvious candidate). The library-side issues in §3 are written so that *both* consumers see the same surface.

### 2.3 ZP/REU normalization

Inconsistencies across the libraries:

| Aspect | nistcurves | x25519 | ChaCha20-Poly1305 |
|---|---|---|---|
| `.ifndef`-guard ZP equates | yes (all 16 slots) | yes (all 87 B claimed) | partial (in `constants_lib.s` but not full coverage) |
| `.exportzp` ZP equates | **yes** (line 110-113 of zp_config.s) | no | no |
| `LIB_VERSION_*` equates | **yes** | no | no |
| Documented memory map at static address | yes (API.md §2) | yes (LIBRARY.md §4.2) | partial (docs/MEMORY_MAP.md) |
| Configurable REU base | partial (banks hardcoded in source) | no (the *blocker* of wireguard #43) | yes since #19 |
| Archive (`.a`) shipped from `make lib` | yes (`build/lib/`) | yes (`libx25519.a`) | no (consumer compiles `.s` directly) |
| "Minimal subset" build target (P-256 only, etc.) | no (consumer's `tools/integration/build_*.sh` strips) | no (the whole archive is reasonable, only `util.o` is excluded by consumer) | n/a (small enough whole) |

Wireguard issues #43/#44/#26 close the `.exportzp` and configurable-REU gaps. The "minimal subset" gap is c64-https-specific (we want a "P-256 verify without Lim-Lee precompute" build target so we don't have to sed-strip 700 lines).

The end-state contract — what every consumed library should look like:

1. `src/zp_config.s` (or `.inc`): every ZP slot `.ifndef`-guarded then `.exportzp`-ed. Pattern is nistcurves'.
2. `src/lib_version.s`: `LIB_VERSION_{MAJOR,MINOR,PATCH}` + `LIB_ABI_VERSION` equates exported.
3. `src/reu_config.s` (new): every REU bank/offset `.ifndef`-guarded then `.export`-ed.
4. **Stable segment names**: library code goes into `LIB_<X>_CODE`, `LIB_<X>_RODATA`, `LIB_<X>_BSS` (or whatever the library's owners choose, as long as they don't change between releases). No more consumer `sed` to rename `CODE` to `CRYPTO_CODE`.
5. `make lib-<variant>` build targets: each library publishes any "minimal subset" variants its primary consumers actually need. Consumer-side build is `bash -c 'cd libs/<x> && make lib-<variant>' && cp libs/<x>/build/lib/lib<x>-<variant>.a build/lib/`.
6. **All siblings adopt nistcurves' "wrap in `.ifndef` + `.exportzp`" pattern uniformly**.

### 2.4 Overlay slot model

Under UCI today: `CRYPTO_OVERLAY = $4200-$5FFF` (7.5 KB). Under ip65: zero-sized alias.

Proposed under UCI (no change to base addresses; reuses existing slot):

- One paging slot at $4200-$5FFF, dispatcher `src/crypto/shared/crypto_swap.s` (already exists).
- Four overlay IDs: `OV_X25519` (new — was state-only marker, now a real DMA), `OV_P256_VERIFY` (new), `OV_P384_SHA384` (exists), `OV_P384_CURVE` (exists).
- REU-resident backing store: under `src/crypto/shared/reu_layout.inc`, four bank assignments (banks 2/3/6/7 currently; reshape per §2.5).

Proposed under ip65:

- Today's ip65 cfg has $4F8C-$5FFF as `NET_BSS_TAIL` (~$1074 / 4.1 KB) used for TLS_CODE + sha256 — the Phase C.4 dance the user is trying to escape.
- The right structural answer: reclaim $4F8C-$5FFF as `CRYPTO_OVERLAY_IP65` ($1074 ≈ 4 KB), at the cost of putting TLS_CODE + sha256 *back* into CRYPTO_HOT (which the hot-cold partition now allows: CRYPTO_HOT will have 9 KB more headroom than CRYPTO_RESIDENT did).
- 4 KB is smaller than UCI's 7.5 KB, which means **two-stage overlays** for P-384 (sha384 then curve) and a *smaller* X25519 + P-256 verify image. The library issues in §3 explicitly request "fit into 4 KB" as a target slot size; current P-256 verify is ~6 KB in `build/lib/nistcurves-p256.sizes.txt`, so this needs a code-shrink follow-up on the library side.
- Alternative: ip65 hardcodes that USE_X25519_SIBLING is supported but P-384 isn't. ip65 is already the smaller-feature backend; this is fine.

The swap dispatcher `src/crypto/shared/crypto_swap.s` already implements the right pattern (idempotent ID check, SEI window, REU→C64 DMA). We extend it with `crypto_swap_to_x25519` (real DMA, not state-only), `crypto_swap_to_p256_verify` (new), and a unified `crypto_overlay_call(<id>, <fn_offset>)` helper that JSRs the target after swap. The TLS handshake driver then issues exactly four swaps per handshake worst case (X25519 once at ECDH; P-256 verify once at CertVerify, or P-384 sha384 + P-384 curve if negotiated).

### 2.5 REU layout under the new model

`src/crypto/shared/reu_layout.inc` is already symbolic and `.ifndef`-guarded; what changes is the *content*:

| REU range | Today | Proposed |
|---|---|---|
| Banks 0-1 ($00000-$1FFFF) | x25519 mul tables | unchanged |
| Bank 2 ($20000-$2FFFF) | overlay store + sibling-x25519 16-bit carry table when present | overlay store: 4 slots × 8 KB = 32 KB used, 32 KB free |
| Bank 3 ($30000-$3FFFF) | P-256 precompute (RESERVED, currently unused under TLS path) **or** sibling-x25519 doubled-product table | reorganize: x25519 sibling tables get bank 3 (resolves the wireguard #43 collision); P-256 precompute drops because nistcurves' ec_scalar_mul_var doesn't use it |
| Banks 4-5 ($40000-$5FFFF) | P-384 precompute (RESERVED, currently unused) **or** sibling-x25519 17-bit-carry | sibling-x25519 gets bank 4 (resolves wireguard #43); banks 5-7 reserved for future c64-aes256-ecdsa precompute |
| Banks 6-7 ($60000-$7FFFF) | P-384 SHA-384 overlay + P-384 curve overlay images | unchanged (these are the *images*, DMA'd into the live slot) |

This pushes more work onto wireguard #43's `--asm-define REU_BANK_BASE` knob — when it lands, c64-https assembles the sibling with `--asm-define X25519_REU_BANK_BASE=$03` so the sibling's banks 3/4 don't collide with anyone.

### 2.6 Integration script replacement

Once the libraries publish:
- Stable segment names (no consumer-side rename needed)
- `.exportzp` of all ZP slots (consumer-side `.importzp`, no `-D` flag list)
- `make lib-<variant>` targets for "P-256 verify minimal" etc.
- `LIB_VERSION_*` equates

then `tools/integration/build_*.sh` collapses to roughly:

```
make -C libs/nistcurves lib-p256-verify
cp libs/nistcurves/build/lib/nistcurves-p256-verify.a build/lib/
```

…optionally with a sha256 check on the archive. **Zero `sed`**. The cfg picks up segments named `LIB_NISTCURVES_P256_HOT_CODE` etc. and places them. Bumping nistcurves from v0.2.0 to v0.3.0 becomes a one-line submodule update; the CI bot detects "tag pushed, fetch, build, test, open PR".

## 3. Library-side feature requests

c64-wireguard has already filed three of these *today* (2026-05-20). c64-https's posture: **endorse those three, and add c64-https-specific issues for what wireguard wouldn't need (minimal P-256/P-384 subset archives, sibling SHA-256, etc.)**.

### 3.1 Endorsements (already filed, no new issue from c64-https)

- **c64-x25519 #43** — Make REU bank allocation configurable via `--asm-define`. c64-https endorses verbatim; this is a prerequisite for clean `USE_X25519_SIBLING=1` under both backends.
- **c64-x25519 #44** — Publish a `.exportzp` ZP-config header. c64-https endorses verbatim; eliminates 5-7 of the `--asm-define` flags in `tools/integration/build_x25519.sh`.
- **c64-ChaCha20-Poly1305 #26** — Same `.exportzp` ZP-config header. c64-https endorses; this becomes the foundation for an eventual `USE_CHACHA_SIBLING=1` integration (c64-https today is in-tree, but the long-term direction is to consume the sibling here too).

c64-https-side: when filing the issues below, cross-link the three wireguard issues so library maintainers see them as a coherent contract.

### 3.2 New library-side issues (c64-https specific)

#### Issue A — c64-nist-curves: publish minimal-subset archive build targets

**Title:** Publish `lib-p256-verify` and `lib-p384-verify` minimal-archive build targets

**Body:**

c64-https consumes `libs/nistcurves` v0.2.0 as a git submodule. The current consumer-side integration is `tools/integration/build_nistcurves_p{256,384}.sh`, two shell scripts totaling ~700 lines that *stage upstream sources into a build dir and sed-patch them*. The patches strip Lim-Lee precompute bodies (we use `ec_scalar_mul_var` only — variable-base verify, no fixed-base ECDH-style scalar mul), strip P-384 from the P-256 build, strip `ecdsa_verify_with_message_384` (we drive `sha384_init/update/final` ourselves for TLS-style streaming transcripts), strip Lim-Lee anchor tables, etc.

Every upstream tag bump risks breaking these `sed` patterns. PR #34's `ec_point_add_jj` insertion already broke our line-anchor-based strip once (see comments in `tools/integration/build_nistcurves_p256.sh:95-117`). We want upstream to ship the minimal-subset variants as first-class build targets so the consumer-side step collapses to `make lib-p256-verify && cp build/lib/nistcurves-p256-verify.a <downstream>/build/lib/`.

**Proposed**

Add to `libs/nistcurves/Makefile`:

```
.PHONY: lib-p256-verify lib-p384-verify lib-p384-sha384 lib-p384-curve
lib-p256-verify: build/lib/nistcurves-p256-verify.a
lib-p384-verify: build/lib/nistcurves-p384-verify.a
lib-p384-sha384: build/lib/nistcurves-p384-sha384.a
lib-p384-curve:  build/lib/nistcurves-p384-curve.a
```

Each archive contains exactly the symbols that variable-base verify needs:

- `nistcurves-p256-verify.a`: `fp256`, `mod256`, `points256` (only `ec_point_double`, `ec_point_add`, `ec_point_add_jj`, `ec_scalar_mul_var`, `ec_jacobian_to_affine`), `curve256` (only `ec_a256/b256/gx256/gy256`), `ecdsa256` (only `ecdsa_verify_256`, `fp_reverse32`), `mul_8x8`, `zp_config`, `lib_version`. **Excludes** `ec_scalar_mul` (Lim-Lee), `ec_precompute_256`, anchor tables, `inv256`, and `data.s`'s P-384/Lim-Lee buffers.
- `nistcurves-p384-verify.a`: analogous for P-384.
- `nistcurves-p384-sha384.a` and `nistcurves-p384-curve.a`: the two halves c64-https already paginates into the live overlay slot per `src/crypto/shared/crypto_swap.s`. Today these are produced by a consumer-side strip script (`tools/integration/build_nistcurves_p384_bin.sh`); they should live upstream because the split point is library-internal.

The library's `data.s` is currently monolithic — the same Phase G that retained scalar mul vs. excluded Lim-Lee anchors decides what RW buffers are needed. Recommend splitting `data.s` into `data_p256.s` + `data_p384.s` + `data_lim_lee.s` so the minimal archives don't drag in `cm_k`, anchor tables, P-384 buffers that the verify path doesn't touch.

**Stable segment names**

While doing this work, please switch library segment names from generic `CODE` / `RODATA` / `DATA` to library-prefixed names — `LIB_NISTCURVES_CODE`, `LIB_NISTCURVES_RODATA`, `LIB_NISTCURVES_BSS`. Today's consumer `sed -i '' 's/^\.segment "CODE"/.segment "CRYPTO_CODE"/'` exists only because the library uses the same segment names a typical consumer's main does. With distinct names, the consumer's cfg places the library wherever it wants (always-resident, overlay-resident, separate per-archive region) by name, with zero source patching.

**ABI versioning hint**

Bump `LIB_VERSION_MINOR` for this work (additive: new build targets, new segment names, no removed symbols). Existing `lib` target stays. Existing segment names stay as aliases (or get removed at the next MAJOR — separate decision).

**Definition of done**

- `make lib-p256-verify` produces `build/lib/nistcurves-p256-verify.a` containing exactly the symbols c64-https needs (cross-check via `ar65 v` against the inventory above).
- `make lib-p384-sha384` and `make lib-p384-curve` produce 7.5 KB-or-less archives suitable for c64-https's CRYPTO_OVERLAY slot.
- New segment names documented in API.md §8.2.
- c64-https's `tools/integration/build_nistcurves_p256.sh` can be reduced to a 3-line `make` invocation + `cp`.
- `make` (no args) builds the standalone test PRG as today; no regression to the test harness.

#### Issue B — c64-nist-curves: stable segment names

(May be folded into Issue A if upstream prefers — separated here because it's the *contract* part and Issue A is the *content* part.)

**Title:** Rename library segments from `CODE`/`RODATA`/`DATA` to `LIB_NISTCURVES_*`

**Body:**

Consumer projects (c64-https, c64-wireguard) embedding this library need to place the library's code/rodata/bss in their own memory regions — sometimes CRYPTO_RESIDENT, sometimes CRYPTO_OVERLAY, sometimes a backend-specific region. With the library's current segment names matching what a consumer's own `main.s` typically uses, the consumer must `sed -i ''` the library sources to rename segments before assembly.

**Proposed**: switch `.segment "CODE"` → `.segment "LIB_NISTCURVES_CODE"`, `RODATA` → `LIB_NISTCURVES_RODATA`, `DATA` → `LIB_NISTCURVES_BSS` (with appropriate per-curve / per-archive splits — `LIB_NISTCURVES_P256_CODE` and `LIB_NISTCURVES_P384_CODE` once Issue A's split lands). The library's own `src/c64.cfg` adds a SEGMENTS block aliasing the new names back to `MAIN`/`RODATA`/`DATA` so the standalone PRG build is unchanged.

ZP slots are unaffected — those are address equates, not segments.

**Definition of done**: library's standalone test PRG builds unchanged; consumer projects can place library code in any MEMORY region without source patches; API.md §8.2 documents the segment names.

#### Issue C — c64-x25519: ABI version equates + minimal "verify-only" archive

**Title:** Export `LIB_VERSION_*` constants and consider a verify-only archive variant

**Body:**

Mirror nistcurves' `src/lib_version.s` pattern — export `LIB_VERSION_MAJOR / _MINOR / _PATCH` as integer equates so consumers can `.if` against them at assemble time. Today c64-x25519 consumers pin via git submodule SHA only; an assemble-time guard against an unsupported library version is impossible because the symbols don't exist.

(Filing concurrently with wireguard #43 and #44 — those two fix the configurable-REU and `.exportzp` gaps; this one adds the version contract on top.)

Long-term, a `make lib-x25519-scalarmult` minimal-archive variant (no `util.o` benchmark helpers, no `main.o` test harness — basically what `tools/integration/build_x25519.sh` produces today after exclusions) would let consumers drop the 250-line `cat > data_x25519_bss_raw.s <<EOF ...` block from the integration script. Lower priority than wireguard #43/#44 because c64-x25519's source layout is already cleaner than nistcurves' was pre-API.md.

**Proposed minimal scope (for this issue)**

- Add `src/lib_version.s` exporting `LIB_VERSION_MAJOR=0`, `_MINOR=4`, `_PATCH=0`, `LIB_ABI_VERSION=1`. Pattern: copy nistcurves' file.
- Reference from `cfg/x25519.cfg` and `cfg/x25519-example.cfg` so the standalone PRG embeds the version constants.

**Definition of done**: consumer can `.import LIB_VERSION_MAJOR / LIB_VERSION_MINOR / .if LIB_VERSION_MINOR < 4 ; .error "needs c64-x25519 v0.4+" ; .endif`. Standalone library tests pass unchanged.

#### Issue D — c64-ChaCha20-Poly1305: ABI version equates

**Title:** Export `LIB_VERSION_*` constants

**Body:** Same scope as the c64-x25519 issue above. The c64-https long-term plan is to consume `c64-ChaCha20-Poly1305` as a sibling library (today the chacha20/poly1305/aead is an in-tree fork in c64-https's `src/crypto/`). When that integration lands, an assemble-time version guard against unsupported sibling versions is the lightest-weight stability anchor we can have. Pattern: same as the nistcurves and x25519 issues — `src/lib_version.s` with four integer equates.

#### Issue E — c64-nist-curves: aggregate REU and ZP usage manifest equates

**Title:** Expose `LIB_NISTCURVES_REU_BANKS_USED` and `LIB_NISTCURVES_ZP_USAGE_BYTES` aggregate equates

**Body:**

Add to `src/lib_version.s` (or a new `src/lib_manifest.s`):

```asm
.export LIB_NISTCURVES_REU_BANKS_USED   ; bitmask of REU bank indices owned
.export LIB_NISTCURVES_ZP_USAGE_BYTES   ; total bytes of ZP slots owned
.export LIB_NISTCURVES_RESIDENT_BYTES   ; rough resident footprint
.export LIB_NISTCURVES_COLD_BYTES       ; rough overlay-able footprint

LIB_NISTCURVES_REU_BANKS_USED = $07   ; banks 0, 1, 2 (mul tables + anchors)
LIB_NISTCURVES_ZP_USAGE_BYTES = 16
...
```

c64-https today re-derives these from the linker map after every build to surface them in the CI bot's PR description. Library-side declaration lets the consumer's assemble-time `.assert` check guarantee no collision before the link even runs — and lets the CI bot decide *whether to attempt a build* against the new library version before kicking off a 30-minute compile + VICE test cycle.

These match the c64-https-side `.import __<MEMORY>_SIZE__` pattern: consumer cfg derives "is there room for this library in my CRYPTO_HOT region" without humans editing the cfg.

**Definition of done**: equates exported, documented in API.md §8.5 alongside the existing `LIB_VERSION_*` discussion. Same equates added to c64-x25519 and c64-ChaCha20-Poly1305 in follow-up issues against those repos (filed separately so each library can land independently).

---

Summary of which issues to file where:

| Library | Already filed (by wireguard) | New (by c64-https) |
|---|---|---|
| c64-nist-curves | — | A (minimal archives), B (segment rename), E (manifest equates) |
| c64-x25519 | #43 (REU config), #44 (`.exportzp`) | C (`LIB_VERSION_*`) |
| c64-ChaCha20-Poly1305 | #26 (`.exportzp`) | D (`LIB_VERSION_*`); E-equivalent later |

c64-https will *cross-link* wireguard's filings in its own filings so library maintainers see one consumer contract.

## 4. c64-https-side work items

Suitable to file as GitHub issues against `JC-000/c64-https`. Each is sized for a discrete PR.

### W1 — Cfg restructure: hot/cold partition under UCI

**Scope:** Split `cfg/c64-https-uci.cfg`'s `CRYPTO_RESIDENT` ($6000-$BFFF, 24 KB) into `CRYPTO_HOT` ($6000-$9FFF, 16 KB) and `CRYPTO_COLD_SHADOW` ($A000-$BFFF, 8 KB, under-BASIC-ROM RAM). Move ChaCha20-Poly1305 + SHA-256 + HKDF + TLS state machine + HTTP + record I/O into CRYPTO_HOT; move ECDSA-verify dispatcher, X25519 ECDH glue, per-curve scratch BSS into CRYPTO_COLD_SHADOW. CRYPTO_OVERLAY ($4200-$5FFF, 7.5 KB) absorbs all cold-path *code* via REU-paged overlays.

**Expected output:** `build/c64-https.prg` builds clean under `BACKEND=uci`. Smoke tests (`test_https_local.py`, `test_https_local_p384.py`) PASS. `build/labels.txt` shows CRYPTO_HOT under-allocated by ≥1 KB.

**Dependencies:** None; this work is c64-https-internal.

### W2 — Cfg restructure: equivalent split under ip65 backend

**Scope:** Same as W1 but for `cfg/c64-https-ip65.cfg`. Reclaim `NET_BSS_TAIL` ($4F8C-$5FFF, ~4.1 KB) as `CRYPTO_OVERLAY_IP65`. Confirm that with TLS_CODE + sha256 *back* in CRYPTO_HOT (instead of NET_BSS_TAIL), CRYPTO_HOT still fits in 16 KB.

**Expected output:** `make BACKEND=ip65` PRG builds clean, `make USE_X25519_SIBLING=1 BACKEND=ip65` now builds clean too (closes the long-standing ip65 sibling-fit issue), `test_phase3_https_1mhz.py` PASSes.

**Dependencies:** W1 (proves the hot/cold split works) and Issue A/B (smaller P-256 verify archive that fits in 4 KB overlay slot).

### W3 — Overlay infrastructure extension

**Scope:** Extend `src/crypto/shared/crypto_swap.s` with:
- `crypto_swap_to_x25519` — real DMA from REU bank 3 (X25519 sibling code + rodata) into the live overlay slot. Today this is a state-only marker; the X25519 sibling rodata is linker-placed at PRG load time and lost after the first P-384 swap. The new entry point recovers it via DMA.
- `crypto_swap_to_p256_verify` — DMA from REU bank 2 offset $1F00 (new slot) into the live overlay slot.
- `crypto_overlay_call(<id>, <fn_offset_in_slot>)` — convenience wrapper: swap, JSR to slot base + offset, return.
- Boot-time stash: `src/boot.s::reu_p384_overlay_init` extends to also DMA the X25519 sibling image and the P-256 verify image into their REU homes at boot. `tools/integration/build_*.sh` already produces the matching `.bin` files via `build_nistcurves_p384_bin.sh`; analogous bins get produced for P-256 and X25519.

**Expected output:** Handshake completes end-to-end with up to 4 overlay swaps (X25519 → P-256 verify, or X25519 → P-384 sha384 → P-384 curve). Wall-clock cost: each swap is one 8-KB REU→C64 DMA at ~1 MHz REU bus speed ≈ 8 ms. Four swaps = ~32 ms total. P-256-cert handshake (currently 81.9 s on U64E 48 MHz) gets +16 ms — measurement-noise-level.

**Dependencies:** W1 (CRYPTO_OVERLAY slot is the swap target).

### W4 — Library manifest consumer

**Scope:** Replace hardcoded sizes in cfgs with `__<SEGMENT>_SIZE__` markers. Add a build-time post-link diagnostic (`tools/diag/print_segment_fill.py`) that prints "CRYPTO_HOT: 14,832 / 16,384 B used (1,552 B free)" for the CI bot to grep. Add assemble-time `.assert LIB_NISTCURVES_ZP_USAGE_BYTES + LIB_X25519_ZP_USAGE_BYTES + LIB_HTTPS_ZP_USAGE_BYTES <= 192` (or similar) to `src/crypto/shared/zp_canon.inc` so a future library bump that grows ZP claim fails at link time, not at runtime.

**Expected output:** Build prints fill report. ZP collision detection works under all combinations (BACKEND × USE_X25519_SIBLING).

**Dependencies:** Issue E (library-side ZP/REU usage equates landed). Until those land, W4 uses a hand-maintained `LIB_*_ZP_USAGE_BYTES` table in `src/crypto/shared/lib_manifest.inc`.

### W5 — Integration script removal

**Scope:** Delete `tools/integration/build_nistcurves_p256.sh`, `build_nistcurves_p384.sh`, `build_x25519.sh`. Replace with `make -C libs/<x> lib-<variant>` invocations in the top-level Makefile. Keep `build_nistcurves_p384_bin.sh` for now (it's a *padding* step, not a *strip* step — it pads the archive to the live overlay slot size for DMA alignment; once library publishes pre-padded `.bin` outputs this script also goes away).

**Expected output:** `make clean && make` produces identical PRG to today (modulo new segment names). `git rm` removes ~1500 lines of fragile shell.

**Dependencies:** Issues A, B, C, D landed in the libraries.

### W6 — Test harness updates: deterministic VICE config

**Scope:** Centralize `ViceConfig(..., extra_args=["-reu", "-reusize", "512"])` into a helper at `tools/_vice_helpers.py::default_vice_config()`. Today this is duplicated across `tools/test_x509.py:769`, `tools/test_ecdsa_kat_oracle.py:293`, `tools/test_x25519.py:722`, `tools/bench_x25519.py:138`, `tools/test_p384_symbols.py:370`. Memory `vice_reu_required_for_p256` is the canonical motivation. With the hot/cold split, *every* test that exercises crypto needs `-reu`, so the default should be the helper.

**Expected output:** New tests get correct VICE config by default. Existing tests pass; existing call sites get refactored to use the helper.

**Dependencies:** None.

### W7 — Test harness updates: U64E queue conventions

**Scope:** Memorialize the U64E shared-queue conventions in `tools/uci/_device_lock_helper.py`. Today `tools/uci/_memory_policy.py` (408 lines) handles memory; we need an equivalent for device-time. The CI bot needs to know: "if DeviceLock queue depth ≥ 3, abort and reschedule" so a stuck job from a sibling project doesn't deadlock the CI for hours. Reference `u64e_shared_queue` memory.

**Expected output:** CI bot exits cleanly with "queue too deep, retry later" instead of waiting indefinitely. Existing `tools/uci/*.py` keep working unchanged (they're interactive use; only the CI-bot driver needs the retry budget).

**Dependencies:** None.

## 5. CI/CD pipeline design

### 5.1 Triggers

**Primary:** GitHub Actions workflow on `JC-000/c64-https`, triggered by:
- `repository_dispatch` event sent by each library's "release" workflow on tag push (preferred — propagates within minutes).
- Daily `schedule: cron` at, say, 06:00 UTC (fallback — catches anything that missed the dispatch).

**Bumping:** workflow checks out c64-https, fetches `libs/<x>` tags, picks the latest stable tag (skips pre-release tags by default), commits the submodule SHA bump on a branch `auto/bump-<lib>-<ver>`.

### 5.2 Build matrix

Four cells:

| Cell | `BACKEND` | `USE_X25519_SIBLING` |
|---|---|---|
| 1 | ip65 | 0 |
| 2 | ip65 | 1 |
| 3 | uci | 0 |
| 4 | uci | 1 |

Each runs `make clean && make` under the matrix cell. Build failures here are the cheap-to-detect failures — they happen in the GitHub runner without needing any C64-specific hardware.

### 5.3 Test matrix

After all four cells build clean:

**Tier 1 — VICE (fast, deterministic, ~5-10 minutes):**
- Runs in the GitHub runner with VICE installed.
- All `tools/test_*.py` scripts (`test_entropy.py`, `test_hkdf.py`, `test_chained_hmac.py`, `test_keyschedule_steps.py`, `test_tls_handshake.py`, `test_http.py`, `test_x509.py`, plus crypto-specific tests). Uses W6's centralized REU helper.
- Determinism: `-warp` mode + fixed seeds where possible. Some tests use unseeded `secrets.token_bytes()` — replace with seeded RNG for CI runs.

**Tier 2 — U64E (slow, gated, ~10-90 minutes):**
- Runs on self-hosted runner with LAN access to the U64E (probably `192.168.1.81` per the project memory).
- Acquires DeviceLock via `c64-test-harness` (queue-aware). If queue depth exceeds threshold (W7), skip with `:warning: queue busy, skipping U64E tier; will retry in 6h`.
- `tools/uci/test_https_local.py`, `test_https_local_p384.py`, `phase3_tcp_echo.py`, `boot_check.py`.
- Wall-clock budgets per CLAUDE.md: ~82 s P-256 handshake, ~7 min P-384 handshake.

### 5.4 U64E hardware contention

The U64E (10.43.23.81 per `u64e_shared_queue` memory) is shared with c64-aes256-ecdsa, c64-wireguard, c64-nist-curves's own bench harness, etc. The c64-test-harness `DeviceLock` is queue-aware: agents queue, get a position, wait. CI is just another agent.

**Conventions for the CI bot (memorialized in W7):**
- First-line log: "DeviceLock queue position: N" so the supervisor can distinguish queued / in-flight / wedged from the workflow log alone.
- Hard timeout: if not granted lock within 30 min, abort with "queue saturated; will retry next cron tick" rather than blocking the runner. The retry happens 6 hours later on the daily cron.
- Never force-reboot the U64E. Never `pkill` a sibling project's harness process.
- Surface queue depth in PR descriptions: `**U64E status:** in queue at position 2; estimated wait 12 min` so the user can decide to wait or merge ip65-only.

### 5.5 Reporting

**Success path (all four build cells + Tier 1 + Tier 2 pass):**
- PR opened with title `bump: <lib> v<old> → v<new>`.
- PR body includes: VICE test summary, U64E test summary, wall-clock deltas (e.g., `P-256 handshake: 81.9 s → 82.3 s (+0.4 s, within noise)`), segment fill report from W4 (`CRYPTO_HOT: 14,832 / 16,384 B (90.5% full)`), library `LIB_VERSION_*` confirmation.
- Auto-merge requires manual approval (the user). Even green PRs sit until a human green-lights.

**Tier 1 success, Tier 2 timeout (queue busy, U64E unreachable):**
- PR opened with `:warning: U64E tier deferred; VICE-only verified` annotation. Next daily cron tick retries Tier 2 on the merged PR's commit; on success a follow-up comment "U64E verified at 06:14 UTC" is added.

**Build or VICE failure:**
- No PR opened. Workflow comments on the *library's* corresponding tag with `c64-https build failed on <lib> v<new>; see <workflow url>`. Library maintainers see the consumer-side breakage on the same page as the release.
- A reproducer is attached: `build/c64-https.map`, `build/labels.txt`, ld65 stderr, test output. The CI bot's job is to make root-cause debug-from-scratch unnecessary.

### 5.6 Concrete tools

- **GitHub Actions** for the orchestration. The repo already uses `gh` in interactive workflows; the bot uses the same CLI surface.
- **Self-hosted runner** (a Mac or Linux box on the user's LAN). Has VICE installed, has Python with `c64-test-harness` installed, has SSH-or-direct LAN access to the U64E at 10.43.23.81.
- **`gh pr create`** wrapping per `tools/integration/worktree_merge.sh`'s pattern (already in-repo for human use).
- **Submodule bump** via `git submodule update --remote --merge libs/<x> && git -C libs/<x> checkout v<new>`.

### 5.7 What the bot does NOT do

- It does not edit cfgs. That's W4's job — the cfg references segment-marker symbols, not numbers, so a library bump that grows by 200 B either fits or surfaces "CRYPTO_HOT overflow by 200 B" as a build error. The bot opens the failing PR; the human (or a subsequent design pass) decides where to make room.
- It does not silently force-merge. Even green PRs require user approval (the user explicitly wants this — see the user's instruction "open PRs without manual cfg patching", not "merge PRs without review").
- It does not touch the U64E firmware. No reboots, no reconfig, no jumping the queue.

## 6. Sequencing

The contract is the foundation; everything else stacks on top of it. The strategy is to *file all library-side issues immediately and concurrently* (so library agents can land them in parallel), while c64-https-side work proceeds in parallel on the non-blocked items.

| Step | Deliverable | Side | Depends on |
|---|---|---|---|
| 0 | This document committed to `docs/library-ingestion-architecture.md`; cross-linked to c64-wireguard's #43/#44/#26 | c64-https | — |
| 1a | File Issue A (nistcurves minimal archives) | nistcurves | — |
| 1b | File Issue B (nistcurves segment rename) | nistcurves | — |
| 1c | File Issue C (x25519 LIB_VERSION) | x25519 | — |
| 1d | File Issue D (ChaCha20-Poly1305 LIB_VERSION) | ChaCha20-Poly1305 | — |
| 1e | File Issue E (nistcurves manifest equates); follow-on for x25519 + ChaCha20 | all three | — |
| 2a | W6 — VICE REU helper | c64-https | — (can land independently) |
| 2b | W7 — U64E queue conventions | c64-https | — |
| 2c | W3 — Overlay infrastructure (real X25519 + P-256 swap) | c64-https | — (uses existing 7.5 KB UCI slot) |
| 3 | W1 — Cfg restructure UCI (hot/cold split) | c64-https | W3 |
| 4 | wireguard #43 (REU config) + #44 (`.exportzp`) + #26 (chacha `.exportzp`) lands | libraries | step 1 (filed; libraries' work) |
| 5 | Issues C + D land (LIB_VERSION across siblings) | libraries | step 1 |
| 6 | Issue B lands (segment rename) | nistcurves | step 1 |
| 7 | Issue A lands (minimal archives) | nistcurves | step 6 (segment names) |
| 8 | Issue E lands (manifest equates) | libraries | step 1 |
| 9 | W4 — c64-https consumes manifest equates; cfg uses segment markers | c64-https | steps 4, 5, 8 |
| 10 | W5 — Integration script removal | c64-https | steps 6, 7 |
| 11 | W2 — Cfg restructure ip65 (closes the long-standing X25519-sibling-on-ip65 issue) | c64-https | W5 (need smaller P-256 archive that fits in 4 KB ip65 overlay) |
| 12 | CI/CD bot enabled | c64-https | All of W1-W7 + all library issues landed |

This sequencing means:
- **Steps 1a-1e + 2a-2c happen the same day** as committing this doc — the library agents and c64-https-side concurrency-safe agents all kick off in parallel.
- **Step 3 (W1)** can start without waiting for the library issues because it only relies on the cfg structure already shipped (the 7.5 KB CRYPTO_OVERLAY slot under UCI).
- **Steps 9-11** are dependent on library-side completion; they're the long pole. With 4-5 library issues filed simultaneously, the library-team agents can land them in parallel rather than sequentially.
- **Step 12 (CI/CD bot)** is the capstone — it doesn't fire until everything underneath it works. This is intentional: a CI bot opening PRs against a fragile cfg is worse than no CI bot.

Realistically: library issues at ~1 day each, c64-https-side work items at ~1-3 days each, the whole thing wraps in ~2 weeks of concentrated work if library-team agents and c64-https agents are running in parallel. Could compress if library team uses worktrees per issue.

## 7. Risks + open questions

### 7.1 Performance: overlay swap cost

Each REU→C64 DMA at 7.5 KB takes ~8 ms (REU bus runs at ~1 MHz regardless of CPU speed; `src/crypto/shared/crypto_swap.s:18-19` documents this). Worst-case handshake under the new model:

- X25519 ECDH: 1 swap (8 ms)
- ECDSA P-256 verify: 1 swap (8 ms)
- ECDSA P-384 verify (if negotiated): 2 swaps for SHA-384 + curve (16 ms)

Total worst-case overlay cost per handshake: ~32 ms. Against today's 81.9 s P-256 handshake or ~7-min P-384 handshake, this is 0.04% — measurement-noise-level. Hot-path crypto (per-record AEAD) is *not* swapped, so no per-record overlay tax.

The only place to be careful: **don't swap inside a fast-path loop**. The current TLS state machine drives one swap per handshake-stage transition, which is the right granularity.

### 7.2 REU availability assumptions

UCI/U64E hardware: REU always present. ip65/VICE: requires `-reu` flag. The W6 helper closes this for new tests; existing tests already have it per `vice_reu_required_for_p256` memory. The new overlay paths *make this even more critical* — without REU, every overlay swap silently no-ops. This needs a runtime guard at boot: detect REU presence by probing `$DF00`, and if absent, panic-print "REU REQUIRED" and halt rather than continuing to a handshake that will silently corrupt. Currently the boot code does not check.

### 7.3 U64E shared-hardware contention

Real risk. The CI bot must respect the queue (W7); a poorly-implemented CI bot could lock out interactive users for hours. Mitigations in §5.4 — but worth flagging explicitly in the bot's deploy README.

### 7.4 Breaking changes to `src/crypto_abi.inc`

The public crypto ABI (`x25519_scalarmult`, `ecdsa_verify_256`, `chacha20_encrypt`, `aead_*`, `sha256_*`) is *consumer-facing*. TLS sources `.import` from `src/crypto_abi.inc` and never branch on implementation. As long as the libraries continue exporting the same symbol names — which they do, by design, and Issues C/D pin via `LIB_VERSION_*` — the TLS call sites are stable.

Where breakage *could* leak in: if a library renames an internal symbol that c64-https's integration script depends on. Issue A's minimal-subset archives close this by making the published symbol set explicit (`ar65 v` is reproducible), and Issue E's manifest equates let the CI bot assert "library still exports the symbols we need" at assemble time before the link.

### 7.5 P-384 already on the slot edge

P-384 curve overlay is 7,317 B unpadded (per `crypto_swap.s` comments); the live slot is 7,680 B (`OVERLAY_SIZE = $1E00`). Margin: 363 B. Any defensive-init bytes added to nistcurves' P-384 code path (the same "+6 cycles per call" defence pattern that bloated v0.2.0) could overflow.

This is exactly the *kind* of failure the new architecture turns from "manual cfg surgery" into "CI bot opens PR titled :warning: P-384 overlay overflow by N bytes, attached map". The user reviews the PR, decides whether to (a) bump OVERLAY_SIZE and shrink another overlay, (b) defer the library bump, (c) ask the library maintainer to land a code-size pass first. None of those answers require humans to read 700 lines of `sed`.

### 7.6 ip65 backend remains structurally smaller

Even after W2, the ip65 overlay slot is ~4 KB vs UCI's 7.5 KB. This means:
- Under ip65, only X25519 + P-256 verify minimal-archive variants fit. P-384 stays out.
- The c64-https feature matrix is `BACKEND × cipher_suite`: UCI supports ECDSA-P256 + ECDSA-P384; ip65 supports ECDSA-P256 only.

This is *already true today* (CLAUDE.md:131: "ip65 backend does NOT embed the P-384 split overlay blobs"). W2 codifies it rather than introducing it.

### 7.7 The `c64-aes256-ecdsa` and `c64-polyval` projects exist

`/Users/someone/Documents/c64-aes256-ecdsa` and `/Users/someone/Documents/c64-polyval` exist as sibling projects. They are not c64-https dependencies today but they may become future libraries (AES-256 + ECDSA-P256 for a future TLS 1.2 / legacy-server compatibility path; POLYVAL for AES-GCM-SIV). The library manifest contract is forward-compatible — when a future `c64-https` adopts c64-aes256-ecdsa as a sibling, the same `LIB_VERSION_*` + `.exportzp` + segment-naming pattern applies.

### 7.8 Open question — should the manifest become a cross-project standard doc?

c64-https + c64-wireguard now jointly need the same library contract. Worth asking the user: should the spec land in *one* of the consumer projects, in a separate "c64-crypto-abi" repo, or as a section in each library's `API.md`? The current plan parks it in `docs/library-ingestion-architecture.md` (this file), with library-side issues cross-linked between consumers — but a future "the spec lives at <stable URL>" reference would be a smaller move once the contract stabilizes. Defer that decision until after Issues A-E close.

## Appendix — Status as of 2026-05-23

This document was written on 2026-05-20 as a forward-looking plan. The cross-project contract has since landed at [JC-000/c64-lib-contract](https://github.com/JC-000/c64-lib-contract) as `SPEC.md` (answering §7.8 — the spec lives in a dedicated repo, not in either consumer). Adopter and consumer work has progressed in parallel; this appendix snapshots which items have shipped vs. are still in-flight.

### Library-side issues — status

| Issue | Status | Note |
|---|---|---|
| c64-x25519 #43 (REU config) | landed | absorbed into c64-x25519 v0.6.0 + c64-lib-contract SPEC §8.1 adoption |
| c64-x25519 #44 (`.exportzp`) | landed | same v0.6.0 release |
| c64-ChaCha20-Poly1305 #26 (`.exportzp`) | landed | not yet consumed by c64-https — in-tree ChaCha20-Poly1305 is permanent |
| Issue A (nistcurves minimal archives) | landed | `make -C libs/nistcurves lib-p256-verify` / `lib-p384-verify` / `lib-p384-sha384` / `lib-p384-curve` ship in v0.3.0 |
| Issue B (nistcurves segment rename) | landed | `LIB_NISTCURVES_*` segment names in v0.3.0; cfg routes them by name |
| Issue C (x25519 `LIB_VERSION_*`) | landed | v0.5.0+ |
| Issue D (ChaCha20-Poly1305 `LIB_VERSION_*`) | landed | filed and absorbed |
| Issue E (nistcurves manifest equates) | landed | per SPEC §8.1 |

### c64-https-side work items — status

| Item | Status | PR / commit |
|---|---|---|
| W1 — Cfg restructure UCI (hot/cold split) | landed | PR #55 (cfg/c64-https-uci.cfg: CRYPTO_HOT $6000-$9FFF + CRYPTO_COLD_SHADOW $A000-$BFFF) |
| W2 — Cfg restructure ip65 | partial | PR #55 landed the ip65 cfg in W1-partial form; `LIB_NISTCURVES_P256_BSS` overflows CRYPTO_COLD_SHADOW by 1,662 B under ip65, tracked at [c64-nist-curves#54](https://github.com/JC-000/c64-nist-curves/issues/54) (Task #12 — library-side minimal-archive variant) |
| W3 — Overlay infrastructure extension | partial | PR #55 ships the W3 P-256 overlay slot under EMBED_P256_OVERLAY=1; X25519 / P-256 verify swap dispatchers landed; reu_p384_overlay_init extension still aspirational |
| W4 — Library manifest consumer | partial | segment markers (`__<SEGMENT>_SIZE__`) used in cfg post-W1; assemble-time `.assert` ZP collision guard is future work |
| W5 — Integration script removal | landed | `tools/integration/build_nistcurves_p{256,384}.sh` / `build_x25519.sh` now are thin `make -C libs/<X> lib-<VARIANT>` wrappers (PR #55); legacy sed-strip retired |
| W6 — VICE REU helper | landed | PR #53 (`tools/_vice_helpers.py::default_vice_config()`); all in-tree VICE tests routed through it |
| W7 — U64E queue conventions | landed | PR #53 (DeviceLock queue-budget helper) |

### Outstanding work

- **Task #12** — fix ip65 `LIB_NISTCURVES_P256_BSS` overflow via library-side minimal-archive variant (tracked at [c64-nist-curves#54](https://github.com/JC-000/c64-nist-curves/issues/54)).
- **P-384 wall-clock measurement** — still owed in CLAUDE.md's "ECDSA P-384 verify wall-clock" subsection; the dispatcher works on hardware but a clean end-to-end wall-clock has not yet been captured.
- **CI/CD bot (§5)** — design is documented; implementation is post-stabilisation.

Everything else described in this document either shipped via PRs #51-#55 or is operating in its target steady state.
