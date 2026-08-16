# Makefile — ca65/ld65 build for c64-https
#
# Replaces the original ACME-based build. ACME is no longer required.
#
# Targets:
#   make              — default, produces build/c64-https.prg + build/labels.txt
#   make clean        — remove build artifacts
#   make run          — launch the PRG in VICE x64sc
#   make ip65-libs    — build ip65 object libraries from the submodule
#                       (required once per fresh clone, BACKEND=ip65 only)
#   make ip65-blob    — rebuild ip65-build/ip65-c64.bin (requires ip65-libs first)
#
# Variables:
#   BACKEND=ip65|uci  — select networking backend config (default: ip65)
#   CA65, LD65        — ca65 / ld65 binaries (default: cc65 toolchain in PATH)
#   VICE              — VICE binary for `make run` (default: x64sc)

CA65      ?= ca65
LD65      ?= ld65
VICE      ?= x64sc
BACKEND   ?= ip65
CFG       := cfg/c64-https-$(BACKEND).cfg

# --- Sibling X25519 integration (Phase C.5, c64-x25519 v0.4.0) ---
# `USE_X25519_SIBLING=1` swaps in `build/lib/x25519.a` for the in-tree
# `src/crypto/fe25519.s` + `src/crypto/x25519.s` + in-tree X25519 data
# buffers from `src/data.s`. Default OFF — the in-tree implementation
# stays the shipped default until the supervisor + validator sign off
# on the sibling drop-in. The flag is read at link time; both code
# paths coexist on the branch so an A/B comparison is `make` vs
# `make USE_X25519_SIBLING=1`.
USE_X25519_SIBLING ?= 0

IP65_DIR     := ip65
IP65_BUILD   := ip65-build
IP65_BIN     := $(IP65_BUILD)/ip65-c64.bin

CA65FLAGS := -I src -I src/inc -I src/crypto/shared -I src/net/$(BACKEND) -I build --debug-info
# Binary-include search roots for `.incbin` (issue #116).
#
# `-I` above does NOT feed `.incbin` — that is a separate search path in ca65,
# and pointing `-I` at a blob directory fails with "Cannot open include file"
# even though the file is right there (measured, ca65 V2.18). Binary includes
# need `--bin-include-dir`.
#
# Why this exists at all: ca65 resolves a relative `.incbin` operand against
# the CURRENT DIRECTORY FIRST, falling back to the including source file's
# directory only if that misses. Every `.incbin` here used to be spelled
# `../../../<dir>/<file>` on the belief that source-relative was the rule. From
# the repo root those two interpretations coincide, so it worked — but an agent
# worktree lives at `.claude/worktrees/<name>/`, exactly three levels down, so
# `../../../` climbed straight out into the PRIMARY checkout and every worktree
# build silently embedded the primary's blob. The worktree's own freshly-built
# copy was never read, by anything, while make's dependency graph tracked it.
#
# ABSOLUTE paths, not relative: a relative root would be cwd-relative and would
# re-acquire the same class of bug the moment any recipe assembles from a
# subdirectory. `$(abspath ...)` pins these to make's own working directory.
# The operands in the sources are then written WITHOUT any `../`, so there is
# no escape hatch left to resolve. A missing blob now fails the assemble
# loudly instead of quietly resolving somewhere else.
CA65FLAGS += --bin-include-dir $(abspath $(IP65_BUILD))
CA65FLAGS += --bin-include-dir $(abspath build)
# Which backend is selected, as a ca65 define. Sources that must name a
# cfg-level symbol need this, because the two cfgs give the same region
# different names: the crypto code+rodata region is CRYPTO_HOT under UCI and
# CRYPTO_RESIDENT under ip65, so the ld65-published __<AREA>_SIZE__ symbol an
# `.import` has to spell differs by backend (src/contract_footprint_asserts.s
# is the current consumer). The `-I src/net/$(BACKEND)` path above cannot
# serve this: it carries net tuning, and region naming is a cfg property, not
# a networking one.
ifeq ($(BACKEND),uci)
CA65FLAGS += -D BACKEND_UCI=1
else
CA65FLAGS += -D BACKEND_IP65=1
endif
# Optional HTTPS target-port override (src/boot.s defaults to 443).
# `make HTTPS_PORT=4433` lets a test rig's TLS listener bind unprivileged.
ifdef HTTPS_PORT
CA65FLAGS += -D HTTPS_PORT=$(HTTPS_PORT)
endif
# VIC-II blanking around the CPU-bound crypto primitives (src/vic.s).
# ON by default and that is what ships; `make VIC_BLANK=0` degrades
# vic_blank/vic_unblank to bare RTS so the badline tax can be measured
# A/B with everything else in the image identical. That control build is
# a measurement tool, not a shipping configuration — see the "VIC-II
# blanking" section of CLAUDE.md for the numbers it produced.
ifeq ($(VIC_BLANK),0)
CA65FLAGS += -D NO_VIC_BLANK=1
endif
# Lazy (=) so the USE_NISTCURVES_ONCHIP_COMB block below can retarget
# CFG to the cfg variant after this line.
LD65FLAGS = -C $(CFG) -Ln build/labels.txt -m build/c64-https.map --dbgfile build/c64-https.dbg

# Source inventory.
TOP_SRCS    := $(wildcard src/*.s)
# Crypto sources: wildcard-discovered. In-tree src/crypto/x25519.s +
# src/crypto/fe25519.s are used under both backends; the Phase C.1
# libs/x25519/ overlay integration was rolled back after it broke the
# TLS handshake under BACKEND=uci at 48 MHz — see the commit that
# removed libs/x25519 for details.
# Phase C.4: the in-tree P-256 primitives (ecdsa_{curve,fp,mod,points}.s)
# were replaced by the sibling `libs/nistcurves/` P-256 integration
# (build/lib/nistcurves-p256.a). The now-unused files were physically
# deleted in Phase G. ecdsa_verify.s stays — rewritten as a thin
# dispatcher that packs the BE struct + calls ecdsa_verify_256.
CRYPTO_SRCS_ALL := $(wildcard src/crypto/*.s)
# Shared crypto infrastructure introduced in Phase C.0: canonical ZP map,
# overlay swap dispatcher, init orchestrator, shared sqtab stub. Always
# linked; sibling-lib integration (Phase C.3) hangs off these.
CRYPTO_SHARED_SRCS := $(wildcard src/crypto/shared/*.s)
IP65_SRCS   := src/net/ip65/ip65_blob.s src/net/ip65/net.s src/net/ip65/net_banner.s src/net/ip65/exports.s
UCI_SRCS    := src/net/uci/net.s src/net/uci/uci_cmd.s

# Sibling-lib archive set. Phase C.3's nistcurves-p384 archive remains an
# external overlay image (see below), not linked into the main PRG.
# Phase C.4 adds nistcurves-p256.a which IS linked in, always-resident,
# for BOTH backends (replaces the in-tree ecdsa_{curve,fp,mod,points}.s).
#
# USE_NISTCURVES_ONCHIP=1 (issue #69 / nistcurves v0.5.0): swap in the
# FP_ONCHIP_MUL turbo-profile archive — fp_mul/fp_sqr generate multiply
# rows on-chip instead of REU DMA row fetches, removing the ~1 MHz-anchored
# DMA floor on turbo hosts (crossover ~30 MHz; see CLAUDE.md "Why turbo
# stops paying"). Gates: data.s yields sqtab to the lib's $BC00 equates,
# poly1305.s provides the §8.3 canonical ct_mul_8x8 + SMC bake sites,
# boot.s skips reu_mul_init + yields the reu_fetch_mul_row export.
# USE_NISTCURVES_ONCHIP_COMB=1: comb-accelerated onchip profile — the
# comb ecdsa256 + points256_comb + Lim-Lee data replace the no-comb
# verifier (u1*G via 8-way fixed-base comb instead of a second
# variable-base ladder). Implies USE_NISTCURVES_ONCHIP; adds the
# ec_precompute_256 boot pass (REU bank 2 $0000-$3FFF anchors) and
# switches to the CRYPTO_HOT-relieving cfg variant.
ifeq ($(USE_NISTCURVES_ONCHIP_COMB),1)
USE_NISTCURVES_ONCHIP := 1
endif
ifeq ($(USE_NISTCURVES_ONCHIP),1)
ifeq ($(USE_X25519_SIBLING),1)
$(error USE_NISTCURVES_ONCHIP and USE_X25519_SIBLING are mutually exclusive for now: both archives export reu_fetch_mul_row)
endif
ifeq ($(USE_OVERLAY_P384_EMBED),1)
$(error USE_NISTCURVES_ONCHIP places LIB_NISTCURVES_MUL_CODE in CRYPTO_OVERLAY - mutually exclusive with USE_OVERLAY_P384_EMBED)
endif
ifeq ($(EMBED_P256_OVERLAY),1)
$(error USE_NISTCURVES_ONCHIP places LIB_NISTCURVES_MUL_CODE in CRYPTO_OVERLAY - mutually exclusive with EMBED_P256_OVERLAY)
endif
CA65FLAGS += -D USE_NISTCURVES_ONCHIP=1
ifeq ($(USE_NISTCURVES_ONCHIP_COMB),1)
SIBLING_LIB_ARCHIVES := build/lib/nistcurves-p256-onchip-comb.a
CA65FLAGS += -D USE_NISTCURVES_COMB=1
CFG := cfg/c64-https-$(BACKEND)-onchip.cfg
else
SIBLING_LIB_ARCHIVES := build/lib/nistcurves-p256-onchip.a
endif
else
SIBLING_LIB_ARCHIVES := build/lib/nistcurves-p256.a
endif

# Phase C.5 (USE_X25519_SIBLING=1): c64-x25519 v0.4.0 sibling, always-resident,
# replaces in-tree fe25519.s + x25519.s + X25519 buffers in src/data.s.
# Off by default.
ifeq ($(USE_X25519_SIBLING),1)
SIBLING_LIB_ARCHIVES += build/lib/x25519.a
# Propagate the flag to ca65 so src/data.s suppresses the in-tree X25519
# buffer declarations (the sibling's data_x25519_raw.s provides them).
CA65FLAGS += -D USE_X25519_SIBLING=1

# Split the sibling's code across CRYPTO_HOT and CRYPTO_OVERLAY. This is
# what makes USE_X25519_SIBLING=1 link at all under UCI, so it is a
# default rather than something the operator has to know.
#
# The sibling's 4,226 B of code does not fit either region whole:
# CRYPTO_HOT has ~3.3 KB of room for it (measured), and CRYPTO_OVERLAY
# has ~3.7 KB once the sibling's own 3,840 B of tables and BSS are in
# there. Leaving the ladder (717 B) and the boot-only table init (666 B)
# in CRYPTO_OVERLAY satisfies both. Under USE_X25519_SIBLING=1 that
# region is not a paged overlay -- both embed flags that page it are
# mutually exclusive with this one -- so it is plain resident RAM.
#
# X25519_RODATA is the wrong NAME for executable code; it is used only
# because it is the one segment both backend cfgs already route into
# CRYPTO_OVERLAY. The clean form is a cfg declaring the SPEC §4 names
# (LIB_X25519_CODE / LIB_X25519_INIT_CODE / LIB_X25519_DATA); at that
# point these two lines and the wrapper's sed both go away.
#
# ip65 does not link either way -- its CRYPTO_OVERLAY is 4,212 B and
# already holds TLS_CODE + CRYPTO_AUX_CODE, so X25519_RODATA overflows
# it by 2,048 B (2,816 B with these settings). See build_x25519.sh.
export X25519_INIT_SEGMENT ?= X25519_RODATA
export X25519_SEG_LADDER   ?= X25519_RODATA
endif

# Phase C.5: under USE_X25519_SIBLING=1, evict the in-tree X25519
# implementation from the link line — the sibling archive
# (build/lib/x25519.a) provides byte-compatible exports for x25519_*
# and a richer fe25519_* surface than the in-tree fe_* symbols.
ifeq ($(USE_X25519_SIBLING),1)
CRYPTO_SRCS_EFFECTIVE := $(filter-out src/crypto/fe25519.s src/crypto/x25519.s,$(CRYPTO_SRCS_ALL))
else
CRYPTO_SRCS_EFFECTIVE := $(CRYPTO_SRCS_ALL)
endif

# Per-backend source + object selection.
ifeq ($(BACKEND),ip65)
NET_SRCS := $(IP65_SRCS)
CRYPTO_SRCS := $(CRYPTO_SRCS_EFFECTIVE)
else ifeq ($(BACKEND),uci)
NET_SRCS := $(UCI_SRCS)
CRYPTO_SRCS := $(CRYPTO_SRCS_EFFECTIVE)

# --- W3: EMBED_P256_OVERLAY=1 stages the P-256 verify .bin as a
# .incbin into CRYPTO_OVERLAY at PRG-load time.  Mutually exclusive
# with USE_OVERLAY_P384_EMBED (same slot at $4200) — the rules below
# turn the P-384 SHA embed off when EMBED_P256_OVERLAY=1 to avoid
# overflowing the 7,680 B slot.  Default 0 so the un-flagged UCI
# build is byte-identical to today.
#
# Mirrors the P-384 USE_OVERLAY_P384_EMBED bootstrap pattern: the user-
# visible Make flag is `EMBED_P256_OVERLAY=1`; the ca65-level symbol
# `USE_OVERLAY_P256_EMBED` (which gates the .incbin in
# src/crypto/shared/p256_overlay_blobs.s) defaults to the same value
# but can be explicitly overridden via the command line for the
# bootstrap prelim link (avoids the overlay-bin <-> labels.txt cycle on
# a clean tree).  Bootstrap workflow:
#   make BACKEND=uci EMBED_P256_OVERLAY=1 USE_OVERLAY_P256_EMBED=0
#   make BACKEND=uci EMBED_P256_OVERLAY=1
EMBED_P256_OVERLAY ?= 0
USE_OVERLAY_P256_EMBED ?= $(EMBED_P256_OVERLAY)

# Phase 3: embed the two P-384 split overlay blobs in the PRG so boot
# can populate REU banks 6/7 at startup.  Gated to UCI (ip65 has no
# room for the SHA blob in main RAM) and to !USE_X25519_SIBLING (the
# sibling rodata occupies CRYPTO_OVERLAY at PRG load time, displacing
# the SHA blob).  Adds a build-order dep on the .bin files; a missing
# .bin causes the .incbin to fail, so we extend PRG_DEPS below.
ifneq ($(USE_X25519_SIBLING),1)
# Phase 5 Fix D: respect a command-line USE_OVERLAY_P384_EMBED=0 so the
# bootstrap rule below can do a no-overlay-embed prelim link to break
# the overlay-bin <-> labels.txt cycle on a clean tree.  Default is
# still 1 unless the operator explicitly disables it.  W3: also
# auto-turn-off when EMBED_P256_OVERLAY=1 (mutually-exclusive slot).
ifeq ($(EMBED_P256_OVERLAY),1)
USE_OVERLAY_P384_EMBED ?= 0
else
# W5 / libs/nistcurves cfa9085+ bump: PR #25's SHA-384 rotr LUTs
# (LIB_NISTCURVES_SHA384_TABLES, 3 KB page-aligned) push the SHA-384
# overlay-half archive above the 7.5 KB CRYPTO_OVERLAY slot limit by
# ~1.5 KB. Default flips to 0 until the SHA-384 LUTs are either:
#   - relocated out of the overlay slot (consumer-side path: route
#     LIB_NISTCURVES_SHA384_TABLES to a separate resident region and
#     teach the standalone overlay cfg to omit them from the .bin), or
#   - shrunk on the library side (eg by sharing rotr LUTs across the
#     8 shift amounts, or runtime-generating them at boot).
# Set USE_OVERLAY_P384_EMBED=1 explicitly to attempt the embed (will
# fail at link with an overflow until the SHA-384 LUTs are dealt with).
USE_OVERLAY_P384_EMBED ?= 0
endif
ifeq ($(USE_OVERLAY_P384_EMBED),1)
CA65FLAGS += -D USE_OVERLAY_P384_EMBED=1
endif
endif

# W3: propagate USE_OVERLAY_P256_EMBED to ca65 (the .incbin in
# src/crypto/shared/p256_overlay_blobs.s is gated on this).  The
# default-derivation from EMBED_P256_OVERLAY happens above.
ifeq ($(USE_OVERLAY_P256_EMBED),1)
CA65FLAGS += -D USE_OVERLAY_P256_EMBED=1
endif
# Phase C.3: add c64-nist-curves P-384 primitives as a REU overlay.
# Variable-base P-384 point ops (double/add/jacobian-to-affine) only —
# see tools/integration/build_nistcurves_p384.sh for the scope rationale.
# `USE_NISTCURVES_P384` toggles the `.ifdef` guard in
# src/crypto/p384_force_link.s so ld65 pulls the archive members into
# the final PRG. P-256 ECDSA stays in-tree under both backends.
# Phase C.3 is BLOCKED at the cfg level: the current CRYPTO_OVERLAY region
# (7.5 KB at $4200) can only hold one of OVERLAY_X25519 (3.4 KB) and
# OVERLAY_P384 (5.7 KB) at a time; ld65 lays them out sequentially and
# overflows by 1.6 KB. Architecturally max(x25519,p384)=5.7 KB ≤ 7.5 KB,
# so the slot is large enough — what's missing is the `run=CRYPTO_OVERLAY,
# load=<separate staging>` cfg plumbing plus a boot-time stash for both
# images. That restructure is out of scope for Phase C.3 and is gated on
# a supervisor OK. The archive + force-link stub are in place so the
# integration can be re-enabled by uncommenting the two lines below once
# the cfg is extended.
#CA65FLAGS += -D USE_NISTCURVES_P384=1
# Phase 1.5 split the monolithic nistcurves-p384.a into two halves
# (nistcurves-p384-sha384.a + nistcurves-p384-curve.a) since the
# combined image overflowed the live 7.5 KB CRYPTO_OVERLAY slot.
# Either-of approach for the production wire-up will be Phase 4a.
#SIBLING_LIB_ARCHIVES += build/lib/nistcurves-p384-sha384.a
#SIBLING_LIB_ARCHIVES += build/lib/nistcurves-p384-curve.a
else
$(error Unknown BACKEND=$(BACKEND); expected ip65 or uci)
endif

TOP_OBJS    := $(patsubst src/%.s,build/%.o,$(TOP_SRCS))
CRYPTO_OBJS := $(patsubst src/%.s,build/%.o,$(CRYPTO_SRCS))
CRYPTO_SHARED_OBJS := $(patsubst src/%.s,build/%.o,$(CRYPTO_SHARED_SRCS))
NET_OBJS    := $(patsubst src/%.s,build/%.o,$(NET_SRCS))

ALL_OBJS := $(TOP_OBJS) $(CRYPTO_OBJS) $(CRYPTO_SHARED_OBJS) $(NET_OBJS)

PRG    := build/c64-https.prg
LABELS := build/labels.txt

.PHONY: all link run clean ip65-libs ip65-blob package package-verify

all: $(PRG)

ifeq ($(BACKEND),ip65)
PRG_DEPS := $(ALL_OBJS) $(IP65_BIN) $(SIBLING_LIB_ARCHIVES)
else ifeq ($(BACKEND),uci)
PRG_DEPS := $(ALL_OBJS) $(SIBLING_LIB_ARCHIVES)
else
PRG_DEPS := $(ALL_OBJS)
endif

# Phase 3: when USE_OVERLAY_P384_EMBED is on, add the two .bin files
# to PRG_DEPS so make builds them before the .incbin in
# src/crypto/shared/p384_overlay_blobs.s tries to read them.
ifeq ($(USE_OVERLAY_P384_EMBED),1)
PRG_DEPS += build/lib/overlay-p384-sha384.bin build/lib/overlay-p384-curve.bin
PRG_DEPS += build/p384_overlay_equates.inc
build/crypto/shared/p384_overlay_blobs.o: build/lib/overlay-p384-sha384.bin build/lib/overlay-p384-curve.bin
endif

# W3: when USE_OVERLAY_P256_EMBED is on, add the P-256 verify .bin to
# PRG_DEPS so make builds it before the .incbin in
# src/crypto/shared/p256_overlay_blobs.s tries to read it.  The .bin
# rule below also has an order-only dep on build/labels.txt for the
# main-PRG label lookup (same bootstrap cycle as P-384).  Gated on the
# ca65-level USE_OVERLAY_P256_EMBED rather than EMBED_P256_OVERLAY so
# the bootstrap prelim link (with USE_OVERLAY_P256_EMBED=0) skips the
# .bin dep cleanly.
ifeq ($(USE_OVERLAY_P256_EMBED),1)
PRG_DEPS += build/lib/nistcurves-p256-verify.bin
build/crypto/shared/p256_overlay_blobs.o: build/lib/nistcurves-p256-verify.bin
endif

$(PRG): $(PRG_DEPS)
	@mkdir -p build
	$(LD65) $(LD65FLAGS) -o $@ $(ALL_OBJS) $(SIBLING_LIB_ARCHIVES)
	# Rewrite ca65 label format `al XXXXXX .name` -> VICE format `al C:XXXX .name`
	# so the c64-test-harness Labels.from_file() reader can parse it.
	sed -i '' 's/^al 00\([0-9a-fA-F]\{4\}\) /al C:\1 /' $(LABELS)
ifeq ($(USE_NISTCURVES_ONCHIP),1)
	# Onchip-profile invariant: the sibling's sqtab_lo/hi equates are
	# BAKED to $$BC00/$$BE00 (LIB_SHARED_SQTAB_BASE in the wrapper).
	# src/data.s owns sqtab_lo/hi, but the sibling reads the table through
	# its OWN equates derived from that base, so the two must agree on the
	# address. Drift is neither a link nor a boot failure — just every
	# multiply reading the wrong memory.
	@grep -q '^al C:BC00 \.sqtab_lo' $(LABELS) || \
		{ echo 'ERROR: sqtab_lo is not at $$BC00 — TABLES_BSS layout drifted; realign LIB_SHARED_SQTAB_BASE in tools/integration/build_nistcurves_p256.sh'; \
		  grep ' \.sqtab_lo$$' $(LABELS); exit 1; }
endif
ifeq ($(USE_X25519_SIBLING),1)
	# Same invariant, other sibling: build_x25519.sh bakes sqtab_lo/hi
	# into the sibling at X25519_SQTAB_BASE while in-tree sqtab_init
	# fills the real table wherever ld65 put it. Disagreement is neither
	# a link nor a boot failure, just a wrong shared secret. Rationale
	# and the $$B800-vs-$$BC00 history: tools/integration/build_x25519.sh.
	@grep -q '^al C:B800 \.sqtab_lo' $(LABELS) || \
		{ echo 'ERROR: sqtab_lo is not at $$B800 — TABLES_BSS layout drifted; realign X25519_SQTAB_BASE in tools/integration/build_x25519.sh'; \
		  grep ' \.sqtab_lo$$' $(LABELS); exit 1; }
endif

# Phase 5 Fix D: $(LABELS) is normally a side-effect of the $(PRG)
# link recipe; we don't add an explicit rule.  The overlay-bin rule
# below has an order-only dep on $(LABELS) so its lookup_label()
# resolves the main PRG's runtime mul_dma_lo / mul_dma_hi /
# mul_cached_a / reu_fetch_mul_row to real addresses (was: silent
# $0000 fallback that produced a curve overlay whose fp_mul_384
# read/wrote $0000 and silently corrupted downstream state).
#
# Bootstrap workflow (clean tree under USE_OVERLAY_P384_EMBED=1):
#   make BACKEND=uci USE_OVERLAY_P384_EMBED=0    # produce labels.txt
#   make BACKEND=uci                              # real link with overlays
# After this two-step bootstrap, plain `make BACKEND=uci` rebuilds
# incrementally without intervention.  The script
# tools/integration/build_nistcurves_p384_bin.sh prints a clear error
# pointing at this two-step procedure if it runs without labels.txt
# (vs the old silent $0000 stub fallback).


link: $(PRG)

build/%.o: src/%.s
	@mkdir -p $(dir $@)
	$(CA65) $(CA65FLAGS) -o $@ $<

# src/net/ip65/ip65_blob.s pulls the prebuilt ip65 image in with a ca65
# `.incbin`, which make's dependency graph cannot see. Without this edge
# make is free to assemble ip65_blob.s before the $(IP65_BIN) rule has
# run, and from a clean build/ it does exactly that — failing with
# "Cannot open include file '../../../ip65-build/ip65-c64.bin'" even
# though the very same `make` invocation builds the blob a few targets
# later. That is the fresh-clone failure in issue #89. Stating the edge
# explicitly forces the correct order; it changes no output bytes.
# (Only meaningful under BACKEND=ip65 — the UCI build never assembles
# this object, and never requests $(IP65_BIN).)
build/net/ip65/ip65_blob.o: $(IP65_BIN)

# Phase C.3: c64-nist-curves sibling archive (libs/nistcurves/ submodule).
# Phase 1.5 split: produces TWO archives, one per overlay half. The
# script writes both with a single invocation; the second target is a
# pseudo-rule that piggybacks on the first.
build/lib/nistcurves-p384-sha384.a build/lib/nistcurves-p384-curve.a:
	@mkdir -p build/lib
	bash tools/integration/build_nistcurves_p384.sh

# Phase C.4: c64-nist-curves P-256 archive — replaces the in-tree ECDSA
# P-256 primitives (ecdsa_{curve,fp,mod,points}.s) with the sibling's
# variable-base scalar mul + packaged ecdsa_verify_256. Always-resident;
# linked into the PRG under BOTH backends. See the build script for the
# full stripped-symbol list and the dispatcher (src/crypto/ecdsa_verify.s)
# for the 160-byte BE struct packing that bridges TLS to the sibling.
build/lib/nistcurves-p256.a:
	@mkdir -p build/lib
	bash tools/integration/build_nistcurves_p256.sh reu

# Onchip turbo-profile variant (issue #69). Same wrapper, onchip mode:
# builds upstream lib-p256-verify-onchip and rebuilds mul_8x8_onchip.o
# with the SHARED_* consumer defines + LIB_SHARED_SQTAB_BASE=$BC00.
build/lib/nistcurves-p256-onchip.a:
	@mkdir -p build/lib
	bash tools/integration/build_nistcurves_p256.sh onchip

# Comb-accelerated onchip variant: full onchip archive trimmed to the
# P-256 comb verify set (comb ecdsa256 + points256_comb + Lim-Lee data).
build/lib/nistcurves-p256-onchip-comb.a:
	@mkdir -p build/lib
	bash tools/integration/build_nistcurves_p256.sh onchip-comb

# Phase C.5: c64-x25519 v0.4.0 X25519 archive — replaces the in-tree
# fe25519.s + x25519.s + X25519 buffer declarations in src/data.s when
# USE_X25519_SIBLING=1. Linked into the PRG under BOTH backends. The
# sibling's reu_mul_init is called from src/boot.s in place of the
# in-tree REU mul table generator; sqtab_init is still served by the
# in-tree src/crypto/poly1305.s (sibling's mul_8x8.s is excluded from
# the archive to avoid duplicate-symbol with poly1305's mul_8x8).
build/lib/x25519.a:
	@mkdir -p build/lib
	bash tools/integration/build_x25519.sh

# Phase C.3b / Phase 1.5 split: P-384 overlay IMAGES + labels for
# harness-time use only.  The production PRG does NOT link
# nistcurves-p384-{sha384,curve}.a — these are smoke-test infrastructure.
# A future Phase 3 / Phase 4a harness will load both .bins into REU at
# test time, then DMA them into the live slot via two new swap entry
# points (crypto_swap_to_p384_sha384 / crypto_swap_to_p384_curve);
# the existing crypto_swap_to_p384 entry point is now stale -- see the
# comment block at the top of src/crypto/shared/crypto_swap.s.
#
# All four outputs (two .bins + two labels files) are produced by a
# single script invocation; the rule lists all four targets so make
# only runs the script once even when several are stale.
#
# Phase 5 Fix D: build/labels.txt is an ORDER-ONLY dependency.  The
# overlay-bin script's lookup_label() reads build/labels.txt to resolve
# mul_dma_lo / mul_dma_hi / mul_cached_a / reu_fetch_mul_row to the
# main PRG's runtime addresses (so the curve overlay's fp_mul_384
# reads/writes the right $BA00 / $BB00 / etc. cells).  On a clean
# build, build/labels.txt doesn't exist yet when this rule runs and the
# script falls back to $0000 stubs - silently producing an overlay
# image whose fp_mul_384 reads from $0000.  Order-only ('|') ensures
# labels.txt exists before the script runs but doesn't trigger an
# overlay rebuild on every main-PRG link.
build/lib/overlay-p384-sha384.bin build/lib/overlay-p384-curve.bin build/labels-p384-sha384.txt build/labels-p384-curve.txt: \
		build/lib/nistcurves-p384-sha384.a build/lib/nistcurves-p384-curve.a \
		cfg/p384-overlay-sha384.cfg cfg/p384-overlay-curve.cfg \
		tools/integration/build_nistcurves_p384_bin.sh \
		| build/labels.txt
	bash tools/integration/build_nistcurves_p384_bin.sh

.PHONY: p384-overlay
p384-overlay: build/lib/overlay-p384-sha384.bin build/lib/overlay-p384-curve.bin \
              build/labels-p384-sha384.txt build/labels-p384-curve.txt

# W3: P-256 verify overlay .bin (library-ingestion architecture).
# Mirrors the P-384 overlay .bin rule: depends on the P-256 sibling
# archive (build/lib/nistcurves-p256.a, already a default PRG dep) +
# the standalone overlay cfg.  Order-only dep on build/labels.txt for
# the lookup_label() fallback (same pattern as P-384 — see Fix D
# comment block above).
build/lib/nistcurves-p256-verify.bin build/labels-p256-verify.txt: \
		build/lib/nistcurves-p256.a \
		cfg/p256-overlay-verify.cfg \
		tools/integration/build_nistcurves_p256_bin.sh \
		| build/labels.txt
	bash tools/integration/build_nistcurves_p256_bin.sh

.PHONY: p256-overlay
p256-overlay: build/lib/nistcurves-p256-verify.bin build/labels-p256-verify.txt

# Phase 5 Fix C: regenerate the P-384 overlay-resident symbol equates
# (build/p384_overlay_equates.inc) from the overlay labels files so the
# TLS-side dispatcher (src/crypto/ecdsa_verify_384.s) picks up address
# changes via .include, with .assert pins catching drift.  Whenever
# either labels file is rebuilt, the .inc regenerates and the
# dispatcher .o is forced to rebuild.
build/p384_overlay_equates.inc: build/labels-p384-sha384.txt build/labels-p384-curve.txt \
                                tools/integration/gen_p384_overlay_equates.sh
	bash tools/integration/gen_p384_overlay_equates.sh \
	    build/labels-p384-sha384.txt build/labels-p384-curve.txt $@

# The dispatcher .o now depends on the generated equates file (via
# .include) AND on the overlay .bin files (PRG_DEPS already lists those
# under USE_OVERLAY_P384_EMBED).  Phase 5 Fix D: gate the .inc dep on
# USE_OVERLAY_P384_EMBED so the bootstrap rule for $(LABELS) (which
# sub-makes with USE_OVERLAY_P384_EMBED=0) can skip rebuilding the .inc
# from labels-p384-* (those depend on overlay-bins which depend on
# $(LABELS) -- cycle).  The bootstrap pre-creates a placeholder .inc
# before sub-making.
ifeq ($(USE_OVERLAY_P384_EMBED),1)
build/crypto/ecdsa_verify_384.o: build/p384_overlay_equates.inc
endif

# Build ip65 object libraries from the submodule. Required once per fresh
# clone — the submodule ships sources, and the ip65-blob link below needs
# the .lib archives this target produces. Re-run when the submodule moves.
ip65-libs:
	cd $(IP65_DIR) && $(MAKE) -C ip65 && $(MAKE) -C drivers

# Build the ip65 binary blob (ip65-build/ip65-c64.bin). The file is a
# gitignored build artifact (.gitignore: ip65-build/*.bin), NOT committed.
# `all` depends on it under BACKEND=ip65, so a normal `make` builds it once
# and then reuses it — `clean` only removes build/, so it survives.
ip65-blob: $(IP65_BIN)

$(IP65_BIN): $(IP65_BUILD)/ip65_stub.s $(IP65_BUILD)/ip65.cfg
	cd $(IP65_BUILD) && $(CA65) -I ../$(IP65_DIR) ip65_stub.s -o ip65_stub.o
	cd $(IP65_BUILD) && $(LD65) -C ip65.cfg -o ip65-c64.bin -m ip65-c64.map \
	    ip65_stub.o ../$(IP65_DIR)/ip65/ip65_tcp.lib \
	    ../$(IP65_DIR)/drivers/ip65_c64.lib c64.lib

run: $(PRG)
	$(VICE) -autostart $(PRG)

clean:
	rm -rf build

# Release packaging: build all four PRG variants (both backends x both crypto
# profiles), put each on its own D64 plus a per-backend D64, generate the
# single-file test listener, and write dist/MANIFEST.txt.
#
# The scripts run `make clean` between flag combinations themselves, so
# `package` deliberately depends on no build artifact — and re-running it after
# a submodule bump regenerates everything with no edits anywhere. Order
# matters: build_prgs.sh writes dist/build-info.txt and build_d64.sh writes
# dist/d64-listings.txt, both of which write_manifest.sh consumes.
#
# PACKAGE_PYTHON must be an interpreter that can run the listener's own
# selftest — see `make package-verify`.
#
# build_prgs.sh is three-valued: 0 = all variants built, 2 = PARTIAL, 1 = none.
# On PARTIAL the pipeline deliberately runs to completion anyway, so a single
# broken variant still yields disks, a listener and a manifest that names what
# is missing and why — then the target fails, because a partial matrix must
# never be mistaken for a release. `-` on the first line lets make continue;
# the status is recovered from the build-info records rather than from $?,
# which `-` discards.
PACKAGE_PYTHON ?= python3
package:
	-bash tools/package/build_prgs.sh
	@grep -q 'result=OK' dist/build-info.txt 2>/dev/null \
	    || { echo "[package] no variant built at all — nothing to package" >&2; exit 1; }
	bash tools/package/build_d64.sh
	$(PACKAGE_PYTHON) tools/package/build_listener.py
	bash tools/package/write_manifest.sh
	@if grep -q '^failreason=' dist/build-info.txt; then \
	    echo ""; \
	    echo "[package] ***** INCOMPLETE: the following variants did NOT build *****"; \
	    grep '^failreason=' dist/build-info.txt | cut -d= -f2- | sed 's/^/[package]   /'; \
	    echo "[package] dist/ holds the variants that DID build; see MANIFEST.txt."; \
	    echo "[package] Do not tag a release from this."; \
	    exit 1; \
	fi

# Acceptance gate for the release artifacts: rebuild every PRG a second time
# and compare PRG hashes, boot every D64 in VICE and assert the banner, and run
# the built listener end to end against a Python ssl client. Measures; does not
# assert. Run it after `make package`.
#
# The gate's own verdict logic is unit-tested first, and that ordering is the
# point: verify_release.py shipped with a bug where it reported RELEASE
# ARTIFACTS VERIFIED having checked nothing, so "the gate said yes" is only
# worth something if the gate's yes still means what it should. The tests need
# no VICE and no build; they cost milliseconds. A failure here stops the run
# rather than letting a broken verdict bless a release.
#
# tools/run_all_tests.py deliberately does not carry these: it allocates a VICE
# instance per suite and dispatches `run_tests(transport, labels, seed)`, a
# shape a pure-logic test does not fit. The gate is the right home for them.
package-verify:
	$(PACKAGE_PYTHON) tools/test_package_verify.py
	$(PACKAGE_PYTHON) tools/package/verify_release.py
