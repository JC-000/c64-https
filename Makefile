# Makefile — ca65/ld65 build for c64-https
#
# Replaces the original ACME-based build. ACME is no longer required.
#
# Targets:
#   make              — default, produces build/c64-https.prg + build/labels.txt
#   make clean        — remove build artifacts
#   make run          — launch the PRG in VICE x64sc
#   make ip65-libs    — rebuild ip65 object libraries from the submodule
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

IP65_DIR     := ip65
IP65_BUILD   := ip65-build
IP65_BIN     := $(IP65_BUILD)/ip65-c64.bin

CA65FLAGS := -I src -I src/inc -I src/crypto/shared -I src/net/$(BACKEND) --debug-info
LD65FLAGS := -C $(CFG) -Ln build/labels.txt -m build/c64-https.map

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
SIBLING_LIB_ARCHIVES := build/lib/nistcurves-p256.a

# Per-backend source + object selection.
ifeq ($(BACKEND),ip65)
NET_SRCS := $(IP65_SRCS)
CRYPTO_SRCS := $(CRYPTO_SRCS_ALL)
else ifeq ($(BACKEND),uci)
NET_SRCS := $(UCI_SRCS)
CRYPTO_SRCS := $(CRYPTO_SRCS_ALL)
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
#SIBLING_LIB_ARCHIVES += build/lib/nistcurves-p384.a
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

.PHONY: all link run clean ip65-libs ip65-blob

all: $(PRG)

ifeq ($(BACKEND),ip65)
PRG_DEPS := $(ALL_OBJS) $(IP65_BIN) $(SIBLING_LIB_ARCHIVES)
else ifeq ($(BACKEND),uci)
PRG_DEPS := $(ALL_OBJS) $(SIBLING_LIB_ARCHIVES)
else
PRG_DEPS := $(ALL_OBJS)
endif

$(PRG): $(PRG_DEPS)
	@mkdir -p build
	$(LD65) $(LD65FLAGS) -o $@ $(ALL_OBJS) $(SIBLING_LIB_ARCHIVES)
	# Rewrite ca65 label format `al XXXXXX .name` -> VICE format `al C:XXXX .name`
	# so the c64-test-harness Labels.from_file() reader can parse it.
	sed -i '' 's/^al 00\([0-9a-fA-F]\{4\}\) /al C:\1 /' $(LABELS)

link: $(PRG)

build/%.o: src/%.s
	@mkdir -p $(dir $@)
	$(CA65) $(CA65FLAGS) -o $@ $<

# Phase C.3: c64-nist-curves sibling archive (libs/nistcurves/ submodule).
# Same gating as x25519: only linked under BACKEND=uci; ip65 continues
# without P-384 entirely. Exports only the variable-base primitives
# (see the build script for the excluded symbols and why).
build/lib/nistcurves-p384.a:
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
	bash tools/integration/build_nistcurves_p256.sh

# Phase C.3b: P-384 overlay IMAGE + labels for harness-time use only.
# The production PRG does NOT link nistcurves-p384.a — this is smoke-test
# infrastructure. tools/test_p384_symbols.py loads overlay-p384.bin into
# REU at test time via a trampoline, then calls crypto_swap_to_p384 to
# page it into the live slot. Keeps the main PRG size unchanged.
#
# Both outputs live below build/; depend on the archive being built first.
build/lib/overlay-p384.bin build/labels-p384.txt: build/lib/nistcurves-p384.a cfg/p384-overlay.cfg tools/integration/build_nistcurves_p384_bin.sh
	bash tools/integration/build_nistcurves_p384_bin.sh

.PHONY: p384-overlay
p384-overlay: build/lib/overlay-p384.bin build/labels-p384.txt

# Build ip65 object libraries from the submodule. Only needed if the ip65
# submodule changes; the prebuilt blob is committed to ip65-build/.
ip65-libs:
	cd $(IP65_DIR) && $(MAKE) -C ip65 && $(MAKE) -C drivers

# Build the ip65 binary blob (ip65-build/ip65-c64.bin). The resulting file is
# committed to the repo so a normal `make` does not need to rebuild it.
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
