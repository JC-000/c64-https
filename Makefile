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
# Crypto sources: wildcard-discovered, minus any files explicitly swapped
# out under a sibling-lib integration. Phase C.1 drops in-tree
# src/crypto/x25519.s + src/crypto/fe25519.s under BACKEND=uci in favour
# of libs/x25519/.
CRYPTO_SRCS_ALL := $(wildcard src/crypto/*.s)
# Shared crypto infrastructure introduced in Phase C.0: canonical ZP map,
# overlay swap dispatcher, init orchestrator, shared sqtab stub. Always
# linked; sibling-lib integration (Phase C.1-.3) hangs off these.
CRYPTO_SHARED_SRCS := $(wildcard src/crypto/shared/*.s)
IP65_SRCS   := src/net/ip65/ip65_blob.s src/net/ip65/net.s src/net/ip65/net_banner.s src/net/ip65/exports.s
UCI_SRCS    := src/net/uci/net.s src/net/uci/uci_cmd.s

# Sibling-lib archive set. Phase C.1 adds the x25519 archive under UCI.
SIBLING_LIB_ARCHIVES :=

# Per-backend source + object selection.
ifeq ($(BACKEND),ip65)
NET_SRCS := $(IP65_SRCS)
CRYPTO_SRCS := $(CRYPTO_SRCS_ALL)
else ifeq ($(BACKEND),uci)
NET_SRCS := $(UCI_SRCS)
# Phase C.1: replace in-tree x25519.s + fe25519.s with libs/x25519/.
# `USE_X25519_SIBLING` toggles every `.ifdef USE_X25519_SIBLING` guard
# that skips the in-tree duplicates in data.s / boot.s / x25519_aliases.s.
CRYPTO_SRCS := $(filter-out src/crypto/x25519.s src/crypto/fe25519.s,$(CRYPTO_SRCS_ALL))
CA65FLAGS += -D USE_X25519_SIBLING=1
SIBLING_LIB_ARCHIVES += build/lib/x25519.a
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
PRG_DEPS := $(ALL_OBJS) $(IP65_BIN)
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
	sed -i 's/^al 00\([0-9a-fA-F]\{4\}\) /al C:\1 /' $(LABELS)

link: $(PRG)

build/%.o: src/%.s
	@mkdir -p $(dir $@)
	$(CA65) $(CA65FLAGS) -o $@ $<

# Phase C.1: c64-x25519 sibling archive (libs/x25519/ submodule).
# Builds only under BACKEND=uci per the SIBLING_LIB_ARCHIVES gate above;
# ip65 builds continue to use the in-tree src/crypto/x25519.s + fe25519.s.
# The build script lives in tools/integration/ (outside the submodule) to
# keep the submodule's working tree clean.
build/lib/x25519.a:
	@mkdir -p build/lib
	bash tools/integration/build_x25519.sh

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
