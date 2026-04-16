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

CA65FLAGS := -I src -I src/inc -I src/net/$(BACKEND) --debug-info
LD65FLAGS := -C $(CFG) -Ln build/labels.txt -m build/c64-https.map

# Source inventory.
TOP_SRCS    := $(wildcard src/*.s)
CRYPTO_SRCS := $(wildcard src/crypto/*.s)
IP65_SRCS   := src/net/ip65/ip65_blob.s src/net/ip65/net.s src/net/ip65/net_banner.s src/net/ip65/exports.s
UCI_SRCS    := src/net/uci/net.s src/net/uci/uci_cmd.s

# Per-backend source + object selection.
ifeq ($(BACKEND),ip65)
NET_SRCS := $(IP65_SRCS)
else ifeq ($(BACKEND),uci)
NET_SRCS := $(UCI_SRCS)
else
$(error Unknown BACKEND=$(BACKEND); expected ip65 or uci)
endif

TOP_OBJS    := $(patsubst src/%.s,build/%.o,$(TOP_SRCS))
CRYPTO_OBJS := $(patsubst src/%.s,build/%.o,$(CRYPTO_SRCS))
NET_OBJS    := $(patsubst src/%.s,build/%.o,$(NET_SRCS))

ALL_OBJS := $(TOP_OBJS) $(CRYPTO_OBJS) $(NET_OBJS)

PRG    := build/c64-https.prg
LABELS := build/labels.txt

.PHONY: all link run clean ip65-libs ip65-blob

all: $(PRG)

ifeq ($(BACKEND),ip65)
PRG_DEPS := $(ALL_OBJS) $(IP65_BIN)
else
PRG_DEPS := $(ALL_OBJS)
endif

$(PRG): $(PRG_DEPS)
	@mkdir -p build
	$(LD65) $(LD65FLAGS) -o $@ $(ALL_OBJS)
	# Rewrite ca65 label format `al XXXXXX .name` -> VICE format `al C:XXXX .name`
	# so the c64-test-harness Labels.from_file() reader can parse it.
	sed -i 's/^al 00\([0-9a-fA-F]\{4\}\) /al C:\1 /' $(LABELS)

link: $(PRG)

build/%.o: src/%.s
	@mkdir -p $(dir $@)
	$(CA65) $(CA65FLAGS) -o $@ $<

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
