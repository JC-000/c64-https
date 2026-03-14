ACME = acme
CA65 = ca65
LD65 = ld65
VICE = x64sc

SRC_DIR = src
BUILD_DIR = build
IP65_BUILD = ip65-build
IP65_SRC = ip65

PRG = $(BUILD_DIR)/c64-https.prg
LABELS = $(BUILD_DIR)/labels.txt

# ACME sources
ASM_SRCS = $(wildcard $(SRC_DIR)/*.asm)

.PHONY: all clean run ip65

all: $(PRG)

$(PRG): $(ASM_SRCS) | $(BUILD_DIR)
	cd $(SRC_DIR) && $(ACME) -f cbm -o ../$(PRG) --vicelabels ../$(LABELS) main.asm

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

run: $(PRG)
	$(VICE) -autostart $(PRG)

# ip65 binary blob build (requires cc65 toolchain + ip65 submodule)
# Uncomment and adjust when ip65 submodule is added:
# ip65: $(IP65_BUILD)/ip65-c64.bin
#
# $(IP65_BUILD)/ip65-c64.bin: $(IP65_SRC)/ip65/*.s $(IP65_SRC)/drivers/*.s
# 	cd $(IP65_SRC) && make
# 	# TODO: link ip65_tcp.lib + c64rrnet.lib with custom config
# 	# $(LD65) -C $(IP65_BUILD)/ip65.cfg -o $@ ...

clean:
	rm -f $(BUILD_DIR)/c64-https.prg $(BUILD_DIR)/labels.txt
