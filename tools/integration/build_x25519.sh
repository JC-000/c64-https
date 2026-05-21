#!/usr/bin/env bash
# =============================================================================
# tools/integration/build_x25519.sh - Build c64-x25519 v0.6.0
# X25519 primitives as a resident .a archive linked into the main PRG.
#
# Optional sibling-library integration (Phase C.5). Produces
# build/lib/x25519.a containing:
#   - fe25519 field arithmetic (fe25519_mul/sqr/inv/...)
#   - X25519 Montgomery ladder (x25519_scalarmult, x25519_clamp, x25519_base)
#   - x25519_init (reu_mul_init + REU DMA helpers reu_fetch_mul_row,
#     reu_fetch_doubled_row, reu_clear_wide)
#   - data buffers (x25_*, fe25519_tmp*, mul_*, sqr_*, a24_*, fe_p)
#   - util (vic_blank, vic_unblank, bench helpers — pulled in if referenced)
#
# Submodule pin: v0.6.0 (95fdd70) — adopts c64-lib-contract §8.1 (the
# canonical shared 1 KB quarter-square table) plus RAM reclamation in
# x25519_init.s (bank-2 stash removed) and bench rehab (bench_start/stop
# php/plp shape so jiffy-based benches measure real cycles again).
# Earlier contract-§1/§2/§3/§5 adoption landed in v0.4.0-7-g4d1c752 and
# remains in place: every ZP slot is `.exportzp`-ed (zp_config.s),
# LIB_VERSION_*/LIB_ABI_VERSION absolute exports (lib_version.s),
# X25519_REU_BANK configurable REU base (reu_config.s), and the
# LIB_X25519_* aggregate manifest equates.
#
# Activated only when `make USE_X25519_SIBLING=1`. Default is OFF; the
# in-tree src/crypto/fe25519.s + src/crypto/x25519.s remain the
# default implementation until the supervisor + validator sign off on
# the sibling integration. See PR description / commit message for
# the A/B test rollout plan.
#
# Excluded (replaced by in-tree equivalents):
#   - src/mul_8x8.s: in-tree src/crypto/poly1305.s already exports
#     mul_8x8 / sqtab_init / poly_prod_lo / poly_prod_hi / sqtab_lo /
#     sqtab_hi. Including the sibling's would duplicate symbols. The
#     two implementations are calling-convention-compatible
#     (A=multiplicand, X=multiplier → poly_prod_lo/hi). The in-tree
#     variant uses a small branch on the sum-page byte; the sibling's
#     is CT-clean via SMC patching. Using in-tree's is a CT regression
#     for the X25519 mul path; the supervisor's plan accepts this for
#     the integration smoke and defers a CT clean-up to a follow-up.
#     Under v0.6.0 §8.1 the sibling's mul_8x8 + the mult66 path inside
#     fe25519_sqr both resolve `sqtab_lo` / `sqtab_hi` against the
#     LIB_SHARED_SQTAB_BASE equate set via -D below; the equate is
#     `.ifndef`-guarded in libs/x25519/src/constants.s so passing
#     SHARED_SQTAB_INIT collapses the duplicate init body but keeps
#     the SHARED_SQTAB_BASE-derived loads pointing at c64-https's
#     resident table.
#   - src/main.s: the sibling's BASIC stub / test harness entry. We
#     have our own boot.s entry point.
#
# Memory: sibling code + rodata goes into CRYPTO_CODE / CRYPTO_RODATA;
# sibling BSS goes into TABLES_BSS (must stay < $A000 for the
# page-aligned mul_dma / sqr / a24 / fe25519_tmp / x25_* buffers).
#
# Usage (from top-level Makefile, gated by USE_X25519_SIBLING=1):
#   bash tools/integration/build_x25519.sh
# Produces:
#   build/lib/x25519.a
#   build/lib/x25519.sizes.txt  (per-source byte counts)
# =============================================================================
set -eo pipefail

# --- Paths ---
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB_SRC="$PROJECT_ROOT/libs/x25519/src"
STAGING="$PROJECT_ROOT/build/lib/x25519_staging"
OUT_DIR="$PROJECT_ROOT/build/lib"
ARCHIVE="$OUT_DIR/x25519.a"
SIZES="$OUT_DIR/x25519.sizes.txt"

CA65="${CA65:-ca65}"
AR65="${AR65:-ar65}"

# --- Canonical ZP defines ---
# The sibling's src/zp_config.s now wraps every library-owned ZP equate
# in `.ifndef <name>` AND `.exportzp`-s the symbol (issue #44, closes
# c64-lib-contract §2). c64-https uses the sibling's defaults — they
# are byte-compatible with the in-tree map under the following
# time-sharing analysis:
#
#   Sibling claim   In-tree slot at same addr     Time-share?
#   -------------   --------------------------    -----------
#   $14-$16         cc20_round/qr_idx/data_ptr    yes — ChaCha20 and
#                   (lmul0/lmul1 alias)            fe25519 never co-run
#                                                  by design in TLS
#   $1C             poly_carry                    yes — same role
#   $1E-$23         tls_rec_ptr/idx/dir, fp_src1  yes — TLS record state
#                                                  not live at the X25519
#                                                  call site in
#                                                  tls_ecdh_compute_shared;
#                                                  ECDSA (fp_src1) runs
#                                                  AFTER X25519 in the
#                                                  handshake (CertVerify
#                                                  follows ServerHello)
#   $24-$2A         fp_src2/dst/misc/carry/loop   yes — ECDSA-only,
#                                                  runs after X25519
#   $2C-$2F         fe_src1/src2/dst (in-tree     yes — in-tree fe25519
#                   fe25519 only)                  is dropped from the
#                                                  link under
#                                                  USE_X25519_SIBLING=1
#   $40-$7F         ZP_WIDE region (fe_wide)      yes — sibling's
#                                                  fe_wide pins here
#                                                  via .assert
#
# No ZP -D overrides needed — sibling defaults match c64-https's map.
ZP_DEFINES=()

# --- REU bank base pin ---
# c64-x25519 v0.4.0-7-g4d1c752 ships src/reu_config.s with a
# `.ifndef`-guarded X25519_REU_BANK equate (default $00) — issue #43,
# closes c64-lib-contract §3. The library claims six contiguous REU
# banks starting at X25519_REU_BANK (banks 0..5 at the default) for
# its precomputed mul / doubled / 17th-bit-carry tables.
#
# c64-https pins the base to bank 0, matching the in-tree layout in
# src/crypto/shared/reu_layout.inc:
#     REU_X25519_MUL_TABLES_BASE = $00000  (bank 0)
# The in-tree comment block at the bottom of reu_layout.inc enumerates
# the theoretical bank-3/4/5 collision with P-256/P-384 precompute
# reservations under USE_X25519_SIBLING=1; that collision remains
# theoretical only under the current TLS path. Passing X25519_REU_BANK
# explicitly (rather than relying on the library default) defends
# against a future c64-x25519 release bumping its default base.
#
# ca65 takes `-D <name>=<value>` for assemble-time symbol definitions
# (the library docs use "--asm-define" in prose but ca65 only supports
# the `-D` short form per `ca65 --help`).
REU_DEFINES=(-D X25519_REU_BANK=0)

# --- c64-lib-contract §8.1 shared sqtab adoption (v0.6.0) ---
# c64-https owns the canonical 1 KB quarter-square multiply table —
# `sqtab_lo` / `sqtab_hi` live at $BC00 / $BE00 in TABLES_BSS (see
# src/data.s), populated by src/crypto/poly1305.s::sqtab_init at boot.
#
# Pass LIB_SHARED_SQTAB_BASE so the sibling's mul_8x8.s + fe25519.s
# `mult66` path resolve `sqtab_lo` / `sqtab_hi` against the shared
# c64-https table rather than the sibling's $7800 default (which would
# fight c64-https's TABLES_BSS-resident copy at link time / runtime).
# The `.ifndef`-guarded equate in libs/x25519/src/constants.s
# (v0.6.0 §8.1 adoption) plus `.assert (sqtab_lo & $00ff) = 0` +
# `.assert sqtab_hi = sqtab_lo + $0200` catch a misconfigured base at
# assemble time rather than runtime.
#
# SHARED_SQTAB_INIT signals that the host program supplies the
# canonical `mul_tables_init` from a shared-primitives module
# (c64-https's poly1305.s::sqtab_init, aliased through
# src/crypto/shared/mul_tables.s). With the gate defined, the sibling's
# own `sqtab_init` body collapses to a no-op stub
# (libs/x25519/src/mul_8x8.s::sqtab_init .ifdef SHARED_SQTAB_INIT) so
# the two libs don't duplicate work.
SQTAB_DEFINES=(
    -D 'LIB_SHARED_SQTAB_BASE=$BC00'
    -D SHARED_SQTAB_INIT=1
)

# --- Stage sources ---
rm -rf "$STAGING"
mkdir -p "$STAGING"

cp "$LIB_SRC"/constants.s "$STAGING/"
# zp_config.s + reu_config.s — transitively .include'd from constants.s
# (v0.4.0-7-g4d1c752, contract §2 + §3). Both files set
# ZP_CONFIG_NO_EXPORTS / REU_CONFIG_NO_EXPORTS when included via
# constants.s, so the .exportzp / .export directives in them only fire
# once per archive (no duplicate-symbol risk).
cp "$LIB_SRC"/zp_config.s  "$STAGING/"
cp "$LIB_SRC"/reu_config.s "$STAGING/"
cp "$LIB_SRC"/fe25519.s    "$STAGING/fe25519_raw.s"
cp "$LIB_SRC"/x25519.s     "$STAGING/x25519_raw.s"
cp "$LIB_SRC"/x25519_init.s "$STAGING/x25519_init_raw.s"
# util.s (bench_*, vic_blank/unblank) is NOT staged — c64-https has no
# in-PRG user of those helpers; vic_blank-style display blanking is a
# perf optimization for benchmarks, not a correctness requirement.
# lib_version.s (LIB_VERSION_* + LIB_X25519_*) is NOT staged for now —
# c64-https doesn't .import any of those symbols yet. Future
# assemble-time fit/collision checks against LIB_X25519_RESIDENT_BYTES
# / LIB_X25519_REU_BANKS_USED would require staging lib_version.s and
# adding the assertions in a cfg or include file.

# Route all sibling data (BSS buffers + initialized rodata tables) to
# the page-aligned TABLES_BSS segment. TABLES_BSS has `align = $100`
# in the c64-https cfg, so the sibling's .align 256 directives land on
# real page boundaries (CRYPTO_RODATA has no segment-level alignment
# and would waste up to 256 B of padding per .align 256 directive).
#
# ld65 emits a "Segment 'TABLES_BSS' with type 'bss' contains
# initialized data" warning, which is benign — the initialized bytes
# are loaded into RAM at PRG load time, same as any RODATA. The
# segment is `type = bss` only for the in-tree mul_dma_lo/hi etc.
# that originally lived there; mixing the modes is what the cfg
# already does (sqtab_lo/hi are `.res` zero-init in TABLES_BSS today).
#
# Emitted from scratch (rather than sed-patched) so the layout is
# explicit and easy to audit. Buffer ordering / size / alignment is
# preserved from libs/x25519/src/data.s.

cat > "$STAGING/data_x25519_bss_raw.s" <<'BSS_EOF'
.setcpu "6502"

; =============================================================================
; data_x25519_bss_raw.s — zero-init buffers + x25_basepoint + fe_p
; extracted from libs/x25519/src/data.s for the c64-https Phase C.5
; integration.
;
; Routed to a dedicated X25519_BSS segment so each backend cfg places
; it independently of the in-tree TABLES_BSS:
;   - UCI : X25519_BSS -> CRYPTO_OVERLAY ($4200-$5FFF, 7.5 KB free)
;   - ip65: X25519_BSS -> CRYPTO_RESIDENT (will overflow — see the
;           integrator's report; UCI is the supported path under
;           USE_X25519_SIBLING=1).
;
; All buffers must live below $A000 (BASIC ROM shadow) and must
; survive bank-out — CRYPTO_OVERLAY at $4200-$5FFF satisfies both
; under UCI.
;
; x25_basepoint and fe_p are *initialized* constants and live in
; data_x25519_rodata_raw.s (X25519_RODATA, type = ro). They were
; previously routed here under the mistaken assumption that the
; "bss type contains initialized data" ld65 warning is benign;
; it is not — ld65 drops init bytes from type=bss segments, which
; left both constants as zero at runtime, making every fe25519
; modular reduction see fe_p=0 and every x25519_base see basepoint=0.
; =============================================================================

.export fe25519_tmp1, fe25519_tmp2, fe25519_tmp3, fe25519_tmp4
.export x25_x2, x25_z2, x25_x3, x25_z3
.export x25_a, x25_b, x25_da, x25_cb, x25_e
.export x25_scalar, x25_u, x25_result
.export mul_cached_a, mul_src2_buf
.export mul_dma_lo, mul_dma_hi, mul_dma_carry

.segment "X25519_BSS"

; --- Page-aligned 32-byte field buffers (block 1) ---
        .align 256
fe25519_tmp1:   .res 32, 0
fe25519_tmp2:   .res 32, 0
fe25519_tmp3:   .res 32, 0
fe25519_tmp4:   .res 32, 0
x25_x2:         .res 32, 0
x25_z2:         .res 32, 0
x25_x3:         .res 32, 0
x25_z3:         .res 32, 0

; --- Page-aligned 32-byte field buffers (block 2) ---
        .align 256
x25_a:          .res 32, 0
x25_b:          .res 32, 0
x25_da:         .res 32, 0
x25_cb:         .res 32, 0
x25_e:          .res 32, 0
x25_scalar:     .res 32, 0
x25_u:          .res 32, 0
x25_result:     .res 32, 0

; --- fe25519_mul optimization scratch (unaligned) ---
;
; mul_src2_buf is 35 bytes:
;   - sibling fe25519_sqr body B reads up to byte 32 (phantom slot,
;     must be 0)
;   - nistcurves fp256 fp_mul writes to bytes 32, 33, 34 (the
;     4x-unrolled inner loop's over-read pad — Phase C.4 note)
; The earlier 33-byte declaration matched the sibling's standalone
; data.s but was 2 bytes short for nistcurves, leaking writes into
; the padding gap before mul_dma_lo at the next page boundary.
mul_cached_a:   .res 1, 0
mul_src2_buf:   .res 35, 0          ; 32 + 1 phantom + 2 over-read pad

; --- REU DMA target buffers, page-aligned for abs,Y without penalty ---
        .align 256
mul_dma_lo:     .res 256, 0
mul_dma_hi:     .res 256, 0
mul_dma_carry:  .res 256, 0

; --- Alignment asserts (mirrored from sibling data.s) ---
.assert (fe25519_tmp1 & $1F) = 0, lderror, "fe25519_tmp1 must be 32-byte aligned"
.assert (fe25519_tmp2 & $1F) = 0, lderror, "fe25519_tmp2 must be 32-byte aligned"
.assert (fe25519_tmp3 & $1F) = 0, lderror, "fe25519_tmp3 must be 32-byte aligned"
.assert (fe25519_tmp4 & $1F) = 0, lderror, "fe25519_tmp4 must be 32-byte aligned"
.assert (x25_x2 & $1F) = 0, lderror, "x25_x2 must be 32-byte aligned"
.assert (x25_z2 & $1F) = 0, lderror, "x25_z2 must be 32-byte aligned"
.assert (x25_x3 & $1F) = 0, lderror, "x25_x3 must be 32-byte aligned"
.assert (x25_z3 & $1F) = 0, lderror, "x25_z3 must be 32-byte aligned"
.assert (x25_a & $1F) = 0, lderror, "x25_a must be 32-byte aligned"
.assert (x25_b & $1F) = 0, lderror, "x25_b must be 32-byte aligned"
.assert (x25_da & $1F) = 0, lderror, "x25_da must be 32-byte aligned"
.assert (x25_cb & $1F) = 0, lderror, "x25_cb must be 32-byte aligned"
.assert (x25_e & $1F) = 0, lderror, "x25_e must be 32-byte aligned"
.assert (x25_scalar & $1F) = 0, lderror, "x25_scalar must be 32-byte aligned"
.assert (x25_u & $1F) = 0, lderror, "x25_u must be 32-byte aligned"
.assert (x25_result & $1F) = 0, lderror, "x25_result must be 32-byte aligned"
BSS_EOF

cat > "$STAGING/data_x25519_rodata_raw.s" <<'RODATA_EOF'
.setcpu "6502"

; =============================================================================
; data_x25519_rodata_raw.s — initialized lookup tables extracted from
; libs/x25519/src/data.s for the c64-https Phase C.5 integration.
;
; Routed to a dedicated X25519_RODATA segment so each backend cfg can
; place it in its own way:
;   - UCI : X25519_RODATA -> CRYPTO_OVERLAY ($4200-$5FFF, 7.5 KB free)
;   - ip65: X25519_RODATA -> CRYPTO_RESIDENT (will overflow until the
;           ip65 memory map is restructured — currently a blocker for
;           the ip65 path; reported by the integrator).
; The segment is declared with `align = $100` in the UCI cfg so the
; .align 256 directives below land on real page boundaries (sqr_lo
; and a24_b0 must start on a page for fe25519_sqr / fe25519_mul_a24).
; =============================================================================

.export mul38_lo_tab, mul38_hi_tab
.export sqr_lo, sqr_hi
.export a24_b0, a24_b1, a24_b2, a24_b3

.export x25_basepoint, fe_p

.segment "X25519_RODATA"

; --- Initialized constants (32 bytes each, 32-byte aligned via
;     X25519_RODATA's align = $100 segment alignment + .align 32) ---
        .align 32
x25_basepoint:
        .byte 9
        .res 31, 0
fe_p:
        .byte $ed
        .res 30, $ff
        .byte $7f

.assert (x25_basepoint & $1F) = 0, lderror, "x25_basepoint must be 32-byte aligned"
.assert (fe_p & $1F) = 0, lderror, "fe_p must be 32-byte aligned"

; mul_by_38 lookup tables (256 B each)
        .align 256
mul38_lo_tab:
        .byte 0
        .repeat 255, i
                .byte <((i+1) * 38)
        .endrepeat
mul38_hi_tab:
        .byte 0
        .repeat 255, i
                .byte >((i+1) * 38)
        .endrepeat

; fe25519_sqr diagonal squaring tables (page-aligned)
        .align 256
sqr_lo:
        .repeat 256, i
                .byte <(i * i)
        .endrepeat
sqr_hi:
        .repeat 256, i
                .byte >(i * i)
        .endrepeat

; fe25519_mul_a24 split tables (page-aligned)
        .align 256
a24_b0:
        .repeat 256, i
                .byte <(121665 * i)
        .endrepeat
a24_b1:
        .repeat 256, i
                .byte <((121665 * i) >> 8)
        .endrepeat
a24_b2:
        .repeat 256, i
                .byte <((121665 * i) >> 16)
        .endrepeat
a24_b3:
        .repeat 256, i
                .byte <((121665 * i) >> 24)
        .endrepeat

RODATA_EOF

# mul_8x8.s is intentionally NOT staged. The in-tree src/crypto/poly1305.s
# provides mul_8x8 / sqtab_init / poly_prod_lo / poly_prod_hi /
# sqtab_lo / sqtab_hi. The sibling's fe25519 + x25519_init imports those
# symbols; the in-tree link satisfies them.

# --- Route CODE segments to CRYPTO_CODE ---
# The sibling uses `.segment "CODE"` (LOADER under c64-https) for all
# code sources. constants.s has no segment directive (pure equates),
# and the data was already split into purpose-built staged files above
# (data_x25519_bss_raw.s + data_x25519_rodata_raw.s).
for src in fe25519_raw x25519_raw x25519_init_raw; do
    sed -i '' 's/^\.segment "CODE"$/.segment "CRYPTO_CODE"/' "$STAGING/$src.s"
done

# --- Sanity: no leftover CODE segments in patched sources ---
for src in fe25519_raw x25519_raw x25519_init_raw; do
    if grep -qE '^\.segment "CODE"$' "$STAGING/$src.s"; then
        echo "ERROR: leftover .segment \"CODE\" in $src.s" >&2
        exit 1
    fi
done

# --- Assemble each staged .s file ---
OBJ_DIR="$STAGING/obj"
rm -rf "$OBJ_DIR"
mkdir -p "$OBJ_DIR" "$OUT_DIR"

for src in fe25519_raw x25519_raw x25519_init_raw data_x25519_bss_raw data_x25519_rodata_raw; do
    # `-g` embeds cc65 debug info; ld65 --dbgfile (top-level Makefile)
    # merges per-source line/symbol records into build/c64-https.dbg.
    # Does not change emitted code bytes.
    "$CA65" \
        -g \
        -I "$STAGING" \
        "${ZP_DEFINES[@]}" \
        "${REU_DEFINES[@]}" \
        "${SQTAB_DEFINES[@]}" \
        -o "$OBJ_DIR/$src.o" "$STAGING/$src.s"
done

# --- Archive ---
rm -f "$ARCHIVE"
"$AR65" a "$ARCHIVE" \
    "$OBJ_DIR/fe25519_raw.o" \
    "$OBJ_DIR/x25519_raw.o" \
    "$OBJ_DIR/x25519_init_raw.o" \
    "$OBJ_DIR/data_x25519_bss_raw.o" \
    "$OBJ_DIR/data_x25519_rodata_raw.o"

# --- Per-source byte counts ---
{
    echo "# x25519.a per-source byte counts (ca65 .o file sizes)"
    for src in fe25519_raw x25519_raw x25519_init_raw data_x25519_bss_raw data_x25519_rodata_raw; do
        bytes=$(wc -c < "$OBJ_DIR/$src.o")
        printf '%-24s %d bytes (.o)\n' "$src" "$bytes"
    done
} > "$SIZES"

echo "built $ARCHIVE"
cat "$SIZES"

# =============================================================================
# W3 (library-ingestion architecture) -- emit a padded overlay .bin
# image of the sibling for documentation / CI parity checking.
#
# The .bin is the same byte image the linker places into CRYPTO_OVERLAY
# under c64-https's main UCI cfg + USE_X25519_SIBLING=1.  Producing it
# as a standalone artefact:
#   * lets a CI bot diff the in-PRG slot bytes against the .bin to
#     detect cfg drift,
#   * gives W1 a ready-to-DMA staging image when the cold-path overlay
#     wiring lands (REU bank 3, REU_OVERLAY_X25519),
#   * documents the sibling's PRG-load-time bytes in `git status`.
#
# Output:
#   build/lib/x25519-scalarmult.bin (7,680 B padded)
#   build/lib/x25519-scalarmult.sizes.txt
#
# Pad / truncate to exactly $SLOT_BYTES so the .bin matches the live
# UCI CRYPTO_OVERLAY slot.
# =============================================================================
BIN_OUT="$OUT_DIR/x25519-scalarmult.bin"
SIZES_BIN_OUT="$OUT_DIR/x25519-scalarmult.sizes.txt"
LABELS_BIN_OUT="$PROJECT_ROOT/build/labels-x25519-scalarmult.txt"
MAP_BIN_OUT="$OUT_DIR/x25519-scalarmult.map"
DBG_BIN_OUT="${BIN_OUT%.bin}.dbg"
CFG_BIN="$PROJECT_ROOT/cfg/x25519-overlay-scalarmult.cfg"
SLOT_BYTES=7680

if [ ! -f "$CFG_BIN" ]; then
    echo "WARN: $CFG_BIN missing -- skipping .bin emission" >&2
else
    LD65="${LD65:-ld65}"

    # ld65 needs the archive members as plain .o files.  We already
    # have them in $OBJ_DIR from the archive step above -- pass them
    # directly.
    OBJ_BIN_ARGS=(
        "$OBJ_DIR/fe25519_raw.o"
        "$OBJ_DIR/x25519_raw.o"
        "$OBJ_DIR/x25519_init_raw.o"
        "$OBJ_DIR/data_x25519_bss_raw.o"
        "$OBJ_DIR/data_x25519_rodata_raw.o"
    )

    # Resolve sibling imports against the main PRG's labels.txt when
    # available (mirrors the P-384 overlay .bin script's pattern).
    MAIN_LABELS="$PROJECT_ROOT/build/labels.txt"

    bin_lookup_label () {
        local name="$1"
        local fallback="$2"
        if [ ! -f "$MAIN_LABELS" ]; then
            echo "$fallback"
            return
        fi
        local hex
        hex=$(grep -E " \.${name}\$" "$MAIN_LABELS" | head -n1 | awk '{print $2}' | sed 's|^C:||')
        if [ -z "$hex" ]; then
            echo "$fallback"
        else
            printf '$%s' "$hex"
        fi
    }

    DEF_MUL_8X8=$(bin_lookup_label mul_8x8 '$0000')
    DEF_SQTAB_LO=$(bin_lookup_label sqtab_lo '$0000')
    DEF_SQTAB_HI=$(bin_lookup_label sqtab_hi '$0000')
    DEF_POLY_PROD_LO=$(bin_lookup_label poly_prod_lo '$CFFE')
    DEF_POLY_PROD_HI=$(bin_lookup_label poly_prod_hi '$CFFF')

    "$LD65" \
        -C "$CFG_BIN" \
        -o "$BIN_OUT" \
        -Ln "$LABELS_BIN_OUT" \
        -m "$MAP_BIN_OUT" \
        --dbgfile "$DBG_BIN_OUT" \
        --define reu_status=\$df00 \
        --define reu_command=\$df01 \
        --define reu_c64_lo=\$df02 \
        --define reu_c64_hi=\$df03 \
        --define reu_reu_lo=\$df04 \
        --define reu_reu_hi=\$df05 \
        --define reu_reu_bank=\$df06 \
        --define reu_len_lo=\$df07 \
        --define reu_len_hi=\$df08 \
        --define reu_addr_ctrl=\$df0a \
        --define mul_8x8="$DEF_MUL_8X8" \
        --define sqtab_lo="$DEF_SQTAB_LO" \
        --define sqtab_hi="$DEF_SQTAB_HI" \
        --define poly_prod_lo="$DEF_POLY_PROD_LO" \
        --define poly_prod_hi="$DEF_POLY_PROD_HI" \
        "${OBJ_BIN_ARGS[@]}" \
        2>"$OUT_DIR/x25519-bin-ld.err" \
        || {
            # Standalone .bin link is best-effort -- if it fails (e.g.
            # missing symbol on a sibling bump), surface a warning but
            # don't break the archive build that the main PRG actually
            # needs.  The W1 follow-on tightens this when the cold-path
            # overlay slot lands.
            echo "WARN: standalone x25519-scalarmult.bin link failed:" >&2
            cat "$OUT_DIR/x25519-bin-ld.err" >&2 || true
            rm -f "$BIN_OUT"
        }

    if [ -f "$BIN_OUT" ]; then
        # Pad / truncate to exactly $SLOT_BYTES.
        truncate -s "$SLOT_BYTES" "$BIN_OUT"
        sed -i '' 's/^al 00\([0-9a-fA-F]\{4\}\) /al C:\1 /' "$LABELS_BIN_OUT" 2>/dev/null || true

        size=$(wc -c < "$BIN_OUT")
        {
            echo "# x25519-scalarmult overlay image (W3)"
            echo "# slot size:           $SLOT_BYTES B (\$1E00 -- UCI CRYPTO_OVERLAY)"
            echo "# padded .bin:         $size B"
        } > "$SIZES_BIN_OUT"

        echo "built $BIN_OUT ($size B padded)"
        cat "$SIZES_BIN_OUT"
    fi
fi
