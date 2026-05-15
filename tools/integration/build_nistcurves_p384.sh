#!/usr/bin/env bash
# =============================================================================
# tools/integration/build_nistcurves_p384.sh - Build c64-nist-curves P-384
# primitives + SHA-384 + ECDSA-with-message wrapper as a REU overlay .a archive
# for the UCI backend smoke test.
#
# Phase 1b extension. Produces build/lib/nistcurves-p384.a containing:
#   * Variable-base P-384 primitives (ec_point_double_384, ec_point_add_384,
#     ec_jacobian_to_affine_384, ec_scalar_mul_var_384) plus their fp/mod
#     helpers.
#   * SHA-384 streaming hash (sha384_init / update / final + sha384_digest).
#   * Packaged ECDSA-P384 verify (ecdsa_verify_384) and the
#     ecdsa_verify_with_message_384 one-shot wrapper.
#   * curve384 generator constants (ec_gx384, ec_gy384) for the
#     ec_scalar_mul_384 -> ec_scalar_mul_var_384 shim (Option A; see below).
#
# Segment layout:
#   OVERLAY_P384     - all P-384 + SHA-384 + ECDSA-P384 runtime code +
#                      RODATA (K[80] SHA constants, curve384 constants).
#                      Paged into the live CRYPTO_OVERLAY slot via REU DMA.
#   CRYPTO_RESIDENT  - P-384 + SHA-384 + ECDSA-P384 RW data (ec384_*, fp384_*,
#                      ecdsa384_*, sha_state, sha_w, sha_block_buf, ...)
#                      routed through the DATA / BSS segments.
#
# Excluded:
#   - ec_scalar_mul_384  - The sibling's Lim-Lee fixed-base 8-comb.  Needs a
#                          24 KB REU bank-2 anchor table built by
#                          ec_precompute_384 at boot (~100 s of init time).
#                          Phase 1b takes Option A: STRIP the Lim-Lee body and
#                          replace with an in-staging shim that copies G into
#                          ec_base384_x/y and tail-calls ec_scalar_mul_var_384.
#                          Mirrors the Phase C.4 P-256 dispatcher pattern (see
#                          src/crypto/ecdsa_verify.s::ec_scalar_mul).  Slower
#                          per-call (double-and-add in lieu of a windowed
#                          comb) but avoids the ~24 KB precompute table and
#                          the ~100 s boot drag.
#   - ec_precompute_384  - builds the Lim-Lee anchor table; only useful with
#                          ec_scalar_mul_384.
#   - Lim-Lee anchor tables (ec_anchor1_384_x..ec_anchor8_384_y) and
#     comb-scalar state (cm_k_384, ec384_sc_byte/mask, ec384_precomp_i).
#   - sha384_msg_buf      - 1 KB test scratch buffer owned by the upstream
#                          test harness.  Production / overlay-smoke-test
#                          consumers do not need it; the .import lines in
#                          sha384.s and ecdsa384.s are stripped in this
#                          script.
#   - ec_aff2g_256_*, ec_anchor*_256, cm_k -- P-256 Lim-Lee infrastructure.
#     Not relevant to the P-384 overlay.
#   - mul_8x8 / sqtab_init / mul_dma_lo/hi / mul_cached_a / mul_src2_buf /
#     reu_fetch_mul_row / poly_prod_lo/hi / sqtab_lo/hi - resolved at link
#     time by build_nistcurves_p384_bin.sh's --define stubs (these symbols
#     come from the in-PRG c64-x25519 sibling at runtime; the standalone
#     overlay image references them but does not inline their bytes).
#
# The script stages the sibling's .s files in build/lib/nistcurves_p384_staging/,
# applies sed-patches to each to override their `.segment "CODE"` / "DATA"
# directives, drops `.import sha384_msg_buf` lines from sha384.s and
# ecdsa384.s, and assembles with canonical ZP equates passed via -D.
#
# Usage (from top-level Makefile):
#   bash tools/integration/build_nistcurves_p384.sh
# Produces:
#   build/lib/nistcurves-p384.a
#   build/lib/nistcurves-p384.sizes.txt   (per-source byte counts)
# =============================================================================
set -eo pipefail

# --- Paths ---
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB_SRC="$PROJECT_ROOT/libs/nistcurves/src"
STAGING="$PROJECT_ROOT/build/lib/nistcurves_p384_staging"
OUT_DIR="$PROJECT_ROOT/build/lib"
ARCHIVE="$OUT_DIR/nistcurves-p384.a"
SIZES="$OUT_DIR/nistcurves-p384.sizes.txt"

CA65="${CA65:-ca65}"
AR65="${AR65:-ar65}"

# --- Canonical ZP defines ---
# The sibling's zp_config.s wraps every ZP equate in .ifndef, so command-line
# -D values win over the defaults. We pin the sibling to c64-https's
# canonical ZP map (src/crypto/shared/zp_canon.inc) where the slots overlap;
# SHA-384's sha_src/sha_len/sha_w_ptr/sha_w_ptr2 ($04-$0B) are LEFT AT THE
# SIBLING'S DEFAULTS because:
#   (1) The overlay binary produced here is harness-time only (Phase C.3b).
#       It is loaded by tools/test_p384_symbols.py into REU then DMA'd into
#       the live overlay slot AT TEST TIME -- production PRG never links it.
#   (2) Inside the c64-https production ZP map ($04-$09 = w32_*, $0a-$0d =
#       sha_temp1) those slots are claimed by ChaCha20/Poly1305 + SHA-256
#       which run concurrently with TLS handshake.  If/when Phase 2 wires
#       SHA-384 / ECDSA-with-message into the production handshake, the ZP
#       collision MUST be resolved either by relocating sha_src/sha_len/etc.
#       into c64-https's free range or by repurposing $04-$0B during the
#       (brief) ECDSA verify window.  Out of scope for Phase 1b.
#
# Note: fp_mul_i / fp_mul_j overlap with x25_byte_idx / x25_bit_mask at
# $39/$3a. This is fine because x25519 and P-384 run at different times
# (different overlays; only one resident at a time) and the canonical
# map documents the time-sharing.
ZP_DEFINES=(
    '-Dproc_port=$01'
    '-Dzp_tmp1=$02'
    '-Dzp_tmp2=$03'
    '-Dzp_ptr1=$fb'
    '-Dzp_ptr2=$fd'
    '-Dfp_src1=$22'
    '-Dfp_src2=$24'
    '-Dfp_dst=$26'
    '-Dfp_misc=$28'
    '-Dfp_carry=$2a'
    '-Dfp_loop=$2b'
    '-Dfp_mul_i=$39'
    '-Dfp_mul_j=$3a'
    '-Dec_scalar_ptr=$3b'
    '-Dpoly_i=$1a'
    '-Dpoly_j=$1b'
    '-Dpoly_carry=$1c'
    '-Dpoly_tmp=$1d'
    # SHA-384 streaming pointer slots (matches sibling defaults)
    '-Dsha_src=$04'
    '-Dsha_len=$06'
    '-Dsha_w_ptr=$08'
    '-Dsha_w_ptr2=$0a'
)

# --- Stage sources ---
rm -rf "$STAGING"
mkdir -p "$STAGING"

# The sibling's constants.s is pulled in via -I; we don't stage it here
# (it has no segment directives we'd rewrite, and it's .include'd by
# zp_config.s / data.s transitively).
cp "$LIB_SRC"/constants.s "$STAGING/"
cp "$LIB_SRC"/zp_config.s "$STAGING/"
cp "$LIB_SRC"/fp384.s      "$STAGING/fp384_raw.s"
cp "$LIB_SRC"/mod384.s     "$STAGING/mod384_raw.s"
cp "$LIB_SRC"/points384.s  "$STAGING/points384_raw.s"
cp "$LIB_SRC"/curve384.s   "$STAGING/curve384_raw.s"
cp "$LIB_SRC"/sha384.s     "$STAGING/sha384_raw.s"
cp "$LIB_SRC"/ecdsa384.s   "$STAGING/ecdsa384_raw.s"

# --- Strip points384.s of ec_precompute_384 and ec_scalar_mul_384 ---
# Those live between lines 787 (just before ec_precompute_384:) and
# 1489 (just before the ec_scalar_mul_var_384: header).
# We also strip the `.export ec_precompute_384, ec_scalar_mul_384` line
# so the archive doesn't advertise symbols whose bodies were removed.
# The remaining four `.export` symbols (ec_point_double_384,
# ec_point_add_384, ec_scalar_mul_var_384, ec_jacobian_to_affine_384) stay.
#
# OPTION A choice (Phase 1b): the Lim-Lee body for ec_scalar_mul_384 is
# stripped; an in-staging shim file (ec_scalar_mul_384_shim_raw.s, emitted
# below) provides the symbol by copying G into ec_base384_x/y and
# tail-calling ec_scalar_mul_var_384.  This avoids the ~24 KB Lim-Lee
# anchor table + ~100 s ec_precompute_384 boot drag.  Pattern mirrors
# src/crypto/ecdsa_verify.s::ec_scalar_mul (Phase C.4 for P-256).
#
# Imports that the removed bodies relied on (anchors, cm_k_384, sc_byte,
# sc_mask, precomp_i, ec_set_modp is still used by double/add/var) - we
# remove ONLY the anchor + comb-state imports since everything else is used
# by the retained primitives.  We also keep `ec_gx384, ec_gy384` because
# the shim references them; that import line is left in place.
# BSD-sed compat: macOS sed requires `-i ''` (empty extension).
sed -i '' '787,1488d' "$STAGING/points384_raw.s"
sed -i '' '/^\.export ec_precompute_384, ec_scalar_mul_384$/d' "$STAGING/points384_raw.s"
# Strip imports only used by the removed bodies. Patterns are anchored
# to avoid accidentally deleting unrelated lines.  ec_gx384 / ec_gy384 are
# KEPT (used by the shim emitted below).
sed -i '' '/^\.import ec_anchor[1-8]_384_x/d' "$STAGING/points384_raw.s"
sed -i '' '/^\.import ec_anchor[1-8]_384_y/d' "$STAGING/points384_raw.s"
sed -i '' '/^\.import cm_k_384, mul_dma_lo$/d' "$STAGING/points384_raw.s"
sed -i '' '/^\.import ec384_sc_byte, ec384_sc_mask, ec384_precomp_i$/d' "$STAGING/points384_raw.s"

# --- Drop test-only sha384_msg_buf imports ---
# sha384.s and ecdsa384.s both `.import sha384_msg_buf` at file scope but
# never reference the symbol in code (sha384.s never touches it; ecdsa384.s
# only mentions it in the test trampoline's docstring).  We drop the
# 1024-byte test scratch buffer from data_raw.s, so the imports must go
# too or the linker will fail to resolve them.
sed -i '' 's/^\(\.import sha384_digest, sha384_msg_buf\)$/.import sha384_digest/' "$STAGING/sha384_raw.s"
sed -i '' 's/^\(\.import sha384_digest, sha384_msg_buf\)$/.import sha384_digest/' "$STAGING/ecdsa384_raw.s"

# --- Extend data_raw.s with all the BSS / DATA exports the P-384 path needs.
# ---
# Hand-extracted from the sibling's data.s.  Drops:
#   - P-256 field buffers (fp_wide, fp_tmp*, fp_r*, fp_inv_*, ec_p1..)
#     because the P-256 sibling archive (build/lib/nistcurves-p256.a)
#     already provides these and we must not double-define them at link
#     time (the standalone overlay binary uses --define stubs for the
#     few P-256 symbols the P-384 path could in theory cross-reference).
#   - mul_cached_a, mul_src2_buf, mul_dma_lo/hi - provided by the
#     x25519 sibling at runtime; resolved via --define stubs at standalone
#     overlay link time.
#   - Lim-Lee anchors (ec_anchor*_x/y, ec_aff2g_256_*), cm_k / cm_k_384,
#     ec384_sc_*, ec384_precomp_i - only used by the stripped scalar-mul
#     and precompute bodies.
#   - sha384_msg_buf (1024 B) - test-only scratch buffer; not needed for
#     the production overlay path.
#
# Strategy: write a brand new data_raw.s that pulls only what we need.
# We keep the sibling's data.s around for reference but emit an
# explicit minimal one.
cat > "$STAGING/data_raw.s" <<'DATA_EOF'
; =============================================================================
; data_raw.s - Minimal P-384 + SHA-384 + ECDSA-P384 RW buffers for c64-https /
;              c64-nist-curves integration (Phase 1b).  Hand-extracted from
;              the sibling's data.s so the P-256 side (sibling-provided) and
;              the x25519 sibling's shared mul tables remain unclobbered.
;
; All exports here are P-384- / SHA-384- / ECDSA-with-message-exclusive.
; sha384_msg_buf (test-only 1 KB scratch) is intentionally OMITTED -- see
; build_nistcurves_p384.sh header for the rationale.
; =============================================================================
.setcpu "6502"

.segment "DATA"

; --- P-384 field arithmetic working buffers (48 bytes each) ---
.export fp384_wide
fp384_wide:     .res 96, 0    ; 768-bit product from multiply
.export fp384_tmp1
fp384_tmp1:     .res 48, 0
.export fp384_tmp2
fp384_tmp2:     .res 48, 0
.export fp384_tmp3
fp384_tmp3:     .res 48, 0
.export fp384_tmp4
fp384_tmp4:     .res 48, 0

; --- P-384 result registers ---
.export fp384_r0
fp384_r0:       .res 48, 0
.export fp384_r1
fp384_r1:       .res 48, 0
.export fp384_r2
fp384_r2:       .res 48, 0
.export fp384_r3
fp384_r3:       .res 48, 0

; --- P-384 modular inverse working space ---
.export fp384_inv_u
fp384_inv_u:    .res 48, 0
.export fp384_inv_v
fp384_inv_v:    .res 48, 0
.export fp384_inv_x1
fp384_inv_x1:   .res 48, 0
.export fp384_inv_x2
fp384_inv_x2:   .res 48, 0

; --- P-384 point storage (Jacobian: X=48 + Y=48 + Z=48 = 144 bytes) ---
.export ec384_p1
ec384_p1:       .res 144, 0
.export ec384_p2
ec384_p2:       .res 144, 0
.export ec384_p3
ec384_p3:       .res 144, 0

; --- P-384 point math temporaries ---
.export ec384_t1
ec384_t1:       .res 48, 0
.export ec384_t2
ec384_t2:       .res 48, 0
.export ec384_t3
ec384_t3:       .res 48, 0
.export ec384_t4
ec384_t4:       .res 48, 0
.export ec384_t5
ec384_t5:       .res 48, 0
.export ec384_t6
ec384_t6:       .res 48, 0

; --- P-384 affine output ---
.export ec384_affine_x
ec384_affine_x: .res 48, 0
.export ec384_affine_y
ec384_affine_y: .res 48, 0

; --- Variable-base scalar-mul input (affine, 48 bytes each, LE).
;     Consumed by ec_scalar_mul_var_384 (ECDSA-verify building block) and
;     populated by the ec_scalar_mul_384 shim (G -> ec_base384_x/y).
.export ec_base384_x
ec_base384_x:   .res 48, 0
.export ec_base384_y
ec_base384_y:   .res 48, 0

; --- P-384 Solinas reduction scratch ---
.export fp384_red_tmp
fp384_red_tmp:  .res 49, 0

; --- ECDSA verify scratch (P-384). All 48-byte little-endian unless noted. ---
.export ecdsa384_r
ecdsa384_r:     .res 48, 0      ; LE r (byte-reversed from BE input)
.export ecdsa384_s
ecdsa384_s:     .res 48, 0      ; LE s
.export ecdsa384_h
ecdsa384_h:     .res 48, 0      ; LE message hash
.export ecdsa384_qx
ecdsa384_qx:    .res 48, 0      ; LE public-key affine X
.export ecdsa384_qy
ecdsa384_qy:    .res 48, 0      ; LE public-key affine Y
.export ecdsa384_w
ecdsa384_w:     .res 48, 0      ; LE w = s^-1 mod n
.export ecdsa384_u1
ecdsa384_u1:    .res 48, 0      ; LE u1 = h*w mod n
.export ecdsa384_u2
ecdsa384_u2:    .res 48, 0      ; LE u2 = r*w mod n
.export ecdsa384_u1_be
ecdsa384_u1_be: .res 48, 0      ; BE u1 (scalar_mul input)
.export ecdsa384_u2_be
ecdsa384_u2_be: .res 48, 0      ; BE u2 (scalar_mul_var input)
.export ecdsa384_u1g_x
ecdsa384_u1g_x: .res 48, 0      ; LE affine X of u1*G
.export ecdsa384_u1g_y
ecdsa384_u1g_y: .res 48, 0      ; LE affine Y of u1*G

; --- fp_reverse48 staging buffer (one 48-byte scratch). ---
.export fp_rev_buf_384
fp_rev_buf_384: .res 48, 0

; --- ECDSA verify test-driver staging buffer (240 B BE struct).
;     The c64-test-harness jsr() helper cannot pass register arguments, so
;     the BE input struct is staged here and the test trampoline points
;     A/X at it.
.export ecdsa_inputs_384
ecdsa_inputs_384:       .res 240, 0     ; r|s|h|Qx|Qy each 48 B BE

; --- ecdsa_verify_with_message_384 scratch + test-driver result byte ---
.export ecdsa384_msg_struct_ptr
ecdsa384_msg_struct_ptr: .res 2, 0
.export ecdsa_result_msg_384
ecdsa_result_msg_384:   .byte 0

; =============================================================================
; SHA-384 streaming hash state (FIPS 180-4 §6.4)
;
; Storage convention: each 64-bit word is held LITTLE-ENDIAN-WITHIN-WORD,
; matching 6502 ADC carry propagation. All buffers are owned exclusively
; by sha384.s.  sha384_msg_buf (1 KB test scratch) is intentionally OMITTED.
; =============================================================================
.export sha_state
sha_state:        .res 64, 0     ; H[0..7], 8 bytes each LE-within-word
.export sha_w
sha_w:            .res 640, 0    ; W[0..79] message schedule, 8 B each LE
.export sha_abcdefgh
sha_abcdefgh:     .res 64, 0     ; working a..h, 8 B each LE
.export sha_t
sha_t:            .res 16, 0     ; T1 (8 B) + T2 (8 B), LE
.export sha_scratch
sha_scratch:      .res 64, 0     ; 8x 8-byte scratch slots for round helpers
.export sha_block_buf
sha_block_buf:    .res 128, 0    ; current 1024-bit block (wire order)
.export sha_block_len
sha_block_len:    .byte 0        ; bytes used in sha_block_buf, 0..127
.export sha_total_len
sha_total_len:    .res 16, 0     ; 128-bit total bit count, LE on-chip
.export sha384_digest
sha384_digest:    .res 48, 0     ; final BE digest output
DATA_EOF

# --- Emit ec_scalar_mul_384 shim (Option A) ---
# Pattern mirrors src/crypto/ecdsa_verify.s::ec_scalar_mul (Phase C.4 P-256
# dispatcher).  Lives in OVERLAY_P384 alongside the rest of the P-384 code.
# ec_gx384 and ec_gy384 are each contiguous 48-byte slots in curve384.s
# RODATA, so a single 96-byte copy loop (using two reads per Y for X then
# Y at +48) is straightforward.  We use a simple ldy #47 / lda src,y /
# sta dst,y / dey / bpl loop (47 = $2F has bit 7 clear so BPL is safe;
# DEY updates N flag based on the decremented Y, not the LDA byte) twice
# to copy ec_gx384 -> ec_base384_x and ec_gy384 -> ec_base384_y separately.
cat > "$STAGING/ec_scalar_mul_384_shim_raw.s" <<'SHIM_EOF'
; =============================================================================
; ec_scalar_mul_384_shim_raw.s -- Phase 1b shim for the stripped Lim-Lee
; fixed-base scalar-mul (Option A).  Provides ec_scalar_mul_384 by copying
; G into ec_base384_x/y and tail-calling ec_scalar_mul_var_384.
;
; Mirrors the Phase C.4 P-256 dispatcher pattern in
; src/crypto/ecdsa_verify.s::ec_scalar_mul.  Slower per-call than the real
; Lim-Lee comb (double-and-add vs. windowed comb) but avoids the ~24 KB
; REU bank-2 anchor table + ~100 s ec_precompute_384 boot drag.
; =============================================================================
.setcpu "6502"

.segment "OVERLAY_P384"

.export ec_scalar_mul_384

.import ec_gx384, ec_gy384
.import ec_base384_x, ec_base384_y
.import ec_scalar_mul_var_384

ec_scalar_mul_384:
        ; Copy G.x -> ec_base384_x (48 bytes; ldy #47, dey/bpl safe)
        ldy #47
@cp_x:  lda ec_gx384,y
        sta ec_base384_x,y
        dey
        bpl @cp_x
        ; Copy G.y -> ec_base384_y (48 bytes)
        ldy #47
@cp_y:  lda ec_gy384,y
        sta ec_base384_y,y
        dey
        bpl @cp_y
        jmp ec_scalar_mul_var_384       ; tail-call: result and clobbers passthrough
SHIM_EOF

# --- Route CODE / RODATA segments into OVERLAY_P384 ---
# fp384_raw.s and mod384_raw.s use `.segment "CODE"` (once each) and
# fp384_raw.s has a second `.segment "BSS"` block at the tail. Those
# tail BSS buffers (fp384_sqr_extra, mul_src2_buf_384, fp384_sqr_pairs)
# must go in CRYPTO_RESIDENT BSS (always-resident state, not overlay)
# since the overlay gets swapped out between calls. We rename the BSS
# segment to the c64-https canonical `BSS` name which the cfg maps into
# the RESIDENT region.
# BSD-sed compat: macOS sed requires `-i ''` (empty extension).
sed -i '' 's/^\.segment "CODE"/.segment "OVERLAY_P384"/' "$STAGING/fp384_raw.s"
sed -i '' 's/^\.segment "CODE"/.segment "OVERLAY_P384"/' "$STAGING/mod384_raw.s"
sed -i '' 's/^\.segment "CODE"/.segment "OVERLAY_P384"/' "$STAGING/points384_raw.s"
sed -i '' 's/^\.segment "CODE"/.segment "OVERLAY_P384"/' "$STAGING/sha384_raw.s"
sed -i '' 's/^\.segment "CODE"/.segment "OVERLAY_P384"/' "$STAGING/ecdsa384_raw.s"
# curve384.s uses RODATA -- route it into OVERLAY_P384 (read-only constants).
sed -i '' 's/^\.segment "RODATA"/.segment "OVERLAY_P384"/' "$STAGING/curve384_raw.s"
# sha384.s has a second `.segment "RODATA"` block at the tail for the SHA-384
# IV + K[80] round constants (704 B).  Route it into OVERLAY_P384 alongside
# the code that reads it; otherwise it lands at $0000 and the linker won't
# write it into the overlay binary.
sed -i '' 's/^\.segment "RODATA"/.segment "OVERLAY_P384"/' "$STAGING/sha384_raw.s"
# fp384_raw.s .segment "BSS" stays - already matches the canonical BSS
# segment which cfg/p384-overlay.cfg maps into the RESIDENT region.

# --- mod384.s curve constants (ec_p384, ec_n384) live in CODE segment
# in the sibling and are emitted inline with .byte directives. After the
# CODE->OVERLAY_P384 rewrite they flow into the overlay alongside the
# code that reads them; that is intentional (ec_p384 is used by
# fp_mod_reduce384 which IS in the overlay).

# --- Forbidden-symbol guard ---
# After the strip, points384_raw.s must NOT reference any of the removed
# Lim-Lee comb / precompute symbols.  ec_gx384 / ec_gy384 / cm_k_384 /
# ec_anchor*_384 patterns CAN appear in points384_raw.s only as comments;
# we strip leading whitespace and a leading `;` before the grep so we only
# match active code.  ec_gx384 / ec_gy384 are intentionally left LIVE in
# the staging tree (used by the shim) so we don't include them in the
# guard.  cm_k_384, ec_anchor[0-9]_384, ec384_sc_byte/mask, ec384_precomp_i
# remain forbidden -- those bodies were physically removed.
if grep -v '^\s*;' "$STAGING/points384_raw.s" \
   | grep -qE '\bec384_sc_byte\b|\bec384_sc_mask\b|\bec384_precomp_i\b|\bcm_k_384\b|\bec_anchor[0-9]_384\b'; then
    echo "ERROR: stripped points384 still references removed-body symbols" >&2
    grep -v '^\s*;' "$STAGING/points384_raw.s" \
      | grep -nE '\bec384_sc_byte\b|\bec384_sc_mask\b|\bec384_precomp_i\b|\bcm_k_384\b|\bec_anchor[0-9]_384\b' \
      | head -5 >&2
    exit 1
fi

# --- Assemble each staged .s file ---
OBJ_DIR="$STAGING/obj"
rm -rf "$OBJ_DIR"
mkdir -p "$OBJ_DIR" "$OUT_DIR"

# zp_config.s is the single point of truth for the library's ZP equates.
# We assemble it with `-D` overrides so the sibling's defaults are
# replaced by c64-https's canonical ZP map. The other source files use
# `.importzp` to pull these equates from the linker-resolved zp_config.o.
"$CA65" \
    -I "$STAGING" \
    -I "$PROJECT_ROOT/src/crypto/shared" \
    "${ZP_DEFINES[@]}" \
    -o "$OBJ_DIR/zp_config.o" "$STAGING/zp_config.s"

# Other files: NO -D. Let `.importzp` resolve through the linker to
# zp_config.o's `.exportzp` declarations. If we passed -D here the
# assembler would treat the symbol as locally-defined absolute and
# conflict with the .importzp declaration.
for src in fp384_raw mod384_raw points384_raw curve384_raw \
           sha384_raw ecdsa384_raw ec_scalar_mul_384_shim_raw data_raw; do
    "$CA65" \
        -I "$STAGING" \
        -I "$PROJECT_ROOT/src/crypto/shared" \
        -o "$OBJ_DIR/$src.o" "$STAGING/$src.s"
done

# --- Archive into nistcurves-p384.a ---
rm -f "$ARCHIVE"
"$AR65" a "$ARCHIVE" \
    "$OBJ_DIR/zp_config.o" \
    "$OBJ_DIR/fp384_raw.o" \
    "$OBJ_DIR/mod384_raw.o" \
    "$OBJ_DIR/points384_raw.o" \
    "$OBJ_DIR/curve384_raw.o" \
    "$OBJ_DIR/sha384_raw.o" \
    "$OBJ_DIR/ecdsa384_raw.o" \
    "$OBJ_DIR/ec_scalar_mul_384_shim_raw.o" \
    "$OBJ_DIR/data_raw.o"

# --- Per-source byte counts ---
{
    echo "# nistcurves-p384.a per-source byte counts (ca65 .o file sizes)"
    for src in zp_config fp384_raw mod384_raw points384_raw curve384_raw \
               sha384_raw ecdsa384_raw ec_scalar_mul_384_shim_raw data_raw; do
        bytes=$(wc -c < "$OBJ_DIR/$src.o")
        printf '%-32s %d bytes (.o)\n' "$src" "$bytes"
    done
} > "$SIZES"

echo "built $ARCHIVE"
cat "$SIZES"
