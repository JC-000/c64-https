#!/usr/bin/env bash
# =============================================================================
# tools/integration/build_nistcurves_p384.sh - Build c64-nist-curves P-384
# overlay archives for the UCI backend smoke test.
#
# Phase 1.5 split.  Phase 1b's monolithic OVERLAY_P384 segment was 12,836 B
# and overflowed the live UCI CRYPTO_OVERLAY slot (7,680 B at $4200-$5FFF).
# This script now produces TWO archives, each fitting the 7.5 KB slot:
#
#   build/lib/nistcurves-p384-sha384.a  - SHA-384 streaming hash (sha384.s
#                                          + the SHA-384 portion of the
#                                          minimal data heredoc).
#                                          Segment: OVERLAY_P384_SHA384.
#   build/lib/nistcurves-p384-curve.a   - fp384 + mod384 + points384
#                                          (post-strip) + curve384 +
#                                          ecdsa384 (verify_384 ONLY -
#                                          the verify_with_message_384
#                                          wrapper that imports
#                                          sha384_init/update/final is
#                                          stripped here; TLS drives SHA
#                                          via the sha384 overlay) + the
#                                          ec_scalar_mul_384 shim.
#                                          Segment: OVERLAY_P384_CURVE.
#
# Both archives also contribute disjoint subsets of data_raw.s into the
# resident DATA segment (CRYPTO_RESIDENT under the live cfg, at $C000 in
# the standalone overlay cfgs).  The split is byte-for-byte identical to
# Phase 1b's combined data_raw.s so resident DATA growth stays at the
# Phase 1b figure (3,541 B); see the per-half data heredocs below.
#
# Wrapper strip:
#   ecdsa_verify_with_message_384 + ecdsa_verify_with_msg_384_tramp are
#   physically removed from the curve archive's ecdsa384_raw.s so the
#   archive does not import sha384_init/update/final (those live only in
#   the OTHER half).  TLS will call sha384_init / update / final
#   directly from the sha384 overlay, then swap in the curve overlay,
#   then call ecdsa_verify_384 with the digest pre-spliced into
#   ecdsa_inputs_384[96..143].  See Phase 4a's TLS dispatcher work for
#   the call sequencing.
#
# ZP allocation (Phase 1.5):
#   sha_src   = $3D, sha_len   = $3F,
#   sha_w_ptr = $41, sha_w_ptr2 = $43.
#   These supersede the sibling defaults ($04/$06/$08/$0A) which collide
#   with c64-https's canonical $04-$09 = w32_* (ChaCha20/Poly1305) and
#   $0A-$0D = sha_temp1 (SHA-256).  $3D-$44 is the lowest 8-byte
#   contiguous free block above the canonical crypto ZP map (ec_scalar_ptr
#   ends at $3C; nothing in src/* claims $3D-$FA except the universal
#   $FB-$FF general pointers).  Verified by grep against
#   src/constants.inc, src/crypto/shared/zp_canon.inc, and all .s files
#   under src/.  Safe during the SHA-384 call window because no other
#   crypto / TLS path uses these slots.
#
# Excluded (same as Phase 1b — see comments inline):
#   - ec_precompute_384 / ec_scalar_mul_384 (Lim-Lee body) — replaced by
#     the in-staging shim that copies G into ec_base384_x/y and
#     tail-calls ec_scalar_mul_var_384.
#   - Lim-Lee anchor tables and comb-scalar state.
#   - sha384_msg_buf (1024 B test scratch).
#   - mul_8x8 / sqtab_init / mul_dma_lo/hi / mul_cached_a / mul_src2_buf /
#     reu_fetch_mul_row / poly_prod_lo/hi / sqtab_lo/hi - resolved at link
#     time by build_nistcurves_p384_bin.sh's --define stubs.
#   - ecdsa_verify_with_message_384 + ecdsa_verify_with_msg_384_tramp
#     (Phase 1.5 NEW — see "Wrapper strip" above).
#
# The script stages the sibling's .s files in build/lib/nistcurves_p384_staging/,
# applies sed-patches to override their `.segment` directives and rewrite
# them into the new dual-segment scheme.
#
# Usage (from top-level Makefile):
#   bash tools/integration/build_nistcurves_p384.sh
# Produces:
#   build/lib/nistcurves-p384-sha384.a
#   build/lib/nistcurves-p384-curve.a
#   build/lib/nistcurves-p384-sha384.sizes.txt
#   build/lib/nistcurves-p384-curve.sizes.txt
# =============================================================================
set -eo pipefail

# --- Paths ---
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB_SRC="$PROJECT_ROOT/libs/nistcurves/src"
STAGING="$PROJECT_ROOT/build/lib/nistcurves_p384_staging"
OUT_DIR="$PROJECT_ROOT/build/lib"
ARCHIVE_SHA="$OUT_DIR/nistcurves-p384-sha384.a"
ARCHIVE_CURVE="$OUT_DIR/nistcurves-p384-curve.a"
SIZES_SHA="$OUT_DIR/nistcurves-p384-sha384.sizes.txt"
SIZES_CURVE="$OUT_DIR/nistcurves-p384-curve.sizes.txt"

CA65="${CA65:-ca65}"
AR65="${AR65:-ar65}"

# --- Canonical ZP defines ---
# The sibling's zp_config.s wraps every ZP equate in .ifndef, so command-line
# -D values win over the defaults.  We pin the sibling to c64-https's
# canonical ZP map (src/crypto/shared/zp_canon.inc) AND override the SHA-384
# pointer slots to $3D-$44 (Phase 1.5).
#
# Why $3D-$44?  The sibling's defaults sha_src=$04, sha_len=$06,
# sha_w_ptr=$08, sha_w_ptr2=$0a collide with c64-https's canonical
# $04-$09 = w32_* (ChaCha20/Poly1305) and $0A-$0D = sha_temp1 (SHA-256).
# $3D-$44 is the lowest 8-byte contiguous free range above the canonical
# crypto ZP map (ec_scalar_ptr ends at $3C); see this file's header for
# the full audit.  Demonstrated free during the SHA-384 call window:
#   - Not used by ip65 ($02-$1B), ChaCha20/Poly1305 ($04-$1D),
#     SHA-256 ($0A-$13), TLS record layer ($1E-$21), fp_* ECDSA bignum
#     ($22-$2B + $39-$3C), fe25519 ($2C-$35), or x25519 ($38-$3A).
#   - $36-$37 was reserved for fe25519 future expansion (only 2 bytes,
#     insufficient for the 8 bytes SHA-384 needs).
#
# Note: fp_mul_i / fp_mul_j overlap with x25_byte_idx / x25_bit_mask at
# $39/$3a.  This is fine because x25519 and P-384 run at different times
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
    # SHA-384 streaming pointer slots (Phase 1.5 — moved out of the
    # sibling's $04-$0B defaults to avoid the canonical w32_* / sha_temp1
    # collision; see header).
    '-Dsha_src=$3d'
    '-Dsha_len=$3f'
    '-Dsha_w_ptr=$41'
    '-Dsha_w_ptr2=$43'
)

# --- Stage sources ---
rm -rf "$STAGING"
mkdir -p "$STAGING"

# constants.s and zp_config.s are shared between both halves.  zp_config.s
# is .include'd transitively; we assemble it once with -D overrides and
# add the resulting .o to BOTH archives.
cp "$LIB_SRC"/constants.s "$STAGING/"
cp "$LIB_SRC"/zp_config.s "$STAGING/"
cp "$LIB_SRC"/fp384.s      "$STAGING/fp384_raw.s"
cp "$LIB_SRC"/mod384.s     "$STAGING/mod384_raw.s"
cp "$LIB_SRC"/points384.s  "$STAGING/points384_raw.s"
cp "$LIB_SRC"/curve384.s   "$STAGING/curve384_raw.s"
cp "$LIB_SRC"/sha384.s     "$STAGING/sha384_raw.s"
cp "$LIB_SRC"/ecdsa384.s   "$STAGING/ecdsa384_raw.s"

# --- Strip points384.s of ec_precompute_384 and ec_scalar_mul_384 ---
# Same surgery as Phase 1b.  Bodies between lines 787 and 1488 inclusive
# are physically removed; the related `.export` and `.import` lines are
# scrubbed below.  ec_gx384 / ec_gy384 imports are KEPT (used by the shim).
#
# OPTION A choice (Phase 1b): the Lim-Lee body for ec_scalar_mul_384 is
# stripped; an in-staging shim file (ec_scalar_mul_384_shim_raw.s, emitted
# below) provides the symbol by copying G into ec_base384_x/y and
# tail-calling ec_scalar_mul_var_384.  This avoids the ~24 KB Lim-Lee
# anchor table + ~100 s ec_precompute_384 boot drag.  Pattern mirrors
# src/crypto/ecdsa_verify.s::ec_scalar_mul (Phase C.4 for P-256).
# BSD-sed compat: macOS sed requires `-i ''` (empty extension).
sed -i '' '787,1488d' "$STAGING/points384_raw.s"
sed -i '' '/^\.export ec_precompute_384, ec_scalar_mul_384$/d' "$STAGING/points384_raw.s"
sed -i '' '/^\.import ec_anchor[1-8]_384_x/d' "$STAGING/points384_raw.s"
sed -i '' '/^\.import ec_anchor[1-8]_384_y/d' "$STAGING/points384_raw.s"
sed -i '' '/^\.import cm_k_384, mul_dma_lo$/d' "$STAGING/points384_raw.s"
sed -i '' '/^\.import ec384_sc_byte, ec384_sc_mask, ec384_precomp_i$/d' "$STAGING/points384_raw.s"

# --- Strip ecdsa_verify_with_message_384 wrapper from the curve archive ---
# Phase 1.5 NEW.  The wrapper imports sha384_init/update/final, which live
# in the OTHER overlay half (sha384 archive).  TLS now drives the SHA
# overlay manually then swaps in the curve overlay and calls
# ecdsa_verify_384 directly with the digest pre-spliced into
# ecdsa_inputs_384[96..143].
#
# In libs/nistcurves@90830c9 the wrapper + trampoline span lines 568-end
# of ecdsa384.s.  We delete from line 568 to the end of file ("568,$d")
# and scrub:
#   - the two wrapper .export lines (verify_with_message_384 +
#     verify_with_msg_384_tramp)
#   - the .import sha384_init/update/final line
#   - the .import sha384_msg_buf reference (the test trampoline only)
#   - the .import ecdsa384_msg_struct_ptr line (wrapper-only scratch)
#   - the .import ecdsa_inputs_384, ecdsa_result_msg_384 line
#     (test-trampoline only — the standalone curve archive doesn't need
#     these symbols since the wrapper that consumed them is gone; ld65
#     would fail to resolve them if we left the .import in place since
#     they live in the data heredoc as exports but nothing else references
#     them after the wrapper is dropped — keep the .import to keep the
#     symbol pulled in via .import-as-link-anchor; data_curve_raw.s still
#     exports both for the harness driver path).
# We sed only on the curve copy AFTER making a separate sha-only copy is
# unnecessary because sha384_raw.s never sees ecdsa384_raw.s.
sed -i '' '568,$d' "$STAGING/ecdsa384_raw.s"
sed -i '' '/^\.export ecdsa_verify_with_message_384$/d' "$STAGING/ecdsa384_raw.s"
sed -i '' '/^\.export ecdsa_verify_with_msg_384_tramp$/d' "$STAGING/ecdsa384_raw.s"
sed -i '' '/^\.import sha384_init, sha384_update, sha384_final$/d' "$STAGING/ecdsa384_raw.s"
sed -i '' '/^\.import ecdsa384_msg_struct_ptr$/d' "$STAGING/ecdsa384_raw.s"

# --- Drop test-only sha384_msg_buf import from sha384.s ---
# sha384.s `.import sha384_digest, sha384_msg_buf` at file scope but never
# references sha384_msg_buf in code.  We drop the 1024-byte test scratch
# buffer from data_raw.s, so the import must go too.
sed -i '' 's/^\(\.import sha384_digest, sha384_msg_buf\)$/.import sha384_digest/' "$STAGING/sha384_raw.s"
# Same scrub on the curve-half ecdsa384_raw.s (the .import line is on a
# different line in ecdsa384.s; preserve only sha384_digest if the line is
# present after the wrapper-strip above — it should NOT be, since the
# import for sha384_init/update/final/digest/msg_buf is bundled together.
# Defensive: leave a no-op sed in case the upstream layout changes).
sed -i '' 's/^\(\.import sha384_digest, sha384_msg_buf\)$/.import sha384_digest/' "$STAGING/ecdsa384_raw.s"

# --- Emit data_curve_raw.s (resident DATA exports for the curve archive) ---
# Hand-extracted from the sibling's data.s — non-SHA portion only.
# This is the SAME byte-for-byte content as Phase 1b's data_raw.s up to
# (but not including) the SHA-384 streaming state block.  Land in DATA
# (= CRYPTO_RESIDENT in the live cfg, $C000 in the standalone cfgs).
cat > "$STAGING/data_curve_raw.s" <<'DATA_EOF'
; =============================================================================
; data_curve_raw.s - Resident DATA exports for the curve / verify half of
; the split P-384 overlay (Phase 1.5).  Non-SHA portion of Phase 1b's
; minimal data_raw.s.  Lands in CRYPTO_RESIDENT under the live cfg.
;
; The 240 B BE input struct (ecdsa_inputs_384) is shared with the SHA
; archive's caller path -- TLS pre-stages r/s/Qx/Qy here, then drives
; sha384_init/update/final to populate the digest at struct[96..143],
; then swaps in this overlay and calls ecdsa_verify_384.
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
;     A/X at it.  TLS pre-fills r|s|Qx|Qy here, then runs SHA over the
;     handshake transcript, then writes the digest into struct[96..143],
;     then swaps in the curve overlay and calls ecdsa_verify_384.
.export ecdsa_inputs_384
ecdsa_inputs_384:       .res 240, 0     ; r|s|h|Qx|Qy each 48 B BE

; --- ECDSA result byte (test driver / dispatcher result) ---
.export ecdsa_result_msg_384
ecdsa_result_msg_384:   .byte 0
DATA_EOF

# --- Emit data_sha_raw.s (resident DATA exports for the SHA archive) ---
# Hand-extracted from the sibling's data.s — SHA-384 portion only.
# Same byte-for-byte content as Phase 1b's data_raw.s SHA-384 block.
cat > "$STAGING/data_sha_raw.s" <<'DATA_EOF'
; =============================================================================
; data_sha_raw.s - Resident DATA exports for the SHA-384 half of the split
; P-384 overlay (Phase 1.5).  SHA-384 portion of Phase 1b's minimal
; data_raw.s.  Lands in CRYPTO_RESIDENT under the live cfg.
;
; Storage convention: each 64-bit word is held LITTLE-ENDIAN-WITHIN-WORD,
; matching 6502 ADC carry propagation.  All buffers are owned exclusively
; by sha384.s.  sha384_msg_buf (1 KB test scratch) is intentionally OMITTED
; (would inflate resident DATA by ~25%; not used by sha384.s itself).
; =============================================================================
.setcpu "6502"

.segment "DATA"

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
sha384_digest:    .res 48, 0     ; final BE digest output (read by curve
                                  ; overlay's ecdsa_verify_384 path after
                                  ; TLS splices it into ecdsa_inputs_384[96..143])
DATA_EOF

# --- Emit ec_scalar_mul_384 shim (Option A) ---
# Pattern mirrors src/crypto/ecdsa_verify.s::ec_scalar_mul (Phase C.4 P-256
# dispatcher).  Lives in OVERLAY_P384_CURVE alongside the rest of the curve
# code.  ec_gx384 and ec_gy384 are each contiguous 48-byte slots in
# curve384.s RODATA, so a simple ldy #47 / lda src,y / sta dst,y / dey /
# bpl loop works (47 = $2F has bit 7 clear; DEY updates N flag based on
# the decremented Y, not the LDA byte).
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
;
; Phase 1.5: lives in OVERLAY_P384_CURVE (was OVERLAY_P384 in Phase 1b).
; =============================================================================
.setcpu "6502"

.segment "OVERLAY_P384_CURVE"

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

# --- Route CODE / RODATA segments into per-half OVERLAY segments ---
# Phase 1.5 split: each source goes into either OVERLAY_P384_SHA384 (just
# sha384) or OVERLAY_P384_CURVE (everything else).
#
# fp384_raw.s also has a `.segment "BSS"` block at the tail (53 B) for
# fp384_sqr_extra / mul_src2_buf_384 / fp384_sqr_pairs.  Those land in
# CRYPTO_RESIDENT BSS via the canonical BSS segment name (no rewrite
# needed) since the overlay gets swapped out between calls.
sed -i '' 's/^\.segment "CODE"/.segment "OVERLAY_P384_CURVE"/' "$STAGING/fp384_raw.s"
sed -i '' 's/^\.segment "CODE"/.segment "OVERLAY_P384_CURVE"/' "$STAGING/mod384_raw.s"
sed -i '' 's/^\.segment "CODE"/.segment "OVERLAY_P384_CURVE"/' "$STAGING/points384_raw.s"
sed -i '' 's/^\.segment "CODE"/.segment "OVERLAY_P384_CURVE"/' "$STAGING/ecdsa384_raw.s"
# curve384.s uses RODATA -- route into OVERLAY_P384_CURVE (read-only constants).
sed -i '' 's/^\.segment "RODATA"/.segment "OVERLAY_P384_CURVE"/' "$STAGING/curve384_raw.s"
# sha384.s: code (CODE) and IV/K[80] round constants (RODATA) both into
# the SHA-384 overlay.
sed -i '' 's/^\.segment "CODE"/.segment "OVERLAY_P384_SHA384"/' "$STAGING/sha384_raw.s"
sed -i '' 's/^\.segment "RODATA"/.segment "OVERLAY_P384_SHA384"/' "$STAGING/sha384_raw.s"

# --- mod384.s curve constants (ec_p384, ec_n384) live in CODE segment in
# the sibling and are emitted inline with .byte directives.  After the
# CODE->OVERLAY_P384_CURVE rewrite they flow into the curve overlay
# alongside the code that reads them; that is intentional
# (fp_mod_reduce384 reads ec_p384 and IS in the curve overlay).

# --- Forbidden-symbol guard (curve archive only) ---
# After the strip, points384_raw.s must NOT reference any of the removed
# Lim-Lee comb / precompute symbols.  ec_gx384 / ec_gy384 / cm_k_384 /
# ec_anchor*_384 patterns CAN appear as comments; we strip leading
# whitespace and a leading `;` before the grep so we only match active
# code.  ec_gx384 / ec_gy384 are intentionally left LIVE in the staging
# tree (used by the shim).  cm_k_384, ec_anchor[0-9]_384, ec384_sc_byte/
# mask, ec384_precomp_i remain forbidden -- those bodies were physically
# removed.
if grep -v '^\s*;' "$STAGING/points384_raw.s" \
   | grep -qE '\bec384_sc_byte\b|\bec384_sc_mask\b|\bec384_precomp_i\b|\bcm_k_384\b|\bec_anchor[0-9]_384\b'; then
    echo "ERROR: stripped points384 still references removed-body symbols" >&2
    grep -v '^\s*;' "$STAGING/points384_raw.s" \
      | grep -nE '\bec384_sc_byte\b|\bec384_sc_mask\b|\bec384_precomp_i\b|\bcm_k_384\b|\bec_anchor[0-9]_384\b' \
      | head -5 >&2
    exit 1
fi

# --- Forbidden-symbol guard (Phase 1.5 wrapper-strip) ---
# After the wrapper-strip, ecdsa384_raw.s must NOT reference any of the
# SHA-384 entry points (those live in the OTHER overlay half) or the
# wrapper-only labels.  Active-code grep only.
if grep -v '^\s*;' "$STAGING/ecdsa384_raw.s" \
   | grep -qE '\bsha384_init\b|\bsha384_update\b|\bsha384_final\b|\becdsa_verify_with_message_384\b|\becdsa_verify_with_msg_384_tramp\b|\becdsa384_msg_struct_ptr\b'; then
    echo "ERROR: stripped ecdsa384 still references wrapper / SHA symbols" >&2
    grep -v '^\s*;' "$STAGING/ecdsa384_raw.s" \
      | grep -nE '\bsha384_init\b|\bsha384_update\b|\bsha384_final\b|\becdsa_verify_with_message_384\b|\becdsa_verify_with_msg_384_tramp\b|\becdsa384_msg_struct_ptr\b' \
      | head -5 >&2
    exit 1
fi

# --- Assemble each staged .s file ---
OBJ_DIR="$STAGING/obj"
rm -rf "$OBJ_DIR"
mkdir -p "$OBJ_DIR" "$OUT_DIR"

# zp_config.s is the single point of truth for the library's ZP equates.
# We assemble it with `-D` overrides so the sibling's defaults are
# replaced by c64-https's canonical ZP map (with the Phase 1.5 SHA-384
# slot moves).  The other source files use `.importzp` to pull these
# equates from the linker-resolved zp_config.o.
# `-g` embeds cc65 debug info into each .o; the overlay ld65 invocation
# in build_nistcurves_p384_bin.sh merges it into build/lib/overlay-p384.dbg.
# Does not change emitted code bytes.
"$CA65" \
    -g \
    -I "$STAGING" \
    -I "$PROJECT_ROOT/src/crypto/shared" \
    "${ZP_DEFINES[@]}" \
    -o "$OBJ_DIR/zp_config.o" "$STAGING/zp_config.s"

# Other files: NO -D.  Let `.importzp` resolve through the linker to
# zp_config.o's `.exportzp` declarations.  If we passed -D here the
# assembler would treat the symbol as locally-defined absolute and
# conflict with the .importzp declaration.
for src in fp384_raw mod384_raw points384_raw curve384_raw \
           sha384_raw ecdsa384_raw ec_scalar_mul_384_shim_raw \
           data_curve_raw data_sha_raw; do
    "$CA65" \
        -g \
        -I "$STAGING" \
        -I "$PROJECT_ROOT/src/crypto/shared" \
        -o "$OBJ_DIR/$src.o" "$STAGING/$src.s"
done

# --- Archive: nistcurves-p384-sha384.a (SHA-384 hash overlay half) ---
# Members: zp_config + sha384_raw + data_sha_raw.
# The SHA archive does NOT contain ANY curve code; ld65 link resolves
# only the SHA exports + the resident SHA DATA buffers.
rm -f "$ARCHIVE_SHA"
"$AR65" a "$ARCHIVE_SHA" \
    "$OBJ_DIR/zp_config.o" \
    "$OBJ_DIR/sha384_raw.o" \
    "$OBJ_DIR/data_sha_raw.o"

# --- Archive: nistcurves-p384-curve.a (curve / verify overlay half) ---
# Members: zp_config + fp384 + mod384 + points384 + curve384 +
# ecdsa384 (verify_384 only) + shim + data_curve_raw.
# The curve archive does NOT contain ANY SHA code or SHA DATA exports;
# ld65 link resolves only ecdsa_verify_384 + the resident curve DATA
# buffers.
rm -f "$ARCHIVE_CURVE"
"$AR65" a "$ARCHIVE_CURVE" \
    "$OBJ_DIR/zp_config.o" \
    "$OBJ_DIR/fp384_raw.o" \
    "$OBJ_DIR/mod384_raw.o" \
    "$OBJ_DIR/points384_raw.o" \
    "$OBJ_DIR/curve384_raw.o" \
    "$OBJ_DIR/ecdsa384_raw.o" \
    "$OBJ_DIR/ec_scalar_mul_384_shim_raw.o" \
    "$OBJ_DIR/data_curve_raw.o"

# --- Per-source byte counts ---
{
    echo "# nistcurves-p384-sha384.a per-source byte counts (ca65 .o file sizes)"
    for src in zp_config sha384_raw data_sha_raw; do
        bytes=$(wc -c < "$OBJ_DIR/$src.o")
        printf '%-32s %d bytes (.o)\n' "$src" "$bytes"
    done
} > "$SIZES_SHA"

{
    echo "# nistcurves-p384-curve.a per-source byte counts (ca65 .o file sizes)"
    for src in zp_config fp384_raw mod384_raw points384_raw curve384_raw \
               ecdsa384_raw ec_scalar_mul_384_shim_raw data_curve_raw; do
        bytes=$(wc -c < "$OBJ_DIR/$src.o")
        printf '%-32s %d bytes (.o)\n' "$src" "$bytes"
    done
} > "$SIZES_CURVE"

echo "built $ARCHIVE_SHA"
cat "$SIZES_SHA"
echo "built $ARCHIVE_CURVE"
cat "$SIZES_CURVE"
