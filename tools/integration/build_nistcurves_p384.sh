#!/usr/bin/env bash
# =============================================================================
# tools/integration/build_nistcurves_p384.sh - Build c64-nist-curves P-384
# overlay archives for the UCI backend smoke test + Phase 5 production use.
#
# Phase 1.5 split + W5 (library-ingestion architecture). Under the
# c64-lib-contract (libs/nistcurves v0.3.0), upstream publishes
# `make lib-p384-sha384` and `make lib-p384-verify` build targets. This
# script delegates the heavy lifting to upstream `make`, then performs
# adjustments before placing the archives at the locations the top-level
# Makefile expects:
#
#   1. Rebuild zp_config.o with c64-https's ZP-slot overrides. The
#      sibling defaults sha_src/sha_len/sha_w_ptr/sha_w_ptr2 ($04/$06/
#      $08/$0a) collide with c64-https's $04-$09 = w32_* (ChaCha20/
#      Poly1305) and $0A-$0D = sha_temp1 (SHA-256). $3D-$44 is the
#      lowest 8-byte contiguous free block above the canonical crypto
#      ZP map and is dedicated to the SHA-384 call window. fp_mul_i /
#      fp_mul_j also relocated ($39/$3a vs upstream $2c/$2d) to dodge
#      the fe25519 claim. Other slots inherit upstream defaults.
#
#   2. Drop `mul_8x8.o` + `data_shared.o` from the curve archive
#      (same conflict reasoning as build_nistcurves_p256.sh — c64-https
#      provides them via src/crypto/poly1305.s + src/data.s).
#
#   3. Emit an ec_scalar_mul_384 shim. The upstream lib-p384-verify
#      archive excludes points384_comb.s (the Lim-Lee fixed-base
#      comb), so `ec_scalar_mul_384` is unresolved. We provide the
#      symbol via a one-page shim that copies G into
#      ec_base384_x/y and tail-calls ec_scalar_mul_var_384. Pattern
#      mirrors c64-https's existing src/crypto/ecdsa_verify.s::ec_scalar_mul
#      (Phase C.4 P-256 dispatcher).
#
# Outputs:
#   build/lib/nistcurves-p384-sha384.a            - SHA-384 overlay archive
#   build/lib/nistcurves-p384-curve.a             - curve verify overlay archive
#   build/lib/nistcurves-p384-{sha384,curve}.sizes.txt
# =============================================================================
set -eo pipefail

# --- Paths ---
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB_DIR="$PROJECT_ROOT/libs/nistcurves"
LIB_SRC="$LIB_DIR/src"
LIB_BUILD="$LIB_DIR/build"
STAGING="$PROJECT_ROOT/build/lib/nistcurves_p384_staging"
OUT_DIR="$PROJECT_ROOT/build/lib"
ARCHIVE_SHA="$OUT_DIR/nistcurves-p384-sha384.a"
ARCHIVE_CURVE="$OUT_DIR/nistcurves-p384-curve.a"
SIZES_SHA="$OUT_DIR/nistcurves-p384-sha384.sizes.txt"
SIZES_CURVE="$OUT_DIR/nistcurves-p384-curve.sizes.txt"

CA65="${CA65:-ca65}"
AR65="${AR65:-ar65}"

# --- ZP-slot overrides (c64-https canonical map + SHA-384 isolated window) ---
# zp_ptr2's SPELLING is pin-dependent and probed, never hardcoded — see the
# long rationale in build_nistcurves_p256.sh (contract SPEC §2 ZP prefix
# registry + §6.5's loud-break alias shape: on a migrated pin the bare
# spelling is an unguarded alias and `-D zp_ptr2=...` dies with
# "Symbol 'zp_ptr2' is already defined"). `fp_`/`sha_` are registered §2
# prefixes for c64-nist-curves and keep their `.ifndef` guards, so only this
# one slot needs the probe.
if grep -qE '^[[:space:]]*\.ifndef[[:space:]]+nistcurves_zp_ptr2[[:space:]]*$' "$LIB_SRC/zp_config.s"; then
    ZP_PTR2_SLOT='nistcurves_zp_ptr2'
else
    ZP_PTR2_SLOT='zp_ptr2'
fi
ZP_OVERRIDES=(
    '-D' "$ZP_PTR2_SLOT=\$3d"
    '-D' 'fp_mul_i=$39'
    '-D' 'fp_mul_j=$3a'
    # SHA-384 streaming pointer slots (moved out of $04-$0b defaults
    # to avoid w32_* / sha_temp1 collision; see header).
    '-D' 'sha_src=$3d'
    '-D' 'sha_len=$3f'
    '-D' 'sha_w_ptr=$41'
    '-D' 'sha_w_ptr2=$43'
)
# Note: zp_ptr2 and sha_src both pin $3d. zp_ptr2 is curve-archive-only
# (ecdsa384.s imports it); sha_src is SHA-archive-only. They never share
# a call window — curve overlay and sha overlay are mutually exclusive
# in the live CRYPTO_OVERLAY slot. The defaults below feed BOTH archives'
# zp_config.o builds, but each archive's call window only consumes the
# slot relevant to its own bodies. Safe.

# --- 1. Build upstream's lib-p384-sha384 + lib-p384-verify archives ---
# Same caveat as P-256: upstream's Makefile builds every module with the
# same recipe, so we can't pass -D overrides via `make CA65=...` (would
# error on .importzp redefinition in non-zp_config files). Build upstream
# with defaults, then rebuild zp_config.o ourselves below.
#
# Note on c64-lib-contract SPEC §8.1: only nistcurves v0.3.0's
# `mul_8x8.s` references sqtab_lo / sqtab_hi (via the local
# `.ifndef LIB_SHARED_SQTAB_BASE` equate in that file). Step 4 drops
# `mul_8x8.o` and `data_shared.o` from the curve archive entirely;
# the SHA-384 archive (separate compile path) never linked mul_8x8
# in the first place since SHA-384 is multiply-free. So the upstream
# default LIB_SHARED_SQTAB_BASE baked into mul_8x8.o is discarded
# before it reaches either overlay's link — no override required at
# the nistcurves Makefile invocation.
echo "[p384] building libs/nistcurves lib-p384-sha384 + lib-p384-verify (upstream defaults)..."
make -s -C "$LIB_DIR" lib-p384-sha384 lib-p384-verify >/dev/null

UPSTREAM_SHA_ARCHIVE="$LIB_BUILD/lib/nistcurves-p384-sha384.a"
UPSTREAM_CURVE_ARCHIVE="$LIB_BUILD/lib/nistcurves-p384-verify.a"
for f in "$UPSTREAM_SHA_ARCHIVE" "$UPSTREAM_CURVE_ARCHIVE"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: upstream archive missing: $f" >&2
        exit 1
    fi
done

# --- 2. Stage upstream object files ---
rm -rf "$STAGING"
mkdir -p "$STAGING/sha" "$STAGING/curve" "$OUT_DIR"
cp "$UPSTREAM_SHA_ARCHIVE" "$STAGING/sha/upstream.a"
cp "$UPSTREAM_CURVE_ARCHIVE" "$STAGING/curve/upstream.a"
(cd "$STAGING/sha"   && "$AR65" x upstream.a $( "$AR65" t upstream.a ))
(cd "$STAGING/curve" && "$AR65" x upstream.a $( "$AR65" t upstream.a ))

# --- 3. Rebuild each archive's zp_config member with c64-https overrides ---
# Member names are DISCOVERED, never hardcoded. Upstream v0.9.0 (issue #90)
# gave every archive its own per-variant manifest + ZP objects, so
# `zp_config.o` / `lib_manifest.o` no longer exist in these archives —
# they are `zp_config_sha384.o` / `lib_manifest_p384verify.o` and friends.
# Hardcoding the old names made this script die at the ar65 staging step.
#
# The variant gate matters twice over: it selects which slots the object
# `.exportzp`s, and the SHA-384 variant deliberately exports only the four
# sha_* slots — so the c64-https overrides below are a legitimate no-op there
# and the post-check must tolerate their absence rather than demand them.
find_member() {
    # find_member <staging-dir> <glob>   -> echoes the single matching member
    local dir="$1" glob="$2" hit="" m
    for m in $( "$AR65" t "$dir/upstream.a" ); do
        case "$m" in $glob)
            [ -z "$hit" ] || { echo "ERROR: $dir/upstream.a has >1 member matching '$glob' ($hit, $m)" >&2; exit 1; }
            hit="$m" ;;
        esac
    done
    [ -n "$hit" ] || { echo "ERROR: no member matching '$glob' in $dir/upstream.a — upstream layout changed" >&2; exit 1; }
    echo "$hit"
}

zp_variant_define() {
    case "$1" in
        zp_config.o)             ;;
        zp_config_p256verify.o)  echo '-D LIB_P256_VERIFY_ONLY' ;;
        zp_config_p384verify.o)  echo '-D LIB_P384_VERIFY_ONLY' ;;
        zp_config_p384curve.o)   echo '-D LIB_P384_CURVE_ONLY' ;;
        zp_config_sha384.o)      echo '-D LIB_SHA384_ONLY' ;;
        *) echo "ERROR: unrecognised zp_config member '$1' — add its upstream -D gate" >&2; exit 1 ;;
    esac
}

# Present ⇒ must carry the c64-https value. Absent ⇒ this variant does not
# export the slot, which is fine. A wrong value is silent memory corruption
# at runtime, never a link error, so it has to be caught here.
check_zp_slot_if_present() {
    local obj="$1" name="$2" want="$3" got
    got=$("${OD65:-od65}" --dump-exports "$obj" \
          | awk -v n="\"$name\"" '$1=="Name:" && $2==n {f=1; next} f && $1=="Value:" {gsub(/[()]/,"",$3); print $3; exit}')
    [ -z "$got" ] && return 0
    if [ "$got" != "$want" ]; then
        echo "ERROR: $(basename "$obj") exports $name = $got, expected $want (c64-https ZP override did not take)" >&2
        exit 1
    fi
}

for tree in sha curve; do
    zp_member="$(find_member "$STAGING/$tree" 'zp_config*.o')"
    echo "[p384] rebuilding $tree/$zp_member with c64-https ZP overrides..."
    # shellcheck disable=SC2046  # deliberate word-split of the -D pair
    "$CA65" \
        --cpu 6502 \
        -g \
        -I "$LIB_SRC" \
        $(zp_variant_define "$zp_member") \
        "${ZP_OVERRIDES[@]}" \
        -o "$STAGING/$tree/$zp_member" \
        "$LIB_SRC/zp_config.s"
    check_zp_slot_if_present "$STAGING/$tree/$zp_member" zp_ptr2  61   # $3d
    check_zp_slot_if_present "$STAGING/$tree/$zp_member" fp_mul_i 57   # $39
    check_zp_slot_if_present "$STAGING/$tree/$zp_member" fp_mul_j 58   # $3a
done

SHA_ZP="$(find_member "$STAGING/sha" 'zp_config*.o')"
CURVE_ZP="$(find_member "$STAGING/curve" 'zp_config*.o')"
SHA_MANIFEST="$(find_member "$STAGING/sha" 'lib_manifest*.o')"
CURVE_MANIFEST="$(find_member "$STAGING/curve" 'lib_manifest*.o')"
SHA_PRECALC="$(find_member "$STAGING/sha" 'precalc_manifest*.o')"
CURVE_PRECALC="$(find_member "$STAGING/curve" 'precalc_manifest*.o')"

# --- 4. Drop conflicting members from the curve archive ---
# Same reasoning as P-256: mul_8x8.o + data_shared.o collide with
# c64-https's in-tree src/crypto/poly1305.s + src/data.s exports.
rm -f "$STAGING/curve/mul_8x8.o" "$STAGING/curve/data_shared.o"

# --- 5. Build ec_scalar_mul_384 shim (Option A: variable-base scalar-mul) ---
# The upstream lib-p384-verify archive excludes points384_comb.s (the
# Lim-Lee fixed-base comb), so `ec_scalar_mul_384` (the symbol ecdsa384.s
# imports at line 49) is unresolved. We provide it via this shim that
# copies G into ec_base384_x/y and tail-calls ec_scalar_mul_var_384.
#
# Pattern mirrors src/crypto/ecdsa_verify.s::ec_scalar_mul (Phase C.4
# P-256 dispatcher). Slower per-call than the real Lim-Lee comb but
# avoids the ~24 KB REU bank-2 anchor table + ~100 s
# ec_precompute_384 boot drag.
cat > "$STAGING/curve/ec_scalar_mul_384_shim.s" <<'SHIM_EOF'
.setcpu "6502"

; =============================================================================
; ec_scalar_mul_384_shim.s -- Option A shim for the Lim-Lee fixed-base
; scalar-mul (excluded from lib-p384-verify). Provides ec_scalar_mul_384
; by copying G into ec_base384_x/y and tail-calling ec_scalar_mul_var_384.
;
; Lives in the P384 code segment (same overlay slot as the rest of the
; curve archive).
; =============================================================================

.segment "LIB_NISTCURVES_P384_CODE"

.export ec_scalar_mul_384

.import ec_gx384, ec_gy384
.import ec_base384_x, ec_base384_y
.import ec_scalar_mul_var_384

ec_scalar_mul_384:
        ; Copy G.x -> ec_base384_x (48 bytes; ldy #47 / bpl safe since 47 < 128)
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
        jmp ec_scalar_mul_var_384       ; tail-call
SHIM_EOF

"$CA65" \
    --cpu 6502 \
    -g \
    -I "$LIB_SRC" \
    -o "$STAGING/curve/ec_scalar_mul_384_shim.o" \
    "$STAGING/curve/ec_scalar_mul_384_shim.s"

# --- 6. Re-archive both halves ---
# SHA archive: zp_config + lib_version + lib_manifest + sha384 + data_sha.
# Self-contained — no curve / mul code.
rm -f "$ARCHIVE_SHA"
"$AR65" a "$ARCHIVE_SHA" \
    "$STAGING/sha/lib_version.o" \
    "$STAGING/sha/$SHA_MANIFEST" \
    "$STAGING/sha/$SHA_PRECALC" \
    "$STAGING/sha/$SHA_ZP" \
    "$STAGING/sha/sha384.o" \
    "$STAGING/sha/data_sha.o"

# Curve archive: zp_config + lib_version + lib_manifest + constants +
# reu_config + fp384 + mod384 + curve384 + points384_core + ecdsa384 +
# shim + data_p384. mul_8x8 + data_shared dropped (c64-https owns).
rm -f "$ARCHIVE_CURVE"
"$AR65" a "$ARCHIVE_CURVE" \
    "$STAGING/curve/lib_version.o" \
    "$STAGING/curve/$CURVE_MANIFEST" \
    "$STAGING/curve/$CURVE_PRECALC" \
    "$STAGING/curve/$CURVE_ZP" \
    "$STAGING/curve/constants.o" \
    "$STAGING/curve/reu_config.o" \
    "$STAGING/curve/fp384.o" \
    "$STAGING/curve/mod384.o" \
    "$STAGING/curve/curve384.o" \
    "$STAGING/curve/points384_core.o" \
    "$STAGING/curve/ecdsa384_nocomb.o" \
    "$STAGING/curve/ec_scalar_mul_384_shim.o" \
    "$STAGING/curve/data_p384.o"

# --- 7. Per-source byte counts ---
{
    echo "# nistcurves-p384-sha384.a per-source byte counts (ca65 .o file sizes)"
    for src in lib_version "${SHA_MANIFEST%.o}" "${SHA_PRECALC%.o}" "${SHA_ZP%.o}" sha384 data_sha; do
        if [ -f "$STAGING/sha/$src.o" ]; then
            bytes=$(wc -c < "$STAGING/sha/$src.o")
            printf '%-32s %d bytes (.o)\n' "$src" "$bytes"
        fi
    done
} > "$SIZES_SHA"

{
    echo "# nistcurves-p384-curve.a per-source byte counts (ca65 .o file sizes)"
    for src in lib_version "${CURVE_MANIFEST%.o}" "${CURVE_PRECALC%.o}" "${CURVE_ZP%.o}" constants reu_config \
               fp384 mod384 curve384 points384_core ecdsa384_nocomb \
               ec_scalar_mul_384_shim data_p384; do
        if [ -f "$STAGING/curve/$src.o" ]; then
            bytes=$(wc -c < "$STAGING/curve/$src.o")
            printf '%-32s %d bytes (.o)\n' "$src" "$bytes"
        fi
    done
} > "$SIZES_CURVE"

echo "built $ARCHIVE_SHA"
cat "$SIZES_SHA"
echo "built $ARCHIVE_CURVE"
cat "$SIZES_CURVE"
