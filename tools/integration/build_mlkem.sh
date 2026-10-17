#!/usr/bin/env bash
# =============================================================================
# tools/integration/build_mlkem.sh - Build the c64-mlkem v0.6.0 ML-KEM-768
# archive for the PQ_HYBRID=1 link (PQC plan phase P0).
#
# Thin wrapper, the nistcurves shape (not the x25519 staging shape): it drives
# upstream's own `make lib` with consumer CONTRACT_DEFINES, then checks what
# came out before re-archiving it as build/lib/mlkem.a with OUR zero-page
# object added. No upstream source is staged or rewritten.
#
#   build/lib/mlkem.a           upstream members (discovered, never named)
#                               + mlkem_zp_config.o (our ZP slots)
#   build/lib/mlkem.sizes.txt   per-member LIB_MLKEM_* segment sizes (od65)
#
# CONTRACT_DEFINES (reach every archive member):
#   SHARED_SQTAB_INIT=1          c64-https owns the §8.1 sqtab and its init
#                                (src/crypto/poly1305.s::sqtab_init, run by
#                                boot.s); the library's own mul_tables_init
#                                body collapses to an import. c64-https's
#                                `mul_tables_init` export
#                                (src/crypto/shared/mul_tables.s) is an RTS
#                                stub; the library never calls it itself
#                                (init is the consumer's job), so the import
#                                only has to resolve.
#   LIB_SHARED_SQTAB_BASE=0xBC00 the address src/data.s's sqtab_lo lands at,
#                                asserted after every link by the Makefile's
#                                $(PRG) recipe. Same value as build_x25519.sh
#                                and build_nistcurves_p256.sh: ONE table.
#                                `$`-free on purpose (§2: an unquoted `$B`
#                                is a shell positional parameter).
#   LIB_NO_BARE_EXPORTS=1        no deprecated unprefixed §1/§8.4 exports
#                                (c64-mlkem ships none anyway; belt+braces,
#                                they would collide with nistcurves').
#
# Zero page: c64-mlkem uses the §6.2 consumer-assembled model — no archive
# member defines a slot; we assemble upstream's src/zp_config.s ourselves
# with -D overrides. Upstream's defaults ($30-$3F) are NOT usable here:
#
#   default slot          c64-https tenant at that address
#   $30-$37 src/dst/len/tmp   inside fe25519's declared $2C-$37 claim and the
#                             ECDSA bignum range $22-$3C
#   $38-$3F mlkem_zp_mul      fp_mul_i $39, fp_mul_j $3A, ec_scalar_ptr
#                             $3B-$3C, nistcurves_zp_ptr2 $3D, and
#                             tls_hs_ptr $3E-$3F — the W1 handshake-message
#                             base pointer, which is LIVE across the message
#                             handlers. P4 calls Decaps from the ServerHello
#                             path, so the default would clobber it.
#
# Chosen: ZP_WIDE $40-$4F (16 B, cfg ZP_WIDE $40-$7F).
#
#   slot           addr      co-tenant at that address   why it is free there
#   mlkem_zp_src   $40-$41   X25519 fe_wide ($40-$7F)    fe_wide is per-call
#   mlkem_zp_dst   $42-$43     "                         scratch inside
#   mlkem_zp_len   $44-$45     "                         fe25519_mul/sqr; an
#   mlkem_zp_tmp   $46-$47     "                         X25519 call never
#   mlkem_zp_mul   $48-$4F     "  (8 B)                  nests in an ML-KEM
#                                                        call or vice versa
#
# Nothing of c64-https's own is placed in ZP_WIDE (src/constants.inc), so
# the ONLY co-tenant is another leaf crypto primitive, and every ML-KEM slot
# is per-call scratch too (mlkem.inc: "Clobbers ... every mlkem_zp_* slot";
# the parameter block lives in LIB_MLKEM_BSS, not ZP). Lifetimes are
# disjoint, so time-sharing is safe; no TLS state is exposed. The values are
# re-asserted at link time against these exact addresses in
# src/crypto/mlkem_link.s, so this table cannot drift silently.
#
# Usage (from the Makefile, PQ_HYBRID=1 only):
#   bash tools/integration/build_mlkem.sh
# =============================================================================
set -eo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB_ROOT="$PROJECT_ROOT/libs/mlkem"
STAGING="$PROJECT_ROOT/build/lib/mlkem_staging"
OUT_DIR="$PROJECT_ROOT/build/lib"
ARCHIVE="$OUT_DIR/mlkem.a"
SIZES="$OUT_DIR/mlkem.sizes.txt"

CA65="${CA65:-ca65}"
AR65="${AR65:-ar65}"
OD65="${OD65:-od65}"
MAKE="${MAKE:-make}"

# `$`-free values (contract §2).
CONTRACT_DEFINES="-D SHARED_SQTAB_INIT=1 -D LIB_SHARED_SQTAB_BASE=0xBC00 -D LIB_NO_BARE_EXPORTS=1"
ZP_DEFINES=(
    -D mlkem_zp_src=0x40
    -D mlkem_zp_dst=0x42
    -D mlkem_zp_len=0x44
    -D mlkem_zp_tmp=0x46
    -D mlkem_zp_mul=0x48
)

if [ ! -f "$LIB_ROOT/src/kem.s" ]; then
    echo "ERROR: libs/mlkem is not checked out (git submodule update --init --recursive)" >&2
    exit 1
fi

# --- 0. Preflight: the checkout must be new enough (the #124 shape) ---
# A source probe, not a tag comparison, for the same reason as
# build_nistcurves_p256.sh: what this wrapper and src/crypto/mlkem_link.s
# require is behavioural. v0.6.0 / ABI 3 is the first release with
#   - the LIB_MLKEM_POLY_BSS segment (the cfgs' MLKEM_POLY_RAM at $D000
#     and the $B100 union both depend on the split), and
#   - mlkem_decaps_seed (Decaps from the 64 B seed; no 2,400 B dk kept).
# A v0.5.x checkout would otherwise fail much later, at link, as
# "Missing memory area assignment" or as an unresolved symbol, which names
# neither the cause nor the remedy.
probe_fail() {
    local head pin
    head="$(git -C "$PROJECT_ROOT/libs/mlkem" rev-parse HEAD 2>/dev/null || echo unknown)"
    pin="$(git -C "$PROJECT_ROOT" ls-tree HEAD libs/mlkem 2>/dev/null | awk '{print $3}' || true)"
    cat >&2 <<EOF
ERROR: libs/mlkem checkout is unusable for this build (PQ_HYBRID=1).

  $1

  submodule checkout : ${head:0:12}
  this repo pins     : ${pin:0:12}

Fix it with:

    git submodule update --init --recursive

If that reports nothing and the build still fails, force it:

    git submodule update --force --init --recursive
EOF
    exit 1
}
grep -q 'LIB_MLKEM_ABI_VERSION *= *3' "$LIB_ROOT/src/lib_version.s" 2>/dev/null \
    || probe_fail "src/lib_version.s does not declare LIB_MLKEM_ABI_VERSION = 3 (need c64-mlkem >= v0.6.0)"
grep -q 'LIB_MLKEM_POLY_BSS' "$LIB_ROOT/src/kem.s" 2>/dev/null \
    || probe_fail "src/kem.s has no LIB_MLKEM_POLY_BSS segment (need c64-mlkem >= v0.6.0)"
grep -q 'mlkem_decaps_seed' "$LIB_ROOT/src/kem.s" 2>/dev/null \
    || probe_fail "src/kem.s has no mlkem_decaps_seed (need c64-mlkem >= v0.6.0)"

# --- Upstream archive ---
# -B: upstream keeps its objects in libs/mlkem/build, outside `make clean`;
# its own config-sig guard already invalidates on a CONTRACT_DEFINES change,
# but forcing costs ~1 s and removes the question.
"$MAKE" -B -C "$LIB_ROOT" lib CA65="$CA65" AR65="$AR65" \
    CONTRACT_DEFINES="$CONTRACT_DEFINES" >/dev/null
UP_ARCHIVE="$LIB_ROOT/build/lib/mlkem.a"
[ -f "$UP_ARCHIVE" ] || { echo "ERROR: upstream make lib produced no $UP_ARCHIVE" >&2; exit 1; }

rm -rf "$STAGING"
mkdir -p "$STAGING/members" "$OUT_DIR"

# --- Discover members (never hardcode: the nistcurves v0.9.0 lesson) ---
MEMBERS=()
while IFS= read -r m; do
    [ -n "$m" ] && MEMBERS+=("$m")
done < <("$AR65" t "$UP_ARCHIVE")
[ "${#MEMBERS[@]}" -gt 0 ] || { echo "ERROR: $UP_ARCHIVE has no members" >&2; exit 1; }
( cd "$STAGING/members" && "$AR65" x "$UP_ARCHIVE" "${MEMBERS[@]}" )

# --- od65 checks on every member ---
fail=0
for m in "${MEMBERS[@]}"; do
    obj="$STAGING/members/$m"
    # 1. Only the four §4 segments may carry bytes; anything else has no
    #    home in our cfgs (and a bare CODE/BSS would land in c64-https's).
    bad=$("$OD65" --dump-segsize "$obj" | awk -F: '/^    [A-Z_0-9]+:/ {
            gsub(/ /,"",$1); gsub(/ /,"",$2);
            if ($2 != "0" && $1 !~ /^LIB_MLKEM_(CODE|RODATA|BSS|POLY_BSS)$/) print $1"="$2 }')
    if [ -n "$bad" ]; then
        echo "ERROR: $m carries bytes outside LIB_MLKEM_{CODE,RODATA,BSS,POLY_BSS}: $bad" >&2; fail=1
    fi
    exports=$("$OD65" --dump-exports "$obj" | sed -n 's/^ *Name: *"\(.*\)"$/\1/p')
    # 2. §8.1 deferral took: no sqtab provider, no unprefixed table names.
    # 3. §6.2 consumer-assembled ZP: no member defines a slot.
    # 4. No test hooks (upstream issue #1 shape).
    leak=$(printf '%s\n' "$exports" | grep -E '^(mul_tables_init|sqtab_lo|sqtab_hi|mlkem_zp_[a-z]+|LIB_VERSION_[A-Z]+|LIB_ABI_VERSION)$|_hook|^test_' || true)
    if [ -n "$leak" ]; then
        echo "ERROR: $m exports $leak (deferral/ZP model/test-hook check)" >&2; fail=1
    fi
done
# The deferring sqtab member must carry no code, proving SHARED_SQTAB_INIT
# reached it (owner build: 84 B of mul_tables_init). Its `.import
# mul_tables_init` is unreferenced, and ca65 emits no import record for an
# unreferenced .import, so an import check would be vacuous; size is not.
sq_code=$("$OD65" --dump-segsize "$STAGING"/members/*sqtab*.o 2>/dev/null \
          | awk -F: '/LIB_MLKEM_CODE/ {gsub(/ /,"",$2); s+=$2} END {print s+0}')
if [ "$sq_code" -ne 0 ]; then
    echo "ERROR: the sqtab member carries $sq_code B of code: SHARED_SQTAB_INIT did not take" >&2; fail=1
fi
[ "$fail" -eq 0 ] || exit 1

# --- Our ZP object (consumer-assembled, §6.2) ---
"$CA65" -t c64 -g -I "$LIB_ROOT/src" "${ZP_DEFINES[@]}" \
    -o "$STAGING/mlkem_zp_config.o" "$LIB_ROOT/src/zp_config.s"
zp_exports=$("$OD65" --dump-exports "$STAGING/mlkem_zp_config.o" | grep -c '"mlkem_zp_' || true)
if [ "$zp_exports" -ne 5 ]; then
    echo "ERROR: mlkem_zp_config.o exports $zp_exports mlkem_zp_* slots, expected 5" >&2; exit 1
fi

# --- Archive ---
rm -f "$ARCHIVE"
OBJ_PATHS=()
for m in "${MEMBERS[@]}"; do OBJ_PATHS+=("$STAGING/members/$m"); done
"$AR65" a "$ARCHIVE" "${OBJ_PATHS[@]}" "$STAGING/mlkem_zp_config.o"

{
    echo "# mlkem.a members and LIB_MLKEM_* segment sizes (od65 --dump-segsize)"
    echo "# upstream: libs/mlkem $(git -C "$LIB_ROOT" describe --tags --always 2>/dev/null || echo unknown)"
    for m in "${MEMBERS[@]}" ; do
        printf '%-24s %s\n' "$m" "$("$OD65" --dump-segsize "$STAGING/members/$m" \
            | awk -F: '/LIB_MLKEM_/ {gsub(/ /,"",$1); gsub(/ /,"",$2); printf "%s=%s ", $1, $2}')"
    done
    printf '%-24s %s\n' mlkem_zp_config.o '(ZP equates only: $40-$4F)'
} > "$SIZES"

echo "built $ARCHIVE"
cat "$SIZES"
