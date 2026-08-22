#!/usr/bin/env bash
# =============================================================================
# tools/integration/build_nistcurves_p256.sh - Build c64-nist-curves P-256
# ECDSA verify primitives as a resident .a archive linked into the main PRG.
#
# Phase C.4 + W5 (library-ingestion architecture). Under the c64-lib-contract
# (libs/nistcurves v0.5.0), the upstream library publishes
# `make lib-p256-verify` / `make lib-p256-verify-onchip` build targets that
# produce minimal-subset archives carrying exactly the symbols needed for
# variable-base P-256 verify. This script delegates the heavy lifting to
# `make -C libs/nistcurves`, then performs adjustments before placing the
# result at the location the top-level Makefile expects:
#
#   1. Rebuild the archive's `zp_config*.o` member with c64-https's ZP-slot
#      overrides (the upstream defaults collide with c64-https's canonical map
#      on three slots: zp_ptr2, fp_mul_i, fp_mul_j). The library's zp_config.s
#      `.ifndef`-guards every slot, so an override-built version replaces the
#      upstream default cleanly. The member name is DISCOVERED from the
#      archive, not hardcoded — upstream v0.9.0 gave each archive its own
#      per-variant object (`zp_config_p256verify.o`), and a hardcoded name
#      would drop the overrides silently. Post-checked with od65.
#
#   2. Drop `mul_8x8[_onchip].o` (REU profile) and `data_shared.o` (both
#      profiles) from the archive. c64-https's in-tree
#      `src/crypto/poly1305.s` and `src/data.s` already export the same
#      symbols (mul_8x8, sqtab_init, poly_prod_lo/hi, mul_cached_a,
#      mul_src2_buf, mul_dma_lo/hi). Including the library's copies would
#      cause ld65 duplicate-symbol errors.
#
#   3. ONCHIP PROFILE ONLY (issue #69 / v0.5.0): re-add a REBUILT
#      `mul_8x8_onchip.o`, assembled with the SPEC §8.1/§8.3 consumer-shared
#      defines:
#        -D FP_ONCHIP_MUL=1        row-gen loop og_common/og_src_ld kept
#        -D SHARED_CT_MUL_8X8=1    canonical ct_mul_8x8 + poly_prod +
#                                  smc_* SUPPLIED BY src/crypto/poly1305.s
#        -D SHARED_SQTAB_INIT=1    sqtab_init SUPPLIED BY poly1305.s
#        -D LIB_SHARED_SQTAB_BASE=$BC00
#                                  sqtab_lo/hi become absolute equates at
#                                  the address data.s's placeholder reserves
#                                  (post-link check in the Makefile verifies)
#      The resulting object provides og_common / og_src_ld (imported by
#      fp256_onchip.o's gen_mul_row stubs) + the sqtab equates +
#      reu_fetch_mul_row (boot.s gates its duplicate export under
#      USE_NISTCURVES_ONCHIP).
#
# Usage:  build_nistcurves_p256.sh [reu|onchip]     (default: reu)
#
# Outputs (reu):    build/lib/nistcurves-p256.a         + .sizes.txt
# Outputs (onchip): build/lib/nistcurves-p256-onchip.a  + .sizes.txt
# =============================================================================
set -eo pipefail

PROFILE="${1:-reu}"
case "$PROFILE" in reu|onchip|onchip-comb) ;; *) echo "ERROR: profile must be reu|onchip|onchip-comb, got '$PROFILE'" >&2; exit 2;; esac

# --- Paths ---
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIB_DIR="$PROJECT_ROOT/libs/nistcurves"
LIB_SRC="$LIB_DIR/src"
LIB_BUILD="$LIB_DIR/build"
OUT_DIR="$PROJECT_ROOT/build/lib"
if [ "$PROFILE" = "onchip-comb" ]; then
    # Comb-accelerated turbo profile.
    #
    # Through the v0.10.2 pin this staged from the FULL `lib-onchip`
    # archive and deleted ~13 non-P-256 members by hand, because no
    # narrowed comb archive existed. That was SPEC §6.1 non-conformant
    # (an edited member set is outside every §5/§8.0 manifest claim the
    # archive ships) and it is why src/contract_footprint_asserts.s had
    # to exclude this profile from the §6.6 assert: the surviving
    # manifest described the pre-surgery set, 27,000 B against a
    # 16,384 B region.
    #
    # libs/nistcurves v0.11.0 added `lib-p256-comb-onchip` in response
    # (c64-nist-curves#117), carrying its own §6.4 manifest triple under
    # the LIB_P256_COMB_ONLY switch. Member set = the
    # lib-p256-verify-onchip set with the comb-fast ecdsa256.o replacing
    # ecdsa256_nocomb.o, plus points256_comb.o + data_p256_limlee.o.
    # So the surgery in step 4b is retired and the archive we link is
    # one upstream actually ships.
    #
    # Consumer boot obligation still grows by ec_precompute_256 (REU
    # bank 2 $0000-$3FFF anchors, SPEC §8.3/§8.5): measured 45 s at
    # 48 MHz on a U64E, i.e. ~36 min at 1 MHz. See c64-https#120 for
    # loading the table from disk instead.
    UPSTREAM_TARGET="lib-p256-comb-onchip"
    UPSTREAM_ARCHIVE="$LIB_BUILD/lib/nistcurves-p256-comb-onchip.a"
    ARCHIVE="$OUT_DIR/nistcurves-p256-onchip-comb.a"
    SIZES="$OUT_DIR/nistcurves-p256-onchip-comb.sizes.txt"
elif [ "$PROFILE" = "onchip" ]; then
    UPSTREAM_TARGET="lib-p256-verify-onchip"
    UPSTREAM_ARCHIVE="$LIB_BUILD/lib/nistcurves-p256-verify-onchip.a"
    ARCHIVE="$OUT_DIR/nistcurves-p256-onchip.a"
    SIZES="$OUT_DIR/nistcurves-p256-onchip.sizes.txt"
else
    UPSTREAM_TARGET="lib-p256-verify"
    UPSTREAM_ARCHIVE="$LIB_BUILD/lib/nistcurves-p256-verify.a"
    ARCHIVE="$OUT_DIR/nistcurves-p256.a"
    SIZES="$OUT_DIR/nistcurves-p256.sizes.txt"
fi

CA65="${CA65:-ca65}"
AR65="${AR65:-ar65}"

# --- 0. Preflight: the submodule checkout must be new enough ---
# Issue #124. A stale libs/nistcurves working checkout under a current
# wrapper produces an error that names the wrong cause entirely:
#
#   ERROR: zp_config.o exports nistcurves_zp_ptr2 = <absent>,
#          expected 0x0000003D (CONTRACT_ZP_DEFINES did not take)
#
# — which reads as "the knob is broken" when the truth is "your submodule is
# four releases behind the gitlink". The reporter never touched that knob.
# Reproduced by moving ONLY the submodule checkout under a fresh clone of
# master: v0.6.0 and v0.8.0 give that line character for character (their
# lib-p256-verify archive still carries a bare `zp_config.o`; the per-variant
# name arrived in v0.9.0), v0.9.1 gives the same text with the per-variant
# member name, v0.10.1 and later pass.
#
# Two properties make this worth a preflight rather than a better message
# further down:
#
#   - `tools/check_upstream_pins.py` cannot catch it. It reads the gitlink
#     with `git ls-tree` on purpose, so it works on a submodule that was
#     never `--init`'d — which means it reports the PINNED version and would
#     have said "v0.11.2, no drift" while the working tree sat at v0.6.0.
#     Its --worktree mode, added alongside this, is the standalone check.
#   - The failure is several minutes into a build, after upstream's make has
#     assembled the whole archive.
#
# The gate is a source probe, not a tag comparison: tags are the wrong
# oracle here (c64-x25519 ships lightweight ones that `git describe`
# without `--tags` cannot see, and this org rebuilt the c64-nist-curves
# history in 2026-05, moving tag commits). What the wrapper actually
# requires is behavioural — the two knobs it passes must be honoured:
#
#   CONTRACT_ZP_DEFINES     upstream v0.10.0; without it the ZP overrides
#                           are discarded and the post-check reports
#                           <absent> (the #124 signature)
#   nistcurves_zp_ptr2      the §6.5 canonical spelling of the slot, also
#                           v0.10.0 — a pin that predates it would need the
#                           bare `zp_ptr2`, and this wrapper only passes the
#                           canonical name
#
# Probing for those two says exactly what the next 200 lines depend on, and
# keeps saying it correctly if upstream renames a tag under us. It is
# deliberately NOT the full requirement — CLAUDE.md records >= v0.11.2 for
# reasons this cannot see (v0.11.1's on-chip SHARED_CT_MUL_8X8 fix, v0.11.2's
# knob-staleness guard, both of which fail later and elsewhere). This gate
# exists to convert one specific illegible failure into a remedy, not to
# certify the pin.
lib_preflight_fail() {
    local what="$1"
    local head;  head="$(git -C "$LIB_DIR" rev-parse HEAD 2>/dev/null || true)"
    local found; found="$(git -C "$LIB_DIR" describe --tags --always 2>/dev/null || echo '<unknown>')"
    local pin;   pin="$(git -C "$PROJECT_ROOT" ls-tree HEAD libs/nistcurves 2>/dev/null | awk '{print $3}')"
    local diagnosis
    if [ -z "$head" ]; then
        diagnosis="The submodule is not checked out at all."
    elif [ "$head" != "$pin" ]; then
        diagnosis="The submodule working tree is NOT the commit this repo pins."
    else
        # Same sha as the gitlink, yet the probes failed: the checkout has been
        # edited in place, or the gitlink itself is stale. Say so rather than
        # sending someone at a `git submodule update` that will report nothing.
        diagnosis="The working tree IS at the pinned commit, so this is not the usual
staleness — the checkout has local modifications, or this branch's gitlink is
itself too old."
    fi
    cat >&2 <<EOF
ERROR: libs/nistcurves checkout is unusable for this build (c64-https#124).

  $what

  submodule checkout : $found
  this repo pins     : ${pin:0:12}${pin:+ (v0.11.2)}

$diagnosis Fix it with:

    git submodule update --init --recursive

If that reports nothing and the build still fails, force it:

    git submodule update --force --init --recursive

Note that tools/check_upstream_pins.py will NOT show this by default -- it
reads the pinned gitlink, not your working checkout. Use its --worktree mode.
EOF
    exit 1
}

[ -f "$LIB_SRC/zp_config.s" ] || lib_preflight_fail \
    "libs/nistcurves/src/zp_config.s is missing — the submodule is not checked out,\n  or that file was removed from it."

grep -qE '^[[:space:]]*\.ifndef[[:space:]]+nistcurves_zp_ptr2[[:space:]]*$' "$LIB_SRC/zp_config.s" \
    || lib_preflight_fail \
    "src/zp_config.s has no '.ifndef nistcurves_zp_ptr2' — the SPEC 6.5 canonical
  ZP spelling this wrapper passes arrived in libs/nistcurves v0.10.0."

grep -q 'CONTRACT_ZP_DEFINES' "$LIB_DIR/Makefile" \
    || lib_preflight_fail \
    "libs/nistcurves/Makefile does not honour CONTRACT_ZP_DEFINES — the SPEC 6.2
  route for consumer ZP-slot overrides arrived in libs/nistcurves v0.10.0.
  Without it the -D flags below are silently discarded."

# --- ZP-slot overrides (c64-https canonical map) ---
# nistcurves_zp_ptr2 = $3D : library default $fd collides with c64-https
#                 zp_temp/zp_count used by der_decode.s during cert parsing.
# fp_mul_i = $39, fp_mul_j = $3A : library defaults $2c/$2d collide with
#                 c64-https fe25519 ZP claim ($2c-$37). $39-$3a is otherwise
#                 unused inside ZP_CRYPTO.
# Other slots match upstream defaults — see libs/nistcurves/src/zp_config.s.
#
# THE POINTER SLOT IS SPELLED `nistcurves_zp_ptr2` FROM v0.10.0, and this
# wrapper passes ONLY that spelling — the preflight above is what makes that
# safe, by refusing a pin where the bare `zp_ptr2` would have been required.
#
# c64-lib-contract SPEC §2 gained a ZP prefix registry at v0.9.0: a bare
# `zp_ptr2` is unregistered (three adopters had independently converged on
# bare zp_tmp1/zp_ptr1 — contract #83), so c64-nist-curves renamed its four
# general-scratch slots to the registered `nistcurves_zp_*` family and left
# the bare names as aliases for the §6.5 rename window, in the "loud-break"
# shape that clause ratifies:
#
#     .ifndef nistcurves_zp_ptr2
#       nistcurves_zp_ptr2 = $fd
#     .endif
#     zp_ptr2 = nistcurves_zp_ptr2        <- NOT .ifndef-guarded
#
# Measured, ca65 V2.18, against each pin's own zp_config.s:
#
#   spelling                      v0.9.1                v0.10.1
#   -D 'zp_ptr2=$3d'              overrides correctly   Error: Symbol
#                                                       'zp_ptr2' is
#                                                       already defined
#   -D 'nistcurves_zp_ptr2=$3d'   defines an unused     overrides both
#                                 symbol; real slot     names to $3D
#                                 stays at $fd
#
# Neither spelling is safe across both, which is why a pre-v0.10.0 checkout
# is rejected outright above rather than accommodated. An earlier revision
# of this file probed the source and built a `ZP_OVERRIDES` array from the
# result; that array became dead code when f090469 retired the
# rebuild-a-member path in favour of CONTRACT_ZP_DEFINES, and it has been
# removed. The probe itself survives, promoted to the preflight gate.
#
# fp_mul_i / fp_mul_j need no probe: `fp_` is a registered §2 prefix for
# c64-nist-curves, so those names are canonical already and keep their
# `.ifndef` guards across the migration (verified on v0.10.1).

# --- 1. Build upstream's verify archive ---
# Upstream's Makefile builds every module with the same recipe (no per-file
# CA65FLAGS hook), so we cannot pass -D overrides via `make CA65=...` here.
# We build upstream with its defaults, then rebuild the TUs that need
# consumer overrides (zp_config.o always; mul_8x8_onchip.o under onchip).
# SPEC §6.2: request the §8.0 APP_OWNED shape and §6.5 bare-name
# suppression through CONTRACT_DEFINES, rather than building upstream's
# defaults and then deleting the members that collide. §6.1 bans that
# surgery, and the reason is concrete: the manifest then describes an
# archive we did not link, which is what forced the §6.6 comb exemption.
#
#   SHARED_SQTAB_INIT / SHARED_CT_MUL_8X8   bodies come from
#                                           src/crypto/poly1305.s
#   SHARED_REU_MUL_INIT / _FETCH            reu_mul_init from src/boot.s;
#                                           §8.2 requires both or neither
#   LIB_NO_BARE_EXPORTS=1                   suppress the bare mul_dma_lo/hi,
#                                           mul_cached_a, mul_src2_buf that
#                                           src/data.s defines. §8.2 rules
#                                           those ADOPTER-PRIVATE and rules
#                                           OUT deferring them ("would point
#                                           a library's own field arithmetic
#                                           at another library's memory") —
#                                           the §6.5 rename track plus this
#                                           gate is the sanctioned remedy.
#   LIB_SHARED_SQTAB_BASE=0xBC00            the sibling reads the table
#                                           through its own baked equates;
#                                           src/data.s owns the storage and
#                                           must land there. 0x-hex, never
#                                           `$BC00`: SPEC §2 records that an
#                                           unquoted `$BC00` through
#                                           make+shell expands to `$B`+"C00"
#                                           and silently yields a WRONG
#                                           address with no diagnostic.
#
# Requires libs/nistcurves >= v0.11.2:
#   v0.11.1 made SHARED_CT_MUL_8X8 assemble against the on-chip TU
#           (c64-nist-curves#123) — before that this needed a glue TU.
#   v0.11.2 added the knob-staleness guard: a changed CONTRACT_DEFINES used
#           to reuse stale objects and exit 0 with a DIFFERENT archive than
#           requested. That silent no-op is why an earlier attempt at this
#           change produced a comb image that would not boot.
CONTRACT_DEFINES="-D SHARED_SQTAB_INIT -D SHARED_REU_MUL_INIT -D SHARED_REU_MUL_FETCH -D SHARED_CT_MUL_8X8 -D LIB_NO_BARE_EXPORTS=1 -D LIB_SHARED_SQTAB_BASE=0xBC00"
# ZP-slot overrides go in the SEPARATE variable, not the one above: SPEC §6.2
# splits them because a globally-delivered slot define collides with every
# `.importzp` site. c64-https needs three (upstream defaults collide with our
# canonical map): nistcurves_zp_ptr2 $fd -> $3D (upstream's default hits our
# zp_temp/zp_count during cert parsing), fp_mul_i/j $2c/$2d -> $39/$3A
# (upstream's defaults sit inside our fe25519 claim $2c-$37).
#
# 0x-hex, never `$3d`: SPEC §2 records that an unquoted `$3d` through
# make+shell expands to `$3`+"d" and silently assembles the slot at address
# $00, with no diagnostic at any stage. The od65 post-check below is what
# actually proves the values landed.
CONTRACT_ZP_DEFINES="-D nistcurves_zp_ptr2=0x3d -D fp_mul_i=0x39 -D fp_mul_j=0x3a"
echo "[p256/$PROFILE] building libs/nistcurves $UPSTREAM_TARGET (APP_OWNED + gated bare exports)..."
make -s -C "$LIB_DIR" "$UPSTREAM_TARGET" CONTRACT_DEFINES="$CONTRACT_DEFINES" CONTRACT_ZP_DEFINES="$CONTRACT_ZP_DEFINES" >/dev/null

if [ ! -f "$UPSTREAM_ARCHIVE" ]; then
    echo "ERROR: upstream archive missing: $UPSTREAM_ARCHIVE" >&2
    exit 1
fi

# --- 2. Verify the ZP overrides landed, then use the archive as built ---
# NOTHING IS STAGED, REBUILT OR RE-ARCHIVED ANY MORE. The archive we link is
# byte-for-byte the one upstream's make produced, which is what makes SPEC
# §6.1's "no ar65 member surgery, no copying intermediates around" true by
# construction rather than by inspection.
#
# This replaces a rebuild-one-member-and-re-archive dance. That dance had a
# §6.2 defect that outlived the member drops: it passed only the ZP
# overrides to the rebuilt object and NOT the CONTRACT_DEFINES string, so
# `zp_config.s`'s `.ifndef LIB_NO_BARE_EXPORTS` gate did not apply to the
# one member we rebuilt — the archive shipped a single object re-exporting
# the bare `zp_*` names every other member had been built to suppress.
# One artifact, two configurations. Dormant while only one contract library
# links, live the moment a second one does: that is exactly the #83 ZP
# collision family the suppression gate exists to prevent.
#
# CONTRACT_ZP_DEFINES is the sanctioned route (upstream since nist#104) and
# is scoped correctly by construction: slot defines reach every TU that
# DEFINES a slot and never one that `.importzp`s it, which is the
# model-independent rule SPEC §6.2 states after measured failures in both
# directions.
#
# The post-check below is kept and is the load-bearing part. A wrong ZP slot
# is not a link error — `nistcurves_zp_ptr2` colliding with c64-https's
# zp_temp/zp_count corrupts cert parsing at runtime, and fp_mul_i/j landing
# inside the fe25519 claim ($2c-$37) corrupts multiplies. Verify from the
# emitted object, never from the fact that a -D was passed.
mkdir -p "$OUT_DIR"

# Name the member from the ARCHIVE BEING LINKED, never by globbing the build
# directory. All three profiles are built from the same libs/nistcurves tree,
# so several variants' ZP objects coexist there — after a comb build followed
# by a REU build, `ls zp_config_*.o | head -1` yields zp_config_p256comb.o
# while the REU archive ships zp_config_p256verify.o (reproduced). The check
# would then verify an object this archive does not contain.
#
# Today that would still pass, because v0.11.2's staleness stamp guarantees
# every object in the directory carries the same knob string — but a guard
# that reads a different artifact than the one shipped is the wrong shape
# regardless, and a variant-gated slot could someday differ between variants'
# ZP TUs. Listing an archive is not extracting it, so §6.1 stays clean.
ZP_MEMBER="$( "$AR65" t "$UPSTREAM_ARCHIVE" | grep '^zp_config' )"
case "$(printf '%s\n' "$ZP_MEMBER" | grep -c .)" in
    1) ;;
    0) echo "ERROR: no zp_config member in $(basename "$UPSTREAM_ARCHIVE")" >&2; exit 1 ;;
    *) echo "ERROR: multiple zp_config members in $(basename "$UPSTREAM_ARCHIVE"): $ZP_MEMBER" >&2; exit 1 ;;
esac
[ -f "$LIB_BUILD/$ZP_MEMBER" ] || { echo "ERROR: $ZP_MEMBER named by the archive but absent from $LIB_BUILD" >&2; exit 1; }

check_zp_slot() {
    local name="$1" want="$2" got
    got=$("${OD65:-od65}" --dump-exports "$LIB_BUILD/$ZP_MEMBER" \
          | awk -v n="\"$name\"" '$1=="Name:" && $2==n {f=1; next} f && $1=="Value:" {print $2; exit}')
    if [ "$got" != "$want" ]; then
        echo "ERROR: $ZP_MEMBER exports $name = ${got:-<absent>}, expected $want (CONTRACT_ZP_DEFINES did not take)" >&2
        exit 1
    fi
}
# Canonical spellings only: the bare aliases vanish under LIB_NO_BARE_EXPORTS,
# and a guard that can go vacuous under a build-tightening flag is worse than
# no guard.
check_zp_slot nistcurves_zp_ptr2 0x0000003D
check_zp_slot fp_mul_i           0x00000039
check_zp_slot fp_mul_j           0x0000003A

# The suppression gate must have reached this TU too — that is the whole
# point of routing the overrides through CONTRACT_ZP_DEFINES.
if "${OD65:-od65}" --dump-exports "$LIB_BUILD/$ZP_MEMBER" | grep -q '"zp_ptr2"'; then
    echo "ERROR: $ZP_MEMBER re-exports the bare 'zp_ptr2' — LIB_NO_BARE_EXPORTS did not reach it." >&2
    echo "       One archive must carry one configuration (SPEC 6.2)." >&2
    exit 1
fi
echo "[p256/$PROFILE] ZP overrides verified in $ZP_MEMBER; bare zp_* suppressed"

cp "$UPSTREAM_ARCHIVE" "$ARCHIVE"


# (steps 4 and 5 retired: no member drops, no glue TU, no re-archive)

# --- 3. Per-source byte counts (for the PR description) ---
{
    echo "# $(basename "$ARCHIVE") per-source byte counts (ca65 .o file sizes)"
    for m in $( "$AR65" t "$ARCHIVE" ); do
        f="$LIB_BUILD/$m"
        [ -f "$f" ] && printf '%-24s %d bytes (.o)\n' "${m%.o}" "$(wc -c < "$f")"
    done
} > "$SIZES"

echo "built $ARCHIVE"
cat "$SIZES"
