; =============================================================================
; mlkem_link.s - PQ_HYBRID=1 link anchor and placement proof for libs/mlkem
; (c64-mlkem v0.6.0, ABI 3). PQC plan phase P0.
;
; Nothing calls ML-KEM yet: this object exists so ld65 pulls mlkem_keygen /
; mlkem_decaps / mlkem_decaps_seed (and through them every library member)
; into the image, and so the placement the cfgs give the library is checked
; at link time rather than trusted. The Makefile links this file only under
; PQ_HYBRID=1 (it is filtered out of the wildcard otherwise), so an unset
; build is byte-identical to one that has never heard of it. It emits NO
; bytes: every reference is inside an `.assert ..., lderror`. ca65 drops an
; .import nothing references, but an assert expression is a reference, and
; ld65 evaluates it after placement - which is what makes these both the
; force-link and the placement proof.
;
; PLACEMENT (cfg/c64-https-uci-onchip.cfg and ...-onchip-cold.cfg)
;
;   LIB_MLKEM_CODE/RODATA  MLKEM_CODE_RAM  $E000-$FDFF  RAM under the KERNAL
;                          ROM. file="" - NOT in the PRG (see HAZARD below).
;   LIB_MLKEM_POLY_BSS     MLKEM_POLY_RAM  $D000-$DFFF  RAM under I/O, the
;                          eight polynomials, exactly 4,096 B.
;   LIB_MLKEM_BSS          MLKEM_BSS_RAM   $B100-$BBFF  = X25519_TABLES
;                          ($B100-$B8FF) + the $B900 hole + mul_dma_lo/hi
;                          ($BA00-$BBFF). 2,816 B window, up to the sqtab.
;   dk scratch             the TCP ring at tcp_recv_buf = $C000 (below).
;
; LIFETIME RULES (what makes the unions legal - none is checkable at link):
;   1. ML-KEM never interleaves with X25519 or fp_mul. X25519_TABLES is
;      rebuilt per scalar mult (x25519_*_fresh run x25519_tables_init), and
;      mul_dma_lo/hi is the REU row-fetch buffer of the REU profile (refused
;      under PQ_HYBRID). The converse also holds: LIB_MLKEM_BSS holds the
;      two 512 B reduction tables mlkem_arith_init builds, so EVERY ML-KEM
;      call group must be preceded by mlkem_arith_init once X25519 has run.
;   2. Both BSS segments hold secrets afterwards (POLY_BSS: s_hat after
;      mlkem_keygen, secret-derived y/e1/e2 after Decaps; LIB_MLKEM_BSS:
;      m', K', r'). src/session_scrub.s zeroes both under PQ_HYBRID.
;   3. $E000 code and the $D000 polys need $01 banked (KERNAL and I/O out,
;      $01 = $34) under sei around every ML-KEM call. With the KERNAL out the
;      hardware vectors are RAM: a RESTORE-key NMI during a call jumps through
;      whatever sits at $FFFA. $FE00-$FFFF is left free for a vector stub.
;
; HAZARD (#288) - the code is LINKED at $E000 but NOT DELIVERED by the PRG.
; An ld65 file-backed $E000 image would carry a zero pad over $C000-$DFFF,
; and a KERNAL LOAD stores through the I/O page (tools/test_prg_io_range.py
; forbids it). Staging 7,541 B inside the PRG below $D000 and copying it up
; at boot needs ~7.5 KB of file space the images do not have (the only
; free file bytes are scattered 1-2 KB tails, plus a 4 KB $C000-$CFFF
; area). So the image links and every address below is proven, but the
; bytes are absent: an ML-KEM call is not runnable yet. The ldwarning below
; says so on every PQ_HYBRID link until the delivery question is decided.
;
; ZERO PAGE (tools/integration/build_mlkem.sh has the table and reasoning):
; $40-$4F, inside ZP_WIDE; the only co-tenant is the X25519 sibling's
; per-call fe_wide. Pinned here so the wrapper's -D values and the
; documented map cannot drift apart.
; =============================================================================

.ifndef PQ_HYBRID
.error "mlkem_link.s is PQ_HYBRID-only; the Makefile filters it out otherwise"
.endif

.include "constants.inc"

; The base libs/mlkem was assembled against (build_mlkem.sh: -D
; LIB_SHARED_SQTAB_BASE=0xBC00); the library's own default ($9000) is not ours.
LIB_SHARED_SQTAB_BASE = $BC00

; --- Public entries (the force-link) ---------------------------------------
.import mlkem_keygen, mlkem_decaps, mlkem_decaps_seed, mlkem_arith_init
.import keccak_state

; --- Contract section 1 / 5 surface ----------------------------------------
.import LIB_MLKEM_VERSION_MAJOR, LIB_MLKEM_VERSION_MINOR, LIB_MLKEM_ABI_VERSION
.import LIB_MLKEM_RESIDENT_BYTES, LIB_MLKEM_COLD_BYTES
.import LIB_MLKEM_ZP_USAGE_BYTES, LIB_MLKEM_REU_BANKS_USED
.import LIB_MLKEM_SHARED_PRIMITIVES, LIB_MLKEM_SHARED_CONSUMES

; --- ZP slots (consumer-assembled; tools/integration/build_mlkem.sh) -------
.importzp mlkem_zp_src, mlkem_zp_dst, mlkem_zp_len, mlkem_zp_tmp, mlkem_zp_mul

; --- Regions and neighbours --------------------------------------------------
.import __MLKEM_CODE_RAM_START__, __MLKEM_CODE_RAM_SIZE__, __MLKEM_CODE_RAM_LAST__
.import __MLKEM_BSS_RAM_START__,  __MLKEM_BSS_RAM_SIZE__,  __MLKEM_BSS_RAM_LAST__
.import __MLKEM_POLY_RAM_START__, __MLKEM_POLY_RAM_SIZE__, __MLKEM_POLY_RAM_LAST__
.import __LIB_MLKEM_BSS_RUN__, __LIB_MLKEM_BSS_SIZE__
.import __LIB_MLKEM_POLY_BSS_RUN__, __LIB_MLKEM_POLY_BSS_SIZE__
.import sqtab_lo
.import mul38_lo_tab, mul38_hi_tab, a24_b3, mul_dma_lo, mul_dma_hi

; --- Version and ABI ---------------------------------------------------------
; ABI 3 (v0.6.0) is the pin: LIB_MLKEM_POLY_BSS and mlkem_decaps_seed. A
; generation bump is the gate telling you to re-read libs/mlkem/src/mlkem.inc
; before re-pinning, exactly as for libs/nistcurves.
.assert (LIB_MLKEM_VERSION_MAJOR > 0) .or (LIB_MLKEM_VERSION_MINOR >= 6), lderror, "PQ_HYBRID needs c64-mlkem >= v0.6.0 (POLY_BSS split, mlkem_decaps_seed)"
.assert LIB_MLKEM_ABI_VERSION = 3, lderror, "c64-mlkem ABI generation moved: re-read libs/mlkem/src/mlkem.inc before re-pinning"

; --- Section 8.0 / 8.1: one sqtab, c64-https owns it ------------------------
; Both masks come from the archive's own manifest member, so this proves the
; CONTRACT_DEFINES reached the build.
.assert (LIB_MLKEM_SHARED_PRIMITIVES & $0001) = 0, lderror, "libs/mlkem claims sqtab ownership: SHARED_SQTAB_INIT did not reach the archive"
.assert (LIB_MLKEM_SHARED_CONSUMES & $0001) = $0001, lderror, "libs/mlkem no longer consumes the shared sqtab: re-check build_mlkem.sh"
; ONE table, at the base the library was assembled against (0xBC00). The
; library's NTT reads it; c64-https's boot sqtab_init fills it.
.assert sqtab_lo = LIB_SHARED_SQTAB_BASE, lderror, "sqtab_lo is not at $BC00, the LIB_SHARED_SQTAB_BASE libs/mlkem was built with"

; No REU: onchip ships without one, and comb's bank 2 is the anchor table.
.assert LIB_MLKEM_REU_BANKS_USED = 0, lderror, "libs/mlkem claims REU banks"

; --- Code + rodata: $E000, whole footprint, every entry in the slot ---------
.assert __MLKEM_CODE_RAM_START__ = $E000, lderror, "MLKEM_CODE_RAM is not at $E000"
.assert __MLKEM_CODE_RAM_SIZE__ = $1E00, lderror, "MLKEM_CODE_RAM is not 7,680 B ($E000-$FDFF; $FE00-$FFFF stays free for the vector stub)"
.assert LIB_MLKEM_RESIDENT_BYTES + LIB_MLKEM_COLD_BYTES <= __MLKEM_CODE_RAM_SIZE__, lderror, "c64-mlkem footprint exceeds MLKEM_CODE_RAM"
.assert __MLKEM_CODE_RAM_LAST__ <= __MLKEM_CODE_RAM_START__ + __MLKEM_CODE_RAM_SIZE__, lderror, "MLKEM_CODE_RAM overflows its area"
.assert mlkem_keygen >= __MLKEM_CODE_RAM_START__, lderror, "mlkem_keygen is not in MLKEM_CODE_RAM"
.assert mlkem_decaps >= __MLKEM_CODE_RAM_START__, lderror, "mlkem_decaps is not in MLKEM_CODE_RAM"
.assert mlkem_decaps_seed >= __MLKEM_CODE_RAM_START__, lderror, "mlkem_decaps_seed is not in MLKEM_CODE_RAM"
.assert mlkem_arith_init >= __MLKEM_CODE_RAM_START__, lderror, "mlkem_arith_init is not in MLKEM_CODE_RAM"
.assert mlkem_keygen < __MLKEM_CODE_RAM_START__ + __MLKEM_CODE_RAM_SIZE__, lderror, "mlkem_keygen is past the end of MLKEM_CODE_RAM"

; --- Polynomials: $D000, exactly 4 KB ---------------------------------------
.assert __MLKEM_POLY_RAM_START__ = $D000, lderror, "MLKEM_POLY_RAM is not at $D000"
.assert __MLKEM_POLY_RAM_SIZE__ = $1000, lderror, "MLKEM_POLY_RAM is not 4 KB"
.assert __LIB_MLKEM_POLY_BSS_RUN__ = $D000, lderror, "LIB_MLKEM_POLY_BSS is not at $D000"
.assert __LIB_MLKEM_POLY_BSS_SIZE__ = $1000, lderror, "LIB_MLKEM_POLY_BSS is not 4,096 B"

; --- Rest-BSS: the $B100 union ----------------------------------------------
; Window = X25519_TABLES (8 pages from mul38_lo_tab) + the $B900 hole +
; mul_dma_lo/hi, ending at sqtab_lo. Each equation below pins one edge, so a
; reorder of X25519_TABLES or TABLES_BSS breaks the link by name.
.assert __MLKEM_BSS_RAM_START__ = mul38_lo_tab, lderror, "MLKEM_BSS_RAM must start on X25519_TABLES (mul38_lo_tab)"
.assert __LIB_MLKEM_BSS_RUN__ = mul38_lo_tab, lderror, "LIB_MLKEM_BSS must start on X25519_TABLES (mul38_lo_tab)"
.assert (__LIB_MLKEM_BSS_RUN__ & $00FF) = 0, lderror, "LIB_MLKEM_BSS must start on a page"
.assert (keccak_state & $00FF) = 0, lderror, "keccak_state must be page-aligned"
.assert mul38_hi_tab = mul38_lo_tab + $100, lderror, "X25519_TABLES layout moved (mul38_hi_tab)"
.assert a24_b3 + $100 = mul38_lo_tab + $800, lderror, "X25519_TABLES is no longer 2 KB: the union's first edge moved"
.assert mul_dma_lo = mul38_lo_tab + $900, lderror, "mul_dma_lo moved off $BA00 (the $B900 hole is no longer one page)"
.assert mul_dma_hi = mul_dma_lo + $100, lderror, "mul_dma_hi is not the page after mul_dma_lo"
.assert mul_dma_hi + $100 = sqtab_lo, lderror, "mul_dma is not adjacent to sqtab: the union's last edge moved"
.assert __MLKEM_BSS_RAM_SIZE__ = sqtab_lo - mul38_lo_tab, lderror, "MLKEM_BSS_RAM is not exactly [mul38_lo_tab, sqtab_lo)"
.assert __LIB_MLKEM_BSS_RUN__ + __LIB_MLKEM_BSS_SIZE__ <= sqtab_lo, lderror, "LIB_MLKEM_BSS runs into the sqtab"
.assert __MLKEM_BSS_RAM_LAST__ <= sqtab_lo, lderror, "MLKEM_BSS_RAM runs into the sqtab"

; --- dk scratch: the TCP ring -----------------------------------------------
; mlkem_keygen writes a 2,400 B dk that is then discarded (Decaps uses only
; the 64 B seed, mlkem_decaps_seed). It goes in the ring at tcp_recv_buf.
.assert mlkem_dk_scratch = $C000, lderror, "the dk scratch moved off the TCP ring base"
.assert MLKEM_DK_SIZE = 2400, lderror, "ML-KEM-768 dk is 2,400 B (FIPS 203 Table 3)"
.assert TCP_RECV_BUF_SIZE >= MLKEM_DK_SIZE, lderror, "the TCP ring is smaller than the 2,400 B dk it hosts"
.assert mlkem_dk_scratch + TCP_RECV_BUF_SIZE <= __MLKEM_POLY_RAM_START__, lderror, "the TCP ring runs into the $D000 polys"

; --- Zero page --------------------------------------------------------------
.assert mlkem_zp_src = $40, lderror, "mlkem_zp_src moved off $40"
.assert mlkem_zp_dst = $42, lderror, "mlkem_zp_dst moved off $42"
.assert mlkem_zp_len = $44, lderror, "mlkem_zp_len moved off $44"
.assert mlkem_zp_tmp = $46, lderror, "mlkem_zp_tmp moved off $46"
.assert mlkem_zp_mul = $48, lderror, "mlkem_zp_mul moved off $48"
.assert LIB_MLKEM_ZP_USAGE_BYTES = 16, lderror, "c64-mlkem ZP claim is no longer 16 B: re-plan $40-$4F"
; ...and wholly clear of every c64-https crypto slot ($22-$3F) and of the
; low pool: the only thing at $40-$7F is the X25519 sibling's fe_wide.
.assert mlkem_zp_src >= $40, lderror, "ML-KEM zero page overlaps ZP_CRYPTO ($22-$3F)"
.assert mlkem_zp_mul + 8 <= $50, lderror, "ML-KEM zero page runs past $4F"

; --- Section 8.1 image guard: no area may overlap the sqtab window ----------
; libs/mlkem's REQUIRED guard (cfg/mlkem-example.cfg): mul_tables_init writes
; the whole 1,024 B window at run time, so one assert per MEMORY area of the
; link, file-emitting or not. "Ends at or below the window, or starts at or
; above its end." Every area needs `define = yes` in the cfg, so a new area
; with no line here is a gap tools/test_mlkem_placement.py reports by name.
.macro SQTAB_GUARD nm, st, la
        .assert ((la) <= LIB_SHARED_SQTAB_BASE) .or ((st) >= LIB_SHARED_SQTAB_BASE + $0400), lderror, .concat("area ", nm, " overlaps the sqtab window")
.endmacro
.import __ZP_CRYPTO_START__,  __ZP_CRYPTO_LAST__
.import __ZP_WIDE_START__,    __ZP_WIDE_LAST__
.import __LOADADDR_START__,   __LOADADDR_LAST__
.import __LOADER_START__,     __LOADER_LAST__
.import __NET_CODE_START__,   __NET_CODE_LAST__
.import __NET_BSS_TAIL_START__, __NET_BSS_TAIL_LAST__
.import __UCI_BSS_REGION_START__, __UCI_BSS_REGION_LAST__
.import __CRYPTO_OVERLAY_START__, __CRYPTO_OVERLAY_LAST__
.import __P256_SCRATCH_UNION_START__, __P256_SCRATCH_UNION_LAST__
.import __CRYPTO_HOT_START__, __CRYPTO_HOT_LAST__
.import __X25519_SCRATCH_START__, __X25519_SCRATCH_LAST__
SQTAB_GUARD "ZP_CRYPTO",          __ZP_CRYPTO_START__,          __ZP_CRYPTO_LAST__
SQTAB_GUARD "ZP_WIDE",            __ZP_WIDE_START__,            __ZP_WIDE_LAST__
SQTAB_GUARD "LOADADDR",           __LOADADDR_START__,           __LOADADDR_LAST__
SQTAB_GUARD "LOADER",             __LOADER_START__,             __LOADER_LAST__
SQTAB_GUARD "NET_CODE",           __NET_CODE_START__,           __NET_CODE_LAST__
SQTAB_GUARD "NET_BSS_TAIL",       __NET_BSS_TAIL_START__,       __NET_BSS_TAIL_LAST__
SQTAB_GUARD "UCI_BSS_REGION",     __UCI_BSS_REGION_START__,     __UCI_BSS_REGION_LAST__
SQTAB_GUARD "CRYPTO_OVERLAY",     __CRYPTO_OVERLAY_START__,     __CRYPTO_OVERLAY_LAST__
SQTAB_GUARD "P256_SCRATCH_UNION", __P256_SCRATCH_UNION_START__, __P256_SCRATCH_UNION_LAST__
SQTAB_GUARD "CRYPTO_HOT",         __CRYPTO_HOT_START__,         __CRYPTO_HOT_LAST__
SQTAB_GUARD "X25519_SCRATCH",     __X25519_SCRATCH_START__,     __X25519_SCRATCH_LAST__
SQTAB_GUARD "MLKEM_CODE_RAM",     __MLKEM_CODE_RAM_START__,     __MLKEM_CODE_RAM_LAST__
SQTAB_GUARD "MLKEM_BSS_RAM",      __MLKEM_BSS_RAM_START__,      __MLKEM_BSS_RAM_LAST__
SQTAB_GUARD "MLKEM_POLY_RAM",     __MLKEM_POLY_RAM_START__,     __MLKEM_POLY_RAM_LAST__
.ifdef COLD_BANK
.import __COLD_IMAGE_START__,    __COLD_IMAGE_LAST__
.import __COLD_RUN_UI_START__,   __COLD_RUN_UI_LAST__
.import __COLD_RUN_TRUST_START__, __COLD_RUN_TRUST_LAST__
SQTAB_GUARD "COLD_IMAGE",         __COLD_IMAGE_START__,         __COLD_IMAGE_LAST__
SQTAB_GUARD "COLD_RUN_UI",        __COLD_RUN_UI_START__,        __COLD_RUN_UI_LAST__
SQTAB_GUARD "COLD_RUN_TRUST",     __COLD_RUN_TRUST_START__,     __COLD_RUN_TRUST_LAST__
.endif
; CRYPTO_COLD_SHADOW ($A000-$BFFF) is the one area that CONTAINS the window,
; because the window is c64-https's own table (TABLES_BSS at $BA00, written
; by boot.s's sqtab_init, which is the section 8.1 owner here). The generic
; guard cannot pass it; the equivalent is that the table is exactly the
; area's tail and nothing else is allowed past it:
.import __CRYPTO_COLD_SHADOW_START__, __CRYPTO_COLD_SHADOW_LAST__
.import sqtab_hi
.assert sqtab_hi + $200 = LIB_SHARED_SQTAB_BASE + $0400, lderror, "the sqtab window is not the owner's lo+hi planes"
.assert __CRYPTO_COLD_SHADOW_LAST__ = LIB_SHARED_SQTAB_BASE + $0400, lderror, "CRYPTO_COLD_SHADOW has a tenant past the sqtab window"

; Link-only, and the linker says so (see HAZARD above).
.assert __MLKEM_CODE_RAM_LAST__ < __MLKEM_CODE_RAM_START__, ldwarning, "PQ_HYBRID: libs/mlkem is LINKED at $E000 but not delivered by the PRG (#288: no byte may load through $D000-$DFFF); an ML-KEM call is not runnable yet"
