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
;                          ROM. file="" - NOT in the PRG (see DELIVERY below).
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
;      $01 = $34) under sei around every ML-KEM call; pq_mlkem_call does
;      both. With the KERNAL out the hardware vectors are RAM, and
;      mlkem_boot_init points all three at an RTI (VECTORS below).
;
; DELIVERY (#288): the PRG may not carry a byte at $D000+, so the code is not
; file-backed at $E000. It LOADS at $A000 (COLD_FILE: the file bytes under
; CRYPTO_COLD_SHADOW's BSS, which boot zeroes anyway) and RUNS at $E000;
; mlkem_boot_init copies it up from boot.s BEFORE the zeroing (writes to
; $E000 land in RAM under the KERNAL, and boot has already banked BASIC out
; so $A000 reads RAM). The ordering is asserted in boot.s and tested in
; tools/test_mlkem_linked.py (which also compares the copied bytes).
;
; ENTRY: pq_mlkem_call (and its named wrappers pq_mlkem_keygen and
; pq_mlkem_decaps_seed) is the only way in. It banks ($01 = $34, under sei),
; runs mlkem_arith_init (RULE 1 above: the reduction tables live in a window
; X25519 rebuilds), jsrs the entry in A/X and restores. No symbol the linker
; places in $E000-$FDFF may be referenced outside this file
; (tools/test_mlkem_placement.py reads the map's export list). A client needs
; KeyGen and Decaps-from-seed only; Encaps and Decaps-with-dk have no wrapper
; because nothing here calls them. The parameter block
; (mlkem_arg_*) is ALSO in LIB_MLKEM_BSS: fill it after the last X25519 /
; fp_mul and before pq_mlkem_call, never across one.
;
; VECTORS: with the KERNAL out $FFFA-$FFFF are RAM. mlkem_boot_init points
; NMI, RESET and IRQ/BRK at one RTI (in NET_CODE, always RAM), so a
; RESTORE-key NMI (edge-triggered, one event) returns instead of jumping
; through garbage. The sei in pq_mlkem_call is LOAD-BEARING for IRQ: CIA1's
; IRQ line is level-triggered and an RTI stub acknowledges nothing (with I/O
; in or out), so an IRQ that reached the RTI would re-enter at once and
; livelock the call. The sei is what prevents that. No BRK is executed; its
; vector shares the RTI.
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
.import __COLD_FILE_START__, __COLD_FILE_SIZE__
.import __LIB_MLKEM_CODE_LOAD__, __LIB_MLKEM_CODE_RUN__, __LIB_MLKEM_CODE_SIZE__
.import __LIB_MLKEM_RODATA_LOAD__, __LIB_MLKEM_RODATA_RUN__, __LIB_MLKEM_RODATA_SIZE__
.import __LIB_MLKEM_MARK_LOAD__, __LIB_MLKEM_MARK_RUN__, __LIB_MLKEM_MARK_SIZE__
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

; --- The load image: $A000, one block copy to $E000 ------------------------
; mlkem_boot_init copies __MLKEM_CODE_RAM_SIZE__ bytes from $A000. So the
; image must start at the head of COLD_FILE, be laid out exactly like the run
; image (the same offsets, or the block copy mis-places the rodata), and end
; inside COLD_FILE, i.e. inside the PRG's file content (the file runs on to
; $BFFF there; comb's COLD_IMAGE follows it). Nothing past COLD_FILE's end is
; read, so the image cannot reach the I/O page.
MLKEM_LOAD_BASE = $A000
.assert __COLD_FILE_START__ = MLKEM_LOAD_BASE, lderror, "COLD_FILE is not at $A000: the boot copy source moved"
.assert __COLD_FILE_START__ + __COLD_FILE_SIZE__ = $C000, lderror, "COLD_FILE no longer ends at $BFFF (the PRG's old end)"
.assert __LIB_MLKEM_CODE_LOAD__ = MLKEM_LOAD_BASE, lderror, "LIB_MLKEM_CODE does not load at $A000"
.assert __LIB_MLKEM_CODE_RUN__ = __MLKEM_CODE_RAM_START__, lderror, "LIB_MLKEM_CODE does not run at the head of MLKEM_CODE_RAM"
.assert __LIB_MLKEM_RODATA_LOAD__ - __LIB_MLKEM_CODE_LOAD__ = __LIB_MLKEM_RODATA_RUN__ - __LIB_MLKEM_CODE_RUN__, lderror, "the load image and the run image are laid out differently: one block copy would mis-place the rodata"
.assert __LIB_MLKEM_RODATA_LOAD__ + __LIB_MLKEM_RODATA_SIZE__ <= MLKEM_LOAD_BASE + __MLKEM_CODE_RAM_SIZE__, lderror, "the ML-KEM load image is longer than the block boot copies"
.assert __LIB_MLKEM_RODATA_LOAD__ + __LIB_MLKEM_RODATA_SIZE__ <= __COLD_FILE_START__ + __COLD_FILE_SIZE__, lderror, "the ML-KEM load image runs past the PRG's file content"
.assert __LIB_MLKEM_RODATA_RUN__ + __LIB_MLKEM_RODATA_SIZE__ <= __MLKEM_CODE_RAM_START__ + __MLKEM_CODE_RAM_SIZE__, lderror, "the ML-KEM run image overflows MLKEM_CODE_RAM"
; After boot the marker's LOAD address holds live sqtab bytes (the window
; $BC00-$BFFF), not the marker, unless the table happens to have the same
; byte there: mlkem_boot_init case 2 would then re-copy stale RAM over a good
; $E000 image. Keep the marker inside the table's lo/hi planes, where
; tools/test_mlkem_placement.py computes the byte (n*n/4) and fails on a
; collision. Image growth/shrink that moves it out of the planes fails here.
.assert (__LIB_MLKEM_MARK_LOAD__ >= sqtab_lo) .and (__LIB_MLKEM_MARK_LOAD__ < sqtab_lo + $0400), lderror, "the tail marker's load address left the sqtab window: re-derive the collision check in tools/test_mlkem_placement.py"
.assert __LIB_MLKEM_MARK_SIZE__ = 1, lderror, "the tail marker is not one byte"
.assert __LIB_MLKEM_MARK_LOAD__ = __LIB_MLKEM_RODATA_LOAD__ + __LIB_MLKEM_RODATA_SIZE__, lderror, "the tail marker is not the last byte of the load image"
.assert __LIB_MLKEM_MARK_LOAD__ - __LIB_MLKEM_CODE_LOAD__ = __LIB_MLKEM_MARK_RUN__ - __LIB_MLKEM_CODE_RUN__, lderror, "the tail marker's load and run offsets differ"
.assert __LIB_MLKEM_MARK_LOAD__ < MLKEM_LOAD_BASE + __MLKEM_CODE_RAM_SIZE__, lderror, "the tail marker is past the block boot copies"
.assert __LIB_MLKEM_MARK_RUN__ < __MLKEM_CODE_RAM_START__ + __MLKEM_CODE_RAM_SIZE__, lderror, "the tail marker overflows MLKEM_CODE_RAM"
.assert __MLKEM_CODE_RAM_SIZE__ .mod 256 = 0, lderror, "the boot copy moves whole pages: MLKEM_CODE_RAM is not a page multiple"
.assert __MLKEM_CODE_RAM_START__ + __MLKEM_CODE_RAM_SIZE__ <= $FFFA, lderror, "MLKEM_CODE_RAM overlaps the $FFFA vectors"

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
; COLD_FILE is the file view of CRYPTO_COLD_SHADOW (same range, same exemption).
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

; =============================================================================
; Code (NET_CODE via LOADER_OVERFLOW; always RAM, so the SMC below is legal)
; =============================================================================
.export mlkem_copied
.export mlkem_boot_init, pq_mlkem_call, pq_mlkem_keygen, pq_mlkem_decaps_seed, pq_mlkem_scrub

.segment "LOADER_OVERFLOW"

; mlkem_boot_init - boot.s, right after `sei`, BEFORE it zeroes $A000-$BFFF.
; In:  BASIC ROM already banked out ($01 bit 0 clear), so $A000 reads RAM.
; Out: the load image at $A000 copied to $E000 (30 pages) and
;      mlkem_copied = 1; NMI/RESET/IRQ vectors in RAM point at an RTI.
;      Clobbers A, X, Y.
; Three cases, decided by the image's TAIL MARKER (LIB_MLKEM_MARK, the last
; byte of the load image, like cold_bank_init's COLD_MARK: a LOAD cut short
; before it never has it):
;   1. mlkem_copied already 1 (a SYS re-entry): nothing to do.
;   2. the marker is present at the load address: a fresh, complete LOAD:
;      copy, set the vectors, mlkem_copied = 1.
;   3. no marker at the load address (the stage was zeroed by an earlier boot
;      or the LOAD stopped short): if the RUN address already holds the marker
;      the image is resident from an earlier boot (the PRG-data flag was
;      clobbered, e.g. by BASIC after 'Q'): mlkem_copied = 1. Otherwise
;      REFUSE: mlkem_copied stays 0, the border goes red, and pq_mlkem_call
;      returns A=$FF with C=1 and runs nothing. Never a silent skip.
; $E000 and the vectors are not secret and 'Q' leaves them alone
; (session_scrub has no span there).
MLKEM_MARK = $5C
mlkem_boot_init:
        ldy #5                  ; the vectors first, on every path: every later
@vec:   lda mlkem_vec_tab,y     ; $01=$34 window (this routine's, the scrub's,
        sta $FFFA,y             ; pq_mlkem_call's) then has a valid RTI target
        dey
        bpl @vec
        lda mlkem_copied
        bne @done
        lda __LIB_MLKEM_MARK_LOAD__
        cmp #MLKEM_MARK
        bne @resident
        lda #>MLKEM_LOAD_BASE
        sta @ld+2
        lda #>__MLKEM_CODE_RAM_START__
        sta @st+2
        ldx #>__MLKEM_CODE_RAM_SIZE__
        ldy #0
@pg:
@ld:    lda MLKEM_LOAD_BASE,y
@st:    sta __MLKEM_CODE_RAM_START__,y
        iny
        bne @pg
        inc @ld+2
        inc @st+2
        dex
        bne @pg
        inc mlkem_copied
@done:  rts
@resident:
        lda $01
        pha
        lda #$34                ; all RAM: $E000+ would read the KERNAL
        sta $01
        ldx __LIB_MLKEM_MARK_RUN__
        pla
        sta $01
        cpx #MLKEM_MARK
        bne @refuse
        inc mlkem_copied
        rts
@refuse:
        lda #2                  ; red border: the image is not there
        sta $D020
        rts

mlkem_vec_tab:                  ; NMI, RESET, IRQ/BRK -> the one RTI
        .word mlkem_rti, mlkem_rti, mlkem_rti
mlkem_rti:
        rti
mlkem_copied:
        .byte 0

; pq_mlkem_call - the only entry into libs/mlkem.
; In:  A/X = entry (mlkem_keygen, mlkem_decaps_seed, ...); the mlkem_arg_*
;      block already filled.
; Out: C=0: A = the entry's A (its status), X/Y/N/Z clobbered, the caller's I
;      flag restored. C=1, A=$FF: refused (the image is not resident, see
;      mlkem_boot_init); nothing ran.
; Banks $01 = $34 (KERNAL, BASIC and I/O out: code at $E000, polys at
; $D000) under sei, runs mlkem_arith_init FIRST on every call because its
; tables live in the window X25519 rebuilds, then the entry.
pq_mlkem_call:
        ldy mlkem_copied
        bne @run
        lda #$FF
        sec
        rts
@run:   sta @go+1
        stx @go+2
        php
        sei
        lda $01
        pha
        lda #$34
        sta $01
        jsr mlkem_arith_init
@go:    jsr mlkem_keygen        ; operand patched above
        sta @ra+1
        pla
        sta $01
        plp
@ra:    lda #0
        clc
        rts

; Named entries: all a client calls (KeyGen to send ek; Decaps from the
; 64 B seed). Encaps and Decaps-with-dk are not wrapped: nothing calls them.
pq_mlkem_keygen:
        lda #<mlkem_keygen
        ldx #>mlkem_keygen
        jmp pq_mlkem_call
pq_mlkem_decaps_seed:
        lda #<mlkem_decaps_seed
        ldx #>mlkem_decaps_seed
        jmp pq_mlkem_call

; pq_mlkem_scrub - zero everything ML-KEM leaves secret: the eight polynomials
; ($D000-$DFFF: s_hat after KeyGen, y/e1/e2 after Decaps) and the whole rest-BSS
; window ($B100-$BBFF: m', K', r', the Keccak state; X25519_TABLES and mul_dma
; share it and are rebuilt by their owners). Same banking discipline as
; pq_mlkem_call: sei, $01 = $34, restored. ~7,000 stores, ~80K cycles.
; Clobbers A, X, Y, zp_ptr. Preserves the caller's I flag.
pq_mlkem_scrub:
        php
        sei
        lda $01
        pha
        lda #$34
        sta $01
        lda #>__MLKEM_POLY_RAM_START__
        ldx #>__MLKEM_POLY_RAM_SIZE__
        jsr @zero
        lda #>__MLKEM_BSS_RAM_START__
        ldx #>__MLKEM_BSS_RAM_SIZE__
        jsr @zero
        pla
        sta $01
        plp
        rts
@zero:  sta zp_ptr+1
        ldy #0
        sty zp_ptr
        tya
:       sta (zp_ptr),y
        iny
        bne :-
        inc zp_ptr+1
        dex
        bne :-
        rts

.segment "LIB_MLKEM_MARK"
mlkem_mark:
        .byte MLKEM_MARK
