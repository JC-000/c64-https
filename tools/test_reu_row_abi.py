#!/usr/bin/env python3
"""test_reu_row_abi.py - pin the `reu_fetch_mul_row` entry convention.

`reu_fetch_mul_row` is a **rendezvous**: c64-https is the APP_OWNED
provider (`src/boot.s`, the `.ifndef USE_X25519_SIBLING` block) and the
libs/nistcurves sibling is a consumer of it. c64-lib-contract SPEC §8.2
says the row index arrives in register **A**.

The in-tree provider does not read A. It does::

    reu_fetch_mul_row:
            lda mul_cached_a        ; <-- memory, NOT the A it was called with
            asl
            ...

The only caller in any build we ship or test happens to leave A holding
the same value it just stored into `mul_cached_a` (`src/crypto/fe25519.s`
does ``sta mul_cached_a`` immediately before the ``jsr``), so provider
and contract agree *by coincidence of that one call site*, not by
construction. If either side changes — upstream nistcurves v0.14.0 makes
its own copy ``sta nistcurves_mul_cached_a`` and treats A as
authoritative — nothing in this tree would go red. Every multiply row
would silently be the wrong row, which is the class of defect that
surfaces as "the signature did not verify" minutes downstream, with no
diagnostic.

Be precise about who calls this today, because it is easy to overstate
(and was, in this file's first draft). At the v0.11.2 pin the sibling
does NOT call it on any profile: the wrapper defers upstream's whole
``mul_8x8.s`` via ``CONTRACT_DEFINES``, and ``mul_8x8.o`` in the archive
is an empty object. The obligation is real and the provider is ours to
get right, but it is currently exercised only in-tree. See
:func:`profile_problem` for the od65 measurements.

This suite closes that. It calls `reu_fetch_mul_row` with A and
`mul_cached_a` **deliberately disagreeing**, then reads back the 512
bytes that arrived and works out which multiplier's row they are. The
answer names the convention:

    row == mul_cached_a  ->  "memory"    (today's in-tree provider)
    row == A             ->  "register"  (SPEC §8.2 / nistcurves v0.14.0)

`EXPECTED_CONVENTION` below is what this suite asserts. It is
"memory" because that is what `src/boot.s` does **today**. The
one-instruction §8.2 conformance change (`lda mul_cached_a` ->
`sta mul_cached_a`) is a separate commit; when it lands, this suite goes
RED with a message naming the flip, and `EXPECTED_CONVENTION` must be
changed to "register" in the same commit. That is the point — the
convention now has exactly one place where it is written down as an
executable assertion.

Scope limitation (read before quoting a green run)
--------------------------------------------------
`reu_fetch_mul_row` is exported only ``.ifndef USE_NISTCURVES_ONCHIP``
(``src/boot.s`` exports block) and its only in-tree caller,
``src/crypto/fe25519.s``'s ``fe_mul``, calls it only in the same
non-onchip case. So this suite can run against the **REU profile only**
— a plain ``make`` (BACKEND=ip65, no USE_NISTCURVES_ONCHIP*), which is
the same build ``tools/test_ecdsa_kat_oracle.py`` defaults to. Under
``USE_NISTCURVES_ONCHIP=1`` / ``..._COMB=1`` the suite reports CANNOT
RUN and exits 2, never 0: an involuntary skip is a failure, not a pass.
It decides that from ``build/flags.stamp``, **not** from the label,
because on those profiles the label is still there and still works —
and means nothing. See :func:`profile_problem`. Note that none of the
three shipped products
(`tools/package/_common.sh`) is a REU-profile image, so a green run here
is coverage of the *rendezvous*, not of a shipped binary.

REU is mandatory
----------------
VICE must be launched with ``-reu -reusize 512`` or the fetch DMA
silently no-ops and `mul_dma_lo/hi` keeps whatever was there before —
which would make this suite *inconclusive*, not red. It therefore goes
through ``tools/_vice_helpers.py::default_vice_config()`` and runs a
positive control FIRST (A and `mul_cached_a` agreeing, expecting that
row to actually arrive over a poisoned buffer). If the control fails,
the convention verdict is not reported at all.

Usage:
    python3 tools/test_reu_row_abi.py [--verbose]

Honours ``C64_SKIP_BUILD=1``.
"""

import os
import subprocess
import sys

from c64_test_harness import (
    Labels, ViceInstanceManager, read_bytes, write_bytes, jsr, wait_for_text,
)

from _vice_helpers import default_vice_config, no_reu_requested
from _skip_policy import verdict  # noqa: E402

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64-https.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

VERBOSE = False

#: The convention `src/boot.s` implements today. Flip to "register" in the
#: same commit that makes `reu_fetch_mul_row` read A (SPEC §8.2).
EXPECTED_CONVENTION = "memory"

REQUIRED_LABELS = ["reu_fetch_mul_row", "mul_cached_a", "mul_dma_lo", "mul_dma_hi"]

FLAGS_STAMP = os.path.join(PROJECT_ROOT, "build", "flags.stamp")

# Cassette buffer. $0334 is the harness's own jsr trampoline; $0360/$03F0 are
# the U64 rig's. $0340 is the slot tools/test_ecdh_zero_check.py uses.
TRAMPOLINE_ADDR = 0x0340

POISON = 0xA5


def profile_problem():
    """Return why this build cannot carry this suite, or None if it can.

    The label check alone is NOT sufficient, and that is the trap this
    function exists for. On an onchip or comb build
    ``labels.address("reu_fetch_mul_row")`` still resolves — to
    ``$0B4E``, our own routine — and calling it still WORKS: only the
    ``.export`` is gated (``src/boot.s`` exports block), the body is
    assembled either way, and ``src/boot.s`` still runs ``reu_mul_init``
    under both profiles, so the REU rows are populated. Measured: with
    this gate bypassed on a comb build the suite goes 7/7 green with the
    same verdict. That green is worthless — on those profiles nothing
    calls the routine at all. ``fe_mul`` uses ``fe_gen_mul_row``
    instead. A suite that certifies a calling convention on dead code
    reads as coverage and is not.

    So the label is not a witness of anything here. ``labels.txt`` is
    built with ``-Ln`` plus ``--debug-info`` and lists non-exported
    local labels, which is exactly why a label probe cannot answer
    "is this routine live in this build?".

    Measured with od65 at the v0.11.2 pin (``--dump-exports`` /
    ``--dump-imports`` over every member of both archives and every
    c64-https object):

      REU profile   exported by build/boot.o; imported by exactly one
                    object, build/crypto/fe25519.o (our own fe_mul)
      onchip/comb   exported by nobody, imported by nobody

    No sibling member exports or imports it on either profile. The
    wrapper passes ``-D SHARED_REU_MUL_INIT -D SHARED_REU_MUL_FETCH -D
    SHARED_CT_MUL_8X8`` in ``CONTRACT_DEFINES``, which defers the whole
    of upstream's ``mul_8x8.s`` to us — ``mul_8x8.o`` in
    ``nistcurves-p256.a`` is an EMPTY object (0 imports, 0 exports, 0
    bytes in every segment). So today the convention this suite pins is
    a contract obligation (SPEC 8.2) on a routine c64-https publishes as
    the APP_OWNED provider, exercised only by an in-tree caller. It goes
    live the moment a consumer stops deferring, or upstream's own copy
    changes convention — nistcurves v0.14.0 does the latter.

    The authoritative witness is ``build/flags.stamp``, which holds the
    fully expanded ``CA65FLAGS`` the objects in ``build/`` were made
    with (#159). Fail closed: an unreadable stamp is a refusal, not a
    shrug — a suite that cannot tell which build it is looking at has no
    business reporting a convention.
    """
    try:
        with open(FLAGS_STAMP) as fh:
            stamp = fh.read()
    except OSError as e:
        return (f"cannot read {FLAGS_STAMP} ({e}); the profile of the build "
                f"in build/ is unknown and this suite refuses to guess")
    ca65 = [ln for ln in stamp.splitlines() if ln.startswith("CA65FLAGS=")]
    if not ca65:
        return (f"{FLAGS_STAMP} carries no CA65FLAGS line; its format has "
                f"changed and this guard can no longer read it")
    if "USE_NISTCURVES_ONCHIP" in ca65[0]:
        return ("this is an on-chip build (USE_NISTCURVES_ONCHIP in "
                "CA65FLAGS). `reu_fetch_mul_row` is still assembled and "
                "still callable here, but it is dead code: nothing in "
                "the image or the sibling archive calls it, so pinning "
                "its convention on this build certifies nothing")
    if "USE_X25519_SIBLING" in ca65[0]:
        return ("USE_X25519_SIBLING evicts the in-tree provider entirely "
                "(src/boot.s .ifndef USE_X25519_SIBLING)")
    return None


def build_trampoline(a_value: int, target: int) -> bytes:
    """``LDA #a_value ; JSR target ; RTS`` — six bytes."""
    return bytes([0xA9, a_value & 0xFF,
                  0x20, target & 0xFF, (target >> 8) & 0xFF,
                  0x60])


def identify_row(lo: bytes, hi: bytes):
    """Return the multiplier whose row this is, or None.

    Row *a* holds ``lo[b] | hi[b] << 8 == a * b`` for every b in 0..255.
    ``b = 1`` names the candidate; all 256 entries then have to agree, so a
    buffer that merely happens to start with a plausible byte is rejected.
    """
    if len(lo) != 256 or len(hi) != 256:
        return None
    candidate = lo[1] | (hi[1] << 8)
    if candidate > 255:
        return None
    for b in range(256):
        if (lo[b] | (hi[b] << 8)) != candidate * b:
            return None
    return candidate


def fetch_row(transport, labels, *, a_reg: int, a_mem: int):
    """Call `reu_fetch_mul_row` with A=*a_reg* and mul_cached_a=*a_mem*.

    Returns ``(row, lo, hi)`` where *row* is the identified multiplier or
    ``None`` when the 512 bytes are not a multiplication row at all (no
    DMA happened, or the buffer is ROM).
    """
    write_bytes(transport, labels["mul_cached_a"], bytes([a_mem]))

    # Poison both halves: a fetch that never happened must not be able to
    # masquerade as one that did and agreed with us.
    write_bytes(transport, labels["mul_dma_lo"], bytes([POISON]) * 256)
    write_bytes(transport, labels["mul_dma_hi"], bytes([POISON]) * 256)

    stub = build_trampoline(a_reg, labels["reu_fetch_mul_row"])
    write_bytes(transport, TRAMPOLINE_ADDR, stub)
    readback = read_bytes(transport, TRAMPOLINE_ADDR, len(stub))
    if readback != stub:
        raise RuntimeError(
            f"trampoline readback mismatch at ${TRAMPOLINE_ADDR:04X}: "
            f"wrote {stub.hex()}, read {readback.hex()}")

    jsr(transport, TRAMPOLINE_ADDR, timeout=30.0)

    lo = read_bytes(transport, labels["mul_dma_lo"], 256)
    hi = read_bytes(transport, labels["mul_dma_hi"], 256)
    return identify_row(lo, hi), lo, hi


def check_shadow_ram_readable(transport, labels) -> bool:
    """`mul_dma_lo/hi` live at $BA00/$BB00, under the BASIC ROM shadow.

    `boot.s` banks BASIC out ($01 = $36), so by the time the menu is up
    these are RAM — but a monitor read of a ROM-banked $BA00 returns ROM
    bytes and *looks* like data. Prove it is RAM by writing and reading
    back before believing any value from this region.
    """
    probe = bytes(range(0x10, 0x20))
    for addr_name in ("mul_dma_lo", "mul_dma_hi"):
        write_bytes(transport, labels[addr_name], probe)
        if read_bytes(transport, labels[addr_name], len(probe)) != probe:
            print(f"    FAIL: ${labels[addr_name]:04X} ({addr_name}) is not "
                  f"writable RAM — BASIC ROM is still banked in. Every value "
                  f"read from this region would be a ROM byte.")
            return False
    return True


# ============================================================================
# Tests
# ============================================================================

def test_positive_control(transport, labels):
    """A and mul_cached_a AGREE: the named row must actually arrive.

    This is the REU-presence and plumbing check. Without ``-reu`` the fetch
    DMA no-ops and the poison survives; that is an inconclusive run, and it
    must be reported as such rather than as a convention verdict.
    """
    passed = failed = 0
    for value in (0x11, 0x7F, 0xC3):
        print(f"    A = mul_cached_a = ${value:02X}...", end="", flush=True)
        row, lo, hi = fetch_row(transport, labels, a_reg=value, a_mem=value)
        if row == value:
            passed += 1
            print(" PASS")
        else:
            failed += 1
            print(" FAIL")
            if all(b == POISON for b in lo[:8]):
                print("      the poison survived: no DMA reached "
                      "mul_dma_lo. Is VICE running with -reu -reusize 512?")
            print(f"      identified row: {row!r} (wanted {value})")
            print(f"      lo[:8] = {lo[:8].hex()}  hi[:8] = {hi[:8].hex()}")
    return passed, failed


def test_row_index_source(transport, labels):
    """A and mul_cached_a DISAGREE: which one selected the row?"""
    passed = failed = 0
    # Pairs chosen so neither value is 0 or 1 and neither is a multiple of
    # the other — an ambiguous identification is impossible.
    for a_reg, a_mem in ((0x2F, 0x11), (0x05, 0xB7), (0xFE, 0x03)):
        print(f"    A = ${a_reg:02X}, mul_cached_a = ${a_mem:02X}...",
              end="", flush=True)
        row, lo, hi = fetch_row(transport, labels, a_reg=a_reg, a_mem=a_mem)
        if row == a_mem:
            observed = "memory"
        elif row == a_reg:
            observed = "register"
        else:
            observed = None

        if observed == EXPECTED_CONVENTION:
            passed += 1
            print(f" PASS (row ${row:02X}, convention={observed})")
        else:
            failed += 1
            print(" FAIL")
            if observed is None:
                print(f"      the 512 bytes are not a multiplication row at "
                      f"all (row={row!r}); lo[:8] = {lo[:8].hex()}")
                print("      treat this run as INCONCLUSIVE, not as a "
                      "convention change.")
            else:
                print(f"      reu_fetch_mul_row took its row index from the "
                      f"{observed.upper()}, not from {EXPECTED_CONVENTION}.")
                print(f"      row that arrived: ${row:02X} "
                      f"(A=${a_reg:02X}, mul_cached_a=${a_mem:02X})")
                if observed == "register":
                    print("      This is what SPEC §8.2 asks for. If "
                          "src/boot.s was just changed to `sta "
                          "mul_cached_a`,")
                    print("      set EXPECTED_CONVENTION = \"register\" at "
                          "the top of this file in that same commit.")
                else:
                    print("      The provider regressed to reading memory "
                          "while the libraries pass A. Every fp_mul/fe_mul")
                    print("      row is now the wrong row.")
    return passed, failed


def run_tests(transport, labels):
    """Run all groups. Returns (passed, failed).

    Runner entry point (``tools/run_all_tests.py``). That runner builds
    with a bare ``make`` and launches VICE with ``-reu -reusize 512``,
    which is exactly the configuration this suite needs. A missing label
    is counted as a FAILURE here rather than skipped: under the runner it
    can only mean the build is not the one the runner claims to have made.
    """
    total_passed = total_failed = 0

    problem = profile_problem()
    if problem:
        print(f"  FAIL: wrong build profile — {problem}.")
        print("  The runner builds with a bare `make`; if that is no longer "
              "true, this arm needs revisiting rather than deleting.")
        return 0, 1
    missing = [n for n in REQUIRED_LABELS if labels.address(n) is None]
    if missing:
        print(f"  FAIL: missing labels {', '.join(missing)} — this suite "
              f"needs the REU profile (a bare `make`).")
        return 0, 1

    print("\n--- shadow RAM readable ($BA00/$BB00 under BASIC ROM) ---")
    if not check_shadow_ram_readable(transport, labels):
        print("  FAIL: 1/1 — cannot trust any mul_dma_* readback; aborting.")
        return 0, 1
    print("  OK: 1/1 passed")
    total_passed += 1

    print("\n--- positive control (A and mul_cached_a agree) ---")
    p, f = test_positive_control(transport, labels)
    total_passed += p
    total_failed += f
    print(f"  {'OK' if f == 0 else 'FAIL'}: {p}/{p + f} passed")
    if f:
        print("\n  Positive control failed: the row-fetch path itself is not "
              "working, so the")
        print("  convention verdict below would be meaningless. Not run.")
        return total_passed, total_failed

    print("\n--- row index source (A and mul_cached_a disagree) ---")
    p, f = test_row_index_source(transport, labels)
    total_passed += p
    total_failed += f
    print(f"  {'OK' if f == 0 else 'FAIL'}: {p}/{p + f} passed")

    return total_passed, total_failed


# ============================================================================
# Main
# ============================================================================

def main():
    global VERBOSE
    os.chdir(PROJECT_ROOT)

    VERBOSE = "--verbose" in sys.argv[1:]

    if no_reu_requested():
        print("FATAL: C64_VICE_NO_REU=1 — this suite fetches rows out of the "
              "REU. Without it the DMA no-ops and every result is "
              "inconclusive.")
        sys.exit(2)

    if os.environ.get("C64_SKIP_BUILD"):
        print("\n=== Building (skipped: C64_SKIP_BUILD set) ===")
    else:
        print("\n=== Building (REU profile: plain `make`) ===")
        subprocess.run(["make", "clean"], capture_output=True, cwd=PROJECT_ROOT)
        result = subprocess.run(["make"], capture_output=True, text=True,
                                cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            sys.exit(1)
        print(f"  Build OK: {PRG_PATH}")

    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found")
        sys.exit(1)

    labels = Labels.from_file(LABELS_PATH)
    # CANNOT RUN exits 2 — never 0 — so a profile that cannot carry this
    # coverage can't be mistaken for one that passed it. Same policy as
    # tools/test_x509_name.py on a non-uci build.
    problem = profile_problem()
    if problem:
        print("\n=== CANNOT RUN ===")
        print(f"  {problem}.")
        print("  Rebuild with a plain `make` (BACKEND=ip65, REU profile) "
              "and re-run.")
        sys.exit(2)
    missing = [n for n in REQUIRED_LABELS if labels.address(n) is None]
    if missing:
        print("\n=== CANNOT RUN ===")
        print(f"  missing labels: {', '.join(missing)}")
        print("  Rebuild with a plain `make` and re-run.")
        sys.exit(2)

    print(f"\n  Labels loaded from {LABELS_PATH}")
    print(f"  reu_fetch_mul_row = ${labels['reu_fetch_mul_row']:04X}, "
          f"mul_cached_a = ${labels['mul_cached_a']:04X}")
    print(f"  EXPECTED_CONVENTION = {EXPECTED_CONVENTION!r}")

    config = default_vice_config(prg_path=PRG_PATH, warp=True, ntsc=True,
                                 sound=False)

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"\n=== Starting VICE ===")
        print(f"  VICE PID={inst.pid}, port={inst.port}")
        print("  Waiting for main menu...")
        # The menu appears only after boot's sqtab_init + reu_mul_init have
        # populated all 256 REU rows, which is exactly the state this suite
        # needs, so there is nothing to initialise by hand.
        menu_to = float(os.environ.get("C64_INIT_TIMEOUT", "120"))
        if wait_for_text(transport, "Q=QUIT", timeout=menu_to,
                         verbose=False) is None:
            print("FATAL: Main menu did not appear")
            sys.exit(1)
        print("  Main menu ready (boot has run reu_mul_init)")

        passed, failed = run_tests(transport, labels)
        mgr.release(inst)

    total = passed + failed
    print(f"\n{'=' * 60}")
    print("RESULTS")
    print(f"{'=' * 60}")
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {failed}/{total}")
    if failed == 0:
        print(f"\n  [+] reu_fetch_mul_row takes its row index from "
              f"{EXPECTED_CONVENTION.upper()}, as asserted")
    else:
        print(f"\n  [-] reu_fetch_mul_row entry convention: {failed} "
              f"CHECK(S) FAILED")
    print(f"{'=' * 60}")
    sys.exit(verdict(passed, failed,
                     certifies="reu_fetch_mul_row's entry convention"))


if __name__ == "__main__":
    main()
