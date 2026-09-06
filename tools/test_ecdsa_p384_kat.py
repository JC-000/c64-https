#!/usr/bin/env python3
"""test_ecdsa_p384_kat.py — KAT smoke test for the dual-overlay
P-384 ECDSA verify path (Phase 2 deliverable).

Exercises the bare-metal Phase-3 dual-overlay flow end-to-end without
depending on Phase-4a's TLS-side dispatcher (`src/crypto/ecdsa_verify_384.s`):

    1. crypto_swap_to_p384_sha384            ; DMA SHA-384 overlay from REU bank 6
    2. sha384_init / sha384_update / sha384_final  ; produce 48 B BE digest
    3. memcpy sha384_digest -> ecdsa_inputs_384[96..143]
    4. crypto_swap_to_p384_curve             ; DMA curve / verify overlay from REU bank 7
    5. jsr ecdsa_verify_384                  ; A/X = pointer to 240 B BE struct

The stub runs on the C64 and signals completion + result via sentinel
bytes the host polls.  The host pre-loads (r, s, Qx, Qy, message) into
the resident DATA buffers via DMA before each invocation.

Vector subset (RFC 6979 + NIST CAVP P-384,SHA-384).  Default ("smoke"):

    - RFC 6979 A.3.1 P-384 "sample" (positive, deterministic-k canonical)

`--full` adds:

    - RFC 6979 A.3.1 with LSB-flipped r              (negative derivative)
    - First CAVP SigVer Result=P                     (positive)
    - First CAVP SigVer Result=F (modification 1-4)  (negative)

Single-vector default exists because one P-384 verify costs anywhere from
~5 s (fast Mac, VICE warp) to ~15-30 min (slower hosts) of wall-clock,
and one verify is enough to confirm the dual-overlay flow is wired up.
Use `--full` once you have a wall-clock budget for 4x the per-verify
cost.

Usage:

    /Users/someone/.local/share/c64-test-harness/venv/bin/python3 \
        tools/test_ecdsa_p384_kat.py [--u64] [--full] [--verbose]

    --u64       Also run on a real Ultimate 64 Elite (requires U64_HOST).
                Default skips U64 — VICE-only.
    --full      Run all 4 vectors (positive RFC + neg-r + CAVP P + CAVP F).
    --verbose   Print per-vector wall-clock + carry breakdown.
    --sha-only  Diagnostic: skip the slow ecdsa_verify_384 step.  Confirms
                the dual-overlay swap dispatch + SHA-384 + splice path
                works without paying for the verify (which on a busy
                VICE warp host can take 5-30 min/vector).  Use this
                first if --full hangs.  It leaves every vector without a
                verdict, so it always exits non-zero and can never report
                OVERALL: PASS — read the per-step output, not the tally.

Exit codes (tools/_skip_policy.py, issue #178):
    0 PASS
    1 FAIL (a vector ran and failed)
    2 COULD NOT RUN -- --u64 was requested with no U64_HOST, so nothing ran.
      NOT opt-out-able: honouring C64_ALLOW_SKIP here would fire before the
      VICE lane and silence the emulator half too, which needs no hardware.
      The remedy is free: set U64_HOST, or drop --u64 and get the VICE lane
      on its own.  Not passing --u64 at all is a VOLUNTARY skip, exits 0,
      and is how you say "this lane has no hardware".

Environment:
    C64_SKIP_BUILD=1            Reuse existing build artifacts (skip make).
    C64_ALLOW_SKIP=1            Honoured by the rig lane; NOT by the --u64
                                gate above (see its comment in main()).
    U64_HOST=<ip>               Ultimate 64 host (default 192.168.1.81).
    P384_KAT_VICE_TIMEOUT_S     Per-VERIFY-step timeout under VICE
                                (default 1800 s = 30 min).
    P384_KAT_U64_TIMEOUT_S      Per-vector timeout under U64
                                (default 600 s).

Build-order trap: this test does a two-pass build internally because
the overlay-bin link script reads `build/labels.txt` to resolve
`mul_dma_lo`/`mul_dma_hi`/`mul_cached_a`/`reu_fetch_mul_row` at the
SAME runtime addresses the main PRG uses.  On a clean build,
`labels.txt` doesn't exist when the overlay-bin link runs, those
symbols stub out to `$0000`, and the curve overlay's `fp_mul_384`
hangs in field arithmetic with no obvious symptom.  Two passes
(first builds labels.txt, second re-runs the overlay-bin link with
the resolved addresses) work around it; an explicit sanity check
after the build asserts the curve overlay's labels are non-zero.
Cleaner upstream fix: add `build/labels.txt` as an order-only
dependency on the overlay-bin Make target.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import time
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _skip_policy import cannot_run  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PRG_PATH = PROJECT_ROOT / "build" / "c64-https.prg"
LABELS_PATH = PROJECT_ROOT / "build" / "labels.txt"
LABELS_SHA384_PATH = PROJECT_ROOT / "build" / "labels-p384-sha384.txt"
LABELS_CURVE_PATH = PROJECT_ROOT / "build" / "labels-p384-curve.txt"
NIST_VECTORS_PATH = (
    PROJECT_ROOT / "libs" / "nistcurves" / "tools" / "vectors"
    / "nist_p384_sigver.rsp"
)


# -----------------------------------------------------------------------------
# Test vectors
# -----------------------------------------------------------------------------

# RFC 6979 Appendix A.3.1 — P-384, SHA-384, message "sample" (positive)
RFC6979_P384 = {
    "name": "rfc6979_p384_sample",
    "msg": b"sample",
    "Qx": 0xEC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13,
    "Qy": 0x8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720,
    "r":  0x94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46,
    "s":  0x99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8,
    "expected_valid": True,
}


# Negative derivative of RFC 6979 — flip LSB of r.
RFC6979_P384_NEG_R = {
    "name": "rfc6979_p384_sample_flip_r",
    "msg": b"sample",
    "Qx": RFC6979_P384["Qx"],
    "Qy": RFC6979_P384["Qy"],
    "r":  RFC6979_P384["r"] ^ 1,
    "s":  RFC6979_P384["s"],
    "expected_valid": False,
}


def _parse_cavp_p384_section(path: Path) -> list[dict]:
    """Parse the [P-384,SHA-384] section of nist_p384_sigver.rsp."""
    out = []
    cur: dict = {}
    in_section = False
    with path.open("r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                if cur and in_section and "expected_pass" in cur:
                    out.append(cur)
                    cur = {}
                continue
            if line.startswith("[") and line.endswith("]"):
                if cur and in_section and "expected_pass" in cur:
                    out.append(cur)
                cur = {}
                in_section = (line[1:-1].strip() == "P-384,SHA-384")
                continue
            if not in_section:
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                k = k.strip()
                v = v.strip()
                if k == "Msg":
                    cur["Msg"] = bytes.fromhex(v)
                elif k in ("Qx", "Qy", "R", "S"):
                    cur[k] = int(v, 16)
                elif k == "Result":
                    cur["raw_result"] = v
                    cur["expected_pass"] = v.startswith("P")
    if cur and in_section and "expected_pass" in cur:
        out.append(cur)
    return out


def _build_vector_list(*, full: bool = False) -> list[dict]:
    """Pick the diverse smoke-test vector subset.

    Default ("smoke"): RFC 6979 positive only — one verify under VICE
    warp can run anywhere from 30 s to several minutes wall-clock
    depending on host CPU, and this is the fastest signal that the
    end-to-end dual-overlay path is wired up correctly.

    --full: add the RFC 6979 negative derivative + first CAVP P + first
    CAVP F.  Total wall-clock under VICE warp is 4x the per-vector
    verify time plus overhead.
    """
    vectors = [RFC6979_P384]

    if not full:
        return vectors

    vectors.append(RFC6979_P384_NEG_R)

    cavp = _parse_cavp_p384_section(NIST_VECTORS_PATH)
    cavp_pos = next((v for v in cavp if v["expected_pass"]), None)
    cavp_neg = next((v for v in cavp if not v["expected_pass"]), None)
    if cavp_pos is None or cavp_neg is None:
        raise RuntimeError(
            f"Could not find a P/F pair in {NIST_VECTORS_PATH} "
            f"section [P-384,SHA-384] (parsed {len(cavp)} vectors)"
        )

    vectors.append({
        "name": f"cavp_pos[{cavp_pos['raw_result']}]",
        "msg": cavp_pos["Msg"],
        "Qx": cavp_pos["Qx"],
        "Qy": cavp_pos["Qy"],
        "r":  cavp_pos["R"],
        "s":  cavp_pos["S"],
        "expected_valid": True,
    })
    vectors.append({
        "name": f"cavp_neg[{cavp_neg['raw_result']}]",
        "msg": cavp_neg["Msg"],
        "Qx": cavp_neg["Qx"],
        "Qy": cavp_neg["Qy"],
        "r":  cavp_neg["R"],
        "s":  cavp_neg["S"],
        "expected_valid": False,
    })

    return vectors


# -----------------------------------------------------------------------------
# Address layout
#
# All overlay-side and dispatch addresses are resolved dynamically from
# build/labels.txt + build/labels-p384-{sha384,curve}.txt at runtime
# (see _resolve_addresses).  The constants below are only the pieces
# that *don't* come from labels — harness scratch addresses (where the
# stub + message + sentinels live) and the SHA-384 ZP slots, which the
# sibling's overlay-side labels file expose but which we want to be
# explicit about anyway since they're shared between caller and callee.
# -----------------------------------------------------------------------------

# Sibling SHA-384 streaming pointers — ZP $3D-$40 (per Phase 1.5 sibling
# zp_config.s; comment in src/crypto/shared/crypto_swap.s confirms the
# slots are c64-https-safe across all crypto/TLS/ip65/UCI/fe25519/x25519/
# ECDSA-bignum paths).  We cross-check against labels-p384-sha384.txt at
# runtime to detect any sibling-side ZP relocation.
SHA_SRC_ZP_EXPECTED = 0x003D   # 2 B little-endian message pointer
SHA_LEN_ZP_EXPECTED = 0x003F   # 2 B little-endian message length

# Harness scratch addresses (live in the OVERLAY_FILE_PAD tail past the
# curve overlay's resident DATA at $C9F7).  $CFFE/$CFFF are reserved by
# the overlay link defines for poly_prod_lo/hi, so we stay below $CFE0.
STUB_ADDR     = 0xCA00         # 6502 stub body
MSG_BUF_ADDR  = 0xCB00         # message bytes (max 256 B; CAVP msgs are 128 B)
RESULT_CARRY  = 0xCFE0         # 0=valid (C=0), 1=invalid (C=1)
SENTINEL_DONE = 0xCFE1         # 0=running, $42=stub finished
PROGRESS_BYTE = 0xCFE2         # debug: which step the stub got to

DONE_VALUE = 0x42


# -----------------------------------------------------------------------------
# 6502 stub generator (verify-only)
#
# We split the dual-overlay flow into per-step jsr() calls instead of one
# monolithic stub so the harness has full visibility (and can apply
# tighter per-step timeouts) at each transition.  The only step that
# needs a stub is the verify itself, because run_subroutine cannot
# preload CPU registers — the verify's BE-struct ABI takes the pointer
# in A/X.  The stub is also the natural place to capture the C flag
# returned by ecdsa_verify_384 and stash it for the host to read back.
# -----------------------------------------------------------------------------

def _build_verify_stub(addresses: dict[str, int]) -> bytes:
    """Emit the verify-only stub:

        lda #<ecdsa_inputs_384
        ldx #>ecdsa_inputs_384
        jsr ecdsa_verify_384
        php / pla / and #$01
        sta RESULT_CARRY
        rts

    Caller is responsible for: swapping in the curve overlay (otherwise
    the bytes at ecdsa_verify_384's address are stale / wrong); having
    pre-staged r/s/h/Qx/Qy in ecdsa_inputs_384.
    """
    ecdsa_verify_384  = addresses["ecdsa_verify_384"]
    ecdsa_inputs_384  = addresses["ecdsa_inputs_384"]

    code = bytearray()

    def emit(*bs: int) -> None:
        code.extend(bs)

    code += bytes([
        0xA9, ecdsa_inputs_384 & 0xFF,                  # LDA #<inputs
        0xA2, (ecdsa_inputs_384 >> 8) & 0xFF,           # LDX #>inputs
        0x20, ecdsa_verify_384 & 0xFF,
              (ecdsa_verify_384 >> 8) & 0xFF,           # JSR ecdsa_verify_384
        0x08,                                           # PHP
        0x68,                                           # PLA
        0x29, 0x01,                                     # AND #$01
        0x8D, RESULT_CARRY & 0xFF,
              (RESULT_CARRY >> 8) & 0xFF,               # STA RESULT_CARRY
        0x60,                                           # RTS
    ])

    return bytes(code)


def _build_splice_stub(addresses: dict[str, int]) -> bytes:
    """Emit a stub that copies sha384_digest -> ecdsa_inputs_384+96.

    Y-indexed reverse loop: the SHA digest is 48 B and both source and
    destination fit in absolute,Y-addressable space.  This runs while
    the SHA-384 overlay is resident — sha384_digest's address ($C3E1)
    is inside the SHA overlay's resident DATA span; ecdsa_inputs_384's
    address ($C8D1) is inside the curve overlay's resident DATA span,
    BUT ecdsa_inputs_384 is past the SHA's resident DATA tail at $C411
    so writing there does not alias any SHA state.
    """
    sha384_digest    = addresses["sha384_digest"]
    ecdsa_inputs_384 = addresses["ecdsa_inputs_384"]
    DIGEST_DST = ecdsa_inputs_384 + 96
    DIGEST_BYTES = 48

    code = bytearray()
    code += bytes([
        0xA0, DIGEST_BYTES - 1,                         # LDY #47
    ])
    cp_loop = len(code)
    code += bytes([
        0xB9, sha384_digest & 0xFF,
              (sha384_digest >> 8) & 0xFF,              # LDA sha384_digest,Y
        0x99, DIGEST_DST & 0xFF,
              (DIGEST_DST >> 8) & 0xFF,                 # STA DIGEST_DST,Y
        0x88,                                           # DEY
    ])
    rel = cp_loop - (len(code) + 2)
    code += bytes([0x10, rel & 0xFF])                   # BPL @cp_loop
    code += bytes([0x60])                               # RTS
    return bytes(code)


# -----------------------------------------------------------------------------
# Label-file readers
# -----------------------------------------------------------------------------

def _load_labels(path: Path) -> dict[str, int]:
    """Parse a VICE-format labels.txt ("al C:XXXX .name")."""
    out: dict[str, int] = {}
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) < 3 or parts[0] != "al":
                continue
            addr_field = parts[1]
            if addr_field.startswith("C:"):
                addr = int(addr_field[2:], 16)
            else:
                addr = int(addr_field, 16)
            name = parts[2].lstrip(".")
            out[name] = addr
    return out


def _resolve_addresses() -> dict[str, int]:
    """Pull every needed address from the on-disk label files.

    The main PRG's labels.txt resolves the swap dispatchers
    (crypto_swap_to_p384_*).  The split-overlay labels-p384-*.txt
    files resolve the overlay-resident entry points (sha384_*,
    ecdsa_verify_384) and the resident-DATA buffers (sha384_digest,
    ecdsa_inputs_384).

    A small consistency check confirms the sibling SHA-384 ZP slots
    haven't moved out from under us; the stub doesn't actually use
    these addresses (it relies on the host setting them via DMA before
    each call), but a relocation of the sibling's zp_config.s would
    silently break the test if the host kept writing to $3D/$3F.
    """
    main = _load_labels(LABELS_PATH)
    sha = _load_labels(LABELS_SHA384_PATH)
    curve = _load_labels(LABELS_CURVE_PATH)

    sources = {
        "crypto_swap_to_p384_sha384": main,
        "crypto_swap_to_p384_curve":  main,
        "sha384_init":   sha,
        "sha384_update": sha,
        "sha384_final":  sha,
        "sha384_digest": sha,
        "ecdsa_verify_384":  curve,
        "ecdsa_inputs_384":  curve,
        "sha_src": sha,
        "sha_len": sha,
    }
    resolved: dict[str, int] = {}
    missing: list[str] = []
    for name, label_dict in sources.items():
        if name not in label_dict:
            missing.append(name)
            continue
        resolved[name] = label_dict[name]
    if missing:
        raise RuntimeError(
            f"Required label(s) missing from on-disk labels files: {missing}"
        )

    # Sibling-ZP sanity: the test stub's host-side DMA writes assume
    # sha_src=$3D/$3E + sha_len=$3F/$40.  If the sibling relocates
    # these, the host will write to dead ZP and the on-device sha_*
    # routines will read garbage instead of MSG_BUF_ADDR.  Catch that
    # before running rather than diagnosing wrong-digest failures.
    if resolved["sha_src"] != SHA_SRC_ZP_EXPECTED:
        raise RuntimeError(
            f"sha_src moved to ${resolved['sha_src']:04X} "
            f"(expected ${SHA_SRC_ZP_EXPECTED:04X}); update SHA_SRC_ZP_EXPECTED"
            f" + the host-side DMA write."
        )
    if resolved["sha_len"] != SHA_LEN_ZP_EXPECTED:
        raise RuntimeError(
            f"sha_len moved to ${resolved['sha_len']:04X} "
            f"(expected ${SHA_LEN_ZP_EXPECTED:04X}); update SHA_LEN_ZP_EXPECTED"
            f" + the host-side DMA write."
        )

    return resolved


# -----------------------------------------------------------------------------
# Vector → DMA payloads
# -----------------------------------------------------------------------------

def _be48(v: int) -> bytes:
    """Encode an integer as 48 BE bytes."""
    return v.to_bytes(48, "big")


def _stage_vector_buffers(transport, vec: dict, addresses: dict[str, int]) -> None:
    """DMA r/s/Qx/Qy into ecdsa_inputs_384 and the message into MSG_BUF.

    The h slot (ecdsa_inputs_384+96) is left for the stub's
    sha384_final + memcpy step.  Pre-zeroing it is harmless paranoia.
    """
    from c64_test_harness import write_bytes

    inputs = addresses["ecdsa_inputs_384"]

    # Layout: r(48) | s(48) | h(48) | Qx(48) | Qy(48)
    write_bytes(transport, inputs + 0,   _be48(vec["r"]))
    write_bytes(transport, inputs + 48,  _be48(vec["s"]))
    write_bytes(transport, inputs + 96,  bytes(48))      # h zeroed
    write_bytes(transport, inputs + 144, _be48(vec["Qx"]))
    write_bytes(transport, inputs + 192, _be48(vec["Qy"]))

    msg = vec["msg"]
    if len(msg) > 0xFE:
        raise ValueError(
            f"vector {vec['name']!r}: message length {len(msg)} exceeds "
            f"the harness scratch budget at MSG_BUF (256 B - guard)."
        )
    if len(msg) > 0:
        write_bytes(transport, MSG_BUF_ADDR, msg)

    # sha_src = MSG_BUF_ADDR (LE 16-bit), sha_len = len(msg) (LE 16-bit).
    write_bytes(transport, addresses["sha_src"],
                bytes([MSG_BUF_ADDR & 0xFF, (MSG_BUF_ADDR >> 8) & 0xFF]))
    write_bytes(transport, addresses["sha_len"],
                bytes([len(msg) & 0xFF, (len(msg) >> 8) & 0xFF]))


# -----------------------------------------------------------------------------
# Test loop
# -----------------------------------------------------------------------------

def _run_one_vector(target, vec: dict, addresses: dict[str, int], *,
                    splice_addr: int, verify_addr: int,
                    timeout_s: float, verbose: bool = False,
                    sha_only: bool = False) -> dict:
    """Run a single vector through the dual-overlay flow.

    Each step is an isolated run_subroutine() call so we can apply
    tight per-step timeouts and surface failures at the granularity of
    the failed step (rather than discovering "stub never returned" 600s
    later with no breadcrumbs).

    Steps:
       1) DMA r/s/Qx/Qy + message + sha_src/sha_len.
       2) jsr crypto_swap_to_p384_sha384.
       3) jsr sha384_init.
       4) jsr sha384_update (consumes sha_src/sha_len).
       5) jsr sha384_final (writes 48 B to sha384_digest).
       6) jsr splice_stub (memcpy sha384_digest -> ecdsa_inputs_384+96).
       7) Cross-check the spliced digest against host hashlib.
       8) jsr crypto_swap_to_p384_curve.
       9) jsr verify_stub (loads A/X with struct ptr, jsr verify, captures C).
      10) Read RESULT_CARRY and return.
    """
    from c64_test_harness import read_bytes
    from c64_test_harness.execute import run_subroutine

    transport = target.transport

    expected_digest = hashlib.sha384(vec["msg"]).digest()

    # Step 1: stage all input buffers via DMA.
    _stage_vector_buffers(transport, vec, addresses)

    # Helper: invoke an address with a per-step budget; record the step
    # that failed in the returned dict.
    def _step(label: str, addr: int, *, step_timeout: float) -> dict | None:
        t0 = time.perf_counter()
        try:
            run_subroutine(target, addr, timeout=step_timeout,
                           trampoline_addr=0x0334)
        except TimeoutError as exc:
            return {
                "error": f"TIMEOUT in step '{label}' after "
                         f"{step_timeout:.0f}s: {exc}",
                "valid": None,
                "seconds": time.perf_counter() - t0,
                "failed_step": label,
            }
        return None

    # Steps 2-5: SHA-384 dispatch.
    t_overall = time.perf_counter()
    err = _step("swap_to_sha384", addresses["crypto_swap_to_p384_sha384"],
                step_timeout=10.0)
    if err: return err
    err = _step("sha384_init", addresses["sha384_init"], step_timeout=10.0)
    if err: return err
    msg_len = len(vec["msg"])
    # SHA-384 update budget: ~5 ms / byte at 1 MHz, sub-frame under VICE
    # warp, so 60 s for the largest CAVP message (128 B) is overkill.
    err = _step("sha384_update", addresses["sha384_update"],
                step_timeout=60.0)
    if err: return err
    err = _step("sha384_final", addresses["sha384_final"], step_timeout=15.0)
    if err: return err

    # Step 6: splice digest.  Tight loop, < 200 cy, sub-frame even at 1 MHz.
    err = _step("splice_digest", splice_addr, step_timeout=5.0)
    if err: return err

    # Step 7: cross-check the spliced digest against host hashlib BEFORE
    # the curve overlay clobbers $C000-$C5A0 (which subsumes
    # sha384_digest at $C3E1).  ecdsa_inputs_384+96 is at $C931, past
    # the curve overlay's first-scratch span at $C5A0, so reading it
    # post-swap would also work — but reading here gives us a clean
    # error message if the SHA path is the one that broke.
    on_device_digest = bytes(read_bytes(transport,
                                       addresses["ecdsa_inputs_384"] + 96, 48))
    if on_device_digest != expected_digest:
        return {
            "error": f"sha384 digest mismatch (spliced): "
                     f"device={on_device_digest.hex()} "
                     f"expected={expected_digest.hex()}",
            "valid": None,
            "seconds": time.perf_counter() - t_overall,
            "failed_step": "sha_digest_check",
        }

    # Step 8: swap to curve overlay.
    err = _step("swap_to_curve", addresses["crypto_swap_to_p384_curve"],
                step_timeout=10.0)
    if err: return err

    if sha_only:
        # Diagnostic short-circuit: the dual-overlay swap, SHA-384 and the
        # digest splice have all been confirmed above without paying for
        # the (slow) ecdsa_verify_384 call.
        #
        # What must NOT happen here is synthesising `valid` from
        # vec["expected_valid"]: that fabricates the answer the test exists
        # to obtain, makes every vector compare equal to its own
        # expectation, and prints OVERALL: PASS for a run in which
        # ecdsa_verify_384 was never executed. The vector has no verdict,
        # so it is reported as one that could not run — a failure, per the
        # audit rule that an involuntary skip is a failure. --sha-only is a
        # diagnostic; by construction it can never certify the verify path.
        if verbose:
            print(f"      [--sha-only] swap + SHA-384 + splice OK; "
                  f"ecdsa_verify_384 NOT run — no verdict for this vector")
        return {
            "error": "--sha-only: ecdsa_verify_384 was never executed, so "
                     "this vector has no verdict (counted as a failure). "
                     "The swap/SHA-384/splice steps up to it did pass.",
            "valid": None,
            "carry": 0xFE,                    # marker for "skipped"
            "seconds": 0.0,
            "overall_seconds": time.perf_counter() - t_overall,
            "sha_only": True,
            "failed_step": "ecdsa_verify_384 (skipped by --sha-only)",
        }

    # Step 9: verify (the slow one — bench wall-clock ~75-90 s on real
    # 1 MHz, sub-second to a few seconds under VICE warp on a fast host
    # but can be tens of seconds on a busy machine).
    t_verify = time.perf_counter()
    err = _step("ecdsa_verify_384", verify_addr, step_timeout=timeout_s)
    if err: return err
    verify_seconds = time.perf_counter() - t_verify

    # Step 10: read result.
    carry = read_bytes(transport, RESULT_CARRY, 1)[0]
    valid = (carry == 0)
    overall = time.perf_counter() - t_overall
    if verbose:
        print(f"      digest OK, carry=${carry:02X}, "
              f"verify_dt={verify_seconds:.3f}s, "
              f"overall_dt={overall:.3f}s")
    return {
        "valid": valid,
        "carry": carry,
        "seconds": verify_seconds,
        "overall_seconds": overall,
    }


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

def _build_prg() -> None:
    if os.environ.get("C64_SKIP_BUILD") == "1":
        print("  C64_SKIP_BUILD=1 — reusing existing build artifacts")
        return
    # Two-pass build dance.  The overlay-bin link
    # (tools/integration/build_nistcurves_p384_bin.sh) looks up the
    # main PRG's `mul_cached_a` / `mul_dma_lo` / `mul_dma_hi` /
    # `reu_fetch_mul_row` symbols in build/labels.txt to resolve them
    # at the SAME runtime addresses the main PRG uses.  On a clean
    # build, labels.txt does not exist when the overlay-bin step runs,
    # and those symbols silently fall back to $0000 — the curve
    # overlay's fp_mul_384 then reads/writes $0000 instead of
    # $BA00/$BB00 (mul_dma_lo/hi) and the verify hangs in field
    # arithmetic with no obvious symptom.  The Makefile's overlay-bin
    # target only depends on the cfg + archives + script, NOT on
    # labels.txt, so a single `make` after `make clean` produces a
    # broken overlay.  We work around it with a two-pass build: first
    # `make` produces labels.txt; force-touching the overlay-bin
    # script makes the second `make` re-run the overlay-bin link with
    # the now-resolved addresses; then ld65 re-links the main PRG
    # with the corrected .bin embedded.  Future fix: add labels.txt
    # as an order-only dep on the overlay-bin target in the Makefile.
    print("  Building (BACKEND=uci, two-pass for overlay-bin resolution)...")
    print("    [pass 1] make clean + make...")
    subprocess.run(["make", "clean", "BACKEND=uci"],
                   capture_output=True, cwd=str(PROJECT_ROOT))
    r1 = subprocess.run(["make", "BACKEND=uci"],
                        capture_output=True, text=True,
                        cwd=str(PROJECT_ROOT))
    if r1.returncode != 0:
        print(f"Build pass 1 failed:\n{r1.stderr}")
        sys.exit(1)

    # Touch the overlay-bin script so make re-runs it now that
    # labels.txt exists.  The script-touch beats the .bin's mtime, so
    # make rebuilds the .bin, which in turn forces a re-link of the
    # main PRG that .incbins it.
    script = PROJECT_ROOT / "tools" / "integration" / "build_nistcurves_p384_bin.sh"
    script.touch()

    print("    [pass 2] re-link overlay + main PRG with resolved addresses...")
    r2 = subprocess.run(["make", "BACKEND=uci"],
                        capture_output=True, text=True,
                        cwd=str(PROJECT_ROOT))
    if r2.returncode != 0:
        print(f"Build pass 2 failed:\n{r2.stderr}")
        sys.exit(1)

    # Sanity-check the overlay links resolved the imports rather than
    # leaving them stubbed at $0000.  This is the canary that catches
    # the build-order bug above if it ever resurfaces (e.g. someone
    # changes the cfg in a way that re-shuffles the linker's
    # dependency graph).
    curve_labels = _load_labels(LABELS_CURVE_PATH)
    for sym in ("mul_dma_lo", "mul_dma_hi", "mul_cached_a",
                "reu_fetch_mul_row"):
        addr = curve_labels.get(sym)
        if addr is None or addr == 0:
            print(f"FATAL: curve overlay's {sym} resolved to "
                  f"${addr:04X} after two-pass build (expected non-zero "
                  f"main-PRG address); fp_mul_384 will hang.  "
                  f"Re-run after `make clean BACKEND=uci && make BACKEND=uci`.")
            sys.exit(1)


def _run_backend(*, backend: str, vectors: list[dict],
                 splice_stub: bytes, verify_stub: bytes,
                 addresses: dict[str, int],
                 timeout_s: float, verbose: bool,
                 sha_only: bool = False) -> tuple[int, int, list[dict]]:
    """Acquire a target, install the stubs, run all vectors, return
    (passed, failed, details)."""
    from c64_test_harness import (
        UnifiedManager, ViceConfig, write_bytes, read_bytes, wait_for_text,
    )
    from c64_test_harness.keyboard import send_text

    if backend == "vice":
        config = ViceConfig(
            prg_path=str(PRG_PATH), warp=True, ntsc=True, sound=False,
            extra_args=["-reu", "-reusize", "512"],
        )
        mgr = UnifiedManager(backend="vice", vice_config=config)
    else:
        mgr = UnifiedManager(backend="u64", lock_timeout=120.0)

    passed = failed = 0
    details: list[dict] = []

    # Layout the two stubs back-to-back inside our scratch range.  The
    # splice stub is ~12 B, the verify stub is ~16 B — fit comfortably
    # in the 256 B page at $CA00.
    splice_addr = STUB_ADDR
    verify_addr = STUB_ADDR + ((len(splice_stub) + 15) & ~15)  # 16-B aligned

    target = mgr.acquire()
    try:
        transport = target.transport
        if backend == "vice":
            print(f"  VICE PID={target.pid}, transport ready")
        else:
            print(f"  U64 transport ready")

        # Wait for menu — confirms boot sequence (incl. reu_p384_overlay_init)
        # has finished and main_loop is polling.
        if backend == "vice":
            grid = wait_for_text(transport, "Q=QUIT", timeout=180.0,
                                 verbose=False)
            if grid is None:
                raise RuntimeError("VICE: menu banner never appeared")
        else:
            # On U64 the device is already running the PRG (run_prg).
            # Give boot ~30 s to populate REU banks + run do_net_init.
            time.sleep(30.0)

        # Install the two stubs at $CA00 / $CA10 (in OVERLAY_FILE_PAD
        # tail past the curve overlay's resident DATA at $C9F7).
        write_bytes(transport, splice_addr, splice_stub)
        write_bytes(transport, verify_addr, verify_stub)
        print(f"  splice stub at ${splice_addr:04X} ({len(splice_stub)} B)")
        print(f"  verify stub at ${verify_addr:04X} ({len(verify_stub)} B)")

        # On U64, exit main_loop to BASIC so SYS-injection works for the
        # run_subroutine trampoline.  VICE's binary-monitor jsr() does
        # not need this.
        if backend == "u64":
            send_text(transport, "q\r")
            time.sleep(2.0)

        for vec in vectors:
            print(f"  [{backend}] {vec['name']}: running"
                  f" (msg={len(vec['msg'])} B, expect="
                  f"{'VALID' if vec['expected_valid'] else 'INVALID'})...",
                  flush=True)
            result = _run_one_vector(
                target, vec, addresses,
                splice_addr=splice_addr, verify_addr=verify_addr,
                timeout_s=timeout_s, verbose=verbose,
                sha_only=sha_only,
            )
            result["name"] = vec["name"]
            result["expected_valid"] = vec["expected_valid"]
            result["backend"] = backend
            details.append(result)
            if "error" in result:
                print(f"    FAIL [{backend}] {vec['name']}: {result['error']}")
                failed += 1
                continue
            ok = (result["valid"] == vec["expected_valid"])
            tag = "PASS" if ok else "FAIL"
            overall = result.get("overall_seconds", result["seconds"])
            print(f"    {tag} [{backend}] {vec['name']}: "
                  f"valid={result['valid']} (expected {vec['expected_valid']}) "
                  f"verify={result['seconds']:.3f}s "
                  f"overall={overall:.3f}s "
                  f"carry=${result['carry']:02X}")
            if ok:
                passed += 1
            else:
                failed += 1
    finally:
        mgr.release(target)
        mgr.shutdown()

    return passed, failed, details


def main() -> int:
    # Force line-buffered stdout/stderr so live progress shows up under
    # piped invocations (otherwise Python block-buffers when not connected
    # to a terminal and the user only sees output at process exit).
    try:
        sys.stdout.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
        sys.stderr.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
    except AttributeError:
        pass  # Python < 3.7

    args = sys.argv[1:]
    run_u64 = "--u64" in args
    verbose = "--verbose" in args
    full = "--full" in args
    sha_only = "--sha-only" in args  # diagnostic: run swap+sha+splice but
                                     # skip the slow ecdsa_verify_384 step

    print(f"=== test_ecdsa_p384_kat.py (P-384 dual-overlay KAT) ===")
    os.chdir(str(PROJECT_ROOT))

    # --u64 is the caller asking for hardware.  Without U64_HOST the hardware
    # lane cannot run at all, and the tally below would otherwise add 0/0 to
    # the VICE result and print OVERALL: PASS (issue #178).  Refuse up front,
    # before the multi-hour VICE lane, rather than at the verdict.
    #
    # NO OPT-OUT, and this gate is the reason the rule needs stating: the
    # opt-out here would be scoped WRONG.  C64_ALLOW_SKIP answers "this lane
    # has no hardware", but firing before the VICE lane means honouring it
    # also silences the EMULATOR half -- which needs no hardware and could
    # have run.  Measured against master: `--u64` with U64_HOST unset ran the
    # whole VICE lane and returned 1 on a failing vector; with the opt-out
    # honoured here that became exit 0, so an operator who set
    # C64_ALLOW_SKIP=1 for the honest reason (no U64E on this lane) would
    # never learn the emulator-only half had regressed.
    #
    # The remedy costs nothing and needs no environment variable: set
    # U64_HOST, or drop --u64 and get the VICE lane on its own.  "This lane
    # has no hardware" is spelled by NOT PASSING --u64; asking for hardware
    # and not supplying it is a malformed invocation, not a coverage gap to
    # be acknowledged.
    if run_u64 and not os.environ.get("U64_HOST"):
        return cannot_run(
            "--u64 requested but U64_HOST is not set in the environment"
            " -- drop --u64 to run the VICE lane alone",
            executed=0,
            total=1,
            certifies="the P-384 verify path on real hardware",
            opt_out_env=None,
        )

    # Check the upstream test vector file exists.
    if not NIST_VECTORS_PATH.exists():
        print(f"FATAL: vector file not found: {NIST_VECTORS_PATH}")
        return 1

    _build_prg()

    for path in (PRG_PATH, LABELS_PATH, LABELS_SHA384_PATH, LABELS_CURVE_PATH):
        if not path.exists():
            print(f"FATAL: required artifact missing: {path}")
            return 1

    addresses = _resolve_addresses()
    print(f"  Addresses verified against on-disk labels:")
    for name in sorted(addresses):
        print(f"    {name:32s} = ${addresses[name]:04X}")

    vectors = _build_vector_list(full=full)
    print(f"  Loaded {len(vectors)} vectors (full={full}):")
    for v in vectors:
        print(f"    - {v['name']:30s} expect={v['expected_valid']!s} "
              f"msg={len(v['msg'])} B")

    splice_stub = _build_splice_stub(addresses)
    verify_stub = _build_verify_stub(addresses)
    print(f"  splice stub: {len(splice_stub)} B")
    print(f"  verify stub: {len(verify_stub)} B")

    # Per-VERIFY-step timeout.  VICE warp wall-clock for one P-384
    # verify is ~10-300 s on a fast Mac but can be 10-30 min on a
    # slower host, since VICE single-threads through 6502 emulation +
    # 600+ M cycles of REU DMA setup.  Default 1800 s gives generous
    # headroom; override via env if you need a tight budget.
    vice_timeout = float(os.environ.get("P384_KAT_VICE_TIMEOUT_S", "1800.0"))
    u64_timeout  = float(os.environ.get("P384_KAT_U64_TIMEOUT_S",  "600.0"))

    print(f"\n=== VICE backend (warp, -reu) ===")
    v_pass, v_fail, v_details = _run_backend(
        backend="vice", vectors=vectors,
        splice_stub=splice_stub, verify_stub=verify_stub,
        addresses=addresses,
        timeout_s=vice_timeout, verbose=verbose,
        sha_only=sha_only,
    )

    u_pass = u_fail = 0
    u_details: list[dict] = []
    if run_u64:
        print(f"\n=== U64 backend (real hardware) ===")
        if not os.environ.get("U64_HOST"):
            # Unreachable: the early gate in main() already refused.  Kept as
            # a backstop, and it must NOT leave a 0/0 lane -- that is exactly
            # what the tally used to read as OVERALL: PASS (issue #178).
            # Same no-opt-out rule as that gate, and for the same reason:
            # one file must not answer the same question two ways, or a
            # later reader "fixes" the inconsistency in whichever direction
            # they happen to notice first.
            return cannot_run(
                "--u64 requested but U64_HOST is not set in the environment"
                " -- drop --u64 to run the VICE lane alone",
                executed=v_pass + v_fail,
                total=v_pass + v_fail + len(vectors),
                certifies="the P-384 verify path on real hardware",
                opt_out_env=None,
            )
        else:
            try:
                u_pass, u_fail, u_details = _run_backend(
                    backend="u64", vectors=vectors,
                    splice_stub=splice_stub, verify_stub=verify_stub,
                    addresses=addresses,
                    timeout_s=u64_timeout, verbose=verbose,
                    sha_only=sha_only,
                )
            except Exception as exc:
                print(f"  U64 backend FAILED: {exc!r}")
                u_fail = len(vectors)
    else:
        print(f"\n=== U64 backend SKIPPED (pass --u64 to enable) ===")

    print(f"\n{'=' * 60}")
    print(f"VICE: {v_pass}/{v_pass + v_fail} passed")
    if run_u64:
        print(f"U64:  {u_pass}/{u_pass + u_fail} passed")
    print(f"{'=' * 60}")

    total_fail = v_fail + u_fail
    # NOTE: there is deliberately no `total_run == 0` vacuity guard here.
    # One was written and removed: _build_vector_list() never returns an
    # empty list (1 vector for the smoke default, 4 for --full) and
    # _run_backend() puts every vector into `passed` or `failed`, including
    # under --sha-only, whose short-circuit in _run_one_vector() returns an
    # "error" dict and is therefore counted as a failure.  So the guard could
    # not fire under any flag combination.  A check that matches nothing is
    # the same vacuous-green shape issue #178 exists to close, so it does not
    # belong in #178's own implementation.  If a vector FILTER is ever added,
    # add the guard back beside it -- where it can actually fire.
    overall = "PASS" if total_fail == 0 else "FAIL"
    print(f"OVERALL: {overall}")
    if sha_only:
        print("NOTE: --sha-only skips ecdsa_verify_384, so no vector can "
              "produce a verdict\n      and this mode can never report "
              "OVERALL: PASS. It is a diagnostic for the\n      "
              "swap + SHA-384 + splice path only; drop --sha-only to test "
              "the verify.")
    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
