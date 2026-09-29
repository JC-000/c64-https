#!/usr/bin/env python3
"""Pin where the UCI SYS-trampoline rigs put their C64 scratch (#209, #247).

``rig_https_local`` (and the two wrappers that run its ``main()``),
``rig_https_live`` and ``rig_https_bad_finished`` used to carve 387 B of
scratch out of whatever tail of a linked region was left — on the shipped
``uci-comb`` product that is the ~126 B CRYPTO_OVERLAY tail, so the rigs
died in ``MemoryArbiter.alloc`` before touching the device, and the fastest
product had no offline handshake rig at all. They now allocate from page 3
($0334-$03FF, ``_memory_policy.LOW_RAM_SCRATCH``), sized to what is
actually written.

No VICE, no hardware, no build: the labels file is a fixture carrying the
segment markers of a real ``BACKEND=uci USE_NISTCURVES_ONCHIP_COMB=1`` link
(PRG sha256 ``638529b5…`` at master ``eed451b``), plus the handful of
symbols the rigs look up. Each rig's ``main()`` is RUN against it, with
every device call faked, up to the DeviceLock — which is exactly where the
old allocation died. On the pre-fix rigs these tests fail with
``MemoryArbiterError``.

    python3 tools/test_rig_scratch.py
"""

from __future__ import annotations

import ast
import contextlib
import importlib
import io
import ssl
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
UCI = REPO / "tools" / "uci"
for p in (str(UCI), str(REPO / "tools")):
    if p not in sys.path:
        sys.path.insert(0, p)

import _memory_policy as mp  # noqa: E402

#: Segment markers from a real uci-comb link (see module docstring). The
#: CRYPTO_OVERLAY tail here is what the old allocation could not fit in.
COMB_SEGMENTS = """\
al C:0000 .__UCI_BSS_REGION_SIZE__
al C:001E .__ZP_CRYPTO_SIZE__
al C:0022 .__ZP_CRYPTO_LAST__
al C:0022 .__ZP_CRYPTO_START__
al C:0040 .__ZP_WIDE_LAST__
al C:0040 .__ZP_WIDE_SIZE__
al C:0040 .__ZP_WIDE_START__
al C:069A .__NET_BSS_TAIL_SIZE__
al C:0801 .__LOADER_START__
al C:17FF .__LOADER_SIZE__
al C:1B66 .__NET_CODE_SIZE__
al C:1E00 .__CRYPTO_OVERLAY_SIZE__
al C:1E00 .__OVERLAY_BLOB_CURVE_RAM_SIZE__
al C:1F75 .__LOADER_LAST__
al C:2000 .__CRYPTO_COLD_SHADOW_SIZE__
al C:2000 .__NET_CODE_START__
al C:2000 .__OVERLAY_FILE_PAD_SIZE__
al C:3AB6 .__NET_CODE_LAST__
al C:3B66 .__NET_BSS_TAIL_START__
al C:4000 .__CRYPTO_HOT_SIZE__
al C:4000 .__UCI_BSS_REGION_LAST__
al C:4000 .__UCI_BSS_REGION_START__
al C:41D5 .__NET_BSS_TAIL_LAST__
al C:4200 .__CRYPTO_OVERLAY_START__
al C:5F92 .__CRYPTO_OVERLAY_LAST__
al C:6000 .__CRYPTO_HOT_START__
al C:9FBC .__CRYPTO_HOT_LAST__
al C:A000 .__CRYPTO_COLD_SHADOW_START__
al C:C000 .__CRYPTO_COLD_SHADOW_LAST__
al C:C000 .__OVERLAY_FILE_PAD_LAST__
al C:C000 .__OVERLAY_FILE_PAD_START__
al C:E000 .__OVERLAY_BLOB_CURVE_RAM_LAST__
al C:E000 .__OVERLAY_BLOB_CURVE_RAM_START__
al C:0F5C .http_get
al C:A526 .http_host_ptr
al C:A528 .http_host_len
al C:A529 .http_path_ptr
al C:A52B .http_path_len
al C:4870 .http_port
al C:2000 .net_init
al C:A227 .net_initialized
al C:610C .uci_socket_id
al C:B3BF .net_last_error
al C:B3C0 .net_tcp_state
al C:A244 .tcp_recv_head
al C:A246 .tcp_recv_tail
al C:611B .uci_req_len
al C:6117 .uci_read_hdr
al C:A630 .http_resp_buf
al C:A830 .http_resp_len
al C:A52C .http_status
al C:A24D .tls_state
al C:A24E .tls_last_state
al C:A24F .tls_reached_connected
al C:0004 .LIB_NISTCURVES_REU_BANKS_USED
al C:9BEB .ec_precompute_256
"""


class _AtLock(Exception):
    """main() reached the DeviceLock: every allocation before it succeeded."""


def _declared_regions(labels: Path):
    return mp._parse_segment_bounds(labels)


def _run_to_lock(modname: str):
    """Run a rig's main() on the comb fixture up to acquire_device_lock.

    -> (reached_lock: bool, allocations, error text)
    """
    mod = importlib.import_module(modname)
    arbiters: list = []
    saved = {}

    def patch(name, value):
        if hasattr(mod, name) and name not in saved:
            saved[name] = getattr(mod, name)
            setattr(mod, name, value)

    def record(fn):
        def wrapped(*a, **k):
            policy, arb = fn(*a, **k)
            arbiters.append(arb)
            return policy, arb
        return wrapped

    def at_lock(lock, **k):
        raise _AtLock

    orig_bind = getattr(mod, "_try_bind", None)
    out = io.StringIO()
    reached, err = False, ""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        labels = tmp / "labels.txt"
        labels.write_text(COMB_SEGMENTS)
        prg = tmp / "c64-https.prg"
        prg.write_bytes(b"\x01\x08" + bytes(64))
        for name in list(vars(mod)):
            if name.startswith("build_policy_and_"):
                patch(name, record(getattr(mod, name)))
        patch("PRG_PATH", prg)
        patch("LABELS_PATH", labels)
        patch("acquire_device_lock", at_lock)
        patch("enforce_sni_precondition", lambda *a, **k: None)
        patch("_ensure_certs_or_fail", lambda: 0)
        patch("_ensure_certs_p256", lambda: ("cert.pem", "key.pem"))
        patch("_detect_local_ip", lambda h: "127.0.0.1")
        patch("_make_ssl_context",
              lambda: ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))
        patch("ACCEPT_TIMEOUT", 0.2)
        if orig_bind is not None:
            patch("_try_bind", lambda ip, port: orig_bind("127.0.0.1", 0))
        try:
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(out):
                mod.main()
        except _AtLock:
            reached = True
        except Exception as exc:                          # noqa: BLE001
            err = f"{type(exc).__name__}: {exc}"
        finally:
            for k, v in saved.items():
                setattr(mod, k, v)
        regions = _declared_regions(labels)
    allocs = [a for arb in arbiters for a in arb.allocations]
    return reached, allocs, err or out.getvalue()[-600:], regions


def _assert_rig_fits_on_comb(modname: str) -> None:
    reached, allocs, err, regions = _run_to_lock(modname)
    assert reached, (f"{modname} could not allocate its scratch on the "
                     f"uci-comb layout (#209): {err}")
    lo, hi = mp.LOW_RAM_SCRATCH
    assert allocs, "no allocation was made"
    for start, last, name in allocs:
        assert lo <= start <= last <= hi, (
            f"{name} ${start:04X}-${last:04X} is outside page-3 scratch "
            f"${lo:04X}-${hi:04X}; it moves with the link again")
        for rname, (rs, re_) in regions.items():
            if rname in mp._SKIP_REGIONS:
                continue
            assert last < rs or start >= re_, (
                f"{name} overlaps declared region {rname}")
    spans = sorted((s, l) for s, l, _ in allocs)
    for (s1, l1), (s2, _) in zip(spans, spans[1:]):
        assert l1 < s2, "allocations overlap"
    names = {n for *_, n in allocs}
    assert any("sentinel" in n for n in names), names


def test_local_rig_allocates_on_comb() -> None:
    _assert_rig_fits_on_comb("rig_https_local")


def test_live_rig_allocates_on_comb() -> None:
    _assert_rig_fits_on_comb("rig_https_live")


def test_bad_finished_rig_allocates_on_comb() -> None:
    _assert_rig_fits_on_comb("rig_https_bad_finished")


def test_the_old_carveout_really_cannot_hold_it() -> None:
    """The fixture reproduces #209: 387 B does not fit the comb tail."""
    with tempfile.TemporaryDirectory() as td:
        labels = Path(td) / "labels.txt"
        labels.write_text(COMB_SEGMENTS)
        _, arb = mp.build_policy_and_arbiter_with_overlay_carveout(
            labels, labels)
        try:
            arb.alloc(256, name="trampoline")
        except Exception as exc:                          # noqa: BLE001
            assert "no free range" in str(exc), exc
        else:
            raise AssertionError("the comb fixture no longer reproduces #209 "
                                 "— the tests above prove nothing on it")


def test_markers_are_one_contiguous_allocation() -> None:
    """The poll reads sentinel+progress as one 2-byte blob; separate allocs
    were only adjacent by first-fit luck. And the clear writes exactly 3."""
    for f in ("rig_https_local.py", "rig_https_live.py",
              "rig_https_bad_finished.py"):
        src = (UCI / f).read_text()
        assert 'arbiter.alloc(3, name="sentinel+progress+carry")' in src, f
        assert "bytes(16)" not in src, (
            f"{f} still clears 16 bytes at the sentinel — 13 past its "
            "3-byte allocation")


def test_unaudited_harness_page3_writer_refuses_the_window() -> None:
    from c64_test_harness.memory_policy import ScratchRegion
    saved = mp.HARNESS_SCRATCH
    mp.HARNESS_SCRATCH = saved + (ScratchRegion(
        0x0350, 0x0360, owner="some.new_helper", purpose="test"),)
    try:
        with tempfile.TemporaryDirectory() as td:
            labels = Path(td) / "labels.txt"
            labels.write_text(COMB_SEGMENTS)
            try:
                mp.build_policy_and_low_ram_arbiter(labels, labels)
            except RuntimeError as exc:
                assert "some.new_helper" in str(exc)
            else:
                raise AssertionError("an unaudited page-3 writer was "
                                     "silently overridden")
    finally:
        mp.HARNESS_SCRATCH = saved


def test_the_window_is_page_three() -> None:
    """$0334 is the first byte above the KERNAL vectors; $0400 is screen
    RAM. Widening either end is a decision, not a tweak."""
    assert mp.LOW_RAM_SCRATCH == (0x0334, 0x03FF), mp.LOW_RAM_SCRATCH


def _fixture_labels() -> dict[str, int]:
    out = {}
    for line in COMB_SEGMENTS.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2].startswith("."):
            out[parts[2][1:]] = int(parts[1].split(":")[1], 16)
    return out


def test_each_rig_fits_routine_and_data_in_the_window() -> None:
    """Routine + host + path + the 3 marker bytes, per rig, <= the window.
    Every operand is absolute, so the routine's length is address-free."""
    lo, hi = mp.LOW_RAM_SCRATCH
    window = hi - lo + 1
    labels = _fixture_labels()
    sizes = {}
    for name in ("rig_https_local", "rig_https_bad_finished"):
        mod = importlib.import_module(name)
        code = mod._build_http_routine(labels, 443)[0]
        sizes[name] = (len(code) + mod.HOST_STR_BYTES + mod.PATH_STR_BYTES
                       + 3)
    live = importlib.import_module("rig_https_live")
    code = live.build_live_routine(
        labels, routine_addr=0, host_str_addr=0, path_str_addr=0,
        sentinel_addr=0, progress_addr=1, carry_flag_addr=2, host_len=10,
        port=443)
    sizes["rig_https_live"] = (len(code) + live.HOST_STR_BYTES
                               + live.PATH_STR_BYTES + 3)
    over = {n: v for n, v in sizes.items() if v > window}
    assert not over, f"over the {window} B window: {over}"


def test_no_rig_calls_the_page3_harness_writers() -> None:
    """The audit behind LOW_RAM_HARNESS_WRITERS_UNUSED, kept true."""
    names = {"jsr", "run_subroutine", "play_sid_vice", "liveness_probe",
             "probe_u64"}
    bad = []
    for p in sorted(UCI.glob("*.py")):
        tree = ast.parse(p.read_text())
        # A script's own helper of the same name (rig_close_retry's
        # opcode-emitting `jsr`) is not the harness routine.
        local = {n.name for n in ast.walk(tree)
                 if isinstance(n, ast.FunctionDef)}
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                f = n.func
                fn = f.id if isinstance(f, ast.Name) else getattr(f, "attr", "")
                if fn in names and not (isinstance(f, ast.Name)
                                        and fn in local):
                    bad.append(f"{p.name}:{n.lineno} {fn}()")
    assert not bad, ("a tools/uci script calls a harness routine that writes "
                     f"page 3, the rigs' scratch window: {bad}")


def main() -> int:
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failed += 1
            print(f"  FAIL  {name}: {exc}")
        except Exception as exc:                              # noqa: BLE001
            failed += 1
            print(f"  ERROR {name}: {type(exc).__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    from _skip_policy import verdict
    return verdict(len(tests) - failed, failed,
                   certifies="the UCI rigs' page-3 scratch (#209)")


if __name__ == "__main__":
    sys.exit(main())
