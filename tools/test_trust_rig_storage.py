#!/usr/bin/env python3
"""Guard the trust rigs' use of the harness storage API (#155; harness #526, #527).

tools/uci/rig_trust_store.py and rig_trust_policy.py keep TRUST.A / TRUST.B
on the device's removable volume. They used to do it over a private
``ftplib`` session, and swept ``/Temp`` with a private GC
(``tools/uci/_temp_gc.py``). Both are now c64-test-harness's job: the
storage helpers (``storage_*``, which demand the DeviceLock and never write
``/Temp`` or ``/Flash``), and the automatic ``/Temp`` hygiene of any
``Ultimate64Client`` on a leak-prone device while the lock is held.

Nothing here touches hardware, VICE or a build: the storage calls, the
DeviceLock and the ``Ultimate64Client`` are faked. The fake storage calls
behave like the real ones on the one rule a fake can drop silently: they
refuse (``Ultimate64StorageError``) and record a violation unless the fake
DeviceLock is held. Pinned:

1. **Volume selection** (``_trust_storage.select_store_dir``): only a
   volume in ``storage_writable_volumes``; an explicit ``TRUST_STORE_DIR``
   must match the image; only ``/<vol>/c64https-test``.
2. **Exit codes.** No writable volume (a C64U with no medium) or an
   ``Ultimate64StorageVolumeError`` is COULD NOT RUN: exit 2, the volumes
   named, no traceback, no ``Ultimate64Client`` built. A directory holding
   anything but TRUST.A/B (listed, or TRUST.P probed by name) is exit 2
   too, and is left untouched. Any other storage error (FTP unreachable,
   lock not held) is a failure, exit 1, never "unavailable".
3. **Every storage call runs under the lock**, cleanup included; an error
   from a read is never swallowed as "file absent".
4. **No zero-byte trust file is ever written.**
5. **Cleanup removes the directory.** Leftovers found at SETUP predate the
   run (exit 2); found at phase 14 or cleanup they were written during it,
   by the program under test (setup proved the directory empty, the lock
   excludes other writers): exit 1, named, never forced.    forced.
6. **No private FTP, no private /Temp GC**: neither trust rig imports
   ``ftplib`` or ``_temp_gc``, nor does ``rig_https_m3_demo.py`` import
   ``ftplib``; no rig imports ``_temp_gc``, and the module is gone.

Runs under pytest, and standalone::

    python3 tools/test_trust_rig_storage.py
"""
from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
UCI = REPO / "tools" / "uci"
RIGS = ("rig_trust_store.py", "rig_trust_policy.py")
for p in (str(UCI), str(REPO / "tools")):
    if p not in sys.path:
        sys.path.insert(0, p)

from c64_test_harness import (  # noqa: E402
    StorageEntry,
    Ultimate64StorageError,
    Ultimate64StorageNotEmptyError,
    Ultimate64StorageVolumeError,
)

C64U_VOLUMES = ["Flash", "Temp"]
U64E_VOLUMES = ["Flash", "Temp", "USB1"]
IMAGE_PATH = "/USB1/c64https-test/TRUST."
DIR = "/USB1/c64https-test"
_LOCK = {"held": False}


def _storage():
    import _trust_storage  # noqa: PLC0415 - tools/uci is not a package
    return _trust_storage


@contextlib.contextmanager
def _patched(obj, **attrs):
    old = {k: getattr(obj, k) for k in attrs if hasattr(obj, k)}
    for k, v in attrs.items():
        setattr(obj, k, v)
    try:
        yield
    finally:
        for k in attrs:
            if k in old:
                setattr(obj, k, old[k])
            else:
                delattr(obj, k)


@contextlib.contextmanager
def _held():
    _LOCK["held"] = True
    try:
        yield
    finally:
        _LOCK["held"] = False


_FAKES = ("storage_volumes", "storage_writable_volumes", "storage_list_dir",
          "storage_mkdir", "storage_put_file", "storage_get_file",
          "storage_delete_file", "storage_rmdir")


class _Calls:
    """Fake storage_* functions. Each refuses unless the fake lock is held."""

    def __init__(self, volumes, *, listing=(), files=None, raises=None,
                 rmdir_raises=None, nth=None):
        self.volumes = list(volumes)
        self.listing = list(listing)            # visible names in DIR
        self.files = dict(files or {})          # path -> bytes, for gets
        self.raises = dict(raises or {})        # op -> exception
        self.rmdir_raises = rmdir_raises
        self.nth = dict(nth or {})              # op -> (n, exception): the nth call raises
        self.counts = {}
        self.log, self.violations = [], []

    def _op(self, op, *args):
        self.log.append((op, *args))
        if not _LOCK["held"]:
            self.violations.append(op)
            raise Ultimate64StorageError(f"refusing {op}: this process does not hold "
                                         "the device's DeviceLock (fake)")
        if op in self.raises:
            raise self.raises[op]
        self.counts[op] = self.counts.get(op, 0) + 1
        if op in self.nth and self.nth[op][0] == self.counts[op]:
            raise self.nth[op][1]

    def storage_volumes(self, host, **kw):
        self._op("volumes")
        return list(self.volumes)

    def storage_writable_volumes(self, host, **kw):
        self._op("writable")
        return [v for v in self.volumes if v.casefold() not in ("temp", "flash")]

    def storage_list_dir(self, host, path, **kw):
        self._op("list", path)
        return [StorageEntry(name=n, kind="file", size=1) for n in sorted(self.listing)]

    def storage_mkdir(self, host, path, **kw):
        self._op("mkdir", path)
        return True

    def storage_put_file(self, host, path, data, **kw):
        self._op("put", path, bytes(data), kw)

    def storage_get_file(self, host, path, **kw):
        self._op("get", path)
        if path in self.files:
            return self.files[path]
        raise FileNotFoundError(path)

    def storage_delete_file(self, host, path, **kw):
        self._op("delete", path, kw)
        return False

    def storage_rmdir(self, host, path, **kw):
        self._op("rmdir", path)
        if self.rmdir_raises is not None:
            raise self.rmdir_raises
        return True

    def ops(self, name):
        return [c for c in self.log if c[0] == name]

    def install(self):
        return _patched(_storage(), **{n: getattr(self, n) for n in _FAKES})


@contextlib.contextmanager
def _env(**kv):
    old = {k: os.environ.get(k) for k in kv}
    for k, v in kv.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# --- 1. volume selection ----------------------------------------------------------

def _select(volumes, image=IMAGE_PATH, explicit=None):
    calls = _Calls(volumes)
    with calls.install(), _held():
        return _storage().select_store_dir("dev", image, explicit), calls


def _unavailable(volumes, image=IMAGE_PATH, explicit=None):
    m = _storage()
    try:
        got, _ = _select(volumes, image, explicit)
    except m.StoreUnavailable as exc:
        return exc
    raise AssertionError(f"expected StoreUnavailable, got {got!r}")


def test_selects_the_images_writable_volume() -> None:
    got, calls = _select(U64E_VOLUMES)
    assert got == DIR, got
    assert calls.ops("writable"), "storage_writable_volumes was not asked"


def test_uses_the_devices_spelling_of_the_volume() -> None:
    got, _ = _select(U64E_VOLUMES, image="/usb1/c64https-test/TRUST.")
    assert got == DIR, got


def test_writable_set_comes_from_the_harness() -> None:
    """A volume storage_writable_volumes leaves out is never chosen, even
    when storage_volumes lists it."""
    m = _storage()
    calls = _Calls(U64E_VOLUMES)
    calls.storage_writable_volumes = lambda host, **kw: (calls._op("writable"), [])[1]
    with calls.install(), _held():
        try:
            m.select_store_dir("dev", IMAGE_PATH)
        except m.StoreUnavailable:
            return
    raise AssertionError("chose a volume storage_writable_volumes did not offer")


def test_no_writable_volume_names_what_exists() -> None:
    exc = _unavailable(C64U_VOLUMES)
    assert exc.available == C64U_VOLUMES
    assert "/Flash" in str(exc) and "/Temp" in str(exc), str(exc)


def test_image_volume_absent_suggests_a_writable_one() -> None:
    exc = _unavailable(["Flash", "SD", "Temp"])
    assert "TRUST_STORE_DIR=/SD/c64https-test" in str(exc), str(exc)


def test_explicit_dir_is_preferred_and_validated() -> None:
    got, _ = _select(U64E_VOLUMES, explicit=DIR)
    assert got == DIR
    exc = _unavailable(["Flash", "Temp", "USB1", "USB2"], explicit="/USB2/c64https-test")
    assert "rebuild with TRUST_STORE_DIR=/USB2/c64https-test" in str(exc), str(exc)
    _unavailable(U64E_VOLUMES, explicit="/USB1/real-store")


def test_refused_volume_never_lists() -> None:
    m = _storage()
    calls = _Calls(U64E_VOLUMES)
    with calls.install(), _held():
        for image in ("/Temp/c64https-test/TRUST.", "/flash/c64https-test/TRUST."):
            try:
                m.select_store_dir("dev", image)
            except m.StoreUnavailable:
                pass
            else:
                raise AssertionError(f"{image} accepted")
    assert calls.log == [], calls.log


def test_only_the_dedicated_test_directory() -> None:
    for image in ("/USB1/TRUST.", "/USB1/store/TRUST.", "/USB1/a/c64https-test/TRUST.",
                  "/USB1/c64https-test/TRUST.P"):
        _unavailable(U64E_VOLUMES, image=image)


# --- 3/4/5. TrustFiles ----------------------------------------------------------------

def test_zero_byte_trust_file_is_refused() -> None:
    m = _storage()
    calls = _Calls(U64E_VOLUMES)
    files = m.TrustFiles("dev", DIR)
    with calls.install(), _held():
        for empty in (b"", bytearray()):
            try:
                files.put(files.a, empty)
            except ValueError as exc:
                assert "zero-byte" in str(exc), str(exc)
            else:
                raise AssertionError("a zero-byte trust file was written")
        files.put(files.b, b"C6TS\x01")
    puts = calls.ops("put")
    assert len(puts) == 1 and puts[0][1] == files.b and puts[0][3].get("overwrite") is True, puts


def test_delete_is_limited_to_our_two_names() -> None:
    m = _storage()
    calls = _Calls(U64E_VOLUMES)
    files = m.TrustFiles("dev", DIR)
    with calls.install(), _held():
        files.delete_ours()
        try:
            files.delete("TRUST.P")
        except ValueError:
            pass
        else:
            raise AssertionError("deleted a file that is not the rig's")
    assert [c[1] for c in calls.log] == [f"{DIR}/TRUST.A", f"{DIR}/TRUST.B"], calls.log
    assert all(c[2].get("missing_ok") for c in calls.log)


def test_a_read_error_is_not_file_absent() -> None:
    """Only FileNotFoundError means "absent": a lock refusal or an FTP
    failure from a read must propagate, not read as an empty slot."""
    m = _storage()
    files = m.TrustFiles("dev", DIR)
    calls = _Calls(U64E_VOLUMES)
    with calls.install():
        try:                                    # lock NOT held
            got = files.get(files.a)
        except Ultimate64StorageError:
            pass
        else:
            raise AssertionError(f"a lock refusal read as {got!r}")
    calls = _Calls(U64E_VOLUMES, raises={"get": Ultimate64StorageError("FTP dropped")})
    with calls.install(), _held():
        try:
            got = files.get(files.a)
        except Ultimate64StorageError:
            pass
        else:
            raise AssertionError(f"an FTP failure read as {got!r}")


def test_foreign_entries_are_refused() -> None:
    m = _storage()
    files = m.TrustFiles("dev", DIR)
    for calls, what in ((_Calls(U64E_VOLUMES, listing=["TRUST.A", "notes.txt"]), "notes.txt"),
                        (_Calls(U64E_VOLUMES, files={f"{DIR}/TRUST.P": b"x"}), "TRUST.P")):
        with calls.install(), _held():
            try:
                files.check_only_ours()
            except m.StoreUnavailable as exc:
                assert what in str(exc), str(exc)
            else:
                raise AssertionError(f"{what} in the directory was accepted")
    calls = _Calls(U64E_VOLUMES, listing=["TRUST.A", "TRUST.B"])
    with calls.install(), _held():
        files.check_only_ours()
    assert (("get", f"{DIR}/TRUST.P")) in calls.log, "TRUST.P was not probed by name"


def test_hidden_leftovers_are_reported_not_forced() -> None:
    m = _storage()
    files = m.TrustFiles("dev", DIR)
    calls = _Calls(U64E_VOLUMES, rmdir_raises=Ultimate64StorageNotEmptyError("550", []))
    with calls.install(), _held():
        try:
            files.remove_dir()
        except m.StoreLeftovers as exc:
            assert "hidden" in str(exc), str(exc)
        else:
            raise AssertionError("hidden leftovers did not raise StoreLeftovers")
    assert len(calls.ops("rmdir")) == 1 and not calls.ops("delete"), calls.log
    with _Calls(U64E_VOLUMES).install(), _held():
        assert files.remove_dir() is True


def test_final_exit_folds_cleanup() -> None:
    m = _storage()
    with contextlib.redirect_stdout(io.StringIO()):
        assert m.final_exit(0, (0, "")) == 0
        assert m.final_exit(0, (1, "x")) == 1
        assert m.final_exit(1, (1, "x")) == 1
        assert m.final_exit(2, (1, "x")) == 1


def test_setup_leftovers_say_they_predate_the_run() -> None:
    m = _storage()
    files = m.TrustFiles("dev", DIR)
    calls = _Calls(U64E_VOLUMES, rmdir_raises=Ultimate64StorageNotEmptyError("550", []))
    with calls.install(), _held():
        try:
            files.prepare()
        except m.StoreLeftovers as exc:
            assert "before this run" in str(exc), str(exc)
        else:
            raise AssertionError("prepare() accepted a directory it cannot remove")
    assert not calls.ops("mkdir"), calls.log


# --- phase 14 (rig_trust_store) and the CLOSED waits (rig_trust_policy), offline ----

class _NopathRig:
    """Just enough of rig_trust_store.Rig for phase_nopath."""

    def __init__(self, store_rig, ftp, calls, reason):
        self.ftp, self.calls, self.reason = ftp, calls, reason
        self.passed, self.failed, self.notes = 0, [], {}
        self.check = store_rig.Rig.check.__get__(self)
        self.require = store_rig.Rig.require.__get__(self)

    def load(self, host):
        self.calls.log.append(("c64-load", host))
        return 1, 3, {"reason": self.reason}


def _phase14(calls, reason=None):
    store_rig = _load_rig("rig_trust_store.py")
    import trust_store as ts  # noqa: PLC0415
    files = _storage().TrustFiles("dev", DIR)
    r = _NopathRig(store_rig, files, calls, ts.R_NOPATH if reason is None else reason)
    exc = None
    with calls.install(), _held(), contextlib.redirect_stdout(io.StringIO()):
        try:
            store_rig.phase_nopath(r)
        except Exception as e:  # noqa: BLE001
            exc = e
    return r, exc


def test_phase14_removes_loads_then_restores() -> None:
    calls = _Calls(U64E_VOLUMES)
    r, exc = _phase14(calls)
    assert exc is None and not r.failed and r.passed >= 2, (exc, r.failed)
    seq = [c[0] for c in calls.log]
    i_rm, i_load = seq.index("rmdir"), seq.index("c64-load")
    assert i_rm < i_load, seq
    assert "mkdir" in seq[i_load:], f"the directory was not put back after the load: {seq}"


def test_phase14_stops_when_the_directory_was_not_removed() -> None:
    calls = _Calls(U64E_VOLUMES)
    calls.storage_rmdir = lambda host, path, **kw: (calls._op("rmdir", path), False)[1]
    r, exc = _phase14(calls)
    assert exc is not None and r.failed, "phase 14 went on after rmdir removed nothing"
    assert "c64-load" not in [c[0] for c in calls.log], calls.log


def test_phase14_checks_the_reason() -> None:
    r, exc = _phase14(_Calls(U64E_VOLUMES), reason=0)
    assert r.failed and any("NOPATH" in f for f in r.failed), r.failed


def test_closed_wait_is_a_check() -> None:
    pol = _load_rig("rig_trust_policy.py")

    class R:
        def __init__(self, screen):
            self.screen, self.passed, self.failed = screen, 0, []

        def wait(self, marker, budget):
            return self.screen if marker == pol.CLOSED else None

        def check(self, cond, what):
            if cond:
                self.passed += 1
            else:
                self.failed.append(what)

    r = R(None)
    pol.await_closed(r, "match")
    assert r.failed == [f"match: {pol.CLOSED}"], r.failed
    r = R("... CONNECTION CLOSED")
    pol.await_closed(r, "match")
    assert not r.failed and r.passed == 1
    assert pol.CLOSED == "CONNECTION CLOSED"


def test_phases_use_the_checked_closed_wait() -> None:
    tree = ast.parse((UCI / "rig_trust_policy.py").read_text())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "phases_local")
    calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)]
    awaited = [c for c in calls if getattr(c.func, "id", None) == "await_closed"]
    assert len(awaited) >= 2, f"phases_local calls await_closed {len(awaited)} time(s), want 2"
    bare = [c for c in calls if getattr(c.func, "attr", None) == "wait" and c.args
            and isinstance(c.args[0], ast.Name) and c.args[0].id == "CLOSED"]
    assert not bare, "an unchecked run.wait(CLOSED) is back in phases_local"


# --- 2. the rigs' exit codes -----------------------------------------------------------

class _FakeLock:
    instances: list = []

    def __init__(self, host, *a, **kw):
        self.host, self.released = host, False
        _FakeLock.instances.append(self)

    def release(self):
        self.released = True
        _LOCK["held"] = False


def _acquire(lock):
    _LOCK["held"] = True


class _ClientBuilt(AssertionError):
    pass


def _no_client(*a, **kw):
    raise _ClientBuilt("an Ultimate64Client was built: the device would be touched")


def _no_network(*a, **kw):
    raise OSError("test: real FTP attempted")


class _Arbiter:
    def __init__(self):
        self.next = 0x0334

    def alloc(self, n, name=""):
        a, self.next = self.next, self.next + n
        return a


def _load_rig(name):
    spec = importlib.util.spec_from_file_location(f"_ut_{name[:-3]}", UCI / name)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _labels(rig):
    names = set(getattr(rig, "NEEDED", ()))
    names |= {"trust_pre", "trust_post", "tp_mode", "net_tcp_state", "tls_state",
              "tls_reached_connected", "ts_name", "http_host_target", "ts_letter"}
    labels = {n: 0x6000 + i for i, n in enumerate(sorted(names))}
    labels["http_host_target"] = 0x0801
    return labels


class _FakeClient:
    def __init__(self, calls):
        self.calls = calls

    def reset(self):
        self.calls.log.append(("reset",))

    def get_info(self):
        return {}

    def send_text(self, *a, **kw):
        pass

    def read_mem(self, addr, n):
        return bytes(n)

    def write_mem(self, *a, **kw):
        pass


class _FakeTransport:
    def __init__(self, **kw):
        self.memory_policy = None


class _FakeRun:
    def __init__(self, client, L):
        self.passed, self.failed, self.notes = 0, [], {}

    def wait(self, *a, **kw):
        return "screen"

    def check(self, cond, what):
        if cond:
            self.passed += 1
        else:
            self.failed.append(what)

    def settled(self, *a):
        return True

    def r8(self, name):
        return 0


def _full_run_patches(rig, calls):
    """Let main() run to the end with no device: every device step faked,
    the phases reduced to one passing check."""
    noop = lambda *a, **kw: None                            # noqa: E731
    p = dict(Ultimate64Client=lambda **kw: _FakeClient(calls), enable_uci=noop,
             disable_uci=noop, prepare_device=noop, preflight_reu=noop,
             load_verified_and_run=noop)
    if hasattr(rig, "Ultimate64Transport"):
        p["Ultimate64Transport"] = _FakeTransport
    if hasattr(rig, "run_phases"):
        p["run_phases"] = lambda r: r.check(True, "fake phase")
    if hasattr(rig, "phases_local"):
        p.update(Run=_FakeRun, guard_socket_teardown=noop,
                 phases_local=lambda run, *a: run.check(True, "fake phase"))
    return p


def _run_main(rig_name, calls, *, full=False, extra=None):
    rig = _load_rig(rig_name)
    tmp = Path(tempfile.mkdtemp(prefix="trust_rig_ut_"))
    prg = tmp / "c64-https.prg"
    prg.write_bytes(b"\x01\x08dev.example\x00" + b"\x00" * 64)
    labels_path = tmp / "labels.txt"
    labels_path.write_text("")
    _FakeLock.instances = []
    _LOCK["held"] = False
    patches = dict(
        PRG_PATH=prg, LABELS_PATH=labels_path, load_labels=lambda: _labels(rig),
        image_store_path=lambda prg, L: IMAGE_PATH, DeviceLock=_FakeLock,
        acquire_device_lock=_acquire, Ultimate64Client=_no_client,
        build_policy_and_low_ram_arbiter=lambda *a: (None, _Arbiter()),
        REPO=tmp,
    )
    # Master's rigs: keep a regression from reaching a real device.
    for legacy in ("FTP", "gc_temp"):
        if hasattr(rig, legacy):
            patches[legacy] = _no_network
    peers = [sys.modules[n] for n in ("rig_trust_store",) if n in sys.modules]
    out, err = io.StringIO(), io.StringIO()
    rc = exc = None
    if full:
        patches.update(_full_run_patches(rig, calls))
    patches.update(extra or {})
    with contextlib.ExitStack() as st:
        st.enter_context(_patched(rig, **patches))
        if full and hasattr(rig, "Rig"):
            st.enter_context(_patched(rig.Rig, boot=lambda self: None))
        for peer in peers:
            if hasattr(peer, "FTP"):
                st.enter_context(_patched(peer, FTP=_no_network))
        st.enter_context(calls.install())
        st.enter_context(_env(TRUST_STORE_DIR=None, RIG_MODE=None))
        st.enter_context(contextlib.redirect_stdout(out))
        st.enter_context(contextlib.redirect_stderr(err))
        try:
            rc = rig.main()
        except BaseException as e:  # noqa: BLE001 - a raise is the failure
            exc = e
    _LOCK["held"] = False
    return rc, exc, out.getvalue() + err.getvalue()


def _check_lock(rig_name, calls, text):
    assert not calls.violations, \
        f"{rig_name}: storage called without the DeviceLock: {calls.violations}\n{text}"
    assert _FakeLock.instances and all(lk.released for lk in _FakeLock.instances), \
        f"{rig_name}: the DeviceLock was not released"


def _assert_exit(rig_name, calls, want, *, names=(), absent=()):
    rc, exc, text = _run_main(rig_name, calls)
    assert exc is None, f"{rig_name}: main() raised {type(exc).__name__}: {exc}\n{text}"
    assert rc == want, f"{rig_name}: exit {rc}, want {want}\n{text}"
    assert "Traceback" not in text, text
    for n in names:
        assert n in text, f"{rig_name}: output does not name {n}\n{text}"
    for n in absent:
        assert n not in text, f"{rig_name}: output says {n!r}\n{text}"
    _check_lock(rig_name, calls, text)
    return text


def _volume_error():
    return Ultimate64StorageVolumeError(
        "/USB1 is listed but cannot be entered on dev; usable volumes: /Flash, /Temp",
        ["Flash", "Temp"])


def _both(fn):
    for rig_name in RIGS:
        fn(rig_name)


def test_rigs_exit_2_with_no_writable_volume() -> None:
    _both(lambda r: _assert_exit(r, _Calls(C64U_VOLUMES), 2, names=("/Flash", "/Temp")))


def test_rigs_exit_2_on_volume_error() -> None:
    _both(lambda r: _assert_exit(r, _Calls(U64E_VOLUMES, raises={"mkdir": _volume_error()}),
                                 2, names=("/Flash", "/Temp")))


def test_rigs_exit_2_on_foreign_files_and_touch_nothing() -> None:
    def one(r):
        calls = _Calls(U64E_VOLUMES, listing=["TRUST.A", "keep.me"])
        _assert_exit(r, calls, 2, names=("keep.me",))
        touched = [c for c in calls.log if c[0] in ("delete", "rmdir", "put", "mkdir")]
        assert not touched, f"{r}: touched a foreign directory: {touched}"
    _both(one)


def test_rigs_fail_not_skip_on_other_storage_errors() -> None:
    """FTP unreachable is a failure (exit 1), not 'no usable volume'."""
    _both(lambda r: _assert_exit(
        r, _Calls(U64E_VOLUMES, raises={"writable": Ultimate64StorageError("cannot reach FTP")}),
        1, names=("cannot reach FTP",), absent=("COULD NOT RUN", "unavailable")))


def test_rigs_exit_2_on_hidden_leftovers_before_touching_the_device() -> None:
    _both(lambda r: _assert_exit(
        r, _Calls(U64E_VOLUMES, rmdir_raises=Ultimate64StorageNotEmptyError("550", [])),
        2, names=("hidden",)))


def _full(rig_name, calls, **extra):
    rc, exc, text = _run_main(rig_name, calls, full=True, extra=extra)
    assert exc is None, f"{rig_name}: main() raised {type(exc).__name__}: {exc}\n{text}"
    assert "Traceback" not in text, text
    _check_lock(rig_name, calls, text)
    return rc, text


def test_rigs_full_offline_run_passes_and_removes_the_directory() -> None:
    def one(r):
        calls = _Calls(U64E_VOLUMES)
        rc, text = _full(r, calls)
        assert rc == 0, f"{r}: exit {rc}\n{text}"
        assert len(calls.ops("rmdir")) == 2, f"{r}: setup + cleanup rmdir: {calls.log}"
    _both(one)


def test_rigs_cleanup_failure_is_not_exit_0() -> None:
    def one(r):
        calls = _Calls(U64E_VOLUMES, nth={"rmdir": (2, Ultimate64StorageError("FTP dropped"))})
        rc, text = _full(r, calls)
        assert rc == 1, f"{r}: a failed cleanup rmdir exited {rc}\n{text}"
        calls = _Calls(U64E_VOLUMES, nth={"delete": (3, Ultimate64StorageError("FTP dropped"))})
        rc, text = _full(r, calls)
        assert rc == 1, f"{r}: a failed cleanup delete exited {rc}\n{text}"
    _both(one)


def test_rigs_cleanup_leftovers_are_a_failure() -> None:
    """A stray TRUST.C (visible) or hidden entry at cleanup was written
    during the run: exit 1, named -- not COULD NOT RUN."""
    def one(r):
        for entries, name in ((["TRUST.C"], "TRUST.C"), ([], "hidden")):
            err = Ultimate64StorageNotEmptyError("not empty", entries)
            calls = _Calls(U64E_VOLUMES, nth={"rmdir": (2, err)})
            rc, text = _full(r, calls)
            assert rc == 1 and name in text and "DURING the run" in text, \
                f"{r}: leftovers {entries} exited {rc}\n{text}"
            assert "COULD NOT RUN" not in text, text
    _both(one)


def test_store_rig_phase14_leftovers_are_a_failure() -> None:
    calls = _Calls(U64E_VOLUMES,
                   rmdir_raises=Ultimate64StorageNotEmptyError("not empty", ["TRUST.C"]))
    r, exc = _phase14(calls)
    assert exc is not None and any("TRUST.C" in f and "DURING the run" in f for f in r.failed), \
        (exc, r.failed)
    assert "c64-load" not in [c[0] for c in calls.log], calls.log


def test_store_rig_resets_before_cleanup() -> None:
    calls = _Calls(U64E_VOLUMES)
    rc, text = _full("rig_trust_store.py", calls)
    seq = [c[0] for c in calls.log]
    resets = [i for i, op in enumerate(seq) if op == "reset"]
    first_cleanup = seq.index("delete", seq.index("mkdir"))
    assert resets and resets[-1] < first_cleanup, f"cleanup ran before the C64 was reset: {seq}"


def test_rigs_clean_up_under_the_lock() -> None:
    """Past setup, any end of the run deletes TRUST.A/B and removes the
    directory, and every one of those calls happens before the lock is
    released."""
    def one(r):
        calls = _Calls(U64E_VOLUMES)
        rc, exc, text = _run_main(r, calls)
        assert isinstance(exc, _ClientBuilt), f"{r}: {rc} {exc!r}\n{text}"
        _check_lock(r, calls, text)
        assert calls.ops("rmdir"), f"{r}: the test directory was not removed\n{text}"
        assert len(calls.ops("delete")) >= 4, f"{r}: cleanup deletes missing: {calls.log}"
    _both(one)


# --- 6. no private FTP, no private /Temp GC ------------------------------------------

def _imports(path: Path) -> set[str]:
    out = set()
    for node in ast.walk(ast.parse(path.read_text(), str(path))):
        if isinstance(node, ast.Import):
            out |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module.split(".")[0])
    return out


def test_rigs_import_no_ftplib_and_no_temp_gc() -> None:
    for name in RIGS + ("_trust_storage.py", "rig_https_m3_demo.py"):
        bad = _imports(UCI / name) & {"ftplib", "_temp_gc"}
        assert not bad, f"{name} imports {sorted(bad)}"


def test_no_rig_imports_the_retired_temp_gc() -> None:
    assert not (UCI / "_temp_gc.py").exists(), "tools/uci/_temp_gc.py still exists"
    offenders = [str(p.relative_to(REPO)) for d in (UCI, REPO / "tools", REPO / "tests")
                 for p in sorted(d.glob("*.py")) if "_temp_gc" in _imports(p)]
    assert not offenders, f"still import _temp_gc: {offenders}"


def _main(tests=None) -> int:
    """Run every case without pytest; any exception is that case's failure."""
    if tests is None:
        tests = {n: f for n, f in globals().items()
                 if n.startswith("test_") and callable(f)}
    failures = 0
    for name, fn in sorted(tests.items()):
        try:
            fn()
        except AssertionError as exc:
            failures += 1
            print(f"FAIL {name}: {str(exc).splitlines()[0] if str(exc) else ''}")
        except Exception as exc:      # noqa: BLE001 - a raise is a result
            failures += 1
            print(f"ERROR {name}: {type(exc).__name__}: {exc}")
        else:
            print(f"ok   {name}")
    print("FAILED" if failures else "PASS")
    from _skip_policy import verdict
    return verdict(len(tests) - failures, failures,
                   certifies="the trust rigs' storage-API use")


if __name__ == "__main__":
    sys.exit(_main())
