#!/usr/bin/env python3
"""Guard the trust rigs' use of the harness storage API (#155; harness #526).

tools/uci/rig_trust_store.py and rig_trust_policy.py keep TRUST.A / TRUST.B
on the device's removable volume. They used to do it over a private
``ftplib`` session, and swept ``/Temp`` with a private GC
(``tools/uci/_temp_gc.py``). Both are now c64-test-harness's job: the
storage helpers (``storage_*``, which demand the DeviceLock and never write
``/Temp`` or ``/Flash``), and the automatic ``/Temp`` hygiene of any
``Ultimate64Client`` on a leak-prone device while the lock is held.

Nothing here touches hardware, VICE or a build: the storage calls, the
DeviceLock and the ``Ultimate64Client`` are faked. Pinned:

1. **Volume selection** (``_trust_storage.select_store_dir``): only a
   volume the device lists, minus ``WRITE_REFUSED_VOLUMES`` compared
   casefolded (the device says ``Flash``, the set holds ``flash``); an
   explicit ``TRUST_STORE_DIR`` must match the image; only
   ``/<vol>/c64https-test``.
2. **No writable volume is "could not run", not a crash.** A C64U with no
   medium lists ``['Flash', 'Temp']``; a stick pulled mid-setup raises
   ``Ultimate64StorageVolumeError``. Both rigs must exit 2, name the
   volumes the device does have, print no traceback, and never build an
   ``Ultimate64Client`` (nothing on the device is touched).
3. **No zero-byte trust file is ever written.**
4. **No private FTP, no private /Temp GC**: neither trust rig imports
   ``ftplib`` or ``_temp_gc``, no rig imports ``_temp_gc``, and the module
   is gone.

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

from c64_test_harness import Ultimate64StorageVolumeError  # noqa: E402

C64U_VOLUMES = ["Flash", "Temp"]
U64E_VOLUMES = ["Flash", "Temp", "USB1"]
IMAGE_PATH = "/USB1/c64https-test/TRUST."


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


class _Calls:
    """Fake storage_* functions that record what they were asked."""

    def __init__(self, volumes, *, mkdir_raises=None):
        self.volumes = list(volumes)
        self.mkdir_raises = mkdir_raises
        self.log = []

    def storage_volumes(self, host, **kw):
        self.log.append(("volumes", host))
        return list(self.volumes)

    def storage_mkdir(self, host, path, **kw):
        self.log.append(("mkdir", path))
        if self.mkdir_raises is not None:
            raise self.mkdir_raises
        return True

    def storage_put_file(self, host, path, data, **kw):
        self.log.append(("put", path, bytes(data), kw))

    def storage_get_file(self, host, path, **kw):
        self.log.append(("get", path))
        raise FileNotFoundError(path)

    def storage_delete_file(self, host, path, **kw):
        self.log.append(("delete", path, kw))
        return False

    def install(self):
        m = _storage()
        return _patched(m, **{n: getattr(self, n) for n in (
            "storage_volumes", "storage_mkdir", "storage_put_file",
            "storage_get_file", "storage_delete_file")})


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
    with calls.install():
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
    assert got == "/USB1/c64https-test", got
    assert ("volumes", "dev") in calls.log


def test_uses_the_devices_spelling_of_the_volume() -> None:
    got, _ = _select(U64E_VOLUMES, image="/usb1/c64https-test/TRUST.")
    assert got == "/USB1/c64https-test", got


def test_refused_volumes_are_filtered_casefolded() -> None:
    m = _storage()
    assert m.writable_volumes(["Flash", "Temp", "USB1", "SD"]) == ["USB1", "SD"]
    assert m.writable_volumes(C64U_VOLUMES) == []


def test_no_writable_volume_names_what_exists() -> None:
    exc = _unavailable(C64U_VOLUMES)
    assert exc.available == C64U_VOLUMES
    assert "/Flash" in str(exc) and "/Temp" in str(exc), str(exc)


def test_image_volume_absent_suggests_a_writable_one() -> None:
    exc = _unavailable(["Flash", "SD", "Temp"])
    assert "TRUST_STORE_DIR=/SD/c64https-test" in str(exc), str(exc)


def test_explicit_dir_is_preferred_and_validated() -> None:
    got, _ = _select(U64E_VOLUMES, explicit="/USB1/c64https-test")
    assert got == "/USB1/c64https-test"
    exc = _unavailable(["Flash", "Temp", "USB1", "USB2"], explicit="/USB2/c64https-test")
    assert "rebuild with TRUST_STORE_DIR=/USB2/c64https-test" in str(exc), str(exc)
    _unavailable(U64E_VOLUMES, explicit="/USB1/real-store")


def test_refused_volume_never_lists() -> None:
    m = _storage()
    calls = _Calls(U64E_VOLUMES)
    with calls.install():
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


# --- 3. zero-byte refusal -----------------------------------------------------------

def test_zero_byte_trust_file_is_refused() -> None:
    m = _storage()
    calls = _Calls(U64E_VOLUMES)
    files = m.TrustFiles("dev", "/USB1/c64https-test")
    with calls.install():
        for empty in (b"", bytearray()):
            try:
                files.put(files.a, empty)
            except ValueError as exc:
                assert "zero-byte" in str(exc), str(exc)
            else:
                raise AssertionError("a zero-byte trust file was written")
        files.put(files.b, b"C6TS\x01")
    puts = [c for c in calls.log if c[0] == "put"]
    assert len(puts) == 1 and puts[0][1] == files.b and puts[0][3].get("overwrite") is True, puts


def test_delete_is_limited_to_our_two_names() -> None:
    m = _storage()
    calls = _Calls(U64E_VOLUMES)
    files = m.TrustFiles("dev", "/USB1/c64https-test")
    with calls.install():
        files.delete_ours()
        try:
            files.delete("TRUST.P")
        except ValueError:
            pass
        else:
            raise AssertionError("deleted a file that is not the rig's")
    assert [c[1] for c in calls.log] == ["/USB1/c64https-test/TRUST.A",
                                        "/USB1/c64https-test/TRUST.B"], calls.log
    assert all(c[2].get("missing_ok") for c in calls.log)


# --- 2. the rigs exit 2 cleanly -------------------------------------------------------

class _FakeLock:
    instances: list = []

    def __init__(self, host, *a, **kw):
        self.host, self.released = host, False
        _FakeLock.instances.append(self)

    def release(self):
        self.released = True


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


def _run_main(rig_name, calls):
    rig = _load_rig(rig_name)
    tmp = Path(tempfile.mkdtemp(prefix="trust_rig_ut_"))
    prg = tmp / "c64-https.prg"
    prg.write_bytes(b"\x01\x08dev.example\x00" + b"\x00" * 64)
    labels_path = tmp / "labels.txt"
    labels_path.write_text("")
    _FakeLock.instances = []
    patches = dict(
        PRG_PATH=prg, LABELS_PATH=labels_path, load_labels=lambda: _labels(rig),
        image_store_path=lambda prg, L: IMAGE_PATH, DeviceLock=_FakeLock,
        acquire_device_lock=lambda lock: None, Ultimate64Client=_no_client,
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
    with contextlib.ExitStack() as st:
        st.enter_context(_patched(rig, **{k: v for k, v in patches.items()}))
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
    return rc, exc, out.getvalue() + err.getvalue()


def _assert_clean_exit_2(rig_name, calls, *, names):
    rc, exc, text = _run_main(rig_name, calls)
    assert exc is None, f"{rig_name}: main() raised {type(exc).__name__}: {exc}\n{text}"
    assert rc == 2, f"{rig_name}: exit {rc}, want 2\n{text}"
    assert "Traceback" not in text, text
    for n in names:
        assert n in text, f"{rig_name}: output does not name {n}\n{text}"
    assert _FakeLock.instances and all(lk.released for lk in _FakeLock.instances), \
        f"{rig_name}: the DeviceLock was not released"


def test_store_rig_exits_2_with_no_writable_volume() -> None:
    _assert_clean_exit_2("rig_trust_store.py", _Calls(C64U_VOLUMES), names=("/Flash", "/Temp"))


def test_policy_rig_exits_2_with_no_writable_volume() -> None:
    _assert_clean_exit_2("rig_trust_policy.py", _Calls(C64U_VOLUMES), names=("/Flash", "/Temp"))


def _volume_error():
    return Ultimate64StorageVolumeError(
        "/USB1 is listed but cannot be entered on dev; usable volumes: /Flash, /Temp",
        ["Flash", "Temp"])


def test_store_rig_exits_2_on_volume_error() -> None:
    calls = _Calls(U64E_VOLUMES, mkdir_raises=_volume_error())
    _assert_clean_exit_2("rig_trust_store.py", calls, names=("/Flash", "/Temp"))


def test_policy_rig_exits_2_on_volume_error() -> None:
    calls = _Calls(U64E_VOLUMES, mkdir_raises=_volume_error())
    _assert_clean_exit_2("rig_trust_policy.py", calls, names=("/Flash", "/Temp"))


# --- 4. no private FTP, no private /Temp GC ------------------------------------------

def _imports(path: Path) -> set[str]:
    out = set()
    for node in ast.walk(ast.parse(path.read_text(), str(path))):
        if isinstance(node, ast.Import):
            out |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module.split(".")[0])
    return out


def test_trust_rigs_import_no_ftplib_and_no_temp_gc() -> None:
    for name in RIGS + ("_trust_storage.py",):
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
