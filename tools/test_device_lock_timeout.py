#!/usr/bin/env python3
"""Guard the shared device-lock acquire budget (tools/uci/_device_lock_helper.py).

Nothing here touches hardware, VICE, the network or a build. The
``DeviceLock`` is faked, so this is pure logic and runs in milliseconds —
the same shape as ``tools/test_reu_preflight.py``, and for the same
reason: the thing being guarded protects a *hardware* run, and its only
failure mode is to stop guarding, which no hardware run can observe.

Why this exists
---------------
Every rig used to hardcode its own acquire timeout (120 s in four HTTPS
rigs and the RR-Net rig, 60 s in five more, 300 s in one) with no way to
raise it from the environment. That is survivable only because the
harness's ``acquire`` is queue-aware: behind one live, progressing holder
the deadline is re-armed indefinitely and ``timeout`` is never consulted.
It stops being survivable the moment the harness *stops* extending —
after the **fourth** change of holder identity, or against a holder whose
heartbeat has died — at which point the hardcoded number is the entire
budget and a rig queued behind a live device fails while the device is
merely busy. (Four, not the three the harness's docstring implies:
``_MAX_HOLDER_HANDOFFS`` is 3 but extension survives ``handoffs <= 3``.
Measured with a scripted identity sequence: 0/1/2/3 changes still waited
indefinitely, 4 and 5 returned False at ``timeout``.)

Both halves are pinned here:

1. **The budget is one number, read from the environment.**
   ``C64_DEVICE_LOCK_TIMEOUT`` reaches ``DeviceLock.acquire``; unset
   yields the documented default; a malformed value is fatal, never a
   silent fallback to a budget nobody asked for.

2. **Nothing keeps its own.** An AST sweep over ``tools/uci/*.py`` and
   ``tests/rig_*.py``: a module that constructs a ``DeviceLock`` must go
   through ``acquire_device_lock``, and no module outside the helper may
   call ``acquire``/``acquire_or_raise`` on it. A third sweep, over a
   *wider* glob, forbids a literal ``lock_timeout=`` anywhere — that is
   how ``UnifiedManager(backend="u64", lock_timeout=120.0)`` in
   ``tools/test_ecdsa_p384_kat.py`` kept a thirteenth budget that the
   first two checks could not see, since it is neither in a rig
   directory nor a ``DeviceLock`` call. This is the half that keeps the
   fix from decaying — a new rig copied from an old one reintroduces the
   literal, and only a structural check catches that.

Invariant 1 also pins what must NOT change: the helper passes
``progress_window`` through, because ``progress_window=None`` would
restore the legacy hard timeout and destroy the indefinite wait behind a
healthy long holder — the one part of the old behaviour that worked.

Runs under pytest, and standalone for anyone without pytest installed
(the repo declares no pytest dependency)::

    python3 tools/test_device_lock_timeout.py
"""

import ast
import importlib.util
import io
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HELPER_PATH = REPO / "tools" / "uci" / "_device_lock_helper.py"

# tools/uci/ is in pytest.ini's norecursedirs (it is a rig directory), so
# the module under test is loaded by path rather than imported by name.
_spec = importlib.util.spec_from_file_location("_device_lock_helper_ut", HELPER_PATH)
dlh = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dlh)

from c64_test_harness.backends.device_lock import DeviceLockTimeout  # noqa: E402

ENV = dlh.LOCK_TIMEOUT_ENV
DEFAULT = dlh.DEFAULT_LOCK_TIMEOUT_S


class FakeLock:
    """Stands in for ``DeviceLock``: records the acquire call, never locks.

    ``_lock_dir`` is a real empty temp directory so the helper's
    best-effort holder/queue-depth probes look at nothing instead of at
    this machine's live lock directory — a unit test must not read, let
    alone prune, another lane's queue entries.
    """

    def __init__(self, *, raises: BaseException | None = None, host="fake.invalid"):
        self.device_host = host
        self._lock_dir = Path(tempfile.mkdtemp(prefix="dl-ut-"))
        self.calls: list[dict] = []
        self._raises = raises

    def acquire_or_raise(self, timeout=None, *, progress_window=None):
        self.calls.append({"timeout": timeout, "progress_window": progress_window})
        if self._raises is not None:
            raise self._raises


def _timeout_exc(host="fake.invalid"):
    """A real ``DeviceLockTimeout`` with the diagnostics a rig prints."""
    return DeviceLockTimeout(
        device_host=host,
        holder_pid=4242,
        pid_alive=True,
        lockfile_age_seconds=3.0,
        device_reachable_rest=True,
        timeout=1800.0,
        progress_window=60.0,
    )


# --------------------------------------------------------------------------
# 1. Reading the budget
# --------------------------------------------------------------------------


def test_default_when_unset() -> None:
    assert dlh.lock_timeout_s({}) == DEFAULT
    assert DEFAULT == 1800.0, "the documented default moved; update the docs too"


def test_env_override_is_honoured() -> None:
    assert dlh.lock_timeout_s({ENV: "7200"}) == 7200.0
    assert dlh.lock_timeout_s({ENV: " 90.5 "}) == 90.5


def test_empty_env_falls_back_loudly() -> None:
    """``VAR=`` is the shell's "unset", so it falls back — but it says so.

    Silent would be defensible for a value that is merely absent; this
    one was *written* and expanded to nothing, which is usually a bug in
    the caller's own quoting.
    """
    buf = io.StringIO()
    assert dlh.lock_timeout_s({ENV: ""}, stream=buf) == DEFAULT
    assert dlh.lock_timeout_s({ENV: "   "}, stream=buf) == DEFAULT
    text = buf.getvalue()
    assert text.count(ENV) == 2, f"expected a notice per empty read, got {text!r}"


def test_malformed_env_is_fatal() -> None:
    """A typo must not silently reinstate the default.

    The override exists so a lane can say "I know I am behind an
    80-minute run". ``C64_DEVICE_LOCK_TIMEOUT=30m`` quietly meaning 1800
    would fail that lane half an hour later with a message describing a
    budget nobody asked for — the project's standing rule is that a
    guard which silently passes when it cannot read its input is worse
    than no guard.
    """
    for bad in ("30m", "2 min", "abc", "1,800", "'900'", "1800s"):
        try:
            value = dlh.lock_timeout_s({ENV: bad})
        except dlh.LockTimeoutConfigError as exc:
            assert ENV in str(exc) and bad in str(exc), f"unhelpful message: {exc}"
        else:
            raise AssertionError(f"{bad!r} accepted, gave {value}")


def test_non_positive_and_non_finite_are_fatal() -> None:
    for bad in ("0", "-1", "-0.5", "nan", "inf", "-inf"):
        try:
            value = dlh.lock_timeout_s({ENV: bad})
        except dlh.LockTimeoutConfigError:
            pass
        else:
            raise AssertionError(f"{bad!r} accepted, gave {value}")


# --------------------------------------------------------------------------
# 2. The budget reaching DeviceLock.acquire
# --------------------------------------------------------------------------


def test_default_reaches_acquire() -> None:
    lock = FakeLock()
    dlh.acquire_device_lock(lock, env={}, stream=io.StringIO(), progress_interval=0)
    assert lock.calls == [{"timeout": DEFAULT, "progress_window": dlh.PROGRESS_WINDOW_S}]


def test_env_override_reaches_acquire() -> None:
    lock = FakeLock()
    dlh.acquire_device_lock(
        lock, env={ENV: "5400"}, stream=io.StringIO(), progress_interval=0
    )
    assert lock.calls[0]["timeout"] == 5400.0


def test_explicit_timeout_beats_the_environment() -> None:
    """A caller that names a budget owns it; the env does not override it."""
    lock = FakeLock()
    dlh.acquire_device_lock(
        lock, timeout=12.0, env={ENV: "5400"}, stream=io.StringIO(),
        progress_interval=0,
    )
    assert lock.calls[0]["timeout"] == 12.0


def test_progress_window_is_never_disabled() -> None:
    """Passing ``progress_window=None`` would be a real regression.

    It restores the legacy hard timeout, which is what makes an
    indefinite wait behind one healthy long holder possible. Measured on
    the real harness with no hardware: ``acquire(timeout=2.0)`` behind an
    8 s hold returned True after 8.0 s with the default window, and False
    after 2.0 s with ``progress_window=None``.
    """
    lock = FakeLock()
    dlh.acquire_device_lock(lock, env={}, stream=io.StringIO(), progress_interval=0)
    window = lock.calls[0]["progress_window"]
    assert window is not None and window > 0, f"progress_window defeated: {window!r}"


def test_malformed_env_stops_the_acquire() -> None:
    lock = FakeLock()
    try:
        dlh.acquire_device_lock(lock, env={ENV: "30m"}, stream=io.StringIO())
    except dlh.LockTimeoutConfigError:
        pass
    else:
        raise AssertionError("acquire proceeded on a malformed budget")
    assert lock.calls == [], "the device was touched despite a bad budget"


# --------------------------------------------------------------------------
# 3. Diagnostics and progress output
# --------------------------------------------------------------------------


def test_timeout_propagates_with_the_harness_diagnostics() -> None:
    """The rigs' ``except DeviceLockTimeout`` arms must still fire, unchanged.

    The harness message is the part that tells "queued behind a healthy
    holder" from "wedged" from "device unreachable"; wrapping it in a
    helper-specific exception would cost every rig that signal.
    """
    exc = _timeout_exc()
    lock = FakeLock(raises=exc)
    buf = io.StringIO()
    try:
        dlh.acquire_device_lock(lock, env={}, stream=buf, progress_interval=0)
    except DeviceLockTimeout as caught:
        assert caught is exc
        assert "4242" in str(caught), "holder PID lost"
    else:
        raise AssertionError("timeout swallowed")
    note = buf.getvalue()
    assert "gave up" in note and ENV in note, f"no budget note: {note!r}"


def test_progress_and_notices_never_touch_stdout() -> None:
    """Rig stdout is parsed; progress output must not appear in it.

    Covers the slow path too — a wait long enough to tick — because that
    is the only path that emits the periodic line at all.
    """
    import contextlib
    import time

    class SlowLock(FakeLock):
        def acquire_or_raise(self, timeout=None, *, progress_window=None):
            super().acquire_or_raise(timeout=timeout, progress_window=progress_window)
            time.sleep(0.25)

    lock = SlowLock()
    err = io.StringIO()
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        dlh.acquire_device_lock(lock, env={ENV: ""}, stream=err, progress_interval=0.05)
    assert out.getvalue() == "", f"progress leaked to stdout: {out.getvalue()!r}"
    text = err.getvalue()
    assert "still waiting" in text, f"no progress line emitted: {text!r}"
    assert ENV in text, "the progress line does not say how to wait longer"


# --------------------------------------------------------------------------
# 4. No rig keeps its own budget (the half that stops this decaying)
# --------------------------------------------------------------------------

#: Every module that may take the device lock. Directories, not a list of
#: filenames, so a rig added tomorrow is covered the day it lands.
RIG_GLOBS = (("tools/uci", "*.py"), ("tests", "rig_*.py"))

HELPER_NAME = "_device_lock_helper.py"


def _rig_sources():
    for rel, pattern in RIG_GLOBS:
        for path in sorted((REPO / rel).glob(pattern)):
            yield path, ast.parse(path.read_text())


def _calls_to(tree, names):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in names:
                yield node


def _constructs_device_lock(tree):
    return any(
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "DeviceLock"
        for n in ast.walk(tree)
    )


def _imported_names(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.update(a.asname or a.name for a in node.names)
    return names


def test_no_rig_calls_acquire_itself() -> None:
    """Only the helper may drive ``DeviceLock.acquire*``.

    A direct call is how a rig gets its own budget back, and a literal
    timeout in a rig is invisible from the outside — nothing in a passing
    hardware run reveals that this one script still cannot be told to
    wait.
    """
    offenders = []
    for path, tree in _rig_sources():
        if path.name == HELPER_NAME:
            continue
        for call in _calls_to(tree, {"acquire", "acquire_or_raise"}):
            offenders.append(f"{path.relative_to(REPO)}:{call.lineno}")
    assert not offenders, (
        "these call DeviceLock.acquire directly instead of going through "
        f"acquire_device_lock(): {offenders}"
    )


def test_every_locking_rig_uses_the_helper() -> None:
    offenders = []
    for path, tree in _rig_sources():
        if path.name == HELPER_NAME:
            continue
        if _constructs_device_lock(tree) and "acquire_device_lock" not in _imported_names(tree):
            offenders.append(str(path.relative_to(REPO)))
    assert not offenders, (
        "these construct a DeviceLock without importing acquire_device_lock: "
        f"{offenders}"
    )


def test_the_helper_passes_progress_window_through() -> None:
    """Structural counterpart to ``test_progress_window_is_never_disabled``.

    The behavioural test uses a fake lock, so it would still pass if the
    helper's single real call site were edited to pass ``None`` for a
    different argument name. This reads the source.
    """
    tree = ast.parse(HELPER_PATH.read_text())
    calls = [c for c in _calls_to(tree, {"acquire_or_raise"})]
    assert len(calls) == 1, f"expected one acquire_or_raise call, found {len(calls)}"
    kwargs = {k.arg: k.value for k in calls[0].keywords}
    assert set(kwargs) == {"timeout", "progress_window"}, sorted(kwargs)
    assert not isinstance(kwargs["progress_window"], ast.Constant) or (
        kwargs["progress_window"].value is not None
    ), "progress_window=None restores the legacy hard timeout"


#: Wider than RIG_GLOBS on purpose: a literal budget can hide anywhere a
#: device is driven, and the one that did was a UnifiedManager keyword in
#: a suite that is neither a rig nor a DeviceLock caller.
LOCK_TIMEOUT_GLOBS = (("tools", "*.py"), ("tools/uci", "*.py"),
                      ("tools/package", "*.py"), ("tests", "*.py"))


def test_no_module_passes_a_literal_lock_timeout() -> None:
    """``lock_timeout=<literal>`` is a budget the environment cannot raise.

    ``UnifiedManager(backend="u64", lock_timeout=...)`` takes the same
    DeviceLock by the same ``acquire_or_raise``, so a literal there is
    the identical defect one layer up — and invisible to the two checks
    above, which look for ``DeviceLock`` calls in rig directories.
    """
    offenders = []
    for rel, pattern in LOCK_TIMEOUT_GLOBS:
        for path in sorted((REPO / rel).glob(pattern)):
            if path.name in (HELPER_NAME, Path(__file__).name):
                continue
            for node in ast.walk(ast.parse(path.read_text())):
                if not isinstance(node, ast.Call):
                    continue
                for kw in node.keywords:
                    if kw.arg == "lock_timeout" and isinstance(kw.value, ast.Constant):
                        offenders.append(
                            f"{path.relative_to(REPO)}:{kw.value.lineno}"
                        )
    assert not offenders, (
        "these hardcode a device-lock budget the environment cannot "
        f"raise; pass lock_timeout_s() instead: {offenders}"
    )


def test_progress_line_carries_the_lockfile_age() -> None:
    """Age is what separates "healthy long run" from "wedged".

    Without it that verdict arrives only in the final DeviceLockTimeout,
    up to a whole budget later — the time-to-diagnosis cost of a larger
    default. One stat buys it back at the first tick.
    """
    import json
    import os
    import time as _time
    from c64_test_harness.backends.device_lock import device_lock_path

    class SlowLock(FakeLock):
        def acquire_or_raise(self, timeout=None, *, progress_window=None):
            super().acquire_or_raise(timeout=timeout, progress_window=progress_window)
            _time.sleep(0.15)

    lock = SlowLock()
    path = device_lock_path(lock.device_host, lock_dir=lock._lock_dir)
    path.write_text(json.dumps({"pid": os.getpid(), "ts": _time.time(),
                                "device_host": lock.device_host}))

    buf = io.StringIO()
    dlh.acquire_device_lock(lock, env={}, stream=buf, progress_interval=0.05)
    assert "lockfile age=" in buf.getvalue(), buf.getvalue()
    assert "STALE" not in buf.getvalue(), "a fresh lockfile read as wedged"

    old = _time.time() - (dlh.PROGRESS_WINDOW_S * 5)
    os.utime(path, (old, old))
    buf = io.StringIO()
    dlh.acquire_device_lock(lock, env={}, stream=buf, progress_interval=0.05)
    assert "STALE" in buf.getvalue(), (
        "a lockfile older than the progress window must read as wedged: "
        f"{buf.getvalue()!r}"
    )


def test_the_handoff_boundary_is_four_changes_not_three() -> None:
    """Pin the number four files of prose depend on.

    It had no coverage in either direction, in this repo or upstream,
    which is exactly how a wrong value (three, read off the harness's own
    docstring) sat in four files under a green suite.

    Real ``DeviceLock``, no hardware and no flock race: ``_holder_progress``
    is overridden to return a scripted sequence of live holder identities
    and ``_try_acquire_once`` to never grant, which is precisely what a
    waiter behind a handoff chain observes. Three changes must still
    extend past the caller's timeout; four must not.
    """
    import threading
    import time as _time
    from c64_test_harness.backends.device_lock import DeviceLock

    for attr in ("_holder_progress", "_try_acquire_once"):
        assert hasattr(DeviceLock, attr), (
            f"c64-test-harness no longer has DeviceLock.{attr}; this test "
            "and the handoff prose in _device_lock_helper.py, CLAUDE.md and "
            "tools/uci/README.md all rest on that shape — re-measure, do "
            "not delete"
        )

    def stops_extending(changes: int, timeout: float = 0.15,
                        observe: float = 0.9) -> bool:
        # heartbeat_interval=None: granting the lock at the end of the
        # observation window would otherwise start a heartbeat thread
        # that sleeps a full interval before noticing the lockfile is
        # not there. No holder here is real, so none needs one.
        lock = DeviceLock("fake.invalid", lock_dir=Path(tempfile.mkdtemp()),
                          heartbeat_interval=None)
        identities = [1000 + i for i in range(changes + 1)]
        seen = {"i": 0}

        def scripted(_window):
            i = min(seen["i"], len(identities) - 1)
            seen["i"] += 1
            return True, identities[i]

        # Never grant while we are observing; grant afterwards so the
        # still-extending arm's thread ends instead of polling at 10 Hz
        # for the life of the process. A test that leaks a daemon thread
        # per call is cheap here and expensive in a suite that grows.
        give_up_at = _time.monotonic() + observe + 0.2
        lock._holder_progress = scripted
        lock._try_acquire_once = lambda: _time.monotonic() >= give_up_at
        done = threading.Event()
        thread = threading.Thread(
            target=lambda: (lock.acquire(timeout=timeout), done.set()),
            daemon=True,
        )
        thread.start()
        stopped = done.wait(observe)
        thread.join(timeout=2.0)
        assert not thread.is_alive(), (
            "the probe thread outlived its acquire; the overrides no longer "
            "control DeviceLock.acquire and this result means nothing"
        )
        return stopped

    # A rename is caught by the hasattr checks above; a *signature* change
    # is not -- the override would simply never be called the way acquire
    # calls it, and the arm would fail through the boundary assertions with
    # a message blaming the boundary. Call it once here so that failure
    # names the real cause.
    try:
        stops_extending(0, observe=0.2)
    except TypeError as exc:
        raise AssertionError(
            "DeviceLock._holder_progress / _try_acquire_once changed shape "
            f"({exc}); this probe drives them directly, so re-measure the "
            "handoff boundary rather than trusting either assertion below"
        ) from exc

    assert not stops_extending(3), (
        "three identity changes stopped extending; the boundary moved to "
        "three and every 'fourth' in the docs is now wrong"
    )
    assert stops_extending(4), (
        "four identity changes still extended; the boundary moved past "
        "four and the docs understate how long a starved waiter survives"
    )


# --------------------------------------------------------------------------


def _main(tests=None) -> int:
    """Run the checks without pytest, one line per case.

    Catches more than ``AssertionError`` deliberately: the code under
    test raises ``LockTimeoutConfigError`` by design, and a regression
    that let one escape would otherwise abort the run partway and leave
    later cases silently unrun. An unrun test is not a passing one.
    """
    if tests is None:
        tests = {
            n: f
            for n, f in globals().items()
            if n.startswith("test_") and callable(f)
        }
    failures = 0
    for name, fn in sorted(tests.items()):
        try:
            fn()
        except AssertionError as exc:
            failures += 1
            print(f"FAIL {name}: {exc}")
        except Exception as exc:  # noqa: BLE001 — a raise is a result
            failures += 1
            summary = str(exc).strip().splitlines()
            print(f"ERROR {name}: {type(exc).__name__}: "
                  f"{summary[0] if summary else ''}")
        else:
            print(f"ok   {name}")
    print("FAILED" if failures else "PASS")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_main())
