"""tools/uci/_device_lock_helper.py - shared U64E device-lock conventions.

Every rig in this repo that drives a real device takes
``c64_test_harness.DeviceLock`` first.  This module owns the two things
they all need and used to spell out one at a time: **how long to wait**
and **what to say while waiting**.

The wait budget
---------------
``DeviceLock.acquire(timeout=..., progress_window=60.0)`` is *queue
aware*: while the current holder's PID is alive and the lockfile mtime is
fresh, the deadline is re-armed on every poll, so a waiter sits behind one
long healthy holder indefinitely and ``timeout`` is never consulted.
Measured, no hardware: ``acquire(timeout=2.0)`` behind an 8 s hold
returned True after 8.0 s.

``timeout`` is therefore **not** the length of the longest run you may
queue behind.  It is the bound on waits the harness refuses to extend:

* a holder whose PID is dead, or whose mtime has gone stale past
  ``progress_window`` (a wedged holder, or one whose heartbeat gave up);
* a **handoff chain** - after the **fourth** change of holder identity
  the harness stops extending for the rest of that acquire, permanently,
  and the caller's ``timeout`` runs out normally.

  Four, not three.  ``_MAX_HOLDER_HANDOFFS`` is 3 and the harness's own
  docstring says "after ``_MAX_HOLDER_HANDOFFS`` identity changes", but
  the code extends while ``handoffs <= _MAX_HOLDER_HANDOFFS`` and
  increments *on* a change, so three changes still extend for ever.  The
  harness's own WARNING agrees with its code ("the holder changed 4
  times"), not with its prose.  Measured here by driving a scripted
  identity sequence, no hardware: 0/1/2/3 changes then a stable holder
  still waited past the observation window; 4 and 5 returned False at
  ``timeout``.  A doc issue for the harness is drafted; do not "correct"
  this to three from reading their docstring.

The second case is the one that would bite this fleet: several lanes
cycling the same U64E overtake a queued rig within seconds, after which
its hardcoded 120 s was the whole budget - and there was no way to raise
it without editing the rig.  No such timeout has been captured from a
real run here; the mechanism above is lab-measured, the field frequency
is not.  Hence :data:`LOCK_TIMEOUT_ENV`.

Default: :data:`DEFAULT_LOCK_TIMEOUT_S` = 1800 s (30 min).  Justified
against both failure modes.  Too short and a rig fails while the device
is merely busy - 120 s could not survive one overtake by a lane doing a
45 s comb boot, and 30 min outlasts every UCI rig's own hold (the long
one, the RR-Net e2e at 33-80 min, runs alone).  Too long and a rig
blocking on a genuinely wedged device becomes its own outage: at 30 min a
lane fails the same session with diagnostics naming the holder, rather
than being indistinguishable from a hang - which is the same reason
CLAUDE.md's "Design note - bounded timeouts" refuses unbounded waits on
the C64 side.  It also matches the budget the CI path in this file
already used, so the repo has one number instead of two.

Residual limitation, stated rather than hidden: a waiter that has been
overtaken a fourth time and is *then* queued behind a fresh 80-minute
holder still fails at the budget, because the harness never resumes
extending within one acquire.  ``C64_DEVICE_LOCK_TIMEOUT=7200`` is the answer, and the
timeout diagnostic says which case you are in.

Progress output
---------------
A silent 30-minute block is indistinguishable from a hang - that
ambiguity is what prompted this module.  :func:`acquire_device_lock`
therefore prints a line every :data:`PROGRESS_INTERVAL_S` seconds naming
the elapsed wait, the budget, the holder PID and the queue depth.  It
goes to **stderr**, never stdout: rig stdout is parsed (by supervisors,
and by ``tools/package/verify_release.py``-style greps), and a
progress line on it would be a new record in someone's log format.

Public surface
--------------
* :data:`LOCK_TIMEOUT_ENV` / :func:`lock_timeout_s` - the budget and how
  it is read.
* :class:`LockTimeoutConfigError` - raised for a malformed override.
* :func:`acquire_device_lock` - acquire with that budget, progress
  output, and the harness's ``DeviceLockTimeout`` diagnostics preserved.
* :class:`QueueSaturatedError` / :func:`acquire_with_queue_budget` - the
  CI-bot path: same budget, plus a queue-depth gate and a yield-cleanly
  contract for a cron runner.
"""


from __future__ import annotations

import math
import os
import sys
import threading
import time
from contextlib import contextmanager
from typing import IO, Iterator, Mapping

from c64_test_harness.backends.device_lock import (
    DeviceLock, DeviceLockTimeout, device_lock_path,
)


#: Environment variable that overrides the device-lock acquire budget,
#: in seconds.  Unset (or empty) means :data:`DEFAULT_LOCK_TIMEOUT_S`;
#: anything that is not a positive finite number is a hard error, never
#: a silent fallback - see :func:`lock_timeout_s`.
LOCK_TIMEOUT_ENV = "C64_DEVICE_LOCK_TIMEOUT"

#: Default acquire budget in seconds.  See the module docstring for the
#: justification against both failure modes; do not change it here
#: without changing that paragraph.
DEFAULT_LOCK_TIMEOUT_S = 1800.0

#: How often :func:`acquire_device_lock` says it is still waiting.
PROGRESS_INTERVAL_S = 30.0

#: How fresh the holder's lockfile mtime must be for the harness to keep
#: extending the deadline.  Restated here (it is the harness's own
#: default) so that passing it explicitly is a decision this repo owns:
#: ``progress_window=None`` would restore the legacy hard timeout and
#: destroy the indefinite wait behind a healthy long holder, which is the
#: one part of this that already worked.
PROGRESS_WINDOW_S = 60.0


class LockTimeoutConfigError(RuntimeError):
    """Raised when ``C64_DEVICE_LOCK_TIMEOUT`` cannot be read as a budget.

    Deliberately fatal rather than a fall back to the default.  The
    override exists precisely so a lane can say "I know I am behind an
    80-minute run"; a typo (``30m``, ``2 min``, a stray quote) that
    silently reinstated 1800 s would fail two hours later with a message
    describing a budget nobody asked for.  This repo's standing rule -- a
    guard that silently passes when it cannot read its input is worse
    than no guard -- applies to the budget as much as to the REU
    preflight it is modelled on (``tools/uci/_reu_preflight.py``).
    """


def lock_timeout_s(
    env: Mapping[str, str] | None = None,
    *,
    default: float = DEFAULT_LOCK_TIMEOUT_S,
    stream: IO[str] | None = None,
) -> float:
    """The device-lock acquire budget in seconds.

    Read at call time, not import time, so a test (and a long-lived
    supervisor process) can flip it.

    * unset -> *default*, silently: that is the ordinary case.
    * set but empty -> *default*, with a note on *stream*.  ``VAR=`` is
      the shell's own spelling of "not set" and refusing it would break
      ``env -u``-style call sites, but it is worth one line, because a
      variable that expanded to nothing usually meant to expand to
      something.
    * anything else -> parsed as a float; a value that is not finite and
      strictly positive raises :class:`LockTimeoutConfigError`.

    :raises LockTimeoutConfigError: on any unparseable or non-positive
        value.
    """
    source = os.environ if env is None else env
    raw = source.get(LOCK_TIMEOUT_ENV)
    if raw is None:
        return float(default)
    text = raw.strip()
    if not text:
        print(
            f"[device-lock] {LOCK_TIMEOUT_ENV} is set but empty; "
            f"using the default {default:g}s",
            file=stream if stream is not None else sys.stderr,
            flush=True,
        )
        return float(default)
    try:
        value = float(text)
    except ValueError:
        raise LockTimeoutConfigError(
            f"{LOCK_TIMEOUT_ENV}={raw!r} is not a number of seconds. "
            f"Give a positive number, e.g. {LOCK_TIMEOUT_ENV}=7200 for a "
            f"two-hour queue; unset it for the default {default:g}s."
        ) from None
    if not math.isfinite(value) or value <= 0:
        raise LockTimeoutConfigError(
            f"{LOCK_TIMEOUT_ENV}={raw!r} is not a positive, finite number "
            f"of seconds. A zero or negative budget would turn every "
            f"queued run into an instant failure, and an infinite one "
            f"would make a wedged device indistinguishable from a busy "
            f"one; unset it for the default {default:g}s."
        )
    return value


def _holder_note(lock: DeviceLock) -> str:
    """Best-effort ``holder pid=..., queue depth=...`` tag for a progress line.

    Filesystem-only and never raises: this decorates a message, it is not
    a check.  ``foreign_holder`` (not ``read_info``) is the "who holds it
    right now" query -- ``read_info`` names whoever held it *last*, which
    after any completed run is a dead PID.
    """
    bits = []
    try:
        holder = DeviceLock.foreign_holder(
            lock.device_host, lock_dir=getattr(lock, "_lock_dir", None)
        )
    except Exception:                                    # noqa: BLE001
        holder = None
    if holder is not None:
        bits.append(f"holder pid={holder.get('pid')}")
    # Lockfile age is the one field that separates "healthy long run"
    # from "wedged", and without it that verdict arrives only in the
    # final DeviceLockTimeout -- up to a full budget later. One stat
    # buys it back at the first tick. Same rule as the harness's
    # DeviceLockTimeout message: older than the progress window is the
    # wedged reading, and it is why a long wait is not, by itself, a
    # reason to touch the device.
    try:
        age = time.time() - os.stat(
            device_lock_path(
                lock.device_host, lock_dir=getattr(lock, "_lock_dir", None)
            )
        ).st_mtime
    except Exception:                                    # noqa: BLE001
        age = None
    if age is not None:
        stale = " STALE, holder may be wedged" if age > PROGRESS_WINDOW_S else ""
        bits.append(f"lockfile age={max(0.0, age):.0f}s{stale}")
    try:
        depth = DeviceLock.peek_queue_depth(
            lock.device_host, lock_dir=getattr(lock, "_lock_dir", None)
        )
    except Exception:                                    # noqa: BLE001
        depth = None
    if depth is not None:
        bits.append(f"queue depth={depth}")
    return ("; " + ", ".join(bits)) if bits else ""


def acquire_device_lock(
    lock: DeviceLock,
    *,
    timeout: float | None = None,
    env: Mapping[str, str] | None = None,
    stream: IO[str] | None = None,
    progress_interval: float = PROGRESS_INTERVAL_S,
) -> float:
    """Take *lock* within the shared budget, saying so while it waits.

    The one entry point every rig in this repo uses, so that the budget
    is a single env-overridable number instead of a literal per script.

    Returns the wall-clock seconds spent waiting (0.0 for an uncontended
    acquire).  On failure raises the harness's
    :class:`DeviceLockTimeout`, unchanged, so existing ``except
    DeviceLockTimeout`` arms and their holder/liveness/reachability
    diagnostics keep working; a final stderr line adds the elapsed wait
    and the budget that was in force, which the harness cannot know.

    :param timeout: explicit budget; ``None`` reads
        :data:`LOCK_TIMEOUT_ENV` via :func:`lock_timeout_s`.
    :param stream: where progress goes; ``None`` means ``sys.stderr``.
        Never stdout -- see the module docstring.
    :raises LockTimeoutConfigError: malformed :data:`LOCK_TIMEOUT_ENV`.
    :raises DeviceLockTimeout: budget exhausted.
    """
    out = stream if stream is not None else sys.stderr
    budget = lock_timeout_s(env, stream=out) if timeout is None else float(timeout)

    started = time.monotonic()
    stop = threading.Event()

    def _tick() -> None:
        while not stop.wait(progress_interval):
            waited = time.monotonic() - started
            print(
                f"[device-lock] still waiting {waited:.0f}s of {budget:.0f}s "
                f"for {lock.device_host}{_holder_note(lock)} "
                f"(raise {LOCK_TIMEOUT_ENV} to wait longer)",
                file=out,
                flush=True,
            )

    ticker: threading.Thread | None = None
    if progress_interval and progress_interval > 0:
        ticker = threading.Thread(
            target=_tick, name="device-lock-progress", daemon=True
        )
        ticker.start()
    try:
        lock.acquire_or_raise(timeout=budget, progress_window=PROGRESS_WINDOW_S)
    except DeviceLockTimeout:
        elapsed = time.monotonic() - started
        print(
            f"[device-lock] gave up on {lock.device_host} after {elapsed:.0f}s "
            f"(budget {budget:.0f}s from "
            f"{LOCK_TIMEOUT_ENV if timeout is None else 'the caller'})",
            file=out,
            flush=True,
        )
        raise
    finally:
        stop.set()
        if ticker is not None:
            ticker.join(timeout=1.0)
    elapsed = time.monotonic() - started
    if elapsed >= progress_interval > 0:
        print(
            f"[device-lock] acquired {lock.device_host} after {elapsed:.0f}s",
            file=out,
            flush=True,
        )
    return elapsed


class QueueSaturatedError(RuntimeError):
    """Raised when the U64E DeviceLock could not be acquired in time.

    Carries the host string, observed wait time, and the configured
    budgets so the CI bot can log a structured diagnostic before
    yielding for the next cron tick.
    """

    def __init__(
        self,
        *,
        device_host: str,
        elapsed_sec: float,
        lock_timeout_sec: float,
        max_queue_depth: int,
        reason: str,
    ) -> None:
        self.device_host = device_host
        self.elapsed_sec = elapsed_sec
        self.lock_timeout_sec = lock_timeout_sec
        self.max_queue_depth = max_queue_depth
        self.reason = reason
        super().__init__(
            f"QueueSaturatedError: device={device_host!r} reason={reason!r} "
            f"elapsed={elapsed_sec:.1f}s "
            f"(lock_timeout_sec={lock_timeout_sec:g}, "
            f"max_queue_depth={max_queue_depth})"
        )


def _peek_queue_depth(lock: DeviceLock) -> int | None:
    """Best-effort inspection of the queue depth behind ``lock``.

    Returns the observed waiter count, or ``None`` if it is unobservable
    (an unreadable sidecar directory, or a harness too old to have the
    accessor).

    The harness grew this after the helper was written: waiters register
    an intent file in ``<lockfile>.queue/`` and ``DeviceLock.queue_depth``
    counts the live ones, so the probe below now returns a real number
    rather than ``None``.  It still probes by attribute name so an older
    ``c64-test-harness`` (editable install from a sibling working tree,
    so its version is not ours to pin) degrades to ``None`` instead of
    raising.
    """
    for attr in ("queue_depth", "waiters", "wait_count"):
        probe = getattr(lock, attr, None)
        if probe is None:
            continue
        try:
            value = probe() if callable(probe) else probe
        except Exception:
            continue
        if isinstance(value, int) and value >= 0:
            return value
    return None


@contextmanager
def acquire_with_queue_budget(
    device_host: str | None = None,
    *,
    max_queue_depth: int = 3,
    lock_timeout_sec: float | None = None,
) -> Iterator[DeviceLock]:
    """Acquire ``DeviceLock(device_host)`` with bounded wait + queue logging.

    Behaviour:

    1. **Queue-position log** - the first line printed at acquisition is
       ``"DeviceLock queue position: N"`` (or ``"unknown"`` when
       ``c64_test_harness`` does not yet expose the waiter count - see
       :func:`_peek_queue_depth`). This lets the CI workflow log
       distinguish "queued" from "wedged" from "in flight" without
       parsing the harness's internal state.

    2. **Bounded wait** - the acquire goes through
       :func:`acquire_device_lock`, so it uses the one shared budget
       (``lock_timeout_sec``, else ``C64_DEVICE_LOCK_TIMEOUT``, else
       :data:`DEFAULT_LOCK_TIMEOUT_S`) and prints the same progress
       lines. If the budget is exhausted, :class:`QueueSaturatedError`
       is raised carrying the harness's own holder/liveness/reachability
       diagnostics in ``reason``. The CI bot decides the retry policy
       (typically: log and exit, retry on the next cron tick).

       Note what the budget is not: a live, progressing holder extends
       the harness's deadline indefinitely, so this does not cap the
       time spent behind one healthy long run. See the module
       docstring.

    3. **Queue-depth threshold** - if the observed queue depth at
       acquire time exceeds ``max_queue_depth``,
       :class:`QueueSaturatedError` is raised immediately rather than
       getting in line. Live now that the harness exposes
       ``queue_depth``; still a no-op against a harness that does not,
       where the depth reads ``None``.

    The default device host is ``"10.43.23.81"`` (the U64E in this lab),
    overridable via the ``U64_HOST`` environment variable.

    :param device_host: U64E host string. ``None`` falls back to
        ``$U64_HOST`` then ``"10.43.23.81"``.
    :param max_queue_depth: bail out with :class:`QueueSaturatedError`
        if the queue depth exceeds this value at acquire time.
    :param lock_timeout_sec: budget for the acquire wait. ``None``
        (the default) reads ``C64_DEVICE_LOCK_TIMEOUT``, falling back to
        :data:`DEFAULT_LOCK_TIMEOUT_S`.
    :raises QueueSaturatedError: when the acquire fails inside the
        configured budget(s).
    """
    host = device_host or os.environ.get("U64_HOST", "10.43.23.81")
    # Resolved before anything else: a malformed C64_DEVICE_LOCK_TIMEOUT
    # must fail before the run starts, not after the queue gate has
    # already reported a budget it never used.
    budget = (
        lock_timeout_s() if lock_timeout_sec is None else float(lock_timeout_sec)
    )
    lock = DeviceLock(host)
    depth = _peek_queue_depth(lock)
    depth_label = "unknown" if depth is None else str(depth)
    print(f"DeviceLock queue position: {depth_label}", flush=True)

    if depth is not None and depth > max_queue_depth:
        raise QueueSaturatedError(
            device_host=host,
            elapsed_sec=0.0,
            lock_timeout_sec=budget,
            max_queue_depth=max_queue_depth,
            reason=f"queue depth {depth} > max_queue_depth {max_queue_depth}",
        )

    start = time.monotonic()
    try:
        acquire_device_lock(lock, timeout=budget)
    except DeviceLockTimeout as exc:
        # The harness message names the holder, its liveness, the
        # lockfile age and whether the device answers REST -- everything
        # needed to tell "queued" from "wedged". Carrying it in `reason`
        # keeps that in the CI log; discarding it for a bare
        # "timeout exhausted" is what this rewrite is fixing.
        raise QueueSaturatedError(
            device_host=host,
            elapsed_sec=time.monotonic() - start,
            lock_timeout_sec=budget,
            max_queue_depth=max_queue_depth,
            reason=str(exc),
        ) from exc
    try:
        yield lock
    finally:
        lock.release()
