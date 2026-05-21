"""tools/uci/_device_lock_helper.py - U64E shared-queue conventions for CI.

CI-bot use only. Existing interactive ``tools/uci/*.py`` scripts continue
using ``c64_test_harness.DeviceLock`` directly without going through this
helper; the helper exists so an automated runner can yield cleanly
instead of camping on the U64E queue indefinitely.

See user memory ``u64e_shared_queue`` for the canonical motivation: the
U64E (default 10.43.23.81) is shared across the c64-* projects, so a
poorly-timed CI run that waits forever blocks both itself and any
interactive user. The 30-min hard timeout plus the (future)
queue-depth gate lets the CI bot drop out cleanly and retry on the next
cron tick.

Public surface:

* :class:`QueueSaturatedError` - raised when the lock could not be
  acquired inside the configured budget.
* :func:`acquire_with_queue_budget` - thin wrapper around
  ``DeviceLock.acquire`` with bounded wait and queue-position logging.

Known limitation - ``c64_test_harness.DeviceLock`` does not currently
expose the number of agents waiting behind us in the kernel-level
``flock()`` queue, so today the helper can only gate on
``lock_timeout_sec``. The ``max_queue_depth`` argument is accepted (and
its semantics documented) so the CI bot's call sites do not need to
change once the harness grows a queue-introspection API.
"""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from typing import Iterator

from c64_test_harness.backends.device_lock import DeviceLock


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
        lock_timeout_sec: int,
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
            f"(lock_timeout_sec={lock_timeout_sec}, "
            f"max_queue_depth={max_queue_depth})"
        )


def _peek_queue_depth(lock: DeviceLock) -> int | None:
    """Best-effort inspection of the queue depth behind ``lock``.

    Returns the observed waiter count, or ``None`` if the underlying
    ``c64_test_harness`` build does not yet surface that information.

    TODO(c64-test-harness): ``DeviceLock`` does not currently expose the
    number of agents waiting on its flock. ``read_info()`` only returns
    metadata for the **current holder**, not the queue tail. Until the
    upstream harness grows a ``queue_depth()`` (or equivalent) accessor,
    this function returns ``None`` and the helper gates only on
    ``lock_timeout_sec``. When the API arrives, route it through here so
    no call site has to change.
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
    lock_timeout_sec: int = 1800,
) -> Iterator[DeviceLock]:
    """Acquire ``DeviceLock(device_host)`` with bounded wait + queue logging.

    Behaviour:

    1. **Queue-position log** - the first line printed at acquisition is
       ``"DeviceLock queue position: N"`` (or ``"unknown"`` when
       ``c64_test_harness`` does not yet expose the waiter count - see
       :func:`_peek_queue_depth`). This lets the CI workflow log
       distinguish "queued" from "wedged" from "in flight" without
       parsing the harness's internal state.

    2. **Hard timeout** - if the lock is not granted inside
       ``lock_timeout_sec`` seconds (default 30 min = 1800 s),
       :class:`QueueSaturatedError` is raised. The CI bot decides the
       retry policy (typically: log and exit, retry on the next cron
       tick).

    3. **Queue-depth threshold** - if the observed queue depth at
       acquire time exceeds ``max_queue_depth``,
       :class:`QueueSaturatedError` is raised immediately rather than
       getting in line. Currently a no-op until the upstream harness
       grows queue introspection; see the TODO in
       :func:`_peek_queue_depth`.

    The default device host is ``"10.43.23.81"`` (the U64E in this lab),
    overridable via the ``U64_HOST`` environment variable.

    :param device_host: U64E host string. ``None`` falls back to
        ``$U64_HOST`` then ``"10.43.23.81"``.
    :param max_queue_depth: bail out with :class:`QueueSaturatedError`
        if the queue depth exceeds this value at acquire time.
    :param lock_timeout_sec: hard wall-clock limit on the acquire wait.
        Defaults to 30 minutes.
    :raises QueueSaturatedError: when the acquire fails inside the
        configured budget(s).
    """
    host = device_host or os.environ.get("U64_HOST", "10.43.23.81")
    lock = DeviceLock(host)
    depth = _peek_queue_depth(lock)
    depth_label = "unknown" if depth is None else str(depth)
    print(f"DeviceLock queue position: {depth_label}", flush=True)

    if depth is not None and depth > max_queue_depth:
        raise QueueSaturatedError(
            device_host=host,
            elapsed_sec=0.0,
            lock_timeout_sec=lock_timeout_sec,
            max_queue_depth=max_queue_depth,
            reason=f"queue depth {depth} > max_queue_depth {max_queue_depth}",
        )

    start = time.monotonic()
    if not lock.acquire(timeout=float(lock_timeout_sec)):
        elapsed = time.monotonic() - start
        raise QueueSaturatedError(
            device_host=host,
            elapsed_sec=elapsed,
            lock_timeout_sec=lock_timeout_sec,
            max_queue_depth=max_queue_depth,
            reason=f"lock_timeout_sec={lock_timeout_sec} exhausted",
        )
    try:
        yield lock
    finally:
        lock.release()
