"""Keyboard / screen helpers for interacting with the c64-https boot menu.

Everything goes through the canonical c64-test-harness entry points:
- keyboard input uses transport.inject_keys() -- the same path as
  harness.send_key()
- screen reads use ScreenGrid.from_transport(); between polls we call
  transport.resume() so the binary monitor's memory read does not leave
  the CPU paused.
"""

from __future__ import annotations

import time
from typing import Optional

from c64_test_harness.backends.vice_binary import BinaryViceTransport
from c64_test_harness.screen import ScreenGrid


def press_key(transport: BinaryViceTransport, ch: str | int) -> None:
    """Press a single ASCII/PETSCII key on the C64.

    Accepts either a one-character str (upper- or lower-case) or an int
    (raw PETSCII / screen code). For letters, we send the uppercase ASCII
    value -- the boot menu reads $49 etc. via CHRIN which handles this.
    """
    if isinstance(ch, str):
        if len(ch) != 1:
            raise ValueError(f"press_key: expected 1 char, got {ch!r}")
        code = ord(ch.upper())
    else:
        code = int(ch) & 0xFF
    # Ensure CPU isn't paused from a prior screen read.
    try:
        transport.resume()
    except Exception:  # noqa: BLE001
        pass
    transport.inject_keys([code])


def get_screen_text(transport: BinaryViceTransport) -> str:
    """Read the current C64 screen as a flat string."""
    grid = ScreenGrid.from_transport(transport)
    return grid.continuous_text()


def wait_for_screen_text(
    transport: BinaryViceTransport,
    needle: str,
    timeout: float = 90.0,
    poll_interval: float = 0.75,
    verbose: bool = False,
) -> str:
    """Poll the screen until `needle` appears (case-insensitive).

    Returns the final screen text on success. Raises TimeoutError on
    failure, with the last screen text in the exception message.
    """
    needle_upper = needle.upper()
    deadline = time.monotonic() + timeout
    last_text = ""
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            # Binary monitor pauses CPU on reads -- resume each iteration.
            transport.resume()
            time.sleep(poll_interval)
            last_text = get_screen_text(transport)
            if needle_upper in last_text.upper():
                if verbose:
                    print(f"[screen] matched {needle!r}")
                return last_text
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(0.3)
    raise TimeoutError(
        f"screen text {needle!r} not seen within {timeout:.0f}s.\n"
        f"Last screen text:\n{last_text!r}\n"
        f"Last poll error: {last_err}"
    )
