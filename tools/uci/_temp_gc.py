"""Userspace GC for the U64E's /Temp attachment leak (fw <= 3.14d).

Every REST call that carries a body — run_prg's PRG upload, the keystroke
trigger POST, machine:writemem — lands as a file in /Temp on the device,
and released firmware never deletes them: the "writemem exhaustion wedge".
When /Temp fills (~15 rig runs at ~63 KB PRG + 1 small attachment per
run), the REST API *and* the C64-facing UCI bridge wedge together and
only a power cycle recovers. Upstream fixed it in
GideonZ/1541ultimate#686 (auto-cleanup keeping the youngest 10 managed
files), but no released firmware carries it yet.

This helper mirrors that policy from the host side over FTP: it deletes
/Temp files matching ``temp<digits>`` — the firmware's managed-attachment
naming — oldest-first, keeping the youngest ``keep``. It never touches
any other /Temp entry (user files, mounted images).

Call ``gc_temp(host)`` at rig start (rigs run it right after enable_uci,
under the DeviceLock) or run standalone:

    python3 tools/uci/_temp_gc.py [host]

Environment: ``U64_HOST`` (default 192.168.1.81), ``C64_SKIP_TEMP_GC=1``
to bypass, ``TEMP_GC_KEEP`` to override the keep count (default 2).
"""

from __future__ import annotations

import os
import re
import sys
from ftplib import FTP, error_perm

# The firmware's attachment counter is HEX: temp0009 is followed by
# temp000A (observed live). A \d+ pattern silently skips lettered names.
_MANAGED = re.compile(r"^temp[0-9a-fA-F]+$")


def gc_temp(host: str, keep: int | None = None, timeout: float = 10.0) -> int:
    """Delete managed /Temp attachments, keeping the youngest *keep*.

    Returns the number of files deleted. Any FTP failure is reported and
    swallowed — GC is best-effort hygiene and must never fail a rig run.
    """
    if os.environ.get("C64_SKIP_TEMP_GC") == "1":
        return 0
    if keep is None:
        keep = int(os.environ.get("TEMP_GC_KEEP", "2"))
    deleted = 0
    try:
        with FTP(host, timeout=timeout) as ftp:
            ftp.login()
            ftp.cwd("/Temp")
            # NLST order is the firmware's directory order, which is
            # creation order for the monotonically numbered tempNNNN
            # files; the numeric sort below makes oldest-first explicit
            # (and survives a counter that skips).
            names = [n for n in ftp.nlst() if _MANAGED.match(n)]
            names.sort(key=lambda n: int(n[4:], 16))
            victims = names[: max(0, len(names) - keep)] if keep else names
            for name in victims:
                try:
                    ftp.delete(name)
                    deleted += 1
                except error_perm as exc:
                    # e.g. still referenced; skip — the next GC gets it
                    print(f"  temp-gc: skip {name}: {exc}", file=sys.stderr)
    except OSError as exc:
        print(f"  temp-gc: FTP unavailable on {host}: {exc}", file=sys.stderr)
        return deleted
    if deleted:
        print(f"  temp-gc: deleted {deleted} /Temp attachment(s) "
              f"(kept youngest {keep}) — writemem-wedge budget restored")
    return deleted


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else \
        os.environ.get("U64_HOST", "192.168.1.81")
    gc_temp(target)
