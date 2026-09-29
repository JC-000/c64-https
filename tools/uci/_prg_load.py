"""tools/uci/_prg_load.py - load the PRG, prove it landed, then start it (#199).

Every UCI rig used to boot its image with ``client.run_prg``, which loads
AND starts it in one firmware call, and nothing ever read the image back.
A byte dropped or flipped on the way in would surface minutes later as a
crash, a hang or a failed handshake, and be written up as a defect in the
code under test - this project's most-recorded misdiagnosis shape.
``tests/rig_ip65_rrnet_hw.py`` measured exactly that fault on the bulk
``writemem`` path (c64-test-harness#231: one wrong byte in 47 kB, n=2).

Why not verify after ``run_prg``: the program is already running, and it
writes its own image (self-modifying code in ``uci_cmd.s``, zero-filled BSS
laid out inside the file), so a post-start compare races the thing it
checks. Why not ``writemem`` + SYS like the RR-Net rig: that swaps the
firmware runner every UCI result so far was produced on for the very path
the corruption was measured on, and costs ~33 s a load.

So: ``client.load_prg`` - the SAME firmware runner as ``run_prg``, minus the
run - then read the image back and compare it, then type ``SYS<entry>``
with the entry parsed from the image's own BASIC stub. ``RUN`` is avoided
on purpose: it walks the BASIC link pointer at $0801/$0802, which this
device has been measured zeroing 2-5 s after READY (the RR-Net rig and
c64-wireguard, independently), and SYS does not read it.

  * Only $0801-$9FFF is compared, and the report says so. The image's
    $A000+ tail is BSS zero fill, a host read of it returns the BASIC ROM
    until the program banks it out, and the one property of it that IS
    decidable from the file - all zeros - is checked instead.
  * The head is re-checked past a settle window (and rewritten if the
    zeroing event hit it) before the full compare, so the compare tolerates
    nothing.
  * One retry, then :class:`PrgLoadError`: a run is never started on an
    image known to be wrong. The first differing ADDRESS is reported.

The comparison is ``tools/ip65_hw_checks.check_image_readback`` - the RR-Net
rig's own, reused rather than re-invented. Pinned hardware-free by
``tools/test_prg_load.py``.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ip65_hw_checks import check_image_readback  # noqa: E402

from c64_test_harness.execute import parse_basic_sys_address

#: First address NOT compared: $A000+ is CRYPTO_COLD_SHADOW, RAM under the
#: BASIC ROM, which a host read returns as ROM until boot.s banks it out.
VERIFY_END = 0xA000
#: The head-zeroing event lands 2-5 s after READY; re-check past it.
HEAD_SETTLE_S = 7.0
#: Readback chunk; small enough that no firmware readmem cap is in play.
READ_CHUNK = 4096


class PrgLoadError(RuntimeError):
    """The image did not verify; the run must not start."""


def image_span(prg: bytes):
    """-> (load_addr, body, verify_len). Raises PrgLoadError on a PRG whose
    unverifiable tail holds anything but zero fill."""
    if len(prg) < 3:
        raise PrgLoadError(f"PRG is {len(prg)} bytes; nothing to load")
    load_addr = prg[0] | (prg[1] << 8)
    body = bytes(prg[2:])
    verify_len = max(0, min(len(body), VERIFY_END - load_addr))
    tail = body[verify_len:]
    if any(tail):
        first = verify_len + next(i for i, b in enumerate(tail) if b)
        raise PrgLoadError(
            f"the image holds non-zero bytes at ${load_addr + first:04X}, "
            f"past ${VERIFY_END:04X}: that span cannot be read back before "
            "the program banks BASIC out, so the verify would not cover the "
            "whole image")
    return load_addr, body, verify_len


def read_back(read_mem, addr: int, length: int) -> bytes:
    out = bytearray()
    while len(out) < length:
        n = min(READ_CHUNK, length - len(out))
        out += bytes(read_mem(addr + len(out), n))
    return bytes(out)


def load_verified_and_run(client, prg: bytes, *, retries: int = 1,
                          clock=time.monotonic, sleep=time.sleep,
                          out=None) -> dict:
    """``load_prg`` -> verify $0801-$9FFF -> ``SYS<entry>``. -> a report dict.

    Raises :class:`PrgLoadError` (nothing started) when the image does not
    verify after ``1 + retries`` loads, or when the PRG has no SYS stub.
    """
    out = out if out is not None else sys.stdout
    entry = parse_basic_sys_address(prg)
    if entry is None:
        raise PrgLoadError("the PRG carries no BASIC SYS stub to start it by")
    load_addr, body, verify_len = image_span(prg)
    head = body[:2]
    attempts = []
    verdict = None
    for attempt in range(1, retries + 2):
        t0 = clock()
        client.load_prg(prg)
        settle = HEAD_SETTLE_S - (clock() - t0)
        if settle > 0:
            sleep(settle)
        for _ in range(3):
            if bytes(client.read_mem(load_addr, 2)) == head:
                break
            client.write_mem(load_addr, head)
            sleep(1.0)
        back = read_back(client.read_mem, load_addr, verify_len)
        verdict = check_image_readback(body[:verify_len], back)
        first = verdict.evidence.get("first_difference")
        attempts.append({
            "attempt": attempt, "ok": verdict.ok,
            "first_difference": (None if first is None
                                 else f"${load_addr + first:04X}"),
        })
        if verdict.ok:
            break
        print(f"  PRG load attempt {attempt}: image does not verify — first "
              f"difference at ${load_addr + first:04X} (offset {first}); "
              f"wrote ${body[first]:02X}, read ${back[first]:02X}",
              file=out)
    report = {"load_addr": f"${load_addr:04X}", "bytes": len(body),
              "verified": f"${load_addr:04X}-${load_addr + verify_len - 1:04X}",
              "unverified_zero_tail": len(body) - verify_len,
              "sys": entry, "attempts": attempts}
    if not verdict.ok:
        raise PrgLoadError(
            f"the PRG did not load byte-exact in {len(attempts)} attempts "
            f"({attempts}); not starting a run on an image known to be wrong")
    print(f"PRG verified in RAM: {report['verified']} ({verify_len} B; the "
          f"{report['unverified_zero_tail']} B $A000+ tail is zero fill, "
          f"not compared) — SYS{entry}", file=out)
    client.send_text(f"SYS{entry}", finish_with_return=True)
    return report


__all__ = ["HEAD_SETTLE_S", "PrgLoadError", "VERIFY_END", "image_span",
           "load_verified_and_run", "read_back"]
