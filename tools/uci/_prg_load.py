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

  * $0801-$9FFF is compared, and so is $C000-$CFFF (plain RAM: the
    cold-code bank's image, src/net/uci/cold_bank.s, is carried there
    until boot stashes it in the REU). The rest of the tail is BSS zero fill or sits under a ROM /
    I/O, so a host read there does not return what was loaded; the one
    property of it that IS decidable from the file - all zeros - is
    checked instead. The report names both spans.
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

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ip65_hw_checks import check_image_readback  # noqa: E402

from c64_test_harness.execute import parse_basic_sys_address

#: First address NOT compared: $A000+ is CRYPTO_COLD_SHADOW, RAM under the
#: BASIC ROM, which a host read returns as ROM until boot.s banks it out.
VERIFY_END = 0xA000
#: A second span that IS compared: RAM no ROM shadows. The cold-code bank
#: (src/net/uci/cold_bank.s) carries its image here; no other image reaches
#: it since #288 (they end at $BFFF), so the window compares nothing there.
RAM_WINDOW = (0xC000, 0xD000)
#: The ML-KEM load image (PQ_HYBRID): LIB_MLKEM_CODE/RODATA/MARK LOAD at
#: $A000, in the file bytes under CRYPTO_COLD_SHADOW, and boot copies them to
#: $E000 and then zeroes the stage. A host read of $A000-$BFFF returns the
#: BASIC ROM and of $E000 the KERNAL, so the stage cannot be compared before
#: the run or after it. Exactly that span - [__LIB_MLKEM_CODE_LOAD__, tail
#: marker + 1) from the build's labels.txt, and only when the build links
#: pq_mlkem_call - may be non-zero (counted in the report, loudly);
#: tools/uci/rig_mlkem_hw.py parks the CPU with all RAM banked in and
#: compares the copy at $E000 to the PRG's bytes. Every other byte of the
#: tail is refused exactly as before, knob-off images included.
DEFAULT_LABELS = Path(__file__).resolve().parents[2] / "build" / "labels.txt"
_LABEL = re.compile(r"^al\s+C:([0-9A-Fa-f]+)\s+\.(\S+)\s*$")


def stage_from_labels(labels_path) -> "tuple[int, int] | None":
    """-> (first, end_exclusive) of the ML-KEM load image, or None.

    None unless the labels name pq_mlkem_call (a PQ_HYBRID build) and the
    image symbols: a knob-off build has no staged span, so nothing is allowed.
    """
    try:
        text = Path(labels_path).read_text()
    except OSError:
        return None
    sym = {}
    for line in text.splitlines():
        m = _LABEL.match(line)
        if m:
            sym[m.group(2)] = int(m.group(1), 16)
    need = ("pq_mlkem_call", "__LIB_MLKEM_CODE_LOAD__", "__LIB_MLKEM_MARK_LOAD__")
    if any(n not in sym for n in need):
        return None
    return sym["__LIB_MLKEM_CODE_LOAD__"], sym["__LIB_MLKEM_MARK_LOAD__"] + 1
#: The head-zeroing event lands 2-5 s after READY; re-check past it.
HEAD_SETTLE_S = 7.0
#: Readback chunk; small enough that no firmware readmem cap is in play.
READ_CHUNK = 4096


class PrgLoadError(RuntimeError):
    """The image did not verify; the run must not start."""


def ram_window(load_addr: int, body: bytes):
    """-> (offset, length) of RAM_WINDOW inside the image (length 0 if none)."""
    lo = max(RAM_WINDOW[0], load_addr)
    hi = min(RAM_WINDOW[1], load_addr + len(body))
    return lo - load_addr, max(0, hi - lo)


def image_span(prg: bytes, stage=None):
    """-> (load_addr, body, verify_len). Raises PrgLoadError on a PRG whose
    unverifiable tail (past verify_len, outside RAM_WINDOW) holds anything
    but zero fill. *stage* = (first, end_exclusive) from stage_from_labels:
    the one span allowed to be non-zero."""
    if len(prg) < 3:
        raise PrgLoadError(f"PRG is {len(prg)} bytes; nothing to load")
    load_addr = prg[0] | (prg[1] << 8)
    body = bytes(prg[2:])
    verify_len = max(0, min(len(body), VERIFY_END - load_addr))
    w_off, w_len = ram_window(load_addr, body)
    tail = bytearray(body[verify_len:])
    if w_len:
        tail[w_off - verify_len:w_off - verify_len + w_len] = bytes(w_len)
    if stage is not None:
        s_lo = max(stage[0] - load_addr - verify_len, 0)
        s_hi = max(stage[1] - load_addr - verify_len, 0)
        tail[s_lo:s_hi] = bytes(len(tail[s_lo:s_hi]))
    if any(tail):
        first = verify_len + next(i for i, b in enumerate(tail) if b)
        raise PrgLoadError(
            f"the image holds non-zero bytes at ${load_addr + first:04X}, "
            f"past ${VERIFY_END:04X} and outside ${RAM_WINDOW[0]:04X}-"
            f"${RAM_WINDOW[1] - 1:04X}: that span cannot be read back as "
            "loaded, so the verify would not cover the whole image")
    return load_addr, body, verify_len


#: LIB_MLKEM_MARK's value (src/crypto/mlkem_link.s MLKEM_MARK).
MLKEM_MARK = 0x5C


def bind_stage(prg: bytes, stage):
    """Keep *stage* only if THIS PRG is the build the labels describe.

    labels.txt is a separate file: a stale or foreign one must not widen what
    a PRG may hide in $A000-$BFFF. The PRG itself must carry the tail marker
    at the labels' marker address (the last byte of the image); otherwise no
    span is allowed and any non-zero byte there is refused as on a knob-off
    image."""
    if stage is None or len(prg) < 3:
        return None
    off = stage[1] - 1 - (prg[0] | (prg[1] << 8))
    body = prg[2:]
    if 0 <= off < len(body) and body[off] == MLKEM_MARK:
        return stage
    return None


def stage_bytes(prg: bytes, stage=None) -> int:
    """Bytes of the allowed stage span that are non-zero (up to the last one)."""
    if stage is None:
        return 0
    load_addr = prg[0] | (prg[1] << 8)
    body = prg[2:]
    lo = stage[0] - load_addr
    hi = min(stage[1] - load_addr, len(body))
    seg = body[lo:hi] if lo >= 0 else b""
    return len(seg.rstrip(b"\x00"))


def read_back(read_mem, addr: int, length: int) -> bytes:
    out = bytearray()
    while len(out) < length:
        n = min(READ_CHUNK, length - len(out))
        out += bytes(read_mem(addr + len(out), n))
    return bytes(out)


def load_verified_and_run(client, prg: bytes, *, retries: int = 1,
                          labels_path=DEFAULT_LABELS,
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
    stage = bind_stage(prg, stage_from_labels(labels_path))
    load_addr, body, verify_len = image_span(prg, stage)
    w_off, w_len = ram_window(load_addr, body)
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
        if verdict.ok and w_len:
            want = body[w_off:w_off + w_len]
            got = read_back(client.read_mem, load_addr + w_off, w_len)
            verdict = check_image_readback(want, got)
            if verdict.evidence.get("first_difference") is not None:
                first = w_off + verdict.evidence["first_difference"]
                back = bytes(w_off) + got
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
              "verified_ram_window": (f"${load_addr + w_off:04X}-"
                                      f"${load_addr + w_off + w_len - 1:04X}"
                                      if w_len else None),
              "unverified_zero_tail": len(body) - verify_len - w_len,
              "sys": entry, "attempts": attempts}
    if not verdict.ok:
        raise PrgLoadError(
            f"the PRG did not load byte-exact in {len(attempts)} attempts "
            f"({attempts}); not starting a run on an image known to be wrong")
    window = (f" and {report['verified_ram_window']} ({w_len} B)"
              if w_len else "")
    staged = stage_bytes(prg, stage)
    report["unverified_stage_bytes"] = staged
    if staged:
        print(f"NOTE: {staged} B of the $A000-$BFFF tail are the staged ML-KEM "
              "image: NOT read back (a host read there returns the BASIC "
              "ROM). tools/uci/rig_mlkem_hw.py proves the copy at $E000.",
              file=out)
    print(f"PRG verified in RAM: {report['verified']} ({verify_len} B){window}; "
          f"the other {report['unverified_zero_tail']} B of the $A000+ tail "
          f"are zero fill (or the staged image noted above), not compared — SYS{entry}", file=out)
    client.send_text(f"SYS{entry}", finish_with_return=True)
    return report


__all__ = ["HEAD_SETTLE_S", "PrgLoadError", "RAM_WINDOW", "DEFAULT_LABELS",
           "VERIFY_END", "bind_stage", "stage_bytes", "stage_from_labels",
           "image_span", "load_verified_and_run", "ram_window", "read_back"]
