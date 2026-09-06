#!/usr/bin/env python3
"""tools/probe_cia_timer_rate.py — do the CIA timers scale with the CPU?

THE QUESTION, AND WHY IT MATTERS
================================
ip65's C64 timer driver (`ip65/drivers/c64timer.s`) programs CIA2 timer A
to 1000 cycles, continuous, cascaded into timer B, and `timer_read`
returns timer B. **CIA timers count phi2 cycles.** `ip65/ip65/dhcp.s`
budgets `MAX_DHCP_MESSAGES_SENT = 12` retries with growing backoff, about
15 seconds — but that is 15 seconds only if a "tick" is a millisecond.

So: on a U64 at 48 MHz, are the CIA timers still clocked at a real 1 MHz,
or do they scale with the CPU? If they scale, ip65's whole DHCP budget
compresses ~48x to ~0.3 s and every turbo run needs a 1 MHz assist to
acquire a lease.

**CLAUDE.md's CIA1 TOD measurement does not answer this.** TOD is a
different clock domain, fed from mains rather than phi2; that it runs at
wall rate under turbo says nothing about timers A and B. Hence this probe.

THE ANSWER (U64E "Ultimate 64 Elite", 2026-09-06, n=6 intervals each)
=====================================================================
    1 MHz    mean 1023.2 ticks/wall-second
    48 MHz   mean 1022.9 ticks/wall-second
    ratio    1.000

The timers are REALTIME. Two things make that more than a ratio:

  * The absolute value is right. NTSC phi2 is 1,022,727 Hz and timer A is
    1000 cycles, so the prediction is 1022.7 ticks/s. Both clocks land
    inside 0.05% of it. A phi2-scaled timer would have read ~49,000/s.
  * The negative control: the same probe's loop-iteration counter DID
    scale — 6,266/s at 1 MHz against 152,396/s at 48 MHz, a factor of
    24.3 — so the 6510 was demonstrably at turbo while the timer it was
    reading was not. Without it, a turbo write that silently did nothing
    gives the same flat tick rate. (24.3x rather than 48x because the
    loop's three CIA register reads are stretched to bus speed.)

Confirmed independently on the live path the same day:
`tests/rig_ip65_rrnet_hw.py` with `TURBO_MHZ=48` acquired its DHCP lease
on the automatic attempt, zero retries.

METHOD
======
A 271-byte standalone program at $CA00 programs CIA2 exactly as ip65's
`timer_init` does, then loops reading timer B.

UNWRAPPING — timer B is a 16-bit DOWN counter that ip65 inverts, so the
inverted value wraps every 65536 ticks. **The margin here is budgeted
against the hypothesis being REFUTED, not the one expected, and the two
differ by 48x — which is why the figure below looks wrong until you read
this sentence.** If the timers are realtime the wrap period is 65.5 s; if
they scale with a 48 MHz CPU it is **1.37 s**, and 1.37 s is the number
this probe is built to survive. That matters because the aliasing points
the wrong way: a host reading raw 16-bit values across a 15 s interval
under the scaling hypothesis would alias, and would alias *towards* the
answer "about 1000/s" — it would manufacture the realtime result it was
supposed to test for.

So this probe never exports a raw value: the C64 accumulates the MODULAR
16-bit difference between consecutive samples into a 32-bit counter. The
loop period is microseconds against that 1.37 s worst case, so no single
delta can alias under either hypothesis, and the interval length stops
mattering.

TORN READS — the host does not read a counter the loop is updating. It
writes REQ; the loop copies the accumulator, its iteration count and the
CIA1 TOD into a publish block nothing else writes, clears REQ and bumps
SERVED. The timestamp is the midpoint of the REQ write and its span is
reported (0.02-0.16 s against 15 s intervals); the loop services REQ
within one loop period.

CIA1 TOD is published as a control, not as evidence for the answer.

USAGE
=====
    U64_HOST=10.43.23.81 python3 tools/probe_cia_timer_rate.py

    CLOCKS=1,48   RUNS=3   SAMPLES=3   GAP_S=15   (defaults)

Exit codes: 0 measured / 2 could not run.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
for _p in ("/Users/someone/Documents/c64-test-harness/src",):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

from c64_test_harness import (                                     # noqa: E402
    DeviceLock, DeviceLockTimeout, probe_u64, read_bytes, send_text,
    wait_for_text, write_bytes,
)
from c64_test_harness.backends.ultimate64 import Ultimate64Transport   # noqa: E402
from c64_test_harness.backends.ultimate64_client import (          # noqa: E402
    Ultimate64Client, Ultimate64RunnerStuckError,
)
from c64_test_harness.backends.ultimate64_helpers import (         # noqa: E402
    get_turbo_mhz, recover, runner_health_check, set_reu, set_turbo_mhz,
)

CODE = 0xCA00
DATA = 0xCC00
REQ = DATA + 0x00
U64_HOST = os.environ.get("U64_HOST", "10.43.23.81")
CLOCKS = [int(x) for x in os.environ.get("CLOCKS", "1,48").split(",")]
RUNS = int(os.environ.get("RUNS", "3"))
SAMPLES = int(os.environ.get("SAMPLES", "3"))
GAP_S = float(os.environ.get("GAP_S", "15"))
CA65 = os.environ.get("CA65", "ca65")
LD65 = os.environ.get("LD65", "ld65")

#: The CIA2 setup below is `timer_init` from ip65/drivers/c64timer.s
#: verbatim. If that driver ever changes, this probe stops measuring what
#: ip65 does — re-read it before trusting a number from here.
PROBE_S = r"""
DATA      = $cc00
REQ       = DATA + $00
SERVED    = DATA + $01
PUB_ACC   = DATA + $02
PUB_LOOP  = DATA + $06
PUB_TOD   = DATA + $09
PUB_RAW   = DATA + $0d
MAGIC     = DATA + $0f
acc0      = DATA + $10
acc1      = DATA + $11
acc2      = DATA + $12
acc3      = DATA + $13
loop0     = DATA + $14
loop1     = DATA + $15
loop2     = DATA + $16
prev_lo   = DATA + $17
prev_hi   = DATA + $18
cur_lo    = DATA + $19
cur_hi    = DATA + $1a
dlo       = DATA + $1b
dhi       = DATA + $1c

start:
        sei
        lda #$80                  ; ---- ip65 timer_init, verbatim ----
        sta $dd0e
        sta $dd0f
        lda #<999                 ; timer A to 1000 cycles
        sta $dd04
        lda #>999
        sta $dd05
        lda #$ff                  ; timer B to max
        sta $dd06
        sta $dd07
        lda #$81                  ; timer A continuous
        sta $dd0e
        lda #$c1                  ; timer B counts timer A underflows
        sta $dd0f
        lda #0
        sta $dc08                 ; also starts CIA1 TOD (the control)
        sta $dc09
        lda #0
        ldx #$1f
clr:    sta DATA,x
        dex
        bpl clr
        jsr readtb
        sta prev_lo
        stx prev_hi
        lda #$5a
        sta MAGIC
main:
        inc loop0
        bne rd
        inc loop1
        bne rd
        inc loop2
rd:
        jsr readtb
        sta cur_lo
        stx cur_hi
        sec                       ; acc32 += (cur16 - prev16) mod 65536
        lda cur_lo
        sbc prev_lo
        sta dlo
        lda cur_hi
        sbc prev_hi
        sta dhi
        clc
        lda acc0
        adc dlo
        sta acc0
        lda acc1
        adc dhi
        sta acc1
        lda acc2
        adc #0
        sta acc2
        lda acc3
        adc #0
        sta acc3
        lda cur_lo
        sta prev_lo
        lda cur_hi
        sta prev_hi
        lda REQ
        beq main
        lda acc0                  ; ---- publish ----
        sta PUB_ACC+0
        lda acc1
        sta PUB_ACC+1
        lda acc2
        sta PUB_ACC+2
        lda acc3
        sta PUB_ACC+3
        lda loop0
        sta PUB_LOOP+0
        lda loop1
        sta PUB_LOOP+1
        lda loop2
        sta PUB_LOOP+2
        lda cur_lo
        sta PUB_RAW+0
        lda cur_hi
        sta PUB_RAW+1
        lda $dc0b                 ; hours: latches the TOD registers
        sta PUB_TOD+3
        lda $dc0a
        sta PUB_TOD+2
        lda $dc09
        sta PUB_TOD+1
        lda $dc08                 ; tenths: unlatches
        sta PUB_TOD+0
        lda #0
        sta REQ
        inc SERVED
        jmp main

; A = low, X = high of the INVERTED (up-counting) timer B value. The pair
; is re-read until the high byte is stable, so a borrow between the two
; reads cannot tear the sample.
readtb:
        ldx $dd07
        lda $dd06
        cpx $dd07
        bne readtb
        eor #$ff
        pha
        txa
        eor #$ff
        tax
        pla
        rts
"""

PROBE_CFG = """MEMORY {
    RAM: start = $CA00, size = $0180, type = rw, file = %O, fill = no;
}
SEGMENTS {
    CODE: load = RAM, type = ro;
}
"""


def assemble() -> bytes:
    """ca65 + ld65 the probe into a raw image located at $CA00."""
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "probe.s").write_text(PROBE_S)
        (d / "probe.cfg").write_text(PROBE_CFG)
        subprocess.run([CA65, "-t", "c64", "-o", str(d / "probe.o"),
                        str(d / "probe.s")], check=True, capture_output=True)
        subprocess.run([LD65, "-C", str(d / "probe.cfg"), "-o",
                        str(d / "probe.bin"), str(d / "probe.o")],
                       check=True, capture_output=True)
        image = (d / "probe.bin").read_bytes()
    if CODE + len(image) > DATA:
        raise RuntimeError(f"probe code ({len(image)} B at ${CODE:04X}) "
                           f"overruns its data block at ${DATA:04X}")
    return image


def bcd(b: int) -> int:
    return (b >> 4) * 10 + (b & 0x0F)


def sample(tr) -> tuple:
    before = read_bytes(tr, DATA, 16)
    t0 = time.monotonic()
    tr.write_memory(REQ, bytes([1]))
    t1 = time.monotonic()
    deadline = t1 + 5.0
    while time.monotonic() < deadline:
        blk = bytes(read_bytes(tr, DATA, 16))
        if blk[1] != before[1] and blk[0] == 0:
            break
        time.sleep(0.05)
    else:
        raise RuntimeError(f"loop never serviced REQ (block={before.hex()})")
    tod = (bcd(blk[12]) * 3600 + bcd(blk[11]) * 60 + bcd(blk[10])
           + blk[9] * 0.1)
    return (t0 + t1) / 2.0, {
        "t_write_span_s": round(t1 - t0, 4),
        "acc": int.from_bytes(blk[2:6], "little"),
        "loop": int.from_bytes(blk[6:9], "little"),
        "tod_s": round(tod, 1),
        "raw_inverted_tb": int.from_bytes(blk[13:15], "little"),
        "magic": blk[15], "served": blk[1],
    }


def one_run(tr, image: bytes) -> list:
    tr.reset()
    if wait_for_text(tr, "READY.", timeout=45.0, poll_interval=0.3,
                     verbose=False) is None:
        raise RuntimeError("no READY. after reset")
    time.sleep(0.5)
    write_bytes(tr, CODE, image)
    back = bytes(read_bytes(tr, CODE, len(image)))
    if back != image:
        bad = next(i for i in range(len(image)) if back[i] != image[i])
        raise RuntimeError(f"probe readback differs at +{bad} "
                           f"({image[bad]:02x} -> {back[bad]:02x})")
    send_text(tr, f"SYS{CODE}\r")
    time.sleep(1.5)
    blk = bytes(read_bytes(tr, DATA, 16))
    if blk[15] != 0x5A:
        raise RuntimeError(f"probe did not start (MAGIC=${blk[15]:02x})")
    pts = []
    for i in range(SAMPLES):
        if i:
            time.sleep(GAP_S)
        t, d = sample(tr)
        pts.append((t, d))
        print(f"      sample {i}: acc={d['acc']:>10d} loop={d['loop']:>9d} "
              f"tod={d['tod_s']:>8.1f}s span={d['t_write_span_s']}s")
    return pts


def main() -> int:
    out: dict = {"host": U64_HOST, "clocks": {}}
    try:
        image = assemble()
    except (OSError, subprocess.CalledProcessError) as exc:
        err = getattr(exc, "stderr", b"") or b""
        print(f"CANNOT RUN: could not assemble the probe ({exc}) "
              f"{err.decode(errors='replace')[:400]}")
        return 2
    print(f"probe {len(image)} bytes -> ${CODE:04X}, data ${DATA:04X}")

    pr = probe_u64(U64_HOST)
    if not getattr(pr, "reachable", bool(pr)):
        print(f"CANNOT RUN: {U64_HOST} unreachable: {pr}")
        return 2
    lock = DeviceLock(U64_HOST)
    try:
        lock.acquire_or_raise(timeout=180.0)
    except DeviceLockTimeout as exc:
        print(f"CANNOT RUN: {exc}")
        return 2

    client = None
    try:
        client = Ultimate64Client(host=U64_HOST, timeout=60.0)
        tr = Ultimate64Transport(host=U64_HOST, timeout=60.0, client=client)
        try:
            runner_health_check(client)
        except Ultimate64RunnerStuckError as exc:
            print(f"  runner wedged ({exc}); recovering")
            recover(client)
            runner_health_check(client)
        try:
            out["product"] = client.get_info().get("product")
        except Exception as exc:                                 # noqa: BLE001
            out["product"] = f"unreadable: {exc}"
        set_reu(client, False)
        for mhz in CLOCKS:
            print(f"=== clock {mhz} MHz ===")
            set_turbo_mhz(client, mhz)
            time.sleep(3.0)
            reported = get_turbo_mhz(client)
            print(f"  device reports {reported} MHz")
            runs = []
            for r in range(RUNS):
                print(f"    run {r + 1}/{RUNS}")
                try:
                    pts = one_run(tr, image)
                except Exception as exc:                         # noqa: BLE001
                    print(f"      FAILED: {type(exc).__name__}: {exc}")
                    runs.append({"error": f"{type(exc).__name__}: {exc}"})
                    continue
                ivals = []
                for a, b in zip(pts, pts[1:]):
                    dt = b[0] - a[0]
                    row = {
                        "wall_s": round(dt, 3),
                        "ticks": b[1]["acc"] - a[1]["acc"],
                        "ticks_per_wall_s":
                            round((b[1]["acc"] - a[1]["acc"]) / dt, 1),
                        "loop_iters_per_wall_s":
                            round((b[1]["loop"] - a[1]["loop"]) / dt, 1),
                        "tod_over_wall":
                            round((b[1]["tod_s"] - a[1]["tod_s"]) / dt, 4),
                    }
                    ivals.append(row)
                    print(f"      {row['wall_s']:7.3f}s wall -> "
                          f"{row['ticks']:>9d} ticks = "
                          f"{row['ticks_per_wall_s']:>9.1f} ticks/s "
                          f"(loop {row['loop_iters_per_wall_s']:.0f}/s, "
                          f"TOD/wall {row['tod_over_wall']})")
                runs.append({"samples": [d for _, d in pts],
                             "intervals": ivals})
            rates = [i["ticks_per_wall_s"] for run in runs
                     for i in run.get("intervals", [])]
            out["clocks"][str(mhz)] = {
                "reported_mhz": reported, "runs": runs, "rates": rates,
                "mean_ticks_per_s":
                    round(sum(rates) / len(rates), 1) if rates else None}
            if rates:
                print(f"  => {mhz} MHz: mean {sum(rates) / len(rates):.1f} "
                      f"ticks/wall-second over n={len(rates)} intervals "
                      f"(min {min(rates):.1f} max {max(rates):.1f})")
    finally:
        if client is not None:
            try:
                set_turbo_mhz(client, 1)
                set_reu(client, False)
                client.reset()
            except Exception as exc:                             # noqa: BLE001
                print(f"  restore FAILED: {exc}")
        lock.release()
        print("  device lock released")

    lo, hi = str(CLOCKS[0]), str(CLOCKS[-1])
    a = out["clocks"].get(lo, {}).get("mean_ticks_per_s")
    b = out["clocks"].get(hi, {}).get("mean_ticks_per_s")
    if a and b:
        out["ratio"] = round(b / a, 3)
        print(f"\nRATIO {hi} MHz / {lo} MHz = {out['ratio']}  "
              f"(~1.0 = realtime timers, ip65's DHCP budget survives turbo; "
              f"~{int(CLOCKS[-1])} = phi2-scaled, the budget collapses)")
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
