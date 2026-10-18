#!/usr/bin/env python3
"""S4 spike: REU DMA wall time vs size on the U64E at 1 and 48 MHz.

Times C64->REU ($90) and REU->C64 ($91) transfers of N bytes, each followed
by a clone of src/reu_exec.s's REU_CONFIRM_LONG confirm + settle, with CIA2
timer A (realtime ~1.0227 MHz phi2 under turbo, per
tools/probe_cia_timer_rate.py). Timer is stopped before it is read.
Negative control: a fixed CPU loop, which must shrink ~48x at turbo.
"""
import os, sys, time, json, subprocess, tempfile
from pathlib import Path
sys.path.insert(0, "/Users/someone/Documents/c64-test-harness/src")
sys.path.insert(0, "/Users/someone/Documents/c64-https-wt/p2-s4/tools/uci")
from c64_test_harness import DeviceLock, probe_u64, read_bytes, send_text, wait_for_text, write_bytes
from c64_test_harness.backends.ultimate64 import Ultimate64Transport
from c64_test_harness.backends.ultimate64_client import Ultimate64Client, Ultimate64RunnerStuckError
from c64_test_harness.backends.ultimate64_helpers import get_turbo_mhz, recover, runner_health_check, set_reu, set_turbo_mhz, get_reu_config
from _device_lock_helper import acquire_device_lock

HOST = os.environ.get("U64_HOST", "10.43.23.81")
CLOCKS = [int(x) for x in os.environ.get("CLOCKS", "1,48").split(",")]
SIZES = [1, 256, 1024, 4096, 7680, 10240, 16384, 32768]
REPS = 3
CODE, DATA = 0xC000, 0xC800
SRC = r"""
DATA = $c800
NSIZES = %d
REPS = %d
sizes_lo = DATA+$00
sizes_hi = DATA+$10
res      = DATA+$20      ; [size][dir][rep] x 2 bytes
ctrl     = DATA+$e0      ; 2 bytes cpu-loop control
flag     = DATA+$e2      ; confirm-expiry count
done     = DATA+$e3
si = $fb
di = $fc
ri = $fd
ptr = $fe
cnt = DATA+$e4
start:  sei
wait:   lda DATA+$e5
        beq wait
        lda #0
        sta DATA+$e5
        sta done
        sta flag
        sta ptr
        lda #$7f
        sta $dd0d
        ; CPU control loop
        jsr tstart
        ldy #10
        ldx #0
cl:     dex
        bne cl
        dey
        bne cl
        jsr tstop
        sta ctrl
        stx ctrl+1
        lda #<res
        sta ptr
        lda #>res
        sta ptr+1
        lda #0
        sta si
szl:    lda #0
        sta di
dirl:   lda #0
        sta ri
repl:   ldx si
        lda #$00
        sta $df02
        lda #$20
        sta $df03          ; C64 $2000
        lda #0
        sta $df04
        sta $df05
        lda #1
        sta $df06          ; REU $01:0000
        lda sizes_lo,x
        sta $df07
        lda sizes_hi,x
        sta $df08
        lda #0
        sta $df0a
        lda di
        ora #$90           ; $90 stash / $91 fetch
        pha
        jsr tstart
        pla
        jsr reu_exec
        jsr tstop
        ldy #0
        sta (ptr),y
        iny
        txa
        sta (ptr),y
        clc
        lda ptr
        adc #2
        sta ptr
        inc ri
        lda ri
        cmp #REPS
        bne repl
        inc di
        lda di
        cmp #2
        bne dirl
        inc si
        lda si
        cmp #NSIZES
        bne szl
        lda #$5a
        sta done
        jmp wait
tstart: lda #0
        sta $dd0e
        lda #$ff
        sta $dd04
        sta $dd05
        lda #$11           ; force load + start, continuous
        sta $dd0e
        rts
tstop:  ldy #0
        sty $dd0e          ; stop
        lda $dd04
        eor #$ff
        pha
        lda $dd05
        eor #$ff
        tax
        pla
        rts
; clone of src/reu_exec.s REU_CONFIRM_LONG
reu_exec:
        sta $df01
        lda #0
        sta cnt
        sta cnt+1
@spin:  bit $df00
        bvs @settle
        inc cnt
        bne @spin
        inc cnt+1
        bne @spin
        inc flag
@settle:
        lda #10
        sta cnt
@sl:    dec cnt
        bne @sl
        rts
""" % (len(SIZES), REPS)
CFG = "MEMORY { RAM: start=$C000, size=$0800, file=%O; } SEGMENTS { CODE: load=RAM, type=ro; }\n"

def assemble():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td); (d/"p.s").write_text(SRC); (d/"p.cfg").write_text(CFG)
        subprocess.run(["ca65", "-o", str(d/"p.o"), str(d/"p.s")], check=True)
        subprocess.run(["ld65", "-C", str(d/"p.cfg"), "-o", str(d/"p.bin"), str(d/"p.o")], check=True)
        return (d/"p.bin").read_bytes()

def one(tr, image):
    tr.reset()
    if wait_for_text(tr, "READY.", timeout=45.0, poll_interval=0.3, verbose=False) is None:
        raise RuntimeError("no READY.")
    time.sleep(0.5)
    write_bytes(tr, DATA, bytes(256))
    tbl = bytes([s & 0xff for s in SIZES] + [0]*(16-len(SIZES)) + [(s >> 8) & 0xff for s in SIZES])
    write_bytes(tr, CODE, image); write_bytes(tr, DATA, tbl)
    if bytes(read_bytes(tr, CODE, len(image))) != image or bytes(read_bytes(tr, DATA, len(tbl))) != tbl:
        raise RuntimeError("readback mismatch")
    send_text(tr, f"SYS{CODE}\r")
    passes = []
    for ps in range(int(os.environ.get("PASSES", "3"))):
        time.sleep(float(os.environ.get("PASS_GAP", "3")))
        passes.append(one_pass(tr))
        print("   pass", ps, "ctrl", passes[-1]["ctrl_ticks"], "32768 fetch", passes[-1]["ticks"]["32768:fetch"], flush=True)
    return passes

def one_pass(tr):
    write_bytes(tr, DATA + 0xe3, bytes([0]))
    write_bytes(tr, DATA + 0xe5, bytes([1]))
    for _ in range(100):
        time.sleep(0.2)
        blk = bytes(read_bytes(tr, DATA, 0x100))
        if blk[0xe3] == 0x5a:
            break
    else:
        raise RuntimeError("probe never finished")
    res = {}
    for i, n in enumerate(SIZES):
        for dname, di in (("stash", 0), ("fetch", 1)):
            vals = []
            for r in range(REPS):
                o = 0x20 + ((i*2 + di)*REPS + r)*2
                vals.append(blk[o] | blk[o+1] << 8)
            res[f"{n}:{dname}"] = vals
    return {"ctrl_ticks": blk[0xe0] | blk[0xe1] << 8, "confirm_expired": blk[0xe2], "ticks": res}

def main():
    image = assemble()
    print(f"probe {len(image)} B")
    lock = DeviceLock(HOST)
    acquire_device_lock(lock)
    client = None; out = {}
    try:
        client = Ultimate64Client(host=HOST, timeout=60.0)
        tr = Ultimate64Transport(host=HOST, timeout=60.0, client=client)
        try:
            runner_health_check(client)
        except Ultimate64RunnerStuckError:
            recover(client); runner_health_check(client)
        out["product"] = client.get_info().get("product")
        out["reu_before"] = get_reu_config(client)
        set_reu(client, os.environ.get("REU","1")=="1")
        out["reu_after"] = get_reu_config(client)
        for mhz in CLOCKS:
            set_turbo_mhz(client, mhz)
            time.sleep(3.0)
            rep = get_turbo_mhz(client)
            r = {"passes": one(tr, image), "reported_mhz": rep}
            out[str(mhz)] = r
            print(mhz, json.dumps(r))
    finally:
        if client is not None:
            try:
                set_turbo_mhz(client, 1); set_reu(client, False); client.reset()
            except Exception as e:
                print("restore failed", e)
        lock.release()
    print(json.dumps(out, indent=1))
    Path(os.environ.get("OUT", "reu_dma.json")).write_text(json.dumps(out, indent=1))

if __name__ == "__main__":
    main()
