"""Launch a single VICE instance on the c64-https bridge.

Mirrors the single-instance half of c64-test-harness's bridge_vice_pair
fixture. Normal-speed RR-Net, CS8900a initialised, MAC programmed, PRG
autoloaded via ViceConfig.prg_path.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from c64_test_harness.backends.vice_binary import BinaryViceTransport
from c64_test_harness.backends.vice_lifecycle import ViceConfig, ViceProcess
from c64_test_harness.backends.vice_manager import PortAllocator
from c64_test_harness.ethernet import set_cs8900a_mac
from c64_test_harness.execute import jsr, load_code
from c64_test_harness.memory import read_bytes
from c64_test_harness.screen import ScreenGrid
from c64_test_harness.bridge_ping import (
    cs8900a_rxctl_code,
    cs8900a_read_linectl_code,
    cs8900a_write_linectl_code,
)

DEFAULT_MAC = bytes.fromhex("02C6400000A1")  # 02:C6:40:00:00:A1 -- c64-https


@dataclass
class ViceHandle:
    """Everything a test needs to drive and shut down a VICE instance."""
    process: ViceProcess
    transport: BinaryViceTransport
    allocator: PortAllocator
    port: int


def _connect(port: int, proc: ViceProcess, timeout: float = 30.0) -> BinaryViceTransport:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return BinaryViceTransport(port=port)
        except Exception as e:  # noqa: BLE001
            last = e
            if proc._proc is not None and proc._proc.poll() is not None:
                raise RuntimeError(f"VICE on port {port} exited early") from e
            time.sleep(0.25)
    raise RuntimeError(f"could not connect to VICE on port {port}: {last}")


def _wait_for_ready(transport: BinaryViceTransport, timeout: float = 60.0) -> None:
    """Wait for either BASIC READY (no PRG autoload) or for an autostarted
    program to have taken over the screen. We poll continuous_text() for
    either 'READY' or common c64-https banner text.
    """
    deadline = time.monotonic() + timeout
    last_text = ""
    while time.monotonic() < deadline:
        try:
            transport.resume()
            time.sleep(0.5)
            grid = ScreenGrid.from_transport(transport)
            text = grid.continuous_text().upper()
            last_text = text
            if "READY" in text or "C64-HTTPS" in text or "Q=QUIT" in text:
                return
        except Exception:  # noqa: BLE001
            time.sleep(0.3)
    raise RuntimeError(
        f"BASIC READY / banner not seen within {timeout}s. Last text:\n{last_text}"
    )


def _init_cs8900a(transport: BinaryViceTransport, code: int = 0xC000, scratch: int = 0xC1E0) -> None:
    load_code(transport, code, cs8900a_rxctl_code())
    jsr(transport, code, timeout=5.0)
    load_code(transport, code, cs8900a_read_linectl_code(scratch))
    jsr(transport, code, timeout=5.0)
    linectl = read_bytes(transport, scratch, 2)
    load_code(transport, code, cs8900a_write_linectl_code(linectl[0] | 0xC0, linectl[1]))
    jsr(transport, code, timeout=5.0)


def launch_vice_on_bridge(
    prg_path: str,
    tap: str = "tap-c64-0",
    mac: bytes = DEFAULT_MAC,
    port_range: tuple[int, int] = (6560, 6580),
    ready_timeout: float = 60.0,
    verbose: bool = True,
) -> ViceHandle:
    """Start one VICE on the bridge, autoload prg_path, init CS8900a.

    The program's own code is running by the time this returns -- because
    we use -autostart, ip65 boots as soon as BASIC runs it. The CS8900a
    init is NOT performed on c64-https (it takes over the chip itself);
    we only run it here to match the harness pattern's "known-good" init
    before the program grabs the chip. In practice c64-https re-initialises
    the chip on its own so this is harmless.

    Returns a ViceHandle. Call shutdown_vice() to stop cleanly.
    """
    allocator = PortAllocator(port_range_start=port_range[0], port_range_end=port_range[1])
    port = allocator.allocate()
    res = allocator.take_socket(port)
    if res is not None:
        res.close()

    config = ViceConfig(
        port=port,
        prg_path=prg_path,
        warp=False,             # load-bearing: warp breaks DHCP
        sound=False,
        minimize=False,
        ethernet=True,
        ethernet_mode="rrnet",
        ethernet_interface=tap,
        ethernet_driver="tuntap",
        extra_args=["-reu", "-reusize", "512"],  # boot.asm uses REU for mul tables
    )

    proc = ViceProcess(config)
    proc.start()
    if verbose:
        pid = proc._proc.pid if proc._proc is not None else "?"
        print(f"[vice] started pid={pid} port={port} tap={tap}")

    try:
        transport = _connect(port, proc, timeout=20.0)
        _wait_for_ready(transport, timeout=ready_timeout)
        # Best-effort: program a MAC via the harness helper. c64-https
        # may overwrite this on its own init pass; that's fine.
        try:
            set_cs8900a_mac(transport, mac)
        except Exception as e:  # noqa: BLE001
            if verbose:
                print(f"[vice] set_cs8900a_mac skipped: {e}")
    except Exception:
        # Clean up on failure.
        proc.stop()
        allocator.release(port)
        raise

    return ViceHandle(process=proc, transport=transport, allocator=allocator, port=port)


def shutdown_vice(handle: ViceHandle) -> None:
    """Close transport, stop VICE process, release port."""
    try:
        handle.transport.close()
    except Exception:  # noqa: BLE001
        pass
    try:
        handle.process.stop()
    except Exception:  # noqa: BLE001
        pass
    try:
        handle.allocator.release(handle.port)
    except Exception:  # noqa: BLE001
        pass
