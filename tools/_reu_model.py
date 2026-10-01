"""A 1764/1750-style REU at $DF00-$DF0A, for the repo's 6502 interpreter.

Enough of the register file for src/reu_exec.s and src/net/uci/cold_bank.s:
STASH / FETCH with both addresses incrementing, the execute bit with the
$FF00 trigger disabled, autoload, and status bit 6 (END OF BLOCK), which a
read clears. Addresses wrap modulo the REU's size, as a 1750/1764/U64 REU
does. Nothing else (no SWAP/VERIFY, no fixed addresses);
asking for it raises rather than doing something plausible.

`present=False` models a machine with no REU: commands do nothing. What
$DF00 then reads is open bus, so `absent_status` picks it: 0x00 makes
reu_execute's confirm expire (reu_dma_timeout), 0xFF makes it believe a
DMA that never happened -- the case only a check of the fetched bytes
catches.

Used by tools/test_cold_bank.py, tools/test_trust_store_6502.py and
tools/test_reu_body_sink.py.
"""
from __future__ import annotations


class REU:
    def __init__(self, ram: bytearray, size: int = 512 * 1024,
                 present: bool = True, absent_status: int = 0x00):
        self.ram = ram                  # the C64's 64 KB
        self.mem = bytearray(size)
        self.present = present
        self.absent_status = absent_status
        self.regs = bytearray(0x0B)
        self.status = 0x00
        self.log: list[tuple[str, int, int, int]] = []  # (op, c64, reu, len)

    def handles(self, addr: int) -> bool:
        return 0xDF00 <= addr <= 0xDF0A

    def read(self, addr: int) -> int:
        if not self.present:
            return self.absent_status
        reg = addr - 0xDF00
        if reg == 0:
            v = self.status
            self.status &= 0x1F         # bits 5-7 clear on read
            return v
        return self.regs[reg]

    def write(self, addr: int, value: int) -> None:
        if not self.present:
            return
        reg = addr - 0xDF00
        self.regs[reg] = value & 0xFF
        if reg == 1 and value & 0x80:
            self._execute(value)

    def _execute(self, cmd: int) -> None:
        if not cmd & 0x10:
            raise NotImplementedError("REU: $FF00-triggered execute")
        if self.regs[0x0A]:
            raise NotImplementedError("REU: fixed-address transfer")
        saved = bytes(self.regs)        # autoload restores them afterwards
        op = cmd & 0x03
        c64 = self.regs[2] | self.regs[3] << 8
        reu = (self.regs[4] | self.regs[5] << 8 | self.regs[6] << 16) % len(self.mem)
        n = (self.regs[7] | self.regs[8] << 8) or 0x10000
        if op == 0:
            for i in range(n):
                self.mem[(reu + i) % len(self.mem)] = self.ram[(c64 + i) & 0xFFFF]
            self.log.append(("stash", c64, reu, n))
        elif op == 1:
            for i in range(n):
                self.ram[(c64 + i) & 0xFFFF] = self.mem[(reu + i) % len(self.mem)]
            self.log.append(("fetch", c64, reu, n))
        else:
            raise NotImplementedError(f"REU: transfer type {op}")
        if cmd & 0x20:
            self.regs[2:9] = saved[2:9]
        self.status |= 0x40             # END OF BLOCK


class Bus:
    """$DF00-$DF0A to the REU, the rest of $DFxx to the UCI/DOS model."""

    def __init__(self, reu: REU, other):
        self.reu = reu
        self.other = other

    def read(self, addr: int) -> int:
        if self.reu.handles(addr):
            return self.reu.read(addr)
        return self.other.read(addr)

    def write(self, addr: int, value: int) -> None:
        if self.reu.handles(addr):
            self.reu.write(addr, value)
        else:
            self.other.write(addr, value)
