#!/usr/bin/env python3
"""check_prg_io_range.py -- no image may load into the I/O page (#288).

A KERNAL LOAD (disk, .d64, a real 1541) stores every byte of a PRG with
the CPU, and with the default $01 every byte at $D000-$DFFF lands in a
chip register (VIC-II, SID, colour RAM, the CIAs). Measured in VICE under
true drive emulation, the old 55,297 B UCI images froze the load with its
pointer in CIA1's page ($DC06, $DC09 and $DC0A observed). On a U64 the DMA
load (Ultimate64Client.load_prg) of the old image left $D020/$D021/
$DC02/$DC03/$DD02 unchanged, so there only RAM changes.

Two checks, both pure:

  cfg  where each file-backed MEMORY area of an ld65 cfg LOADS, from file
       order: the first area writing the output file is the two-byte load
       address header (start + 2 is the load address), and each later area
       lands at the load address plus the bytes written before it. A
       `fill = yes` area writes its whole size; any other area writes up to
       its size if a segment that is not bss/zp loads into it, else
       nothing. Sizes and starts may be expressions; anything this cannot
       parse or evaluate is an error (fail closed), never a pass.
  PRG  a linked PRG's load range: load address + body length.

    python3 tools/check_prg_io_range.py [--cfg CFG ...] [PRG ...]

Exit 0 clean, 1 an image reaches the I/O page or an input could not be
checked. tools/test_prg_io_range.py is its test (pytest testpaths);
make package-verify runs the PRG half on every dist/*.prg.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

IO_LO, IO_HI = 0xD000, 0xDFFF            # inclusive
NO_OUTPUT_TYPES = {"bss", "zp"}


class CfgError(ValueError):
    """The cfg has a shape this checker does not understand."""


# --- expression evaluation ----------------------------------------------------
_ALLOWED = (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant, ast.Add,
            ast.Sub, ast.Mult, ast.FloorDiv, ast.Div, ast.USub, ast.UAdd)


def eval_expr(text: str) -> int:
    """Evaluate an ld65 numeric expression: $hex, %bin, decimal, + - * / ()."""
    src = text.strip()
    if not src:
        raise CfgError("empty expression")
    py = re.sub(r"\$([0-9A-Fa-f]+)", r"0x\1", src)
    py = re.sub(r"%([01]+)\b", r"0b\1", py)
    py = py.replace("/", "//")
    try:
        tree = ast.parse(py, mode="eval")
    except SyntaxError as e:
        raise CfgError(f"cannot parse expression {text!r}") from e
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED) or (
                isinstance(node, ast.Constant) and not isinstance(node.value, int)):
            raise CfgError(f"cannot evaluate expression {text!r}")
    return int(eval(compile(tree, "<cfg>", "eval"), {"__builtins__": {}}))


# --- cfg parsing ----------------------------------------------------------------
def _block(text: str, name: str) -> str:
    m = re.search(r"\b" + name + r"\s*\{", text)
    if not m:
        raise CfgError(f"no {name} block")
    end = text.find("}", m.end())
    if end < 0:
        raise CfgError(f"{name} block is not closed")
    return text[m.end():end]


def _entries(block: str, what: str) -> list[tuple[str, dict[str, str]]]:
    """`NAME: key = value, ...;` entries, newlines anywhere."""
    out = []
    for raw in block.split(";"):
        body = " ".join(raw.split())
        if not body:
            continue
        m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)", body)
        if not m:
            raise CfgError(f"cannot parse {what} entry {body!r}")
        attrs = {}
        for part in m.group(2).split(","):
            kv = part.split("=", 1)
            if len(kv) != 2 or not kv[0].strip():
                raise CfgError(f"{m.group(1)}: cannot parse attribute {part.strip()!r}")
            attrs[kv[0].strip().lower()] = kv[1].strip()
        out.append((m.group(1), attrs))
    if not out:
        raise CfgError(f"{what} block has no entries")
    return out


def load_map(cfg_text: str) -> list[dict]:
    """Each output-writing area of the main output file, with the address
    range its bytes LOAD to (upper bound for a non-fill area)."""
    text = re.sub(r"#[^\n]*", "", cfg_text)
    areas = _entries(_block(text, "MEMORY"), "MEMORY")
    segs = _entries(_block(text, "SEGMENTS"), "SEGMENTS")
    loaded_types: dict[str, set[str]] = {}
    for name, a in segs:
        if "load" not in a:
            raise CfgError(f"segment {name} has no load =")
        loaded_types.setdefault(a["load"], set()).add(a.get("type", "ro").lower())

    out, load_addr, off = [], None, 0
    for name, a in areas:
        if a.get("file", "%O") != "%O":      # "" or another output file
            continue
        try:
            start, size = eval_expr(a["start"]), eval_expr(a["size"])
        except KeyError as e:
            raise CfgError(f"area {name} has no {e.args[0]} =") from e
        fill = a.get("fill", "no").lower() == "yes"
        writes = fill or bool(loaded_types.get(name, set()) - NO_OUTPUT_TYPES)
        if not writes:
            continue
        if load_addr is None:
            if size != 2:
                raise CfgError(f"first output area {name} is {size} B, not a "
                               "2-byte load-address header")
            load_addr = start + size
            continue
        lo = load_addr + off
        out.append({"name": name, "lo": lo, "hi": lo + size - 1, "fill": fill})
        off += size
    if load_addr is None:
        raise CfgError("no area writes the output file")
    return out


def cfg_io_violations(cfg_text: str) -> list[str]:
    """Output-writing areas whose bytes would load into $D000-$DFFF."""
    return [f"{a['name']} loads ${a['lo']:04X}-${a['hi']:04X}"
            + ("" if a["fill"] else " (upper bound)")
            for a in load_map(cfg_text) if not (a["hi"] < IO_LO or a["lo"] > IO_HI)]


# --- PRG ----------------------------------------------------------------------
def prg_range(prg: bytes) -> tuple[int, int]:
    if len(prg) < 3:
        raise ValueError(f"PRG is {len(prg)} bytes")
    la = prg[0] | prg[1] << 8
    return la, la + len(prg) - 3


def prg_io_violation(prg: bytes) -> str | None:
    lo, hi = prg_range(prg)
    if hi < IO_LO or lo > IO_HI:
        return None
    return f"loads ${lo:04X}-${hi:04X}, into ${max(lo, IO_LO):04X}-${min(hi, IO_HI):04X}"


def main(argv: list[str]) -> int:
    cfgs, prgs, it = [], [], iter(argv)
    for a in it:
        if a == "--cfg":
            cfgs.append(Path(next(it)))
        else:
            prgs.append(Path(a))
    if not cfgs and not prgs:
        print("usage: check_prg_io_range.py [--cfg CFG ...] [PRG ...]",
              file=sys.stderr)
        return 1
    bad = 0
    for p in cfgs:
        try:
            v = cfg_io_violations(p.read_text())
        except (OSError, CfgError) as e:
            v = [f"cannot check: {e}"]
        for line in v:
            print(f"ERROR: {p}: {line}")
        bad += bool(v)
    for p in prgs:
        try:
            v = prg_io_violation(p.read_bytes())
        except (OSError, ValueError) as e:
            v = f"cannot check: {e}"
        if v:
            print(f"ERROR: {p}: {v}")
        bad += bool(v)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
