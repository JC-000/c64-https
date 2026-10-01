"""_petscii_keys.py - keystrokes for the typed HTTPS target prompt (UCI 'G').

The harness's char_to_petscii maps 'a' and 'A' to the same code and '_' to
$A4, so it cannot type a mixed-case path. This is what a person presses:
unshifted letters $41-$5A (stored lowercase), shifted $C1-$DA (stored
uppercase), '_' as the left-arrow key $5F, '\\r' RETURN, '\\x7f' DEL.
See https_target_prompt in src/boot.s for how the C64 side reads them.
"""
from __future__ import annotations

import time

KEY_RETURN = 0x0D
KEY_DEL = 0x14
KEYBUF = 0x0277
KEYBUF_COUNT = 0x00C6
KEYBUF_MAX = 10


def target_keys(text: str) -> list[int]:
    out = []
    for ch in text:
        o = ord(ch)
        if "a" <= ch <= "z":
            out.append(o - 0x20)
        elif "A" <= ch <= "Z":
            out.append(o + 0x80)
        elif ch == "\r":
            out.append(KEY_RETURN)
        elif ch == "\x7f":
            out.append(KEY_DEL)
        elif 0x20 <= o <= 0x5F:
            out.append(o)
        else:
            raise ValueError(f"no key for {ch!r}")
    return out


def push_keys(client, codes: list[int], budget: float = 30.0) -> None:
    """Feed raw key codes to an Ultimate64Client's KERNAL buffer.

    Same discipline as the client's own send_text: write a chunk only into
    an EMPTY buffer, so the $C6 count write is the single publication step
    and a KERNAL dequeue can never land between our read and our write.
    """
    remaining = list(codes)
    deadline = time.monotonic() + budget
    while remaining:
        if time.monotonic() > deadline:
            raise TimeoutError(f"keyboard buffer never drained "
                               f"({len(remaining)} keys pending)")
        if client.read_mem(KEYBUF_COUNT, 1)[0] != 0:
            time.sleep(0.05)
            continue
        chunk = remaining[:KEYBUF_MAX]
        remaining = remaining[KEYBUF_MAX:]
        client.write_mem(KEYBUF, bytes(chunk))
        client.write_mem(KEYBUF_COUNT, bytes([len(chunk)]))
