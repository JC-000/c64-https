#!/usr/bin/env python3
"""The HMAC_DRBG's state has one owner: src/crypto/hmac_drbg.s.

``hmac_key`` is the key input of ``hmac_sha256`` and HKDF and the Finished
MAC write it. It used to be the DRBG's K as well, so every handshake left K
holding a key-schedule secret and the next ``tls_connect``'s ECDHE private
key followed from it. K is now ``drbg_k``, which only hmac_drbg.s names.

This pins the source shape that keeps it that way, in milliseconds and with
no build. ``tools/test_drbg_isolation.py`` is the behavioural check (VICE):

1. ``drbg_k`` is defined in hmac_drbg.s and named by no other file under
   src/, and hmac_drbg.s does not export it -- so a module that tries to
   write it fails the link.
2. Inside the DRBG routines (``hmac_drbg_update`` onward) no HMAC is keyed
   from ``hmac_key`` directly: there is no ``jsr hmac_sha256`` and no store
   to ``hmac_key``. Every DRBG HMAC goes through ``drbg_hmac``, which loads
   K first.
3. ``hmac_val`` (V) is stored to only by hmac_drbg.s.
4. ``drbg_hmac`` is exactly the drbg_k -> hmac_key copy and falls into
   ``hmac_sha256``: a copy the other way round would make K whatever HKDF
   left in hmac_key, and every check above would still hold.

Runs under pytest, and standalone::

    python3 tools/test_drbg_state_owner.py
"""

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src"
DRBG = SRC / "crypto" / "hmac_drbg.s"


def _code(path: Path) -> list[str]:
    """Source lines with ';' comments stripped (outside string literals)."""
    out = []
    for line in path.read_text(errors="replace").splitlines():
        in_str = False
        for i, ch in enumerate(line):
            if ch == '"':
                in_str = not in_str
            elif ch == ";" and not in_str:
                line = line[:i]
                break
        out.append(line)
    return out


def _sources() -> list[Path]:
    return sorted(p for p in SRC.rglob("*") if p.suffix in (".s", ".inc"))


def _word(name: str) -> re.Pattern:
    return re.compile(rf"(?<![A-Za-z0-9_@.]){re.escape(name)}(?![A-Za-z0-9_])")


def test_drbg_k_is_named_only_by_the_drbg():
    pat = _word("drbg_k")
    others = [str(p.relative_to(REPO)) for p in _sources()
              if p != DRBG and any(pat.search(l) for l in _code(p))]
    assert not others, (
        f"drbg_k is the DRBG's private K; {others} name it. Any other "
        "writer re-creates the hmac_key aliasing this file exists to stop.")


def test_drbg_k_is_defined_and_not_exported():
    code = _code(DRBG)
    assert any(re.match(r"\s*drbg_k:\s*\.res\s+32\b", l) for l in code), (
        "hmac_drbg.s no longer defines drbg_k (.res 32)")
    exported = [l.strip() for l in code
                if re.match(r"\s*\.(export|exportzp|global|globalzp)\b", l)
                and _word("drbg_k").search(l)]
    assert not exported, (
        f"hmac_drbg.s exports drbg_k ({exported}); the link-time guarantee "
        "that no other module can write K depends on it staying local")


def test_drbg_routines_key_their_hmac_from_drbg_k():
    code = _code(DRBG)
    start = next((i for i, l in enumerate(code)
                  if re.match(r"\s*hmac_drbg_update:", l)), None)
    assert start is not None, "hmac_drbg_update: not found in hmac_drbg.s"
    body = code[start:]
    direct = [l.strip() for l in body
              if re.search(r"\bjsr\s+hmac_sha256\b", l)]
    stores = [l.strip() for l in body
              if re.search(r"\bst[axy]\s+hmac_key\b", l)]
    assert not direct, (
        f"a DRBG routine calls hmac_sha256 directly ({direct}): it would be "
        "keyed by whatever HKDF left in hmac_key. Use drbg_hmac.")
    assert not stores, (
        f"a DRBG routine stores to hmac_key ({stores}): K lives in drbg_k")
    calls = sum(bool(re.search(r"\bjsr\s+drbg_hmac\b", l)) for l in body)
    assert calls >= 5, (
        f"expected the DRBG's 5 HMACs to go through drbg_hmac, found {calls}")


def test_hmac_val_is_stored_only_by_the_drbg():
    pat = re.compile(r"\bst[axy]\s+hmac_val\b")
    others = [str(p.relative_to(REPO)) for p in _sources()
              if p != DRBG and any(pat.search(l) for l in _code(p))]
    assert not others, (
        f"{others} store to hmac_val, the DRBG's V. Only hmac_drbg.s may.")


DRBG_HMAC_BODY = [
    "ldx #31",
    "@load_k:",
    "lda drbg_k,x",
    "sta hmac_key,x",
    "dex",
    "bpl @load_k",
    "hmac_sha256:",
]


def test_drbg_hmac_is_exactly_the_k_load():
    code = [" ".join(l.split()) for l in _code(DRBG) if l.strip()]
    start = next((i for i, l in enumerate(code) if l == "drbg_hmac:"), None)
    assert start is not None, "drbg_hmac: not found in hmac_drbg.s"
    body = code[start + 1:start + 1 + len(DRBG_HMAC_BODY)]
    assert body == DRBG_HMAC_BODY, (
        f"drbg_hmac must be exactly {DRBG_HMAC_BODY} (load K from drbg_k, "
        f"fall into hmac_sha256); found {body}")


def main() -> int:
    print("=== HMAC_DRBG state ownership ===")
    passed = failed = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
        except AssertionError as exc:
            failed += 1
            print(f"  FAIL {name}\n       {exc}")
        else:
            passed += 1
            print(f"  ok   {name}")
    print(f"\n{'FAILED' if failed else 'PASSED'}: {failed} failure(s)")
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from _skip_policy import verdict
    return verdict(passed, failed, certifies="HMAC_DRBG state ownership")


if __name__ == "__main__":
    sys.exit(main())
