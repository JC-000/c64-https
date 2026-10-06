#!/usr/bin/env python3
"""check_release_key.py — refuse a linked PRG that carries the TEST-ONLY bundle key.

#155 phase 2, L3. The Makefile's parse-time guard compares the key .inc's
`$XX` tokens, which is text: an .inc that spells a byte in decimal (`234`
for `$EA`) or hides a `$00` in a comment slips past it while ca65 still
assembles the test key (adv-269 #1). This looks at what was ASSEMBLED: it
derives the test key's 64 bytes (Qx || Qy, the layout trust_bundle.s
embeds) from tools/trust_bundle_TEST_ONLY_signing_key.pem — no .inc parsed —
and searches the whole PRG for them. Anywhere is enough: the key has no
business in a release image, and a whole-file search needs no label math
for the comb cold image (linked to run in cert_buf, carried at $C000).

The Makefile runs it after the link under TRUST_RELEASE=1 TRUST_BUNDLE=1
and deletes the PRG when it fails.

    python3 tools/check_release_key.py build/c64-https.prg

Exit 0 the key is absent; 1 it is present, or the check could not run
(fail closed: this only ever runs for a release).
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def test_key_bytes() -> bytes:
    sys.path.insert(0, str(HERE))
    import trust_bundle as tb       # noqa: PLC0415 — needs `cryptography`
    return tb.pubkey_xy(tb.load_private_key(tb.TEST_KEY_PATH).public_key())


def main(argv) -> int:
    if len(argv) != 1:
        print("usage: check_release_key.py <prg>", file=sys.stderr)
        return 1
    try:
        key = test_key_bytes()
        prg = Path(argv[0]).read_bytes()
    except Exception as exc:        # noqa: BLE001 — fail closed
        print(f"ERROR: release key check could not run ({type(exc).__name__}: {exc})",
              file=sys.stderr)
        return 1
    assert len(key) == 64
    at = prg.find(key)
    if at >= 0:
        print(f"ERROR: {argv[0]} carries the TEST-ONLY trust-bundle key (PRG offset {at}): "
              "its private half is in the repository. Build the release with "
              "TRUST_BUNDLE_KEY_INC=<your production key's .inc>.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
