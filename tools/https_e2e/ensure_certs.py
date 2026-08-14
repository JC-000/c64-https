#!/usr/bin/env python3
"""Ensure the local test certs exist, generating them on demand.

The certs under ``tools/https_e2e/certs/`` are gitignored — they are
throwaway self-signed test material, not something to ship in a repo. That
means a fresh clone has none, and every script that starts a local TLS
listener needs them. Before this module those scripts printed
``ERROR: cert/key not found`` and exited 2, leaving the reader to discover
that a generator existed somewhere else entirely (issue #93).

The certs README has claimed for months that they "are generated on demand
by the listener". This module is what finally makes that sentence true.

Generation is delegated to ``tools/package/listener/gen_certs.py`` rather
than duplicated, so the packaged listener and the in-tree tests produce
identical material: ECDSA P-256, CN ``www.foo.bar``, SAN covering
``foo.bar`` and ``www.foo.bar``.

Usable directly, too:

    python3 tools/https_e2e/ensure_certs.py [--force]
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CERTS_DIR = REPO_ROOT / "tools" / "https_e2e" / "certs"
GEN_DIR = REPO_ROOT / "tools" / "package" / "listener"

CN = "www.foo.bar"
SANS = ["foo.bar", "www.foo.bar"]


def ensure_p256_certs(certs_dir: Path | None = None,
                      force: bool = False,
                      quiet: bool = False) -> tuple[Path, Path]:
    """Return (cert_path, key_path), generating them if absent.

    Idempotent: an existing pair is returned untouched unless *force*.
    Raises SystemExit with a one-line actionable message if generation is
    impossible — never a bare traceback, since the usual cause is a missing
    dependency rather than a bug.
    """
    certs_dir = Path(certs_dir) if certs_dir is not None else CERTS_DIR
    cert_path = certs_dir / "server.pem"
    key_path = certs_dir / "server.key"

    if cert_path.is_file() and key_path.is_file() and not force:
        return cert_path, key_path

    if not quiet:
        print(f"test certs not found in {certs_dir} — generating "
              f"(self-signed P-256, CN={CN}); they are gitignored by design")

    if str(GEN_DIR) not in sys.path:
        sys.path.insert(0, str(GEN_DIR))
    try:
        from gen_certs import generate  # noqa: E402
    except ImportError as exc:
        if "cryptography" in str(exc):
            raise SystemExit(
                "cannot generate test certs: the 'cryptography' package is "
                "missing. Install it with:\n"
                "    python3 -m pip install cryptography") from exc
        raise SystemExit(
            f"cannot generate test certs: {exc}\n"
            f"expected the generator at {GEN_DIR / 'gen_certs.py'}") from exc

    try:
        return generate(CN, SANS, certs_dir, force=force)
    except Exception as exc:  # noqa: BLE001 - surface as one readable line
        raise SystemExit(f"test cert generation failed: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    force = "--force" in argv
    cert, key = ensure_p256_certs(force=force)
    print(f"cert: {cert}\nkey:  {key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
