#!/usr/bin/env python3
"""Ensure the local test certs exist, generating them on demand.

The certs under ``tools/https_e2e/certs/`` are gitignored — they are
throwaway self-signed test material, not something to ship in a repo. That
means a fresh clone has none, and every script that starts a local TLS
listener needs them.

``https_listener.py`` has always generated its own pair, but
``tools/uci/rig_https_local.py`` inlines its own listener and so never
crossed that path: it just printed ``ERROR: cert/key not found`` and exited
2, leaving the reader to discover that a generator existed somewhere else
entirely (issue #93). This module is the single entry point both now use.

Generation is delegated to ``tools/package/listener/gen_certs.py`` rather
than duplicated, so the packaged listener and the in-tree tests produce
identical material: self-signed ECDSA, CN ``www.foo.invalid``, SAN covering
``foo.invalid`` and ``www.foo.invalid``, 10 year validity. Those two names
are ``gen_certs.DEFAULT_CN`` / ``DEFAULT_SANS`` — imported, not repeated,
so the two paths cannot drift apart. ``.invalid`` is RFC 2606 §2 /
RFC 6761 §6.4 reserved and can never resolve; see gen_certs.py.

**Staleness, not just absence.** An existing pair is reused, so changing
the names above would otherwise leave a cert on disk carrying the OLD ones
— silently, since the files are gitignored and nobody deletes them. Every
downstream check would then disagree with this module. ``ensure_certs``
therefore compares the SAN entries of the cert it finds against
``SANS`` and re-mints on a mismatch.

That generator is **pure Python stdlib** (PR #96): no ``cryptography``, no
pip, no venv on either path. P-384 was the one profile that still needed
the package, and #96's implementation extends to it — same algorithm,
different curve — so the in-tree tests now have no third-party dependency
for certs either.

Three profiles, matching the listener's ``cert_profile`` selector:

    p256 (default) -> certs/server.pem       + certs/server.key
    p384           -> certs/server-p384.pem  + certs/server-p384.key
    p256-chain     -> certs/server-chain.pem + certs/server.key
                      (the p256 leaf + 2 padded throwaway intermediates,
                      ~3.2 KB total — the real-record-count bench; see
                      chain_certs.py)

Usable directly, too:

    python3 tools/https_e2e/ensure_certs.py [--profile p256|p384] [--force]
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CERTS_DIR = REPO_ROOT / "tools" / "https_e2e" / "certs"
GEN_DIR = REPO_ROOT / "tools" / "package" / "listener"

if str(GEN_DIR) not in sys.path:
    sys.path.insert(0, str(GEN_DIR))
try:
    from gen_certs import (  # noqa: E402
        DEFAULT_CN, DEFAULT_SANS, san_dns_names, sans_match,
    )
except ImportError as _exc:                          # pragma: no cover
    # The generator is stdlib-only, so this is a missing/broken file rather
    # than a missing package. Say which file, in one line. Deliberately NOT
    # falling back to literals: a second copy of the names is exactly the
    # drift this import exists to remove.
    raise SystemExit(
        f"cannot import the test-cert identity: {_exc} (expected the "
        f"stdlib-only generator at {GEN_DIR / 'gen_certs.py'})") from _exc

CN = DEFAULT_CN
SANS = list(DEFAULT_SANS)
PROFILES = ("p256", "p384", "p256-chain")

# Filenames per profile — must stay in step with gen_certs.CURVE_PROFILES
# (and, for the chain profile, chain_certs.CHAIN_PEM_NAME + the p256 key).
_FILENAMES = {
    "p256": ("server.pem", "server.key"),
    "p384": ("server-p384.pem", "server-p384.key"),
    "p256-chain": ("server-chain.pem", "server.key"),
}


def cert_paths(profile: str = "p256",
               certs_dir: Path | None = None) -> tuple[Path, Path]:
    """Return (cert_path, key_path) for *profile*. Does not generate."""
    if profile not in _FILENAMES:
        raise ValueError(f"unknown cert profile {profile!r}; "
                         f"expected one of {PROFILES}")
    base = Path(certs_dir) if certs_dir is not None else CERTS_DIR
    cert_name, key_name = _FILENAMES[profile]
    return base / cert_name, base / key_name


def _is_stale(cert_path: Path) -> bool:
    """True if the cert on disk does not carry exactly the SANs we want."""
    return not sans_match(cert_path, SANS)


def ensure_certs(profile: str = "p256",
                 certs_dir: Path | None = None,
                 force: bool = False,
                 quiet: bool = False) -> tuple[Path, Path]:
    """Return (cert_path, key_path), generating them if absent OR stale.

    Idempotent for a *matching* pair: it is returned untouched unless
    *force*. A pair whose subjectAltName no longer matches ``SANS`` is
    re-minted, because "the certs are gitignored so they will regenerate"
    is false — nothing deletes them, so a rename of the test identity would
    otherwise be invisible on every machine that had run the tests before,
    and every downstream check would silently disagree with this module.

    Raises SystemExit with a one-line actionable message if generation is
    impossible — never a bare traceback, since the usual cause is a missing
    dependency rather than a bug.
    """
    cert_path, key_path = cert_paths(profile, certs_dir)

    if profile == "p256-chain":
        # Delegates to chain_certs, which ensures the p256 leaf pair first
        # and handles its own staleness (the chain must be rebuilt whenever
        # the leaf regenerates, not only when the chain file is absent).
        here = str(Path(__file__).resolve().parent)
        if here not in sys.path:
            sys.path.insert(0, here)
        from chain_certs import ensure_chain_certs  # noqa: PLC0415
        return ensure_chain_certs(certs_dir, force=force, quiet=quiet)

    pretty = f"P-{profile[1:]}"              # p256 -> P-256
    have_pair = cert_path.is_file() and key_path.is_file()
    stale = have_pair and _is_stale(cert_path)

    if have_pair and not stale and not force:
        return cert_path, key_path

    if not quiet:
        if stale:
            print(f"test cert {cert_path} carries "
                  f"{san_dns_names(cert_path) or '(no SAN)'} but this tree "
                  f"wants {SANS} — re-minting")
        else:
            print(f"test certs not found in {cert_path.parent} — generating "
                  f"(self-signed {pretty}, CN={CN}); "
                  f"they are gitignored by design")

    # A stale pair must be overwritten, not skipped: gen_certs refuses to
    # clobber an existing file unless told to.
    force = force or stale

    if str(GEN_DIR) not in sys.path:
        sys.path.insert(0, str(GEN_DIR))
    try:
        from gen_certs import generate  # noqa: PLC0415
    except ImportError as exc:
        # The generator is stdlib-only, so this is a missing/broken file
        # rather than a missing package. Say which file, in one line.
        raise SystemExit(
            f"cannot generate test certs: {exc} "
            f"(expected the stdlib-only generator at "
            f"{GEN_DIR / 'gen_certs.py'})") from exc

    try:
        return generate(CN, SANS, cert_path.parent, force=force,
                        curve=profile)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - surface as one readable line
        raise SystemExit(
            f"test cert generation failed: {type(exc).__name__}: {exc}") from exc


# Backwards-compatible alias for the P-256-only spelling.
def ensure_p256_certs(certs_dir: Path | None = None, force: bool = False,
                      quiet: bool = False) -> tuple[Path, Path]:
    return ensure_certs("p256", certs_dir, force=force, quiet=quiet)


def main(argv: list[str] | None = None) -> int:
    import argparse  # noqa: PLC0415 - keep import cost off the library path

    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--profile", default="p256", choices=list(PROFILES),
                   help="cert profile to ensure (default: p256)")
    p.add_argument("--force", action="store_true",
                   help="regenerate even if the pair already exists")
    args = p.parse_args(argv)

    cert, key = ensure_certs(args.profile, force=args.force)
    print(f"cert: {cert}\nkey:  {key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
