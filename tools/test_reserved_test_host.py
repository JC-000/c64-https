#!/usr/bin/env python3
"""test_reserved_test_host.py — the test hostname must be unresolvable.

Every name this project *configures itself to dial*, and every name it
mints a certificate for, has to sit under a TLD that the DNS is required
never to answer for. Nothing here needs VICE, hardware or a build; it is
file parsing plus three calls to the stdlib-only cert generator, and runs
in well under a second.

Why it exists
-------------
The project shipped ``www.foo.bar`` as the *default* ``HTTPS_HOST`` — the
value baked into ``src/boot.s`` on a plain ``make``. ``.bar`` is a live
gTLD, so pressing ``G`` on a default-built PRG dialled a name that can
resolve on the open internet, or on any LAN whose resolver answers for
it. The rigs were safe only because they DMA a listener IP in as the
connect host; the menu path was not.

RFC 2606 §2 and RFC 6761 §6.4 reserve ``.invalid`` for exactly this: it is
guaranteed never to be delegated, and resolvers are required not to
resolve it. ``.test``, ``.example`` and ``.localhost`` are the other
reserved choices (``.localhost`` carries loopback semantics, and
``example.com`` *does* resolve, to real IANA servers — so ``.invalid`` is
the one to prefer).

What is asserted, and what is deliberately NOT
----------------------------------------------
This is a check on the **property**, not on the spelling. A
``grep -r 'foo\\.bar'`` guard would be a keyword assertion: it goes green
the moment someone writes ``foo.baz``, which resolves just as happily.
So instead:

  * the Makefile's default ``HTTPS_HOST`` must end in a reserved TLD;
  * the certificate each of the three minting paths actually produces
    (``ensure_certs``, ``gen_certs`` defaults, the packaged listener's
    auto-generate) must carry SAN dNSNames that all end in a reserved
    TLD — read back out of the emitted DER, not off a source literal;
  * the dnsmasq ``--address=`` overrides in both bridge scripts must
    cover every one of those SAN names, so the rig rename cannot drift
    out of step with the cert rename.  "Cover" is dnsmasq's own rule:
    ``--address=/d/ip`` answers for ``d`` *and* every subdomain of it,
    which is why one script lists both names and the other only the
    parent.

That fails for ``foo.bar``. It fails for ``foo.baz``. It passes only for
names that genuinely cannot resolve.

Runs under pytest, and standalone for anyone without pytest installed
(the repo declares no pytest dependency)::

    python3 tools/test_reserved_test_host.py
"""
from __future__ import annotations

import contextlib
import io
import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MAKEFILE = REPO / "Makefile"
GEN_DIR = REPO / "tools" / "package" / "listener"
E2E_DIR = REPO / "tools" / "https_e2e"

# The bridge scripts that publish DNS overrides for the test cert's names.
DNSMASQ_SCRIPTS = (
    REPO / "tools" / "rig-up-macos.sh",          # macOS feth rig (VICE ip65)
    REPO / "scripts" / "setup-bridge-tap.sh",    # Linux br-c64 rig
)

# RFC 2606 §2 (.test/.example/.invalid/.localhost) and RFC 6761 §6.2-6.4.
# Guaranteed never delegated; DNS is required not to resolve them. This is
# the whole point of the file, so it is spelled once, here.
RESERVED_TLDS = frozenset({"invalid", "test", "example", "localhost"})

_RFC_CITE = ("RFC 2606 §2 / RFC 6761 §6.2-6.4 reserve "
             f"{sorted('.' + t for t in RESERVED_TLDS)} so that they can "
             "never resolve. Prefer `.invalid`: `.localhost` carries "
             "loopback semantics and example.com resolves to real IANA "
             "servers.")


# --- the property ------------------------------------------------------------

def tld_of(name: str) -> str:
    """Lowercased last label of *name*, with a trailing root dot tolerated."""
    return name.strip().rstrip(".").rsplit(".", 1)[-1].lower()


def is_unresolvable(name: str) -> bool:
    """True iff *name* sits under a TLD the DNS may never answer for."""
    return tld_of(name) in RESERVED_TLDS


def _assert_unresolvable(names, where: str) -> None:
    bad = sorted({n for n in names if not is_unresolvable(n)})
    assert bad == [], (
        f"{where} names hostnames under a TLD that can resolve on the "
        f"public internet: {bad} (TLDs {sorted({tld_of(n) for n in bad})}). "
        f"{_RFC_CITE}"
    )


# --- readers -----------------------------------------------------------------

def makefile_default_https_host() -> str:
    """The shipped `HTTPS_HOST ?=` default — what a plain `make` bakes in."""
    text = MAKEFILE.read_text()
    m = re.search(r"^HTTPS_HOST\s*\?=\s*(\S+)\s*$", text, re.MULTILINE)
    assert m is not None, (
        f"no `HTTPS_HOST ?= <host>` line in {MAKEFILE}. That line is the "
        "shipped default baked into src/boot.s via build/https_host.inc; if "
        "it moved, this check has to move with it."
    )
    return m.group(1)


def _der_tlv(buf: bytes, off: int):
    """Return (tag, value_start, value_len, next_off) for the TLV at *off*."""
    tag = buf[off]
    n = buf[off + 1]
    off += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(buf[off:off + k], "big")
        off += k
    return tag, off, n, off + n


def san_dns_names(pem_path: Path) -> list[str]:
    """dNSName entries from a certificate's subjectAltName, stdlib only.

    A deliberate hand walk rather than `ssl` or `cryptography`: the whole
    point is to read what the generator actually emitted into the DER, and
    the repo's cert path is stdlib-only by design (see gen_certs.py).
    """
    import base64

    body = "".join(
        line for line in pem_path.read_text().splitlines()
        if "-----" not in line
    )
    der = base64.b64decode(body)

    # Locate the subjectAltName extension by its OID (2.5.29.17 = 55 1d 11)
    # and parse the GeneralNames SEQUENCE inside its OCTET STRING.
    marker = b"\x06\x03\x55\x1d\x11"
    i = der.find(marker)
    assert i != -1, f"{pem_path} carries no subjectAltName extension"
    off = i + len(marker)
    tag, vs, vl, nxt = _der_tlv(der, off)
    if tag == 0x01:                       # optional `critical` BOOLEAN
        tag, vs, vl, nxt = _der_tlv(der, nxt)
    assert tag == 0x04, f"{pem_path}: SAN extnValue is tag {tag:#04x}, not OCTET STRING"
    tag, vs, vl, _ = _der_tlv(der, vs)    # the GeneralNames SEQUENCE
    assert tag == 0x30, f"{pem_path}: SAN payload is tag {tag:#04x}, not SEQUENCE"

    names, cur, end = [], vs, vs + vl
    while cur < end:
        tag, s, ln, cur = _der_tlv(der, cur)
        if tag == 0x82:                   # [2] IMPLICIT IA5String = dNSName
            names.append(der[s:s + ln].decode("ascii"))
    assert names, f"{pem_path}: subjectAltName carries no dNSName entries"
    return names


def dnsmasq_overrides(script: Path) -> set[str]:
    """The names in a script's `--address=/<name>/<ip>` dnsmasq overrides."""
    return {
        m.group(1).lower().strip(".")
        for m in re.finditer(r"--address=/([^/\s\"']+)/", script.read_text())
    }


def covered_by(name: str, overrides: set[str]) -> bool:
    """dnsmasq semantics: `--address=/d/` answers for `d` and every `*.d`."""
    name = name.lower().strip(".")
    return any(name == o or name.endswith("." + o) for o in overrides)


# --- minting paths -----------------------------------------------------------
#
# Three independent entry points mint the test certificate. Each is driven
# for real into a temp directory and the emitted DER read back, so the
# assertion lands on what the tool DOES, not on a literal it happens to
# spell. That also means the check survives any refactor of where the
# default lives.

def _sys_path(*dirs: Path):
    for d in dirs:
        if str(d) not in sys.path:
            sys.path.insert(0, str(d))


def _mint_via_ensure_certs(tmp: Path) -> list[str]:
    _sys_path(E2E_DIR, GEN_DIR)
    import ensure_certs                                   # noqa: PLC0415
    cert, _key = ensure_certs.ensure_certs("p256", tmp, force=True, quiet=True)
    return san_dns_names(cert)


def _mint_via_gen_certs_defaults(tmp: Path) -> list[str]:
    """`gen_certs.py --out-dir TMP` with no --cn/--san: the shipped defaults."""
    _sys_path(GEN_DIR)
    import gen_certs                                      # noqa: PLC0415
    rc = gen_certs.main(["--out-dir", str(tmp), "--force"])
    assert rc == 0, f"gen_certs.main() returned {rc}"
    return san_dns_names(tmp / "server.pem")


def _mint_via_listener(tmp: Path) -> list[str]:
    """The packaged listener's own auto-generate path (listener._ensure_certs)."""
    _sys_path(GEN_DIR)
    import listener                                       # noqa: PLC0415
    cert, key = tmp / "server.pem", tmp / "server.key"
    listener._ensure_certs(cert, key)
    return san_dns_names(cert)


_MINTED: dict[str, list[str]] | None = None


def _all_minted_san_names() -> dict[str, list[str]]:
    """Mint once per process; every test below reads the same three certs."""
    global _MINTED
    if _MINTED is not None:
        return _MINTED
    out = {}
    for label, fn in (
        ("tools/https_e2e/ensure_certs.py", _mint_via_ensure_certs),
        ("tools/package/listener/gen_certs.py defaults", _mint_via_gen_certs_defaults),
        ("tools/package/listener/listener.py auto-generate", _mint_via_listener),
    ):
        with tempfile.TemporaryDirectory() as d:
            # The generators narrate to stdout; useful to a human running
            # them by hand, pure noise in a test report.
            with contextlib.redirect_stdout(io.StringIO()):
                out[label] = fn(Path(d))
    _MINTED = out
    return out


# --- tests -------------------------------------------------------------------

def test_shipped_default_https_host_cannot_resolve() -> None:
    """A plain `make` must not bake in a name the open internet can answer."""
    host = makefile_default_https_host()
    _assert_unresolvable(
        [host],
        f"the shipped `HTTPS_HOST ?=` default in {MAKEFILE.name} ({host!r}) "
        "— this is the host a user reaches by pressing G on a default build, "
        "and it"
    )


def test_minted_certificate_sans_cannot_resolve() -> None:
    """Every SAN of every cert the repo mints must be unresolvable.

    Read back out of the emitted DER, so a stale source literal, a stale
    file on disk, or a fourth minting path added later cannot slip past.
    """
    for label, names in _all_minted_san_names().items():
        _assert_unresolvable(names, f"the certificate minted by {label} ({names})")


def test_all_minting_paths_agree() -> None:
    """The three paths must mint the same names, or downstream checks split.

    ensure_certs.py exists precisely so the in-tree tests and the packaged
    listener produce identical material; if they diverge, the C64's SAN
    check passes against one listener and fails against the other.
    """
    minted = _all_minted_san_names()
    sets = {label: tuple(sorted(n.lower() for n in names))
            for label, names in minted.items()}
    distinct = set(sets.values())
    assert len(distinct) == 1, (
        "the certificate-minting paths disagree on the SAN set: "
        + "; ".join(f"{k} -> {list(v)}" for k, v in sorted(sets.items()))
        + ". They are meant to produce identical material (see the module "
        "docstring of tools/https_e2e/ensure_certs.py)."
    )


def test_san_shape_still_exercises_prefix_logic() -> None:
    """Keep the bare-name + `www.` pair the hostname vectors depend on.

    tools/test_x509_name.py derives its real-certificate vectors from these
    two entries to exercise leftmost-label and prefix logic ("SAN entry is a
    prefix of the host"). Collapsing them to one name would silently drop
    that coverage rather than fail anything.
    """
    names = next(iter(_all_minted_san_names().values()))
    lowered = [n.lower() for n in names]
    assert len(lowered) == 2, f"expected exactly two SAN entries, got {lowered}"
    bare, www = sorted(lowered, key=len)
    assert www == "www." + bare, (
        f"the SAN pair must be a bare name plus its `www.` prefix, got "
        f"{lowered}. tools/test_x509_name.py's prefix/leftmost-label vectors "
        "are built from that shape."
    )


def test_dnsmasq_overrides_cover_every_cert_name() -> None:
    """The bridge rigs must answer for exactly the names the cert carries.

    This is the lockstep pin. Renaming the certificate without renaming the
    `--address=` overrides does not fail any build: the VICE ip65 rig just
    stops resolving, minutes into a run, and reads as a C64-side TCP fault.
    """
    names = {n.lower() for n in next(iter(_all_minted_san_names().values()))}
    for script in DNSMASQ_SCRIPTS:
        assert script.is_file(), f"missing bridge script {script}"
        overrides = dnsmasq_overrides(script)
        missing = sorted(n for n in names if not covered_by(n, overrides))
        assert missing == [], (
            f"{script.relative_to(REPO)} publishes dnsmasq --address= "
            f"overrides for {sorted(overrides)} but the test certificate "
            f"carries {sorted(names)}; {missing} would not resolve on the "
            "rig. The cert names and the DNS overrides must move together."
        )


def test_reserved_tld_predicate_rejects_live_gtlds() -> None:
    """The predicate itself, against the mistake it exists to catch.

    `.bar` and `.baz` are live gTLDs; a keyword guard on the string
    "foo.bar" would pass the moment someone typed "foo.baz".
    """
    for live in ("www.foo.bar", "foo.bar", "foo.baz", "example.com",
                 "listener.local", "a.b.co.uk"):
        assert not is_unresolvable(live), f"{live} must not be treated as reserved"
    for reserved in ("foo.invalid", "www.foo.invalid", "WWW.FOO.INVALID",
                     "foo.invalid.", "host.test", "x.example", "localhost"):
        assert is_unresolvable(reserved), f"{reserved} must be treated as reserved"


# --- standalone runner -------------------------------------------------------

def main() -> int:
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failures = []
    for fn in tests:
        try:
            fn()
        except AssertionError as exc:
            failures.append((fn.__name__, str(exc)))
            print(f"  FAIL  {fn.__name__}\n        {exc}")
        else:
            print(f"  ok    {fn.__name__}")
    print(f"\n{len(tests) - len(failures)}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
