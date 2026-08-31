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
  * every ``HTTPS_HOST=``/``HTTPS_SNI=`` value written down anywhere in
    the tracked tree — README, module docstring, Makefile comment — must
    be a name a reader can safely type. See below.

That fails for ``foo.bar``. It fails for ``foo.baz``. It passes only for
names that genuinely cannot resolve.

The written-down build instructions, and why they need their own check
----------------------------------------------------------------------
The first three checks read the *shipped default* and the *emitted
certificate*. Neither can see a README or a docstring that tells a human
to type a name — and that is the half that rotted. The 2026-08 rename of
the test identity left three instructions (``tools/uci/README.md``,
``rig_https_local.py``, ``rig_https_bad_finished.py``) still passing the
old ``www.foo.bar`` as the SNI override to ``make``. That is not merely
stale: ``.bar`` is a live gTLD, and the PRG such a line builds
presents a name the certificate no longer carries, so
``tools/uci/_sni_precondition.py`` rejects it before the device is even
touched. A doc example is a thing people copy; it has to be as correct as
the default.

So ``test_build_instruction_hosts_are_safe`` scans every tracked text
file for ``HTTPS_HOST=``/``HTTPS_SNI=`` followed by a literal, and sorts
each value into exactly one of four buckets:

  reserved      ends in a reserved TLD — the good case
  ip            a dotted quad; the rigs' connect host *must* be an IP,
                and no dNSName can ever match one (that is what the SNI
                knob exists for)
  external      an explicitly allowlisted real public host — retargeting
                at a real server is a documented feature, so
                ``make HTTPS_HOST=github.com`` is correct as written
  placeholder   ``<host>``, ``{sni}``, ``...`` — not a name at all

Anything else fails. That keeps the property rather than the spelling:
``foo.baz`` fails, ``example.com`` fails, and a newly invented live name
fails. The one way past it is adding a line to ``EXTERNAL_HOSTS`` below,
which is deliberate, reviewed, and has to be justified in a comment —
never a silent exemption.

Note what it does NOT cover, so that nothing here is a *silent* bound:

  * names written in some other shape — an ``openssl req`` ``CN =`` /
    ``DNS:`` recipe, or a bare mention in prose. The historical record in
    ``docs/engineering-notes.md`` and this file's own negative vectors
    below both contain ``foo.bar`` on purpose, and neither sits in an
    assignment, so neither needs an exemption;
  * a value carrying URL punctuation (``HTTPS_HOST=https://x.com``) is
    bucketed as a placeholder rather than a name. It is not a working
    instruction either way: the value is baked in verbatim as a hostname
    (``build/https_host.inc`` → ``src/boot.s``, which also caps it at 63
    chars), so such a line is already broken for a louder reason.

The buckets are asserted directly by ``test_build_instruction_classifier``,
and ``test_build_instruction_scan_is_not_vacuous`` pins a floor under what
the scan sees, so a regex that quietly stopped matching fails instead of
going green.

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


# --- written-down build instructions -----------------------------------------
#
# Real public hosts that a build instruction may legitimately name. Retargeting
# the client at a real server is a documented feature (README "Real public-
# internet HTTPS"), so these are not exceptions to the rule — they are a
# different rule, and each one has to be a site the project actually documents
# fetching from.
#
# ADDING TO THIS LIST IS A DELIBERATE ACT. It says "a reader who copies this
# line will open a TCP connection to somebody else's server, and that is
# intended". If you are reaching for it to make a *local-listener* instruction
# pass, you have the wrong fix: those must name the test certificate's
# identity, which lives under `.invalid`.
EXTERNAL_HOSTS = frozenset({
    "github.com",         # README/CLAUDE.md: first real-server HTTP 200
    "en.wikipedia.org",   # the 125,235 B article fetch (HTTPS_BODY_TO_REU)
})

# `HTTPS_HOST=` / `HTTPS_SNI=`, plus make's `?=` / `:=` / `+=` spellings.
#
# Whitespace after the `=` is tolerated ONLY for the make-style operators.
# A shell/command-line assignment cannot contain one — `make HTTPS_SNI= foo`
# passes an empty value — so allowing it there would swallow the next word of
# any sentence that mentions the flag ("`HTTPS_SNI=` feeds two consumers"),
# and every one of those would read as a live hostname.
_ASSIGN_RE = re.compile(r"\bHTTPS_(?:HOST|SNI)\s*(?:[?:+]=\s*|=)(\S+)")

# Punctuation that wraps a value in prose, markdown, reST, Python or shell.
# `*` is NOT stripped: `*.foo.invalid` is a legitimate wildcard SNI and must
# stay visible to the classifier rather than being trimmed into a placeholder.
_WRAPPERS = " \t\r\n`'\"(),;:\\|"

# A hostname literal: labels of alphanumerics/hyphens, optional leading `*.`.
_HOSTNAME_RE = re.compile(r"^\*?\.?[A-Za-z0-9][A-Za-z0-9.\-_]*$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Characters that mark a value as a placeholder rather than a name. Spelled
# out so that a value matching neither this nor _HOSTNAME_RE is a *failure*
# ("unrecognised") and not a silent skip.
_PLACEHOLDER_CHARS = set("<>{}$()%\\\"'*|=/?&")

# Directories the fallback tree walk must not descend into (submodules, build
# artifacts, agent scratch). Only used when `git ls-files` is unavailable.
_WALK_SKIP = {".git", ".claude", "build", "dist", "libs", "ip65",
              "ip65-build", "__pycache__", ".venv", "node_modules"}

# Anti-vacuity floors. A regex that quietly stops matching, or a tree walk
# that finds nothing, must fail rather than pass having checked nothing.
_MIN_LITERAL_VALUES = 8
_MIN_FILES_WITH_LITERALS = 5


def tracked_text_files() -> tuple[list[Path], str]:
    """Every tracked, decodable text file, plus how the list was obtained.

    Prefers `git ls-files` so an untracked scratch note cannot fail the
    build. Falls back to a tree walk (never a skip: a check that silently
    stops checking is the failure mode this whole file exists to prevent).
    """
    import subprocess                                     # noqa: PLC0415

    mode = "git ls-files"
    names: list[str] = []
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO), "ls-files", "-z"],
            capture_output=True, check=True, timeout=60,
        ).stdout
        names = [n for n in out.decode("utf-8", "replace").split("\0") if n]
    except (OSError, subprocess.SubprocessError):
        names = []
    if not names:
        mode = "tree walk (git unavailable)"
        import os                                         # noqa: PLC0415
        for root, dirs, files in os.walk(REPO):
            dirs[:] = [d for d in dirs if d not in _WALK_SKIP]
            for f in files:
                names.append(str(Path(root, f).relative_to(REPO)))

    out_paths = []
    for name in names:
        p = REPO / name
        try:
            if p.stat().st_size > 1 << 20:     # no build artifact is a doc
                continue
            p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):  # submodule gitlink, or binary
            continue
        out_paths.append(p)
    return out_paths, mode


def classify_host_value(value: str) -> tuple[str, str]:
    """Sort one `HTTPS_HOST=`/`HTTPS_SNI=` value into a bucket.

    Returns (bucket, cleaned) where bucket is one of "reserved", "ip",
    "external", "placeholder", "live" or "unrecognised".
    """
    cleaned = value.strip(_WRAPPERS)
    if not cleaned or set(cleaned) <= {"."}:
        return "placeholder", cleaned
    if _PLACEHOLDER_CHARS & set(cleaned) and not cleaned.startswith("*."):
        return "placeholder", cleaned
    if _IPV4_RE.match(cleaned):
        return "ip", cleaned
    if not _HOSTNAME_RE.match(cleaned):
        return "unrecognised", cleaned
    if is_unresolvable(cleaned):
        return "reserved", cleaned
    if cleaned.lower().lstrip("*.") in EXTERNAL_HOSTS:
        return "external", cleaned
    return "live", cleaned


_SCANNED: tuple | None = None


def scan_build_instructions():
    """(findings, mode), scanned once per process — three tests read it."""
    global _SCANNED
    if _SCANNED is None:
        paths, mode = tracked_text_files()
        _SCANNED = (build_instruction_hosts(paths), mode, len(paths))
    return _SCANNED


def build_instruction_hosts(paths):
    """[(path, lineno, raw, bucket, cleaned)] for every assignment found."""
    found = []
    for p in paths:
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "HTTPS_HOST" not in text and "HTTPS_SNI" not in text:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for m in _ASSIGN_RE.finditer(line):
                raw = m.group(1)
                bucket, cleaned = classify_host_value(raw)
                found.append((p, lineno, raw, bucket, cleaned))
    return found


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


def test_build_instruction_hosts_are_safe() -> None:
    """No written-down build instruction may name a resolvable host.

    A README line or a module docstring is something a human copies into a
    shell. The shipped-default and minted-cert checks above cannot see one,
    which is exactly how three SNI-override instructions naming the old
    `.bar` identity outlived the rename of the certificate they refer to.
    """
    found, mode, n_files = scan_build_instructions()
    assert n_files, f"found no tracked text files to scan ({mode})"

    bad = [(p, n, raw, bucket) for p, n, raw, bucket, _ in found
           if bucket in ("live", "unrecognised")]
    assert bad == [], (
        "build instructions name hostnames that are not safe to type:\n"
        + "\n".join(
            f"  {p.relative_to(REPO)}:{n}  HTTPS_*={raw}  [{bucket}]"
            for p, n, raw, bucket in bad
        )
        + "\n\nA local-listener instruction must name the test certificate's "
          "identity, which\nlives under a reserved TLD — otherwise the PRG it "
          "builds presents a name the\ncert does not carry and "
          "tools/uci/_sni_precondition.py rejects it before the\ndevice is "
          "touched. If the host really is a real public server the project "
          "means\nto fetch from, add it to EXTERNAL_HOSTS in this file with a "
          f"comment saying why.\n{_RFC_CITE}"
    )


def test_build_instruction_scan_is_not_vacuous() -> None:
    """The scan above must actually be finding instructions.

    Its assertion is "nothing bad was found", which a regex that quietly
    stopped matching would also satisfy. Pin a floor on what it sees, and
    pin the one value we know must be there: the shipped default.
    """
    found, mode, _n_files = scan_build_instructions()
    literals = [(p, n, cleaned) for p, n, _raw, bucket, cleaned in found
                if bucket in ("reserved", "ip", "external", "live")]
    files = {p for p, _n, _c in literals}
    assert len(literals) >= _MIN_LITERAL_VALUES and len(files) >= _MIN_FILES_WITH_LITERALS, (
        f"the HTTPS_HOST=/HTTPS_SNI= scan ({mode}) found only "
        f"{len(literals)} literal value(s) in {len(files)} file(s), below the "
        f"floor of {_MIN_LITERAL_VALUES} in {_MIN_FILES_WITH_LITERALS}. Either "
        "the instructions were removed (lower the floor deliberately) or "
        "_ASSIGN_RE has stopped matching how they are written, in which case "
        "test_build_instruction_hosts_are_safe is now green for the wrong "
        "reason."
    )
    default = makefile_default_https_host()
    assert any(c.lower() == default.lower() for _p, _n, c in literals), (
        f"the scan did not see the Makefile's own `HTTPS_HOST ?= {default}` "
        "line, which it must reach if it reaches anything."
    )


def test_build_instruction_classifier() -> None:
    """The classifier itself, including the mistakes it exists to catch."""
    for live in ("www.foo.bar", "foo.bar", "foo.baz", "example.com",
                 "listener.local", "evil.co.uk"):
        assert classify_host_value(live)[0] == "live", live
        # ...and still live once prose punctuation is wrapped around it.
        assert classify_host_value(f"`{live}`,")[0] == "live", live
    for ok in ("www.foo.invalid", "foo.invalid", "host.test", "x.example",
               "localhost", "*.foo.invalid"):
        assert classify_host_value(ok)[0] == "reserved", ok
    for ip in ("10.43.23.99", "10.0.65.1", "192.168.1.81"):
        assert classify_host_value(ip)[0] == "ip", ip
    for ext in ("github.com", "en.wikipedia.org"):
        assert classify_host_value(ext)[0] == "external", ext
    for placeholder in ("<host>", "<name>", "{sni}", "...", "$(HOST)", "",
                        '"', "%s"):
        assert classify_host_value(placeholder)[0] == "placeholder", placeholder


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
