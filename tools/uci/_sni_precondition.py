#!/usr/bin/env python3
"""Offline precondition: does this PRG present a name the listener's cert names?

Issue #141. The local HTTPS rigs DMA the *dev host's dotted-quad IP* in as
``http_host_ptr``, because that is what the UCI firmware has to dial. Before
v0.4.2 that address was also what ``http_get`` copied into ``tls_hostname``,
and nothing looked at it again. Since v0.4.2 ``src/x509_name.s`` validates the
server certificate's SAN dNSName entries against ``tls_hostname``, and an IP
literal never matches a dNSName — so every UCI HTTPS rig has failed at
Certificate (``tls_last_state=$04``, ``tls_state=$FF``) since #135. The client
is right; the rig was asking it to accept a certificate for a name it was not
connecting to.

The fix is ``make HTTPS_SNI=<name>``: the connect host stays the listener's IP
(**it must** — see below), while ``http_get``'s override arm copies a fixed
name into ``tls_hostname`` for the ClientHello and the SAN check. That is a
property of the *image on disk*, so this module asserts it offline, before any
rig touches ``DeviceLock`` — a wrong PRG then costs zero device time instead of
a multi-minute hardware run that fails identically to the bug it is meant to
detect.

Two labels are checked, and either alone is insufficient:

    https_sni_override    boot.o was assembled with the flag: the string is in
                          the image (src/boot.s, HTTPS_TARGET_RODATA)
    @copy_sni             http.o was assembled with the flag: the override
                          *arm* is compiled in (src/http.s)

``HTTPS_SNI=`` is not in #128's no-clean-needed set: it regenerates
``build/https_host.inc`` (which invalidates ``boot.o``) *and* adds
``-D HTTPS_SNI_OVERRIDE=1`` (which is a flag change, so ``http.o`` goes stale
and make does not notice). Without ``make clean`` you get a **mixed link** that
has the first symbol and lacks the second: it links, the string greps out of
the PRG, the hash changes, and the run fails exactly like a no-SNI build. Two
onchip images built here, one clean and one not, differ only in that:

    a65fff60cbeb57e35cddeb9ed42d5a88c0597e5ab96c64636ed692eeea2efc0a  clean
    d1b6350886c66fce63f5798dea943daae11c718171524b9538c5c963f9d3eb6f  mixed

Nothing else on either side of that pair distinguishes them, which is why the
mixed link gets its own error message here.

Safety — the DMA'd connect host must stay the IP
------------------------------------------------
``.bar`` is a live gTLD. The rigs deliberately pass ``www.foo.bar`` only as the
*presented* name; the host the C64 dials is still the dev host's IP. DMA'ing
``www.foo.bar`` as the connect host would hand the hostname to the UCI
firmware's resolver and send the C64 to a stranger's address on any LAN whose
DNS resolves it. Change ``tls_hostname``, never ``http_host_ptr``.

Related: ``http_build_request`` composes ``Host:`` from ``http_host_ptr``
independently of ``tls_hostname`` (src/http.s), so the listener still sees
``Host: <listener IP>`` and the rigs' server-side request matcher keeps
passing. Do not "fix" that matcher to expect the SNI name.

No constant to keep in step
---------------------------
The expected name is **derived**, never pinned. ``dns_names_from_cert()`` reads
the SAN dNSNames out of the certificate the listener will actually present, and
``sni_string_from_prg()`` reads the name actually embedded in the PRG. Both
sides come from the artifacts under test, so there is no third copy to drift:
a regenerated cert, a sibling rig that swaps ``CERT_PATH`` (p384), or a build
left over from some other experiment (``HTTPS_SNI=en.wikipedia.org``) are all
caught by the same comparison.

Self-test (pure logic, no build, no VICE, no hardware)::

    python3 tools/uci/_sni_precondition.py --selftest
"""
from __future__ import annotations

import base64
import sys
from pathlib import Path

# Labels that must both be present in a build with the SNI override compiled
# in. See the module docstring for what each one proves.
SNI_STRING_LABEL = "https_sni_override"   # boot.o: the string is in the image
SNI_CODE_LABEL = "@copy_sni"              # http.o: the override arm is linked

# Longest name the ClientHello SNI guard accepts (src/boot.s .assert).
MAX_SNI_LEN = 63


# ---------------------------------------------------------------------------
# Certificate: SAN dNSNames, stdlib only
# ---------------------------------------------------------------------------
# The repo's certs are minted by tools/package/listener/gen_certs.py, which is
# pure stdlib by design (PR #96) — so this reader is too, rather than making
# the rigs depend on `cryptography` for one field.

_OID_SAN = bytes((0x06, 0x03, 0x55, 0x1D, 0x11))    # 2.5.29.17
_TAG_DNSNAME = 0x82                                 # [2] IMPLICIT IA5String


def _der_tlv(der: bytes, pos: int) -> tuple[int, int, int]:
    """Read one DER TLV at *pos*. Returns (tag, value_start, value_end)."""
    tag = der[pos]
    length = der[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(der[pos:pos + n], "big")
        pos += n
    return tag, pos, pos + length


def dns_names_from_cert(pem: str | bytes) -> list[str]:
    """SAN dNSName entries of the first certificate in *pem*, in order.

    Returns [] when the certificate carries no SAN extension. Raises
    ValueError if *pem* is not a parsable PEM certificate — the caller
    decides whether that is fatal.
    """
    if isinstance(pem, bytes):
        pem = pem.decode("ascii", errors="replace")
    lines: list[str] = []
    inside = False
    for line in pem.splitlines():
        if line.startswith("-----BEGIN CERTIFICATE"):
            inside = True
        elif line.startswith("-----END CERTIFICATE"):
            break
        elif inside:
            lines.append(line.strip())
    if not lines:
        raise ValueError("no PEM CERTIFICATE block found")
    try:
        der = base64.b64decode("".join(lines))
    except Exception as exc:                      # noqa: BLE001 — reported below
        raise ValueError(f"undecodable PEM body: {exc}") from exc

    idx = der.find(_OID_SAN)
    if idx < 0:
        return []
    # Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
    #                          extnValue OCTET STRING }
    pos = idx + len(_OID_SAN)
    tag, start, end = _der_tlv(der, pos)
    if tag == 0x01:                               # critical BOOLEAN, skip it
        tag, start, end = _der_tlv(der, end)
    if tag != 0x04:                               # extnValue OCTET STRING
        raise ValueError(f"SAN extnValue has tag 0x{tag:02x}, expected 0x04")
    names_tag, names_start, names_end = _der_tlv(der, start)
    if names_tag != 0x30:                         # GeneralNames SEQUENCE
        raise ValueError(f"GeneralNames has tag 0x{names_tag:02x}")

    out: list[str] = []
    pos = names_start
    while pos < names_end:
        tag, start, end = _der_tlv(der, pos)
        if tag == _TAG_DNSNAME:
            out.append(der[start:end].decode("ascii", errors="replace"))
        pos = end
    return out


def name_matches(presented: str, san: str) -> bool:
    """Mirror src/x509_name.s: case-insensitive, leftmost-label wildcards only."""
    presented = presented.rstrip(".").lower()
    san = san.rstrip(".").lower()
    if not presented or not san:
        return False
    if not san.startswith("*."):
        return presented == san
    # `*.example.com` matches exactly one leading label of `example.com`.
    suffix = san[1:]                              # ".example.com"
    if not presented.endswith(suffix):
        return False
    label = presented[:-len(suffix)]
    return bool(label) and "." not in label


def suggested_sni(dns_names: list[str]) -> str | None:
    """The name to put in the HTTPS_SNI= rebuild hint.

    The most specific non-wildcard SAN — a wildcard is a legal SNI for the
    client but a confusing thing to type, and the longest concrete name is the
    one a real client would have sent (``www.foo.bar`` over ``foo.bar`` for
    the repo's test cert).
    """
    concrete = [n for n in dns_names if not n.startswith("*.")]
    if not concrete:
        return None
    return max(concrete, key=len)


# ---------------------------------------------------------------------------
# PRG: the SNI string actually embedded in the image
# ---------------------------------------------------------------------------

_SNI_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                 "0123456789.-*_")


def sni_string_from_prg(prg: bytes, addr: int) -> str | None:
    """Read the NUL-terminated SNI string at C64 address *addr* out of *prg*.

    *prg* is a raw PRG: two little-endian load-address bytes then a
    contiguous image (both backend cfgs fill to the last segment, so every
    labelled address below the end of the file is at a fixed offset).

    Returns None if the offset is outside the file or the bytes there are not
    a plausible hostname — the caller degrades to the label checks rather than
    blocking a run on a guess.
    """
    if len(prg) < 2:
        return None
    load = prg[0] | (prg[1] << 8)
    off = addr - load + 2
    if off < 2 or off >= len(prg):
        return None
    end = prg.find(b"\x00", off, min(off + MAX_SNI_LEN + 1, len(prg)))
    if end < 0 or end == off:
        return None
    raw = prg[off:end]
    text = raw.decode("ascii", errors="replace")
    if any(c not in _SNI_CHARS for c in text):
        return None
    return text


# ---------------------------------------------------------------------------
# The precondition itself
# ---------------------------------------------------------------------------

def _rebuild_hint(sni: str, backend: str = "uci") -> str:
    return (f"    make clean && make BACKEND={backend} "
            f"USE_NISTCURVES_ONCHIP=1 HTTPS_SNI={sni}\n"
            f"    (any profile works; HTTPS_SNI= needs the clean — see #141)")


def check_sni_precondition(labels,
                           prg: bytes | None = None,
                           dns_names: list[str] | None = None,
                           connect_host: str = "",
                           backend: str = "uci") -> str | None:
    """Return None if this build can pass the SAN check, else why not.

    Pure function of its arguments: no I/O, no device, no build. *labels* is
    the ``build/labels.txt`` mapping, *prg* the raw PRG bytes (optional),
    *dns_names* the SAN dNSNames of the cert the listener will present
    (None = unknown, e.g. EXTERNAL_LISTENER=1), *connect_host* the address
    the rig will DMA in as ``http_host_ptr``.
    """
    has_string = SNI_STRING_LABEL in labels
    has_code = SNI_CODE_LABEL in labels

    # 1. Mixed link. Checked first and unconditionally: it is the one state
    #    that no other evidence distinguishes from a good build.
    if has_string != has_code:
        if has_string:
            return (
                "MIXED LINK: this PRG has the SNI string but not the code.\n"
                f"  build/labels.txt has {SNI_STRING_LABEL} (boot.o was "
                f"assembled with HTTPS_SNI=) but no {SNI_CODE_LABEL} "
                "(http.o was not).\n"
                "  http_get will copy the connect host into tls_hostname and "
                "the SAN check will\n"
                "  reject it, exactly as if HTTPS_SNI= had never been passed. "
                "The string is in\n"
                "  the image and the PRG hash changed, so nothing else gives "
                "this away.\n"
                "  Cause: HTTPS_SNI= adds -D HTTPS_SNI_OVERRIDE=1, a flag "
                "change make cannot see.\n"
                "  Rebuild from clean:\n"
                + _rebuild_hint(suggested_sni(dns_names or []) or "<name>",
                                backend)
            )
        return (
            "MIXED LINK: this PRG has the SNI code but not the string.\n"
            f"  build/labels.txt has {SNI_CODE_LABEL} but no "
            f"{SNI_STRING_LABEL}; http.o and boot.o disagree about "
            "HTTPS_SNI_OVERRIDE.\n"
            "  Rebuild from clean:\n"
            + _rebuild_hint(suggested_sni(dns_names or []) or "<name>", backend)
        )

    # 2. What name will the C64 actually put in tls_hostname?
    embedded: str | None = None
    if has_string and has_code:
        if prg is not None:
            embedded = sni_string_from_prg(prg, int(labels[SNI_STRING_LABEL]))
        presented = embedded
    else:
        presented = connect_host or None

    # 3. Compare it with what the certificate names. Unknown cert (external
    #    listener) or unreadable string: the label checks above are the honest
    #    bound, so stop here.
    if dns_names is None or presented is None:
        return None
    if not dns_names:
        return ("The listener's certificate carries no SAN dNSName entries.\n"
                "  src/x509_name.s rejects a no-SAN certificate outright; "
                "regenerate the test\n"
                "  cert with tools/https_e2e/ensure_certs.py --force.")
    if any(name_matches(presented, n) for n in dns_names):
        return None

    if has_string and has_code:
        what = (f"This PRG presents SNI {presented!r} "
                f"(from {SNI_STRING_LABEL} at "
                f"${int(labels[SNI_STRING_LABEL]):04X}),")
    else:
        what = (f"This PRG was NOT built with HTTPS_SNI=, so it will present "
                f"the connect host {presented!r},")
    return (
        f"{what}\n"
        f"  but the listener's certificate names only: "
        f"{', '.join(dns_names)}.\n"
        "  src/x509_name.s (v0.4.2+) matches SAN dNSName entries only, so an "
        "IP literal can\n"
        "  never match and the handshake aborts at Certificate "
        "(tls_state=$FF, tls_last_state=$04).\n"
        "  Build an image that presents a name the cert carries:\n"
        + _rebuild_hint(suggested_sni(dns_names) or dns_names[0], backend)
    )


def cert_dns_names_or_none(cert_path: Path | str) -> list[str] | None:
    """SAN dNSNames of *cert_path*, or None if it cannot be read/parsed.

    None means "unknown", which downgrades the precondition to the label
    checks; it never fails a run on its own.
    """
    try:
        return dns_names_from_cert(Path(cert_path).read_text())
    except (OSError, ValueError) as exc:
        print(f"NOTE: could not read SAN names from {cert_path} ({exc}); "
              f"checking build labels only", file=sys.stderr)
        return None


def enforce_sni_precondition(labels,
                             prg_path: Path,
                             cert_path: Path | None,
                             connect_host: str,
                             backend: str = "uci") -> str | None:
    """Convenience wrapper for the rigs: read the artifacts, run the check.

    Returns None on success (after printing what it concluded), else the
    error message. Call it BEFORE DeviceLock.acquire_or_raise(): a wrong PRG
    then costs no device time.
    """
    try:
        prg = Path(prg_path).read_bytes()
    except OSError:
        prg = b""
    dns_names = cert_dns_names_or_none(cert_path) if cert_path else None

    problem = check_sni_precondition(
        labels, prg=prg or None, dns_names=dns_names,
        connect_host=connect_host, backend=backend,
    )
    if problem is not None:
        return problem

    if SNI_STRING_LABEL in labels:
        embedded = sni_string_from_prg(prg, int(labels[SNI_STRING_LABEL])) \
            if prg else None
        print(f"SNI precondition: PRG presents "
              f"{embedded if embedded else '<unreadable>'!r}"
              f", connecting to {connect_host!r}"
              + (f"; cert names {', '.join(dns_names)}" if dns_names else ""))
    else:
        print(f"SNI precondition: no HTTPS_SNI override; "
              f"presenting the connect host {connect_host!r}"
              + (f"; cert names {', '.join(dns_names)}" if dns_names else ""))
    return None


# ---------------------------------------------------------------------------
# Self-test — pure logic, no build, no VICE, no hardware
# ---------------------------------------------------------------------------

_GOOD = {SNI_STRING_LABEL: 0x5772, SNI_CODE_LABEL: 0x0F5D,
         "@copy_sni_done": 0x0F68}
_NONE: dict[str, int] = {"@copy_host": 0x099D}
_MIXED = {SNI_STRING_LABEL: 0x5772, "@copy_host": 0x099D}
_CERT_NAMES = ["foo.bar", "www.foo.bar"]
_IP = "10.43.23.99"


def _prg_with(addr: int, text: str, load: int = 0x0801) -> bytes:
    """A synthetic PRG carrying *text* NUL-terminated at C64 address *addr*."""
    body = bytearray(b"\xEA" * (addr - load + 64))
    off = addr - load
    body[off:off + len(text) + 1] = text.encode("ascii") + b"\x00"
    return bytes(bytearray([load & 0xFF, load >> 8]) + body)


def _selftest() -> int:
    failures: list[str] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        print(f"  {'ok  ' if cond else 'FAIL'}  {name}"
              + (f"  [{detail}]" if detail and not cond else ""))
        if not cond:
            failures.append(name)

    good_prg = _prg_with(0x5772, "www.foo.bar")

    print("check_sni_precondition")
    # 1. Not built with HTTPS_SNI at all: the connect host is an IP literal,
    #    which no dNSName can match. This is issue #141 as filed.
    msg = check_sni_precondition(_NONE, prg=good_prg, dns_names=_CERT_NAMES,
                                 connect_host=_IP)
    check("no symbols -> 'not built with HTTPS_SNI' error",
          msg is not None and "NOT built with HTTPS_SNI=" in msg
          and _IP in msg and "HTTPS_SNI=www.foo.bar" in msg, repr(msg))

    # 2. The one that matters: string without code. Links, greps, new hash,
    #    fails identically to case 1 on hardware.
    msg = check_sni_precondition(_MIXED, prg=good_prg, dns_names=_CERT_NAMES,
                                 connect_host=_IP)
    check("string label without code label -> MIXED LINK error",
          msg is not None and msg.startswith("MIXED LINK")
          and SNI_CODE_LABEL in msg and "make clean" in msg, repr(msg))

    # 2b. The mirror image, for symmetry (make cannot produce it, a hand-run
    #     ca65 can).
    msg = check_sni_precondition({SNI_CODE_LABEL: 0x0F5D}, prg=good_prg,
                                 dns_names=_CERT_NAMES, connect_host=_IP)
    check("code label without string label -> MIXED LINK error",
          msg is not None and msg.startswith("MIXED LINK"), repr(msg))

    # 3. Both symbols, and the embedded name is one the cert carries.
    msg = check_sni_precondition(_GOOD, prg=good_prg, dns_names=_CERT_NAMES,
                                 connect_host=_IP)
    check("both labels + matching SNI -> passes", msg is None, repr(msg))

    # 4. Both symbols, wrong name: a leftover image from another experiment.
    #    Symbol presence alone would call this good.
    msg = check_sni_precondition(_GOOD, prg=_prg_with(0x5772,
                                                      "en.wikipedia.org"),
                                 dns_names=_CERT_NAMES, connect_host=_IP)
    check("both labels + non-matching SNI -> wrong-name error",
          msg is not None and "en.wikipedia.org" in msg
          and "MIXED LINK" not in msg, repr(msg))

    # 5. Unknown cert (EXTERNAL_LISTENER=1): label checks only, no veto on a
    #    name we cannot know.
    check("unknown cert -> no veto on the name",
          check_sni_precondition(_GOOD, prg=good_prg, dns_names=None,
                                 connect_host=_IP) is None)
    check("unknown cert still catches the mixed link",
          check_sni_precondition(_MIXED, prg=good_prg, dns_names=None,
                                 connect_host=_IP) is not None)

    # 6. Unreadable PRG string: do not block a run on a guess.
    check("both labels, no PRG bytes -> no veto",
          check_sni_precondition(_GOOD, prg=None, dns_names=_CERT_NAMES,
                                 connect_host=_IP) is None)

    # 7. A cert with no SAN at all is a reject in src/x509_name.s.
    msg = check_sni_precondition(_GOOD, prg=good_prg, dns_names=[],
                                 connect_host=_IP)
    check("cert with no SAN dNSNames -> error",
          msg is not None and "no SAN dNSName" in msg, repr(msg))

    # 8. A hostname connect host that the cert names needs no override.
    check("no override but connect host matches the cert -> passes",
          check_sni_precondition(_NONE, prg=good_prg, dns_names=_CERT_NAMES,
                                 connect_host="www.foo.bar") is None)

    print("sni_string_from_prg")
    check("reads the embedded string",
          sni_string_from_prg(good_prg, 0x5772) == "www.foo.bar")
    check("address past the end of the image -> None",
          sni_string_from_prg(good_prg, 0xE000) is None)
    check("address below the load address -> None",
          sni_string_from_prg(good_prg, 0x0400) is None)
    check("non-hostname bytes -> None",
          sni_string_from_prg(_prg_with(0x5772, "") + b"", 0x5772) is None)
    binary = bytearray(_prg_with(0x5772, "www.foo.bar"))
    binary[0x5772 - 0x0801 + 2] = 0x8E
    check("binary garbage at the address -> None",
          sni_string_from_prg(bytes(binary), 0x5772) is None)

    print("name_matches (mirrors src/x509_name.s)")
    check("exact", name_matches("www.foo.bar", "www.foo.bar"))
    check("case-insensitive", name_matches("WWW.Foo.Bar", "www.foo.bar"))
    check("different name", not name_matches("foo.bar", "www.foo.bar"))
    check("IP literal never matches a dNSName",
          not name_matches("10.43.23.99", "www.foo.bar"))
    check("leftmost wildcard", name_matches("www.foo.bar", "*.foo.bar"))
    check("wildcard spans one label only",
          not name_matches("a.www.foo.bar", "*.foo.bar"))
    check("wildcard does not match the bare domain",
          not name_matches("foo.bar", "*.foo.bar"))

    print("suggested_sni")
    check("most specific concrete name",
          suggested_sni(["foo.bar", "www.foo.bar"]) == "www.foo.bar")
    check("wildcards are not suggested",
          suggested_sni(["*.foo.bar"]) is None)

    print()
    if failures:
        print(f"FAIL: {len(failures)} check(s): {', '.join(failures)}")
        return 1
    print("PASS: all self-test checks")
    return 0


def _main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return _selftest()
    if len(argv) == 2 and argv[1].endswith((".pem", ".crt")):
        print(dns_names_from_cert(Path(argv[1]).read_text()))
        return 0
    print(__doc__)
    print("usage: _sni_precondition.py --selftest | <cert.pem>",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
