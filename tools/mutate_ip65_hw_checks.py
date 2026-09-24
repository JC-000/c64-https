#!/usr/bin/env python3
"""tools/mutate_ip65_hw_checks.py — break the RR-Net checker on purpose.

`tools/test_ip65_hw_checks_unit.py` claims that every verdict in
`tools/ip65_hw_checks.py` alarms on a known-bad input. This is the thing
that CHECKS that claim: it copies the module and the suite into a scratch
mirror, applies one textual mutation at a time — each one a plausible way
a verdict could have been written wrong — and requires the suite to go red.

A mutant that SURVIVES is a red case that proves nothing: the suite passes
whether or not the checker works, which is the exact failure this whole
lane exists to prevent. Written after four survivors were found on the
first run, all four in cases that read as thorough:

  * `check_dhcp_lease` — every red case also passed `subnet=`, and ip65's
    build-time default 192.168.1.64 fails the subnet test on its own, so
    deleting the default-rejection branch changed nothing observable.
  * `check_shadow_ram_readable` — a real $A000 read carries BOTH ROM
    markers, so losing either arm still rejected the realistic input.
  * `check_http_response` — every red case had a wrong length AND wrong
    content, so a checker comparing only a prefix passed them all on the
    length test.

Each is now asserted in isolation. Nothing about those three was visible
by reading the suite; they were visible by breaking the module.

BRANCH-COMPLETE SINCE #201. The first set was 14 mutants. #201 recorded
that a larger adversarial set left untested defence-in-depth branches —
branches that change no verdict on the inputs the suite happened to use,
because an earlier or neighbouring test already rejected them. The set
below now deletes (or weakens) EVERY rejecting branch of every `check_*`,
plus the decoder and reassembly defences those checks stand on, plus the
#202 ports. Each survivor was then either killed by a red case that
reaches the branch on its own, deleted (two `broadcast` branches in
`check_dhcp_lease` / `check_mac_on_wire` that the next branch always
subsumed), or pinned below as KNOWN-EQUIVALENT with the reason.

KNOWN-EQUIVALENT MUTANTS are reported as survivors-with-a-reason, never
suppressed, and the list is kept short on purpose: a growing one is how a
mutation score stops meaning anything. Every entry is a branch whose
removal leaves `ok`, `status` and every asserted evidence field unchanged
for EVERY input — the branch exists for its message. The first entry
ever listed here, `check_http_response`'s length test, turned out NOT to
be equivalent (slicing clamps an over-long `resp_len`, and a negative one
slices from the end), and is now killed by a red case. That is the
reason every entry has to be argued for all inputs, not the inputs the
suite happened to use.

ANCHORS MUST BE UNIQUE. A mutation whose anchor text appears more than
once in the module would mutate whichever copy comes first, which may not
be the branch its name describes; that is reported as AMBIGUOUS and fails
the run, the same as an anchor that no longer exists.

A METHODOLOGY TRAP, fixed here rather than left for the next reader.
Python caches bytecode on (mtime, size), and a mutation harness rewrites
the same path many times within the same second. Two different mutants
whose files happen to be the same length then run the FIRST one's
bytecode, and the results are silently wrong — on the first run of this
script three verdicts were attributed to `test_image_readback_red_green`,
which does not test any of them. The subprocess is therefore launched with
PYTHONDONTWRITEBYTECODE=1. A harness that certifies other checks must not
itself be the unreliable part.

    python3 tools/mutate_ip65_hw_checks.py [--keep] [--source-root DIR]
                                           [--allow-not-applicable]

`--source-root` mutates another checkout's module and suite (for a
before/after score across a change); `--allow-not-applicable` then lets
mutants whose code does not exist there be reported and skipped instead
of failing the run. Neither is for normal use.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _off(anchor: str) -> tuple:
    """`if COND:` -> `if False:` — delete a rejecting branch."""
    head, _, rest = anchor.partition("if ")
    return anchor, head + "if False:" + rest[rest.rindex(":") + 1:]


#: (description, text to find in the module, text to replace it with).
#: Each mutation is a plausible weaker implementation, not a random edit.
MUTANTS = [
    # --- the original fourteen ------------------------------------------
    ("check_c64_originated ignores frames from a third MAC",
     '    if s.other:\n        return Verdict(False,',
     '    if False:\n        return Verdict(False,'),
    ("check_dhcp_lease accepts ip65's build-time cfg_ip default",
     "    if octets == IP65_DEFAULT_CFG_IP:",
     "    if False and octets == IP65_DEFAULT_CFG_IP:"),
    ("check_body_not_on_wire reports absence with no positive control",
     "    if not control_hits:",
     "    if False and not control_hits:"),
    ("check_shadow_ram_readable loses the ROM-prefix arm",
     "    if bytes_at_a000.startswith(BASIC_ROM_A000_PREFIX) or \\",
     "    if False and bytes_at_a000.startswith(BASIC_ROM_A000_PREFIX) or \\"),
    ("check_http_response drops the length test",
     "    if resp_len != len(expected_body):",
     "    if False and resp_len != len(expected_body):"),
    ("check_http_response compares only a prefix of the body",
     "    if got != expected_body:",
     "    if not got.startswith(expected_body[:4]):"),
    ("parse_pcap accepts a snaplen-clipped capture",
     "        if incl < orig and strict:",
     "        if False and incl < orig and strict:"),
    ("check_tls_connected accepts FINISHED as CONNECTED",
     "    if tls_state_max != TLS_STATE_CONNECTED:",
     "    if tls_state_max not in (TLS_STATE_CONNECTED, TLS_STATE_FINISHED):"),
    ("tcp_streams fuses every connection into one sequence space",
     '        key = (bytes(f.ip_src or b""), f.sport, bytes(f.ip_dst or b""), f.dport)',
     '        key = "one-stream-for-everything"'),
    ("check_mac_on_wire never looks at the wire",
     "    if len(seen) < min_frames:",
     "    if False and len(seen) < min_frames:"),
    ("check_image_readback tolerates a differing image",
     "    if readback != expected:",
     "    if False and readback != expected:"),
    ("check_capture_grew accepts a file that did not grow",
     "    if size_after == size_before:",
     "    if False and size_after == size_before:"),
    ("check_capture_bracket accepts a wholly stale capture",
     "    if not inside:",
     "    if False and not inside:"),
    ("a check_* is renamed away (the RED_CASES registry goes stale)",
     "def check_net_last_error(", "def renamed_check_net_last_error("),

    # --- #201: every remaining rejecting branch ---------------------------
    # pcap decoding and reassembly
    ("parse_pcap accepts a file shorter than a pcap header",
     *_off("    if len(data) < 24:")),
    ("parse_pcap accepts a file with no pcap magic",
     *_off("    if magic not in _PCAP_MAGICS:")),
    ("parse_pcap accepts a non-Ethernet link type",
     *_off("    if linktype != 1 and strict:")),
    ("parse_pcap accepts an absurd record length",
     *_off("        if incl > 262144:")),
    ("parse_pcap decodes a half-written trailing record",
     "        if off + incl > len(data):\n            break",
     "        if False:\n            break"),
    ("tcp_streams ignores the Ethernet-source filter",
     *_off("        if eth_src is not None and bytes(f.eth_src) != bytes(eth_src):")),
    ("tcp_streams keeps the first copy of a segment, not the longest",
     "        if prev is None or len(f.tcp_payload) > len(prev):",
     "        if prev is None:"),
    ("tcp_stream frames the FIRST connection, not the longest",
     '    return max(streams, key=len) if streams else b""',
     '    return streams[0] if streams else b""'),
    ("parse_tls_records accepts any protocol version",
     "        if version >> 8 != 0x03 or length > 0x4000 + 256:",
     "        if length > 0x4000 + 256:"),
    # two-station discrimination
    ("check_c64_originated accepts c64_mac == host_mac",
     *_off("    if bytes(c64_mac) == bytes(host_mac):")),
    ("check_c64_originated ignores the tcp_port it was given",
     "    if tcp_port is not None:\n        matching",
     "    if False:\n        matching"),
    ("check_c64_originated counts C64 TCP on ANY port",
     "                    and (f.dport == tcp_port or f.sport == tcp_port)]",
     "                    ]"),
    ("check_c64_originated (no port) accepts too few C64 frames",
     *_off("    if len(s.c64) < min_frames:")),
    ("check_mac_on_wire accepts an unread (None) MAC",
     "    if c64_mac is None:\n        return Verdict(False, \"the C64's MAC was never",
     "    if False:\n        return Verdict(False, \"the C64's MAC was never"),
    ("check_mac_on_wire accepts a MAC that is not 6 bytes",
     *_off("    if len(mac) != 6:")),
    ("check_mac_on_wire accepts the all-zero MAC",
     *_off('    if mac == b"\\x00" * 6:')),
    ("check_mac_on_wire accepts a group (multicast/broadcast) source",
     *_off("    if mac[0] & 0x01:")),
    ("check_mac_on_wire accepts ip65's build-time cfg_mac default",
     *_off("    if tuple(mac) == IP65_DEFAULT_CFG_MAC:")),
    ("check_mac_on_wire accepts the Mac's own address",
     *_off("    if mac == bytes(host_mac):")),
    # the capture bracket
    ("check_capture_grew accepts an unsampled size",
     *_off("    if size_before is None or size_after is None:")),
    ("check_capture_grew accepts a capture that shrank",
     *_off("    if size_after < size_before:")),
    ("check_capture_bracket accepts an inverted window",
     *_off("    if ended_at < started_at:")),
    ("check_capture_bracket accepts an empty capture",
     '    if not frames:\n        ev["diagnosis"] = "empty"',
     '    if False:\n        ev["diagnosis"] = "empty"'),
    ("check_capture_bracket accepts too few frames inside",
     *_off("    if len(inside) < min_inside:")),
    # DHCP
    ("check_dhcp_lease accepts an unread IP", *_off("    if local_ip is None:")),
    ("check_dhcp_lease accepts a short read", *_off("    if len(local_ip) != 4:")),
    ("check_dhcp_lease accepts 0.0.0.0", *_off("    if octets == (0, 0, 0, 0):")),
    ("check_dhcp_lease accepts loopback", *_off("    if octets[0] == 127:")),
    ("check_dhcp_lease accepts multicast/reserved/broadcast",
     *_off("    if octets[0] >= 224:")),
    ("check_dhcp_lease accepts link-local",
     *_off("    if octets[0] == 169 and octets[1] == 254:")),
    ("check_dhcp_lease accepts the host's own address",
     *_off("    if host_ip is not None and fmt_ip(octets) == host_ip:")),
    ("check_dhcp_lease accepts an off-subnet address",
     *_off("        if [str(o) for o in octets[:3]] != want:")),
    ("check_dhcp_lease accepts a pool address instead of the pinned one",
     *_off("    if expect_ip is not None and fmt_ip(octets) != expect_ip:")),
    # DNS / TLS on the wire
    ("check_dns_query_on_wire accepts the Mac's own queries",
     "        if bytes(f.eth_src) != mac:\n            continue\n        for name",
     "        if False:\n            continue\n        for name"),
    ("check_dns_query_on_wire accepts a query to any UDP port",
     "        if f.ip_proto != IPPROTO_UDP or f.dport != 53:",
     "        if f.ip_proto != IPPROTO_UDP:"),
    ("check_dns_query_on_wire matches the name as a substring",
     '            if name.lower().rstrip(".") == want:',
     "            if want in name.lower():"),
    ("check_client_hello_on_wire skips the empty-stream test (KNOWN EQUIVALENT)",
     "    if not stream:\n        return Verdict(False, f\"the C64 put no TCP",
     "    if False:\n        return Verdict(False, f\"the C64 put no TCP"),
    ("check_client_hello_on_wire skips the no-records test",
     "    if not records:\n        return Verdict(False, f\"the {len(stream)}",
     "    if False:\n        return Verdict(False, f\"the {len(stream)}"),
    ("check_client_hello_on_wire accepts a non-handshake first record",
     *_off("    if first.content_type != TLS_CONTENT_HANDSHAKE:")),
    ("check_client_hello_on_wire accepts a non-ClientHello handshake",
     *_off("    if not first.body or first.body[0] != TLS_HS_CLIENT_HELLO:")),
    ("check_client_hello_on_wire accepts the wrong SNI",
     *_off('    if expect_sni is not None and (sni or "").lower() != expect_sni.lower():')),
    ("check_tls_traffic_both_ways accepts no appdata from the C64",
     *_off("    if not c64_app:")),
    ("check_tls_traffic_both_ways accepts no appdata from the host",
     *_off("    if not host_app:")),
    # the cleartext search
    ("check_body_not_on_wire accepts an empty secret",
     "    if not secret:\n        return Verdict(False, \"no secret was supplied",
     "    if False:\n        return Verdict(False, \"no secret was supplied"),
    ("check_body_not_on_wire accepts an empty control",
     "    if not control:\n        return Verdict(False, \"no control needle",
     "    if False:\n        return Verdict(False, \"no control needle"),
    ("check_body_not_on_wire skips the empty-capture test (KNOWN EQUIVALENT)",
     "    if not frames:\n        return Verdict(False, \"the capture holds no frames",
     "    if False:\n        return Verdict(False, \"the capture holds no frames"),
    ("check_body_not_on_wire searches reassembled streams only, not frames",
     "    corpora: list[bytes] = [bytes(f.raw) for f in frames]",
     "    corpora: list[bytes] = []"),
    ("check_body_not_on_wire searches frames only, not reassembled streams",
     *_off("            if st:")),
    ("check_body_not_on_wire runs the partial search on frames only, "
     "not on reassembled streams",
     "        if run >= partial_min:",
     "        if run >= partial_min and i < n_frame_corpora:"),
    ("PARTIAL_RUN_MIN raised from 8 to 9",
     "PARTIAL_RUN_MIN = 8", "PARTIAL_RUN_MIN = 9"),
    ("PARTIAL_RUN_MIN raised from 8 to 12",
     "PARTIAL_RUN_MIN = 8", "PARTIAL_RUN_MIN = 12"),
    ("PARTIAL_RUN_MIN lowered from 8 to 7",
     "PARTIAL_RUN_MIN = 8", "PARTIAL_RUN_MIN = 7"),
    ("check_body_not_on_wire drops the PETSCII shifted form (#202)",
     '("petscii-shifted", petscii_shifted_form(secret))',
     '("petscii-shifted", bytes(secret))'),
    ("check_body_not_on_wire drops the PETSCII folded form (#202)",
     '(("petscii", petscii_form(secret)),',
     '(("petscii", bytes(secret)),'),
    ("petscii_form stops folding at 'y'",
     "        if 0x61 <= b <= 0x7A:",
     "        if 0x61 <= b < 0x7A:"),
    ("petscii_shifted_form stops shifting at 'Y'",
     "if 0x41 <= b <= 0x5A else b",
     "if 0x41 <= b < 0x5A else b"),
    ("check_body_not_on_wire reports no partial runs (#202)",
     *_off("        if run >= partial_min:")),
    ("check_body_not_on_wire's partial floor is off by one",
     "        if run >= partial_min:",
     "        if run > partial_min:"),
    ("check_body_not_on_wire ignores the partial_min it was given",
     "        if run >= partial_min:",
     "        if run >= PARTIAL_RUN_MIN:"),
    ("check_body_not_on_wire looks for partial runs of the exact form only",
     "        run, form = max((longest_run(c, pat)[0], name) for name, pat in forms)",
     '        run, form = longest_run(c, forms[0][1])[0], "exact"'),
    ("check_body_not_on_wire downgrades a found leak to INCONCLUSIVE "
     "when the control is missing",
     "    if full_hits:\n        return Verdict(False,",
     "    if not control_hits:\n        return Verdict(False, 'x', ev, "
     "status='inconclusive')\n    if full_hits:\n        return Verdict(False,"),
    # what the C64 says
    ("check_shadow_ram_readable accepts an unread $A000",
     *_off("    if bytes_at_a000 is None:")),
    ("check_shadow_ram_readable accepts a short read",
     *_off("    if len(bytes_at_a000) < 12:")),
    ("check_shadow_ram_readable loses the CBMBASIC-signature arm",
     "            BASIC_ROM_SIGNATURE in bytes_at_a000[:16]:",
     "            False:"),
    ("check_tls_connected skips the unread test (KNOWN EQUIVALENT)",
     *_off("    if tls_state_max is None:")),
    ("check_tls_connected skips the ERROR test (KNOWN EQUIVALENT)",
     *_off("    if tls_state_max == TLS_STATE_ERROR:")),
    ("check_http_response accepts an empty expected body",
     *_off("    if not expected_body:")),
    ("check_http_response accepts an unread response",
     *_off("    if status is None or resp_len is None or resp_buf is None:")),
    ("check_http_response accepts a non-200 status",
     *_off("    if status != 200:")),
    ("check_net_last_error accepts an unread byte",
     "    if value is None:\n        return Verdict(False, \"net_last_error was never",
     "    if False:\n        return Verdict(False, \"net_last_error was never"),
    ("check_net_last_error stops decoding a defined code",
     *_off("    if value in table:")),
    ("check_image_readback accepts an unread image",
     *_off("    if readback is None:")),
    ("check_image_readback accepts a length mismatch",
     *_off("    if len(readback) != len(expected):")),
    ("resolve_symbols accepts an empty request",
     *_off("    if not names:")),
    ("resolve_symbols accepts a missing symbol",
     *_off("    if missing:")),
    # #202: ip65's own config fields
    ("check_ip65_config_written accepts an unread field",
     *_off("    if unread:")),
    ("check_ip65_config_written accepts a field of the wrong width",
     "        if got is None or len(got) != size:",
     "        if got is None:"),
    ("check_ip65_config_written accepts fields still at their defaults",
     *_off("    if still_default:")),
    ("check_ip65_config_written never compares against the defaults",
     *_off("        if tuple(got) == tuple(default):")),
    ("check_ip65_config_written treats cfg_ip as non-decisive",
     '"cfg_ip": (cfg_ip, IP65_DEFAULT_CFG_IP, 4, True),',
     '"cfg_ip": (cfg_ip, IP65_DEFAULT_CFG_IP, 4, False),'),
    ("check_ip65_config_written treats cfg_gateway as non-decisive",
     '"cfg_gateway": (cfg_gateway, IP65_DEFAULT_CFG_GATEWAY, 4, True),',
     '"cfg_gateway": (cfg_gateway, IP65_DEFAULT_CFG_GATEWAY, 4, False),'),
    ("check_ip65_config_written treats cfg_mac as non-decisive",
     '"cfg_mac": (cfg_mac, IP65_DEFAULT_CFG_MAC, 6, True),',
     '"cfg_mac": (cfg_mac, IP65_DEFAULT_CFG_MAC, 6, False),'),
    ("check_ip65_config_written ASSERTS the netmask (fails a healthy /24)",
     '"cfg_netmask": (cfg_netmask, IP65_DEFAULT_CFG_NETMASK, 4, False),',
     '"cfg_netmask": (cfg_netmask, IP65_DEFAULT_CFG_NETMASK, 4, True),'),
    ("check_ip65_config_written accepts all-zero cfg_ip / cfg_mac",
     *_off("    if zeroed:")),
    ("check_ip65_config_written accepts an all-zero cfg_mac",
     '(("cfg_ip", cfg_ip), ("cfg_mac", cfg_mac))',
     '(("cfg_ip", cfg_ip),)'),
    ("check_ip65_config_written accepts an all-zero cfg_ip",
     '(("cfg_ip", cfg_ip), ("cfg_mac", cfg_mac))',
     '(("cfg_mac", cfg_mac),)'),
    ("check_ip65_config_written ignores every expected value",
     *_off("    if wrong:")),
    ("check_ip65_config_written never compares against expect_*",
     *_off("        if want is not None and bytes(got) != bytes(want):")),
    ("check_ip65_config_written ignores expect_ip",
     '    for name, got, want in (("cfg_ip", cfg_ip, expect_ip),',
     '    for name, got, want in ('),
    ("check_ip65_config_written ignores expect_gateway",
     '                            ("cfg_gateway", cfg_gateway, expect_gateway),',
     ''),
    ("check_ip65_config_written ignores expect_mac",
     '                            ("cfg_mac", cfg_mac, expect_mac)):',
     '                            ):'),
    ("read_ip65_config follows a pointer that cannot be ip65's",
     *_off("        if not lo <= ptr <= hi - size:")),
    ("read_ip65_config lets a field run past the end of ip65's range",
     "        if not lo <= ptr <= hi - size:",
     "        if not lo <= ptr <= hi:"),
    ("read_ip65_config keeps a short read",
     "        fields[name] = got if len(got) == size else None",
     "        fields[name] = got"),
    ("read_ip65_config reads the wrong pointer-table slot",
     "IP65_VT_ADDR = IP65_BLOB_BASE + 33",
     "IP65_VT_ADDR = IP65_BLOB_BASE + 35"),
    ("read_ip65_config swaps the netmask and gateway slots",
     '("cfg_netmask", 4, 4), ("cfg_gateway", 6, 4))',
     '("cfg_netmask", 6, 4), ("cfg_gateway", 4, 4))'),
]

#: Mutants that CANNOT be detected, with the reason. Reported, never hidden.
#: Each one leaves `ok`, `status` and every evidence field a caller branches
#: on unchanged for EVERY input; the branch is kept for its message.
KNOWN_EQUIVALENT = {
    "check_client_hello_on_wire skips the empty-stream test (KNOWN EQUIVALENT)":
        "parse_tls_records(b'') is [], so the no-records branch fails the "
        "same input with the same status",
    "check_body_not_on_wire skips the empty-capture test (KNOWN EQUIVALENT)":
        "no frames means no corpora, so no control hit and no secret hit: "
        "the no-control branch returns the same INCONCLUSIVE",
    "check_tls_connected skips the unread test (KNOWN EQUIVALENT)":
        "None != TLS_STATE_CONNECTED, so the not-CONNECTED branch fails it "
        "with the same status",
    "check_tls_connected skips the ERROR test (KNOWN EQUIVALENT)":
        "$FF != TLS_STATE_CONNECTED, so the not-CONNECTED branch fails it "
        "with the same status",
}


def stage(root: Path, source: Path = REPO) -> None:
    (root / "tools").mkdir(parents=True)
    (root / "src" / "net" / "ip65").mkdir(parents=True)
    (root / "build").mkdir(parents=True)
    (root / "ip65-build").mkdir(parents=True)
    for rel in ("tools/ip65_hw_checks.py", "tools/test_ip65_hw_checks_unit.py",
                "tools/rig-up-rrnet-macos.sh", "src/net/ip65/ip65_errors.inc",
                "src/net/ip65/ip65_symbols.inc", "ip65-build/ip65_stub.s"):
        if (source / rel).exists():
            shutil.copy(source / rel, root / rel)
    # Build outputs come from THIS checkout: they are inputs the suite reads,
    # not code under test.
    for rel in ("build/labels.txt", "ip65-build/ip65-c64.bin"):
        if (REPO / rel).exists():
            shutil.copy(REPO / rel, root / rel)


def run_suite(root: Path):
    """The suite, against the mirror. Bytecode caching OFF — see the docstring."""
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    r = subprocess.run(
        [sys.executable, str(root / "tools" / "test_ip65_hw_checks_unit.py")],
        capture_output=True, text=True, env=env)
    failed = [ln.strip() for ln in r.stdout.splitlines()
              if ln.strip().startswith(("FAIL", "ERROR"))]
    return r.returncode, failed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true",
                    help="leave the scratch mirror in place for inspection")
    ap.add_argument("--source-root", type=Path, default=REPO,
                    help="mutate the module and suite from this tree instead")
    ap.add_argument("--allow-not-applicable", action="store_true",
                    help="report a mutant whose anchor is absent and move on, "
                         "instead of failing (for before/after comparisons)")
    args = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="ip65-mutate-"))
    try:
        stage(tmp, args.source_root.resolve())
        rc, failed = run_suite(tmp)
        if rc != 0:
            print(f"BASELINE IS ALREADY RED ({len(failed)} failures) — fix that "
                  "first; mutation results mean nothing against a red baseline")
            print("\n".join(failed))
            return 2
        print(f"baseline: {len(MUTANTS)} mutations to apply, suite green")
        names = [m[0] for m in MUTANTS]
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            print(f"DUPLICATE MUTANT NAMES {dupes}; results would be ambiguous")
            return 2

        mod = tmp / "tools" / "ip65_hw_checks.py"
        pristine = mod.read_text()
        survived, unexpected, skipped, equivalent, raised = [], [], [], [], []
        for name, old, new in MUTANTS:
            n = pristine.count(old)
            if n != 1:
                what = "NOT APPLICABLE" if n == 0 else f"AMBIGUOUS ({n} copies)"
                if n == 0 and args.allow_not_applicable:
                    print(f"  n/a         {name}")
                    skipped.append(name)
                    continue
                print(f"  !! {what}  {name}\n     (the anchor must occur exactly "
                      "once, or the mutation does not describe the code it "
                      "names, and proves nothing; update it)")
                unexpected.append(name)
                continue
            mod.write_text(pristine.replace(old, new, 1))
            rc, failed = run_suite(tmp)
            mod.write_text(pristine)
            if rc == 0:
                if name in KNOWN_EQUIVALENT:
                    print(f"  equivalent  {name}\n              "
                          f"{KNOWN_EQUIVALENT[name]}")
                    equivalent.append(name)
                else:
                    print(f"  SURVIVED    {name}")
                    survived.append(name)
                continue
            if name in KNOWN_EQUIVALENT:
                # Listed as undetectable but the suite caught it: the list is
                # wrong, and a stale entry would hide a real survivor later.
                print(f"  !! CAUGHT BUT LISTED EQUIVALENT  {name}")
                unexpected.append(name)
                continue
            who = ", ".join(sorted({f.split(":")[0].split()[-1]
                                    for f in failed}))
            # Caught only because the mutated check RAISED (e.g. len(None))
            # rather than returned a wrong verdict. Still a real difference --
            # the rig would crash instead of recording a verdict -- but a
            # weaker kind of evidence, so it is counted out loud.
            by_raise = bool(failed) and all(f.startswith("ERROR") for f in failed)
            if by_raise:
                raised.append(name)
            print(f"  caught{'*' if by_raise else ' '}     {name}\n"
                  f"              by {who}"
                  + ("  (by an exception only)" if by_raise else ""))

        applied = len(MUTANTS) - len(skipped)
        detectable = applied - len(equivalent)
        caught = detectable - len(survived) - len(unexpected)
        print(f"\n{caught}/{detectable} detectable mutants caught, "
              f"{len(equivalent)} known-equivalent, {len(raised)} of the "
              "catches by an exception only"
              + (f", {len(skipped)} not applicable to this tree" if skipped else ""))
        if survived:
            print("SURVIVORS:\n  " + "\n  ".join(survived))
        if survived or unexpected:
            print("A surviving mutant means the suite passes whether or not "
                  "the checker works.")
            return 1
        return 0
    finally:
        if args.keep:
            print(f"mirror kept at {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
