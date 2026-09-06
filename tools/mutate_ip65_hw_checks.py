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

ONE KNOWN-EQUIVALENT MUTANT, and it is reported as a survivor rather than
suppressed: removing the length test from `check_http_response` cannot be
detected, because `got = resp_buf[:resp_len]` already has the wrong length
whenever `resp_len` is wrong, so the exact-content compare subsumes it.
The length test is kept for its error message, not for its coverage.

A METHODOLOGY TRAP, fixed here rather than left for the next reader.
Python caches bytecode on (mtime, size), and a mutation harness rewrites
the same path many times within the same second. Two different mutants
whose files happen to be the same length then run the FIRST one's
bytecode, and the results are silently wrong — on the first run of this
script three verdicts were attributed to `test_image_readback_red_green`,
which does not test any of them. The subprocess is therefore launched with
PYTHONDONTWRITEBYTECODE=1. A harness that certifies other checks must not
itself be the unreliable part.

    python3 tools/mutate_ip65_hw_checks.py [--keep]
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

#: (description, text to find in the module, text to replace it with).
#: Each mutation is a plausible weaker implementation, not a random edit.
MUTANTS = [
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
    ("check_http_response drops the length test (KNOWN EQUIVALENT)",
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
]

#: Mutants that CANNOT be detected, with the reason. Reported, never hidden.
KNOWN_EQUIVALENT = {
    "check_http_response drops the length test (KNOWN EQUIVALENT)":
        "resp_buf[:resp_len] already has the wrong length when resp_len is "
        "wrong, so the exact-content compare subsumes this test; it is kept "
        "for its error message",
}


def stage(root: Path) -> None:
    (root / "tools").mkdir(parents=True)
    (root / "src" / "net" / "ip65").mkdir(parents=True)
    (root / "build").mkdir(parents=True)
    for rel in ("tools/ip65_hw_checks.py", "tools/test_ip65_hw_checks_unit.py",
                "tools/rig-up-rrnet-macos.sh", "src/net/ip65/ip65_errors.inc"):
        shutil.copy(REPO / rel, root / rel)
    if (REPO / "build" / "labels.txt").exists():
        shutil.copy(REPO / "build" / "labels.txt", root / "build" / "labels.txt")


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
    args = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="ip65-mutate-"))
    try:
        stage(tmp)
        rc, failed = run_suite(tmp)
        if rc != 0:
            print(f"BASELINE IS ALREADY RED ({len(failed)} failures) — fix that "
                  "first; mutation results mean nothing against a red baseline")
            print("\n".join(failed))
            return 2
        print(f"baseline: {len(MUTANTS)} mutations to apply, suite green")

        mod = tmp / "tools" / "ip65_hw_checks.py"
        pristine = mod.read_text()
        survived, unexpected = [], []
        for name, old, new in MUTANTS:
            if old not in pristine:
                print(f"  !! NOT APPLICABLE  {name}\n     (the anchor text is "
                      "gone — the mutation no longer describes the code, so "
                      "this proves nothing; update it)")
                unexpected.append(name)
                continue
            mod.write_text(pristine.replace(old, new, 1))
            rc, failed = run_suite(tmp)
            mod.write_text(pristine)
            if rc == 0:
                if name in KNOWN_EQUIVALENT:
                    print(f"  equivalent  {name}\n              "
                          f"{KNOWN_EQUIVALENT[name]}")
                else:
                    print(f"  SURVIVED    {name}")
                    survived.append(name)
                continue
            who = ", ".join(sorted({f.split(":")[0].split()[-1]
                                    for f in failed}))
            print(f"  caught      {name}\n              by {who}")

        detectable = [m for m in MUTANTS if m[0] not in KNOWN_EQUIVALENT]
        caught = len(detectable) - len(survived) - len(unexpected)
        print(f"\n{caught}/{len(detectable)} detectable mutants caught, "
              f"{len(KNOWN_EQUIVALENT)} known-equivalent")
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
