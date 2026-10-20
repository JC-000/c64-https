#!/usr/bin/env python3
"""Run the pytest set under several python3 interpreters, none pinned.

    python3 tools/pytest_interpreters.py [python ...]

Default: /usr/bin/python3 (macOS's) and every distinct python3 on PATH
(Homebrew's latest, typically), deduplicated by resolved path. Each gets
its own venv from tools/mkvenv.sh, then a plain `pytest` from the repo root.

An interpreter below c64-test-harness's floor cannot import the harness;
the modules that need it fail with ModuleNotFoundError('c64_test_harness').
Those are counted and reported as HARNESS-UNSUPPORTED, never as passes, and
do not fail that interpreter's verdict. Anything else that fails does.

Exit 0 only if every interpreter has no other failure; 1 otherwise.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HARNESS_MISSING = "No module named 'c64_test_harness'"


def default_interpreters() -> list[str]:
    seen, out = set(), []
    cands = ["/usr/bin/python3"]
    for d in os.environ.get("PATH", "").split(os.pathsep):
        cands.append(os.path.join(d, "python3"))
    for c in cands:
        if os.access(c, os.X_OK):
            real = os.path.realpath(c)
            if real not in seen:
                seen.add(real)
                out.append(c)
    return out


def run_one(py: str) -> bool:
    print(f"=== {py} ===", flush=True)
    mk = subprocess.run(["bash", str(REPO / "tools" / "mkvenv.sh"), py],
                        cwd=REPO, stdout=subprocess.PIPE, text=True)
    if mk.returncode != 0:
        print(f"  FAIL: mkvenv.sh exited {mk.returncode}")
        return False
    vpy = mk.stdout.strip().splitlines()[-1]
    with tempfile.TemporaryDirectory() as td:
        xml = os.path.join(td, "junit.xml")
        subprocess.run([vpy, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                        "--continue-on-collection-errors",
                        f"--junitxml={xml}"], cwd=REPO,
                       stdout=subprocess.DEVNULL)
        if not os.path.exists(xml):
            print("  FAIL: pytest produced no report")
            return False
        passed = harness = 0
        other: list[str] = []
        for case in ET.parse(xml).iter("testcase"):
            bad = case.find("failure")
            if bad is None:
                bad = case.find("error")
            if bad is None:
                if case.find("skipped") is None:
                    passed += 1
                continue
            text = (bad.get("message") or "") + (bad.text or "")
            name = f"{case.get('classname')}::{case.get('name')}"
            if HARNESS_MISSING in text:
                harness += 1
            else:
                other.append(name)
    print(f"  {passed} passed, {len(other)} failed"
          + (f", {harness} HARNESS-UNSUPPORTED (c64_test_harness not "
             f"importable under this interpreter)" if harness else ""))
    for name in other:
        print(f"    FAILED {name}")
    return not other


def main(argv: list[str]) -> int:
    pys = argv or default_interpreters()
    if not pys:
        print("no python3 interpreters found")
        return 1
    if not shutil.which("bash"):
        print("bash not found")
        return 1
    results = {py: run_one(py) for py in pys}
    print()
    for py, ok in results.items():
        print(f"  {'OK  ' if ok else 'FAIL'} {py}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
