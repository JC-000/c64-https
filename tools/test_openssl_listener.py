#!/usr/bin/env python3
"""tools/test_openssl_listener.py - the PQ rigs' OpenSSL listener cannot lie.

openssl_listener.py once printed LISTENING after probing the port: when
another process already held it (the fleet's 4433), the probe connected to THAT
process while our s_server had died on the bind, and a rig then ran against a
stranger's server. It now reports LISTENING only when s_server prints ACCEPT.
Red case: occupy a port, the launcher must exit non-zero and never print
LISTENING. Green control: a free port prints LISTENING. Needs OpenSSL 3.x
(Homebrew openssl@3; the launcher says so if it is missing, and that is a
failure here, not a skip).

    pytest tools/test_openssl_listener.py
"""
from __future__ import annotations

import socket
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LISTENER = REPO / "tools" / "https_e2e" / "openssl_listener.py"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]


def _run(port, wait):
    keylog = Path(tempfile.mkdtemp(prefix="listener_test_")) / "k"
    p = subprocess.Popen([sys.executable, str(LISTENER), "--port", str(port), "--keylog", str(keylog),
                          "--groups", "X25519"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        out, err = p.communicate(timeout=wait)
        return p.returncode, out, err
    except subprocess.TimeoutExpired:
        p.terminate()
        out, err = p.communicate(timeout=10)
        return None, out, err


def test_a_port_held_by_someone_else_is_an_error():
    holder = socket.socket()
    holder.bind(("0.0.0.0", 0))
    holder.listen(1)
    try:
        rc, out, err = _run(holder.getsockname()[1], 30)
    finally:
        holder.close()
    assert rc not in (None, 0), f"rc={rc}\n{out}\n{err}"
    assert "LISTENING" not in out, out


def test_a_free_port_reports_listening():
    rc, out, err = _run(_free_port(), 8)
    assert rc is None and "LISTENING" in out, f"rc={rc}\n{out}\n{err}"


def main() -> int:
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failed += 1
            print(f"  FAIL  {name}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.path.insert(0, str(REPO / "tools"))
    from _skip_policy import verdict
    return verdict(len(tests) - failed, failed, certifies="the OpenSSL test listener")


if __name__ == "__main__":
    sys.exit(main())
