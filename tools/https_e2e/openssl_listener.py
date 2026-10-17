#!/usr/bin/env python3
"""openssl_listener.py - an OpenSSL 3.5+ `s_server` for the PQ_HYBRID rigs.

Python's ssl module (and macOS /usr/bin/openssl, which is LibreSSL) cannot do
X25519MLKEM768; Homebrew's openssl@3 can. This launches its `s_server` with the
repo's throwaway P-256 test certificate (tools/https_e2e/ensure_certs.py),
TLS 1.3, the one suite this client offers, a chosen group list, a key log, and a
reply to GET (sent through s_server's stdin) carrying the body
tools/uci/rig_https_local.py expects.

    openssl_listener.py --groups X25519 --port 4433 --keylog /tmp/k.log
    openssl_listener.py --groups X25519MLKEM768 ...

Prints "LISTENING <port> <openssl version>" once the server accepts, then runs
until killed. Group selection is the server's whole policy: under
`-groups X25519` it answers 001D to a hybrid ClientHello, under
`-groups X25519MLKEM768` it answers 11EC (a 1,120 B key_exchange).
"""

import argparse
import os
import pty
import select
import termios
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

# Sent through s_server's own stdin once the request line arrives: the
# interactive server forwards stdin lines to the peer, and `Q` closes the
# connection. (-HTTP/-WWW cannot serve "GET /": they open the empty file name.)
BODY = (b"HTTP/1.0 200 OK\r\nContent-Length: 22\r\n\r\nHELLO FROM TLS SERVER\n")


def find_openssl():
    cands = [os.environ.get("OPENSSL"), "/opt/homebrew/opt/openssl@3/bin/openssl",
             "/usr/local/opt/openssl@3/bin/openssl", shutil.which("openssl")]
    for c in cands:
        if c and Path(c).exists():
            out = subprocess.run([c, "version"], capture_output=True, text=True).stdout
            if out.startswith("OpenSSL 3."):
                return c, out.strip()
    raise SystemExit("no OpenSSL 3.x `openssl` found (macOS /usr/bin/openssl is LibreSSL); "
                     "brew install openssl@3 or set OPENSSL=")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--groups", default="X25519MLKEM768:X25519")
    ap.add_argument("--port", type=int, default=4433)
    ap.add_argument("--keylog", required=True)
    ap.add_argument("--bind", default="0.0.0.0")
    a = ap.parse_args(argv)
    from ensure_certs import ensure_certs
    cert, key = ensure_certs("p256")
    exe, ver = find_openssl()
    Path(a.keylog).unlink(missing_ok=True)
    cmd = [exe, "s_server", "-accept", f"{a.bind}:{a.port}", "-cert", str(cert),
           "-key", str(key), "-tls1_3", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256",
           "-groups", a.groups, "-keylogfile", a.keylog, "-num_tickets", "0", "-state"]
    # A pty, not pipes: s_server block-buffers stdout on a pipe, and the request
    # line would sit in its buffer instead of reaching us.
    master, slave = pty.openpty()
    # canonical mode (s_server parses the `Q` line) but no CR/LF translation,
    # so the CRLFs of the HTTP response reach the peer as written
    attrs = termios.tcgetattr(slave)
    attrs[0] &= ~(termios.ICRNL | termios.INLCR | termios.IGNCR)
    attrs[1] &= ~termios.OPOST
    attrs[3] &= ~termios.ECHO
    termios.tcsetattr(slave, termios.TCSANOW, attrs)
    proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)

    def stop(*_):
        proc.terminate()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    # LISTENING only when s_server itself reports it is accepting ("ACCEPT"
    # on its console). Probing the port instead would "succeed" against a
    # foreign process already holding it, with our s_server dead behind it.
    boot = b""
    deadline = time.monotonic() + 15
    while b"ACCEPT" not in boot:
        if proc.poll() is not None or time.monotonic() > deadline \
                or b"Address already in use" in boot or b"unable to bind" in boot:
            proc.terminate()
            sys.stderr.write(boot.decode("latin-1") + "\nERROR: s_server is not listening on "
                             f"{a.bind}:{a.port} (port in use, or it died)\n")
            return 2
        r, _, _ = select.select([master], [], [], 0.2)
        if r:
            try:
                boot += os.read(master, 4096)
            except OSError:
                pass
    sys.stdout.write(boot.decode("latin-1").replace("\r\n", "\n"))
    print(f"LISTENING {a.port} {ver} groups={a.groups}", flush=True)
    buf = b""
    try:
        while True:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            sys.stdout.write(chunk.decode("latin-1").replace("\r\n", "\n"))
            sys.stdout.flush()
            buf += chunk
            if b"GET " in buf:
                buf = b""
                os.write(master, BODY + b"Q\n")
    finally:
        proc.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
