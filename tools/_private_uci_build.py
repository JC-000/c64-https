"""_private_uci_build.py -- a BACKEND=uci build that is not build/ (#302).

Six pytest modules execute the shipped UCI 6502 bytes. build/ holds whatever
build ran last, so with an ip65 one in it they fail (#178: a missing
prerequisite is a failure) and a bare `pytest` was green on no single build.
`conftest.py` points those modules here instead, but only when build/ is not
already a UCI build: then build/ is used as is, and nothing is copied.

The build runs in a private COPY of the tree (the Makefile and the sibling
wrappers hard-code build/ next to themselves), kept between runs so make
rebuilds only what changed. Any failure raises Unavailable -- the callers
turn that into a test failure, never a skip.
"""
import fcntl
import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_EXCLUDES = ("build", ".git", "__pycache__", ".pytest_cache", "dist")


class Unavailable(Exception):
    """No UCI build could be produced."""


def _backend(build_dir: Path):
    try:
        for line in (build_dir / "flags.stamp").read_text().splitlines():
            if line.startswith("BACKEND="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return None


def uci_build_dir() -> Path:
    """The directory holding a BACKEND=uci c64-https.prg + labels.txt."""
    if (_backend(REPO / "build") == "uci"
            and (REPO / "build" / "c64-https.prg").is_file()
            and (REPO / "build" / "labels.txt").is_file()):
        return REPO / "build"
    if not shutil.which("rsync"):
        raise Unavailable("rsync is not on PATH; cannot stage a private "
                          "BACKEND=uci build (or `make BACKEND=uci` in "
                          "the tree)")
    tag = hashlib.sha1(str(REPO).encode()).hexdigest()[:8]
    root = Path(os.environ.get("C64_PRIVATE_BUILD_ROOT")
                or tempfile.gettempdir()) / f"c64-https-pytest-uci-{tag}"
    root.parent.mkdir(parents=True, exist_ok=True)
    with open(f"{root}.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        cmd = ["rsync", "-a", "--delete"]
        for ex in _EXCLUDES:
            cmd += ["--exclude", f"/{ex}" if ex in ("build", "dist") else ex]
        # --delete must not eat the copy's own build/.
        cmd += ["--filter", "P /build", f"{REPO}/", f"{root}/"]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise Unavailable(f"staging the private tree failed: {r.stderr}")
        env = {k: v for k, v in os.environ.items()
               if k not in ("BACKEND", "MAKEFLAGS", "MFLAGS", "MAKELEVEL")}
        m = subprocess.run(["make", "BACKEND=uci"], cwd=root, env=env,
                           capture_output=True, text=True)
        if m.returncode != 0:
            raise Unavailable("private `make BACKEND=uci` failed:\n"
                              + (m.stderr or m.stdout)[-2000:])
    out = root / "build"
    if _backend(out) != "uci" or not (out / "c64-https.prg").is_file():
        raise Unavailable(f"{out} is not a BACKEND=uci build after make")
    return out
