"""_private_uci_build.py -- a BACKEND=uci build that is not build/ (#302).

Six pytest modules execute the shipped UCI 6502 bytes. build/ holds whatever
build ran last, so with an ip65 one in it they fail (#178: a missing
prerequisite is a failure) and a bare `pytest` was green on no single build.
`conftest.py` points those modules here instead -- always, even when build/
is a UCI build, because nothing proves that one is fresh.

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
_cached = None          # (dir, None) or (None, Unavailable): one make per run


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


def _tracked():
    """Tracked + untracked-unignored files, submodule contents included."""
    r = subprocess.run(["git", "ls-files", "-z", "--cached", "--others",
                        "--exclude-standard", "--recurse-submodules"],
                       cwd=REPO, capture_output=True)
    if r.returncode != 0:
        # --others and --recurse-submodules do not combine on older git.
        r = subprocess.run(["git", "ls-files", "-z", "--cached",
                            "--recurse-submodules"], cwd=REPO,
                           capture_output=True)
    if r.returncode != 0:
        raise Unavailable("git ls-files failed: " + r.stderr.decode()[-500:])
    return {f for f in r.stdout.decode().split("\0") if f}


def _sync(root: Path):
    want = _tracked()
    for rel in want:
        src, dst = REPO / rel, root / rel
        if not src.is_file():
            continue
        st = src.stat()
        if dst.is_file():
            dt = dst.stat()
            if dt.st_size == st.st_size and dt.st_mtime_ns == st.st_mtime_ns:
                continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    # A file deleted from the source must not linger (wildcard sources).
    for dirpath, dirs, files in os.walk(root):
        if Path(dirpath) == root and "build" in dirs:
            dirs.remove("build")
        for f in files:
            rel = os.path.relpath(os.path.join(dirpath, f), root)
            if rel not in want:
                os.unlink(os.path.join(dirpath, f))


def uci_build_dir() -> Path:
    """build dir of a FRESH BACKEND=uci c64-https.prg + labels.txt.

    Always the private copy, never build/: whatever build/ holds may predate a
    source edit. make is incremental there. Cached, failure included, so a
    broken build is one error rather than one make per test.
    """
    global _cached
    if _cached is None:
        try:
            _cached = (_build(), None)
        except Unavailable as exc:
            _cached = (None, exc)
    if _cached[1] is not None:
        raise _cached[1]
    return _cached[0]


def _build() -> Path:
    tag = hashlib.sha1(str(REPO).encode()).hexdigest()[:8]
    root = Path(os.environ.get("C64_PRIVATE_BUILD_ROOT")
                or tempfile.gettempdir()) / f"c64-https-pytest-uci-{tag}"
    root.parent.mkdir(parents=True, exist_ok=True)
    with open(f"{root}.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        root.mkdir(exist_ok=True)
        _sync(root)
        env = {k: v for k, v in os.environ.items()
               if k not in ("BACKEND", "MAKEFLAGS", "MFLAGS", "MAKELEVEL")}
        m = subprocess.run(["make", "BACKEND=uci"], cwd=root, env=env,
                           capture_output=True, text=True)
        if m.returncode != 0:
            raise Unavailable("private `make BACKEND=uci` in %s failed:\n%s"
                              % (root, (m.stderr or m.stdout)[-2000:]))
    out = root / "build"
    if _backend(out) != "uci" or not (out / "c64-https.prg").is_file():
        raise Unavailable(f"{out} is not a BACKEND=uci build after make")
    return out
