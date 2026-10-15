"""_private_uci_build.py -- a BACKEND=uci build that is not build/ (#302).

Six pytest modules execute the shipped UCI 6502 bytes. build/ holds whatever
build ran last, so with an ip65 one in it they fail (#178: a missing
prerequisite is a failure) and a bare `pytest` was green on no single build.
`conftest.py` points those modules here instead -- always, even when build/
is a UCI build, because nothing proves that one is fresh.

The build runs in a private COPY of the tree (the Makefile and the sibling
wrappers hard-code build/ next to themselves), re-synced and
cold-built every run. Any failure raises Unavailable -- the callers turn that
into a test failure (or, only under C64_UCI_TESTS_OPTIONAL=1, a loud skip).
"""
import atexit
import os
import shutil
import subprocess
import sys
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


def _ls(*args):
    try:
        r = subprocess.run(["git", "ls-files", "-z", *args], cwd=REPO,
                           capture_output=True)
    except OSError as exc:
        raise Unavailable(f"cannot run git: {exc}")
    if r.returncode != 0:
        raise Unavailable("git ls-files %s failed (rc=%d): %s"
                          % (" ".join(args), r.returncode,
                             r.stderr.decode()[-500:]))
    return {f for f in r.stdout.decode().split("\0") if f}


def _tracked():
    """Working-tree files: tracked (submodule contents included) plus
    untracked-unignored. Two calls: git refuses to combine --others with
    --recurse-submodules. Entries whose file is gone (unstaged delete) drop."""
    want = _ls("--cached", "--recurse-submodules")
    want |= _ls("--others", "--exclude-standard")
    return {f for f in want if (REPO / f).is_file()}


def _sync(root: Path):
    """Copy the working tree over root, unconditionally: a size+mtime skip
    would miss a same-size edit that kept its old mtime."""
    want = _tracked()
    for rel in want:
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / rel, dst)
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
    source edit. The build there is cold every run. Cached, failure included, so a
    broken build is one error rather than one make per test.
    """
    global _cached
    if _cached is None:
        try:
            _cached = (_build(), None)
        except Unavailable as exc:
            _cached = (None, exc)
    if _cached[1] is not None:
        # Fresh each time: re-raising the cached object grows its traceback.
        raise Unavailable(str(_cached[1]))
    return _cached[0]


def _build() -> Path:
    """A per-process private tree, so concurrent pytest runs in one checkout
    never delete each other's build/. Removed at exit."""
    parent = Path(os.environ.get("C64_PRIVATE_BUILD_ROOT")
                  or tempfile.gettempdir())
    try:
        parent.mkdir(parents=True, exist_ok=True)
        root = Path(tempfile.mkdtemp(prefix="c64-https-pytest-uci-",
                                     dir=parent))
    except OSError as exc:
        raise Unavailable(f"cannot create a private build dir: {exc}")
    atexit.register(shutil.rmtree, root, True)
    _sync(root)
    env = {k: v for k, v in os.environ.items()
           if k not in ("BACKEND", "MAKEFLAGS", "MFLAGS", "MAKELEVEL")}
    try:
        m = subprocess.run(["make", "BACKEND=uci"], cwd=root, env=env,
                           capture_output=True, text=True)
    except OSError as exc:
        raise Unavailable(f"cannot run make: {exc}")
    if m.returncode != 0:
        raise Unavailable("private `make BACKEND=uci` in %s failed:\n%s"
                          % (root, (m.stderr or m.stdout)[-2000:]))
    out = root / "build"
    if _backend(out) != "uci" or not (out / "c64-https.prg").is_file():
        raise Unavailable(f"{out} is not a BACKEND=uci build after make")
    return out


ENV = "C64_UCI_BUILD_DIR"


class BuildFile:
    """A path into the UCI build, resolved at use, not at import.

    conftest.py exports ENV (this process's private build) before any of the
    six UCI modules runs, whatever pytest's import mode names them. Under
    pytest with ENV unset the path points at a directory that cannot exist, so
    the module fails closed instead of reading a stale build/. Standalone
    (`python3 tools/test_uci_*.py`) it is build/, as before.
    """

    def __init__(self, name):
        self.name = name

    def path(self) -> Path:
        d = os.environ.get(ENV)
        if d:
            return Path(d) / self.name
        if "pytest" in sys.modules:
            return Path(f"<{ENV} unset under pytest>") / self.name
        return REPO / "build" / self.name

    def __getattr__(self, attr):
        return getattr(self.path(), attr)

    def __str__(self):
        return str(self.path())
