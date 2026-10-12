"""The trust rigs' TRUST.A / TRUST.B files, through c64-test-harness storage (#155).

rig_trust_store.py and rig_trust_policy.py read, write and delete the store
files on the device's removable volume. They do it only through the
harness's storage API (``storage_*``), never over a private FTP session, so
the harness's rules hold for every call: the DeviceLock must be held by
this process, ``/Temp`` and ``/Flash`` are never written, paths are
validated, and a failed new-file upload is removed.

The store directory is baked into the image (``TRUST_STORE_DIR`` at build
time), so the rig cannot move it at run time; it can only check that the
image's directory is somewhere the device can write. ``select_store_dir``
does that:

* the directory must be ``/<volume>/c64https-test`` -- the rigs delete
  TRUST.A / TRUST.B there and remove the directory, so they refuse any
  directory a real store could live in;
* an explicit ``TRUST_STORE_DIR`` in the environment wins, and must be the
  image's directory (otherwise the C64 writes one place and the rig reads
  another);
* the volume must be in ``storage_writable_volumes(host)``.

Exit-code contract for a rig's setup: ``StoreUnavailable`` and
``Ultimate64StorageVolumeError`` mean "this device cannot host the test
store" -- COULD NOT RUN, exit 2. A C64U with no medium (``['Flash',
'Temp']``) lands there by design. Every other storage error (lock not
held, FTP unreachable, a transfer failure) is a real failure, never
reported as a missing volume.

``check_only_ours`` refuses a directory holding anything but TRUST.A /
TRUST.B. Listings omit hidden names (a leading ``.``, or the hidden
attribute), so TRUST.P -- which a TRUST_BUNDLE build reads -- is also
probed by name; a hidden file is caught only when ``storage_rmdir``
refuses the directory, and is reported, never forced.
"""
from __future__ import annotations

from c64_test_harness import (
    WRITE_REFUSED_VOLUMES,
    Ultimate64StorageNotEmptyError,
    Ultimate64StorageVolumeError,
    storage_delete_file,
    storage_get_file,
    storage_list_dir,
    storage_mkdir,
    storage_put_file,
    storage_rmdir,
    storage_volumes,
    storage_writable_volumes,
)

TEST_DIR_NAME = "c64https-test"
OURS = ("TRUST.A", "TRUST.B")
#: Read by the image when present (TRUST_BUNDLE=1), so it must not be.
PROBED = ("TRUST.P",)
SLOT_SUFFIX = "/TRUST."


class StoreUnavailable(Exception):
    """The store directory cannot be used on this device or with this image."""

    def __init__(self, message: str, available: list[str] | None = None) -> None:
        super().__init__(message)
        self.available = list(available or [])


class StoreLeftovers(StoreUnavailable):
    """The emptied test directory cannot be removed: it still holds entries
    -- hidden ones the listing omits (.DS_Store, ._*) when none are named.

    Who put them there decides the exit code. Met at SETUP they predate the
    run: device state, COULD NOT RUN (2). Met at phase 14 or at cleanup they
    were written DURING the run -- setup proved the directory removable and
    the DeviceLock excludes other FTP writers -- so the program under test
    wrote them: a failure (1)."""

    def __init__(self, directory: str, what: str) -> None:
        super().__init__(f"{directory} cannot be removed: it still holds {what}")
        self.what = what


#: Setup errors that mean COULD NOT RUN (exit 2). Nothing else does.
CANNOT_RUN_ERRORS = (StoreUnavailable, Ultimate64StorageVolumeError)


def _vols(names) -> str:
    return ", ".join("/" + n for n in names) or "(none)"


def image_dir(store_path: str) -> str:
    """The directory of an image's slot path ``/<vol>/c64https-test/TRUST.``.

    Raises StoreUnavailable for any other shape (no volume, not the
    dedicated test directory)."""
    if not store_path.endswith(SLOT_SUFFIX):
        raise StoreUnavailable(f"the image's store path {store_path!r} does not end in "
                               f"{SLOT_SUFFIX!r}")
    d = store_path[: -len(SLOT_SUFFIX)]
    parts = d.split("/")
    if len(parts) != 3 or parts[0] != "" or not parts[1] or parts[2] != TEST_DIR_NAME:
        raise StoreUnavailable(
            f"the image stores at {store_path!r}; the trust rigs only run against "
            f"TRUST_STORE_DIR=/<volume>/{TEST_DIR_NAME} (they delete TRUST.A/TRUST.B there)")
    return d


def select_store_dir(host: str, store_path: str, explicit: str | None = None) -> str:
    """The test directory to use, in the device's spelling of its volume.

    *store_path* is the slot path baked into the image; *explicit* is
    ``$TRUST_STORE_DIR`` (or None). Needs the DeviceLock (it lists volumes).
    """
    want = image_dir(store_path)
    if explicit:
        explicit = explicit.rstrip("/")
        image_dir(explicit + SLOT_SUFFIX)          # same shape rules
        if explicit.casefold() != want.casefold():
            raise StoreUnavailable(
                f"TRUST_STORE_DIR={explicit} but the image was built for {want}; "
                f"rebuild with TRUST_STORE_DIR={explicit}")
        want = explicit
    vol = want.split("/")[1]
    if vol.casefold() in WRITE_REFUSED_VOLUMES:
        raise StoreUnavailable(f"{want} is on /{vol}, which the harness never writes")
    writable = storage_writable_volumes(host)
    for v in writable:
        if v.casefold() == vol.casefold():
            return f"/{v}/{TEST_DIR_NAME}"
    volumes = storage_volumes(host)                # only to name them
    if not writable:
        raise StoreUnavailable(
            f"{host} has no writable storage volume (available: {_vols(volumes)}; "
            f"/Temp and /Flash are never written). Insert a USB stick or SD card.",
            volumes)
    raise StoreUnavailable(
        f"/{vol} is not a writable volume on {host} (available: {_vols(volumes)}); "
        f"rebuild with TRUST_STORE_DIR=/{writable[0]}/{TEST_DIR_NAME}", volumes)


class TrustFiles:
    """TRUST.A / TRUST.B in one test directory, via the harness storage API."""

    def __init__(self, host: str, directory: str) -> None:
        self.host, self.dir = host, directory
        self.a, self.b = f"{directory}/TRUST.A", f"{directory}/TRUST.B"

    def get(self, path: str) -> bytes | None:
        """The file's bytes, or None when it does not exist. Every other
        error (lock not held, FTP failure) propagates."""
        try:
            return storage_get_file(self.host, path)
        except FileNotFoundError:
            return None

    def put(self, path: str, data: bytes) -> None:
        """Write a store image. Zero bytes is refused here, by name: the
        store format never produces one (header + checksum is 16 B), the
        harness refuses it, and the U64E would create no file for it, so a
        rig that wants "no file" must call delete()."""
        if not data:
            raise ValueError(f"refusing a zero-byte trust file at {path}: "
                             "use TrustFiles.delete() for an absent slot")
        if path not in (self.a, self.b):
            raise ValueError(f"{path} is not one of this rig's files ({self.a}, {self.b})")
        storage_put_file(self.host, path, bytes(data), overwrite=True)

    def delete(self, name: str) -> None:
        if name not in OURS:
            raise ValueError(f"{name} is not one of this rig's files {OURS}")
        storage_delete_file(self.host, f"{self.dir}/{name}", missing_ok=True)

    def delete_ours(self) -> None:
        for n in OURS:
            self.delete(n)

    def check_only_ours(self) -> None:
        """StoreUnavailable if the directory exists and holds anything but
        TRUST.A / TRUST.B (visible entries, or TRUST.P by name)."""
        try:
            names = [e.name for e in storage_list_dir(self.host, self.dir)]
        except FileNotFoundError:
            return
        foreign = sorted(set(names) - set(OURS))
        for n in PROBED:
            if n not in foreign and self.get(f"{self.dir}/{n}") is not None:
                foreign.append(n)
        if foreign:
            raise StoreUnavailable(
                f"{self.dir} holds files that are not the rig's: {foreign}; "
                "move them away (the rig deletes TRUST.A/TRUST.B and removes the directory)")

    def ensure_dir(self) -> bool:
        """Create the test directory if missing; True if it was created."""
        return storage_mkdir(self.host, self.dir, exist_ok=True)

    def remove_dir(self) -> bool:
        """Remove the (emptied) test directory: True if removed, False if it
        was absent. Leftovers raise StoreLeftovers -- hidden entries are
        reported, never forced."""
        try:
            return storage_rmdir(self.host, self.dir, missing_ok=True)
        except Ultimate64StorageNotEmptyError as exc:
            what = (f"visible entries {exc.entries}" if exc.entries else
                    "hidden entries the listing omits (e.g. .DS_Store, ._*)")
            raise StoreLeftovers(self.dir, what) from exc

    def prepare(self) -> None:
        """Setup, in order: refuse a foreign directory; prove the directory
        can be removed (hidden leftovers are COULD NOT RUN here, before the
        device is touched, not a phase-14 failure later); recreate it."""
        self.check_only_ours()
        self.delete_ours()
        try:
            self.remove_dir()
        except StoreLeftovers as exc:
            raise StoreLeftovers(self.dir, exc.what + " from before this run; "
                                 "remove them by hand") from exc
        self.ensure_dir()


def clean_up(store: "TrustFiles | None") -> tuple[int, str]:
    """End of run: delete TRUST.A/B and remove the directory, under the lock.

    Returns ``(0, msg)`` when done and ``(1, msg)`` otherwise: a cleanup
    failure leaves TRUST.A/B behind, and leftovers here were written during
    the run (see StoreLeftovers) -- neither may exit 0. Leftovers are
    reported, never forced."""
    if store is None:
        return 0, "cleanup: nothing to clean"
    try:
        store.delete_ours()
        store.remove_dir()
    except StoreLeftovers as exc:
        return 1, (f"cleanup: {', '.join(OURS)} deleted, but {exc}; "
                   "written DURING the run (setup proved the directory removable and the DeviceLock excludes other writers), so the program under test left it")
    except Exception as exc:  # noqa: BLE001 - reported, and turns the exit non-zero
        return 1, f"cleanup of {store.dir} FAILED: {type(exc).__name__}: {exc}"
    return 0, f"cleanup: {', '.join(OURS)} deleted; {store.dir} removed"


def final_exit(rc: int, cleanup: tuple[int, str]) -> int:
    """Fold the cleanup result into the run's exit code: a failed cleanup
    turns any other code into 1."""
    crc, msg = cleanup
    if crc == 0 or rc == 1:
        return rc
    print(f"[fatal] {msg}")
    return 1
