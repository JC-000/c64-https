"""The trust rigs' TRUST.A / TRUST.B files, through c64-test-harness storage (#155).

rig_trust_store.py and rig_trust_policy.py read, write and delete the store
files on the device's removable volume. They do it only through the
harness's storage API (``storage_volumes`` / ``storage_get_file`` /
``storage_put_file`` / ``storage_mkdir`` / ``storage_delete_file``), never
over a private FTP session, so the harness's rules hold for every call:
the DeviceLock must be held by this process, ``/Temp`` and ``/Flash`` are
never written, paths are validated, and a failed new-file upload is
removed.

The store directory is baked into the image (``TRUST_STORE_DIR`` at build
time), so the rig cannot move it at run time; it can only check that the
image's directory is somewhere the device can write. ``select_store_dir``
does that:

* the directory must be ``/<volume>/c64https-test`` -- the rigs delete
  TRUST.A / TRUST.B there, so they refuse any directory a real store could
  live in;
* an explicit ``TRUST_STORE_DIR`` in the environment wins, and must be the
  image's directory (otherwise the C64 writes one place and the rig reads
  another);
* the volume must be in ``storage_volumes(host)`` minus
  ``WRITE_REFUSED_VOLUMES`` (compared casefolded: the device says ``Flash``,
  the harness's set holds ``flash``).

Anything else is ``StoreUnavailable``, which the rigs turn into a COULD NOT
RUN block and exit 2. A C64U with no medium (``['Flash', 'Temp']``) lands
there by design.

The harness has no directory listing or rmdir: the rigs only ever touch
the two file names in ``OURS``, and leave the (empty) test directory in
place at the end.
"""
from __future__ import annotations

from c64_test_harness import (
    WRITE_REFUSED_VOLUMES,
    Ultimate64StorageError,
    Ultimate64StorageVolumeError,
    storage_delete_file,
    storage_get_file,
    storage_mkdir,
    storage_put_file,
    storage_volumes,
)

TEST_DIR_NAME = "c64https-test"
OURS = ("TRUST.A", "TRUST.B")
SLOT_SUFFIX = "/TRUST."

#: What a rig's setup may raise that means "this device cannot host the
#: store" rather than "the code under test is wrong": exit 2, not 1.
SETUP_ERRORS = (Ultimate64StorageVolumeError, Ultimate64StorageError)


class StoreUnavailable(Exception):
    """The store directory cannot be used on this device or with this image."""

    def __init__(self, message: str, available: list[str] | None = None) -> None:
        super().__init__(message)
        self.available = list(available or [])


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


def writable_volumes(volumes) -> list[str]:
    """``volumes`` minus the harness's write-refused set, compared casefolded."""
    return [v for v in volumes if v.casefold() not in WRITE_REFUSED_VOLUMES]


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
    volumes = storage_volumes(host)
    writable = writable_volumes(volumes)
    if not writable:
        raise StoreUnavailable(
            f"{host} has no writable storage volume (available: {_vols(volumes)}; "
            f"/Temp and /Flash are never written). Insert a USB stick or SD card.",
            volumes)
    for v in writable:
        if v.casefold() == vol.casefold():
            return f"/{v}/{TEST_DIR_NAME}"
    raise StoreUnavailable(
        f"/{vol} is not a writable volume on {host} (available: {_vols(volumes)}); "
        f"rebuild with TRUST_STORE_DIR=/{writable[0]}/{TEST_DIR_NAME}", volumes)


class TrustFiles:
    """TRUST.A / TRUST.B in one test directory, via the harness storage API."""

    def __init__(self, host: str, directory: str) -> None:
        self.host, self.dir = host, directory
        self.a, self.b = f"{directory}/TRUST.A", f"{directory}/TRUST.B"

    def get(self, path: str) -> bytes | None:
        """The file's bytes, or None when it does not exist."""
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

    def ensure_dir(self) -> bool:
        """Create the test directory if missing; True if it was created."""
        return storage_mkdir(self.host, self.dir, exist_ok=True)

    def dir_exists(self, directory: str | None = None) -> bool:
        """Whether *directory* (default: ours) is a directory on the device."""
        try:
            storage_get_file(self.host, directory or self.dir)
        except IsADirectoryError:
            return True
        except FileNotFoundError:
            return False
        raise StoreUnavailable(f"{directory or self.dir} is a file, not a directory")
