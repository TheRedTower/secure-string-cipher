"""Writing files safely and owner-only (FORMAT.md section 7.5, VAULT.md
section 1), and the lock that serialises vault writers.

On Linux and macOS, files are mode 0600 and folders 0700. On Windows, SSC
sets no ACLs of its own: what it writes inherits the ACL of the folder it is
written to, and the vault's folder is under the user's own profile.
"""

from __future__ import annotations

import contextlib
import errno
import os
import secrets
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

FILE_MODE = 0o600
DIR_MODE = 0o700

_BINARY: int = getattr(os, "O_BINARY", 0)
_NOFOLLOW: int = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY: int = getattr(os, "O_DIRECTORY", 0)


def private_dir(path: Path) -> None:
    """Create `path` and any missing parents. A folder SSC creates is
    owner-only; an existing one is left as it is."""
    for missing in reversed([p for p in (path, *path.parents) if not p.exists()]):
        with contextlib.suppress(FileExistsError):
            missing.mkdir(mode=DIR_MODE)


def _sync_dir(directory: Path) -> None:
    """Make a rename in `directory` durable. Windows has no equivalent."""
    if os.name != "posix":
        return
    fd = os.open(directory, os.O_RDONLY | _DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _publish_new(temp: Path, path: Path) -> None:
    """Move `temp` to `path` atomically, never replacing an existing file."""
    if os.name == "nt":
        os.rename(temp, path)  # Windows rename never replaces a file
        return
    os.link(temp, path)  # fails with FileExistsError if `path` exists
    os.unlink(temp)


def write_atomic(
    path: Path, write: Callable[[BinaryIO], object], *, replace: bool
) -> None:
    """Write `path` through a temporary file in the same folder, owner-only,
    synced before it is moved into place. A failure leaves `path` as it was
    and no temporary file behind.

    With `replace`, an existing file is replaced; without it, the write fails
    with FileExistsError if anything appears at `path`, even in a race.
    """
    temp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY
    fd = os.open(temp, flags, FILE_MODE)
    try:
        with os.fdopen(fd, "wb") as handle:
            write(handle)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(temp, path)
        else:
            _publish_new(temp, path)
        _sync_dir(path.parent)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


# --- locking -----------------------------------------------------------------


class LockTimeout(Exception):
    """Another process held the lock for longer than the timeout."""


if sys.platform == "win32":
    import msvcrt

    def _try_lock(fd: int) -> bool:
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EDEADLOCK):
                return False
            raise
        return True

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _try_lock(fd: int) -> bool:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


@contextmanager
def locked(path: Path, *, timeout: float = 10.0) -> Iterator[None]:
    """Hold an exclusive lock on the lock file `path` for the whole block.

    The lock file is created owner-only and never deleted: deleting it would
    let a waiting process lock a file that a newcomer no longer sees.
    """
    fd = os.open(path, os.O_RDWR | os.O_CREAT | _BINARY | _NOFOLLOW, FILE_MODE)
    try:
        deadline = time.monotonic() + timeout
        while not _try_lock(fd):
            if time.monotonic() >= deadline:
                raise LockTimeout(str(path))
            time.sleep(0.05)
        try:
            yield
        finally:
            _unlock(fd)
    finally:
        os.close(fd)
