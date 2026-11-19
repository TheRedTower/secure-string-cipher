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
import stat
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

FILE_MODE = 0o600
DIR_MODE = 0o700

# POSIX-only open flags; 0 where the platform lacks them.
_BINARY: int = getattr(os, "O_BINARY", 0)
_NOFOLLOW: int = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY: int = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK: int = getattr(os, "O_NONBLOCK", 0)
# Directories are opened search-only where possible (O_PATH on Linux,
# O_SEARCH on macOS), so a parent with execute but not read permission
# still works, as it does for an ordinary open.
_SEARCH: int = getattr(os, "O_PATH", 0) or getattr(os, "O_SEARCH", 0) or os.O_RDONLY


def private_dir(path: Path) -> None:
    """Create `path` and any missing parents. A folder SSC creates is
    owner-only; an existing one is left as it is."""
    for missing in reversed([p for p in (path, *path.parents) if not p.exists()]):
        with contextlib.suppress(FileExistsError):
            missing.mkdir(mode=DIR_MODE)


class NotDurable(OSError):
    """The file was written and moved into place, but the folder could not
    be synced, so the move might not survive a crash. The write itself is
    complete: callers MUST NOT treat this as a write that did not happen."""


# Errors meaning a folder cannot be synced at all here, rather than that a
# sync failed: some filesystems refuse fsync on a folder.
_SYNC_UNSUPPORTED = {errno.EINVAL, errno.EBADF, getattr(errno, "ENOTSUP", -1)}


def _sync_dir(directory: Path) -> None:
    """Make a rename in `directory` durable. Windows has no equivalent, and a
    folder SSC may write to but not read (mode 0300) cannot be opened to
    sync, so both are skipped."""
    if os.name != "posix":
        return
    try:
        fd = os.open(directory, os.O_RDONLY | _DIRECTORY)
    except PermissionError:
        return
    try:
        os.fsync(fd)
    except OSError as error:
        if error.errno in _SYNC_UNSUPPORTED:
            return
        raise NotDurable(
            error.errno, f"Written, but the folder could not be synced: {error}"
        ) from error
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
    synced before it is moved into place. A failure before the move leaves
    `path` as it was and no temporary file behind.

    With `replace`, an existing file is replaced; without it, the write fails
    with FileExistsError if anything appears at `path`, even in a race.

    The move is the commit point. Only NotDurable can be raised after it,
    and then the new file is in place.
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
    except BaseException:
        temp.unlink(missing_ok=True)
        raise
    _sync_dir(path.parent)


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


# --- reading credential files ----------------------------------------------------


def _refuse_symlink(path: Path, what: str) -> PermissionError:
    return PermissionError(f"Refusing a {what} reached through a symlink: {path}")


def _open_at(name: str, flags: int, dir_fd: int, path: Path, what: str) -> int:
    """Open one component under `dir_fd`, refusing a symlink. O_NOFOLLOW
    makes the open itself fail on a link swapped in after the check, and the
    check turns the platform's error for that into one clear refusal."""
    if stat.S_ISLNK(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode):
        raise _refuse_symlink(path, what)
    try:
        return os.open(name, flags | _NOFOLLOW, dir_fd=dir_fd)
    except OSError as error:
        if error.errno in (errno.ELOOP, getattr(errno, "EMLINK", errno.ELOOP)):
            raise _refuse_symlink(path, what) from None
        raise


def _open_no_symlinks(path: Path, what: str) -> int:
    """Open `path` for reading without following a symlink anywhere on the
    way to it (CLI.md section 1), and without blocking on a FIFO."""
    # Absolute, but not normalised: collapsing "alias/.." here would skip
    # checking `alias`, and could name a different file than the kernel would.
    path = path if path.is_absolute() else Path.cwd() / path
    if os.open in os.supports_dir_fd and _NOFOLLOW and _DIRECTORY:
        # Walk one component at a time from the root, so no component can
        # be swapped for a link between the check and the open.
        fd = os.open(path.anchor, _SEARCH | _DIRECTORY)
        try:
            for part in path.parts[1:-1]:
                following = _open_at(part, _SEARCH | _DIRECTORY, fd, path, what)
                os.close(fd)
                fd = following
            return _open_at(path.name, os.O_RDONLY | _NONBLOCK, fd, path, what)
        finally:
            os.close(fd)
    # Windows has no dir_fd: check each component, then open.
    for component in (path, *path.parents):
        if component.is_symlink() or component.is_junction():
            raise _refuse_symlink(path, what)
    return os.open(path, os.O_RDONLY | _BINARY)


def read_private(path: Path, limit: int, what: str) -> bytes:
    """Up to `limit` bytes of a credential file (CLI.md section 1): a
    regular file, not reached through a symlink, and on POSIX not readable
    by group or others. The checks are made on the open descriptor, so the
    file cannot be swapped between the check and the read. `what` names the
    file in errors, such as "key file"."""
    fd = _open_no_symlinks(path, what)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise PermissionError(f"A {what} must be a regular file: {path}")
        if os.name == "posix" and info.st_mode & 0o044:
            raise PermissionError(
                f"A {what} must not be readable by others (chmod 600): {path}"
            )
    except BaseException:
        os.close(fd)
        raise
    with os.fdopen(fd, "rb") as handle:
        return handle.read(limit)
