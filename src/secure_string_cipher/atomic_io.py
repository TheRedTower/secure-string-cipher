"""Atomic binary file publication helpers."""

from __future__ import annotations

import contextlib
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

from .utils import CryptoError


def _remove_temporary(path: Path | None) -> None:
    """Remove a temporary file without masking an earlier failure."""
    if path is not None:
        with contextlib.suppress(BaseException):
            path.unlink()


def _destination_entry_exists(path: Path) -> bool:
    """Return whether a destination directory entry already exists."""
    return path.exists() or path.is_symlink()


def _sync_directory(directory: Path) -> None:
    """Best-effort sync a published directory entry where supported.

    Publication is already irreversible when this runs. Directory sync errors
    therefore cannot be reported as operation failures without falsely
    implying that the previous destination was preserved.
    """
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY

    try:
        directory_fd = os.open(directory, flags)
    except OSError:
        return

    try:
        with contextlib.suppress(OSError):
            os.fsync(directory_fd)
    finally:
        with contextlib.suppress(OSError):
            os.close(directory_fd)


@contextmanager
def atomic_binary_writer(
    destination: str | Path,
    *,
    overwrite: bool = False,
    mode: int = 0o600,
) -> Iterator[BinaryIO]:
    """Yield a binary stream that is atomically published on successful exit.

    This helper uses the destination path lexically and does not resolve it.
    It does not inspect symlinked parent components; callers remain responsible
    for enforcing any broader path policy. The no-overwrite checks are
    best-effort preflight checks and do not protect against a hostile concurrent
    process racing destination creation.
    """
    if mode != 0o600:
        raise CryptoError("Atomic binary writes require owner-only mode 0o600")

    destination_path = Path(destination)
    parent = destination_path.parent

    if not parent.exists():
        raise CryptoError(f"Parent directory does not exist: {parent}")
    if not parent.is_dir():
        raise CryptoError(f"Parent path is not a directory: {parent}")
    if _destination_entry_exists(destination_path) and not overwrite:
        raise CryptoError(f"Output file already exists: {destination_path}")

    fd: int | None = None
    temporary_path: Path | None = None
    writer: BinaryIO | None = None

    try:
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{destination_path.name}.",
            suffix=".tmp",
            dir=parent,
        )
        temporary_path = Path(temporary_name)
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        else:  # pragma: no cover - Windows fallback
            os.chmod(temporary_path, 0o600)

        writer = os.fdopen(fd, "wb")
        fd = None

        try:
            yield writer
        except BaseException:
            with contextlib.suppress(BaseException):
                writer.close()
            _remove_temporary(temporary_path)
            temporary_path = None
            raise

        writer.flush()
        os.fsync(writer.fileno())
        writer.close()
        writer = None

        if _destination_entry_exists(destination_path) and not overwrite:
            raise CryptoError(f"Output file already exists: {destination_path}")

        os.replace(temporary_path, destination_path)
        temporary_path = None
        _sync_directory(parent)
    finally:
        if writer is not None:
            with contextlib.suppress(BaseException):
                writer.close()
        if fd is not None:
            with contextlib.suppress(BaseException):
                os.close(fd)
        _remove_temporary(temporary_path)
