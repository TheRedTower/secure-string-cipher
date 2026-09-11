"""Cooperative advisory locking for vault mutations.

Provides cross-process synchronization for vault writes with bounded timeout.
Uses OS-level advisory locks on persistent owner-only lock files.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import stat
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .paths import reject_symlink_components

__all__ = [
    "VaultBusyError",
    "get_vault_lock_path",
    "hold_vault_lock",
]


class VaultBusyError(ValueError):
    """Raised when the vault lock cannot be acquired within the bounded timeout."""


def get_vault_lock_path(lock_target: Path | str) -> Path:
    """Derive a stable, persistent lock file path from a vault path or keychain identity."""
    if not isinstance(lock_target, Path | str):
        # Anything else (e.g. an unconfigured test double) would otherwise
        # fall through to str()/Path() below and silently derive a bogus
        # lock path from that object's repr, creating real directories from
        # it (observed in practice with an unconfigured MagicMock).
        raise TypeError(
            f"lock_target must be a Path or str, got {type(lock_target).__name__}"
        )
    target_str = str(lock_target)
    if isinstance(lock_target, str) and (
        target_str.startswith("keychain:")
        or not (target_str.startswith("/") or "\\" in target_str)
    ):
        # Named identity (e.g. keychain service/user)
        digest = hashlib.sha256(target_str.encode("utf-8")).hexdigest()[:16]
        lock_dir = Path.home() / ".secure_string_cipher"
        reject_symlink_components(lock_dir)
        lock_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        return lock_dir / f".vault_{digest}.lock"

    path = Path(lock_target).expanduser()
    reject_symlink_components(path)
    path = path.resolve()
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    return parent / f".{path.name}.lock"


_ACQUIRED_LOCKS: dict[Path, int] = {}
_THREAD_LOCKS: dict[Path, threading.RLock] = {}
_REGISTRY_LOCK = threading.Lock()
_OPEN_FDS: set[int] = set()


def _after_fork() -> None:
    """A child must acquire its own locks, never inherit reentrant ownership."""
    global _REGISTRY_LOCK
    for fd in _OPEN_FDS:
        os.close(fd)
    _OPEN_FDS.clear()
    _ACQUIRED_LOCKS.clear()
    _THREAD_LOCKS.clear()
    _REGISTRY_LOCK = threading.Lock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)


# pyrefly: ignore [deprecated]
@contextmanager
def hold_vault_lock(lock_target: Path | str, timeout: float = 10.0) -> Iterator[Path]:
    """Acquire a cooperative, advisory exclusive lock for the vault.

    Supports re-entrant acquisition by the owning thread only.

    Args:
        lock_target: Absolute vault path or stable keychain identity string.
        timeout: Maximum seconds to wait before raising VaultBusyError.

    Yields:
        Path of the active lock file.

    Raises:
        VaultBusyError: If the lock cannot be acquired within timeout.
    """
    lock_path = get_vault_lock_path(lock_target)
    started = time.monotonic()
    with _REGISTRY_LOCK:
        thread_lock = _THREAD_LOCKS.setdefault(lock_path, threading.RLock())
    if not thread_lock.acquire(timeout=max(0.0, timeout)):
        raise VaultBusyError("Vault is currently locked by another thread.")
    try:
        with _hold_process_lock(
            lock_path, max(0.0, timeout - (time.monotonic() - started))
        ):
            yield lock_path
    finally:
        thread_lock.release()


@contextmanager
def _hold_process_lock(lock_path: Path, timeout: float) -> Iterator[None]:
    if lock_path in _ACQUIRED_LOCKS:
        _ACQUIRED_LOCKS[lock_path] += 1
        try:
            yield
        finally:
            _ACQUIRED_LOCKS[lock_path] -= 1
            if _ACQUIRED_LOCKS[lock_path] == 0:
                del _ACQUIRED_LOCKS[lock_path]
        return

    # Open/create lock file with 0600 permissions
    reject_symlink_components(lock_path)
    fd = os.open(
        lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    _OPEN_FDS.add(fd)

    locked = False
    start_time = time.monotonic()

    try:
        status = os.fstat(fd)
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise OSError("Vault lock must be a regular file with one link.")
        if os.name == "posix":
            if status.st_uid != os.getuid():
                raise OSError("Vault lock must be owned by the current user.")
            os.fchmod(fd, 0o600)
        elif status.st_size == 0:  # pragma: no cover - Windows
            os.write(fd, b"\0")
        while True:
            try:
                if os.name == "posix":
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                else:  # pragma: no cover - Windows fallback
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]

                locked = True
                _ACQUIRED_LOCKS[lock_path] = 1
                break
            except (BlockingIOError, OSError):
                if time.monotonic() - start_time >= timeout:
                    raise VaultBusyError(
                        f"Vault is currently locked by another process (timeout {timeout:.1f}s reached)."
                    ) from None
                time.sleep(0.05)

        yield

    finally:
        if locked:
            _ACQUIRED_LOCKS[lock_path] -= 1
            if _ACQUIRED_LOCKS[lock_path] == 0:
                del _ACQUIRED_LOCKS[lock_path]
            with contextlib.suppress(OSError):
                if os.name == "posix":
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_UN)
                else:  # pragma: no cover - Windows fallback
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]

        with contextlib.suppress(OSError):
            os.close(fd)
        _OPEN_FDS.discard(fd)
