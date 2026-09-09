"""Cooperative advisory locking for vault mutations.

Provides cross-process synchronization for vault writes with bounded timeout.
Uses OS-level advisory locks on persistent owner-only lock files.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

__all__ = [
    "VaultBusyError",
    "get_vault_lock_path",
    "hold_vault_lock",
]


class VaultBusyError(ValueError):
    """Raised when the vault lock cannot be acquired within the bounded timeout."""


def get_vault_lock_path(lock_target: Path | str) -> Path:
    """Derive a stable, persistent lock file path from a vault path or keychain identity."""
    target_str = str(lock_target)
    if isinstance(lock_target, str) and (
        target_str.startswith("keychain:")
        or not (target_str.startswith("/") or "\\" in target_str)
    ):
        # Named identity (e.g. keychain service/user)
        digest = hashlib.sha256(target_str.encode("utf-8")).hexdigest()[:16]
        lock_dir = Path.home() / ".secure_string_cipher"
        lock_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        return lock_dir / f".vault_{digest}.lock"

    path = Path(lock_target).expanduser().resolve()
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    return parent / f".{path.name}.lock"


_ACQUIRED_LOCKS: dict[Path, int] = {}


# pyrefly: ignore [deprecated]
@contextmanager
def hold_vault_lock(lock_target: Path | str, timeout: float = 10.0) -> Iterator[Path]:
    """Acquire a cooperative, advisory exclusive lock for the vault.

    Supports re-entrant acquisition within the same process.

    Args:
        lock_target: Absolute vault path or stable keychain identity string.
        timeout: Maximum seconds to wait before raising VaultBusyError.

    Yields:
        Path of the active lock file.

    Raises:
        VaultBusyError: If the lock cannot be acquired within timeout.
    """
    lock_path = get_vault_lock_path(lock_target)

    if lock_path in _ACQUIRED_LOCKS:
        _ACQUIRED_LOCKS[lock_path] += 1
        try:
            yield lock_path
        finally:
            _ACQUIRED_LOCKS[lock_path] -= 1
            if _ACQUIRED_LOCKS[lock_path] == 0:
                del _ACQUIRED_LOCKS[lock_path]
        return

    # Open/create lock file with 0600 permissions
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    if os.name == "posix":
        with contextlib.suppress(OSError):
            os.chmod(lock_path, 0o600)

    locked = False
    start_time = time.monotonic()

    try:
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

        yield lock_path

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
