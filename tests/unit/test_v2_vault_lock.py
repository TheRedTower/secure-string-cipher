"""Unit tests for cooperative advisory vault locking."""

from __future__ import annotations

import multiprocessing
import time
from pathlib import Path
from typing import Any

import pytest

from secure_string_cipher.v2.vault_lock import (
    VaultBusyError,
    get_vault_lock_path,
    hold_vault_lock,
)


def test_lock_path_derivation(tmp_path: Path) -> None:
    vault_file = tmp_path / "vault.enc"
    lock_path = get_vault_lock_path(vault_file)
    assert lock_path.parent == tmp_path
    assert lock_path.name == ".vault.enc.lock"

    # Named identity (keychain)
    kc_lock = get_vault_lock_path("keychain:secure-string-cipher:test-user")
    assert kc_lock.name.startswith(".vault_")
    assert kc_lock.name.endswith(".lock")


def test_hold_vault_lock_basic(tmp_path: Path) -> None:
    vault_file = tmp_path / "vault.enc"
    with hold_vault_lock(vault_file) as lock_path:
        assert lock_path.is_file()
        assert (lock_path.stat().st_mode & 0o777) == 0o600


def test_hold_vault_lock_reentrant(tmp_path: Path) -> None:
    vault_file = tmp_path / "vault.enc"
    with hold_vault_lock(vault_file):
        with hold_vault_lock(vault_file):
            pass


def _worker_hold_lock(
    lock_path_str: str, hold_seconds: float, ready_event: Any
) -> None:
    with hold_vault_lock(lock_path_str, timeout=2.0):
        ready_event.set()
        time.sleep(hold_seconds)


def test_hold_vault_lock_conflict_and_timeout(tmp_path: Path) -> None:
    vault_file = tmp_path / "vault.enc"
    ctx = multiprocessing.get_context("spawn")
    ready_event = ctx.Event()

    p = ctx.Process(target=_worker_hold_lock, args=(str(vault_file), 1.0, ready_event))
    p.start()
    try:
        # Wait until worker has acquired the lock
        assert ready_event.wait(timeout=5.0)

        # Attempt to acquire with very short timeout (0.1s) -> should fail
        with pytest.raises(VaultBusyError, match="locked by another process"):
            with hold_vault_lock(vault_file, timeout=0.1):
                pass
    finally:
        p.join()

    # Once process finishes, acquiring lock succeeds
    with hold_vault_lock(vault_file, timeout=1.0):
        pass
