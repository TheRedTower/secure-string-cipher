"""Unit tests for cooperative advisory vault locking."""

from __future__ import annotations

import multiprocessing
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from secure_string_cipher.v2.vault_lock import (
    VaultBusyError,
    get_vault_lock_path,
    hold_vault_lock,
)


def _worker_try_lock(target: str, result: Any) -> None:
    try:
        with hold_vault_lock(Path(target), timeout=0.1):
            result.put("acquired")
    except VaultBusyError:
        result.put("busy")


@pytest.mark.skipif(
    "fork" not in multiprocessing.get_all_start_methods(), reason="Requires fork"
)
def test_fork_does_not_inherit_reentrant_ownership(tmp_path: Path) -> None:
    target = tmp_path / "vault.enc"
    ctx = multiprocessing.get_context("fork")
    result = ctx.Queue()
    with hold_vault_lock(target):
        child = ctx.Process(target=_worker_try_lock, args=(str(target), result))
        child.start()
        try:
            assert result.get(timeout=5) == "busy"
        finally:
            child.join(timeout=5)
            if child.is_alive():
                child.terminate()
                child.join(timeout=5)
    result.close()
    assert child.exitcode == 0


def _worker_store(target: str, label: str, ready: Any) -> None:
    from secure_string_cipher.passphrase_manager import PassphraseVault

    ready.wait(timeout=5)
    vault = PassphraseVault(target, backend="file")
    vault.store_passphrase(label, "synthetic value", "Public-Test-Lock-Master-2026!")


def test_competing_process_updates_preserve_both_entries(tmp_path: Path) -> None:
    from secure_string_cipher.passphrase_manager import PassphraseVault

    target = tmp_path / "vault.enc"
    ctx = multiprocessing.get_context("spawn")
    ready = ctx.Event()
    children = [
        ctx.Process(target=_worker_store, args=(str(target), label, ready))
        for label in ("one", "two")
    ]
    for child in children:
        child.start()
    ready.set()
    try:
        for child in children:
            child.join(timeout=10)
            assert child.exitcode == 0
    finally:
        for child in children:
            if child.is_alive():
                child.terminate()
                child.join(timeout=5)
    vault = PassphraseVault(str(target), backend="file")
    assert vault.list_labels("Public-Test-Lock-Master-2026!") == ["one", "two"]


def test_lock_path_derivation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
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


def test_other_thread_cannot_reenter_lock(tmp_path: Path) -> None:
    target = tmp_path / "vault.enc"
    errors = []

    def contender() -> None:
        try:
            with hold_vault_lock(target, timeout=0.05):
                errors.append("unexpectedly acquired")
        except VaultBusyError:
            errors.append("busy")

    with hold_vault_lock(target):
        thread = threading.Thread(target=contender)
        thread.start()
        thread.join(timeout=2)
    assert not thread.is_alive()
    assert errors == ["busy"]
    with hold_vault_lock(target):
        pass


def test_lock_rejects_symlink_file(tmp_path: Path) -> None:
    target = tmp_path / "vault.enc"
    other = tmp_path / "other"
    other.write_bytes(b"unrelated")
    other.chmod(0o644)
    get_vault_lock_path(target).symlink_to(other)
    with pytest.raises(OSError, match="symlink"):
        with hold_vault_lock(target):
            pass
    assert other.read_bytes() == b"unrelated"
    assert other.stat().st_mode & 0o777 == 0o644


def test_process_death_releases_lock(tmp_path: Path) -> None:
    target = tmp_path / "vault.enc"
    ctx = multiprocessing.get_context("spawn")
    ready = ctx.Event()
    process = ctx.Process(target=_worker_hold_lock, args=(str(target), 30, ready))
    process.start()
    try:
        assert ready.wait(timeout=5)
        process.terminate()
        process.join(timeout=5)
        with hold_vault_lock(target, timeout=1):
            pass
    finally:
        if process.is_alive():
            process.terminate()
        process.join(timeout=5)
