"""Unit tests for vault migration and master password change."""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_string_cipher.passphrase_manager import PassphraseVault
from secure_string_cipher.v2.key_identity import KeyStorageMode
from secure_string_cipher.v2.vault_service import V2VaultService

OLD_MASTER = "Old-Master-Password-2026!"  # pragma: allowlist secret
NEW_MASTER = "New-Master-Password-2026!"  # pragma: allowlist secret


def test_migration_from_flat_to_v2(tmp_path: Path) -> None:
    vault_file = tmp_path / "legacy.enc"
    vault = PassphraseVault(vault_path=str(vault_file), backend="file")

    # Store some passphrases in legacy mode
    vault.store_passphrase("site-a", "secret-a", OLD_MASTER)
    vault.store_passphrase("site-b", "secret-b", OLD_MASTER)

    service = V2VaultService(vault=vault)
    v2_doc = service.migrate_schema(OLD_MASTER)

    assert v2_doc.schema_version == 2
    assert v2_doc.passphrases["site-a"] == "secret-a"
    assert v2_doc.passphrases["site-b"] == "secret-b"
    assert len(v2_doc.keys) == 0

    # Migration is idempotent
    v2_doc_again = service.migrate_schema(OLD_MASTER)
    assert v2_doc_again.vault_meta.vault_id == v2_doc.vault_meta.vault_id
    assert v2_doc_again.vault_meta.revision == v2_doc.vault_meta.revision


def test_passphrase_crud_preserves_v2_keys(tmp_path: Path) -> None:
    vault_file = tmp_path / "v2_crud.enc"
    vault = PassphraseVault(vault_path=str(vault_file), backend="file")
    service = V2VaultService(vault=vault)

    # Create a vault-copy key
    key_rec, secret = service.create_key(
        "my-key",
        KeyStorageMode.VAULT_COPY,
        master_password=OLD_MASTER,
    )

    # Use standard PassphraseVault CRUD
    vault.store_passphrase("email", "p@ssword", OLD_MASTER)
    vault.update_passphrase("email", "new_p@ssword", OLD_MASTER)
    vault.store_passphrase("backup", "secret-code", OLD_MASTER)
    vault.delete_passphrase("backup", OLD_MASTER)

    # Verify key record and secret were not lost or corrupted
    fetched_rec, fetched_sec = service.get_key("my-key", OLD_MASTER)
    assert fetched_rec.id == "my-key"
    assert fetched_sec == secret

    # Verify passphrases work
    assert vault.retrieve_passphrase("email", OLD_MASTER) == "new_p@ssword"


def test_change_master_password(tmp_path: Path) -> None:
    vault_file = tmp_path / "pwd_rotation.enc"
    vault = PassphraseVault(vault_path=str(vault_file), backend="file")
    service = V2VaultService(vault=vault)

    # Store passphrases and managed keys
    vault.store_passphrase("service-1", "pass-1", OLD_MASTER)
    k1, s1 = service.create_key(
        "key-one", KeyStorageMode.VAULT_COPY, master_password=OLD_MASTER
    )
    k2, s2 = service.create_key(
        "key-two", KeyStorageMode.VAULT_COPY, master_password=OLD_MASTER
    )

    # Change password
    service.change_master_password(OLD_MASTER, NEW_MASTER)

    # Old password must fail
    with pytest.raises(ValueError):
        vault.retrieve_passphrase("service-1", OLD_MASTER)
    with pytest.raises(ValueError):
        service.get_key("key-one", OLD_MASTER)

    # New password must succeed
    assert vault.retrieve_passphrase("service-1", NEW_MASTER) == "pass-1"
    _, unwrapped1 = service.get_key("key-one", NEW_MASTER)
    assert unwrapped1 == s1
    _, unwrapped2 = service.get_key("key-two", NEW_MASTER)
    assert unwrapped2 == s2
