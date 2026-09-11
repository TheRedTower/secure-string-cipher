"""Failure atomicity and compatibility of complete-document vault updates."""

from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from secure_string_cipher.passphrase_manager import (
    PassphraseVault,
    VaultTransactionError,
    validate_raw_vault,
    validate_raw_vault_document,
)
from secure_string_cipher.v2.key_identity import KeyStorageMode
from secure_string_cipher.v2.vault_schema import b64url_encode
from secure_string_cipher.v2.vault_service import V2VaultService

MASTER = "Public-Test-Transaction-Master-2026!"  # pragma: allowlist secret
NEW_MASTER = "Public-Test-Rotated-Master-2026!"  # pragma: allowlist secret


@pytest.fixture
def vault(tmp_path: Path) -> PassphraseVault:
    result = PassphraseVault(str(tmp_path / "vault.enc"), backend="file")
    result.store_passphrase("site", "public-test-value", MASTER)
    return result


def test_legacy_validator_rejects_structured_document(vault: PassphraseVault) -> None:
    V2VaultService(vault=vault).migrate_schema(MASTER)
    raw = vault.read_raw_vault()
    assert raw is not None
    with pytest.raises(ValueError):
        validate_raw_vault(raw, MASTER)
    assert validate_raw_vault_document(raw, MASTER)[0] == 2
    assert vault.retrieve_passphrase("site", MASTER) == "public-test-value"


@pytest.mark.parametrize("contents", [b"", b"invalid vault"])
def test_migration_rejects_existing_invalid_storage(
    tmp_path: Path, contents: bytes
) -> None:
    path = tmp_path / "vault.enc"
    path.write_bytes(contents)
    vault = PassphraseVault(str(path), backend="file")
    with pytest.raises(ValueError):
        V2VaultService(vault=vault).migrate_schema(MASTER)
    assert path.read_bytes() == contents
    assert vault.list_backups() == []


@pytest.mark.parametrize(
    "operation", ["migration", "creation", "rotation", "passphrase"]
)
@pytest.mark.parametrize("failure", ["corruption", "write", "cancel"])
def test_document_publication_failure_restores_exact_snapshot(
    vault: PassphraseVault, operation: str, failure: str
) -> None:
    service = V2VaultService(vault=vault)
    if operation in {"rotation", "passphrase"}:
        _, secret = service.create_key(
            "test-key", KeyStorageMode.VAULT_COPY, master_password=MASTER
        )
    previous = vault.read_raw_vault()
    real_write = vault.write_raw_vault
    calls = 0

    def fail_first_write(raw: str) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            real_write("invalid synthetic publication")
            if failure == "write":
                raise OSError("synthetic backend failure")
            if failure == "cancel":
                raise KeyboardInterrupt
        else:
            real_write(raw)

    error = KeyboardInterrupt if failure == "cancel" else VaultTransactionError
    with (
        patch.object(vault, "write_raw_vault", side_effect=fail_first_write),
        pytest.raises(error),
    ):
        if operation == "migration":
            service.migrate_schema(MASTER)
        elif operation == "creation":
            service.create_key(
                "new-key", KeyStorageMode.VAULT_COPY, master_password=MASTER
            )
        elif operation == "rotation":
            service.change_master_password(MASTER, NEW_MASTER)
        else:
            vault.update_passphrase("site", "changed", MASTER)
    assert vault.read_raw_vault() == previous
    assert any(Path(p).read_bytes() == previous.encode() for p in vault.list_backups())
    if operation in {"rotation", "passphrase"}:
        assert service.get_key("test-key", MASTER)[1] == secret


def test_failed_first_creation_restores_absence(tmp_path: Path) -> None:
    vault = PassphraseVault(str(tmp_path / "new.enc"), backend="file")
    service = V2VaultService(vault=vault)
    real_write = vault.write_raw_vault

    def corrupt(raw: str) -> None:
        real_write("invalid synthetic publication")

    with (
        patch.object(vault, "write_raw_vault", side_effect=corrupt),
        pytest.raises(VaultTransactionError),
    ):
        service.create_key("new-key", KeyStorageMode.VAULT_COPY, master_password=MASTER)
    assert vault.read_raw_vault() is None


def test_changed_snapshot_is_not_overwritten(vault: PassphraseVault) -> None:
    service = V2VaultService(vault=vault)
    real_backup = vault._publish_backup
    changed = vault._encode_document(1, {"concurrent": "value"}, MASTER)

    def concurrent_change(raw: str, **kwargs: object) -> str:
        backup = real_backup(raw)
        vault.write_raw_vault(changed)
        return backup

    with (
        patch.object(vault, "_publish_backup", side_effect=concurrent_change),
        pytest.raises(VaultTransactionError) as caught,
    ):
        service.migrate_schema(MASTER)
    assert caught.value.category == "stale_snapshot"
    assert vault.read_raw_vault() == changed


def test_migration_backup_failure_preserves_active(vault: PassphraseVault) -> None:
    previous = vault.read_raw_vault()
    with (
        patch.object(vault, "_publish_backup", side_effect=OSError),
        pytest.raises(VaultTransactionError) as caught,
    ):
        V2VaultService(vault=vault).migrate_schema(MASTER)
    assert caught.value.category == "backup_failed"
    assert vault.read_raw_vault() == previous


def test_large_legacy_namespace_migrates_without_header_node_cap(
    vault: PassphraseVault,
) -> None:
    entries = {f"site-{i}": f"value-{i}" for i in range(1500)}
    entries.update({"schema_version": "2", "items": "ordinary", "vault_meta": "legacy"})
    vault.write_raw_vault(vault._encode_document(1, entries, MASTER))
    V2VaultService(vault=vault).migrate_schema(MASTER)
    assert vault._load_vault(MASTER) == entries
    vault.update_passphrase("site-1", "changed", MASTER)
    assert len(vault.list_labels(MASTER)) == len(entries)


def test_oversized_candidate_rejected_before_encryption(vault: PassphraseVault) -> None:
    previous = vault.read_raw_vault()
    with (
        patch("secure_string_cipher.passphrase_manager.MAX_FILE_SIZE", 500),
        patch("secure_string_cipher.passphrase_manager.encrypt_text") as encrypt,
    ):
        with pytest.raises(ValueError):
            vault._encode_document(1, {"entry": "x" * 500}, MASTER)
        encrypt.assert_not_called()
    assert vault.read_raw_vault() == previous


def test_import_rejects_unusable_inner_secret(vault: PassphraseVault) -> None:
    service = V2VaultService(vault=vault)
    record, _ = service.create_key(
        "test-key", KeyStorageMode.VAULT_COPY, master_password=MASTER
    )
    _, doc = vault._load_document(MASTER)
    bad_secret = dict(record.vault_secret)
    bad_secret["tag"] = b64url_encode(b"\x00" * 16)
    bad_record = replace(record, vault_secret=bad_secret)
    candidate = vault._encode_document(
        2, replace(doc, keys={record.fingerprint: bad_record}), MASTER
    )
    previous = vault.read_raw_vault()
    with pytest.raises(VaultTransactionError) as caught:
        vault.import_raw_vault(candidate, MASTER)
    assert caught.value.category == "candidate_validation_failed"
    assert vault.read_raw_vault() == previous


def test_rotation_derives_each_root_once(vault: PassphraseVault) -> None:
    service = V2VaultService(vault=vault)
    service.create_key("test-key", KeyStorageMode.VAULT_COPY, master_password=MASTER)
    with patch.object(
        service, "_derive_vault_root_key", wraps=service._derive_vault_root_key
    ) as derive:
        service.change_master_password(MASTER, NEW_MASTER)
    assert derive.call_count == 2


class MemoryKeychain:
    """Synthetic credential store with failure injection after mutation."""

    def __init__(self) -> None:
        self.raw = None
        self.fail_next = False

    def load_vault(self):
        return self.raw

    def store_vault(self, raw):
        self.raw = raw
        if self.fail_next:
            self.fail_next = False
            raise OSError("Synthetic capacity/write failure")

    def delete_vault(self):
        self.raw = None


def test_keychain_password_rotation_failure_preserves_old_keys(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    backend = MemoryKeychain()
    with patch(
        "secure_string_cipher.keychain_backend.KeychainVaultBackend",
        return_value=backend,
    ):
        vault = PassphraseVault(str(tmp_path / "vault.enc"), backend="keychain")
        service = V2VaultService(vault=vault)
        _, secret = service.create_key(
            "test-key", KeyStorageMode.VAULT_COPY, master_password=MASTER
        )
        before = vault.read_raw_vault()
        backend.fail_next = True
        with pytest.raises(VaultTransactionError) as caught:
            service.change_master_password(MASTER, NEW_MASTER)
        assert caught.value.rollback_succeeded
        assert backend.raw == before
        assert service.get_key("test-key", MASTER)[1] == secret
        assert any(
            Path(p).read_bytes() == before.encode() for p in vault.list_backups()
        )


def test_backend_copy_preserves_structured_records_and_rolls_back(
    vault, tmp_path, monkeypatch
):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    service = V2VaultService(vault=vault)
    _, secret = service.create_key(
        "test-key", KeyStorageMode.VAULT_COPY, master_password=MASTER
    )
    raw = vault.read_raw_vault()
    backend = MemoryKeychain()
    with patch(
        "secure_string_cipher.keychain_backend.KeychainVaultBackend",
        return_value=backend,
    ):
        backend.fail_next = True
        with pytest.raises(VaultTransactionError) as caught:
            vault.migrate_to_keychain(MASTER)
        assert caught.value.rollback_succeeded
        assert backend.raw is None
        assert vault.read_raw_vault() == raw
        vault.migrate_to_keychain(MASTER)
        assert backend.raw == raw
        destination = PassphraseVault(str(tmp_path / "copy.enc"), backend="file")
        destination.migrate_to_file(MASTER)
        assert backend.raw == raw
        assert destination.read_raw_vault() == raw
        assert (
            V2VaultService(vault=destination).get_key("test-key", MASTER)[1] == secret
        )


def test_failed_rollback_reports_possible_inconsistency(vault):
    with patch.object(
        vault, "write_raw_vault", side_effect=OSError("synthetic failure")
    ):
        with pytest.raises(VaultTransactionError) as caught:
            V2VaultService(vault=vault).migrate_schema(MASTER)
    assert caught.value.category == "rollback_failed"
    assert caught.value.rollback_attempted
    assert caught.value.rollback_succeeded is False
    assert caught.value.backup_identifier is not None


def test_old_backup_remains_recoverable_after_password_change(vault):
    service = V2VaultService(vault=vault)
    _, secret = service.create_key(
        "test-key", KeyStorageMode.VAULT_COPY, master_password=MASTER
    )
    old = vault.read_raw_vault()
    service.change_master_password(MASTER, NEW_MASTER)
    backup = next(
        record
        for record in vault.list_backup_records()
        if record.path.read_bytes() == old.encode()
    )
    vault.validate_backup(backup.identifier, MASTER)
    vault.restore_from_backup(backup.identifier, MASTER)
    assert vault.read_raw_vault() == old
    assert service.get_key("test-key", MASTER)[1] == secret


def test_vault_root_uses_explicit_argon_version_and_bounded_password(vault):
    service = V2VaultService(vault=vault)
    doc = service.migrate_schema(MASTER)
    with patch(
        "secure_string_cipher.v2.vault_service.hash_secret_raw", return_value=b"s" * 32
    ) as kdf:
        service._derive_vault_root_key(MASTER, doc.vault_meta.vault_kdf)
        assert kdf.call_args.kwargs["version"] == 19
        kdf.reset_mock()
        with pytest.raises(ValueError, match="input limit"):
            service._derive_vault_root_key("x" * 65537, doc.vault_meta.vault_kdf)
        kdf.assert_not_called()


def test_wrong_encoded_candidate_is_rejected_before_publication(vault):
    previous = vault.read_raw_vault()
    wrong_candidate = vault._encode_document(1, {"unintended": "value"}, MASTER)
    with patch.object(vault, "_encode_document", return_value=wrong_candidate):
        with pytest.raises(VaultTransactionError) as caught:
            V2VaultService(vault=vault).migrate_schema(MASTER)
    assert caught.value.category == "candidate_validation_failed"
    assert vault.read_raw_vault() == previous
