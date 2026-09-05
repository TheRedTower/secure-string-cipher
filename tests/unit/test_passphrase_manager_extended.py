"""
Additional coverage tests for passphrase_manager and core modules.

These tests target uncovered code paths to improve overall test coverage.
"""

import os
from unittest.mock import MagicMock, patch

import pytest

from secure_string_cipher.core import encrypt_text
from secure_string_cipher.passphrase_manager import (
    PassphraseVault,
    VaultTransactionError,
)


def _mock_keyring_with_storage():
    """Create a minimal keyring mock backed by an in-memory dict."""
    storage = {}
    mock = MagicMock()
    mock.get_keyring.return_value = MagicMock(__class__=type("TestKeyring", (), {}))
    mock.errors = MagicMock()
    mock.errors.PasswordDeleteError = type("PasswordDeleteError", (Exception,), {})

    def set_password(service, key, value):
        storage[(service, key)] = value

    def get_password(service, key):
        return storage.get((service, key))

    def delete_password(service, key):
        if (service, key) not in storage:
            raise mock.errors.PasswordDeleteError("not found")
        del storage[(service, key)]

    mock.set_password = set_password
    mock.get_password = get_password
    mock.delete_password = delete_password
    return mock


class TestPassphraseVaultInit:
    """Tests for PassphraseVault initialization."""

    def test_custom_vault_path(self, tmp_path):
        """Should accept custom vault path."""
        custom_path = tmp_path / "custom_vault.enc"

        vault = PassphraseVault(vault_path=str(custom_path))

        assert vault.vault_path == custom_path

    def test_custom_vault_with_backup_dir_env(self, tmp_path):
        """Should use CIPHER_BACKUP_DIR env var for backup directory."""
        custom_path = tmp_path / "vault.enc"
        backup_dir = tmp_path / "custom_backups"

        with patch.dict(os.environ, {"CIPHER_BACKUP_DIR": str(backup_dir)}):
            vault = PassphraseVault(vault_path=str(custom_path))

        assert vault.backup_dir == backup_dir


class TestPassphraseVaultBackups:
    """Tests for vault backup functionality."""

    def test_backup_rotation_keeps_5(self, tmp_path):
        """Should keep only last 5 backups."""
        vault = PassphraseVault(vault_path=str(tmp_path / "vault.enc"))

        # Create initial vault
        vault.store_passphrase("test", "passphrase", "MasterPassword123!@#")

        # Create multiple entries to trigger backups
        for i in range(7):
            vault.store_passphrase(f"entry{i}", f"pass{i}", "MasterPassword123!@#")

        # Check backup count (should be <= 5)
        backups = list(vault.backup_dir.glob("vault_backup_*.enc"))
        assert len(backups) <= 5

    def test_list_and_restore_backup_success(self, tmp_path):
        """Should list newest backups first and restore selected backup."""
        vault = PassphraseVault(vault_path=str(tmp_path / "vault.enc"))
        master = "MasterPassword123!@#"
        vault.store_passphrase("first", "one", master)
        vault.store_passphrase("second", "two", master)
        selected = vault.list_backup_records()[0]

        vault.restore_from_backup(selected.identifier, master)

        assert vault.list_labels(master) == ["first"]
        assert selected.path.exists()

    def test_restore_backup_errors(self, tmp_path):
        """Should reject restore when no backup exists or index is invalid."""
        vault = PassphraseVault(vault_path=str(tmp_path / "vault.enc"))

        with pytest.raises(VaultTransactionError, match="not found"):
            vault.restore_from_backup("missing.enc", "MasterPassword123!@#")

        with pytest.raises(VaultTransactionError, match="not found"):
            vault.restore_from_backup("../outside.enc", "MasterPassword123!@#")


class TestPassphraseVaultErrors:
    """Tests for vault error handling."""

    def test_retrieve_nonexistent_label(self, tmp_path):
        """Should raise error for nonexistent label."""
        vault = PassphraseVault(vault_path=str(tmp_path / "vault.enc"))

        # Create vault first
        vault.store_passphrase("existing", "pass", "MasterPassword123!@#")

        # Try to retrieve nonexistent label
        with pytest.raises(ValueError):
            vault.retrieve_passphrase("nonexistent", "MasterPassword123!@#")

    def test_update_nonexistent_label(self, tmp_path):
        """Should raise error when updating nonexistent label."""
        vault = PassphraseVault(vault_path=str(tmp_path / "vault.enc"))

        # Create vault first
        vault.store_passphrase("existing", "pass", "MasterPassword123!@#")

        # Try to update nonexistent label
        with pytest.raises(ValueError):
            vault.update_passphrase("nonexistent", "newpass", "MasterPassword123!@#")

    def test_delete_nonexistent_label(self, tmp_path):
        """Should raise error when deleting nonexistent label."""
        vault = PassphraseVault(vault_path=str(tmp_path / "vault.enc"))

        # Create vault first
        vault.store_passphrase("existing", "pass", "MasterPassword123!@#")

        # Try to delete nonexistent label
        with pytest.raises(ValueError):
            vault.delete_passphrase("nonexistent", "MasterPassword123!@#")

    def test_wrong_master_password(self, tmp_path):
        """Should raise error for wrong master password."""
        vault = PassphraseVault(vault_path=str(tmp_path / "vault.enc"))

        vault.store_passphrase("test", "mypassphrase", "MasterPassword123!@#")

        # Should raise some exception (CryptoError or ValueError depending on implementation)
        with pytest.raises((ValueError, Exception)):
            vault.retrieve_passphrase("test", "WrongPassword123!@#")

    def test_keychain_store_rejects_wrong_master_without_overwrite(self, tmp_path):
        """Should not overwrite an existing keychain vault on wrong master password."""
        mock_keyring = _mock_keyring_with_storage()

        with patch(
            "secure_string_cipher.keychain_backend._get_keyring",
            return_value=mock_keyring,
        ):
            vault = PassphraseVault(
                vault_path=str(tmp_path / "vault.enc"), backend="keychain"
            )
            vault.store_passphrase("existing", "original", "CorrectMaster123!")

            with pytest.raises(ValueError):
                vault.store_passphrase("new", "replacement", "WrongMaster123!")

            assert (
                vault.retrieve_passphrase("existing", "CorrectMaster123!") == "original"
            )
            assert vault.list_labels("CorrectMaster123!") == ["existing"]

    @pytest.mark.parametrize(
        "raw_contents",
        [
            "LEGACY\nsalt\n---DATA---\ndata\n---HMAC---\nhmac",
            "SSCVAULT\nsalt\nBAD\npayload\n---HMAC---\nhmac",
            "SSCVAULT\nnot-hex\n---DATA---\npayload\n---HMAC---\nhmac",
            "SSCVAULT\nabcdef\n---DATA---\npayload\nNOHMAC\nhmac",
        ],
    )
    def test_load_vault_rejects_malformed_raw_contents(self, tmp_path, raw_contents):
        """Should reject malformed vault storage before decryption."""
        vault = PassphraseVault(vault_path=str(tmp_path / "vault.enc"))
        vault.vault_path.write_text(raw_contents)

        with pytest.raises(
            ValueError,
            match="Wrong master password or corrupted vault file",
        ):
            vault.list_labels("master")

    def test_load_vault_rejects_invalid_decrypted_json(self, tmp_path):
        """Should reject authenticated vault contents that are not JSON."""
        master = "master"
        vault = PassphraseVault(vault_path=str(tmp_path / "vault.enc"))
        encrypted_vault = encrypt_text("not-json", master)
        hmac_salt = b"\x01" * 32
        vault_hmac = vault._compute_hmac(encrypted_vault, master, hmac_salt)
        vault.vault_path.write_text(
            "SSCVAULT\n"
            f"{hmac_salt.hex()}\n"
            "---DATA---\n"
            f"{encrypted_vault}\n"
            "---HMAC---\n"
            f"{vault_hmac}"
        )

        with pytest.raises(
            ValueError,
            match="Wrong master password or corrupted vault file",
        ):
            vault.list_labels(master)


class TestPassphraseVaultOperations:
    """Tests for vault CRUD operations."""

    def test_store_and_list(self, tmp_path):
        """Should store and list multiple passphrases."""
        vault = PassphraseVault(vault_path=str(tmp_path / "vault.enc"))
        master = "MasterPassword123!@#"

        vault.store_passphrase("one", "pass1", master)
        vault.store_passphrase("two", "pass2", master)
        vault.store_passphrase("three", "pass3", master)

        labels = vault.list_labels(master)

        assert "one" in labels
        assert "two" in labels
        assert "three" in labels

    def test_update_passphrase(self, tmp_path):
        """Should update existing passphrase."""
        vault = PassphraseVault(vault_path=str(tmp_path / "vault.enc"))
        master = "MasterPassword123!@#"

        vault.store_passphrase("mykey", "original", master)
        vault.update_passphrase("mykey", "updated", master)

        result = vault.retrieve_passphrase("mykey", master)
        assert result == "updated"

    def test_delete_passphrase(self, tmp_path):
        """Should delete passphrase."""
        vault = PassphraseVault(vault_path=str(tmp_path / "vault.enc"))
        master = "MasterPassword123!@#"

        vault.store_passphrase("to_delete", "pass", master)
        vault.delete_passphrase("to_delete", master)

        labels = vault.list_labels(master)
        assert "to_delete" not in labels

    def test_empty_vault_list(self, tmp_path):
        """Should return empty list for empty vault."""
        vault = PassphraseVault(vault_path=str(tmp_path / "vault.enc"))
        master = "MasterPassword123!@#"

        # Store and delete to create empty vault
        vault.store_passphrase("temp", "pass", master)
        vault.delete_passphrase("temp", master)

        labels = vault.list_labels(master)
        assert labels == []


class TestPassphraseVaultRawStorage:
    """Tests for backend-aware raw vault storage helpers."""

    def test_file_backend_raw_storage_roundtrip_and_delete(self, tmp_path):
        """Should read, write, and delete raw file vault contents."""
        vault = PassphraseVault(vault_path=str(tmp_path / "vault.enc"))

        assert vault.read_raw_vault() is None

        vault.write_raw_vault("raw vault contents")
        assert vault.read_raw_vault() == "raw vault contents"
        assert vault.vault_exists() is True

        vault.delete_vault_storage()
        assert vault.read_raw_vault() is None
        vault.delete_vault_storage()

    def test_keychain_backend_raw_storage_roundtrip_and_delete(self, tmp_path):
        """Should proxy raw storage helpers to the keychain backend."""
        mock_keyring = _mock_keyring_with_storage()
        with patch(
            "secure_string_cipher.keychain_backend._get_keyring",
            return_value=mock_keyring,
        ):
            vault = PassphraseVault(
                vault_path=str(tmp_path / "vault.enc"), backend="keychain"
            )

        assert vault.get_vault_path() == "OS Keychain"
        assert vault.read_raw_vault() is None
        assert vault.vault_exists() is False

        vault.write_raw_vault("keychain raw vault")
        assert vault.read_raw_vault() == "keychain raw vault"
        assert vault.vault_exists() is True

        vault.delete_vault_storage()
        assert vault.read_raw_vault() is None
        assert vault.vault_exists() is False


class TestPassphraseVaultMigration:
    """Tests for file/keychain migration helpers."""

    def test_migrate_to_keychain_stores_existing_file_vault(self, tmp_path):
        """Should validate and copy raw file vault contents to keychain."""
        master = "master"
        vault = PassphraseVault(vault_path=str(tmp_path / "vault.enc"))
        vault.store_passphrase("label", "value", master)
        raw_contents = vault.read_raw_vault()
        mock_keychain = MagicMock()

        with patch(
            "secure_string_cipher.keychain_backend.KeychainVaultBackend",
            return_value=mock_keychain,
        ):
            vault.migrate_to_keychain(master)

        mock_keychain.store_vault.assert_called_once_with(raw_contents)

    def test_migrate_to_keychain_rejects_missing_or_empty_file_vault(self, tmp_path):
        """Should fail clearly when no usable file vault is present."""
        missing_vault = PassphraseVault(vault_path=str(tmp_path / "missing.enc"))
        with pytest.raises(ValueError, match="No file vault"):
            missing_vault.migrate_to_keychain("master")

        empty_vault = PassphraseVault(vault_path=str(tmp_path / "empty.enc"))
        empty_vault.vault_path.write_text("")
        with pytest.raises(ValueError, match="empty"):
            empty_vault.migrate_to_keychain("master")

    def test_migrate_to_file_writes_keychain_vault_and_restores_backend(self, tmp_path):
        """Should validate keychain contents, write them to disk, and restore state."""
        master = "master"
        source = PassphraseVault(vault_path=str(tmp_path / "source.enc"))
        source.store_passphrase("label", "value", master)
        raw_contents = source.read_raw_vault()
        mock_keychain = MagicMock()
        mock_keychain.load_vault.return_value = raw_contents

        target = PassphraseVault(vault_path=str(tmp_path / "target.enc"))
        with patch(
            "secure_string_cipher.keychain_backend.KeychainVaultBackend",
            return_value=mock_keychain,
        ):
            target.migrate_to_file(master)

        assert target.backend == "file"
        assert target.read_raw_vault() == raw_contents
        assert target.retrieve_passphrase("label", master) == "value"

    def test_migrate_to_file_rejects_missing_keychain_vault(self, tmp_path):
        """Should fail clearly when the keychain has no vault contents."""
        mock_keychain = MagicMock()
        mock_keychain.load_vault.return_value = None
        vault = PassphraseVault(vault_path=str(tmp_path / "vault.enc"))

        with patch(
            "secure_string_cipher.keychain_backend.KeychainVaultBackend",
            return_value=mock_keychain,
        ):
            with pytest.raises(ValueError, match="No keychain vault"):
                vault.migrate_to_file("master")
