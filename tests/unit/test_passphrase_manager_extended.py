"""
Additional coverage tests for passphrase_manager and core modules.

These tests target uncovered code paths to improve overall test coverage.
"""

import os
from unittest.mock import patch

import pytest

from secure_string_cipher.passphrase_manager import PassphraseVault


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

    def test_invalid_backend_config_falls_back_to_file(self, tmp_path, monkeypatch):
        """Invalid backend config encoding should not break vault init."""
        monkeypatch.setenv("HOME", str(tmp_path))
        config_path = tmp_path / ".secure-cipher" / "backend.conf"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_bytes(b"\xff\xfe")

        vault = PassphraseVault()

        assert vault.backend == "file"


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
        backups = list(vault.backup_dir.glob("vault_*.enc"))
        assert len(backups) <= 5


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
