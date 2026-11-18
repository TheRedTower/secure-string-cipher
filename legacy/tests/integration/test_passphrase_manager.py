"""
Tests for passphrase_manager module.
"""

from pathlib import Path

import pytest

from secure_string_cipher.passphrase_manager import PassphraseVault


class TestPassphraseVault:
    """Tests for PassphraseVault class."""

    @pytest.fixture
    def temp_vault(self, tmp_path):
        """Create a temporary vault for testing."""
        vault_path = tmp_path / "test_vault.enc"
        return PassphraseVault(str(vault_path))

    def test_vault_initialization(self, temp_vault):
        """Test vault initialization."""
        assert not temp_vault.vault_exists()
        vault_path = temp_vault.get_vault_path()
        assert vault_path is not None

    def test_store_and_retrieve_passphrase(self, temp_vault):
        """Test storing and retrieving a passphrase."""
        label = "test-project"
        passphrase = "mountain-tiger-ocean-basket"
        master_pw = "SecureMasterPassword123!"

        # Store passphrase
        temp_vault.store_passphrase(label, passphrase, master_pw)
        assert temp_vault.vault_exists()

        # Retrieve passphrase
        retrieved = temp_vault.retrieve_passphrase(label, master_pw)
        assert retrieved == passphrase

    def test_store_multiple_passphrases(self, temp_vault):
        """Test storing multiple passphrases."""
        master_pw = "SecureMasterPassword123!"

        passphrases = {
            "project-a": "alpha-beta-gamma-delta",
            "project-b": "echo-foxtrot-golf-hotel",
            "backup-2025": "india-juliet-kilo-lima",
        }

        # Store all passphrases
        for label, passphrase in passphrases.items():
            temp_vault.store_passphrase(label, passphrase, master_pw)

        # Retrieve and verify all
        for label, expected in passphrases.items():
            retrieved = temp_vault.retrieve_passphrase(label, master_pw)
            assert retrieved == expected

    def test_list_labels(self, temp_vault):
        """Test listing all passphrase labels."""
        master_pw = "SecureMasterPassword123!"

        labels_to_store = ["project-x", "backup", "archive"]
        for label in labels_to_store:
            temp_vault.store_passphrase(label, f"passphrase-{label}", master_pw)

        # List labels
        labels = temp_vault.list_labels(master_pw)
        assert sorted(labels) == sorted(labels_to_store)

    def test_empty_vault_list(self, temp_vault):
        """Test listing labels from empty vault."""
        master_pw = "SecureMasterPassword123!"

        # Store one then list (vault creation)
        temp_vault.store_passphrase("test", "passphrase", master_pw)
        temp_vault.delete_passphrase("test", master_pw)

        labels = temp_vault.list_labels(master_pw)
        assert labels == []

    def test_delete_passphrase(self, temp_vault):
        """Test deleting a passphrase."""
        master_pw = "SecureMasterPassword123!"

        temp_vault.store_passphrase("to-delete", "passphrase123", master_pw)
        temp_vault.delete_passphrase("to-delete", master_pw)

        with pytest.raises(ValueError, match="not found"):
            temp_vault.retrieve_passphrase("to-delete", master_pw)

    def test_update_passphrase(self, temp_vault):
        """Test updating an existing passphrase."""
        master_pw = "SecureMasterPassword123!"
        label = "updatable"

        # Store original
        temp_vault.store_passphrase(label, "original-passphrase", master_pw)

        # Update
        new_passphrase = "updated-passphrase"
        temp_vault.update_passphrase(label, new_passphrase, master_pw)

        # Verify update
        retrieved = temp_vault.retrieve_passphrase(label, master_pw)
        assert retrieved == new_passphrase

    def test_wrong_master_password(self, temp_vault):
        """Test that wrong master password fails."""
        correct_pw = "CorrectPassword123!"
        wrong_pw = "WrongPassword456!"

        temp_vault.store_passphrase("test", "passphrase", correct_pw)

        with pytest.raises(ValueError, match="Wrong master password"):
            temp_vault.retrieve_passphrase("test", wrong_pw)

    def test_duplicate_label_error(self, temp_vault):
        """Test that storing duplicate label raises error."""
        master_pw = "SecureMasterPassword123!"
        label = "duplicate"

        temp_vault.store_passphrase(label, "passphrase1", master_pw)

        with pytest.raises(ValueError, match="already exists"):
            temp_vault.store_passphrase(label, "passphrase2", master_pw)

    def test_retrieve_nonexistent_label(self, temp_vault):
        """Test retrieving non-existent label raises error."""
        master_pw = "SecureMasterPassword123!"

        temp_vault.store_passphrase("exists", "passphrase", master_pw)

        with pytest.raises(ValueError, match="not found"):
            temp_vault.retrieve_passphrase("does-not-exist", master_pw)

    def test_delete_nonexistent_label(self, temp_vault):
        """Test deleting non-existent label raises error."""
        master_pw = "SecureMasterPassword123!"

        temp_vault.store_passphrase("exists", "passphrase", master_pw)

        with pytest.raises(ValueError, match="not found"):
            temp_vault.delete_passphrase("does-not-exist", master_pw)

    def test_update_nonexistent_label(self, temp_vault):
        """Test updating non-existent label raises error."""
        master_pw = "SecureMasterPassword123!"

        temp_vault.store_passphrase("exists", "passphrase", master_pw)

        with pytest.raises(ValueError, match="not found"):
            temp_vault.update_passphrase("does-not-exist", "new", master_pw)

    def test_empty_label_error(self, temp_vault):
        """Test that empty label raises error."""
        master_pw = "SecureMasterPassword123!"

        with pytest.raises(ValueError, match="cannot be empty"):
            temp_vault.store_passphrase("", "passphrase", master_pw)

        with pytest.raises(ValueError, match="cannot be empty"):
            temp_vault.store_passphrase("   ", "passphrase", master_pw)

    def test_vault_persistence(self, temp_vault):
        """Test that vault persists across instances."""
        master_pw = "SecureMasterPassword123!"
        label = "persistent"
        passphrase = "this-should-persist"

        # Store in first instance
        temp_vault.store_passphrase(label, passphrase, master_pw)
        vault_path = temp_vault.get_vault_path()

        # Create new vault instance pointing to same file
        new_vault = PassphraseVault(vault_path)

        # Should be able to retrieve
        retrieved = new_vault.retrieve_passphrase(label, master_pw)
        assert retrieved == passphrase

    def test_vault_file_permissions(self, temp_vault):
        """Test that vault file has restricted permissions."""
        import os
        import stat

        master_pw = "SecureMasterPassword123!"
        temp_vault.store_passphrase("test", "passphrase", master_pw)

        vault_path = Path(temp_vault.get_vault_path())
        assert vault_path.exists()

        # Check file permissions (should be 600 - owner read/write only)
        file_stat = vault_path.stat()
        stat.filemode(file_stat.st_mode)

        # On Unix-like systems, should be -rw-------
        # The owner should have read and write, others should have nothing
        assert file_stat.st_mode & stat.S_IRUSR  # Owner can read
        assert file_stat.st_mode & stat.S_IWUSR  # Owner can write
        # Group and others should not have permissions
        # (These assertions may not work on Windows)
        if os.name != "nt":
            assert not (file_stat.st_mode & stat.S_IRGRP)  # Group can't read
            assert not (file_stat.st_mode & stat.S_IWGRP)  # Group can't write
            assert not (file_stat.st_mode & stat.S_IROTH)  # Others can't read
            assert not (file_stat.st_mode & stat.S_IWOTH)  # Others can't write
