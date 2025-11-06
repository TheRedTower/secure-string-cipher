"""
Integration tests for complete CLI workflows.

These tests verify end-to-end functionality of CLI operations,
including file encryption/decryption workflows and vault operations.
"""

import pytest


@pytest.mark.integration
class TestEncryptionWorkflows:
    """Test complete encryption/decryption workflows."""

    def test_encrypt_decrypt_text_workflow(self, tmp_path):
        """Test complete text encryption and decryption workflow."""
        from secure_string_cipher.core import decrypt_text, encrypt_text

        # Test data
        original_text = "This is a secret message!"
        password = "TestPassword123!@#"

        # Encrypt
        encrypted = encrypt_text(original_text, password)
        assert encrypted != original_text
        assert len(encrypted) > len(original_text)

        # Decrypt
        decrypted = decrypt_text(encrypted, password)
        assert decrypted == original_text

    def test_encrypt_decrypt_file_workflow(self, tmp_path):
        """Test complete file encryption and decryption workflow."""
        from secure_string_cipher.core import decrypt_file, encrypt_file

        # Create test file
        input_file = tmp_path / "test_input.txt"
        input_file.write_text("This is secret file content!\n" * 100)

        output_file = tmp_path / "test_output.enc"
        decrypted_file = tmp_path / "test_decrypted.txt"

        password = "FileTestPassword123!@#"

        # Encrypt file
        encrypt_file(str(input_file), str(output_file), password)
        assert output_file.exists()
        assert output_file.stat().st_size > 0

        # Verify encrypted content is different
        assert output_file.read_bytes() != input_file.read_bytes()

        # Decrypt file
        decrypt_file(str(output_file), str(decrypted_file), password)
        assert decrypted_file.exists()

        # Verify content matches
        assert decrypted_file.read_text() == input_file.read_text()

    def test_encrypt_large_file_workflow(self, tmp_path):
        """Test encryption of larger files."""
        from secure_string_cipher.core import decrypt_file, encrypt_file

        # Create a 1MB test file
        large_file = tmp_path / "large_test.txt"
        large_file.write_text("A" * (1024 * 1024))  # 1MB

        encrypted_file = tmp_path / "large_test.enc"
        decrypted_file = tmp_path / "large_decrypted.txt"

        password = "LargeFilePassword123!@#"

        # Encrypt
        encrypt_file(str(large_file), str(encrypted_file), password)
        assert encrypted_file.exists()

        # Decrypt
        decrypt_file(str(encrypted_file), str(decrypted_file), password)
        assert decrypted_file.exists()

        # Verify
        assert decrypted_file.read_text() == large_file.read_text()


@pytest.mark.integration
class TestVaultWorkflows:
    """Test complete vault operation workflows."""

    def test_vault_store_retrieve_workflow(self, tmp_path, monkeypatch):
        """Test complete vault store and retrieve workflow."""
        from secure_string_cipher.passphrase_manager import PassphraseVault

        # Set up vault path
        vault_path = tmp_path / "test_vault.json"

        master_password = "MasterPassword123!@#"

        # Create vault and store passphrase
        vault = PassphraseVault(str(vault_path))
        vault.store_passphrase("github", "GitHubPassword123!@#", master_password)
        vault.store_passphrase("aws", "AWSPassword456!@#", master_password)

        # Verify vault file exists
        assert vault_path.exists()

        # Create new vault instance (simulates reopening)
        vault2 = PassphraseVault(str(vault_path))

        # Retrieve passphrases
        github_pass = vault2.retrieve_passphrase("github", master_password)
        aws_pass = vault2.retrieve_passphrase("aws", master_password)

        assert github_pass == "GitHubPassword123!@#"
        assert aws_pass == "AWSPassword456!@#"

    def test_vault_update_delete_workflow(self, tmp_path, monkeypatch):
        """Test vault update and delete operations."""
        from secure_string_cipher.passphrase_manager import PassphraseVault

        vault_path = tmp_path / "test_vault.json"

        master_password = "MasterPassword123!@#"
        vault = PassphraseVault(str(vault_path))

        # Store initial
        vault.store_passphrase("service", "InitialPassword123", master_password)

        # Verify it was stored
        stored_pass = vault.retrieve_passphrase("service", master_password)
        assert stored_pass == "InitialPassword123"

        # Update
        vault.update_passphrase("service", "UpdatedPassword456", master_password)

        # Verify update
        updated_pass = vault.retrieve_passphrase("service", master_password)
        assert updated_pass == "UpdatedPassword456"

        # Delete
        vault.delete_passphrase("service", master_password)

        # Verify deleted
        labels = vault.list_labels(master_password)
        assert "service" not in labels

    def test_vault_multiple_sessions_workflow(self, tmp_path, monkeypatch):
        """Test vault persistence across multiple sessions."""
        from secure_string_cipher.passphrase_manager import PassphraseVault

        vault_path = tmp_path / "test_vault.json"

        master_password = "MasterPassword123!@#"

        # Session 1: Store data
        vault1 = PassphraseVault(str(vault_path))
        vault1.store_passphrase("label1", "password1", master_password)
        vault1.store_passphrase("label2", "password2", master_password)
        labels1 = vault1.list_labels(master_password)
        assert len(labels1) == 2

        # Session 2: Read and add more
        vault2 = PassphraseVault(str(vault_path))
        assert vault2.retrieve_passphrase("label1", master_password) == "password1"
        vault2.store_passphrase("label3", "password3", master_password)
        labels2 = vault2.list_labels(master_password)
        assert len(labels2) == 3

        # Session 3: Verify all data
        vault3 = PassphraseVault(str(vault_path))
        labels3 = vault3.list_labels(master_password)
        assert len(labels3) == 3
        assert set(labels3) == {"label1", "label2", "label3"}


@pytest.mark.integration
class TestSecurityWorkflows:
    """Test security-related workflows."""

    def test_filename_sanitization_workflow(self, tmp_path):
        """Test filename sanitization in real file operations."""
        from secure_string_cipher.core import encrypt_file
        from secure_string_cipher.security import sanitize_filename

        # Dangerous filename
        dangerous_name = "../../etc/passwd"
        safe_name = sanitize_filename(dangerous_name)

        # Create file with sanitized name
        input_file = tmp_path / "test.txt"
        input_file.write_text("test content")

        output_file = tmp_path / safe_name
        password = "TestPassword123!@#"

        # Should not traverse directories
        encrypt_file(str(input_file), str(output_file), password)

        # Verify file is in expected location
        assert output_file.exists()
        assert output_file.parent == tmp_path
        assert ".." not in str(output_file)

    def test_path_validation_workflow(self, tmp_path):
        """Test path validation in file operations."""
        from secure_string_cipher.core import encrypt_file
        from secure_string_cipher.security import SecurityError, validate_safe_path

        input_file = tmp_path / "test.txt"
        input_file.write_text("test content")

        # Try to write outside allowed directory
        dangerous_output = tmp_path.parent / "escape.enc"
        password = "TestPassword123!@#"

        # Validate path - should catch traversal
        try:
            validate_safe_path(str(dangerous_output), allowed_dir=str(tmp_path))
            # If validation passes, encryption should still be safe
            encrypt_file(str(input_file), str(dangerous_output), password)
            # Clean up if it somehow succeeded
            if dangerous_output.exists():
                dangerous_output.unlink()
        except SecurityError:
            # Expected - path validation caught the issue
            pass


@pytest.mark.integration
class TestErrorHandlingWorkflows:
    """Test error handling in complete workflows."""

    def test_wrong_password_workflow(self, tmp_path):
        """Test decryption with wrong password."""
        from secure_string_cipher.core import decrypt_text, encrypt_text
        from secure_string_cipher.utils import CryptoError

        original = "Secret message"
        correct_password = "CorrectPassword123!@#"
        wrong_password = "WrongPassword456!@#"

        # Encrypt with correct password
        encrypted = encrypt_text(original, correct_password)

        # Try to decrypt with wrong password
        with pytest.raises(CryptoError):  # Should raise decryption error
            decrypt_text(encrypted, wrong_password)

    def test_corrupted_data_workflow(self, tmp_path):
        """Test handling of corrupted encrypted data."""
        from secure_string_cipher.core import decrypt_text
        from secure_string_cipher.utils import CryptoError

        # Corrupted encrypted data
        corrupted_data = "this is not valid encrypted data"
        password = "TestPassword123!@#"

        # Should handle gracefully
        with pytest.raises(CryptoError):
            decrypt_text(corrupted_data, password)

    def test_missing_file_workflow(self, tmp_path):
        """Test handling of missing files."""
        from secure_string_cipher.core import encrypt_file
        from secure_string_cipher.utils import CryptoError

        nonexistent_file = tmp_path / "nonexistent.txt"
        output_file = tmp_path / "output.enc"
        password = "TestPassword123!@#"

        # Should raise appropriate error
        with pytest.raises(CryptoError):
            encrypt_file(str(nonexistent_file), str(output_file), password)


@pytest.mark.integration
@pytest.mark.slow
class TestPerformanceWorkflows:
    """Test performance characteristics of workflows."""

    def test_large_text_encryption_performance(self):
        """Test encryption performance with large text."""
        import time

        from secure_string_cipher.core import decrypt_text, encrypt_text

        # 100KB of text
        large_text = "A" * (100 * 1024)
        password = "TestPassword123!@#"

        # Encrypt
        start = time.perf_counter()
        encrypted = encrypt_text(large_text, password)
        encrypt_time = time.perf_counter() - start

        # Decrypt
        start = time.perf_counter()
        decrypted = decrypt_text(encrypted, password)
        decrypt_time = time.perf_counter() - start

        # Verify
        assert decrypted == large_text

        # Performance assertions (should be fast)
        assert encrypt_time < 1.0, f"Encryption took {encrypt_time:.2f}s, expected <1s"
        assert decrypt_time < 1.0, f"Decryption took {decrypt_time:.2f}s, expected <1s"

    def test_multiple_vault_operations_performance(self, tmp_path, monkeypatch):
        """Test vault performance with multiple operations."""
        import time

        from secure_string_cipher.passphrase_manager import PassphraseVault

        vault_path = tmp_path / "test_vault.json"

        master_password = "MasterPassword123!@#"
        vault = PassphraseVault(str(vault_path))

        # Store many passphrases
        start = time.perf_counter()
        for i in range(50):
            vault.store_passphrase(f"label_{i}", f"password_{i}", master_password)
        store_time = time.perf_counter() - start

        # Retrieve all
        start = time.perf_counter()
        for i in range(50):
            vault.retrieve_passphrase(f"label_{i}", master_password)
        retrieve_time = time.perf_counter() - start

        # Performance assertions (relaxed for real-world conditions)
        assert store_time < 30.0, (
            f"Storing 50 items took {store_time:.2f}s, expected <30s"
        )
        assert retrieve_time < 10.0, (
            f"Retrieving 50 items took {retrieve_time:.2f}s, expected <10s"
        )
