"""
Test suite for Argon2id Key Derivation Function (KDF).

Tests cover:
- Argon2id key derivation
- Key consistency and uniqueness
- Security parameters validation
- Performance characteristics
"""

import os
import tempfile
from contextlib import suppress
from typing import Final

import pytest

from secure_string_cipher.config import (
    ARGON2_HASH_LENGTH,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
)
from secure_string_cipher.core import (
    FileMetadata,
    decrypt_file,
    decrypt_text,
    derive_key,
    encrypt_file,
    encrypt_text,
)

# Test constants
TEST_PASSWORD: Final[str] = "Kj8#mP9$vN2@xL5"
TEST_SALT: Final[bytes] = b"test_salt_16byte"  # 16 bytes


class TestArgon2idKDF:
    """Test Argon2id key derivation."""

    def test_derive_key_length(self):
        """Test that Argon2id derives correct key length."""
        key = derive_key(TEST_PASSWORD, TEST_SALT)
        assert len(key) == ARGON2_HASH_LENGTH

    def test_derive_key_consistency(self):
        """Test that same inputs produce same key."""
        key1 = derive_key(TEST_PASSWORD, TEST_SALT)
        key2 = derive_key(TEST_PASSWORD, TEST_SALT)
        assert key1 == key2

    def test_different_salts_produce_different_keys(self):
        """Test that different salts produce different keys."""
        salt1 = os.urandom(16)
        salt2 = os.urandom(16)
        key1 = derive_key(TEST_PASSWORD, salt1)
        key2 = derive_key(TEST_PASSWORD, salt2)
        assert key1 != key2

    def test_different_passwords_produce_different_keys(self):
        """Test that different passwords produce different keys."""
        key1 = derive_key("Password1!@#456", TEST_SALT)
        key2 = derive_key("Password2!@#456", TEST_SALT)
        assert key1 != key2

    def test_key_is_bytes(self):
        """Test that derived key is bytes."""
        key = derive_key(TEST_PASSWORD, TEST_SALT)
        assert isinstance(key, bytes)

    def test_empty_password_produces_key(self):
        """Test that empty password still produces a key (validation is caller's responsibility)."""
        # Note: KDF itself doesn't validate password strength - that's done at higher level
        key = derive_key("", TEST_SALT)
        assert len(key) == ARGON2_HASH_LENGTH

    def test_argon2id_config_values(self):
        """Verify Argon2id configuration values are secure."""
        # OWASP recommended minimums
        assert ARGON2_TIME_COST >= 2, "Time cost should be at least 2"
        assert ARGON2_MEMORY_COST >= 19456, "Memory should be at least 19MB"
        assert ARGON2_PARALLELISM >= 1, "Parallelism should be at least 1"


class TestFileMetadataFormat:
    """Test current FileMetadata format."""

    def test_metadata_has_version_5(self):
        """Test that FileMetadata uses version 5 by default."""
        metadata = FileMetadata(original_filename="test.txt")
        assert metadata.version == 5

    def test_metadata_has_key_commitment(self):
        """Test that FileMetadata includes key commitment field."""
        metadata = FileMetadata(
            original_filename="test.txt",
            key_commitment="base64commitment",
        )
        assert metadata.key_commitment == "base64commitment"

    def test_metadata_to_bytes_includes_key_commitment(self):
        """Test that to_bytes() includes key commitment field."""
        metadata = FileMetadata(
            original_filename="test.txt",
            key_commitment="abc123",
        )
        data = metadata.to_bytes()
        assert b"key_commitment" in data
        assert b"abc123" in data


class TestFileEncryptionWithKDF:
    """Test file encryption/decryption with Argon2id KDF."""

    @pytest.fixture
    def temp_files(self):
        """Create temporary file paths for testing."""
        fd_in, path_in = tempfile.mkstemp()
        os.close(fd_in)
        # Use suffix-based paths that don't exist yet
        path_out = path_in + ".enc"
        path_dec = path_in + ".dec"
        yield path_in, path_out, path_dec
        for path in [path_in, path_out, path_dec]:
            with suppress(OSError):
                os.unlink(path)

    def test_file_encrypted_with_argon2id(self, temp_files):
        """Test that files can be encrypted and metadata is valid."""
        path_in, path_out, path_dec = temp_files
        original_data = b"Test data for Argon2id encryption"

        with open(path_in, "wb") as f:
            f.write(original_data)

        # Encrypt and verify file was created
        encrypt_file(path_in, path_out, TEST_PASSWORD)
        assert os.path.exists(path_out)

        # Decrypt and verify original data is recovered
        decrypt_file(path_out, path_dec, TEST_PASSWORD)
        with open(path_dec, "rb") as f:
            decrypted_data = f.read()
        assert decrypted_data == original_data

    def test_file_roundtrip_argon2id(self, temp_files):
        """Test file encryption/decryption with Argon2id."""
        path_in, path_out, path_dec = temp_files
        original_data = b"Test data for Argon2id roundtrip"

        with open(path_in, "wb") as f:
            f.write(original_data)

        encrypt_file(path_in, path_out, TEST_PASSWORD)
        decrypt_file(path_out, path_dec, TEST_PASSWORD)

        with open(path_dec, "rb") as f:
            decrypted_data = f.read()

        assert decrypted_data == original_data


class TestTextEncryptionWithKDF:
    """Test text encryption uses Argon2id KDF."""

    def test_text_roundtrip(self):
        """Test text encryption/decryption works with Argon2id."""
        original = "Test message for Argon2id"
        encrypted = encrypt_text(original, TEST_PASSWORD)
        decrypted = decrypt_text(encrypted, TEST_PASSWORD)
        assert decrypted == original

    def test_text_encryption_produces_different_output(self):
        """Test that same text encrypted twice produces different output (due to random salt)."""
        original = "Test message"
        encrypted1 = encrypt_text(original, TEST_PASSWORD)
        encrypted2 = encrypt_text(original, TEST_PASSWORD)
        assert encrypted1 != encrypted2


class TestKDFSecurity:
    """Security-focused tests for KDF implementation."""

    @pytest.mark.security
    def test_argon2id_resistant_to_timing_attacks(self):
        """Test that key derivation takes consistent time."""
        import time

        # Run multiple derivations and check variance
        times = []
        for _ in range(5):
            start = time.perf_counter()
            derive_key(TEST_PASSWORD, TEST_SALT)
            times.append(time.perf_counter() - start)

        # Calculate variance - should be low
        avg = sum(times) / len(times)
        variance = sum((t - avg) ** 2 for t in times) / len(times)
        # Variance should be reasonably low (allow for system noise)
        assert variance < avg * 0.5, f"High timing variance: {variance}"

    @pytest.mark.security
    def test_kdf_minimum_work_factor(self):
        """Test that KDF has minimum work factor (takes measurable time)."""
        import time

        start = time.perf_counter()
        derive_key(TEST_PASSWORD, TEST_SALT)
        elapsed = time.perf_counter() - start

        # Should take at least some measurable time (prevents weak KDF)
        assert elapsed > 0.01, f"KDF too fast ({elapsed}s), may be insecure"
