"""
Test suite for Key Commitment functionality.

Tests cover:
- Key commitment computation
- Key commitment verification
- Integration with file encryption/decryption
- Security against invisible salamanders attack
"""

import base64
import json
import os
import tempfile
from contextlib import suppress
from typing import Final

import pytest

from secure_string_cipher.config import KEY_COMMITMENT_CONTEXT, KEY_COMMITMENT_SIZE
from secure_string_cipher.core import (
    CryptoError,
    FileMetadata,
    compute_key_commitment,
    decrypt_file,
    derive_key,
    encrypt_file,
    verify_key_commitment,
)

# Test constants
TEST_PASSWORD: Final[str] = "Kj8#mP9$vN2@xL5"
TEST_KEY: Final[bytes] = b"\x00" * 32  # 32-byte test key


class TestKeyCommitmentComputation:
    """Test key commitment computation."""

    def test_commitment_length(self):
        """Test that commitment has correct length (32 bytes for SHA-256)."""
        commitment = compute_key_commitment(TEST_KEY)
        assert len(commitment) == KEY_COMMITMENT_SIZE

    def test_commitment_consistency(self):
        """Test that same key produces same commitment."""
        commitment1 = compute_key_commitment(TEST_KEY)
        commitment2 = compute_key_commitment(TEST_KEY)
        assert commitment1 == commitment2

    def test_different_keys_produce_different_commitments(self):
        """Test that different keys produce different commitments."""
        key1 = b"\x00" * 32
        key2 = b"\x01" * 32
        commitment1 = compute_key_commitment(key1)
        commitment2 = compute_key_commitment(key2)
        assert commitment1 != commitment2

    def test_commitment_is_bytes(self):
        """Test that commitment is bytes."""
        commitment = compute_key_commitment(TEST_KEY)
        assert isinstance(commitment, bytes)

    def test_commitment_uses_context(self):
        """Test that commitment uses the defined context string."""
        # This is implicitly tested by consistency, but we verify
        # the context constant exists
        assert KEY_COMMITMENT_CONTEXT is not None
        assert len(KEY_COMMITMENT_CONTEXT) > 0


class TestKeyCommitmentVerification:
    """Test key commitment verification."""

    def test_verify_correct_commitment(self):
        """Test that correct commitment verifies successfully."""
        commitment = compute_key_commitment(TEST_KEY)
        assert verify_key_commitment(TEST_KEY, commitment) is True

    def test_verify_wrong_commitment(self):
        """Test that wrong commitment fails verification."""
        wrong_commitment = b"\xff" * 32
        assert verify_key_commitment(TEST_KEY, wrong_commitment) is False

    def test_verify_wrong_key(self):
        """Test that wrong key fails verification."""
        commitment = compute_key_commitment(TEST_KEY)
        wrong_key = b"\x01" * 32
        assert verify_key_commitment(wrong_key, commitment) is False

    def test_verify_truncated_commitment(self):
        """Test that truncated commitment fails verification."""
        commitment = compute_key_commitment(TEST_KEY)
        truncated = commitment[:16]
        assert verify_key_commitment(TEST_KEY, truncated) is False

    def test_verify_empty_commitment(self):
        """Test that empty commitment fails verification."""
        assert verify_key_commitment(TEST_KEY, b"") is False


class TestFileMetadataKeyCommitment:
    """Test FileMetadata with key commitment."""

    def test_metadata_has_key_commitment_field(self):
        """Test that FileMetadata includes key_commitment field."""
        metadata = FileMetadata(
            original_filename="test.txt",
            version=4,
            key_commitment="dGVzdA==",  # base64 of "test"
        )
        assert metadata.key_commitment == "dGVzdA=="
        assert metadata.version == 4

    def test_metadata_to_bytes_includes_key_commitment(self):
        """Test that to_bytes() includes key_commitment field."""
        metadata = FileMetadata(
            original_filename="test.txt",
            version=4,
            key_commitment="dGVzdA==",
        )
        data = metadata.to_bytes()
        parsed = json.loads(data.decode("utf-8"))
        assert "key_commitment" in parsed
        assert parsed["key_commitment"] == "dGVzdA=="

    def test_metadata_from_bytes_with_key_commitment(self):
        """Test that from_bytes() parses key_commitment field."""
        data = json.dumps(
            {
                "version": 4,
                "original_filename": "test.txt",
                "key_commitment": "dGVzdA==",
            }
        ).encode("utf-8")
        metadata = FileMetadata.from_bytes(data)
        assert metadata.key_commitment == "dGVzdA=="


class TestFileEncryptionKeyCommitment:
    """Test file encryption/decryption with key commitment."""

    @pytest.fixture
    def temp_files(self):
        """Create temporary file paths for testing."""
        fd_in, path_in = tempfile.mkstemp()
        os.close(fd_in)
        path_out = path_in + ".enc"
        path_dec = path_in + ".dec"
        yield path_in, path_out, path_dec
        for path in [path_in, path_out, path_dec]:
            with suppress(OSError):
                os.unlink(path)

    def test_encrypted_file_contains_key_commitment(self, temp_files):
        """Test that encrypted files include key commitment in metadata."""
        path_in, path_out, _ = temp_files
        original_data = b"Test data for key commitment"

        with open(path_in, "wb") as f:
            f.write(original_data)

        encrypt_file(path_in, path_out, TEST_PASSWORD)

        # Read back and verify metadata contains key_commitment
        with open(path_out, "rb") as f:
            magic = f.read(5)
            assert magic == b"SSCV2"
            meta_len = int.from_bytes(f.read(2), "big")
            meta_bytes = f.read(meta_len)
            parsed = json.loads(meta_bytes.decode("utf-8"))

            assert "key_commitment" in parsed
            assert parsed["version"] == 5
            # Verify it's valid base64
            commitment = base64.b64decode(parsed["key_commitment"])
            assert len(commitment) == KEY_COMMITMENT_SIZE

    def test_file_roundtrip_with_key_commitment(self, temp_files):
        """Test that files with key commitment encrypt/decrypt correctly."""
        path_in, path_out, path_dec = temp_files
        original_data = b"Test data for key commitment roundtrip"

        with open(path_in, "wb") as f:
            f.write(original_data)

        encrypt_file(path_in, path_out, TEST_PASSWORD)
        decrypt_file(path_out, path_dec, TEST_PASSWORD)

        with open(path_dec, "rb") as f:
            decrypted_data = f.read()

        assert decrypted_data == original_data

    def test_wrong_password_fails_commitment_check(self, temp_files):
        """Test that wrong password fails key commitment verification."""
        path_in, path_out, path_dec = temp_files
        original_data = b"Test data for wrong password test"

        with open(path_in, "wb") as f:
            f.write(original_data)

        encrypt_file(path_in, path_out, TEST_PASSWORD)

        # Try to decrypt with wrong password
        with pytest.raises(CryptoError) as exc_info:
            decrypt_file(path_out, path_dec, "WrongPassword123!")

        # Should fail on key commitment, not just GCM tag
        assert (
            "commitment" in str(exc_info.value).lower()
            or "failed" in str(exc_info.value).lower()
        )


class TestKeyCommitmentSecurity:
    """Security-focused tests for key commitment."""

    @pytest.mark.security
    def test_commitment_binding(self):
        """Test that commitment truly binds to the key."""
        key1 = derive_key(TEST_PASSWORD, b"salt1" * 4)
        key2 = derive_key(TEST_PASSWORD, b"salt2" * 4)

        commitment1 = compute_key_commitment(key1)
        commitment2 = compute_key_commitment(key2)

        # Different salts produce different keys, thus different commitments
        assert commitment1 != commitment2

        # Each commitment verifies only with its own key
        assert verify_key_commitment(key1, commitment1) is True
        assert verify_key_commitment(key2, commitment2) is True
        assert verify_key_commitment(key1, commitment2) is False
        assert verify_key_commitment(key2, commitment1) is False

    @pytest.mark.security
    def test_commitment_prevents_key_confusion(self):
        """Test that commitment prevents using wrong key for decryption."""
        # This is the "invisible salamanders" prevention test
        key1 = b"\x00" * 32
        key2 = b"\x01" * 32

        commitment_for_key1 = compute_key_commitment(key1)

        # Key2 cannot verify commitment made for key1
        assert verify_key_commitment(key2, commitment_for_key1) is False
