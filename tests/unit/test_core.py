"""
Test suite for secure-string-cipher core encryption functionality.

Tests cover:
- Password validation
- Key derivation with Argon2id
- Text encryption/decryption
- File encryption/decryption with metadata
- Key commitment verification
"""

import contextlib
import json
import os
import tempfile
from typing import Final

import pytest

from secure_string_cipher.config import METADATA_MAGIC
from secure_string_cipher.core import (
    CryptoError,
    FileMetadata,
    StreamProcessor,
    compute_key_commitment,
    decrypt_bytes,
    decrypt_file,
    decrypt_text,
    derive_key,
    encrypt_bytes,
    encrypt_file,
    encrypt_text,
    verify_key_commitment,
)
from secure_string_cipher.timing_safe import check_password_strength

# Test password constants - only used for testing, never in production
TEST_PASSWORDS: Final = {
    "VALID": "Kj8#mP9$vN2@xL5",  # Complex password without common patterns
    "SHORT": "Ab1!defgh",
    "NO_UPPER": "abcd1234!@#$",
    "NO_LOWER": "ABCD1234!@#$",
    "NO_DIGITS": "ABCDabcd!@#$",
    "NO_SYMBOLS": "ABCDabcd1234",
    "COMMON_PATTERNS": ["Password123!@#", "Admin123!@#$", "Qwerty123!@#"],
}


def _tamper_metadata(
    encrypted_file: str | os.PathLike[str], key: str, value: str
) -> None:
    """Modify metadata in an encrypted file without updating authentication data."""
    path = os.fspath(encrypted_file)
    with open(path, "rb") as f:
        data = f.read()

    meta_len_start = len(METADATA_MAGIC)
    meta_len_end = meta_len_start + 2
    meta_len = int.from_bytes(data[meta_len_start:meta_len_end], "big")
    meta_start = meta_len_end
    meta_end = meta_start + meta_len

    metadata = json.loads(data[meta_start:meta_end].decode("utf-8"))
    metadata[key] = value
    meta_bytes = json.dumps(metadata, separators=(",", ":")).encode("utf-8")

    tampered = (
        data[:meta_len_start]
        + len(meta_bytes).to_bytes(2, "big")
        + meta_bytes
        + data[meta_end:]
    )
    with open(path, "wb") as f:
        f.write(tampered)


@pytest.fixture
def temp_file():
    """Create a temporary file for testing."""
    fd, path = tempfile.mkstemp()
    os.close(fd)
    yield path
    with contextlib.suppress(OSError):
        os.unlink(path)


class TestPasswordValidation:
    """Test password strength validation."""

    def test_password_minimum_length(self):
        """Test password length requirements."""
        valid, msg = check_password_strength(TEST_PASSWORDS["SHORT"])
        assert not valid
        assert "12 characters" in msg

    def test_password_complexity(self):
        """Test password complexity requirements."""
        # First test each requirement individually
        test_cases = [
            (TEST_PASSWORDS["NO_LOWER"], False, "lowercase"),
            (TEST_PASSWORDS["NO_UPPER"], False, "uppercase"),
            (TEST_PASSWORDS["NO_DIGITS"], False, "digits"),
            (TEST_PASSWORDS["NO_SYMBOLS"], False, "symbols"),
        ]

        for password, expected_valid, expected_msg in test_cases:
            valid, msg = check_password_strength(password)
            assert valid == expected_valid, f"Failed for password: {password}"
            assert expected_msg in msg.lower(), f"Unexpected message: {msg}"

        # Then test a valid password
        valid, msg = check_password_strength(TEST_PASSWORDS["VALID"])
        assert valid, f"Valid password failed: {msg}"

    def test_common_patterns(self):
        """Test rejection of common password patterns."""
        for password in TEST_PASSWORDS["COMMON_PATTERNS"]:
            valid, msg = check_password_strength(password)
            assert not valid
            assert "common patterns" in msg.lower()


class TestKeyDerivation:
    """Test Argon2id key derivation functionality."""

    def test_key_length(self):
        """Test if derived key has correct length."""
        key = derive_key("testpassword123!@#", b"salt" * 4)
        assert len(key) == 32  # AES-256 key length

    def test_key_consistency(self):
        """Test if same password+salt produces same key."""
        password = "testpassword123!@#"
        salt = b"salt" * 4
        key1 = derive_key(password, salt)
        key2 = derive_key(password, salt)
        assert key1 == key2

    def test_salt_impact(self):
        """Test if different salts produce different keys."""
        password = "testpassword123!@#"
        salt1 = b"salt1" * 4
        salt2 = b"salt2" * 4
        key1 = derive_key(password, salt1)
        key2 = derive_key(password, salt2)
        assert key1 != key2


class TestKeyCommitment:
    """Test key commitment functionality."""

    def test_compute_key_commitment(self):
        """Test key commitment computation."""
        key = derive_key("testpassword123!@#", b"salt" * 4)
        commitment = compute_key_commitment(key)
        assert len(commitment) == 32  # HMAC-SHA256 output

    def test_verify_key_commitment_correct(self):
        """Test key commitment verification with correct key."""
        key = derive_key("testpassword123!@#", b"salt" * 4)
        commitment = compute_key_commitment(key)
        assert verify_key_commitment(key, commitment) is True

    def test_verify_key_commitment_wrong_key(self):
        """Test key commitment verification with wrong key."""
        key1 = derive_key("testpassword123!@#", b"salt" * 4)
        key2 = derive_key("differentpassword!@#", b"salt" * 4)
        commitment = compute_key_commitment(key1)
        assert verify_key_commitment(key2, commitment) is False

    def test_commitment_consistency(self):
        """Test that same key produces same commitment."""
        key = derive_key("testpassword123!@#", b"salt" * 4)
        commitment1 = compute_key_commitment(key)
        commitment2 = compute_key_commitment(key)
        assert commitment1 == commitment2


class TestTextEncryption:
    """Test text encryption/decryption with Argon2id and key commitment."""

    @pytest.mark.parametrize(
        "text",
        [
            "Hello, World!",
            "Special chars: !@#$%^&*()",
            "Unicode: 🔒🔑📝",
            "A" * 1000,  # Long text
            "",  # Empty string
        ],
    )
    def test_text_roundtrip(self, text):
        """Test if text can be encrypted and decrypted correctly."""
        encrypted = encrypt_text(text, TEST_PASSWORDS["VALID"])
        decrypted = decrypt_text(encrypted, TEST_PASSWORDS["VALID"])
        assert decrypted == text

    def test_wrong_password(self):
        """Test decryption with wrong password."""
        text = "Hello, World!"
        encrypted = encrypt_text(text, TEST_PASSWORDS["VALID"])
        with pytest.raises(CryptoError):
            decrypt_text(encrypted, TEST_PASSWORDS["NO_SYMBOLS"])

    def test_corrupted_data(self):
        """Test handling of corrupted encrypted data."""
        with pytest.raises(CryptoError) as exc_info:
            decrypt_text("invalid base64!", TEST_PASSWORDS["VALID"])
        assert "Text decryption failed" in str(exc_info.value)

    def test_encryption_produces_different_output(self):
        """Test that same text encrypted twice produces different output (random salt)."""
        text = "Test message"
        encrypted1 = encrypt_text(text, TEST_PASSWORDS["VALID"])
        encrypted2 = encrypt_text(text, TEST_PASSWORDS["VALID"])
        assert encrypted1 != encrypted2


class TestBytesEncryption:
    """Test binary-safe byte encryption/decryption."""

    def test_bytes_roundtrip(self):
        """Test if bytes can be encrypted and decrypted correctly."""
        data = b"\x00\xffbinary\npayload"
        encrypted = encrypt_bytes(data, TEST_PASSWORDS["VALID"])
        decrypted = decrypt_bytes(encrypted, TEST_PASSWORDS["VALID"])
        assert decrypted == data


class TestStreamProcessor:
    """Test StreamProcessor functionality."""

    def test_overwrite_protection(self, temp_file):
        """Test that StreamProcessor rejects existing output files."""
        # Create a file
        with open(temp_file, "w") as f:
            f.write("original content")

        # Try to open in write mode - should raise error
        with pytest.raises(CryptoError, match="Output file already exists"):
            with StreamProcessor(temp_file, "wb") as _:
                pass  # Should not reach here

    def test_progress_tracking(self, temp_file):
        """Test progress tracking functionality."""
        test_data = b"test data" * 1000

        # Write test file
        with open(temp_file, "wb") as f:
            f.write(test_data)

        # Read with progress tracking
        with StreamProcessor(temp_file, "rb") as sp:
            data = b""
            while True:
                chunk = sp.read(1024)
                if not chunk:
                    break
                data += chunk
                assert sp.bytes_processed <= len(test_data)

            assert sp.bytes_processed == len(test_data)
            assert data == test_data


class TestFileMetadata:
    """Test FileMetadata serialization."""

    def test_metadata_to_bytes(self):
        """Test metadata serializes to JSON bytes."""
        meta = FileMetadata(original_filename="test.txt", version=4)
        data = meta.to_bytes()
        assert b"test.txt" in data
        assert b'"version":4' in data

    def test_metadata_from_bytes(self):
        """Test metadata deserializes from JSON bytes."""
        data = b'{"version":4,"original_filename":"hello.txt"}'
        meta = FileMetadata.from_bytes(data)
        assert meta.original_filename == "hello.txt"
        assert meta.version == 4

    def test_metadata_roundtrip(self):
        """Test metadata serialization roundtrip."""
        original = FileMetadata(
            original_filename="document.pdf",
            version=4,
            key_commitment="abc123",
        )
        serialized = original.to_bytes()
        restored = FileMetadata.from_bytes(serialized)
        assert restored.original_filename == original.original_filename
        assert restored.version == original.version
        assert restored.key_commitment == original.key_commitment

    def test_metadata_without_filename(self):
        """Test metadata without original filename."""
        meta = FileMetadata(original_filename=None, version=4)
        data = meta.to_bytes()
        restored = FileMetadata.from_bytes(data)
        assert restored.original_filename is None
        assert restored.version == 4

    def test_metadata_invalid_json(self):
        """Test handling of invalid JSON metadata."""
        with pytest.raises(CryptoError, match="Invalid metadata"):
            FileMetadata.from_bytes(b"not valid json{{{")

    def test_metadata_filename_truncation(self):
        """Test that very long filenames are truncated."""
        long_name = "a" * 500  # Longer than FILENAME_MAX_LENGTH (255)
        meta = FileMetadata(original_filename=long_name, version=4)
        serialized = meta.to_bytes()
        restored = FileMetadata.from_bytes(serialized)
        assert len(restored.original_filename) == 255


class TestFileEncryption:
    """Test file encryption with metadata and key commitment."""

    @pytest.fixture
    def temp_files(self):
        """Create temporary files for testing and clean up after."""
        files = []
        for _ in range(3):
            fd, path = tempfile.mkstemp()
            os.close(fd)
            files.append(path)
        yield files
        for path in files:
            with contextlib.suppress(OSError):
                os.unlink(path)

    def test_encrypt_with_filename(self, temp_files):
        """Test encryption stores original filename."""
        input_path, _, _ = temp_files
        output_path = input_path + ".enc"
        dec_path = input_path + ".dec"
        test_data = b"Hello, encryption!"

        with open(input_path, "wb") as f:
            f.write(test_data)

        # Encrypt with metadata
        encrypt_file(
            input_path, output_path, TEST_PASSWORDS["VALID"], store_filename=True
        )

        # Verify magic header is present
        with open(output_path, "rb") as f:
            magic = f.read(len(METADATA_MAGIC))
            assert magic == METADATA_MAGIC

        # Decrypt and verify
        actual_path, metadata = decrypt_file(
            output_path, dec_path, TEST_PASSWORDS["VALID"]
        )

        assert actual_path == dec_path
        assert metadata is not None
        assert metadata.original_filename == os.path.basename(input_path)
        assert metadata.key_commitment is not None

        with open(dec_path, "rb") as f:
            assert f.read() == test_data

    def test_encrypt_without_filename(self, temp_files):
        """Test encryption without storing filename."""
        input_path, _, _ = temp_files
        output_path = input_path + ".enc"
        dec_path = input_path + ".dec"
        test_data = b"No filename stored"

        with open(input_path, "wb") as f:
            f.write(test_data)

        # Encrypt without filename
        encrypt_file(
            input_path, output_path, TEST_PASSWORDS["VALID"], store_filename=False
        )

        # Decrypt and verify
        actual_path, metadata = decrypt_file(
            output_path, dec_path, TEST_PASSWORDS["VALID"]
        )

        assert actual_path == dec_path
        assert metadata is not None
        assert metadata.original_filename is None

    def test_decrypt_restore_filename(self, temp_files, tmp_path):
        """Test decryption restores original filename."""
        input_path, output_path, _ = temp_files
        test_data = b"Restore my name!"

        # Create file with a specific name
        named_file = tmp_path / "my_document.txt"
        named_file.write_bytes(test_data)

        # Encrypt
        enc_path = str(named_file) + ".enc"
        encrypt_file(
            str(named_file), enc_path, TEST_PASSWORDS["VALID"], store_filename=True
        )

        # Delete original and decrypt (filename should be restored)
        named_file.unlink()

        actual_path, metadata = decrypt_file(
            enc_path, None, TEST_PASSWORDS["VALID"], restore_filename=True
        )

        assert os.path.basename(actual_path) == "my_document.txt"
        assert metadata.original_filename == "my_document.txt"

        with open(actual_path, "rb") as f:
            assert f.read() == test_data

        # Cleanup
        os.unlink(actual_path)
        os.unlink(enc_path)

    def test_decrypt_without_restore(self, temp_files, tmp_path):
        """Test decryption without restoring filename."""
        test_data = b"Keep encrypted name!"

        named_file = tmp_path / "original.txt"
        named_file.write_bytes(test_data)

        enc_path = str(named_file) + ".enc"
        encrypt_file(
            str(named_file), enc_path, TEST_PASSWORDS["VALID"], store_filename=True
        )

        # Decrypt without restoring filename
        actual_path, metadata = decrypt_file(
            enc_path, None, TEST_PASSWORDS["VALID"], restore_filename=False
        )

        assert actual_path == enc_path + ".dec"
        assert (
            metadata.original_filename == "original.txt"
        )  # Still accessible but not used

        # Cleanup
        os.unlink(actual_path)
        os.unlink(enc_path)

    def test_v5_metadata_tampering_fails_and_leaves_no_output(self, tmp_path):
        """Test v5 metadata is authenticated and temp output is removed."""
        input_file = tmp_path / "input.txt"
        encrypted_file = tmp_path / "input.txt.enc"
        output_file = tmp_path / "output.txt"
        input_file.write_text("secret data")

        encrypt_file(str(input_file), str(encrypted_file), TEST_PASSWORDS["VALID"])
        _tamper_metadata(encrypted_file, "original_filename", "other.txt")

        with pytest.raises(CryptoError):
            decrypt_file(
                str(encrypted_file),
                str(output_file),
                TEST_PASSWORDS["VALID"],
            )

        assert not output_file.exists()
        assert list(tmp_path.glob(".output.txt.*.tmp")) == []

    def test_v4_file_decryption_remains_compatible(self, tmp_path, monkeypatch):
        """Test legacy v4 files remain readable without metadata AAD."""
        from secure_string_cipher import core

        input_file = tmp_path / "legacy.txt"
        encrypted_file = tmp_path / "legacy.txt.enc"
        output_file = tmp_path / "legacy.out"
        input_file.write_text("legacy data")

        monkeypatch.setattr(core, "METADATA_VERSION", 4)
        encrypt_file(str(input_file), str(encrypted_file), TEST_PASSWORDS["VALID"])
        _tamper_metadata(encrypted_file, "original_filename", "legacy2.txt")

        actual_path, metadata = decrypt_file(
            str(encrypted_file),
            str(output_file),
            TEST_PASSWORDS["VALID"],
        )

        assert actual_path == str(output_file)
        assert output_file.read_text() == "legacy data"
        assert metadata is not None
        assert metadata.version == 4

    def test_failed_decrypt_removes_temporary_plaintext(self, tmp_path):
        """Test authentication failure removes temporary plaintext."""
        input_file = tmp_path / "input.txt"
        encrypted_file = tmp_path / "input.txt.enc"
        output_file = tmp_path / "output.txt"
        input_file.write_text("secret data")

        encrypt_file(str(input_file), str(encrypted_file), TEST_PASSWORDS["VALID"])

        with pytest.raises(CryptoError):
            decrypt_file(
                str(encrypted_file), str(output_file), TEST_PASSWORDS["NO_SYMBOLS"]
            )

        assert not output_file.exists()
        assert list(tmp_path.glob(".output.txt.*.tmp")) == []


class TestErrorHandling:
    """Test error handling in encryption/decryption."""

    @pytest.fixture
    def temp_file(self):
        """Create a temporary file for testing."""
        fd, path = tempfile.mkstemp()
        os.close(fd)
        yield path
        with contextlib.suppress(OSError):
            os.unlink(path)

    def test_wrong_password(self, temp_file):
        """Test decryption with wrong password."""
        test_data = b"Secret data"

        with open(temp_file, "wb") as f:
            f.write(test_data)

        enc_path = temp_file + ".enc"
        dec_path = temp_file + ".dec"

        encrypt_file(temp_file, enc_path, TEST_PASSWORDS["VALID"])

        with pytest.raises(CryptoError):
            decrypt_file(enc_path, dec_path, TEST_PASSWORDS["NO_SYMBOLS"])

        # Cleanup
        with contextlib.suppress(OSError):
            os.unlink(enc_path)
            os.unlink(dec_path)

    def test_corrupted_metadata(self, temp_file):
        """Test handling of corrupted metadata in file."""
        # Create a file with valid magic but invalid metadata
        with open(temp_file, "wb") as f:
            f.write(METADATA_MAGIC)
            f.write(b"\x00\x10")  # 16 bytes of metadata expected
            f.write(b"invalid json!!")  # But only 14 bytes of garbage

        with pytest.raises(CryptoError, match="truncated metadata"):
            decrypt_file(temp_file, temp_file + ".dec", TEST_PASSWORDS["VALID"])

    def test_truncated_file(self, temp_file):
        """Test handling of truncated file."""
        # Create a truncated file with just magic header
        with open(temp_file, "wb") as f:
            f.write(METADATA_MAGIC)

        with pytest.raises(CryptoError, match="truncated"):
            decrypt_file(temp_file, temp_file + ".dec", TEST_PASSWORDS["VALID"])

    def test_missing_magic_header(self, temp_file):
        """Test handling of file without magic header."""
        # Create a file without magic header
        with open(temp_file, "wb") as f:
            f.write(b"some random data without magic header")

        with pytest.raises(CryptoError, match="missing magic header"):
            decrypt_file(temp_file, temp_file + ".dec", TEST_PASSWORDS["VALID"])
