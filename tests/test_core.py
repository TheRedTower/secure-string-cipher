"""
Test suite for string_cipher.py core functionality
"""

import contextlib
import os
import tempfile
from typing import Final

import pytest

from secure_string_cipher.core import (
    CryptoError,
    StreamProcessor,
    decrypt_stream,
    decrypt_text,
    derive_key,
    encrypt_stream,
    encrypt_text,
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
    """Test key derivation functionality."""

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


class TestTextEncryption:
    """Test text encryption/decryption."""

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


class TestFileEncryption:
    """Test file encryption/decryption."""

    def test_file_roundtrip(self, temp_file):
        """Test if file can be encrypted and decrypted correctly."""
        original_data = b"Hello, World!\n" * 1000

        # Write original data
        with open(temp_file, "wb") as f:
            f.write(original_data)

        # Encrypt
        enc_file = temp_file + ".enc"
        with (
            StreamProcessor(temp_file, "rb") as r,
            StreamProcessor(enc_file, "wb") as w,
        ):
            encrypt_stream(r, w, TEST_PASSWORDS["VALID"])

        # Decrypt
        dec_file = temp_file + ".dec"
        with StreamProcessor(enc_file, "rb") as r, StreamProcessor(dec_file, "wb") as w:
            decrypt_stream(r, w, TEST_PASSWORDS["VALID"])

        # Verify
        with open(dec_file, "rb") as f:
            decrypted_data = f.read()

        assert decrypted_data == original_data

        # Cleanup
        os.unlink(enc_file)
        os.unlink(dec_file)

    def test_streaming_large_file(self, temp_file):
        """Test encryption/decryption of large file in chunks."""
        # Create 10MB file
        chunk_size = 64 * 1024  # 64 KiB
        chunks = 160  # ~10 MB
        original_data = os.urandom(chunk_size * chunks)

        with open(temp_file, "wb") as f:
            f.write(original_data)

        enc_file = temp_file + ".enc"
        dec_file = temp_file + ".dec"

        # Encrypt
        with (
            StreamProcessor(temp_file, "rb") as r,
            StreamProcessor(enc_file, "wb") as w,
        ):
            encrypt_stream(r, w, TEST_PASSWORDS["VALID"])

        # Decrypt
        with StreamProcessor(enc_file, "rb") as r, StreamProcessor(dec_file, "wb") as w:
            decrypt_stream(r, w, TEST_PASSWORDS["VALID"])

        # Verify
        with open(dec_file, "rb") as f:
            decrypted_data = f.read()

        assert decrypted_data == original_data

        # Cleanup
        os.unlink(enc_file)
        os.unlink(dec_file)


class TestStreamProcessor:
    """Test StreamProcessor functionality."""

    def test_overwrite_protection(self, temp_file, monkeypatch):
        """Test that StreamProcessor protects against file overwrite."""
        # Create a file
        with open(temp_file, "w") as f:
            f.write("original content")

        # Mock the input function to return 'n'
        monkeypatch.setattr("builtins.input", lambda _: "n")

        # Try to open in write mode - should raise error
        with pytest.raises(CryptoError, match="Operation cancelled"):
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
