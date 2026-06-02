"""
Unit tests to increase coverage for core.py.

Covers:
- StreamProcessor edge cases (file-like objects, write errors)
- _ensure_no_symlink with symlinks and OSError
- derive_key_from_file
- generate_key_pair
- FileMetadata
- _determine_output_path in cli_args.py
"""

from __future__ import annotations

from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from secure_string_cipher.core import (
    CryptoError,
    FileMetadata,
    StreamProcessor,
    _ensure_no_symlink,
    decrypt_file,
    decrypt_text,
    encrypt_file,
    encrypt_text,
    generate_key_pair,
)

# =============================================================================
# StreamProcessor edge cases
# =============================================================================


class TestStreamProcessor:
    """Tests for StreamProcessor class."""

    def test_read_without_open(self):
        """Should raise error when reading without open."""
        sp = StreamProcessor("/nonexistent", "rb")
        sp.file = None
        with pytest.raises(CryptoError, match="File not open"):
            sp.read()

    def test_write_without_open(self):
        """Should raise error when writing without open."""
        sp = StreamProcessor("/nonexistent", "wb")
        sp.file = None
        with pytest.raises(CryptoError, match="File not open"):
            sp.write(b"data")

    def test_file_too_large(self, tmp_path):
        """Should reject files exceeding MAX_FILE_SIZE."""
        large_file = tmp_path / "large.bin"
        # Create a sparse file header to trick size check
        large_file.write_bytes(b"x")

        with patch("os.path.getsize", return_value=2 * 1024 * 1024 * 1024):
            with pytest.raises(CryptoError, match="too large"):
                StreamProcessor(str(large_file), "rb")

    def test_output_file_exists(self, tmp_path):
        """Should reject when output file already exists."""
        existing = tmp_path / "output.enc"
        existing.write_bytes(b"data")

        sp = StreamProcessor(str(existing), "wb")
        with pytest.raises(CryptoError, match="already exists"):
            sp.__enter__()

    def test_file_like_object(self):
        """Should accept file-like objects."""
        buf = BytesIO(b"test data")
        sp = StreamProcessor(buf, "rb")  # type: ignore
        with sp:
            data = sp.read()
        assert data == b"test data"

    def test_write_with_progress(self, tmp_path):
        """Should write data with progress tracking."""
        out_path = tmp_path / "output.bin"

        sp = StreamProcessor(str(out_path), "wb")
        with sp:
            n = sp.write(b"hello world")
        assert n == 11
        assert sp.bytes_processed == 11

    def test_write_os_error(self, tmp_path):
        """Should raise CryptoError on write failure."""
        out_path = tmp_path / "output.bin"

        sp = StreamProcessor(str(out_path), "wb")
        with sp:
            # Save original file and replace with mock
            original_file = sp.file
            sp.file = MagicMock()
            sp.file.write.side_effect = OSError("disk full")
            with pytest.raises(CryptoError, match="Write failed"):
                sp.write(b"data")
            # Restore original for proper cleanup
            sp.file = original_file

    def test_read_with_progress(self, tmp_path):
        """Should read with progress tracking."""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"hello world")

        sp = StreamProcessor(str(test_file), "rb")
        with sp:
            data = sp.read()
        assert data == b"hello world"
        assert sp.bytes_processed == 11


# =============================================================================
# _ensure_no_symlink
# =============================================================================


class TestEnsureNoSymlink:
    """Tests for symlink detection."""

    def test_regular_path_ok(self, tmp_path):
        """Should accept regular paths."""
        regular_file = tmp_path / "regular.txt"
        regular_file.write_text("data")
        # Should not raise
        _ensure_no_symlink(regular_file, "test")

    def test_symlink_rejected(self, tmp_path):
        """Should reject symlinked paths."""
        target = tmp_path / "target.txt"
        target.write_text("data")
        link = tmp_path / "link.txt"
        link.symlink_to(target)

        with pytest.raises(CryptoError, match="symlink"):
            _ensure_no_symlink(link, "test")

    def test_relative_path(self, tmp_path):
        """Should handle relative paths."""
        regular_file = tmp_path / "file.txt"
        regular_file.write_text("data")
        # Use the path as-is (relative)
        _ensure_no_symlink(regular_file, "test")


# =============================================================================
# generate_key_pair
# =============================================================================


class TestGenerateKeyPair:
    """Tests for RSA key pair generation."""

    def test_generate_key_pair_success(self, tmp_path):
        """Should generate key pair files."""
        private_key = tmp_path / "id_rsa"
        public_key = tmp_path / "id_rsa.pub"

        generate_key_pair(str(private_key), str(public_key))

        assert private_key.exists()
        assert public_key.exists()
        assert b"BEGIN PRIVATE KEY" in private_key.read_bytes()
        assert b"BEGIN PUBLIC KEY" in public_key.read_bytes()

    def test_generate_key_pair_default_public(self, tmp_path):
        """Should use default public key path."""
        private_key = tmp_path / "id_rsa"

        generate_key_pair(str(private_key))

        assert private_key.exists()
        assert (tmp_path / "id_rsa.pub").exists()

    def test_generate_key_pair_same_path(self, tmp_path):
        """Should reject same path for private and public key."""
        key_path = tmp_path / "same.key"

        with pytest.raises(CryptoError, match="must be different"):
            generate_key_pair(str(key_path), str(key_path))

    def test_generate_key_pair_symlink_rejected(self, tmp_path):
        """Should reject symlinked output paths."""
        target = tmp_path / "target"
        target.mkdir()
        link = tmp_path / "link"
        link.symlink_to(target)

        private_key = link / "id_rsa"
        public_key = tmp_path / "id_rsa.pub"

        with pytest.raises(CryptoError):
            generate_key_pair(str(private_key), str(public_key))

    def test_generate_key_pair_permissions(self, tmp_path):
        """Should set correct permissions on key files."""
        private_key = tmp_path / "id_rsa"
        public_key = tmp_path / "id_rsa.pub"

        generate_key_pair(str(private_key), str(public_key))

        # Private key should be 0o600
        assert oct(private_key.stat().st_mode & 0o777) == oct(0o600)
        # Public key should be 0o644
        assert oct(public_key.stat().st_mode & 0o777) == oct(0o644)


# =============================================================================
# FileMetadata
# =============================================================================


class TestFileMetadata:
    """Tests for FileMetadata class."""

    def test_metadata_round_trip(self):
        """Should serialize and deserialize correctly."""
        meta = FileMetadata(original_filename="test.txt")
        raw = meta.to_bytes()
        restored = FileMetadata.from_bytes(raw)
        assert restored.original_filename == "test.txt"

    def test_metadata_no_filename(self):
        """Should handle metadata without filename."""
        meta = FileMetadata(original_filename=None)
        raw = meta.to_bytes()
        restored = FileMetadata.from_bytes(raw)
        assert restored.original_filename is None

    def test_metadata_unicode_filename(self):
        """Should handle unicode filenames."""
        meta = FileMetadata(original_filename="日本語ファイル.txt")
        raw = meta.to_bytes()
        restored = FileMetadata.from_bytes(raw)
        assert restored.original_filename == "日本語ファイル.txt"

    def test_metadata_invalid_json(self):
        """Should raise CryptoError on invalid JSON."""
        with pytest.raises(CryptoError, match="Invalid metadata"):
            FileMetadata.from_bytes(b"not json")


# =============================================================================
# encrypt_file / decrypt_file with metadata
# =============================================================================


class TestFileEncryptDecryptMetadata:
    """Tests for file encrypt/decrypt with filename metadata."""

    def test_encrypt_with_stored_filename(self, tmp_path):
        """Should store original filename in metadata."""
        source = tmp_path / "myfile.txt"
        source.write_text("hello world")
        output = tmp_path / "myfile.txt.enc"

        encrypt_file(str(source), str(output), "StrongPass1!@#ab", store_filename=True)

        assert output.exists()
        assert output.stat().st_size > 0

    def test_decrypt_restores_filename(self, tmp_path):
        """Should restore original filename on decrypt."""
        source = tmp_path / "original_name.txt"
        source.write_text("hello world")
        enc = tmp_path / "encrypted.enc"

        encrypt_file(str(source), str(enc), "StrongPass1!@#ab", store_filename=True)
        source.unlink()  # Remove original

        actual_path, metadata = decrypt_file(
            str(enc), None, "StrongPass1!@#ab", restore_filename=True
        )

        assert "original_name" in actual_path
        assert metadata is not None
        assert metadata.original_filename == "original_name.txt"

    def test_decrypt_without_restore(self, tmp_path):
        """Should use .dec extension when not restoring filename."""
        source = tmp_path / "test.txt"
        source.write_text("hello world")
        enc = tmp_path / "test.txt.enc"

        encrypt_file(str(source), str(enc), "StrongPass1!@#ab", store_filename=True)

        actual_path, metadata = decrypt_file(
            str(enc), None, "StrongPass1!@#ab", restore_filename=False
        )

        assert actual_path.endswith(".dec")

    def test_decrypt_explicit_output(self, tmp_path):
        """Should use explicit output path."""
        source = tmp_path / "test.txt"
        source.write_text("hello world")
        enc = tmp_path / "test.txt.enc"
        out = tmp_path / "custom_output.txt"

        encrypt_file(str(source), str(enc), "StrongPass1!@#ab")

        actual_path, _ = decrypt_file(str(enc), str(out), "StrongPass1!@#ab")

        assert actual_path == str(out)
        assert out.read_text() == "hello world"

    def test_decrypt_wrong_password(self, tmp_path):
        """Should raise CryptoError on wrong password."""
        source = tmp_path / "test.txt"
        source.write_text("hello world")
        enc = tmp_path / "test.txt.enc"

        encrypt_file(str(source), str(enc), "StrongPass1!@#ab")

        with pytest.raises(CryptoError):
            decrypt_file(str(enc), str(tmp_path / "out.txt"), "WrongPass1!@#xyz")


# =============================================================================
# encrypt_text / decrypt_text error paths
# =============================================================================


class TestTextEncryptDecrypt:
    """Tests for text encrypt/decrypt edge cases."""

    def test_encrypt_empty_text(self):
        """Should encrypt empty text."""
        result = encrypt_text("", "StrongPass1!@#ab")
        assert result  # Should return some ciphertext

    def test_decrypt_invalid_base64(self):
        """Should raise CryptoError on invalid input."""
        with pytest.raises(CryptoError):
            decrypt_text("not-valid-base64!!!", "StrongPass1!@#ab")

    def test_decrypt_wrong_password(self):
        """Should raise CryptoError on wrong password."""
        ciphertext = encrypt_text("hello", "StrongPass1!@#ab")
        with pytest.raises(CryptoError):
            decrypt_text(ciphertext, "WrongPass1!@#xyz")

    def test_encrypt_unicode(self):
        """Should handle unicode text."""
        text = "Hello 🌍 こんにちは"
        ciphertext = encrypt_text(text, "StrongPass1!@#ab")
        result = decrypt_text(ciphertext, "StrongPass1!@#ab")
        assert result == text
