"""
Additional coverage tests for core.py encryption module.

These tests target uncovered code paths to improve overall test coverage.
"""

from io import BytesIO

import pytest

from secure_string_cipher.core import (
    CryptoError,
    FileMetadata,
    StreamProcessor,
    compute_key_commitment,
    decrypt_file,
    decrypt_text,
    derive_key_from_key_file,
    encrypt_file,
    encrypt_text,
    generate_key_pair,
    verify_key_commitment,
)


class TestStreamProcessorInit:
    """Tests for StreamProcessor initialization."""

    def test_stream_processor_with_file_like_object(self):
        """Should accept file-like objects."""
        buffer = BytesIO(b"test data")
        processor = StreamProcessor(buffer, "rb")

        assert processor.path == buffer
        assert processor.mode == "rb"


class TestStreamProcessorOperations:
    """Tests for StreamProcessor read/write operations."""

    def test_stream_processor_read_chunks(self, tmp_path):
        """Should read file in chunks with progress."""
        test_file = tmp_path / "test.bin"
        test_data = b"A" * 10000
        test_file.write_bytes(test_data)

        with StreamProcessor(str(test_file), "rb") as sp:
            data = sp.read(1000)
            assert len(data) == 1000


class TestFileMetadata:
    """Tests for FileMetadata dataclass."""

    def test_metadata_creation(self):
        """Should create metadata with fields."""
        metadata = FileMetadata(
            original_filename="test.txt",
            version=4,
        )

        assert metadata.original_filename == "test.txt"
        assert metadata.version == 4

    def test_metadata_defaults(self):
        """Should have sensible defaults."""
        metadata = FileMetadata()

        assert metadata.original_filename is None
        assert metadata.version == 5
        assert metadata.key_commitment is None


class TestEncryptDecryptText:
    """Tests for text encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Should successfully encrypt and decrypt text."""
        plaintext = "Hello, World!"
        password = "SecurePassword123!@#"  # pragma: allowlist secret

        encrypted = encrypt_text(plaintext, password)
        decrypted = decrypt_text(encrypted, password)

        assert decrypted == plaintext

    def test_encrypt_unicode_text(self):
        """Should handle Unicode text."""
        plaintext = "你好世界 🔐 émoji"
        password = "SecurePassword123!@#"  # pragma: allowlist secret

        encrypted = encrypt_text(plaintext, password)
        decrypted = decrypt_text(encrypted, password)

        assert decrypted == plaintext

    def test_decrypt_wrong_password(self):
        """Should raise error for wrong password."""
        plaintext = "Secret message"
        encrypted = encrypt_text(
            plaintext, "CorrectPassword123!@#"
        )  # pragma: allowlist secret

        with pytest.raises(CryptoError):
            decrypt_text(encrypted, "WrongPassword123!@#")  # pragma: allowlist secret

    def test_decrypt_invalid_ciphertext(self):
        """Should raise error for invalid ciphertext."""
        with pytest.raises(CryptoError):
            decrypt_text(
                "not-valid-base64!", "Password123!@#"
            )  # pragma: allowlist secret


class TestEncryptDecryptFile:
    """Tests for file encryption/decryption."""

    def test_file_encryption_roundtrip(self, tmp_path):
        """Should encrypt and decrypt file."""
        original = tmp_path / "original.txt"
        encrypted = tmp_path / "encrypted.enc"
        decrypted = tmp_path / "decrypted.txt"

        original.write_text("Test file content")
        password = "SecurePassword123!@#"  # pragma: allowlist secret

        encrypt_file(str(original), str(encrypted), password)
        decrypt_file(str(encrypted), str(decrypted), password)

        assert decrypted.read_text() == "Test file content"

    def test_encrypt_nonexistent_file(self, tmp_path):
        """Should raise error for nonexistent input file."""
        nonexistent = tmp_path / "nofile.txt"

        with pytest.raises(CryptoError):
            encrypt_file(
                str(nonexistent), "out.enc", "Password123!@#"
            )  # pragma: allowlist secret

    def test_encrypt_rejects_symlink_input(self, tmp_path):
        """Should reject symlinked input paths."""

        real_file = tmp_path / "real.txt"
        real_file.write_text("secret")
        symlink_file = tmp_path / "link.txt"
        symlink_file.symlink_to(real_file)

        output = tmp_path / "out.enc"

        with pytest.raises(CryptoError, match="symlinked input path"):
            encrypt_file(str(symlink_file), str(output), "Password123!@#")

    def test_encrypt_rejects_symlink_output(self, tmp_path):
        """Should reject symlinked output paths."""

        input_file = tmp_path / "input.txt"
        input_file.write_text("data")

        real_output = tmp_path / "real_out.enc"
        real_output.touch()
        symlink_output = tmp_path / "out.enc"
        symlink_output.symlink_to(real_output)

        with pytest.raises(CryptoError, match="symlinked output path"):
            encrypt_file(str(input_file), str(symlink_output), "Password123!@#")

    def test_encrypt_rejects_symlink_parent_directory(self, tmp_path):
        """Should reject outputs under symlinked parent directories."""

        real_dir = tmp_path / "real_dir"
        real_dir.mkdir()
        symlink_dir = tmp_path / "link_dir"
        symlink_dir.symlink_to(real_dir, target_is_directory=True)

        input_file = real_dir / "input.txt"
        input_file.write_text("payload")

        output_path = symlink_dir / "out.enc"

        with pytest.raises(CryptoError, match="symlinked output path"):
            encrypt_file(str(input_file), str(output_path), "Password123!@#")


class TestKeyCommitment:
    """Tests for key commitment verification."""

    def test_compute_key_commitment(self):
        """Should compute consistent key commitment."""
        key = b"0" * 32

        commitment1 = compute_key_commitment(key)
        commitment2 = compute_key_commitment(key)

        # Same key should produce same commitment
        assert commitment1 == commitment2

    def test_verify_key_commitment_valid(self):
        """Should verify valid key commitment."""
        key = b"0" * 32
        commitment = compute_key_commitment(key)

        # Verify should succeed
        assert verify_key_commitment(key, commitment) is True

    def test_verify_key_commitment_invalid(self):
        """Should reject invalid key commitment."""
        key = b"0" * 32
        wrong_commitment = b"x" * 32

        assert verify_key_commitment(key, wrong_commitment) is False

    def test_different_keys_different_commitments(self):
        """Different keys should produce different commitments."""
        key1 = b"A" * 32
        key2 = b"B" * 32

        commitment1 = compute_key_commitment(key1)
        commitment2 = compute_key_commitment(key2)

        assert commitment1 != commitment2


class TestKeyFileAndKeyPairSecurity:
    """Tests for key-file and key-pair path hardening."""

    def test_derive_key_from_key_file_rejects_symlink(self, tmp_path):
        """Should reject symlinked key files."""

        real_key = tmp_path / "real.key"
        real_key.write_bytes(b"key-material")
        symlink_key = tmp_path / "key_link.key"
        symlink_key.symlink_to(real_key)

        with pytest.raises(CryptoError, match="symlinked key file path"):
            derive_key_from_key_file(str(symlink_key), b"salt" * 4)

    def test_generate_key_pair_rejects_symlink_private_path(self, tmp_path):
        """Should reject symlinked private-key output paths."""

        real_private = tmp_path / "real_private.pem"
        real_private.write_text("placeholder")
        symlink_private = tmp_path / "private.pem"
        symlink_private.symlink_to(real_private)

        with pytest.raises(CryptoError, match="symlinked private key path"):
            generate_key_pair(str(symlink_private))

    def test_generate_key_pair_rejects_same_output_path(self, tmp_path):
        """Should reject using the same path for private and public keys."""

        key_path = tmp_path / "id_rsa.pem"

        with pytest.raises(
            CryptoError,
            match="Private and public key paths must be different files",
        ):
            generate_key_pair(str(key_path), str(key_path))
