"""
Test data factories for generating test fixtures.
"""

import secrets
import string
from pathlib import Path
from typing import Any


class PassphraseFactory:
    """Factory for generating test passphrases."""

    @staticmethod
    def create_simple(length: int = 20) -> str:
        """Create a simple alphanumeric passphrase."""
        return "".join(
            secrets.choice(string.ascii_letters + string.digits) for _ in range(length)
        )

    @staticmethod
    def create_complex(length: int = 30) -> str:
        """Create a complex passphrase with special characters."""
        chars = string.ascii_letters + string.digits + string.punctuation
        return "".join(secrets.choice(chars) for _ in range(length))

    @staticmethod
    def create_weak() -> str:
        """Create a weak passphrase for testing validation."""
        return "password123"

    @staticmethod
    def create_unicode() -> str:
        """Create a passphrase with unicode characters."""
        return "Test™️Pässwörd🔒2024"


class FileFactory:
    """Factory for generating test files."""

    @staticmethod
    def create_text_file(
        directory: Path, name: str = "test.txt", content: str = "test content"
    ) -> Path:
        """Create a text file with content."""
        file_path = directory / name
        file_path.write_text(content)
        return file_path

    @staticmethod
    def create_binary_file(
        directory: Path, name: str = "test.bin", size: int = 1024
    ) -> Path:
        """Create a binary file with random content."""
        file_path = directory / name
        file_path.write_bytes(secrets.token_bytes(size))
        return file_path

    @staticmethod
    def create_encrypted_file(directory: Path, name: str = "test.enc") -> Path:
        """Create a mock encrypted file."""
        file_path = directory / name
        # Simulate encrypted content
        file_path.write_bytes(b"ENCRYPTED:" + secrets.token_bytes(256))
        return file_path

    @staticmethod
    def create_large_file(
        directory: Path, name: str = "large.txt", mb_size: int = 1
    ) -> Path:
        """Create a large file for performance testing."""
        file_path = directory / name
        chunk_size = 1024 * 1024  # 1MB chunks
        with open(file_path, "wb") as f:
            for _ in range(mb_size):
                f.write(b"X" * chunk_size)
        return file_path


class VaultFactory:
    """Factory for generating test vault data."""

    @staticmethod
    def create_empty_vault() -> dict[str, str]:
        """Create an empty vault structure."""
        return {}

    @staticmethod
    def create_vault_with_entries(count: int = 3) -> dict[str, str]:
        """Create a vault with test entries."""
        return {
            f"test_key_{i}": f"test_value_{i}_" + PassphraseFactory.create_simple(10)
            for i in range(count)
        }

    @staticmethod
    def create_vault_entry(
        key: str | None = None, value: str | None = None
    ) -> tuple[str, str]:
        """Create a single vault entry."""
        if key is None:
            key = f"key_{secrets.token_hex(4)}"
        if value is None:
            value = PassphraseFactory.create_complex(20)
        return key, value


class ErrorFactory:
    """Factory for generating test error scenarios."""

    @staticmethod
    def create_permission_error(path: str = "/test/path") -> PermissionError:
        """Create a permission error."""
        return PermissionError(f"Permission denied: {path}")

    @staticmethod
    def create_file_not_found_error(
        path: str = "/test/missing.txt",
    ) -> FileNotFoundError:
        """Create a file not found error."""
        return FileNotFoundError(f"File not found: {path}")

    @staticmethod
    def create_value_error(message: str = "Invalid value") -> ValueError:
        """Create a value error."""
        return ValueError(message)


class ConfigFactory:
    """Factory for generating test configurations."""

    @staticmethod
    def create_default_config() -> dict[str, Any]:
        """Create a default test configuration."""
        return {
            "vault_path": "~/.local/share/secure-string-cipher/vault.json",
            "key_iterations": 100000,
            "salt_size": 32,
            "timeout": 30,
        }

    @staticmethod
    def create_custom_config(**kwargs: Any) -> dict[str, Any]:
        """Create a custom configuration with overrides."""
        config = ConfigFactory.create_default_config()
        config.update(kwargs)
        return config


class CipherFactory:
    """Factory for generating test cipher data."""

    @staticmethod
    def create_test_data(size: int = 100) -> bytes:
        """Create test data for encryption."""
        return secrets.token_bytes(size)

    @staticmethod
    def create_test_string(length: int = 50) -> str:
        """Create a test string for encryption."""
        return "".join(
            secrets.choice(string.ascii_letters + string.digits + " ")
            for _ in range(length)
        )

    @staticmethod
    def create_unicode_string() -> str:
        """Create a unicode test string."""
        return "Hello 世界 🌍 Ñoño Café"
