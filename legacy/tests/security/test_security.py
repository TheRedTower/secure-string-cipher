"""
Tests for security utilities (filename sanitization, secure atomic writes).
"""

import os
from contextlib import suppress
from pathlib import Path
from unittest.mock import patch

import pytest

import secure_string_cipher.security as security_module

SecurityError = security_module.SecurityError
sanitize_filename = security_module.sanitize_filename
secure_atomic_write = security_module.secure_atomic_write


class TestFilenameSanitization:
    """Test filename sanitization security."""

    def test_safe_filename_unchanged(self):
        """Test that already safe filenames pass through unchanged."""
        safe_names = [
            "document.pdf",
            "my-file.txt",
            "test_data.csv",
            "report-2024.xlsx",
            "file123.doc",
        ]
        for name in safe_names:
            assert sanitize_filename(name) == name

    def test_path_traversal_basic(self):
        """Path traversal attempts should extract only the final filename component."""
        # ../../../etc/passwd should become just "passwd" (most secure - removes all path parts)
        assert sanitize_filename("../../../etc/passwd") == "passwd"

    def test_path_traversal_mixed(self):
        """Mixed path separators and . should be handled."""
        # ../folder/./file.txt should become just "file.txt"
        assert sanitize_filename("../folder/./file.txt") == "file.txt"

    def test_absolute_paths(self):
        """Absolute paths should extract only the final component."""
        # /etc/passwd should become just "passwd"
        assert sanitize_filename("/etc/passwd") == "passwd"
        # C:\Windows\System32\config should become just "config"
        assert sanitize_filename("C:\\Windows\\System32\\config") == "config"
        assert sanitize_filename("/home/user/.ssh/id_rsa") == "id_rsa"

    def test_hidden_files_exposed(self):
        """Test hidden files (leading dots) are made visible."""
        assert not sanitize_filename(".hidden").startswith(".")
        assert not sanitize_filename("..secret").startswith(".")
        assert not sanitize_filename("...config").startswith(".")
        assert sanitize_filename(".bashrc") == "bashrc"

    def test_unicode_normalization(self):
        """Test Unicode characters are normalized."""
        # Right-to-left override
        result = sanitize_filename("file\u202etxt.exe")
        assert "\u202e" not in result

        # Zero-width characters
        result = sanitize_filename("file\u200b.txt")
        assert "\u200b" not in result

    def test_control_characters_removed(self):
        """Test control characters are stripped."""
        assert "\x00" not in sanitize_filename("file\x00.txt")
        assert "\r" not in sanitize_filename("file\r\n.txt")
        assert "\t" not in sanitize_filename("file\t.txt")

    def test_special_characters_replaced(self):
        """Special characters should be replaced with underscores, consecutive ones collapsed."""
        # Each special char becomes _, but consecutive _ are collapsed to one
        assert sanitize_filename("file<>name.txt") == "file_name.txt"
        assert sanitize_filename("file|name.txt") == "file_name.txt"

    def test_spaces_replaced(self):
        """Spaces should be replaced with underscores, leading/trailing trimmed."""
        # Multiple spaces collapse to _, leading/trailing _ are removed
        assert sanitize_filename("  spaced  file  .txt") == "spaced_file_.txt"
        assert sanitize_filename("my file.txt") == "my_file.txt"

    def test_length_limiting(self):
        """Test overly long filenames are truncated."""
        # Create a filename longer than 255 characters
        long_name = "a" * 300 + ".txt"
        result = sanitize_filename(long_name)
        assert len(result) <= 255
        assert result.endswith(".txt")  # Extension preserved

    def test_length_limiting_with_extension(self):
        """Test long filenames preserve extension."""
        long_name = "a" * 300 + ".encrypted.backup.txt"
        result = sanitize_filename(long_name)
        assert len(result) <= 255
        assert result.endswith(".encrypted.backup.txt") or result.endswith(".txt")

    def test_empty_filename_fallback(self):
        """Test empty or invalid filenames get default."""
        assert sanitize_filename("") == "decrypted_file"
        assert sanitize_filename("...") == "decrypted_file"
        assert sanitize_filename("___") == "decrypted_file"
        assert sanitize_filename("   ") == "decrypted_file"

    def test_only_special_characters(self):
        """Test filename with only special characters."""
        assert sanitize_filename("***???") == "decrypted_file"
        assert sanitize_filename("<<<>>>") == "decrypted_file"

    @pytest.mark.parametrize(
        ("filename", "expected"),
        [
            ("CON", "_CON"),
            ("nul.txt", "_nul.txt"),
            ("COM1.log", "_COM1.log"),
            ("LPT9.", "_LPT9"),
            ("report.", "report"),
        ],
    )
    def test_windows_device_and_trailing_dot_aliases_are_portable(
        self, filename, expected
    ):
        """Automatic destinations must not resolve to Windows device aliases."""
        assert sanitize_filename(filename) == expected

    def test_realistic_attacks(self):
        """Test realistic attack patterns."""
        # SSH key theft attempt
        assert "ssh" not in sanitize_filename("../../../../.ssh/authorized_keys")

        # System file overwrite
        assert sanitize_filename("../../../etc/passwd") == "passwd"

        # Windows system file
        result = sanitize_filename("..\\..\\..\\Windows\\System32\\config\\SAM")
        assert not result.startswith("..")
        assert "\\" not in result

    def test_mixed_safe_unsafe(self):
        """Test filenames with mix of safe and unsafe chars."""
        assert sanitize_filename("my-file_v2.1.txt") == "my-file_v2.1.txt"
        assert sanitize_filename("my@file#v2!.txt") == "my_file_v2_.txt"

    def test_extension_preservation(self):
        """Test file extensions are preserved correctly."""
        assert sanitize_filename("test.pdf").endswith(".pdf")
        assert sanitize_filename("archive.tar.gz").endswith(
            ".tar.gz"
        ) or sanitize_filename("archive.tar.gz").endswith(".gz")
        assert sanitize_filename("backup.enc").endswith(".enc")


class TestSecurityErrorException:
    """Test SecurityError exception."""

    def test_security_error_is_exception(self):
        """Test SecurityError is an Exception."""
        assert issubclass(SecurityError, Exception)

    def test_security_error_can_be_raised(self):
        """Test SecurityError can be raised and caught."""
        error = SecurityError("Test error")
        assert "Test error" in str(error)
        with pytest.raises(SecurityError, match="Test error"):
            raise error


class TestSecureAtomicWrite:
    """Test secure atomic write operations."""

    def test_secure_atomic_write_basic(self, tmp_path):
        """Test basic atomic write operation."""
        dest = tmp_path / "test.txt"
        content = b"secret content"

        secure_atomic_write(dest, content)

        # Check file exists and has correct content
        assert dest.exists()
        assert dest.read_bytes() == content

        # Check permissions are 0o600
        stat_info = os.stat(dest)
        perms = stat_info.st_mode & 0o777
        assert perms == 0o600

    def test_secure_atomic_write_rejects_permissive_permissions(self, tmp_path):
        """Secure atomic writes must remain owner-only."""
        dest = tmp_path / "test.txt"
        content = b"data"

        with pytest.raises(SecurityError, match="owner-only"):
            secure_atomic_write(dest, content, mode=0o644)
        assert not dest.exists()

    def test_secure_atomic_write_overwrite_existing(self, tmp_path):
        """Test atomic write overwrites existing file."""
        dest = tmp_path / "test.txt"

        # Write initial content
        dest.write_bytes(b"old content")

        # Overwrite with new content
        new_content = b"new content"
        secure_atomic_write(dest, new_content)

        # Check content was updated
        assert dest.read_bytes() == new_content

    def test_secure_atomic_write_nonexistent_directory(self, tmp_path):
        """Test error when parent directory doesn't exist."""
        dest = tmp_path / "nonexistent" / "test.txt"

        with pytest.raises(SecurityError, match="does not exist"):
            secure_atomic_write(dest, b"data")

    def test_secure_atomic_write_unwritable_directory(self, tmp_path, monkeypatch):
        """Test error when parent directory is not writable.

        Uses a monkeypatched os.access result so the logic holds even when
        running as root inside locked-down CI containers.
        """
        # Create a read-only directory
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()

        # Try to make directory read-only
        try:
            readonly_dir.chmod(0o444)
        except (OSError, PermissionError):
            pytest.skip("Environment does not support chmod on directories")

        original_access = security_module.os.access

        def _fake_access(path, mode):
            if Path(path) == readonly_dir:
                return False
            return original_access(path, mode)

        monkeypatch.setattr(security_module.os, "access", _fake_access)

        try:
            with pytest.raises(SecurityError, match="not writable"):
                secure_atomic_write(readonly_dir / "test.txt", b"data")
        finally:
            with suppress(OSError, PermissionError):
                readonly_dir.chmod(0o755)

    def test_secure_atomic_write_preserves_on_failure(self, tmp_path):
        """Test that existing file is preserved if write fails."""
        dest = tmp_path / "test.txt"
        original_content = b"original"

        # Write initial content
        dest.write_bytes(original_content)

        # Fail before publication after all content has been buffered.
        with patch(
            "secure_string_cipher.atomic_io.os.fsync",
            side_effect=OSError("Disk full"),
        ):
            with pytest.raises(SecurityError):
                secure_atomic_write(dest, b"new content")

        # Original file should still exist with original content
        assert dest.exists()
        assert dest.read_bytes() == original_content

    def test_secure_atomic_write_large_content(self, tmp_path):
        """Test atomic write with large content."""
        dest = tmp_path / "large.bin"
        # Create 1MB of data
        large_content = b"X" * (1024 * 1024)

        secure_atomic_write(dest, large_content)

        assert dest.exists()
        assert dest.read_bytes() == large_content
        assert len(dest.read_bytes()) == 1024 * 1024

    def test_secure_atomic_write_empty_content(self, tmp_path):
        """Test atomic write with empty content."""
        dest = tmp_path / "empty.txt"

        secure_atomic_write(dest, b"")

        assert dest.exists()
        assert dest.read_bytes() == b""
        assert dest.stat().st_size == 0
