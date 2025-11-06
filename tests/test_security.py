"""
Tests for security utilities (filename sanitization).
"""

import pytest
from secure_string_cipher.security import (
    sanitize_filename,
    validate_filename_safety,
    SecurityError,
)


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
        assert not sanitize_filename(".hidden").startswith('.')
        assert not sanitize_filename("..secret").startswith('.')
        assert not sanitize_filename("...config").startswith('.')
        assert sanitize_filename(".bashrc") == "bashrc"
    
    def test_unicode_normalization(self):
        """Test Unicode characters are normalized."""
        # Right-to-left override
        result = sanitize_filename("file\u202etxt.exe")
        assert '\u202e' not in result
        
        # Zero-width characters
        result = sanitize_filename("file\u200b.txt")
        assert '\u200b' not in result
    
    def test_control_characters_removed(self):
        """Test control characters are stripped."""
        assert '\x00' not in sanitize_filename("file\x00.txt")
        assert '\r' not in sanitize_filename("file\r\n.txt")
        assert '\t' not in sanitize_filename("file\t.txt")
    
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
    
    def test_realistic_attacks(self):
        """Test realistic attack patterns."""
        # SSH key theft attempt
        assert "ssh" not in sanitize_filename("../../../../.ssh/authorized_keys")
        
        # System file overwrite
        assert "passwd" == sanitize_filename("../../../etc/passwd")
        
        # Windows system file
        result = sanitize_filename("..\\..\\..\\Windows\\System32\\config\\SAM")
        assert not result.startswith('..')
        assert '\\' not in result
    
    def test_mixed_safe_unsafe(self):
        """Test filenames with mix of safe and unsafe chars."""
        assert sanitize_filename("my-file_v2.1.txt") == "my-file_v2.1.txt"
        assert sanitize_filename("my@file#v2!.txt") == "my_file_v2_.txt"
    
    def test_extension_preservation(self):
        """Test file extensions are preserved correctly."""
        assert sanitize_filename("test.pdf").endswith(".pdf")
        assert sanitize_filename("archive.tar.gz").endswith(".tar.gz") or \
               sanitize_filename("archive.tar.gz").endswith(".gz")
        assert sanitize_filename("backup.enc").endswith(".enc")


class TestFilenameSafetyValidation:
    """Test filename safety validation warnings."""
    
    def test_safe_filename_no_warning(self):
        """Test safe filename returns no warning."""
        filename = "document.pdf"
        sanitized = sanitize_filename(filename)
        warning = validate_filename_safety(filename, sanitized)
        assert warning is None
    
    def test_unsafe_filename_returns_warning(self):
        """Test unsafe filename returns warning message."""
        filename = "../../../etc/passwd"
        sanitized = sanitize_filename(filename)
        warning = validate_filename_safety(filename, sanitized)
        assert warning is not None
        assert "sanitized" in warning.lower()
        assert filename in warning
        assert sanitized in warning
    
    def test_warning_contains_reason(self):
        """Test warning explains why sanitization occurred."""
        filename = ".hidden/../../secret.txt"
        sanitized = sanitize_filename(filename)
        warning = validate_filename_safety(filename, sanitized)
        assert "unsafe" in warning.lower() or "security" in warning.lower()


class TestSecurityErrorException:
    """Test SecurityError exception."""
    
    def test_security_error_is_exception(self):
        """Test SecurityError is an Exception."""
        assert issubclass(SecurityError, Exception)
    
    def test_security_error_can_be_raised(self):
        """Test SecurityError can be raised and caught."""
        with pytest.raises(SecurityError) as exc_info:
            raise SecurityError("Test error")
        assert "Test error" in str(exc_info.value)
