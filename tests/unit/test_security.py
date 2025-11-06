"""
Tests for security utilities (filename sanitization, path validation, symlink detection, privilege checking).
"""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from secure_string_cipher.security import (
    SecurityError,
    check_elevated_privileges,
    check_sensitive_directory,
    create_secure_temp_file,
    detect_symlink,
    sanitize_filename,
    secure_atomic_write,
    validate_execution_context,
    validate_filename_safety,
    validate_output_path,
    validate_safe_path,
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


class TestPathValidation:
    """Test path validation security."""

    def test_safe_path_within_allowed_dir(self, tmp_path):
        """Test that paths within allowed directory are accepted."""
        allowed_dir = tmp_path
        safe_file = allowed_dir / "safe.txt"
        safe_file.touch()

        assert validate_safe_path(safe_file, allowed_dir) is True

    def test_safe_path_subdirectory(self, tmp_path):
        """Test that paths in subdirectories are accepted."""
        allowed_dir = tmp_path
        subdir = allowed_dir / "subdir"
        subdir.mkdir()
        safe_file = subdir / "file.txt"
        safe_file.touch()

        assert validate_safe_path(safe_file, allowed_dir) is True

    def test_path_traversal_outside_directory(self, tmp_path):
        """Test that path traversal attempts are blocked."""
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()

        # Try to escape to parent
        dangerous_path = allowed_dir / ".." / "escaped.txt"

        with pytest.raises(SecurityError) as exc_info:
            validate_safe_path(dangerous_path, allowed_dir)
        assert "Path traversal detected" in str(exc_info.value)
        assert "outside allowed directory" in str(exc_info.value)

    def test_absolute_path_outside_allowed(self, tmp_path):
        """Test that absolute paths outside allowed dir are blocked."""
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()

        # Try to access /etc/passwd
        if os.name != "nt":  # Unix-like systems
            with pytest.raises(SecurityError) as exc_info:
                validate_safe_path("/etc/passwd", allowed_dir)
            assert "Path traversal detected" in str(exc_info.value)

    def test_path_validation_with_cwd_default(self, tmp_path):
        """Test that validation defaults to current working directory."""
        original_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)
            safe_file = tmp_path / "file.txt"
            safe_file.touch()

            # Should accept file in cwd when no allowed_dir specified
            assert validate_safe_path(safe_file) is True
        finally:
            os.chdir(original_cwd)

    def test_relative_path_resolution(self, tmp_path):
        """Test that relative paths are resolved correctly."""
        allowed_dir = tmp_path

        # Create nested structure
        subdir = allowed_dir / "sub"
        subdir.mkdir()
        file_path = subdir / "file.txt"
        file_path.touch()

        # Test with relative path containing ./
        relative_path = allowed_dir / "sub" / "." / "file.txt"
        assert validate_safe_path(relative_path, allowed_dir) is True


class TestSymlinkDetection:
    """Test symlink attack detection."""

    def test_regular_file_no_symlink(self, tmp_path):
        """Test that regular files pass symlink check."""
        regular_file = tmp_path / "regular.txt"
        regular_file.touch()

        assert detect_symlink(regular_file) is True

    def test_symlink_detected_and_blocked(self, tmp_path):
        """Test that symlinks are detected and blocked by default."""
        target = tmp_path / "target.txt"
        target.write_text("sensitive data")

        link = tmp_path / "link.txt"
        link.symlink_to(target)

        with pytest.raises(SecurityError) as exc_info:
            detect_symlink(link)
        assert "Symlink detected" in str(exc_info.value)
        assert "symbolic link" in str(exc_info.value)

    def test_symlink_to_outside_directory_blocked(self, tmp_path):
        """Test that symlinks pointing outside cwd are blocked."""
        original_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)

            # Create symlink pointing outside tmp_path
            outside_target = tmp_path.parent / "outside.txt"
            outside_target.touch()

            link = tmp_path / "dangerous_link.txt"
            link.symlink_to(outside_target)

            with pytest.raises(SecurityError) as exc_info:
                detect_symlink(link, follow_links=True)
            assert "Symlink attack detected" in str(exc_info.value)
            assert "outside the current directory" in str(exc_info.value)
        finally:
            os.chdir(original_cwd)

    def test_symlink_within_cwd_allowed_when_following(self, tmp_path):
        """Test that symlinks within cwd are allowed when follow_links=True."""
        original_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)

            target = tmp_path / "target.txt"
            target.write_text("data")

            link = tmp_path / "link.txt"
            link.symlink_to(target)

            # Should be allowed when following links and target is within cwd
            assert detect_symlink(link, follow_links=True) is True
        finally:
            os.chdir(original_cwd)

    def test_symlink_in_parent_path_detected(self, tmp_path):
        """Test that symlinks in parent directories are detected."""
        original_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)

            # Create symlinked directory
            real_dir = tmp_path / "real_dir"
            real_dir.mkdir()

            link_dir = tmp_path / "link_dir"
            link_dir.symlink_to(real_dir)

            # File inside symlinked directory
            file_in_link = link_dir / "file.txt"

            with pytest.raises(SecurityError) as exc_info:
                detect_symlink(file_in_link, follow_links=False)
            assert "Symlink in path detected" in str(exc_info.value)
        finally:
            os.chdir(original_cwd)

    def test_nonexistent_file_no_error(self, tmp_path):
        """Test that checking nonexistent files doesn't raise errors."""
        nonexistent = tmp_path / "does_not_exist.txt"

        # Should not raise - file doesn't exist yet (for output paths)
        # The is_symlink() check returns False for nonexistent paths
        assert detect_symlink(nonexistent) is True


class TestValidateOutputPath:
    """Test comprehensive output path validation."""

    def test_valid_output_path(self, tmp_path):
        """Test that valid output paths are accepted."""
        original_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)

            output = validate_output_path("output.txt")

            assert output.name == "output.txt"
            assert output.parent == tmp_path
        finally:
            os.chdir(original_cwd)

    def test_output_path_sanitizes_filename(self, tmp_path):
        """Test that output path sanitizes the filename."""
        original_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)

            # Filename with unsafe characters
            output = validate_output_path("file<>name.txt")

            assert output.name == "file_name.txt"  # Sanitized
        finally:
            os.chdir(original_cwd)

    def test_output_path_blocks_traversal(self, tmp_path):
        """Test that output path blocks directory traversal."""
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()

        with pytest.raises(SecurityError) as exc_info:
            validate_output_path("../escaped.txt", allowed_dir=allowed_dir)
        assert "Path traversal detected" in str(exc_info.value)

    def test_output_path_blocks_symlinks(self, tmp_path):
        """Test that output path blocks symlinks by default."""
        original_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)

            target = tmp_path / "target.txt"
            target.touch()

            link = tmp_path / "link.txt"
            link.symlink_to(target)

            with pytest.raises(SecurityError):
                validate_output_path(link)
        finally:
            os.chdir(original_cwd)

    def test_output_path_allows_symlinks_when_enabled(self, tmp_path):
        """Test that symlinks can be allowed with flag."""
        original_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)

            target = tmp_path / "target.txt"
            target.touch()

            link = tmp_path / "link.txt"
            link.symlink_to(target)

            # Should succeed with allow_symlinks=True
            output = validate_output_path(link, allow_symlinks=True)
            assert output.resolve() == link.resolve()
        finally:
            os.chdir(original_cwd)

    def test_output_path_with_subdirectory(self, tmp_path):
        """Test output path in subdirectory."""
        original_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)

            subdir = tmp_path / "subdir"
            subdir.mkdir()

            output = validate_output_path("subdir/output.txt")

            assert output.name == "output.txt"
            assert output.parent == subdir
        finally:
            os.chdir(original_cwd)


class TestPrivilegeChecking:
    """Test privilege and execution context validation."""

    def test_check_elevated_privileges_normal_user(self):
        """Test that normal users are not flagged as elevated."""
        # Mock os.geteuid to return non-zero (normal user)
        with patch("os.geteuid", return_value=1000):
            assert check_elevated_privileges() is False

    def test_check_elevated_privileges_root(self):
        """Test that root user is detected."""
        # Mock os.geteuid to return 0 (root)
        with patch("os.geteuid", return_value=0):
            assert check_elevated_privileges() is True

    def test_check_elevated_privileges_no_geteuid(self):
        """Test fallback when os.geteuid doesn't exist."""
        # Mock a system without geteuid (like Windows without admin check)
        original_hasattr = hasattr

        def mock_hasattr(obj, name):
            if obj is os and name == "geteuid":
                return False
            return original_hasattr(obj, name)

        with patch("builtins.hasattr", side_effect=mock_hasattr):
            # Should return False on unknown systems
            result = check_elevated_privileges()
            assert result is False

    def test_check_sensitive_directory_safe_location(self, tmp_path):
        """Test that safe directories pass the check."""
        original_cwd = Path.cwd()
        try:
            # tmp_path is not a sensitive directory
            os.chdir(tmp_path)
            assert check_sensitive_directory() is None
        finally:
            os.chdir(original_cwd)

    def test_check_sensitive_directory_etc(self):
        """Test that /etc is detected as sensitive."""
        # Mock cwd to return /etc
        with patch("pathlib.Path.cwd", return_value=Path("/etc")):
            warning = check_sensitive_directory()
            assert warning is not None
            assert "/etc" in warning
            assert "sensitive directory" in warning.lower()

    def test_check_sensitive_directory_ssh(self):
        """Test that ~/.ssh is detected as sensitive."""
        ssh_path = Path.home() / ".ssh"

        # Mock cwd to return ~/.ssh
        with patch("pathlib.Path.cwd", return_value=ssh_path):
            warning = check_sensitive_directory()
            assert warning is not None
            assert ".ssh" in warning
            assert "sensitive directory" in warning.lower()

    def test_check_sensitive_directory_subdirectory(self):
        """Test that subdirectories of sensitive paths are detected."""
        etc_sub = Path("/etc/systemd")

        # Mock cwd to return /etc/systemd
        with patch("pathlib.Path.cwd", return_value=etc_sub):
            warning = check_sensitive_directory()
            assert warning is not None
            assert "sensitive directory" in warning.lower()

    def test_validate_execution_context_safe(self, tmp_path):
        """Test that safe execution context passes validation."""
        original_cwd = Path.cwd()
        try:
            os.chdir(tmp_path)

            # Mock non-root user
            with patch("os.geteuid", return_value=1000):
                assert validate_execution_context(exit_on_error=False) is True
        finally:
            os.chdir(original_cwd)

    def test_validate_execution_context_root_raises_error(self):
        """Test that root execution raises SecurityError."""
        # Mock root user
        with patch("os.geteuid", return_value=0):
            with pytest.raises(SecurityError) as exc_info:
                validate_execution_context(exit_on_error=False)

            error_msg = str(exc_info.value)
            assert "elevated privileges" in error_msg.lower()
            assert "root" in error_msg.lower() or "sudo" in error_msg.lower()

    def test_validate_execution_context_root_exits(self, capsys):
        """Test that root execution exits when exit_on_error=True."""
        # Mock root user
        with patch("os.geteuid", return_value=0):
            with pytest.raises(SystemExit) as exc_info:
                validate_execution_context(exit_on_error=True)

            assert exc_info.value.code == 1

            # Check that error was printed to stderr
            captured = capsys.readouterr()
            assert "elevated privileges" in captured.err.lower()

    def test_validate_execution_context_sensitive_dir_raises(self):
        """Test that sensitive directory raises SecurityError."""
        # Mock cwd to /etc
        with patch("pathlib.Path.cwd", return_value=Path("/etc")):
            # Mock non-root user so only directory check fails
            with patch("os.geteuid", return_value=1000):
                with pytest.raises(SecurityError) as exc_info:
                    validate_execution_context(exit_on_error=False)

                error_msg = str(exc_info.value)
                assert "sensitive directory" in error_msg.lower()
                assert "/etc" in error_msg

    def test_validate_execution_context_multiple_errors(self):
        """Test that multiple security violations are reported together."""
        # Mock root user AND sensitive directory
        with patch("os.geteuid", return_value=0):
            with patch("pathlib.Path.cwd", return_value=Path("/etc")):
                with pytest.raises(SecurityError) as exc_info:
                    validate_execution_context(exit_on_error=False)

            error_msg = str(exc_info.value)
            # Should contain both errors
            assert "elevated privileges" in error_msg.lower()
            assert "sensitive directory" in error_msg.lower()


class TestSecureTempFile:
    """Test secure temporary file creation."""

    def test_create_secure_temp_file_basic(self, tmp_path):
        """Test basic secure temp file creation."""
        with create_secure_temp_file(directory=tmp_path) as (fd, path):
            # Check that file descriptor is valid
            assert isinstance(fd, int)
            assert fd > 0

            # Check that path exists
            assert os.path.exists(path)

            # Check permissions are 0o600 (owner read/write only)
            stat_info = os.stat(path)
            perms = stat_info.st_mode & 0o777
            assert perms == 0o600

            # Write some data
            os.write(fd, b"secret data")

        # After context exit, file should be deleted
        assert not os.path.exists(path)

    def test_create_secure_temp_file_custom_prefix_suffix(self, tmp_path):
        """Test temp file with custom prefix and suffix."""
        with create_secure_temp_file(
            prefix="test_", suffix=".secret", directory=tmp_path
        ) as (fd, path):
            filename = os.path.basename(path)
            assert filename.startswith("test_")
            assert filename.endswith(".secret")

    def test_create_secure_temp_file_cleanup_on_exception(self, tmp_path):
        """Test that temp file is cleaned up even if exception occurs."""
        temp_path = None
        try:
            with create_secure_temp_file(directory=tmp_path) as (fd, path):
                temp_path = path
                # Simulate an error
                raise ValueError("Test error")
        except ValueError:
            pass

        # File should still be cleaned up
        assert temp_path is not None
        assert not os.path.exists(temp_path)

    def test_create_secure_temp_file_invalid_directory(self):
        """Test error when directory doesn't exist."""
        with pytest.raises(SecurityError, match="does not exist"):
            with create_secure_temp_file(directory="/nonexistent/path"):
                pass

    def test_create_secure_temp_file_unwritable_directory(self, tmp_path):
        """Test error when directory is not writable."""
        # Create a directory and make it read-only
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o444)

        try:
            with pytest.raises(SecurityError, match="not writable"):
                with create_secure_temp_file(directory=readonly_dir):
                    pass
        finally:
            # Restore permissions for cleanup
            readonly_dir.chmod(0o755)

    def test_create_secure_temp_file_write_and_read(self, tmp_path):
        """Test writing and reading from secure temp file."""
        test_data = b"sensitive information"

        with create_secure_temp_file(directory=tmp_path) as (fd, path):
            # Write data
            os.write(fd, test_data)

            # Close the fd and reopen for reading to verify
            os.close(fd)

            with open(path, "rb") as f:
                read_data = f.read()
                assert read_data == test_data


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

    def test_secure_atomic_write_custom_permissions(self, tmp_path):
        """Test atomic write with custom permissions."""
        dest = tmp_path / "test.txt"
        content = b"data"

        secure_atomic_write(dest, content, mode=0o644)

        # Check permissions are 0o644
        stat_info = os.stat(dest)
        perms = stat_info.st_mode & 0o777
        assert perms == 0o644

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

    @pytest.mark.skipif(
        os.getuid() == 0 if hasattr(os, "getuid") else False,
        reason="Cannot test directory permissions as root",
    )
    def test_secure_atomic_write_unwritable_directory(self, tmp_path):
        """Test error when parent directory is not writable.

        Note: This test is skipped in environments where permission restrictions
        don't work (root user, certain CI containers, etc.)
        """
        # Create a read-only directory
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()

        # Try to make directory read-only
        try:
            readonly_dir.chmod(0o444)
        except (OSError, PermissionError):
            pytest.skip("Environment does not support chmod on directories")

        # Verify the directory is actually read-only by checking os.access
        # If os.access still reports writable, skip the test
        if os.access(readonly_dir, os.W_OK):
            readonly_dir.chmod(0o755)  # Restore for cleanup
            pytest.skip("Environment does not respect directory write permissions")

        dest = readonly_dir / "test.txt"

        try:
            with pytest.raises((SecurityError, PermissionError)) as exc_info:
                secure_atomic_write(dest, b"data")

            # We expect either a SecurityError from our check or a PermissionError
            # from the OS if the check wasn't sufficient
            assert (
                "not writable" in str(exc_info.value).lower()
                or "permission denied" in str(exc_info.value).lower()
            )
        finally:
            # Restore permissions for cleanup
            try:
                readonly_dir.chmod(0o755)
            except (OSError, PermissionError):
                pass

    def test_secure_atomic_write_preserves_on_failure(self, tmp_path):
        """Test that existing file is preserved if write fails."""
        dest = tmp_path / "test.txt"
        original_content = b"original"

        # Write initial content
        dest.write_bytes(original_content)

        # Try to write with an error condition
        # We'll mock os.write to raise an exception
        with patch("os.write", side_effect=OSError("Disk full")):
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
