"""
Security utilities for filename sanitization, path validation, and privilege checking.

This module provides security functions to prevent path traversal attacks,
Unicode exploits, symlink attacks, and unsafe execution contexts.
"""

import contextlib
import os
import re
import shutil
import sys
import tempfile
import unicodedata
from pathlib import Path


class SecurityError(Exception):
    """Raised when a security policy is violated."""

    pass


def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """
    Sanitize filename to prevent security issues.

    Protections:
    - Path traversal attempts (../, /)
    - Unicode attacks (RTL override, homoglyphs)
    - Control characters and null bytes
    - Excessive length
    - Hidden files (leading dots)
    - Special/unsafe characters

    Args:
        filename: Original filename to sanitize
        max_length: Maximum allowed filename length (default 255)

    Returns:
        Sanitized safe filename

    Examples:
        >>> sanitize_filename("../../../etc/passwd")
        'etc_passwd'
        >>> sanitize_filename("file\u202etxt.exe")
        'file_txt.exe'
        >>> sanitize_filename(".hidden")
        'hidden'
    """
    # Normalize Unicode (NFKD decomposition)
    # This prevents homoglyph attacks and normalizes lookalike characters
    filename = unicodedata.normalize("NFKD", filename)

    # Control characters are in category 'C'
    filename = "".join(c for c in filename if unicodedata.category(c)[0] != "C")

    # Normalize path separators (both Unix and Windows)
    filename = filename.replace("\\", "/")

    filename = os.path.basename(filename)

    filename = filename.replace("..", "")

    filename = filename.lstrip(".")

    # Replace unsafe characters with underscores
    filename = re.sub(r"[^a-zA-Z0-9._-]", "_", filename)

    # Collapse multiple consecutive underscores to single underscore
    filename = re.sub(r"_+", "_", filename)

    filename = filename.strip("_")

    if len(filename) > max_length:
        name, ext = os.path.splitext(filename)
        available = max_length - len(ext) - 1
        name = name[:available]
        filename = name + ext

    if not filename:
        filename = "decrypted_file"

    return filename


def validate_filename_safety(original: str, sanitized: str) -> str | None:
    """
    Check if filename was modified during sanitization and return warning.

    Args:
        original: Original filename before sanitization
        sanitized: Filename after sanitization

    Returns:
        Warning message if filename was changed, None otherwise
    """
    if original != sanitized:
        return (
            f"⚠️  Filename was sanitized for security:\n"
            f"   Original:  {original}\n"
            f"   Sanitized: {sanitized}\n"
            f"   Reason: Contains potentially unsafe characters or path components"
        )
    return None


def validate_safe_path(
    file_path: str | Path, allowed_dir: str | Path | None = None
) -> bool:
    """
    Validate that a file path is safe and doesn't escape allowed directory.

    This function prevents directory traversal attacks by ensuring the resolved
    path stays within the allowed directory boundary.

    Args:
        file_path: Path to validate
        allowed_dir: Directory that file_path must be within.
                    If None, uses current working directory.

    Returns:
        True if path is safe, False otherwise

    Raises:
        SecurityError: If path attempts to escape allowed directory

    Examples:
        >>> validate_safe_path("/tmp/safe.txt", "/tmp")
        True
        >>> validate_safe_path("/tmp/../etc/passwd", "/tmp")
        False (raises SecurityError)
    """
    file_path = Path(file_path).resolve()

    allowed_dir = Path.cwd() if allowed_dir is None else Path(allowed_dir).resolve()

    try:
        # Will raise ValueError if file_path is not relative to allowed_dir
        file_path.relative_to(allowed_dir)
        return True
    except ValueError:
        raise SecurityError(
            f"Path traversal detected: '{file_path}' is outside allowed directory '{allowed_dir}'"
        ) from None


def detect_symlink(file_path: str | Path, follow_links: bool = False) -> bool:
    """
    Detect if a path is or contains a symbolic link.

    This prevents symlink attacks where an attacker creates a symlink
    pointing to a sensitive file (e.g., /etc/passwd) and tricks the
    program into overwriting it.

    Args:
        file_path: Path to check for symlinks
        follow_links: If False, raises error on any symlink.
                     If True, only checks if target is outside cwd.

    Returns:
        True if path is safe (no symlinks or acceptable symlink)
        False if symlink detected (when follow_links=False)

    Raises:
        SecurityError: If symlink detected and follow_links=False, or if
                      symlink points outside current working directory

    Examples:
        >>> detect_symlink("/tmp/normal.txt")
        True
        >>> detect_symlink("/tmp/link_to_passwd")  # symlink to /etc/passwd
        False (raises SecurityError)
    """
    file_path = Path(file_path)

    if file_path.is_symlink():
        if not follow_links:
            raise SecurityError(
                f"Symlink detected: '{file_path}' is a symbolic link. "
                f"This could be a symlink attack."
            )

        # If following links, ensure target is within cwd
        try:
            target = file_path.resolve()
            target.relative_to(Path.cwd())
        except (ValueError, OSError):
            raise SecurityError(
                f"Symlink attack detected: '{file_path}' points to '{target}' "
                f"which is outside the current directory"
            ) from None

    for parent in file_path.parents:
        if parent.is_symlink():
            if not follow_links:
                raise SecurityError(
                    f"Symlink in path detected: '{parent}' is a symbolic link"
                )

            try:
                target = parent.resolve()
                target.relative_to(Path.cwd())
            except (ValueError, OSError):
                raise SecurityError(
                    f"Symlink attack in path: '{parent}' points outside current directory"
                ) from None

    return True


def validate_output_path(
    output_path: str | Path,
    allowed_dir: str | Path | None = None,
    allow_symlinks: bool = False,
) -> Path:
    """
    Comprehensive validation for output file paths.

    Combines sanitization, path validation, and symlink detection into
    one convenient function for validating output file paths.

    Args:
        output_path: Path to validate and sanitize
        allowed_dir: Directory that output must be within (default: cwd)
        allow_symlinks: Whether to allow symlinks (default: False)

    Returns:
        Validated and sanitized Path object

    Raises:
        SecurityError: If any security check fails

    Examples:
        >>> validate_output_path("output.txt")
        PosixPath('/current/dir/output.txt')
        >>> validate_output_path("../../../etc/passwd")
        SecurityError: Path traversal detected
    """
    output_path = Path(output_path)

    # Sanitize the filename component
    sanitized_name = sanitize_filename(output_path.name)
    output_path = output_path.parent / sanitized_name

    detect_symlink(output_path, follow_links=allow_symlinks)

    # Validate path doesn't escape allowed directory
    if allowed_dir is None:
        allowed_dir = Path.cwd()

    # Resolve to absolute path
    output_path = output_path.resolve()
    validate_safe_path(output_path, allowed_dir)

    return output_path


def check_elevated_privileges() -> bool:
    """
    Check if the program is running with elevated privileges (root/sudo).

    Returns:
        True if running with elevated privileges, False otherwise

    Examples:
        >>> check_elevated_privileges()  # Normal user
        False
        >>> check_elevated_privileges()  # Running as root
        True
    """
    # Unix-like systems
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0

    # Windows - check for admin privileges
    if sys.platform == "win32":
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError):
            return False

    return False


def check_sensitive_directory() -> str | None:
    """
    Check if running from a sensitive system directory.

    Detects if the current working directory is in a sensitive location
    where cryptographic operations could be dangerous (e.g., /etc, ~/.ssh).

    Returns:
        Warning message if in sensitive directory, None otherwise

    Examples:
        >>> check_sensitive_directory()  # Running from /home/user
        None
        >>> check_sensitive_directory()  # Running from /etc
        '⚠️  Running from sensitive directory: /etc'
    """
    cwd = Path.cwd()

    # Sensitive directories that should not contain encrypted files
    sensitive_paths = [
        "/etc",
        "/bin",
        "/sbin",
        "/boot",
        "/sys",
        "/proc",
        "/dev",
        Path.home() / ".ssh",
        Path.home() / ".gnupg",
    ]

    for sensitive in sensitive_paths:
        try:
            sensitive_path = (
                Path(sensitive) if isinstance(sensitive, str) else Path(str(sensitive))
            )

            # Try to check if cwd is relative to sensitive path
            cwd.resolve().relative_to(sensitive_path.resolve())
            return (
                f"⚠️  Running from sensitive directory: {cwd}\n"
                f"   This directory contains system or security files.\n"
                f"   Consider running from a safer location like ~/Documents or ~/Downloads"
            )
        except (ValueError, OSError):
            # ValueError: not relative to this path
            # OSError: path doesn't exist (can't resolve)
            continue

    return None


def validate_execution_context(exit_on_error: bool = True) -> bool:
    """
    Validate that the execution context is safe for cryptographic operations.

    Checks for:
    - Elevated privileges (root/sudo)
    - Sensitive system directories

    Args:
        exit_on_error: If True, exits the program on security violations.
                      If False, returns False on violations.

    Returns:
        True if execution context is safe, False if unsafe

    Raises:
        SecurityError: If exit_on_error=False and context is unsafe

    Examples:
        >>> validate_execution_context()  # Normal user, safe directory
        True
        >>> validate_execution_context()  # Running as root
        False (exits program or raises SecurityError)
    """
    errors = []

    if check_elevated_privileges():
        errors.append(
            "🚫 SECURITY ERROR: Running with elevated privileges (root/sudo)\n"
            "   This is dangerous and unnecessary for encryption operations.\n"
            "   Reasons why this is unsafe:\n"
            "   - Could corrupt system files if encryption goes wrong\n"
            "   - Encrypted files would be owned by root\n"
            "   - Violates principle of least privilege\n"
            "   - Could be exploited by vulnerabilities\n"
            "\n"
            "   Solution: Run this program as a normal user without sudo"
        )

    sensitive_warning = check_sensitive_directory()
    if sensitive_warning:
        errors.append(sensitive_warning)

    if errors:
        error_message = "\n\n".join(errors)

        if exit_on_error:
            print(error_message, file=sys.stderr)
            sys.exit(1)
        else:
            raise SecurityError(error_message)

    return True


def create_secure_temp_file(
    prefix: str = "secure_cipher_",
    suffix: str = ".tmp",
    directory: str | Path | None = None,
) -> contextlib.AbstractContextManager[tuple[int, str]]:
    """
    Create a temporary file with secure permissions (0o600).

    This function creates a temporary file that is only readable and writable
    by the current user (chmod 0o600). The file is automatically deleted when
    the context manager exits.

    Args:
        prefix: Prefix for the temporary filename (default: "secure_cipher_")
        suffix: Suffix for the temporary filename (default: ".tmp")
        directory: Directory to create temp file in (default: system temp dir)

    Returns:
        Context manager yielding (file_descriptor, filepath) tuple

    Raises:
        SecurityError: If unable to create secure temp file or set permissions
        OSError: If file operations fail

    Example:
        >>> with create_secure_temp_file() as (fd, path):
        ...     os.write(fd, b"secret data")
        ...     # File is automatically deleted on exit

    Security:
        - File permissions set to 0o600 (owner read/write only)
        - File descriptor returned for secure writing
        - Automatic cleanup on context exit
        - Validates directory is writable
    """
    import contextlib

    if directory:
        directory = Path(directory)
        if not directory.exists():
            raise SecurityError(f"Directory does not exist: {directory}")
        if not os.access(directory, os.W_OK):
            raise SecurityError(f"Directory is not writable: {directory}")

    @contextlib.contextmanager
    def _secure_temp_context():
        fd = None
        path = None
        try:
            # delete=False because we want manual control over deletion
            fd, path = tempfile.mkstemp(
                prefix=prefix,
                suffix=suffix,
                dir=directory,
            )

            os.chmod(path, 0o600)

            stat_info = os.stat(path)
            actual_perms = stat_info.st_mode & 0o777
            if actual_perms != 0o600:
                raise SecurityError(
                    f"Failed to set secure permissions on {path}. "
                    f"Expected 0o600, got {oct(actual_perms)}"
                )

            yield fd, path

        finally:
            # Clean up: close fd and delete file
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass  # Already closed

            if path and os.path.exists(path):
                try:
                    os.unlink(path)
                except OSError:
                    pass  # Best effort cleanup

    return _secure_temp_context()


def secure_atomic_write(
    destination: str | Path,
    content: bytes,
    mode: int = 0o600,
) -> None:
    """
    Atomically write content to a file with secure permissions.

    This function writes content to a temporary file first, then atomically
    renames it to the destination. This prevents partial writes if the
    operation is interrupted.

    Args:
        destination: Final destination file path
        content: Bytes to write to the file
        mode: File permissions (default: 0o600 - owner read/write only)

    Raises:
        SecurityError: If security checks fail or permissions cannot be set
        OSError: If file operations fail

    Example:
        >>> secure_atomic_write("secrets.txt", b"confidential", mode=0o600)

    Security:
        - Atomic operation (rename) prevents partial writes
        - Secure permissions set on temp file before writing
        - Temp file in same directory as destination (same filesystem)
        - Validates destination path before writing
        - Automatic cleanup on failure
    """
    destination = Path(destination)

    # Validate destination path
    if destination.exists():
        if not os.access(destination, os.W_OK):
            raise SecurityError(f"Destination file is not writable: {destination}")

    # Validate parent directory
    parent_dir = destination.parent
    if not parent_dir.exists():
        raise SecurityError(f"Parent directory does not exist: {parent_dir}")
    if not os.access(parent_dir, os.W_OK):
        raise SecurityError(f"Parent directory is not writable: {parent_dir}")

    # This ensures same filesystem for atomic rename
    temp_fd = None
    temp_path = None

    try:
        temp_fd, temp_path = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=parent_dir,
        )

        os.chmod(temp_path, mode)

        stat_info = os.stat(temp_path)
        actual_perms = stat_info.st_mode & 0o777
        if actual_perms != mode:
            raise SecurityError(
                f"Failed to set permissions {oct(mode)} on temp file. "
                f"Got {oct(actual_perms)}"
            )

        os.write(temp_fd, content)

        os.fsync(temp_fd)

        os.close(temp_fd)
        temp_fd = None

        # Atomic rename to destination
        # On POSIX systems, this is atomic even if destination exists
        shutil.move(temp_path, destination)
        temp_path = None

    except Exception as e:
        if temp_fd is not None:
            try:
                os.close(temp_fd)
            except OSError:
                pass

        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass

        raise SecurityError(f"Secure atomic write failed: {e}") from e
