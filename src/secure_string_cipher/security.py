"""
Security utilities for filename sanitization and secure atomic writes.

This module provides security functions to prevent path traversal attacks
and Unicode exploits in filenames, and to write files atomically with
owner-only permissions.

Path traversal and symlink-attack protection for actual file I/O lives
next to each writer instead of here: see core.py's `_ensure_no_symlink`
(v1) and v2/output.py's `validate_path_safety` (v2) — both handle a
platform quirk (e.g. macOS aliasing /var to /private/var) that a shared
generic checker got wrong, which is why they are not layered on top of a
version of this module's checks.
"""

import os
import re
import unicodedata
from pathlib import Path

from .atomic_io import atomic_binary_writer

_WINDOWS_RESERVED_BASENAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


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
    # Normalize Unicode (NFKD decomposition). This provides a consistent input
    # representation but does not detect or prevent all homoglyphs.
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

    # Windows aliases trailing dots and treats these basenames as devices even
    # when an extension is present. Produce one portable destination policy.
    filename = filename.rstrip(".")
    basename = filename.split(".", maxsplit=1)[0].upper()
    if basename in _WINDOWS_RESERVED_BASENAMES:
        filename = f"_{filename}"

    if len(filename) > max_length:
        name, ext = os.path.splitext(filename)
        available = max_length - len(ext) - 1
        name = name[:available]
        filename = name + ext

    if not filename:
        filename = "decrypted_file"

    return filename


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
    if mode != 0o600:
        raise SecurityError("Secure atomic writes require owner-only mode 0o600")

    # Validate destination path
    try:
        dest_exists = destination.exists()
    except OSError:
        # If we can't check existence due to permissions, treat as not existing
        # (since we likely can't write to it anyway)
        dest_exists = False

    if dest_exists:
        if not os.access(destination, os.W_OK):
            raise SecurityError(f"Destination file is not writable: {destination}")

    # Validate parent directory
    parent_dir = destination.parent
    if not parent_dir.exists():
        raise SecurityError(f"Parent directory does not exist: {parent_dir}")
    if not os.access(parent_dir, os.W_OK):
        raise SecurityError(f"Parent directory is not writable: {parent_dir}")

    try:
        with atomic_binary_writer(destination, overwrite=True, mode=mode) as writer:
            writer.write(content)
    except Exception as e:
        raise SecurityError(f"Secure atomic write failed: {e}") from e
