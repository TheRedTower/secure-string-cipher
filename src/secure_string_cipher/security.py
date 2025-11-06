"""
Security utilities for filename sanitization and path validation.

This module provides security functions to prevent path traversal attacks,
Unicode exploits, symlink attacks, and other filename-based vulnerabilities.
"""

import os
import re
import unicodedata
from pathlib import Path
from typing import Optional, Union


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
    filename = unicodedata.normalize('NFKD', filename)
    
    # Remove all control characters (including null bytes)
    # Control characters are in category 'C'
    filename = ''.join(
        c for c in filename 
        if unicodedata.category(c)[0] != 'C'
    )
    
    # Normalize path separators (both Unix and Windows)
    # This allows os.path.basename to work correctly
    filename = filename.replace('\\', '/')
    
    # Extract basename only - removes ALL path components
    # This handles ../../../etc/passwd -> passwd
    filename = os.path.basename(filename)
    
    # Remove path traversal sequences that might remain
    filename = filename.replace('..', '')
    
    # Remove leading dots to prevent hidden file creation
    filename = filename.lstrip('.')
    
    # Replace unsafe characters with underscores
    # Allow only: alphanumeric, dash, underscore, dot
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    
    # Collapse multiple consecutive underscores to single underscore
    filename = re.sub(r'_+', '_', filename)
    
    # Remove leading/trailing underscores
    filename = filename.strip('_')
    
    # Limit filename length
    if len(filename) > max_length:
        name, ext = os.path.splitext(filename)
        # Reserve space for extension
        available = max_length - len(ext) - 1
        name = name[:available]
        filename = name + ext
    
    # Ensure filename is not empty
    if not filename:
        filename = 'decrypted_file'
    
    return filename


def validate_filename_safety(original: str, sanitized: str) -> Optional[str]:
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
    file_path: Union[str, Path], 
    allowed_dir: Optional[Union[str, Path]] = None
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
    # Convert to Path objects
    file_path = Path(file_path).resolve()
    
    if allowed_dir is None:
        allowed_dir = Path.cwd()
    else:
        allowed_dir = Path(allowed_dir).resolve()
    
    # Check if resolved path is within allowed directory
    try:
        # Will raise ValueError if file_path is not relative to allowed_dir
        file_path.relative_to(allowed_dir)
        return True
    except ValueError:
        raise SecurityError(
            f"Path traversal detected: '{file_path}' is outside allowed directory '{allowed_dir}'"
        )


def detect_symlink(file_path: Union[str, Path], follow_links: bool = False) -> bool:
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
    
    # Check if the path itself is a symlink
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
            return True
        except (ValueError, OSError):
            raise SecurityError(
                f"Symlink attack detected: '{file_path}' points to '{target}' "
                f"which is outside the current directory"
            )
    
    # Check if any parent directory is a symlink
    for parent in file_path.parents:
        if parent.is_symlink():
            if not follow_links:
                raise SecurityError(
                    f"Symlink in path detected: '{parent}' is a symbolic link"
                )
            
            # Check if symlink target is within cwd
            try:
                target = parent.resolve()
                target.relative_to(Path.cwd())
            except (ValueError, OSError):
                raise SecurityError(
                    f"Symlink attack in path: '{parent}' points outside current directory"
                )
    
    return True


def validate_output_path(
    output_path: Union[str, Path],
    allowed_dir: Optional[Union[str, Path]] = None,
    allow_symlinks: bool = False
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
    
    # Check for symlinks
    detect_symlink(output_path, follow_links=allow_symlinks)
    
    # Validate path doesn't escape allowed directory
    if allowed_dir is None:
        allowed_dir = Path.cwd()
    
    # Resolve to absolute path
    output_path = output_path.resolve()
    validate_safe_path(output_path, allowed_dir)
    
    return output_path
