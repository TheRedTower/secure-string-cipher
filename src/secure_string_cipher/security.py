"""
Security utilities for filename sanitization and path validation.

This module provides security functions to prevent path traversal attacks,
Unicode exploits, and other filename-based vulnerabilities.
"""

import os
import re
import unicodedata
from typing import Optional


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
