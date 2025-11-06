"""
Tests for secure memory operations
"""

import pytest

from secure_string_cipher.secure_memory import (
    SecureBytes,
    SecureString,
    secure_compare,
    secure_wipe,
)


def test_secure_wipe():
    """Test that secure_wipe properly zeros out data."""
    data = bytearray(b"sensitive data")
    secure_wipe(data)
    assert all(b == 0 for b in data)


def test_secure_bytes():
    """Test SecureBytes context manager."""
    sensitive = b"top secret"
    with SecureBytes(sensitive) as secure:
        assert bytes(secure.data) == sensitive
    # After context exit, buffer should be wiped
    with pytest.raises(AttributeError):
        secure.data  # noqa: B018


def test_secure_string():
    """Test SecureString context manager."""
    sensitive = "password123"
    with SecureString(sensitive) as secure:
        assert secure.string == sensitive
    # After context exit, string should be wiped
    with pytest.raises(AttributeError):
        secure.string  # noqa: B018


def test_secure_compare():
    """Test constant-time comparison."""
    a = b"hello"
    b = b"hello"
    c = b"world"

    assert secure_compare(a, b)
    assert not secure_compare(a, c)
    assert not secure_compare(b"short", b"longer")


def test_secure_bytes_exception_handling():
    """Test that SecureBytes wipes data even if exception occurs."""
    sensitive = b"classified"
    secure = None
    try:
        with SecureBytes(sensitive) as secure:
            raise Exception("Test exception")
    except Exception:
        pass
    # Data should be wiped even after exception
    with pytest.raises(AttributeError):
        secure.data  # noqa: B018


def test_secure_string_exception_handling():
    """Test that SecureString wipes data even if exception occurs."""
    sensitive = "topsecret"
    secure = None
    try:
        with SecureString(sensitive) as secure:
            raise Exception("Test exception")
    except Exception:
        pass
    # String should be wiped even after exception
    with pytest.raises(AttributeError):
        secure.string  # noqa: B018
