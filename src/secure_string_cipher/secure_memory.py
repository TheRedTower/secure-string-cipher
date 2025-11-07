"""
Secure memory operations for handling sensitive data
"""

import array
import secrets


def secure_wipe(data: bytes | bytearray | memoryview | array.array) -> None:
    """
    Securely wipe sensitive data from memory.

    Args:
        data: The data to wipe. Must be a mutable buffer type.

    Note:
        This is a best-effort implementation. Some Python implementations
        or garbage collectors might keep copies of the data elsewhere in memory.
    """
    if not isinstance(data, (bytearray, memoryview, array.array)):
        raise TypeError("Data must be a mutable buffer type")

    length = len(data)

    for _ in range(3):
        for i in range(length):
            data[i] = secrets.randbelow(256)

    for i in range(length):
        data[i] = 0

    if isinstance(data, memoryview):
        data.release()


class SecureBytes:
    """
    A class for handling sensitive bytes that are automatically wiped from memory.

    Usage:
        with SecureBytes(b"sensitive data") as secure:
            process_secure_data(secure.data)
        # Data is automatically wiped after the with block
    """

    def __init__(self, data: bytes):
        """Initialize with sensitive data."""
        self._buffer = bytearray(data)

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager exit - ensures data is wiped even if an exception occurs.
        """
        self.wipe()

    def __del__(self):
        """Destructor ensures data is wiped if object is garbage collected."""
        self.wipe()

    @property
    def data(self) -> memoryview:
        """Access the secure data."""
        return memoryview(self._buffer)

    def wipe(self) -> None:
        """Explicitly wipe the data."""
        if hasattr(self, "_buffer"):
            secure_wipe(self._buffer)
            del self._buffer


class SecureString:
    """
    A class for handling sensitive strings that are automatically wiped from memory.

    Usage:
        with SecureString("sensitive data") as secure:
            process_secure_string(secure.string)
        # String is automatically wiped after the with block
    """

    def __init__(self, string: str):
        """Initialize with sensitive string."""
        self._chars = bytearray(string.encode("utf-16le"))

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager exit - ensures string is wiped even if an exception occurs.
        """
        self.wipe()

    def __del__(self):
        """Destructor ensures string is wiped if object is garbage collected."""
        self.wipe()

    @property
    def string(self) -> str:
        """Access the secure string."""
        return self._chars.decode("utf-16le")

    def wipe(self) -> None:
        """Explicitly wipe the string."""
        if hasattr(self, "_chars"):
            secure_wipe(self._chars)
            # remove the attribute so accesses raise AttributeError as tests expect
            try:
                del self._chars
            except Exception:
                self._chars = None  # type: ignore[assignment]


def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Perform a constant-time comparison of two byte strings.

    Args:
        a: First byte string
        b: Second byte string

    Returns:
        True if the strings are equal, False otherwise

    Note:
        This comparison is resistant to timing attacks.
    """
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b, strict=False):
        result |= x ^ y
    return result == 0
