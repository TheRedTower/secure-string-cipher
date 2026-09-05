"""
Secure memory operations for handling sensitive data.

Provides secure memory handling with libsodium (via PyNaCl) when available,
falling back to best-effort Python implementation otherwise.

Limitations (even with libsodium):
- Python strings are immutable and may be interned
- GC may copy objects during compaction
- Third-party libraries may keep their own copies
"""

from __future__ import annotations

import array
import secrets
from types import TracebackType
from typing import TYPE_CHECKING

# Try to use libsodium for secure memory operations via PyNaCl's internal FFI
try:
    from nacl import bindings as _sodium_bindings
    from nacl._sodium import ffi as _ffi
    from nacl._sodium import lib as _lib

    HAS_SODIUM = True
except ImportError:
    HAS_SODIUM = False
    _ffi = None  # type: ignore[assignment]
    _lib = None  # type: ignore[assignment]
    _sodium_bindings = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from nacl import bindings as _sodium_bindings
    from nacl._sodium import ffi as _ffi
    from nacl._sodium import lib as _lib


_FALLBACK_WIPE_CHUNK_SIZE = 64 * 1024


def _writable_byte_view(
    data: bytearray | memoryview | array.array,
) -> memoryview:
    """Return a one-dimensional byte view over a supported mutable buffer."""
    view = memoryview(data)
    try:
        if view.readonly:
            raise TypeError("Data must be a writable buffer")
        if not view.c_contiguous:
            raise TypeError("Data must be C-contiguous")

        return view.cast("B")
    finally:
        view.release()


def _sodium_memzero(data: bytearray | memoryview | array.array) -> bool:
    """
    Use libsodium's sodium_memzero to securely wipe memory.

    Returns True if successful, False if fallback should be used.
    """
    if not HAS_SODIUM or _ffi is None or _lib is None:
        return False

    byte_view: memoryview | None = None
    try:
        byte_view = _writable_byte_view(data)
        buf = _ffi.from_buffer(byte_view)
        try:
            _lib.sodium_memzero(buf, byte_view.nbytes)
        finally:
            # cffi keeps the buffer exported for the lifetime of this object.
            del buf

        return True
    except (TypeError, ValueError, AttributeError, BufferError):
        return False
    finally:
        if byte_view is not None:
            byte_view.release()


def secure_wipe(data: bytes | bytearray | memoryview | array.array) -> None:
    """
    Securely wipe sensitive data from memory.

    Uses libsodium's sodium_memzero() when available (guaranteed not optimized away).
    Falls back to multi-pass random overwrite + zero fill otherwise.

    Args:
        data: Mutable buffer (bytearray, memoryview, or array.array).

    Raises:
        TypeError: If data is not a writable, C-contiguous mutable buffer.

    Note: GC may have copied data elsewhere. Original immutable sources can't be wiped.
    """
    if not isinstance(data, (bytearray, memoryview, array.array)):
        raise TypeError("Data must be a mutable buffer type")

    byte_view: memoryview | None = None
    try:
        # Validate before either backend runs so rejected views cannot be
        # partially overwritten by one backend and then fail in the other.
        byte_view = _writable_byte_view(data)

        # Try libsodium first, fall back to Python implementation.
        if not _sodium_memzero(byte_view):
            _fallback_wipe(byte_view)
    finally:
        if byte_view is not None:
            byte_view.release()
        if isinstance(data, memoryview):
            data.release()


def _fallback_wipe(data: bytearray | memoryview | array.array) -> None:
    """
    Best-effort Python memory wiping.

    Performs 3 passes of random data followed by zero fill.
    This may be optimized away by the compiler/interpreter.
    """
    byte_view = _writable_byte_view(data)
    try:
        # Bound temporary allocations while still operating on every byte of
        # multi-byte array and memoryview elements.
        for _ in range(3):
            for start in range(0, byte_view.nbytes, _FALLBACK_WIPE_CHUNK_SIZE):
                chunk_length = min(_FALLBACK_WIPE_CHUNK_SIZE, byte_view.nbytes - start)
                byte_view[start : start + chunk_length] = secrets.token_bytes(
                    chunk_length
                )

        for start in range(0, byte_view.nbytes, _FALLBACK_WIPE_CHUNK_SIZE):
            chunk_length = min(_FALLBACK_WIPE_CHUNK_SIZE, byte_view.nbytes - start)
            byte_view[start : start + chunk_length] = bytes(chunk_length)
    finally:
        byte_view.release()


class SecureBytes:
    """
    Sensitive bytes that are automatically wiped from memory.

    Uses libsodium's sodium_memzero() when available.

    Note: Original bytes passed to __init__ cannot be wiped (immutable).
          GC may copy data before wiping. Use context managers for cleanup.
    """

    def __init__(self, data: bytes):
        """Initialize with sensitive data."""
        self._buffer = bytearray(data)
        self._wiped = False

    def __enter__(self) -> SecureBytes:
        """Context manager entry."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """
        Context manager exit - ensures data is wiped even if an exception occurs.
        """
        self.wipe()

    def __del__(self) -> None:
        """Destructor ensures data is wiped if object is garbage collected."""
        self.wipe()

    @property
    def data(self) -> memoryview:
        """Access the secure data."""
        return memoryview(self._buffer)

    def wipe(self) -> None:
        """Explicitly wipe the data. Safe to call multiple times."""
        if self._wiped:
            return
        self._wiped = True
        if hasattr(self, "_buffer"):
            secure_wipe(self._buffer)
            del self._buffer


class SecureString:
    """
    Sensitive strings that are automatically wiped from memory.

    Stores strings as UTF-16LE in a mutable buffer. Uses libsodium when available.

    Note: Original string passed to __init__ cannot be wiped (immutable).
          Accessing .string creates a new immutable string each time.
    """

    def __init__(self, string: str):
        """Initialize with sensitive string."""
        self._chars = bytearray(string.encode("utf-16le"))
        self._wiped = False

    def __enter__(self) -> SecureString:
        """Context manager entry."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """
        Context manager exit - ensures string is wiped even if an exception occurs.
        """
        self.wipe()

    def __del__(self) -> None:
        """Destructor ensures string is wiped if object is garbage collected."""
        self.wipe()

    @property
    def string(self) -> str:
        """Access the secure string."""
        return self._chars.decode("utf-16le")

    def wipe(self) -> None:
        """Explicitly wipe the string. Safe to call multiple times."""
        if self._wiped:
            return
        self._wiped = True
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

    When libsodium is available, uses sodium_memcmp() which provides
    guaranteed constant-time comparison. Otherwise uses hmac.compare_digest().

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

    if HAS_SODIUM and _sodium_bindings is not None:
        # Use libsodium's constant-time comparison (no fallback - fail loudly if broken)
        return _sodium_bindings.sodium_memcmp(a, b)

    # Fallback only when libsodium is not available
    import hmac

    return hmac.compare_digest(a, b)


def has_secure_memory() -> bool:
    """
    Check if libsodium-backed secure memory is available.

    Returns:
        True if libsodium (PyNaCl) is available, False otherwise.
    """
    return HAS_SODIUM
