"""
Tests for secure memory operations.

Tests verify:
- Memory wiping with multiple overwrite passes
- Context manager semantics and automatic cleanup
- Exception safety (data wiped even on errors)
- Constant-time comparison resistance
- Edge cases (empty data, large buffers, unicode)
- Type safety and error handling
"""

import array
from unittest.mock import Mock

import pytest

import secure_string_cipher.secure_memory as secure_memory_module
from secure_string_cipher.secure_memory import (
    SecureBytes,
    SecureString,
    secure_compare,
    secure_wipe,
)

# =============================================================================
# secure_wipe() Tests
# =============================================================================


class TestSecureWipe:
    """Tests for secure_wipe function."""

    def test_wipe_zeros_bytearray(self):
        """Verify secure_wipe zeros out bytearray data."""
        data = bytearray(b"sensitive data here")
        secure_wipe(data)
        assert all(b == 0 for b in data)

    def test_wipe_zeros_memoryview(self):
        """Verify secure_wipe works with memoryview."""
        buffer = bytearray(b"secret buffer")
        view = memoryview(buffer)
        secure_wipe(view)
        assert all(b == 0 for b in buffer)
        with pytest.raises(ValueError, match="released memoryview"):
            view.tobytes()

    def test_wipe_zeros_array(self):
        """Verify secure_wipe works with array.array."""
        data = array.array("B", b"array secret")
        secure_wipe(data)
        assert all(b == 0 for b in data)

    @pytest.mark.parametrize(
        ("typecode", "values"),
        [
            ("i", [-1, -2, 12345]),
            ("d", [1.25, -4.5, 1024.75]),
        ],
    )
    @pytest.mark.parametrize("as_memoryview", [False, True], ids=["array", "view"])
    @pytest.mark.parametrize("backend", ["sodium", "fallback"])
    def test_wipe_zeros_every_byte_of_multi_byte_buffers(
        self, monkeypatch, typecode, values, as_memoryview, backend
    ):
        """Verify both backends clear signed and multi-byte buffer storage."""
        if backend == "sodium":
            if not secure_memory_module.HAS_SODIUM:
                pytest.skip("PyNaCl not installed")
            fallback = Mock(side_effect=AssertionError("unexpected fallback"))
            monkeypatch.setattr(secure_memory_module, "_fallback_wipe", fallback)
        else:
            monkeypatch.setattr(
                secure_memory_module, "_sodium_memzero", Mock(return_value=False)
            )

        backing = array.array(typecode, values)
        target = memoryview(backing) if as_memoryview else backing

        secure_wipe(target)

        assert backing.tobytes() == bytes(backing.itemsize * len(backing))
        if as_memoryview:
            with pytest.raises(ValueError, match="released memoryview"):
                target.tobytes()

    @pytest.mark.parametrize("backend", ["sodium", "fallback"])
    def test_wipe_memoryview_slice_does_not_touch_neighbors(self, monkeypatch, backend):
        """Verify wiping a contiguous view stays within that view's byte span."""
        if backend == "sodium":
            if not secure_memory_module.HAS_SODIUM:
                pytest.skip("PyNaCl not installed")
            fallback = Mock(side_effect=AssertionError("unexpected fallback"))
            monkeypatch.setattr(secure_memory_module, "_fallback_wipe", fallback)
        else:
            monkeypatch.setattr(
                secure_memory_module, "_sodium_memzero", Mock(return_value=False)
            )

        backing = array.array("i", [1234, -1, -2, 2345])
        original = backing.tobytes()
        target = memoryview(backing)[1:3]

        secure_wipe(target)

        itemsize = backing.itemsize
        wiped = backing.tobytes()
        assert wiped[:itemsize] == original[:itemsize]
        assert wiped[itemsize : 3 * itemsize] == bytes(2 * itemsize)
        assert wiped[3 * itemsize :] == original[3 * itemsize :]
        with pytest.raises(ValueError, match="released memoryview"):
            target.tobytes()

    def test_wipe_rejects_readonly_view_without_writing(self, monkeypatch):
        """Verify a read-only view is rejected before either backend runs."""
        backing = bytearray(b"readonly secret")
        original = bytes(backing)
        owner = memoryview(backing)
        target = owner.toreadonly()
        owner.release()
        sodium = Mock(return_value=True)
        fallback = Mock()
        monkeypatch.setattr(secure_memory_module, "_sodium_memzero", sodium)
        monkeypatch.setattr(secure_memory_module, "_fallback_wipe", fallback)

        with pytest.raises(TypeError, match="writable"):
            secure_wipe(target)

        assert bytes(backing) == original
        sodium.assert_not_called()
        fallback.assert_not_called()
        with pytest.raises(ValueError, match="released memoryview"):
            target.tobytes()

    def test_wipe_rejects_noncontiguous_view_without_writing(self, monkeypatch):
        """Verify a strided view is rejected before either backend runs."""
        backing = bytearray(b"noncontiguous secret")
        original = bytes(backing)
        target = memoryview(backing)[::2]
        sodium = Mock(return_value=True)
        fallback = Mock()
        monkeypatch.setattr(secure_memory_module, "_sodium_memzero", sodium)
        monkeypatch.setattr(secure_memory_module, "_fallback_wipe", fallback)

        with pytest.raises(TypeError, match="C-contiguous"):
            secure_wipe(target)

        assert bytes(backing) == original
        sodium.assert_not_called()
        fallback.assert_not_called()
        with pytest.raises(ValueError, match="released memoryview"):
            target.tobytes()

    def test_wipe_empty_buffer(self):
        """Verify secure_wipe handles empty buffers."""
        data = bytearray(b"")
        secure_wipe(data)  # Should not raise
        assert len(data) == 0

    def test_wipe_large_buffer(self):
        """Verify secure_wipe handles large buffers efficiently."""
        size = 1024 * 1024  # 1 MB
        data = bytearray(size)
        data[:] = b"x" * size
        secure_wipe(data)
        assert all(b == 0 for b in data)

    def test_wipe_single_byte(self):
        """Verify secure_wipe handles single byte."""
        data = bytearray(b"X")
        secure_wipe(data)
        assert data[0] == 0

    def test_wipe_rejects_immutable_bytes(self):
        """Verify secure_wipe rejects immutable bytes."""
        with pytest.raises(TypeError, match="mutable buffer"):
            secure_wipe(b"immutable")

    def test_wipe_rejects_string(self):
        """Verify secure_wipe rejects strings."""
        with pytest.raises(TypeError, match="mutable buffer"):
            secure_wipe("string")  # type: ignore[arg-type]

    def test_wipe_rejects_list(self):
        """Verify secure_wipe rejects lists."""
        with pytest.raises(TypeError, match="mutable buffer"):
            secure_wipe([1, 2, 3])  # type: ignore[arg-type]


# =============================================================================
# SecureBytes Tests
# =============================================================================


class TestSecureBytes:
    """Tests for SecureBytes context manager."""

    def test_context_manager_provides_data(self):
        """Verify data is accessible within context."""
        sensitive = b"top secret bytes"
        with SecureBytes(sensitive) as secure:
            assert bytes(secure.data) == sensitive

    def test_context_exit_wipes_data(self):
        """Verify buffer is wiped after context exit."""
        with SecureBytes(b"secret") as secure:
            pass
        with pytest.raises(AttributeError):
            _ = secure.data

    def test_data_property_returns_memoryview(self):
        """Verify data property returns memoryview for zero-copy access."""
        with SecureBytes(b"test") as secure:
            assert isinstance(secure.data, memoryview)

    def test_memoryview_reflects_original_buffer(self):
        """Verify memoryview is backed by internal buffer."""
        with SecureBytes(b"ABCD") as secure:
            view = secure.data
            # Modifying via memoryview should work
            view[0] = ord("X")
            assert bytes(secure.data) == b"XBCD"

    def test_exception_wipes_data(self):
        """Verify data is wiped even when exception occurs."""
        trigger_error = Mock(side_effect=ValueError("test exception"))
        secure = SecureBytes(b"classified")
        with pytest.raises(ValueError, match="test exception"):
            with secure:
                trigger_error()

        trigger_error.assert_called_once_with()
        with pytest.raises(AttributeError):
            _ = secure.data

    def test_explicit_wipe(self):
        """Verify explicit wipe() clears data."""
        secure = SecureBytes(b"explicit wipe test")
        assert bytes(secure.data) == b"explicit wipe test"
        secure.wipe()
        with pytest.raises(AttributeError):
            _ = secure.data

    def test_double_wipe_safe(self):
        """Verify calling wipe() multiple times is safe."""
        secure = SecureBytes(b"double wipe")
        secure.wipe()
        secure.wipe()  # Should not raise

    def test_empty_bytes(self):
        """Verify handling of empty bytes."""
        with SecureBytes(b"") as secure:
            assert bytes(secure.data) == b""

    def test_binary_data_preservation(self):
        """Verify binary data with null bytes is preserved."""
        binary = b"\x00\xff\x00\xff\x00"
        with SecureBytes(binary) as secure:
            assert bytes(secure.data) == binary


# =============================================================================
# SecureString Tests
# =============================================================================


class TestSecureString:
    """Tests for SecureString context manager."""

    def test_context_manager_provides_string(self):
        """Verify string is accessible within context."""
        sensitive = "password123!"
        with SecureString(sensitive) as secure:
            assert secure.string == sensitive

    def test_context_exit_wipes_string(self):
        """Verify internal buffer is wiped after context exit."""
        with SecureString("secret") as secure:
            pass
        with pytest.raises(AttributeError):
            _ = secure.string

    def test_exception_wipes_string(self):
        """Verify string is wiped even when exception occurs."""
        trigger_error = Mock(side_effect=ValueError("test exception"))
        secure = SecureString("topsecret")
        with pytest.raises(ValueError, match="test exception"):
            with secure:
                trigger_error()

        trigger_error.assert_called_once_with()
        with pytest.raises(AttributeError):
            _ = secure.string

    def test_explicit_wipe(self):
        """Verify explicit wipe() clears string."""
        secure = SecureString("explicit wipe")
        assert secure.string == "explicit wipe"
        secure.wipe()
        with pytest.raises(AttributeError):
            _ = secure.string

    def test_double_wipe_safe(self):
        """Verify calling wipe() multiple times is safe."""
        secure = SecureString("double wipe")
        secure.wipe()
        secure.wipe()  # Should not raise

    def test_empty_string(self):
        """Verify handling of empty string."""
        with SecureString("") as secure:
            assert secure.string == ""

    def test_unicode_preservation(self):
        """Verify unicode characters are preserved correctly."""
        unicode_str = "пароль密码🔐"
        with SecureString(unicode_str) as secure:
            assert secure.string == unicode_str

    def test_utf16le_internal_encoding(self):
        """Verify UTF-16LE encoding for internal storage."""
        test_str = "ABC"
        with SecureString(test_str) as secure:
            # UTF-16LE: each ASCII char is 2 bytes (char + 0x00)
            expected_bytes = test_str.encode("utf-16le")
            assert bytes(secure._chars) == expected_bytes

    def test_long_string(self):
        """Verify handling of long strings."""
        long_str = "A" * 10000
        with SecureString(long_str) as secure:
            assert secure.string == long_str


# =============================================================================
# secure_compare() Tests
# =============================================================================


class TestSecureCompare:
    """Tests for constant-time comparison."""

    def test_equal_bytes(self):
        """Verify equal bytes compare as equal."""
        assert secure_compare(b"hello", b"hello")

    def test_unequal_bytes(self):
        """Verify unequal bytes compare as unequal."""
        assert not secure_compare(b"hello", b"world")

    def test_different_lengths(self):
        """Verify different lengths return False."""
        assert not secure_compare(b"short", b"longer")
        assert not secure_compare(b"longer", b"short")

    def test_empty_bytes(self):
        """Verify empty bytes compare correctly."""
        assert secure_compare(b"", b"")
        assert not secure_compare(b"", b"x")

    def test_single_bit_difference(self):
        """Verify single bit difference is detected."""
        a = b"\x00"
        b = b"\x01"
        assert not secure_compare(a, b)

    def test_binary_data(self):
        """Verify binary data with null bytes compares correctly."""
        a = b"\x00\xff\x00\xff"
        b = b"\x00\xff\x00\xff"
        c = b"\x00\xff\x00\xfe"
        assert secure_compare(a, b)
        assert not secure_compare(a, c)

    def test_large_data_comparison(self):
        """Verify large data compares correctly."""
        size = 1024 * 100  # 100 KB
        a = bytes(range(256)) * (size // 256)
        b = bytes(range(256)) * (size // 256)
        c = bytearray(a)
        c[-1] = (c[-1] + 1) % 256  # Change last byte
        assert secure_compare(a, b)
        assert not secure_compare(a, bytes(c))


# =============================================================================
# Memory Safety Integration Tests
# =============================================================================


class TestMemorySafetyIntegration:
    """Integration tests for memory safety scenarios."""

    def test_nested_secure_contexts(self):
        """Verify nested SecureBytes/SecureString contexts work correctly."""
        with SecureString("outer") as outer:
            with SecureBytes(b"inner") as inner:
                assert outer.string == "outer"
                assert bytes(inner.data) == b"inner"
            # Inner should be wiped
            with pytest.raises(AttributeError):
                _ = inner.data
            # Outer should still be accessible
            assert outer.string == "outer"
        # Now outer should be wiped
        with pytest.raises(AttributeError):
            _ = outer.string

    def test_destructor_wipes_data(self):
        """Verify __del__ wipes data when object is deleted."""
        secure = SecureBytes(b"destructor test")
        buffer_ref = secure._buffer  # Keep reference to buffer
        del secure
        # Buffer should be zeroed (best-effort, depends on GC)
        assert all(b == 0 for b in buffer_ref)

    def test_secure_bytes_from_derived_key(self):
        """Verify SecureBytes works with key-like data."""
        # Simulate a derived key
        key = bytes(range(32))  # 32-byte key
        with SecureBytes(key) as secure:
            assert len(secure.data) == 32
            assert bytes(secure.data) == key
        with pytest.raises(AttributeError):
            _ = secure.data

    def test_wipe_preserves_buffer_length(self):
        """Verify wiped buffer maintains its length."""
        data = bytearray(b"fixed length data")
        original_len = len(data)
        secure_wipe(data)
        assert len(data) == original_len
        assert all(b == 0 for b in data)


# =============================================================================
# PyNaCl / libsodium Integration Tests
# =============================================================================


class TestLibsodiumIntegration:
    """Tests for libsodium (PyNaCl) integration."""

    def test_has_secure_memory_returns_bool(self):
        """Verify has_secure_memory() returns a boolean."""
        from secure_string_cipher.secure_memory import has_secure_memory

        result = has_secure_memory()
        assert isinstance(result, bool)

    def test_has_secure_memory_reflects_pynacl_availability(self):
        """Verify has_secure_memory() correctly detects PyNaCl."""
        from secure_string_cipher.secure_memory import HAS_SODIUM, has_secure_memory

        assert has_secure_memory() == HAS_SODIUM

    def test_secure_wipe_works_regardless_of_backend(self):
        """Verify secure_wipe works with or without libsodium."""
        data = bytearray(b"test data for wiping")
        secure_wipe(data)
        assert all(b == 0 for b in data)

    def test_secure_compare_works_regardless_of_backend(self):
        """Verify secure_compare works with or without libsodium."""
        a = b"hello world"
        b = b"hello world"
        c = b"hello there"

        assert secure_compare(a, b)
        assert not secure_compare(a, c)

    def test_fallback_wipe_function_exists(self):
        """Verify _fallback_wipe is available as internal fallback."""
        from secure_string_cipher.secure_memory import _fallback_wipe

        data = bytearray(b"fallback test")
        _fallback_wipe(data)
        assert all(b == 0 for b in data)

    def test_fallback_wipe_zeros_multi_byte_array(self):
        """Verify the fallback clears the full byte length of each element."""
        from secure_string_cipher.secure_memory import _fallback_wipe

        data = array.array("d", [1.25, -4.5, 1024.75])
        _fallback_wipe(data)

        assert memoryview(data).cast("B").tobytes() == bytes(data.itemsize * len(data))

    def test_fallback_wipe_bounds_random_allocations(self, monkeypatch):
        """Verify fallback random passes allocate at most one bounded chunk."""
        from secure_string_cipher.secure_memory import _fallback_wipe

        chunk_size = secure_memory_module._FALLBACK_WIPE_CHUNK_SIZE
        data = bytearray(b"x" * (2 * chunk_size + 17))
        requested_lengths = []

        def deterministic_token_bytes(length):
            requested_lengths.append(length)
            return b"\xa5" * length

        monkeypatch.setattr(
            secure_memory_module.secrets,
            "token_bytes",
            deterministic_token_bytes,
        )

        _fallback_wipe(data)

        assert data == bytes(len(data))
        assert requested_lengths == [chunk_size, chunk_size, 17] * 3

    @pytest.mark.skipif(
        not __import__(
            "secure_string_cipher.secure_memory", fromlist=["HAS_SODIUM"]
        ).HAS_SODIUM,
        reason="PyNaCl not installed",
    )
    def test_sodium_memzero_is_used_when_available(self):
        """Verify libsodium is actually used when available."""
        from secure_string_cipher.secure_memory import HAS_SODIUM

        assert HAS_SODIUM, "This test requires PyNaCl"
        # If we get here, sodium is available and secure_wipe will use it
        data = bytearray(b"sodium test")
        secure_wipe(data)
        assert all(b == 0 for b in data)

    def test_secure_bytes_uses_secure_wipe(self):
        """Verify SecureBytes uses secure_wipe internally."""
        data = b"secure bytes test"
        secure = SecureBytes(data)
        buffer_ref = secure._buffer
        secure.wipe()
        # Buffer should be zeroed regardless of backend
        assert all(b == 0 for b in buffer_ref)

    def test_secure_string_uses_secure_wipe(self):
        """Verify SecureString uses secure_wipe internally."""
        string = "secure string test"
        secure = SecureString(string)
        buffer_ref = secure._chars
        secure.wipe()
        # Buffer should be zeroed regardless of backend
        assert all(b == 0 for b in buffer_ref)

    @pytest.mark.skipif(
        not __import__(
            "secure_string_cipher.secure_memory", fromlist=["HAS_SODIUM"]
        ).HAS_SODIUM,
        reason="PyNaCl not installed",
    )
    def test_sodium_memcmp_is_used_when_available(self):
        """Verify libsodium's memcmp is actually used, not silently falling back.

        This test prevents regressions where code changes cause silent fallback
        to hmac.compare_digest when sodium should be used.
        """
        from unittest.mock import patch

        from secure_string_cipher.secure_memory import _sodium_bindings

        a = b"test data"
        b = b"test data"

        # Patch sodium_memcmp to track if it's called
        with patch.object(
            _sodium_bindings, "sodium_memcmp", wraps=_sodium_bindings.sodium_memcmp
        ) as mock_memcmp:
            result = secure_compare(a, b)
            assert result is True
            mock_memcmp.assert_called_once_with(a, b)
