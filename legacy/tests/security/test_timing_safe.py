"""
Tests for timing attack mitigations.

Tests verify:
- Constant-time comparison behavior
- Timing jitter functionality
- Password strength validation rules
- Common pattern detection
- Edge cases in validation
"""

import time

from secure_string_cipher.config import MIN_PASSWORD_LENGTH
from secure_string_cipher.timing_safe import (
    add_timing_jitter,
    check_password_strength,
    constant_time_compare,
)

# =============================================================================
# constant_time_compare() Tests
# =============================================================================


class TestConstantTimeCompare:
    """Tests for constant-time byte comparison."""

    def test_equal_bytes_returns_true(self):
        """Verify equal bytes compare as equal."""
        assert constant_time_compare(b"hello", b"hello")

    def test_unequal_bytes_returns_false(self):
        """Verify unequal bytes compare as unequal."""
        assert not constant_time_compare(b"hello", b"world")

    def test_different_lengths_returns_false(self):
        """Verify different lengths return False."""
        assert not constant_time_compare(b"short", b"longer")
        assert not constant_time_compare(b"longer", b"short")

    def test_empty_bytes(self):
        """Verify empty bytes compare correctly."""
        assert constant_time_compare(b"", b"")

    def test_single_byte(self):
        """Verify single byte comparison."""
        assert constant_time_compare(b"x", b"x")
        assert not constant_time_compare(b"x", b"y")

    def test_binary_data_with_nulls(self):
        """Verify binary data with null bytes compares correctly."""
        a = b"\x00\xff\x00\xff"
        b = b"\x00\xff\x00\xff"
        c = b"\x00\xff\x00\xfe"
        assert constant_time_compare(a, b)
        assert not constant_time_compare(a, c)

    def test_single_bit_difference(self):
        """Verify single bit difference is detected."""
        assert not constant_time_compare(b"\x00", b"\x01")
        assert not constant_time_compare(b"\x80", b"\x00")

    def test_large_data(self):
        """Verify large data comparison works."""
        size = 1024 * 100  # 100 KB
        data = bytes(range(256)) * (size // 256)
        assert constant_time_compare(data, data)
        modified = bytearray(data)
        modified[-1] ^= 1
        assert not constant_time_compare(data, bytes(modified))


# =============================================================================
# add_timing_jitter() Tests
# =============================================================================


class TestTimingJitter:
    """Tests for timing jitter functionality."""

    def test_jitter_adds_delay(self):
        """Verify jitter adds some delay."""
        start = time.perf_counter()
        add_timing_jitter()
        duration = time.perf_counter() - start
        # Should be between 0-200ms (allowing system variance)
        assert 0 <= duration <= 0.2

    def test_jitter_varies(self):
        """Verify jitter produces varying delays."""
        durations = []
        for _ in range(10):
            start = time.perf_counter()
            add_timing_jitter()
            durations.append(time.perf_counter() - start)
        # Not all durations should be identical (randomness check)
        # Allow for some variance but expect at least some difference
        unique_rounded = len({round(d, 4) for d in durations})
        # Should have at least 2 different delay values in 10 tries
        assert unique_rounded >= 2


# =============================================================================
# check_password_strength() Tests
# =============================================================================


class TestPasswordStrength:
    """Tests for password strength validation."""

    def test_valid_password_accepted(self):
        """Verify a strong password passes validation."""
        valid, msg = check_password_strength("SecurePass123!@#")
        assert valid
        assert "acceptable" in msg.lower()

    def test_short_password_rejected(self):
        """Verify passwords shorter than minimum are rejected."""
        valid, msg = check_password_strength("Short1!")
        assert not valid
        assert "characters" in msg

    def test_exact_minimum_length_with_complexity(self):
        """Verify password at exact minimum length can pass."""
        # Build a password exactly MIN_PASSWORD_LENGTH chars with all requirements
        password = "Aa1!" + "x" * (MIN_PASSWORD_LENGTH - 4)  # pragma: allowlist secret
        assert len(password) == MIN_PASSWORD_LENGTH
        valid, msg = check_password_strength(password)
        assert valid

    def test_missing_uppercase_rejected(self):
        """Verify passwords without uppercase are rejected."""
        valid, msg = check_password_strength("abcd1234!@#$")
        assert not valid
        assert "uppercase" in msg.lower()

    def test_missing_lowercase_rejected(self):
        """Verify passwords without lowercase are rejected."""
        valid, msg = check_password_strength("ABCD1234!@#$")
        assert not valid
        assert "lowercase" in msg.lower()

    def test_missing_digits_rejected(self):
        """Verify passwords without digits are rejected."""
        valid, msg = check_password_strength("ABCDabcd!@#$")
        assert not valid
        assert "digits" in msg.lower()

    def test_missing_symbols_rejected(self):
        """Verify passwords without symbols are rejected."""
        valid, msg = check_password_strength("ABCDabcd1234")
        assert not valid
        assert "symbols" in msg.lower()

    def test_multiple_missing_requirements(self):
        """Verify multiple missing requirements are reported."""
        valid, msg = check_password_strength("abcdabcdabcd")  # Only lowercase
        assert not valid
        # Should mention multiple missing requirements
        assert "uppercase" in msg.lower()
        assert "digits" in msg.lower()
        assert "symbols" in msg.lower()


class TestCommonPatterns:
    """Tests for common password pattern detection."""

    def test_password_pattern_rejected(self):
        """Verify 'password' pattern is rejected."""
        valid, msg = check_password_strength("Password123!@#")
        assert not valid
        assert "common patterns" in msg.lower()

    def test_admin_pattern_rejected(self):
        """Verify 'admin' pattern is rejected."""
        valid, msg = check_password_strength("Admin123!@#$%")
        assert not valid
        assert "common patterns" in msg.lower()

    def test_qwerty_pattern_rejected(self):
        """Verify 'qwerty' pattern is rejected."""
        valid, msg = check_password_strength("Qwerty123!@#$")
        assert not valid
        assert "common patterns" in msg.lower()

    def test_common_patterns_case_insensitive(self):
        """Verify common pattern detection is case-insensitive."""
        # These should all be rejected for common patterns
        # Passwords must also pass complexity requirements
        variants = ["PassWord123!@#", "pAssWoRd123!@#", "passWORD123!@#"]
        for password in variants:
            valid, msg = check_password_strength(password)
            assert not valid, f"Should reject: {password}"
            assert "common patterns" in msg.lower()

    def test_common_pattern_embedded(self):
        """Verify common patterns embedded in longer passwords are detected."""
        valid, msg = check_password_strength("MyAdminAccount1!")
        assert not valid
        assert "common patterns" in msg.lower()


class TestPasswordEdgeCases:
    """Edge case tests for password validation."""

    def test_empty_password(self):
        """Verify empty password is rejected."""
        valid, msg = check_password_strength("")
        assert not valid

    def test_unicode_password_support(self):
        """Verify unicode characters work in passwords."""
        # Unicode with all requirements
        valid, msg = check_password_strength("Pässwörd123!@#")
        assert valid

    def test_spaces_in_password(self):
        """Verify passwords with spaces work."""
        valid, msg = check_password_strength("Secure Pass 123!")
        assert valid

    def test_only_symbols_rejected(self):
        """Verify passwords with only symbols are rejected."""
        valid, msg = check_password_strength("!@#$%^&*()!@#$")
        assert not valid

    def test_very_long_password(self):
        """Verify very long passwords are handled."""
        long_pass = "Aa1!" + "x" * 1000
        valid, msg = check_password_strength(long_pass)
        assert valid

    def test_timing_consistency(self):
        """Verify all checks complete in reasonable time regardless of outcome."""
        test_cases = [
            ("Short1!", False),  # Too short
            ("ABCD1234!@#$", False),  # Missing lowercase
            ("Password123!", False),  # Common pattern
            ("SecurePass123!@#", True),  # Valid
        ]

        durations = []
        for password, expected_valid in test_cases:
            start = time.perf_counter()
            valid, _ = check_password_strength(password)
            durations.append(time.perf_counter() - start)
            assert valid == expected_valid

        # All checks should complete within similar timeframes
        # (allowing for jitter variance)
        avg_duration = sum(durations) / len(durations)
        for duration in durations:
            assert abs(duration - avg_duration) < 0.3  # Within 300ms
