"""
Tests for timing attack mitigations
"""

import time

from secure_string_cipher.timing_safe import (
    add_timing_jitter,
    check_password_strength,
    constant_time_compare,
)


def test_constant_time_compare():
    """Test constant-time comparison."""
    assert constant_time_compare(b"hello", b"hello")
    assert not constant_time_compare(b"hello", b"world")
    assert not constant_time_compare(b"short", b"longer")


def test_timing_jitter():
    """Test that timing jitter adds delay."""
    start = time.perf_counter()
    add_timing_jitter()
    duration = time.perf_counter() - start
    assert 0 <= duration <= 0.015  # Should be between 0-15ms (allowing some overhead)


def test_password_strength_length():
    """Test password length requirement."""
    valid, msg = check_password_strength("short")
    assert not valid
    assert "characters" in msg


def test_password_strength_complexity():
    """Test password complexity requirements."""
    test_cases = [
        ("ABCD1234!@#$", False, "lowercase"),
        ("abcd1234!@#$", False, "uppercase"),
        ("ABCDabcd!@#$", False, "digits"),
        ("ABCDabcd1234", False, "symbols"),
        ("ABCDabcd1234!@#$", True, "acceptable"),
    ]

    for password, expected_valid, expected_msg in test_cases:
        start = time.perf_counter()
        valid, msg = check_password_strength(password)
        duration = time.perf_counter() - start

        assert valid == expected_valid
        if not valid:
            assert expected_msg in msg.lower()

        # All checks should take similar time
        assert 0 <= duration <= 0.1


def test_password_common_patterns():
    """Test rejection of common password patterns."""
    common_passwords = ["Password123!@#", "Admin123!@#$", "Qwerty123!@#"]

    durations = []
    for password in common_passwords:
        start = time.perf_counter()
        valid, msg = check_password_strength(password)
        durations.append(time.perf_counter() - start)

        assert not valid
        assert "common patterns" in msg.lower()

    # All checks should take similar time
    avg_duration = sum(durations) / len(durations)
    for duration in durations:
        assert abs(duration - avg_duration) < 0.05  # Within 50ms
