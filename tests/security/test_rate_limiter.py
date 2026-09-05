"""
Tests for rate limiting functionality.

Tests verify:
- Basic rate limiting behavior
- Exponential backoff on repeated failures
- Thread safety
- Reset and cleanup behavior
- Decorator functionality
"""

import json
import threading
import time

import pytest

from secure_string_cipher.rate_limiter import (
    PersistentRateLimiter,
    RateLimiter,
    RateLimitError,
    get_global_limiter,
    rate_limited,
)


class TestPersistentRateLimiter:
    """Persistence loading rejects malformed records without crashing."""

    @staticmethod
    def _write_valid_state(state_path, *, operation="decrypt:file.enc"):
        """Write one recent failed attempt and return its timestamp."""
        timestamp = time.time()
        state_path.write_text(
            json.dumps(
                {
                    operation: {
                        "attempts": [timestamp],
                        "lockout_until": 0.0,
                        "consecutive_failures": 1,
                    }
                }
            ),
            encoding="utf-8",
        )
        return timestamp

    def test_loads_valid_records(self, tmp_path):
        """Valid persisted failures should survive process construction."""
        state_path = tmp_path / "rate_limits.json"
        self._write_valid_state(state_path)

        limiter = PersistentRateLimiter(str(state_path), max_attempts=3)

        assert limiter.get_remaining_attempts("decrypt", "file.enc") == 2

    def test_filters_invalid_attempt_timestamps_and_loads_valid_sibling(self, tmp_path):
        """Bad timestamps are dropped without hiding a valid sibling record."""
        state_path = tmp_path / "rate_limits.json"
        timestamp = time.time()
        state_path.write_text(
            json.dumps(
                {
                    "mixed-attempts:": {
                        "attempts": [
                            timestamp,
                            True,
                            float("nan"),
                            float("inf"),
                            float("-inf"),
                            10**400,
                            -1,
                        ],
                        "lockout_until": 0.0,
                        "consecutive_failures": 1,
                    },
                    "valid:": {
                        "attempts": [timestamp],
                        "lockout_until": 0.0,
                        "consecutive_failures": 1,
                    },
                }
            ),
            encoding="utf-8",
        )

        limiter = PersistentRateLimiter(str(state_path), max_attempts=3)

        assert limiter.get_remaining_attempts("mixed-attempts") == 2
        assert limiter.get_remaining_attempts("valid") == 2

    @pytest.mark.parametrize(
        ("field", "invalid_value"),
        [
            ("lockout_until", True),
            ("lockout_until", float("nan")),
            ("lockout_until", float("inf")),
            ("lockout_until", 10**400),
            ("lockout_until", []),
            ("consecutive_failures", True),
            ("consecutive_failures", float("nan")),
            ("consecutive_failures", float("inf")),
            ("consecutive_failures", 10**400),
            ("consecutive_failures", "bad"),
        ],
    )
    def test_ignores_invalid_record_but_loads_valid_sibling(
        self, tmp_path, field, invalid_value
    ):
        """One corrupt record must not block valid persisted state."""
        state_path = tmp_path / "rate_limits.json"
        timestamp = time.time()
        invalid_record = {
            "attempts": [timestamp],
            "lockout_until": 0.0,
            "consecutive_failures": 1,
        }
        invalid_record[field] = invalid_value
        state_path.write_text(
            json.dumps(
                {
                    "invalid:": invalid_record,
                    "valid:": {
                        "attempts": [timestamp],
                        "lockout_until": 0.0,
                        "consecutive_failures": 1,
                    },
                }
            ),
            encoding="utf-8",
        )

        limiter = PersistentRateLimiter(str(state_path), max_attempts=3)

        assert limiter.get_remaining_attempts("invalid") == 3
        assert limiter.get_remaining_attempts("valid") == 2

    @pytest.mark.parametrize("replacement", [None, "{", "[]"])
    def test_missing_or_malformed_state_preserves_loaded_records(
        self, tmp_path, replacement
    ):
        """A failed reload must not erase the last valid in-memory state."""
        state_path = tmp_path / "rate_limits.json"
        self._write_valid_state(state_path, operation="keep:")
        limiter = PersistentRateLimiter(str(state_path), max_attempts=3)

        if replacement is None:
            state_path.unlink()
        else:
            state_path.write_text(replacement, encoding="utf-8")
        limiter._load_state()

        assert limiter.get_remaining_attempts("keep") == 2

    def test_oversized_json_integer_preserves_loaded_records(self, tmp_path):
        """JSON integer parse limits are treated as malformed persisted state."""
        state_path = tmp_path / "rate_limits.json"
        self._write_valid_state(state_path, operation="keep:")
        limiter = PersistentRateLimiter(str(state_path), max_attempts=3)
        state_path.write_text(
            '{"bad:": {"attempts": [], "lockout_until": '
            + ("9" * 5_000)
            + ', "consecutive_failures": 0}}',
            encoding="utf-8",
        )

        limiter._load_state()

        assert limiter.get_remaining_attempts("keep") == 2


class TestRateLimiterBasic:
    """Basic rate limiter functionality tests."""

    def test_allows_first_attempt(self):
        """First attempt should always be allowed."""
        limiter = RateLimiter(max_attempts=3)
        allowed, wait = limiter.check_rate_limit("test_op")
        assert allowed is True
        assert wait == 0.0

    def test_allows_up_to_max_attempts(self):
        """Should allow up to max_attempts within window."""
        limiter = RateLimiter(max_attempts=3, window_seconds=60)

        for _ in range(3):
            allowed, _ = limiter.check_rate_limit("test_op")
            assert allowed is True
            limiter.record_attempt("test_op", success=False)

    def test_blocks_after_max_attempts(self):
        """Should block after max_attempts failures."""
        limiter = RateLimiter(max_attempts=3, window_seconds=60, lockout_seconds=10)

        # Record max failures
        for _ in range(3):
            limiter.record_attempt("test_op", success=False)

        # Next check should be blocked
        allowed, wait = limiter.check_rate_limit("test_op")
        assert allowed is False
        assert wait > 0

    def test_success_resets_attempts(self):
        """Successful attempt should reset the counter."""
        limiter = RateLimiter(max_attempts=3)

        # Record some failures
        limiter.record_attempt("test_op", success=False)
        limiter.record_attempt("test_op", success=False)

        # Success should reset
        limiter.record_attempt("test_op", success=True)

        # Should have full attempts again
        remaining = limiter.get_remaining_attempts("test_op")
        assert remaining == 3

    def test_different_operations_tracked_separately(self):
        """Different operations should have separate limits."""
        limiter = RateLimiter(max_attempts=2)

        # Max out one operation
        limiter.record_attempt("op1", success=False)
        limiter.record_attempt("op1", success=False)

        # Other operation should still be allowed
        allowed, _ = limiter.check_rate_limit("op2")
        assert allowed is True

    def test_different_identifiers_tracked_separately(self):
        """Same operation with different identifiers tracked separately."""
        limiter = RateLimiter(max_attempts=2)

        # Max out one identifier
        limiter.record_attempt("op", "id1", success=False)
        limiter.record_attempt("op", "id1", success=False)

        # Different identifier should still be allowed
        allowed, _ = limiter.check_rate_limit("op", "id2")
        assert allowed is True


class TestExponentialBackoff:
    """Tests for exponential backoff behavior."""

    def test_lockout_duration_increases(self):
        """Lockout duration should increase with consecutive failures."""
        limiter = RateLimiter(
            max_attempts=1,
            lockout_seconds=1.0,
            backoff_multiplier=2.0,
        )

        # First lockout
        limiter.record_attempt("test", success=False)
        _, wait1 = limiter.check_rate_limit("test")
        assert 0.9 <= wait1 <= 1.1  # ~1 second

        # Wait for lockout to expire
        time.sleep(1.1)

        # Second lockout should be longer
        limiter.record_attempt("test", success=False)
        _, wait2 = limiter.check_rate_limit("test")
        assert 1.9 <= wait2 <= 2.1  # ~2 seconds

    def test_success_resets_backoff(self):
        """Successful auth should reset backoff multiplier."""
        limiter = RateLimiter(
            max_attempts=1,
            lockout_seconds=0.1,
            backoff_multiplier=2.0,
        )

        # Trigger multiple lockouts
        limiter.record_attempt("test", success=False)
        limiter.check_rate_limit("test")
        time.sleep(0.15)
        limiter.record_attempt("test", success=False)

        # Success should reset
        time.sleep(0.25)
        limiter.record_attempt("test", success=True)

        # Next lockout should be base duration again
        limiter.record_attempt("test", success=False)
        _, wait = limiter.check_rate_limit("test")
        assert wait <= 0.15  # Back to base ~0.1 seconds


class TestRemainingAttempts:
    """Tests for remaining attempts calculation."""

    def test_initial_remaining_equals_max(self):
        """Initially should have max attempts remaining."""
        limiter = RateLimiter(max_attempts=5)
        remaining = limiter.get_remaining_attempts("test")
        assert remaining == 5

    def test_remaining_decreases_with_failures(self):
        """Remaining attempts should decrease with failures."""
        limiter = RateLimiter(max_attempts=5)

        limiter.record_attempt("test", success=False)
        assert limiter.get_remaining_attempts("test") == 4

        limiter.record_attempt("test", success=False)
        assert limiter.get_remaining_attempts("test") == 3

    def test_remaining_zero_when_locked_out(self):
        """Should return 0 when currently locked out."""
        limiter = RateLimiter(max_attempts=1, lockout_seconds=60)

        limiter.record_attempt("test", success=False)
        limiter.check_rate_limit("test")  # Trigger lockout

        assert limiter.get_remaining_attempts("test") == 0


class TestReset:
    """Tests for reset functionality."""

    def test_reset_clears_single_operation(self):
        """Reset should clear a specific operation."""
        limiter = RateLimiter(max_attempts=3)

        limiter.record_attempt("op1", success=False)
        limiter.record_attempt("op2", success=False)

        limiter.reset("op1")

        assert limiter.get_remaining_attempts("op1") == 3
        assert limiter.get_remaining_attempts("op2") == 2

    def test_reset_all_clears_everything(self):
        """Reset all should clear all records."""
        limiter = RateLimiter(max_attempts=3)

        limiter.record_attempt("op1", success=False)
        limiter.record_attempt("op2", success=False)

        limiter.reset_all()

        assert limiter.get_remaining_attempts("op1") == 3
        assert limiter.get_remaining_attempts("op2") == 3


class TestWindowExpiration:
    """Tests for time window expiration."""

    def test_old_attempts_expire(self):
        """Attempts outside window should be ignored."""
        limiter = RateLimiter(
            max_attempts=2,
            window_seconds=0.1,
            lockout_seconds=0.1,  # Short lockout for test
        )

        limiter.record_attempt("test", success=False)
        limiter.record_attempt("test", success=False)

        # Should be blocked (triggers lockout)
        allowed, _ = limiter.check_rate_limit("test")
        assert allowed is False

        # Wait for both window and lockout to expire
        time.sleep(0.25)

        # Should be allowed again (attempts expired, lockout expired)
        allowed, _ = limiter.check_rate_limit("test")
        assert allowed is True


class TestThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_attempts(self):
        """Concurrent attempts should be handled safely."""
        limiter = RateLimiter(max_attempts=100, window_seconds=60)
        errors = []

        def attempt():
            try:
                for _ in range(10):
                    limiter.check_rate_limit("test")
                    limiter.record_attempt("test", success=False)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=attempt) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0


class TestRateLimitError:
    """Tests for RateLimitError exception."""

    def test_error_contains_wait_time(self):
        """Error should contain wait time."""
        error = RateLimitError(30.5)
        assert error.wait_seconds == 30.5
        assert "30.5" in str(error)

    def test_error_with_custom_message(self):
        """Error should support custom message."""
        error = RateLimitError(10, "Custom message")
        assert str(error) == "Custom message"


class TestRateLimitedDecorator:
    """Tests for the rate_limited decorator."""

    def test_decorator_allows_success(self):
        """Decorated function should work normally."""
        limiter = RateLimiter(max_attempts=3)

        @rate_limited("test_op", limiter=limiter)
        def my_func(x):
            return x * 2

        result = my_func(5)
        assert result == 10

    def test_decorator_blocks_after_failures(self):
        """Decorator should raise RateLimitError after max failures."""
        limiter = RateLimiter(max_attempts=2, lockout_seconds=60)

        @rate_limited("test_op", limiter=limiter)
        def failing_func():
            raise ValueError("Always fails")

        # Use up attempts
        with pytest.raises(ValueError):
            failing_func()
        with pytest.raises(ValueError):
            failing_func()

        # Should be rate limited now
        with pytest.raises(RateLimitError):
            failing_func()

    def test_decorator_with_identifier(self):
        """Decorator should extract identifier from args."""
        limiter = RateLimiter(max_attempts=1)

        @rate_limited("test_op", limiter=limiter, get_identifier=lambda path: path)
        def process_file(path):
            raise ValueError("fail")

        # Fail on file1
        with pytest.raises(ValueError):
            process_file("file1.txt")

        # file2 should still work (different identifier)
        with pytest.raises(ValueError):
            process_file("file2.txt")

        # file1 should be blocked
        with pytest.raises(RateLimitError):
            process_file("file1.txt")


class TestGlobalLimiter:
    """Tests for global limiter instance."""

    def test_global_limiter_exists(self):
        """Global limiter should be accessible."""
        limiter = get_global_limiter()
        assert isinstance(limiter, RateLimiter)

    def test_global_limiter_is_singleton(self):
        """Global limiter should be the same instance."""
        limiter1 = get_global_limiter()
        limiter2 = get_global_limiter()
        assert limiter1 is limiter2
