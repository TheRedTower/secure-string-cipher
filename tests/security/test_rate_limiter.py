"""
Tests for rate limiting functionality.

Tests verify:
- Basic rate limiting behavior
- Exponential backoff on repeated failures
- Thread safety
- Reset and cleanup behavior
- Decorator functionality
"""

import hashlib
import hmac
import json
import math
import secrets
import sys
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


def _derive_key(salt: bytes, operation: str, identifier: str = "") -> str:
    """Independently reproduce PersistentRateLimiter._make_key's on-disk format.

    Deliberately re-derives the formula from spec rather than calling the
    implementation under test, so these tests would catch a regression in
    that formula rather than trivially agreeing with it.
    """
    raw = f"{operation}:{identifier}".encode()
    digest = hmac.new(salt, raw, hashlib.sha256).hexdigest()[:32]
    return f"{operation}:{digest}"


def _write_state_file(state_path, records, *, salt=None):
    """Write a rate-limiter state file keyed exactly as the real code would.

    `records` maps (operation, identifier) -> a dict of AttemptRecord fields
    (attempts/lockout_until/consecutive_failures, last_seen optional).
    Returns the salt used, so callers needing to inject more entries later
    (or assert against the raw file) can reuse the same derivation.
    """
    if salt is None:
        salt = secrets.token_bytes(32)
    data = {"__salt__": salt.hex()}
    for (operation, identifier), fields in records.items():
        data[_derive_key(salt, operation, identifier)] = fields
    state_path.write_text(json.dumps(data), encoding="utf-8")
    return salt


class TestPersistentRateLimiter:
    """Persistence loading rejects malformed records without crashing."""

    @staticmethod
    def _write_valid_state(state_path, *, operation="decrypt", identifier="file.enc"):
        """Write one recent failed attempt and return its timestamp."""
        timestamp = time.time()
        _write_state_file(
            state_path,
            {
                (operation, identifier): {
                    "attempts": [timestamp],
                    "lockout_until": 0.0,
                    "consecutive_failures": 1,
                }
            },
        )
        return timestamp

    def test_loads_valid_records(self, tmp_path):
        """Valid persisted failures should survive process construction."""
        state_path = tmp_path / "rate_limits.json"
        self._write_valid_state(state_path)

        limiter = PersistentRateLimiter(str(state_path), max_attempts=3)

        assert limiter.get_remaining_attempts("decrypt", "file.enc") == 2

    def test_persisted_keys_do_not_reveal_the_identifier(self, tmp_path):
        """The on-disk file must not contain the plaintext identifier."""
        state_path = tmp_path / "rate_limits.json"
        limiter = PersistentRateLimiter(str(state_path), max_attempts=1)
        limiter.record_attempt(
            "decrypt_file", "/home/alice/very-secret-report.pdf.enc", success=False
        )

        raw = state_path.read_text()
        assert "very-secret-report" not in raw
        assert "/home/alice" not in raw
        # The operation name staying readable is fine; only the identifier
        # component must be unrecoverable from the file.
        assert "decrypt_file:" in raw

    def test_reload_preserves_lockout_and_next_backoff(self, tmp_path, monkeypatch):
        """Reload keeps the existing deadline and uses the next failure exponent."""
        state_path = tmp_path / "rate_limits.json"
        now = 1_000.0
        monkeypatch.setattr(time, "time", lambda: now)

        def load_limiter():
            return PersistentRateLimiter(
                str(state_path),
                max_attempts=1,
                window_seconds=60,
                lockout_seconds=10,
                backoff_multiplier=2,
            )

        limiter = load_limiter()
        limiter.record_attempt("decrypt", "file.enc")
        assert limiter.check_rate_limit("decrypt", "file.enc") == (False, 10)
        disk_key = limiter._make_key("decrypt", "file.enc")
        first_record = json.loads(state_path.read_text())[disk_key]
        assert first_record["lockout_until"] == 1_010
        assert first_record["consecutive_failures"] == 1

        now = 1_005.0
        reloaded = load_limiter()
        assert reloaded.check_rate_limit("decrypt", "file.enc") == (False, 5)
        reloaded_record = dict(json.loads(state_path.read_text())[disk_key])
        # last_seen legitimately advances on every check; compare everything else.
        reloaded_record.pop("last_seen", None)
        expected = dict(first_record)
        expected.pop("last_seen", None)
        assert reloaded_record == expected

        now = 1_011.0
        assert reloaded.check_rate_limit("decrypt", "file.enc") == (False, 20)
        second_record = json.loads(state_path.read_text())[disk_key]
        assert second_record["lockout_until"] == 1_031
        assert second_record["consecutive_failures"] == 2

    @pytest.mark.parametrize("deadline", [999.0, 1e200])
    def test_extreme_backoff_keeps_lockout_across_reload(
        self, tmp_path, monkeypatch, deadline
    ):
        """An unrepresentable next delay must not discard an existing lockout."""
        state_path = tmp_path / "rate_limits.json"
        monkeypatch.setattr(time, "time", lambda: 1_000.0)
        salt = _write_state_file(
            state_path,
            {
                ("decrypt", ""): {
                    "attempts": [1_000.0],
                    "lockout_until": deadline,
                    "consecutive_failures": 2,
                }
            },
        )
        disk_key = _derive_key(salt, "decrypt")

        for _ in range(2):
            limiter = PersistentRateLimiter(
                str(state_path),
                max_attempts=1,
                lockout_seconds=1.0,
                backoff_multiplier=1e200,
            )
            allowed, wait = limiter.check_rate_limit("decrypt")
            assert not allowed
            assert math.isfinite(wait) and wait > 0
            record = json.loads(state_path.read_text())[disk_key]
            assert record["lockout_until"] == (
                deadline if deadline > 1_000 else sys.float_info.max
            )

    @pytest.mark.parametrize("failures", [1_000, 1_001, 10**400])
    def test_large_failure_count_is_bounded_without_losing_active_state(
        self, tmp_path, monkeypatch, failures
    ):
        state_path = tmp_path / "rate_limits.json"
        monkeypatch.setattr(time, "time", lambda: 1_000.0)
        salt = _write_state_file(
            state_path,
            {
                ("decrypt", ""): {
                    "attempts": [1_000.0],
                    "lockout_until": 1_010.0,
                    "consecutive_failures": failures,
                }
            },
        )
        disk_key = _derive_key(salt, "decrypt")
        limiter = PersistentRateLimiter(str(state_path), max_attempts=1)
        assert limiter.check_rate_limit("decrypt") == (False, 10)
        assert (
            json.loads(state_path.read_text())[disk_key]["consecutive_failures"]
            == 1_000
        )

        monkeypatch.setattr(time, "time", lambda: 1_011.0)
        allowed, wait = limiter.check_rate_limit("decrypt")
        assert not allowed and math.isfinite(wait)
        record = json.loads(state_path.read_text())[disk_key]
        assert record["consecutive_failures"] == 1_000
        assert math.isfinite(record["lockout_until"])
        assert not PersistentRateLimiter(str(state_path)).check_rate_limit("decrypt")[0]

    def test_deadline_addition_overflow_stays_finite(self, tmp_path, monkeypatch):
        state_path = tmp_path / "rate_limits.json"
        monkeypatch.setattr(time, "time", lambda: sys.float_info.max * 0.75)
        limiter = PersistentRateLimiter(
            str(state_path),
            max_attempts=1,
            window_seconds=sys.float_info.max,
            lockout_seconds=sys.float_info.max,
        )
        limiter.record_attempt("decrypt")
        allowed, wait = limiter.check_rate_limit("decrypt")
        assert not allowed and math.isfinite(wait)
        disk_key = limiter._make_key("decrypt")
        assert (
            json.loads(state_path.read_text())[disk_key]["lockout_until"]
            == sys.float_info.max
        )
        assert not PersistentRateLimiter(str(state_path)).check_rate_limit("decrypt")[0]

    def test_filters_invalid_attempt_timestamps_and_loads_valid_sibling(self, tmp_path):
        """Bad timestamps are dropped without hiding a valid sibling record."""
        state_path = tmp_path / "rate_limits.json"
        timestamp = time.time()
        _write_state_file(
            state_path,
            {
                ("mixed-attempts", ""): {
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
                ("valid", ""): {
                    "attempts": [timestamp],
                    "lockout_until": 0.0,
                    "consecutive_failures": 1,
                },
            },
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
            ("consecutive_failures", -1),
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
        _write_state_file(
            state_path,
            {
                ("invalid", ""): invalid_record,
                ("valid", ""): {
                    "attempts": [timestamp],
                    "lockout_until": 0.0,
                    "consecutive_failures": 1,
                },
            },
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
        self._write_valid_state(state_path, operation="keep", identifier="")
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
        self._write_valid_state(state_path, operation="keep", identifier="")
        limiter = PersistentRateLimiter(str(state_path), max_attempts=3)
        bad_key = limiter._make_key("bad", "")
        # Built as a raw literal rather than via json.dumps: the point is an
        # absurdly large integer *token* in the source text, which is what
        # exercises Python's integer-string conversion length guard.
        oversized_int = "9" * 5_000
        state_path.write_text(
            "{"
            + json.dumps(bad_key)
            + ': {"attempts": [], "lockout_until": '
            + oversized_int
            + ', "consecutive_failures": 0}}',
            encoding="utf-8",
        )

        limiter._load_state()

        assert limiter.get_remaining_attempts("keep") == 2

    def test_stale_records_are_pruned_and_persisted_count_is_bounded(
        self, tmp_path, monkeypatch
    ):
        """Fully-expired, unescalated records are dropped; overflow is capped."""
        from secure_string_cipher import rate_limiter as rl_module

        monkeypatch.setattr(rl_module, "_MAX_PERSISTED_RECORDS", 5)
        now = 1_000.0
        monkeypatch.setattr(time, "time", lambda: now)

        limiter = PersistentRateLimiter(
            str(tmp_path / "rate_limits.json"), max_attempts=100, window_seconds=10_000
        )
        # A record that fails once, then succeeds: fully resettable, prunable.
        limiter.record_attempt("decrypt_file", "prunable", success=False)
        limiter.record_attempt("decrypt_file", "prunable", success=True)

        # More distinct identifiers than the (monkeypatched) cap allows.
        for i in range(10):
            now = 1_000.0 + i
            limiter.record_attempt("decrypt_file", f"id-{i}", success=False)

        on_disk = json.loads((tmp_path / "rate_limits.json").read_text())
        record_keys = [k for k in on_disk if k != "__salt__"]
        assert len(record_keys) <= 5
        prunable_key = limiter._make_key("decrypt_file", "prunable")
        assert prunable_key not in on_disk
        # The most recently touched identifiers should be the ones retained.
        for i in range(6, 10):
            assert limiter._make_key("decrypt_file", f"id-{i}") in on_disk


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
