"""
Rate limiting module to slow repeated local authentication attempts.

Provides configurable rate limiting for sensitive operations like:
- Vault unlock attempts
- Decryption attempts
- Password verification

Uses exponential backoff to slow down repeated failures.
"""

import hashlib
import hmac
import json
import math
import os
import secrets
import sys
import tempfile
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from functools import wraps
from typing import ParamSpec, TypeVar

from .config import (
    RATE_LIMIT_BACKOFF_MULTIPLIER,
    RATE_LIMIT_LOCKOUT_SECONDS,
    RATE_LIMIT_MAX_ATTEMPTS,
    RATE_LIMIT_WINDOW_SECONDS,
    get_config_dir,
)


@dataclass
class AttemptRecord:
    """Record of attempts for a specific operation/key."""

    attempts: list[float] = field(default_factory=list)
    lockout_until: float = 0.0
    consecutive_failures: int = 0
    # Wall-clock time this record was last touched by a check/attempt. Not
    # security-critical (only used to choose eviction order), so a missing or
    # malformed value on load defaults to 0.0 rather than discarding the record.
    last_seen: float = 0.0


P = ParamSpec("P")
R = TypeVar("R")

# Bounds untrusted exponentiation while remaining well beyond a practical lockout.
_MAX_PERSISTED_CONSECUTIVE_FAILURES = 1_000

# Reserved on-disk key holding the per-installation salt used to derive
# PersistentRateLimiter's stored keys; never treated as an attempt record.
_SALT_KEY = "__salt__"
_SALT_BYTES = 32

# Hard cap on persisted records, enforced on save: once exceeded, the
# least-recently-touched records are evicted first. Bounds on-disk growth
# regardless of how many distinct operations/identifiers are ever seen.
_MAX_PERSISTED_RECORDS = 500


def _nonnegative_finite_float(value: object) -> float | None:
    """Normalize an untrusted JSON number without allowing bools or overflow."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None

    try:
        normalized = float(value)
    except (OverflowError, ValueError):
        return None

    if not math.isfinite(normalized) or normalized < 0:
        return None
    return normalized


class RateLimiter:
    """Thread-safe rate limiter with exponential backoff.

    Tracks failed attempts by operation type and key (e.g., vault path),
    implementing progressive delays to deter brute-force attacks.
    """

    def __init__(
        self,
        max_attempts: int = RATE_LIMIT_MAX_ATTEMPTS,
        window_seconds: float = RATE_LIMIT_WINDOW_SECONDS,
        lockout_seconds: float = RATE_LIMIT_LOCKOUT_SECONDS,
        backoff_multiplier: float = RATE_LIMIT_BACKOFF_MULTIPLIER,
    ):
        """Initialize the rate limiter.

        Args:
            max_attempts: Maximum attempts allowed within the time window
            window_seconds: Time window for counting attempts (seconds)
            lockout_seconds: Base lockout duration after exceeding max attempts
            backoff_multiplier: Multiplier for exponential backoff on repeated lockouts
        """
        self._records: dict[str, AttemptRecord] = defaultdict(AttemptRecord)
        self._lock = threading.Lock()
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self.backoff_multiplier = backoff_multiplier

    def _make_key(self, operation: str, identifier: str = "") -> str:
        """Create a unique key for tracking attempts."""
        return f"{operation}:{identifier}"

    def _cleanup_old_attempts(self, record: AttemptRecord, now: float) -> None:
        """Remove attempts outside the current time window."""
        cutoff = now - self.window_seconds
        record.attempts = [t for t in record.attempts if t > cutoff]

    def _lockout_duration(self, failures: int) -> float | None:
        """Return a finite duration, or None when the backoff cannot be represented."""
        try:
            duration = self.lockout_seconds * (
                self.backoff_multiplier
                ** min(failures, _MAX_PERSISTED_CONSECUTIVE_FAILURES)
            )
        except (OverflowError, ValueError, ZeroDivisionError):
            return None
        return _nonnegative_finite_float(duration)

    def check_rate_limit(
        self, operation: str, identifier: str = ""
    ) -> tuple[bool, float]:
        """Check if an operation is rate limited.

        Args:
            operation: Type of operation (e.g., "vault_unlock", "decrypt")
            identifier: Optional identifier (e.g., vault path, file path)

        Returns:
            Tuple of (is_allowed, wait_seconds)
            - is_allowed: True if operation can proceed
            - wait_seconds: Seconds to wait if blocked (0 if allowed)
        """
        key = self._make_key(operation, identifier)
        now = time.time()

        with self._lock:
            record = self._records[key]
            record.last_seen = now

            # Check if currently locked out
            if now < record.lockout_until:
                return False, record.lockout_until - now

            # Clean up old attempts
            self._cleanup_old_attempts(record, now)

            # Check attempt count
            if len(record.attempts) >= self.max_attempts:
                lockout_duration = self._lockout_duration(record.consecutive_failures)
                if lockout_duration is None:
                    # Keep an unrepresentable escalation finite and fail closed.
                    # The prior counter remains valid when this record is reloaded.
                    record.lockout_until = sys.float_info.max
                    return False, record.lockout_until - now

                record.lockout_until = min(now + lockout_duration, sys.float_info.max)
                record.consecutive_failures = min(
                    record.consecutive_failures + 1,
                    _MAX_PERSISTED_CONSECUTIVE_FAILURES,
                )
                return False, lockout_duration

            return True, 0.0

    def record_attempt(
        self, operation: str, identifier: str = "", success: bool = False
    ) -> None:
        """Record an attempt for rate limiting purposes.

        Args:
            operation: Type of operation
            identifier: Optional identifier
            success: Whether the attempt succeeded (resets consecutive failures)
        """
        key = self._make_key(operation, identifier)
        now = time.time()

        with self._lock:
            record = self._records[key]
            record.last_seen = now

            if success:
                # Reset on success
                record.attempts.clear()
                record.consecutive_failures = 0
                record.lockout_until = 0.0
            else:
                # Record failed attempt
                record.attempts.append(now)

    def get_remaining_attempts(self, operation: str, identifier: str = "") -> int:
        """Get the number of remaining attempts before lockout.

        Args:
            operation: Type of operation
            identifier: Optional identifier

        Returns:
            Number of remaining attempts (0 if locked out)
        """
        key = self._make_key(operation, identifier)
        now = time.time()

        with self._lock:
            record = self._records[key]

            if now < record.lockout_until:
                return 0

            self._cleanup_old_attempts(record, now)
            return max(0, self.max_attempts - len(record.attempts))

    def reset(self, operation: str, identifier: str = "") -> None:
        """Reset rate limiting for a specific operation/identifier.

        Args:
            operation: Type of operation
            identifier: Optional identifier
        """
        key = self._make_key(operation, identifier)

        with self._lock:
            if key in self._records:
                del self._records[key]

    def reset_all(self) -> None:
        """Reset all rate limiting records."""
        with self._lock:
            self._records.clear()


class PersistentRateLimiter(RateLimiter):
    """Rate limiter that persists attempts across CLI processes.

    Persisted keys are salted-HMAC hashes of ``f"{operation}:{identifier}"``,
    not the plaintext identifier: the state file otherwise accumulates an
    unbounded, human-readable history of every vault label and file path ever
    attempted. The salt is generated once and stored alongside the records
    (reserved key ``__salt__``) so the same identifier maps to the same
    on-disk key across process restarts, without that mapping being
    reversible by anyone who only has the state file.
    """

    def __init__(
        self,
        state_path: str | None = None,
        max_attempts: int = RATE_LIMIT_MAX_ATTEMPTS,
        window_seconds: float = RATE_LIMIT_WINDOW_SECONDS,
        lockout_seconds: float = RATE_LIMIT_LOCKOUT_SECONDS,
        backoff_multiplier: float = RATE_LIMIT_BACKOFF_MULTIPLIER,
    ):
        super().__init__(
            max_attempts=max_attempts,
            window_seconds=window_seconds,
            lockout_seconds=lockout_seconds,
            backoff_multiplier=backoff_multiplier,
        )
        if state_path is None:
            state_path = str(get_config_dir() / "rate_limits.json")
        self.state_path = state_path
        # Fallback for a fresh or unreadable state file; _load_state below
        # overwrites this with the persisted salt when one is found on disk.
        self._salt = secrets.token_bytes(_SALT_BYTES)
        self._load_state()

    def _make_key(self, operation: str, identifier: str = "") -> str:
        """Salted-hash the identifier; keep the operation name as a readable prefix."""
        raw = f"{operation}:{identifier}".encode()
        digest = hmac.new(self._salt, raw, hashlib.sha256).hexdigest()[:32]
        return f"{operation}:{digest}"

    def _load_state(self) -> None:
        """Load persisted rate-limit state."""
        try:
            with open(self.state_path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError, OverflowError):
            return

        if not isinstance(data, dict):
            return

        loaded_salt: bytes | None = None
        raw_salt = data.get(_SALT_KEY)
        if isinstance(raw_salt, str):
            with suppress(ValueError):
                candidate = bytes.fromhex(raw_salt)
                if len(candidate) == _SALT_BYTES:
                    loaded_salt = candidate

        loaded_records: dict[str, AttemptRecord] = {}
        for key, value in data.items():
            if key == _SALT_KEY:
                continue
            if not isinstance(key, str) or not isinstance(value, dict):
                continue

            attempts_value = value.get("attempts", [])
            if not isinstance(attempts_value, list):
                attempts_value = []
            attempts = []
            for timestamp in attempts_value:
                normalized_timestamp = _nonnegative_finite_float(timestamp)
                if normalized_timestamp is not None:
                    attempts.append(normalized_timestamp)

            lockout_value = value.get("lockout_until", 0.0)
            failures_value = value.get("consecutive_failures", 0)
            lockout_until = _nonnegative_finite_float(lockout_value)
            if (
                lockout_until is None
                or not isinstance(failures_value, int)
                or isinstance(failures_value, bool)
                or failures_value < 0
            ):
                continue

            last_seen = _nonnegative_finite_float(value.get("last_seen", 0.0)) or 0.0

            loaded_records[key] = AttemptRecord(
                attempts=attempts,
                lockout_until=lockout_until,
                consecutive_failures=min(
                    failures_value, _MAX_PERSISTED_CONSECUTIVE_FAILURES
                ),
                last_seen=last_seen,
            )

        with self._lock:
            self._records.clear()
            self._records.update(loaded_records)
            if loaded_salt is not None:
                self._salt = loaded_salt

    def _prune_locked(self, now: float) -> None:
        """Evict records under `self._lock`; caller must already hold it.

        First drops any record that is fully expired and carries no
        escalation state (safe: behaviorally indistinguishable from never
        having existed). If the count is still over the cap, evicts the
        least-recently-touched remaining records until it isn't — a coarser
        bound that accepts losing some escalation memory for records that
        have been quiet a long time, in exchange for a hard growth limit.
        """
        for key in list(self._records.keys()):
            record = self._records[key]
            self._cleanup_old_attempts(record, now)
            if (
                not record.attempts
                and record.consecutive_failures == 0
                and now >= record.lockout_until
            ):
                del self._records[key]

        overflow = len(self._records) - _MAX_PERSISTED_RECORDS
        if overflow > 0:
            oldest_keys = sorted(
                self._records, key=lambda k: self._records[k].last_seen
            )[:overflow]
            for key in oldest_keys:
                del self._records[key]

    def _save_state(self) -> None:
        """Persist rate-limit state atomically."""
        state_file = os.path.abspath(self.state_path)
        state_dir = os.path.dirname(state_file)
        try:
            os.makedirs(state_dir, mode=0o700, exist_ok=True)
        except OSError:
            return

        with self._lock:
            self._prune_locked(time.time())
            data: dict[str, object] = {
                key: {
                    "attempts": record.attempts,
                    "lockout_until": record.lockout_until,
                    "consecutive_failures": record.consecutive_failures,
                    "last_seen": record.last_seen,
                }
                for key, record in self._records.items()
            }
            data[_SALT_KEY] = self._salt.hex()

        try:
            fd, temp_path = tempfile.mkstemp(
                prefix=f".{os.path.basename(state_file)}.",
                suffix=".tmp",
                dir=state_dir,
            )
        except OSError:
            return
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, separators=(",", ":"))
                f.write("\n")
            os.chmod(temp_path, 0o600)
            os.replace(temp_path, state_file)
        except Exception:
            with suppress(OSError):
                os.unlink(temp_path)
            raise

    def check_rate_limit(
        self, operation: str, identifier: str = ""
    ) -> tuple[bool, float]:
        """Check if an operation is rate limited after loading persisted state."""
        self._load_state()
        result = super().check_rate_limit(operation, identifier)
        self._save_state()
        return result

    def record_attempt(
        self, operation: str, identifier: str = "", success: bool = False
    ) -> None:
        """Record and persist an attempt."""
        self._load_state()
        super().record_attempt(operation, identifier, success)
        self._save_state()

    def reset(self, operation: str, identifier: str = "") -> None:
        """Reset and persist a specific operation/identifier."""
        self._load_state()
        super().reset(operation, identifier)
        self._save_state()

    def reset_all(self) -> None:
        """Reset and persist all records."""
        super().reset_all()
        self._save_state()


class RateLimitError(Exception):
    """Raised when an operation is rate limited."""

    def __init__(self, wait_seconds: float, message: str | None = None):
        self.wait_seconds = wait_seconds
        if message is None:
            message = f"Rate limited. Please wait {wait_seconds:.1f} seconds."
        super().__init__(message)


def rate_limited(
    operation: str,
    limiter: RateLimiter | None = None,
    get_identifier: Callable[..., str] | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator to apply rate limiting to a function.

    Args:
        operation: Name of the operation for tracking
        limiter: RateLimiter instance (uses global default if None)
        get_identifier: Function to extract identifier from args/kwargs

    Returns:
        Decorated function with rate limiting

    Example:
        @rate_limited("vault_unlock", get_identifier=lambda vault_path, **kw: vault_path)
        def unlock_vault(vault_path: str, password: str) -> dict:
            ...
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            nonlocal limiter
            if limiter is None:
                limiter = _global_limiter

            # Get identifier from arguments
            identifier = ""
            if get_identifier is not None:
                with suppress(Exception):
                    identifier = get_identifier(*args, **kwargs)

            # Check rate limit
            allowed, wait_time = limiter.check_rate_limit(operation, identifier)
            if not allowed:
                raise RateLimitError(wait_time)

            # Execute function
            try:
                result = func(*args, **kwargs)
                limiter.record_attempt(operation, identifier, success=True)
                return result
            except Exception:
                limiter.record_attempt(operation, identifier, success=False)
                raise

        return wrapper

    return decorator


# Global rate limiter instance
_global_limiter = RateLimiter()


def get_global_limiter() -> RateLimiter:
    """Get the global rate limiter instance."""
    return _global_limiter
