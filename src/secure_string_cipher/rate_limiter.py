"""
Rate limiting module to prevent brute-force attacks.

Provides configurable rate limiting for sensitive operations like:
- Vault unlock attempts
- Decryption attempts
- Password verification

Uses exponential backoff to slow down repeated failures.
"""

import threading
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import wraps
from typing import ParamSpec, TypeVar

from .config import (
    RATE_LIMIT_BACKOFF_MULTIPLIER,
    RATE_LIMIT_LOCKOUT_SECONDS,
    RATE_LIMIT_MAX_ATTEMPTS,
    RATE_LIMIT_WINDOW_SECONDS,
)


@dataclass
class AttemptRecord:
    """Record of attempts for a specific operation/key."""

    attempts: list[float] = field(default_factory=list)
    lockout_until: float = 0.0
    consecutive_failures: int = 0


P = ParamSpec("P")
R = TypeVar("R")


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

            # Check if currently locked out
            if now < record.lockout_until:
                return False, record.lockout_until - now

            # Clean up old attempts
            self._cleanup_old_attempts(record, now)

            # Check attempt count
            if len(record.attempts) >= self.max_attempts:
                # Calculate lockout with exponential backoff
                lockout_duration = self.lockout_seconds * (
                    self.backoff_multiplier**record.consecutive_failures
                )
                record.lockout_until = now + lockout_duration
                record.consecutive_failures += 1
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
                try:
                    identifier = get_identifier(*args, **kwargs)
                except Exception:
                    pass

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
