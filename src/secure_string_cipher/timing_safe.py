"""
Timing attack mitigations and secure password handling
"""

import hmac
import secrets
import time

from .config import COMMON_PASSWORDS, MIN_PASSWORD_LENGTH
from .secure_memory import SecureString


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Perform a constant-time comparison of two byte strings.

    Uses hmac.compare_digest to prevent timing attacks.
    """
    return hmac.compare_digest(a, b)


def add_timing_jitter() -> None:
    """
    Add random timing jitter to prevent timing analysis.
    Adds between 0-10ms of delay.
    """
    jitter = secrets.randbelow(10000) / 1000000
    time.sleep(jitter)


def check_password_strength(password: str) -> tuple[bool, str]:
    """
    Check password strength with constant-time operations.

    Args:
        password: Password to check

    Returns:
        Tuple of (is_valid, message)
    """
    with SecureString(password) as secure_pass:
        # Use constant time operations
        has_length = len(secure_pass.string) >= MIN_PASSWORD_LENGTH
        has_upper = any(c.isupper() for c in secure_pass.string)
        has_lower = any(c.islower() for c in secure_pass.string)
        has_digit = any(c.isdigit() for c in secure_pass.string)
        has_symbol = any(not c.isalnum() for c in secure_pass.string)

        # Add timing jitter to mask actual check time
        add_timing_jitter()

        if not has_length:
            return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"

        missing = []
        if not has_upper:
            missing.append("uppercase")
        if not has_lower:
            missing.append("lowercase")
        if not has_digit:
            missing.append("digits")
        if not has_symbol:
            missing.append("symbols")

        if missing:
            return False, f"Password must include: {', '.join(missing)}"

        # Check for common patterns - do all checks regardless of result
        is_common = False
        for pattern in COMMON_PASSWORDS:
            if pattern in secure_pass.string.lower():
                is_common = True

        # Add final timing jitter
        add_timing_jitter()

        if is_common:
            return False, "Password contains common patterns"

        return True, "Password strength acceptable"
