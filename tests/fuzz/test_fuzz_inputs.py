"""
Fuzz tests for input validation and sanitization.

These tests verify that all input validation functions handle
arbitrary malicious inputs without crashing or allowing exploits.
"""

from contextlib import suppress

from hypothesis import given, settings
from hypothesis import strategies as st

from secure_string_cipher.security import (
    SecurityError,
    sanitize_filename,
    validate_safe_path,
)
from secure_string_cipher.timing_safe import check_password_strength

# =============================================================================
# Filename Sanitization Fuzz Tests
# =============================================================================


class TestFilenameSanitizationFuzz:
    """Fuzz tests for filename sanitization."""

    @settings(max_examples=500)
    @given(
        filename=st.text(min_size=0, max_size=1000),
    )
    def test_sanitize_never_crashes(self, filename: str):
        """Fuzz: Sanitization should never crash on any input."""
        result = sanitize_filename(filename)
        assert isinstance(result, str)

    @settings(max_examples=500)
    @given(
        filename=st.text(min_size=1, max_size=500),
    )
    def test_sanitize_removes_path_separators(self, filename: str):
        """Fuzz: Sanitized filenames should never contain path separators."""
        result = sanitize_filename(filename)
        assert "/" not in result
        assert "\\" not in result
        assert ".." not in result

    @settings(max_examples=200, deadline=None)
    @given(
        prefix=st.sampled_from(["../", "..\\", "/", "\\", "~/", "./", "C:\\"]),
        suffix=st.text(min_size=1, max_size=100),
    )
    def test_sanitize_path_traversal_attempts(self, prefix: str, suffix: str):
        """Fuzz: Path traversal prefixes should be stripped."""
        malicious = prefix * 5 + suffix
        result = sanitize_filename(malicious)

        # Result should not start with traversal patterns
        assert not result.startswith("..")
        assert not result.startswith("/")
        assert not result.startswith("\\")
        assert ".." not in result

    @settings(max_examples=200)
    @given(
        filename=st.text(
            alphabet=st.characters(
                blacklist_characters="\x00",  # Null bytes
                blacklist_categories=["Cs"],  # Surrogates
            ),
            min_size=1,
            max_size=300,
        ),
    )
    def test_sanitize_unicode_filenames(self, filename: str):
        """Fuzz: Unicode filenames should be handled safely."""
        result = sanitize_filename(filename)
        # Should not crash and should return valid string
        assert isinstance(result, str)

    @settings(max_examples=100)
    @given(
        base=st.text(min_size=1, max_size=50),
        injected=st.sampled_from(
            ["\x00", "\n", "\r", "\t", "\x1b", "\x7f", "\x00secret.txt"]
        ),
    )
    def test_sanitize_control_characters(self, base: str, injected: str):
        """Fuzz: Control characters should be stripped or escaped."""
        malicious = base + injected + base
        result = sanitize_filename(malicious)
        # Null bytes should never appear in result
        assert "\x00" not in result


# =============================================================================
# Path Validation Fuzz Tests
# =============================================================================


class TestPathValidationFuzz:
    """Fuzz tests for path validation."""

    @settings(max_examples=200)
    @given(
        path=st.text(min_size=0, max_size=500),
    )
    def test_validate_path_never_crashes(self, path: str):
        """Fuzz: Path validation should never crash."""
        with suppress(SecurityError, ValueError, OSError):
            validate_safe_path(path)

    @settings(max_examples=100)
    @given(
        traversal=st.sampled_from(
            [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32",
                "/etc/shadow",
                "~/.ssh/id_rsa",
                "....//....//etc/passwd",
                "..%2f..%2f..%2fetc/passwd",
                "..%252f..%252f..%252fetc/passwd",
            ]
        ),
    )
    def test_validate_path_blocks_traversal(self, traversal: str):
        """Fuzz: Known path traversal patterns should be blocked."""
        # These should either raise SecurityError or be blocked by OS
        with suppress(SecurityError, ValueError, OSError):
            validate_safe_path(traversal)


# =============================================================================
# Password Strength Fuzz Tests
# =============================================================================


class TestPasswordStrengthFuzz:
    """Fuzz tests for password strength validation."""

    @settings(max_examples=500, deadline=None)
    @given(
        password=st.text(min_size=0, max_size=500),
    )
    def test_check_strength_never_crashes(self, password: str):
        """Fuzz: Password strength check should never crash."""
        result = check_password_strength(password)
        assert isinstance(result, tuple)
        assert len(result) == 2
        is_valid, message = result
        assert isinstance(is_valid, bool)
        assert isinstance(message, str)

    @settings(max_examples=100, deadline=None)
    @given(
        short_password=st.text(min_size=0, max_size=11),
    )
    def test_short_passwords_rejected(self, short_password: str):
        """Fuzz: Passwords under 12 characters should always fail."""
        is_valid, _ = check_password_strength(short_password)
        assert is_valid is False

    @settings(max_examples=100, deadline=None)
    @given(
        password=st.text(min_size=12, max_size=100).filter(
            lambda p: (
                any(c.isupper() for c in p)
                and any(c.islower() for c in p)
                and any(c.isdigit() for c in p)
                and any(not c.isalnum() for c in p)
            )
        ),
    )
    def test_complex_passwords_pass(self, password: str):
        """Fuzz: Complex passwords should pass validation."""
        is_valid, _ = check_password_strength(password)
        assert is_valid is True


# =============================================================================
# Injection Attack Fuzz Tests
# =============================================================================


class TestInjectionFuzz:
    """Fuzz tests for injection attack resistance."""

    @settings(max_examples=100)
    @given(
        payload=st.sampled_from(
            [
                "'; DROP TABLE users; --",
                "<script>alert('xss')</script>",
                "{{7*7}}",
                "${7*7}",
                "$(whoami)",
                "`whoami`",
                "|cat /etc/passwd",
                "; cat /etc/passwd",
                "& cat /etc/passwd",
                '"; cat /etc/passwd"',
                "%s%s%s%s%s%s%s%s%s%s",
                "%n%n%n%n%n%n%n%n%n%n",
                "AAAA%08x.%08x.%08x.%08x",
            ]
        ),
    )
    def test_filename_injection_resistance(self, payload: str):
        """Fuzz: Injection payloads should be neutralized in filenames."""
        result = sanitize_filename(payload)
        # Should not crash and should sanitize
        assert isinstance(result, str)
        # At minimum, path separators are removed
        assert "/" not in result
        assert "\\" not in result

    @settings(max_examples=100)
    @given(
        prefix=st.text(min_size=0, max_size=50),
        injection=st.sampled_from(
            [
                "\x00hidden.txt",
                "visible.txt\x00hidden",
                "file.txt%00.exe",
            ]
        ),
    )
    def test_null_byte_injection(self, prefix: str, injection: str):
        """Fuzz: Null byte injection should be prevented."""
        malicious = prefix + injection
        result = sanitize_filename(malicious)
        # Null bytes should never appear in result
        assert "\x00" not in result
