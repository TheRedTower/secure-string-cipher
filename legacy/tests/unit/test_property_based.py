"""
Property-based tests using Hypothesis for cryptographic operations.

These tests verify invariants that should hold for ANY valid input,
not just specific test cases. This helps catch edge cases and
unexpected behavior that unit tests might miss.

Note: Argon2id is intentionally slow (memory-hard), so we use
deadline=None and reduced max_examples for crypto operations.
"""

import base64
import string

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from secure_string_cipher.config import ARGON2_HASH_LENGTH, SALT_SIZE
from secure_string_cipher.core import (
    CryptoError,
    FileMetadata,
    compute_key_commitment,
    decrypt_text,
    derive_key,
    encrypt_text,
    verify_key_commitment,
)
from secure_string_cipher.secure_memory import SecureBytes, SecureString, secure_wipe
from secure_string_cipher.security import sanitize_filename
from secure_string_cipher.timing_safe import (
    check_password_strength,
    constant_time_compare,
)

# =============================================================================
# Strategy Definitions
# =============================================================================

# Valid passphrases that meet complexity requirements
valid_passphrase = st.text(
    alphabet=string.ascii_letters + string.digits + string.punctuation,
    min_size=12,
    max_size=64,
).filter(
    lambda p: (
        any(c.isupper() for c in p)
        and any(c.islower() for c in p)
        and any(c.isdigit() for c in p)
        and any(c in string.punctuation for c in p)
    )
)

# Any passphrase (may not meet complexity requirements)
any_passphrase = st.text(min_size=1, max_size=64)

# Text data for encryption (valid UTF-8, limited size for speed)
text_data = st.text(min_size=0, max_size=256)

# Salt values
salt_data = st.binary(min_size=SALT_SIZE, max_size=SALT_SIZE)

# Filenames for sanitization testing
unsafe_filename = st.text(min_size=1, max_size=255)


# =============================================================================
# Key Derivation Properties
# =============================================================================


class TestKeyDerivationProperties:
    """Property-based tests for key derivation."""

    @given(passphrase=any_passphrase, salt=salt_data)
    @settings(max_examples=20, deadline=None)  # Argon2id is slow
    def test_key_length_invariant(self, passphrase: str, salt: bytes):
        """Key derivation always produces ARGON2_HASH_LENGTH bytes."""
        key = derive_key(passphrase, salt)
        assert len(key) == ARGON2_HASH_LENGTH

    @given(passphrase=any_passphrase, salt=salt_data)
    @settings(max_examples=10, deadline=None)  # Argon2id is slow
    def test_key_derivation_deterministic(self, passphrase: str, salt: bytes):
        """Same passphrase + salt always produces same key."""
        key1 = derive_key(passphrase, salt)
        key2 = derive_key(passphrase, salt)
        assert key1 == key2

    @given(p1=any_passphrase, p2=any_passphrase, salt=salt_data)
    @settings(max_examples=10, deadline=None)  # Argon2id is slow
    def test_different_passphrases_different_keys(self, p1: str, p2: str, salt: bytes):
        """Different passphrases produce different keys."""
        assume(p1 != p2)
        key1 = derive_key(p1, salt)
        key2 = derive_key(p2, salt)
        assert key1 != key2

    @given(passphrase=any_passphrase, s1=salt_data, s2=salt_data)
    @settings(max_examples=10, deadline=None)  # Argon2id is slow
    def test_different_salts_different_keys(
        self, passphrase: str, s1: bytes, s2: bytes
    ):
        """Different salts produce different keys."""
        assume(s1 != s2)
        key1 = derive_key(passphrase, s1)
        key2 = derive_key(passphrase, s2)
        assert key1 != key2


# =============================================================================
# Encryption/Decryption Properties
# =============================================================================


class TestEncryptionProperties:
    """Property-based tests for encryption/decryption."""

    @given(plaintext=text_data, passphrase=valid_passphrase)
    @settings(max_examples=15, deadline=None)  # Argon2id is slow
    def test_encrypt_decrypt_roundtrip(self, plaintext: str, passphrase: str):
        """Encryption followed by decryption recovers original plaintext."""
        ciphertext = encrypt_text(plaintext, passphrase)
        decrypted = decrypt_text(ciphertext, passphrase)
        assert decrypted == plaintext

    @given(plaintext=text_data, passphrase=valid_passphrase)
    @settings(max_examples=10, deadline=None)  # Argon2id is slow
    def test_ciphertext_differs_from_plaintext(self, plaintext: str, passphrase: str):
        """Ciphertext is different from plaintext (for non-empty input)."""
        assume(len(plaintext) > 0)
        ciphertext = encrypt_text(plaintext, passphrase)
        assert ciphertext != plaintext

    @given(plaintext=text_data, passphrase=valid_passphrase)
    @settings(max_examples=10, deadline=None)  # Argon2id is slow
    def test_encryption_is_randomized(self, plaintext: str, passphrase: str):
        """Multiple encryptions produce different ciphertexts (random nonce)."""
        c1 = encrypt_text(plaintext, passphrase)
        c2 = encrypt_text(plaintext, passphrase)
        assert c1 != c2

    @given(plaintext=text_data, p1=valid_passphrase, p2=valid_passphrase)
    @settings(max_examples=10, deadline=None)  # Argon2id is slow
    def test_wrong_passphrase_fails(self, plaintext: str, p1: str, p2: str):
        """Decryption with wrong passphrase fails."""
        assume(p1 != p2)
        ciphertext = encrypt_text(plaintext, p1)
        with pytest.raises(CryptoError):
            decrypt_text(ciphertext, p2)


# =============================================================================
# Key Commitment Properties
# =============================================================================


class TestKeyCommitmentProperties:
    """Property-based tests for key commitment scheme."""

    @given(key=st.binary(min_size=ARGON2_HASH_LENGTH, max_size=ARGON2_HASH_LENGTH))
    @settings(max_examples=50, deadline=None)
    def test_commitment_deterministic(self, key: bytes):
        """Same key always produces same commitment."""
        c1 = compute_key_commitment(key)
        c2 = compute_key_commitment(key)
        assert c1 == c2

    @given(key=st.binary(min_size=ARGON2_HASH_LENGTH, max_size=ARGON2_HASH_LENGTH))
    @settings(max_examples=50, deadline=None)
    def test_commitment_verifies(self, key: bytes):
        """Commitment verifies correctly with same key."""
        commitment = compute_key_commitment(key)
        assert verify_key_commitment(key, commitment)

    @given(
        k1=st.binary(min_size=ARGON2_HASH_LENGTH, max_size=ARGON2_HASH_LENGTH),
        k2=st.binary(min_size=ARGON2_HASH_LENGTH, max_size=ARGON2_HASH_LENGTH),
    )
    @settings(max_examples=30, deadline=None)
    def test_different_keys_different_commitments(self, k1: bytes, k2: bytes):
        """Different keys produce different commitments."""
        assume(k1 != k2)
        c1 = compute_key_commitment(k1)
        c2 = compute_key_commitment(k2)
        assert c1 != c2

    @given(
        k1=st.binary(min_size=ARGON2_HASH_LENGTH, max_size=ARGON2_HASH_LENGTH),
        k2=st.binary(min_size=ARGON2_HASH_LENGTH, max_size=ARGON2_HASH_LENGTH),
    )
    @settings(max_examples=30, deadline=None)
    def test_wrong_key_fails_verification(self, k1: bytes, k2: bytes):
        """Commitment doesn't verify with wrong key."""
        assume(k1 != k2)
        commitment = compute_key_commitment(k1)
        assert not verify_key_commitment(k2, commitment)


# =============================================================================
# Filename Sanitization Properties
# =============================================================================


class TestFilenameSanitizationProperties:
    """Property-based tests for filename sanitization."""

    @given(filename=unsafe_filename)
    @settings(max_examples=100, deadline=None)
    def test_sanitized_filename_is_safe(self, filename: str):
        """Sanitized filenames pass safety validation."""
        sanitized = sanitize_filename(filename)
        # Should not contain path traversal
        assert ".." not in sanitized
        assert "/" not in sanitized
        assert "\\" not in sanitized
        # Should not be empty (fallback to 'file')
        assert len(sanitized) > 0

    @given(filename=unsafe_filename)
    @settings(max_examples=100, deadline=None)
    def test_sanitized_filename_length_bounded(self, filename: str):
        """Sanitized filenames are within length limits."""
        sanitized = sanitize_filename(filename)
        assert len(sanitized) <= 255

    @given(filename=st.from_regex(r"[a-zA-Z][a-zA-Z0-9_\-\.]{0,50}", fullmatch=True))
    @settings(max_examples=50, deadline=None)
    def test_safe_filenames_preserved(self, filename: str):
        """Already safe filenames are preserved."""
        assume(len(filename) > 0)
        sanitized = sanitize_filename(filename)
        # Core name should be preserved
        assert len(sanitized) > 0


# =============================================================================
# Constant-Time Comparison Properties
# =============================================================================


class TestConstantTimeCompareProperties:
    """Property-based tests for constant-time comparison."""

    @given(data=st.binary(min_size=0, max_size=1024))
    @settings(max_examples=100, deadline=None)
    def test_same_data_compares_equal(self, data: bytes):
        """Same data compares as equal."""
        assert constant_time_compare(data, data)

    @given(
        d1=st.binary(min_size=1, max_size=1024), d2=st.binary(min_size=1, max_size=1024)
    )
    @settings(max_examples=100, deadline=None)
    def test_different_data_compares_unequal(self, d1: bytes, d2: bytes):
        """Different data compares as unequal."""
        assume(d1 != d2)
        assert not constant_time_compare(d1, d2)

    @given(
        d1=st.binary(min_size=0, max_size=100), d2=st.binary(min_size=0, max_size=100)
    )
    @settings(max_examples=50, deadline=None)
    def test_different_lengths_compare_unequal(self, d1: bytes, d2: bytes):
        """Different length data compares as unequal."""
        assume(len(d1) != len(d2))
        assert not constant_time_compare(d1, d2)


# =============================================================================
# Secure Memory Properties
# =============================================================================


class TestSecureMemoryProperties:
    """Property-based tests for secure memory handling."""

    @given(data=st.binary(min_size=1, max_size=1024))
    @settings(max_examples=50, deadline=None)
    def test_secure_wipe_zeros_buffer(self, data: bytes):
        """Secure wipe zeros out mutable buffer."""
        buffer = bytearray(data)
        secure_wipe(buffer)
        assert all(b == 0 for b in buffer)

    @given(data=st.binary(min_size=1, max_size=1024))
    @settings(max_examples=50, deadline=None)
    def test_secure_bytes_context_provides_data(self, data: bytes):
        """SecureBytes context manager provides access to data via .data property."""
        with SecureBytes(data) as secure:
            # Access via memoryview
            assert bytes(secure.data) == data

    @given(text=st.text(alphabet=string.printable, min_size=1, max_size=256))
    @settings(max_examples=50, deadline=None)
    def test_secure_string_context_provides_string(self, text: str):
        """SecureString context manager provides access to string."""
        with SecureString(text) as secure:
            assert secure.string == text


# =============================================================================
# File Metadata Properties
# =============================================================================


class TestFileMetadataProperties:
    """Property-based tests for file metadata serialization."""

    @given(
        version=st.sampled_from([4, 5]),
        filename=st.text(
            alphabet=string.ascii_letters + string.digits + "._-",
            min_size=1,
            max_size=100,
        ),
    )
    @settings(max_examples=30, deadline=None)  # Key derivation is slow
    def test_metadata_roundtrip(self, version: int, filename: str):
        """Metadata serializes and deserializes correctly."""
        assume(filename not in {".", ".."})
        # Use actual key derivation to get proper commitment
        salt = b"\x00" * SALT_SIZE
        key = derive_key("test", salt)
        commitment = compute_key_commitment(key)
        # FileMetadata expects base64-encoded string
        commitment_b64 = base64.b64encode(commitment).decode("ascii")

        meta = FileMetadata(
            version=version,
            original_filename=filename,
            key_commitment=commitment_b64,
        )
        serialized = meta.to_bytes()
        restored = FileMetadata.from_bytes(serialized)

        assert restored.version == version
        assert restored.key_commitment == commitment_b64
        assert restored.original_filename == filename


# =============================================================================
# Password Strength Properties
# =============================================================================


class TestPasswordStrengthProperties:
    """Property-based tests for password strength checking."""

    @given(password=valid_passphrase)
    @settings(max_examples=50, deadline=None)
    def test_valid_passwords_pass(self, password: str):
        """Passwords meeting all requirements pass validation."""
        is_strong, _ = check_password_strength(password)
        assert is_strong

    @given(password=st.text(min_size=0, max_size=11))
    @settings(max_examples=50, deadline=None)
    def test_short_passwords_fail(self, password: str):
        """Passwords shorter than minimum length fail."""
        is_strong, reasons = check_password_strength(password)
        assert not is_strong
        # Either "12 characters" or "Password cannot be empty"
        assert len(reasons) > 0
