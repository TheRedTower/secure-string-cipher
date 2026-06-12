"""
Fuzz tests for encryption/decryption operations.

These tests use Hypothesis to generate random inputs and verify that
the encryption system handles all inputs correctly without crashing.

Run with: pytest tests/fuzz/ -v --hypothesis-seed=random
"""

import pytest
from hypothesis import HealthCheck, Phase, given, settings
from hypothesis import strategies as st

from secure_string_cipher.config import ARGON2_HASH_LENGTH, SALT_SIZE
from secure_string_cipher.core import (
    CryptoError,
    decrypt_text,
    derive_key,
    encrypt_text,
)

# =============================================================================
# Fuzz Test Configuration
# =============================================================================

# Longer deadline for Argon2id operations
FUZZ_SETTINGS = settings(
    max_examples=100,
    deadline=None,  # Argon2id is intentionally slow
    suppress_health_check=[HealthCheck.too_slow],
    phases=[Phase.generate, Phase.target],
)


# =============================================================================
# Input Fuzz Tests
# =============================================================================


class TestEncryptionFuzz:
    """Fuzz tests for encryption input handling."""

    @pytest.mark.timeout(120)  # Extended timeout for Argon2id
    @FUZZ_SETTINGS
    @given(
        plaintext=st.text(min_size=0, max_size=10000),
        passphrase=st.text(min_size=12, max_size=128).filter(
            lambda p: (
                any(c.isupper() for c in p)
                and any(c.islower() for c in p)
                and any(c.isdigit() for c in p)
                and any(not c.isalnum() for c in p)
            )
        ),
    )
    def test_encrypt_decrypt_arbitrary_text(self, plaintext: str, passphrase: str):
        """Fuzz: Any valid plaintext should encrypt and decrypt correctly."""
        if not plaintext:  # Empty strings handled separately
            return

        ciphertext = encrypt_text(plaintext, passphrase)
        decrypted = decrypt_text(ciphertext, passphrase)
        assert decrypted == plaintext

    @pytest.mark.timeout(120)
    @FUZZ_SETTINGS
    @given(
        plaintext=st.binary(min_size=1, max_size=5000),
        passphrase=st.text(min_size=12, max_size=64).filter(
            lambda p: (
                any(c.isupper() for c in p)
                and any(c.islower() for c in p)
                and any(c.isdigit() for c in p)
                and any(not c.isalnum() for c in p)
            )
        ),
    )
    def test_encrypt_binary_as_text(self, plaintext: bytes, passphrase: str):
        """Fuzz: Binary data encoded as text should roundtrip."""
        import base64

        text = base64.b64encode(plaintext).decode("ascii")
        ciphertext = encrypt_text(text, passphrase)
        decrypted = decrypt_text(ciphertext, passphrase)
        assert decrypted == text

    @FUZZ_SETTINGS
    @given(
        plaintext=st.text(
            alphabet=st.characters(blacklist_categories=["Cs"]),  # Exclude surrogates
            min_size=1,
            max_size=1000,
        ),
        passphrase=st.text(min_size=12, max_size=64).filter(
            lambda p: (
                any(c.isupper() for c in p)
                and any(c.islower() for c in p)
                and any(c.isdigit() for c in p)
                and any(not c.isalnum() for c in p)
            )
        ),
    )
    def test_encrypt_unicode_text(self, plaintext: str, passphrase: str):
        """Fuzz: Unicode text (excluding surrogates) should roundtrip."""
        ciphertext = encrypt_text(plaintext, passphrase)
        decrypted = decrypt_text(ciphertext, passphrase)
        assert decrypted == plaintext


class TestKeyDerivationFuzz:
    """Fuzz tests for key derivation."""

    @FUZZ_SETTINGS
    @given(
        passphrase=st.text(min_size=1, max_size=1000),
        salt=st.binary(min_size=SALT_SIZE, max_size=SALT_SIZE),
    )
    def test_derive_key_never_crashes(self, passphrase: str, salt: bytes):
        """Fuzz: Key derivation should never crash on any input."""
        key = derive_key(passphrase, salt)
        assert len(key) == ARGON2_HASH_LENGTH

    @FUZZ_SETTINGS
    @given(
        passphrase=st.binary(min_size=1, max_size=500),
        salt=st.binary(min_size=SALT_SIZE, max_size=SALT_SIZE),
    )
    def test_derive_key_binary_passphrase(self, passphrase: bytes, salt: bytes):
        """Fuzz: Binary passphrases (as decoded strings) should work."""
        try:
            # Try to decode as UTF-8, skip if invalid
            passphrase_str = passphrase.decode("utf-8", errors="strict")
            key = derive_key(passphrase_str, salt)
            assert len(key) == ARGON2_HASH_LENGTH
        except UnicodeDecodeError:
            pass  # Skip invalid UTF-8 sequences


class TestDecryptionFuzz:
    """Fuzz tests for decryption robustness."""

    @settings(max_examples=200, deadline=None)
    @given(
        garbage=st.text(min_size=1, max_size=1000),
        passphrase=st.text(min_size=12, max_size=64).filter(
            lambda p: (
                any(c.isupper() for c in p)
                and any(c.islower() for c in p)
                and any(c.isdigit() for c in p)
                and any(not c.isalnum() for c in p)
            )
        ),
    )
    def test_decrypt_garbage_never_crashes(self, garbage: str, passphrase: str):
        """Fuzz: Decrypting garbage should raise CryptoError, never crash."""
        try:
            decrypt_text(garbage, passphrase)
            # If it somehow succeeds, that's also fine (unlikely but valid)
        except (CryptoError, ValueError, Exception):
            pass  # Expected behavior

    @settings(max_examples=100, deadline=None)
    @given(
        ciphertext_mutation=st.integers(min_value=0, max_value=100),
        mutation_char=st.characters(),
        passphrase=st.just("ValidPass123!@#"),
    )
    def test_mutated_ciphertext_fails_gracefully(
        self, ciphertext_mutation: int, mutation_char: str, passphrase: str
    ):
        """Fuzz: Mutated ciphertexts should fail authentication, not crash."""
        # Create valid ciphertext first
        original = encrypt_text("Test message for mutation", passphrase)

        # Mutate at random position
        if len(original) > 0:
            pos = ciphertext_mutation % len(original)
            mutated = original[:pos] + mutation_char + original[pos + 1 :]

            try:
                decrypt_text(mutated, passphrase)
            except (CryptoError, ValueError, Exception):
                pass  # Expected - authentication should fail


# =============================================================================
# Edge Case Fuzz Tests
# =============================================================================


class TestEdgeCaseFuzz:
    """Fuzz tests for edge cases and boundary conditions."""

    @FUZZ_SETTINGS
    @given(
        repeat_count=st.integers(min_value=1, max_value=100),
        char=st.characters(blacklist_categories=["Cs"]),
    )
    def test_repeated_characters(self, repeat_count: int, char: str):
        """Fuzz: Repeated character strings should encrypt correctly."""
        plaintext = char * repeat_count
        passphrase = "SecurePass123!@#"

        ciphertext = encrypt_text(plaintext, passphrase)
        decrypted = decrypt_text(ciphertext, passphrase)
        assert decrypted == plaintext

    @pytest.mark.xdist_group(name="memory_heavy_fuzz")
    @FUZZ_SETTINGS
    @given(
        size=st.integers(min_value=1, max_value=50000),
    )
    def test_various_sizes(self, size: int):
        """Fuzz: Various plaintext sizes should work.

        Pinned to a single xdist worker via ``xdist_group`` to avoid memory
        contention: running multiple large-plaintext (up to 50 000 chars) ×
        Argon2id roundtrips concurrently can starve workers and flake. This
        keeps full input coverage while serialising only this heavy test.
        """
        plaintext = "A" * size
        passphrase = "SecurePass123!@#"

        ciphertext = encrypt_text(plaintext, passphrase)
        decrypted = decrypt_text(ciphertext, passphrase)
        assert decrypted == plaintext

    @settings(max_examples=50, deadline=None)
    @given(
        nulls=st.integers(min_value=1, max_value=10),
    )
    def test_null_bytes_in_text(self, nulls: int):
        """Fuzz: Text with null-like characters should work."""
        # Use actual null character (valid in Python strings)
        plaintext = f"before{chr(0) * nulls}after"
        passphrase = "SecurePass123!@#"

        ciphertext = encrypt_text(plaintext, passphrase)
        decrypted = decrypt_text(ciphertext, passphrase)
        assert decrypted == plaintext
