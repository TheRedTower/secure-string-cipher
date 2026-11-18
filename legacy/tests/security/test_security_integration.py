"""
Security integration tests for memory handling in crypto operations.

Tests verify:
- Key derivation cleans up passphrase material
- Encryption/decryption handles sensitive data properly
- No plaintext leakage in error conditions
- Key commitment protects against multi-key attacks
"""

import pytest

from secure_string_cipher.core import (
    compute_key_commitment,
    decrypt_text,
    derive_key,
    encrypt_text,
    verify_key_commitment,
)
from secure_string_cipher.secure_memory import SecureBytes, SecureString, secure_compare
from secure_string_cipher.utils import CryptoError

# =============================================================================
# Key Derivation Security Tests
# =============================================================================


class TestKeyDerivationSecurity:
    """Tests for secure key derivation."""

    def test_derive_key_returns_correct_length(self):
        """Verify derive_key returns 32-byte key."""
        key = derive_key("SecurePass123!", b"a" * 16)
        assert len(key) == 32

    def test_derive_key_deterministic(self):
        """Verify same passphrase and salt produce same key."""
        salt = b"fixed_salt_16byt"
        key1 = derive_key("TestPassword123!", salt)
        key2 = derive_key("TestPassword123!", salt)
        assert key1 == key2

    def test_derive_key_different_salts_different_keys(self):
        """Verify different salts produce different keys."""
        key1 = derive_key("TestPassword123!", b"salt_one_16bytes")
        key2 = derive_key("TestPassword123!", b"salt_two_16bytes")
        assert key1 != key2

    def test_derive_key_different_passwords_different_keys(self):
        """Verify different passwords produce different keys."""
        salt = b"fixed_salt_16byt"
        key1 = derive_key("Password1!", salt)
        key2 = derive_key("Password2!", salt)
        assert key1 != key2

    def test_derive_key_empty_passphrase(self):
        """Verify empty passphrase behavior."""
        # Empty passphrase produces a key (Argon2 accepts empty input)
        # This is a policy decision - applications should validate before calling
        key = derive_key("", b"a" * 16)
        assert len(key) == 32

    def test_derive_key_unicode_passphrase(self):
        """Verify unicode passphrases work correctly."""
        key = derive_key("пароль密码🔐!", b"a" * 16)
        assert len(key) == 32

    def test_derive_key_very_long_passphrase(self):
        """Verify very long passphrases work."""
        long_pass = "Secure123!" + "x" * 10000
        key = derive_key(long_pass, b"a" * 16)
        assert len(key) == 32


# =============================================================================
# Key Commitment Security Tests
# =============================================================================


class TestKeyCommitmentSecurity:
    """Tests for key commitment scheme."""

    def test_commitment_deterministic(self):
        """Verify same key produces same commitment."""
        key = b"x" * 32
        c1 = compute_key_commitment(key)
        c2 = compute_key_commitment(key)
        assert c1 == c2

    def test_commitment_different_keys_different_commitments(self):
        """Verify different keys produce different commitments."""
        key1 = b"a" * 32
        key2 = b"b" * 32
        c1 = compute_key_commitment(key1)
        c2 = compute_key_commitment(key2)
        assert c1 != c2

    def test_commitment_length(self):
        """Verify commitment is 32 bytes (SHA-256)."""
        key = b"x" * 32
        commitment = compute_key_commitment(key)
        assert len(commitment) == 32

    def test_verify_commitment_correct_key(self):
        """Verify commitment verification passes with correct key."""
        key = b"correct_key_" + b"x" * 20
        commitment = compute_key_commitment(key)
        assert verify_key_commitment(key, commitment)

    def test_verify_commitment_wrong_key(self):
        """Verify commitment verification fails with wrong key."""
        key1 = b"correct_key_" + b"x" * 20
        key2 = b"wrong_key___" + b"x" * 20
        commitment = compute_key_commitment(key1)
        assert not verify_key_commitment(key2, commitment)

    def test_verify_commitment_tampered(self):
        """Verify commitment verification fails if commitment is tampered."""
        key = b"x" * 32
        commitment = bytearray(compute_key_commitment(key))
        commitment[0] ^= 1  # Flip one bit
        assert not verify_key_commitment(key, bytes(commitment))


# =============================================================================
# Encryption/Decryption Security Tests
# =============================================================================


class TestEncryptionSecurity:
    """Tests for encryption security properties."""

    def test_encrypt_decrypt_roundtrip(self):
        """Verify basic encrypt/decrypt cycle."""
        plaintext = "Sensitive data to encrypt"
        passphrase = "SecurePass123!"
        ciphertext = encrypt_text(plaintext, passphrase)
        decrypted = decrypt_text(ciphertext, passphrase)
        assert decrypted == plaintext

    def test_ciphertext_differs_each_time(self):
        """Verify encryption produces different ciphertext each time (random nonce)."""
        plaintext = "Same message"
        passphrase = "SecurePass123!"
        c1 = encrypt_text(plaintext, passphrase)
        c2 = encrypt_text(plaintext, passphrase)
        assert c1 != c2  # Different due to random salt/nonce

    def test_wrong_passphrase_fails(self):
        """Verify decryption fails with wrong passphrase."""
        plaintext = "Secret message"
        ciphertext = encrypt_text(plaintext, "CorrectPass123!")
        with pytest.raises(CryptoError):
            decrypt_text(ciphertext, "WrongPass123!")

    def test_tampered_ciphertext_fails(self):
        """Verify decryption fails if ciphertext is tampered."""
        plaintext = "Secret message"
        ciphertext = encrypt_text(plaintext, "SecurePass123!")
        # Tamper with multiple bytes in the ciphertext to ensure detection
        # (single byte changes might rarely produce valid base64 with same decoded value)
        mid = len(ciphertext) // 2
        tampered = ciphertext[:mid] + "XXXXX" + ciphertext[mid + 5 :]
        with pytest.raises(CryptoError):
            decrypt_text(tampered, "SecurePass123!")

    def test_truncated_ciphertext_fails(self):
        """Verify decryption fails with truncated ciphertext."""
        plaintext = "Secret message"
        ciphertext = encrypt_text(plaintext, "SecurePass123!")
        with pytest.raises(CryptoError):
            decrypt_text(ciphertext[:20], "SecurePass123!")

    def test_empty_plaintext_works(self):
        """Verify empty plaintext can be encrypted/decrypted."""
        ciphertext = encrypt_text("", "SecurePass123!")
        decrypted = decrypt_text(ciphertext, "SecurePass123!")
        assert decrypted == ""

    def test_unicode_plaintext(self):
        """Verify unicode plaintext works correctly."""
        plaintext = "Привет мир! 你好世界! 🔐🔑"
        passphrase = "SecurePass123!"
        ciphertext = encrypt_text(plaintext, passphrase)
        decrypted = decrypt_text(ciphertext, passphrase)
        assert decrypted == plaintext

    def test_large_plaintext(self):
        """Verify large plaintext works correctly."""
        plaintext = "Large data block: " + "X" * 100000
        passphrase = "SecurePass123!"
        ciphertext = encrypt_text(plaintext, passphrase)
        decrypted = decrypt_text(ciphertext, passphrase)
        assert decrypted == plaintext


# =============================================================================
# Memory Safety in Crypto Operations
# =============================================================================


class TestCryptoMemorySafety:
    """Tests for memory safety in crypto operations."""

    def test_secure_bytes_in_key_derivation_context(self):
        """Verify SecureBytes works correctly with key material."""
        passphrase = "TestPassword123!"
        salt = b"test_salt_16byte"
        key = derive_key(passphrase, salt)

        # Wrap key in SecureBytes and verify functionality
        with SecureBytes(key) as secure_key:
            assert len(secure_key.data) == 32
            # Key should be usable
            commitment = compute_key_commitment(bytes(secure_key.data))
            assert len(commitment) == 32

        # After context exit, should be wiped
        with pytest.raises(AttributeError):
            _ = secure_key.data

    def test_secure_string_passphrase_handling(self):
        """Verify SecureString handles passphrases correctly."""
        passphrase = "SensitivePass123!"

        with SecureString(passphrase) as secure_pass:
            # Can use the passphrase for encryption
            key = derive_key(secure_pass.string, b"salt_for_test123")
            assert len(key) == 32

        # After context exit, should be wiped
        with pytest.raises(AttributeError):
            _ = secure_pass.string

    def test_encrypt_decrypt_with_secure_wrappers(self):
        """Verify encryption works with secure memory wrappers."""
        plaintext = "Sensitive message"

        with SecureString("SecurePass123!") as secure_pass:
            ciphertext = encrypt_text(plaintext, secure_pass.string)
            decrypted = decrypt_text(ciphertext, secure_pass.string)
            assert decrypted == plaintext

    def test_key_material_comparison_uses_constant_time(self):
        """Verify key comparisons use constant-time operations."""
        key1 = derive_key("Password1!", b"salt_for_test123")
        key2 = derive_key("Password1!", b"salt_for_test123")
        key3 = derive_key("Password2!", b"salt_for_test123")

        # Should use secure_compare for key comparison
        assert secure_compare(key1, key2)
        assert not secure_compare(key1, key3)


# =============================================================================
# Error Condition Security Tests
# =============================================================================


class TestErrorConditionSecurity:
    """Tests for security in error conditions."""

    def test_invalid_ciphertext_format_error(self):
        """Verify invalid ciphertext format raises clear error."""
        with pytest.raises(CryptoError):
            decrypt_text("not-valid-base64!!!", "SecurePass123!")

    def test_corrupted_metadata_error(self):
        """Verify corrupted metadata raises error."""
        plaintext = "Test message"
        ciphertext = encrypt_text(plaintext, "SecurePass123!")

        # Corrupt the base64 content
        import base64

        decoded = base64.b64decode(ciphertext)
        corrupted = bytes([decoded[0] ^ 0xFF]) + decoded[1:]
        corrupted_b64 = base64.b64encode(corrupted).decode()

        with pytest.raises(CryptoError):
            decrypt_text(corrupted_b64, "SecurePass123!")

    def test_error_messages_dont_leak_secrets(self):
        """Verify error messages don't contain sensitive data."""
        passphrase = "MySecretPass123!"
        plaintext = "Sensitive plaintext data"

        ciphertext = encrypt_text(plaintext, passphrase)

        try:
            decrypt_text(ciphertext, "WrongPass123!")
        except CryptoError as e:
            error_msg = str(e).lower()
            # Error should not contain passphrase or plaintext
            assert passphrase.lower() not in error_msg
            assert plaintext.lower() not in error_msg
            assert "wrongpass" not in error_msg
