"""
Tests for passphrase_generator module.
"""

import string

import pytest

from secure_string_cipher.passphrase_generator import (
    calculate_entropy_bits,
    generate_alphanumeric_passphrase,
    generate_mixed_passphrase,
    generate_passphrase,
    generate_word_passphrase,
)


class TestWordPassphrase:
    """Tests for word-based passphrase generation."""

    def test_word_passphrase_length(self):
        """Test that word passphrase has correct number of words."""
        passphrase = generate_word_passphrase(word_count=6)
        words = passphrase.split("-")
        assert len(words) == 6

    def test_word_passphrase_custom_separator(self):
        """Test word passphrase with custom separator."""
        passphrase = generate_word_passphrase(word_count=4, separator="_")
        assert "_" in passphrase
        assert "-" not in passphrase
        words = passphrase.split("_")
        assert len(words) == 4

    def test_word_passphrase_minimum_words(self):
        """Test that minimum word count is enforced."""
        with pytest.raises(ValueError, match="at least 4"):
            generate_word_passphrase(word_count=3)

    def test_word_passphrase_randomness(self):
        """Test that word passphrases are different (random)."""
        p1 = generate_word_passphrase(6)
        p2 = generate_word_passphrase(6)
        # Very unlikely to be the same
        assert p1 != p2


class TestAlphanumericPassphrase:
    """Tests for alphanumeric passphrase generation."""

    def test_alphanumeric_length(self):
        """Test that alphanumeric passphrase has correct length."""
        passphrase = generate_alphanumeric_passphrase(length=24)
        assert len(passphrase) == 24

    def test_alphanumeric_with_symbols(self):
        """Test alphanumeric passphrase includes symbols."""
        passphrase = generate_alphanumeric_passphrase(length=50, include_symbols=True)
        # Should have at least one symbol (with high probability)
        has_symbol = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in passphrase)
        assert has_symbol

    def test_alphanumeric_without_symbols(self):
        """Test alphanumeric passphrase without symbols."""
        passphrase = generate_alphanumeric_passphrase(length=50, include_symbols=False)
        # Should only have letters and digits
        assert all(c in string.ascii_letters + string.digits for c in passphrase)

    def test_alphanumeric_minimum_length(self):
        """Test that minimum length is enforced."""
        with pytest.raises(ValueError, match="at least 16"):
            generate_alphanumeric_passphrase(length=15)

    def test_alphanumeric_randomness(self):
        """Test that alphanumeric passphrases are different (random)."""
        p1 = generate_alphanumeric_passphrase(24)
        p2 = generate_alphanumeric_passphrase(24)
        assert p1 != p2


class TestMixedPassphrase:
    """Tests for mixed passphrase generation."""

    def test_mixed_format(self):
        """Test that mixed passphrase has correct format."""
        passphrase = generate_mixed_passphrase(word_count=4, number_count=4)
        parts = passphrase.rsplit("-", 1)
        assert len(parts) == 2
        words = parts[0].split("-")
        assert len(words) == 4
        numbers = parts[1]
        assert len(numbers) == 4
        assert numbers.isdigit()

    def test_mixed_minimum_words(self):
        """Test that minimum word count is enforced."""
        with pytest.raises(ValueError, match="at least 3"):
            generate_mixed_passphrase(word_count=2, number_count=4)

    def test_mixed_minimum_numbers(self):
        """Test that minimum number count is enforced."""
        with pytest.raises(ValueError, match="at least 3"):
            generate_mixed_passphrase(word_count=4, number_count=2)

    def test_mixed_randomness(self):
        """Test that mixed passphrases are different (random)."""
        p1 = generate_mixed_passphrase(4, 4)
        p2 = generate_mixed_passphrase(4, 4)
        assert p1 != p2


class TestEntropyCalculation:
    """Tests for entropy calculation."""

    def test_word_entropy(self):
        """Test entropy calculation for word-based passphrases."""
        entropy = calculate_entropy_bits("word", word_count=6)
        # Should be around 64 bits (log2(~1300) * 6 ≈ 64.5)
        assert 60 < entropy < 70

    def test_alphanumeric_entropy_with_symbols(self):
        """Test entropy for alphanumeric with symbols."""
        entropy = calculate_entropy_bits(
            "alphanumeric", length=24, include_symbols=True
        )
        # Should be quite high
        assert entropy > 140

    def test_alphanumeric_entropy_without_symbols(self):
        """Test entropy for alphanumeric without symbols."""
        entropy = calculate_entropy_bits(
            "alphanumeric", length=24, include_symbols=False
        )
        # Should be lower than with symbols
        assert 120 < entropy < 145

    def test_mixed_entropy(self):
        """Test entropy for mixed passphrases."""
        entropy = calculate_entropy_bits("mixed", word_count=4, number_count=4)
        # Should be around 43 bits from words + 13 bits from numbers ≈ 56
        assert 50 < entropy < 65


class TestGeneratePassphrase:
    """Tests for the main generate_passphrase function."""

    def test_word_strategy(self):
        """Test passphrase generation with word strategy."""
        passphrase, entropy = generate_passphrase("word", word_count=6)
        assert "-" in passphrase
        assert entropy > 60

    def test_alphanumeric_strategy(self):
        """Test passphrase generation with alphanumeric strategy."""
        passphrase, entropy = generate_passphrase("alphanumeric", length=24)
        assert len(passphrase) == 24
        assert entropy > 140

    def test_mixed_strategy(self):
        """Test passphrase generation with mixed strategy."""
        passphrase, entropy = generate_passphrase("mixed", word_count=4, number_count=4)
        assert "-" in passphrase
        assert entropy > 50

    def test_invalid_strategy(self):
        """Test that invalid strategy raises error."""
        with pytest.raises(ValueError, match="Unknown strategy"):
            generate_passphrase("invalid_strategy")

    def test_default_strategy(self):
        """Test that word is the default strategy."""
        passphrase, entropy = generate_passphrase()
        # Default should be word-based with 6 words
        assert "-" in passphrase
        words = passphrase.split("-")
        assert len(words) == 6
