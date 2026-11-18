"""Unit tests for V2 managed key fingerprint computation."""

import pytest

from secure_string_cipher.v2.key_identity import compute_fingerprint


def test_compute_fingerprint_valid_length():
    """Valid managed secret of 32 bytes should compute a 52-char fingerprint."""
    secret = b"\x00" * 32
    fingerprint = compute_fingerprint(secret)
    assert fingerprint.startswith("ssc-k1-")
    assert len(fingerprint) == 59

    assert fingerprint[7:].isupper()
    assert "=" not in fingerprint


def test_compute_fingerprint_invalid_type():
    """Invalid types should raise ValueError."""
    with pytest.raises(ValueError, match="managed_secret must be exactly 32 bytes"):
        compute_fingerprint("not bytes")  # type: ignore


def test_compute_fingerprint_invalid_length():
    """Invalid length should raise ValueError."""
    with pytest.raises(ValueError, match="managed_secret must be exactly 32 bytes"):
        compute_fingerprint(b"\x00" * 31)

    with pytest.raises(ValueError, match="managed_secret must be exactly 32 bytes"):
        compute_fingerprint(b"\x00" * 33)


def test_compute_fingerprint_determinism():
    """Fingerprint computation should be deterministic."""
    secret = b"\x01" * 32
    fingerprint1 = compute_fingerprint(secret)
    fingerprint2 = compute_fingerprint(secret)
    assert fingerprint1 == fingerprint2


def test_compute_fingerprint_uniqueness():
    """Different secrets should yield different fingerprints."""
    fingerprint1 = compute_fingerprint(b"\x00" * 32)
    fingerprint2 = compute_fingerprint(b"\x01" * 32)
    assert fingerprint1 != fingerprint2
