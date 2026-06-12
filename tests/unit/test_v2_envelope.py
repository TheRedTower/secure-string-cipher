"""Tests for v2 envelope value types."""

from dataclasses import FrozenInstanceError

import pytest

from secure_string_cipher.v2.envelope import (
    AccessBlock,
    AccessGrant,
    AccessPolicy,
    GrantType,
    MetadataPolicy,
    PayloadDescriptor,
    PayloadType,
    V2Header,
    canonical_json,
)


def test_envelope_enum_values_match_architecture():
    """Enum values should match the v2 architecture document strings."""
    assert GrantType.PASSWORD.value == "password"
    assert GrantType.MANAGED_KEY.value == "managed-key"
    assert (
        GrantType.COMBINED_PASSWORD_MANAGED_KEY.value == "combined-password-managed-key"
    )
    assert AccessPolicy.SINGLE_GRANT.value == "single-grant"
    assert PayloadType.FILE.value == "file"
    assert PayloadType.TEXT.value == "text"
    assert MetadataPolicy.ENCRYPTED.value == "encrypted"
    assert MetadataPolicy.HIDDEN.value == "hidden"


def test_v2_header_canonical_json_is_deterministic():
    """Protected header serialization should be stable and compact."""
    grant = AccessGrant(
        grant_id="grant-1",
        type=GrantType.MANAGED_KEY,
        kek_derivation={"alg": "hkdf-sha256", "salt": "abc"},
        wrap_alg="aes-256-gcm",
        wrap_nonce="nonce",
        wrapped_dek="wrapped",
        tag="tag",
        key_fingerprint="ssc-k1-example",
    )
    header = V2Header(
        format="SSC-V2",
        version=2,
        object_id="object-1",
        object_type="encrypted-object",
        payload=PayloadDescriptor(
            type=PayloadType.FILE,
            alg="aes-256-gcm",
            kdf={"alg": "none"},
            metadata_policy=MetadataPolicy.ENCRYPTED,
            chunk_size=65536,
        ),
        access=AccessBlock(
            version=1,
            policy=AccessPolicy.SINGLE_GRANT,
            grants=[grant],
        ),
        metadata={"name": "document.txt"},
    )

    encoded = canonical_json(header)

    assert encoded == canonical_json(header)
    assert b" " not in encoded
    assert b"\n" not in encoded
    assert b'"type":"file"' in encoded
    assert b'"type":"managed-key"' in encoded


def test_envelope_records_are_frozen_value_objects():
    """Envelope records should not be mutated in place."""
    payload = PayloadDescriptor(
        type=PayloadType.TEXT,
        alg="aes-256-gcm",
        kdf={"alg": "argon2id"},
        metadata_policy=MetadataPolicy.HIDDEN,
    )

    with pytest.raises(FrozenInstanceError):
        payload.alg = "changed"  # type: ignore[misc]
