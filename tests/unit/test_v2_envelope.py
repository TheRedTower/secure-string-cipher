"""Tests for v2 envelope value types and canonical JSON serialization."""

from dataclasses import FrozenInstanceError
from enum import Enum

import pytest

from secure_string_cipher.v2.envelope import (
    VALID_CHUNK_SIZES,
    AccessBlock,
    AccessGrant,
    AccessPolicy,
    CommitmentDescriptor,
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
    """Protected header serialization should be stable, compact, and conform to SSC2 wire spec."""
    commitment = CommitmentDescriptor(
        alg="hmac-sha256",
        kdf={"alg": "hkdf-sha256", "salt": "c2FsdDE2Ynl0ZXNhbHQ="},
        value="Y29tbWl0bWVudDMyYnl0ZXM=",
    )
    grant = AccessGrant(
        grant_id="grant-0",
        type=GrantType.MANAGED_KEY,
        kek_derivation={"alg": "hkdf-sha256", "salt": "c2FsdDE2Ynl0ZXNhbHQ="},
        wrap_alg="aes-256-gcm",
        wrap_nonce="bm9uY2UxMmJ5dGVz",
        wrapped_dek="d3JhcHBlZGRlazMyYnl0ZXM=",
        tag="dGFnMTZieXRlc3RhZw==",
        commitment=commitment,
        key_fingerprint="ssc-k1-" + "A" * 52,
    )
    header = V2Header(
        format="SSC2",
        version=2,
        object_id="b2JqZWN0MTZieXRlcw==",
        object_type="file",
        payload=PayloadDescriptor(
            type=PayloadType.FILE,
            alg="aes-256-gcm",
            kdf={"alg": "hkdf-sha256", "salt": "c2FsdDE2Ynl0ZXNhbHQ="},
            metadata_policy=MetadataPolicy.ENCRYPTED,
            chunk_size=262144,
            nonce_prefix="bm9u",
        ),
        access=AccessBlock(
            version=1,
            policy=AccessPolicy.SINGLE_GRANT,
            grants=[grant],
        ),
        metadata={"policy": "encrypted"},
    )

    encoded = canonical_json(header)

    assert encoded == canonical_json(header)
    assert b" " not in encoded
    assert b"\n" not in encoded
    assert b'"format":"SSC2"' in encoded
    assert b'"type":"file"' in encoded
    assert b'"type":"managed-key"' in encoded
    assert b'"chunk_size":262144' in encoded


def test_canonical_json_rejects_non_string_keys():
    """Non-string dictionary keys must be strictly rejected without coercion."""
    with pytest.raises(TypeError, match="Dictionary keys must be strings"):
        canonical_json({123: "numeric_key"})

    with pytest.raises(TypeError, match="Dictionary keys must be strings"):
        canonical_json({("tuple", "key"): "value"})


def test_canonical_json_rejects_floating_point_numbers():
    """Floating point numbers, NaN, and Infinity must be strictly rejected."""
    with pytest.raises(TypeError, match="Floating-point numbers are not permitted"):
        canonical_json({"number": 12.34})

    with pytest.raises(TypeError, match="Floating-point numbers are not permitted"):
        canonical_json({"nan": float("nan")})

    with pytest.raises(TypeError, match="Floating-point numbers are not permitted"):
        canonical_json({"inf": float("inf")})


def test_canonical_json_enforces_depth_limit():
    """Nesting depth greater than 16 must be rejected."""
    curr: dict[str, object] = {"bottom": 1}
    for _ in range(17):
        curr = {"nested": curr}

    with pytest.raises(ValueError, match="maximum depth limit"):
        canonical_json(curr)


def test_canonical_json_enforces_node_limit():
    """Container with more than 1024 total nodes must be rejected."""
    large_dict = {f"k_{i}": i for i in range(1025)}
    with pytest.raises(ValueError, match="maximum node limit"):
        canonical_json(large_dict)


def test_envelope_records_deep_immutability():
    """External mutations to passed mappings must not alter the frozen dataclass."""
    kdf_dict = {"alg": "hkdf-sha256", "salt": "original_salt"}
    payload = PayloadDescriptor(
        type=PayloadType.FILE,
        alg="aes-256-gcm",
        kdf=kdf_dict,
        metadata_policy=MetadataPolicy.ENCRYPTED,
        chunk_size=65536,
    )

    # Mutate original caller dictionary
    kdf_dict["salt"] = "mutated_salt"

    # Dataclass internal mapping remains unchanged
    assert payload.kdf["salt"] == "original_salt"

    # Dataclass attributes are frozen
    with pytest.raises(FrozenInstanceError):
        payload.alg = "changed"  # type: ignore[misc]

    # Nested mapping is read-only (MappingProxyType)
    with pytest.raises(TypeError):
        payload.kdf["salt"] = "direct_mutation"  # type: ignore[index]


def test_chunk_size_allowlist():
    """PayloadDescriptor must enforce the legal chunk size allowlist."""
    for valid_size in VALID_CHUNK_SIZES:
        payload = PayloadDescriptor(
            type=PayloadType.FILE,
            alg="aes-256-gcm",
            kdf={"alg": "hkdf-sha256"},
            metadata_policy=MetadataPolicy.ENCRYPTED,
            chunk_size=valid_size,
        )
        assert payload.chunk_size == valid_size

    # Invalid sizes
    with pytest.raises(ValueError, match="not in legal allowlist"):
        PayloadDescriptor(
            type=PayloadType.FILE,
            alg="aes-256-gcm",
            kdf={"alg": "hkdf-sha256"},
            metadata_policy=MetadataPolicy.ENCRYPTED,
            chunk_size=12345,
        )

    with pytest.raises(ValueError, match="not in legal allowlist"):
        PayloadDescriptor(
            type=PayloadType.FILE,
            alg="aes-256-gcm",
            kdf={"alg": "hkdf-sha256"},
            metadata_policy=MetadataPolicy.ENCRYPTED,
            chunk_size=-65536,
        )


def test_payload_descriptor_type_boundaries():
    """Text fields on file payloads and file fields on text payloads must be rejected."""
    # File payload with text field
    with pytest.raises(
        ValueError, match="Text payload fields .* forbidden on file payload"
    ):
        PayloadDescriptor(
            type=PayloadType.FILE,
            alg="aes-256-gcm",
            kdf={"alg": "hkdf-sha256"},
            metadata_policy=MetadataPolicy.ENCRYPTED,
            chunk_size=65536,
            nonce="bm9uY2UxMmJ5dGVz",
        )

    # Text payload with file field
    with pytest.raises(
        ValueError, match="File payload fields .* forbidden on text payload"
    ):
        PayloadDescriptor(
            type=PayloadType.TEXT,
            alg="aes-256-gcm",
            kdf={"alg": "hkdf-sha256"},
            metadata_policy=MetadataPolicy.HIDDEN,
            chunk_size=65536,
        )


def test_v2_header_validation():
    """V2Header validates format, version, and object_type agreement."""
    grant = AccessGrant(
        grant_id="grant-0",
        type=GrantType.PASSWORD,
        kek_derivation={"alg": "hkdf-sha256"},
        wrap_alg="aes-256-gcm",
        wrap_nonce="bm9uY2UxMmJ5dGVz",
        wrapped_dek="d3JhcHBlZGRlazMyYnl0ZXM=",
        tag="dGFnMTZieXRlc3RhZw==",
    )
    access = AccessBlock(version=1, policy=AccessPolicy.SINGLE_GRANT, grants=[grant])
    payload = PayloadDescriptor(
        type=PayloadType.FILE,
        alg="aes-256-gcm",
        kdf={"alg": "hkdf-sha256"},
        metadata_policy=MetadataPolicy.ENCRYPTED,
        chunk_size=65536,
    )

    # Format must be SSC2
    with pytest.raises(ValueError, match="format must be 'SSC2'"):
        V2Header(
            format="INVALID",
            version=2,
            object_id="obj_id",
            object_type="file",
            payload=payload,
            access=access,
            metadata={},
        )

    # Version must be 2
    with pytest.raises(ValueError, match="version must be 2"):
        V2Header(
            format="SSC2",
            version=1,
            object_id="obj_id",
            object_type="file",
            payload=payload,
            access=access,
            metadata={},
        )

    # object_type mismatch
    with pytest.raises(ValueError, match="does not match payload.type"):
        V2Header(
            format="SSC2",
            version=2,
            object_id="obj_id",
            object_type="text",
            payload=payload,
            access=access,
            metadata={},
        )


def test_canonical_json_rejects_float_enum():
    """Enum instances with float values must be rejected by canonical JSON serialization."""

    class FloatEnum(Enum):
        TEST_FLOAT = 3.14159

    with pytest.raises(
        TypeError,
        match="Floating-point numbers are not permitted in SSC canonical JSON",
    ):
        canonical_json({"enum_field": FloatEnum.TEST_FLOAT})
