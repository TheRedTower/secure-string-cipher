"""Tests for v2 managed-key identity types."""

from dataclasses import FrozenInstanceError

import pytest

from secure_string_cipher.v2.key_identity import (
    ExternalKeyReference,
    KeyIdentity,
    KeyPublicMetadata,
    KeyStatus,
    KeyStorageMode,
    KeyType,
)


def test_key_identity_enum_values_match_architecture():
    """Enum values should match the architecture document strings."""
    assert KeyType.SYMMETRIC.value == "symmetric-key"
    assert KeyStorageMode.EXTERNAL_ONLY.value == "external-only"
    assert KeyStorageMode.VAULT_COPY.value == "vault-copy"
    assert KeyStatus.ACTIVE.value == "active"
    assert KeyStatus.ARCHIVED.value == "archived"
    assert KeyStatus.REVOKED.value == "revoked"
    assert KeyStatus.DESTROYED.value == "destroyed"


VALID_FINGERPRINT = "ssc-k1-" + "A" * 52


def test_key_identity_record_contains_required_v2_fields():
    """KeyIdentity should represent the required v2 identity fields including record_id."""
    metadata = KeyPublicMetadata(
        label="laptop-backup",
        algorithm="hkdf-sha256",
        key_length=32,
        format="ssckey-v1",
    )
    identity = KeyIdentity(
        schema_version=1,
        record_id="cmVjb3JkMTZieXRlcw==",
        id="laptop-backup",
        type=KeyType.SYMMETRIC,
        fingerprint=VALID_FINGERPRINT,
        storage=KeyStorageMode.EXTERNAL_ONLY,
        status=KeyStatus.ACTIVE,
        created_at="2026-06-03T00:00:00Z",
        updated_at="2026-06-03T00:00:00Z",
        last_used_at=None,
        public_metadata=metadata,
        external=ExternalKeyReference(path_hint="~/keys/laptop-backup.ssckey"),
        vault_secret=None,
    )

    assert identity.schema_version == 1
    assert identity.record_id == "cmVjb3JkMTZieXRlcw=="
    assert identity.id == "laptop-backup"
    assert identity.type is KeyType.SYMMETRIC
    assert identity.public_metadata is metadata
    assert identity.external.path_hint == "~/keys/laptop-backup.ssckey"
    assert identity.vault_secret is None


def test_key_identity_records_are_deeply_frozen():
    """Identity records must not be mutated in place and nested structures must be immutable."""
    secret_dict = {"protection": "vault-wrapped", "nonce": "abc"}
    identity = KeyIdentity(
        schema_version=1,
        record_id="cmVjb3JkMTZieXRlcw==",
        id="laptop-backup",
        type=KeyType.SYMMETRIC,
        fingerprint=VALID_FINGERPRINT,
        storage=KeyStorageMode.VAULT_COPY,
        status=KeyStatus.ACTIVE,
        created_at="2026-06-03T00:00:00Z",
        updated_at="2026-06-03T00:00:00Z",
        last_used_at=None,
        public_metadata=KeyPublicMetadata(
            label="laptop-backup",
            algorithm="hkdf-sha256",
            key_length=32,
            format="ssckey-v1",
        ),
        external=ExternalKeyReference(path_hint=None),
        vault_secret=secret_dict,
    )

    # Dataclass attribute reassignment fails
    with pytest.raises(FrozenInstanceError):
        identity.status = KeyStatus.ARCHIVED  # type: ignore[misc]

    # Mutating caller dictionary does not alter dataclass
    secret_dict["nonce"] = "mutated_nonce"
    assert identity.vault_secret is not None
    assert identity.vault_secret["nonce"] == "abc"

    # Nested mapping proxy cannot be modified
    with pytest.raises(TypeError):
        identity.vault_secret["nonce"] = "direct_mutation"  # type: ignore[index]


def test_key_identity_validation():
    """KeyIdentity enforces schema_version, record_id, id format, and fingerprint formatting."""
    metadata = KeyPublicMetadata(
        label="key-1",
        algorithm="hkdf-sha256",
        key_length=32,
        format="ssckey-v1",
    )

    # schema_version must be 1
    with pytest.raises(ValueError, match="schema_version must be 1"):
        KeyIdentity(
            schema_version=2,
            record_id="rec_id",
            id="key-1",
            type=KeyType.SYMMETRIC,
            fingerprint=VALID_FINGERPRINT,
            storage=KeyStorageMode.EXTERNAL_ONLY,
            status=KeyStatus.ACTIVE,
            created_at="2026-06-03T00:00:00Z",
            updated_at="2026-06-03T00:00:00Z",
            last_used_at=None,
            public_metadata=metadata,
            external=ExternalKeyReference(),
        )

    # empty record_id rejected
    with pytest.raises(ValueError, match="record_id must be a non-empty string"):
        KeyIdentity(
            schema_version=1,
            record_id="",
            id="key-1",
            type=KeyType.SYMMETRIC,
            fingerprint=VALID_FINGERPRINT,
            storage=KeyStorageMode.EXTERNAL_ONLY,
            status=KeyStatus.ACTIVE,
            created_at="2026-06-03T00:00:00Z",
            updated_at="2026-06-03T00:00:00Z",
            last_used_at=None,
            public_metadata=metadata,
            external=ExternalKeyReference(),
        )

    # invalid key id format rejected (uppercase, special characters, leading digit, etc.)
    for invalid_id in ["", "Key-1", "1key", "-key", "key with space", "a" * 65]:
        with pytest.raises(ValueError, match="KeyIdentity id must match pattern"):
            KeyIdentity(
                schema_version=1,
                record_id="rec_id",
                id=invalid_id,
                type=KeyType.SYMMETRIC,
                fingerprint=VALID_FINGERPRINT,
                storage=KeyStorageMode.EXTERNAL_ONLY,
                status=KeyStatus.ACTIVE,
                created_at="2026-06-03T00:00:00Z",
                updated_at="2026-06-03T00:00:00Z",
                last_used_at=None,
                public_metadata=metadata,
                external=ExternalKeyReference(),
            )

    # invalid fingerprint prefix rejected
    with pytest.raises(ValueError, match="fingerprint must start with 'ssc-k1-'"):
        KeyIdentity(
            schema_version=1,
            record_id="rec_id",
            id="key-1",
            type=KeyType.SYMMETRIC,
            fingerprint="invalid-prefix-fingerprint",
            storage=KeyStorageMode.EXTERNAL_ONLY,
            status=KeyStatus.ACTIVE,
            created_at="2026-06-03T00:00:00Z",
            updated_at="2026-06-03T00:00:00Z",
            last_used_at=None,
            public_metadata=metadata,
            external=ExternalKeyReference(),
        )

    # invalid fingerprint length rejected (too short: 58 chars)
    with pytest.raises(
        ValueError,
        match="fingerprint must start with 'ssc-k1-' and be exactly 59 characters",
    ):
        KeyIdentity(
            schema_version=1,
            record_id="rec_id",
            id="key-1",
            type=KeyType.SYMMETRIC,
            fingerprint="ssc-k1-" + "A" * 51,
            storage=KeyStorageMode.EXTERNAL_ONLY,
            status=KeyStatus.ACTIVE,
            created_at="2026-06-03T00:00:00Z",
            updated_at="2026-06-03T00:00:00Z",
            last_used_at=None,
            public_metadata=metadata,
            external=ExternalKeyReference(),
        )

    # invalid fingerprint length rejected (too long: 60 chars)
    with pytest.raises(
        ValueError,
        match="fingerprint must start with 'ssc-k1-' and be exactly 59 characters",
    ):
        KeyIdentity(
            schema_version=1,
            record_id="rec_id",
            id="key-1",
            type=KeyType.SYMMETRIC,
            fingerprint="ssc-k1-" + "A" * 53,
            storage=KeyStorageMode.EXTERNAL_ONLY,
            status=KeyStatus.ACTIVE,
            created_at="2026-06-03T00:00:00Z",
            updated_at="2026-06-03T00:00:00Z",
            last_used_at=None,
            public_metadata=metadata,
            external=ExternalKeyReference(),
        )
