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


def test_key_identity_record_contains_required_v2_fields():
    """KeyIdentity should represent the required v2 identity fields."""
    metadata = KeyPublicMetadata(
        label="laptop-backup",
        algorithm="hkdf-sha256",
        key_length=32,
        format="ssckey-v1",
    )
    identity = KeyIdentity(
        schema_version=1,
        id="laptop-backup",
        type=KeyType.SYMMETRIC,
        fingerprint="ssc-k1-example",
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
    assert identity.id == "laptop-backup"
    assert identity.type is KeyType.SYMMETRIC
    assert identity.public_metadata is metadata
    assert identity.external.path_hint == "~/keys/laptop-backup.ssckey"
    assert identity.vault_secret is None


def test_key_identity_records_are_frozen_value_objects():
    """Identity records should not be mutated in place."""
    identity = KeyIdentity(
        schema_version=1,
        id="laptop-backup",
        type=KeyType.SYMMETRIC,
        fingerprint="ssc-k1-example",
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
        vault_secret={"protection": "vault-wrapped"},
    )

    with pytest.raises(FrozenInstanceError):
        identity.status = KeyStatus.ARCHIVED  # type: ignore[misc]
