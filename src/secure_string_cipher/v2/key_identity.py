"""Managed-key identity types for SSC v2."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

__all__ = [
    "ExternalKeyReference",
    "KeyIdentity",
    "KeyPublicMetadata",
    "KeyStatus",
    "KeyStorageMode",
    "KeyType",
]


class KeyType(Enum):
    """Managed key types active in v2.0.0."""

    SYMMETRIC = "symmetric-key"


class KeyStorageMode(Enum):
    """Managed key storage modes active in v2.0.0."""

    EXTERNAL_ONLY = "external-only"
    VAULT_COPY = "vault-copy"


class KeyStatus(Enum):
    """Lifecycle status for a managed key identity."""

    ACTIVE = "active"
    ARCHIVED = "archived"
    REVOKED = "revoked"
    DESTROYED = "destroyed"


@dataclass(frozen=True, slots=True)
class KeyPublicMetadata:
    """Public metadata stored with a managed key identity."""

    label: str
    algorithm: str
    key_length: int
    format: str


@dataclass(frozen=True, slots=True)
class ExternalKeyReference:
    """Optional external keyfile location hint."""

    path_hint: str | None


@dataclass(frozen=True, slots=True)
class KeyIdentity:
    """Lifecycle-aware managed key identity record."""

    schema_version: int
    id: str
    type: KeyType
    fingerprint: str
    storage: KeyStorageMode
    status: KeyStatus
    created_at: str
    updated_at: str
    last_used_at: str | None
    public_metadata: KeyPublicMetadata
    external: ExternalKeyReference
    vault_secret: Mapping[str, object] | None
