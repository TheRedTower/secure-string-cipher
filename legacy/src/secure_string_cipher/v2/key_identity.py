"""Managed-key identity types for SSC v2."""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from secure_string_cipher.v2.envelope import deep_freeze

_KEY_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")

__all__ = [
    "ExternalKeyReference",
    "KeyIdentity",
    "KeyPublicMetadata",
    "KeyStatus",
    "KeyStorageMode",
    "KeyType",
    "compute_fingerprint",
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

    def __post_init__(self) -> None:
        if not isinstance(self.label, str) or not self.label:
            raise ValueError("KeyPublicMetadata label must be a non-empty string")
        if not isinstance(self.algorithm, str) or not self.algorithm:
            raise ValueError("KeyPublicMetadata algorithm must be a non-empty string")
        if not isinstance(self.key_length, int) or self.key_length <= 0:
            raise ValueError("KeyPublicMetadata key_length must be a positive integer")
        if not isinstance(self.format, str) or not self.format:
            raise ValueError("KeyPublicMetadata format must be a non-empty string")


@dataclass(frozen=True, slots=True)
class ExternalKeyReference:
    """Optional external keyfile location hint."""

    path_hint: str | None = None

    def __post_init__(self) -> None:
        if self.path_hint is not None and not isinstance(self.path_hint, str):
            raise TypeError("path_hint must be a string or None")


@dataclass(frozen=True, slots=True)
class KeyIdentity:
    """Lifecycle-aware managed key identity record."""

    schema_version: int
    record_id: str
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
    vault_secret: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("KeyIdentity schema_version must be 1")
        if not isinstance(self.record_id, str) or not self.record_id:
            raise ValueError("KeyIdentity record_id must be a non-empty string")
        if not isinstance(self.id, str) or not _KEY_ID_RE.match(self.id):
            raise ValueError(
                "KeyIdentity id must match pattern ^[a-z][a-z0-9._-]{0,63}$"
            )
        if not isinstance(self.type, KeyType):
            raise TypeError(f"Invalid key type: {self.type}")
        if (
            not isinstance(self.fingerprint, str)
            or not self.fingerprint.startswith("ssc-k1-")
            or len(self.fingerprint) != 59
        ):
            raise ValueError(
                "KeyIdentity fingerprint must start with 'ssc-k1-' and be exactly 59 characters"
            )
        if not isinstance(self.storage, KeyStorageMode):
            raise TypeError(f"Invalid storage mode: {self.storage}")
        if not isinstance(self.status, KeyStatus):
            raise TypeError(f"Invalid key status: {self.status}")
        if not isinstance(self.created_at, str) or not self.created_at:
            raise ValueError("KeyIdentity created_at must be a non-empty ISO timestamp")
        if not isinstance(self.updated_at, str) or not self.updated_at:
            raise ValueError("KeyIdentity updated_at must be a non-empty ISO timestamp")
        if not isinstance(self.public_metadata, KeyPublicMetadata):
            raise TypeError("public_metadata must be a KeyPublicMetadata instance")
        if not isinstance(self.external, ExternalKeyReference):
            raise TypeError("external must be an ExternalKeyReference instance")

        if self.vault_secret is not None:
            if not isinstance(self.vault_secret, Mapping):
                raise TypeError("vault_secret must be a Mapping or None")
            object.__setattr__(self, "vault_secret", deep_freeze(self.vault_secret))


def compute_fingerprint(managed_secret: bytes) -> str:
    """Compute the V2 key fingerprint for a symmetric managed secret."""
    if not isinstance(managed_secret, bytes) or len(managed_secret) != 32:
        raise ValueError("managed_secret must be exactly 32 bytes")

    digest = hashlib.sha256(
        b"secure-string-cipher/v2/key-fingerprint/symmetric" + managed_secret
    ).digest()

    base32_str = base64.b32encode(digest).decode("ascii").rstrip("=")
    return f"ssc-k1-{base32_str}"
