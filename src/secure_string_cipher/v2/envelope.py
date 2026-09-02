"""Envelope value types for SSC v2 encrypted objects."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum

__all__ = [
    "AccessBlock",
    "AccessGrant",
    "AccessPolicy",
    "GrantType",
    "MetadataPolicy",
    "PayloadDescriptor",
    "PayloadType",
    "V2Header",
    "canonical_json",
]


class GrantType(Enum):
    """Allowed v2 access grant types."""

    PASSWORD = "password"  # pragma: allowlist secret
    MANAGED_KEY = "managed-key"
    COMBINED_PASSWORD_MANAGED_KEY = (
        "combined-password-managed-key"  # pragma: allowlist secret
    )


class AccessPolicy(Enum):
    """Access policy values supported by v2.0.0."""

    SINGLE_GRANT = "single-grant"


class PayloadType(Enum):
    """Payload types supported by the v2 envelope."""

    FILE = "file"
    TEXT = "text"


class MetadataPolicy(Enum):
    """Restore metadata visibility policy."""

    ENCRYPTED = "encrypted"
    HIDDEN = "hidden"


@dataclass(frozen=True, slots=True)
class PayloadDescriptor:
    """Protected description of an encrypted payload."""

    type: PayloadType
    alg: str
    kdf: Mapping[str, object]
    metadata_policy: MetadataPolicy
    chunk_size: int | None = None
    nonce_prefix: str | None = None


@dataclass(frozen=True, slots=True)
class AccessGrant:
    """A single v2 grant wrapping the object DEK."""

    grant_id: str
    type: GrantType
    kek_derivation: Mapping[str, object]
    wrap_alg: str
    wrap_nonce: str
    wrapped_dek: str
    tag: str
    key_fingerprint: str | None = None
    password_kdf: Mapping[str, object] | None = None
    combined_kdf: Mapping[str, object] | None = None


@dataclass(frozen=True, slots=True)
class AccessBlock:
    """Future-compatible access container for v2 encrypted objects."""

    version: int
    policy: AccessPolicy
    grants: Sequence[AccessGrant]


@dataclass(frozen=True, slots=True)
class V2Header:
    """Protected header shape for v2 encrypted objects."""

    format: str
    version: int
    object_id: str
    object_type: str
    payload: PayloadDescriptor
    access: AccessBlock
    metadata: Mapping[str, object]


def canonical_json(value: object) -> bytes:
    """Serialize protected header data as deterministic UTF-8 JSON bytes."""
    return json.dumps(
        _to_json_compatible(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _to_json_compatible(value: object) -> object:
    """Convert v2 value objects into plain JSON-compatible containers."""
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return _to_json_compatible(asdict(value))
    if isinstance(value, Mapping):
        return {str(k): _to_json_compatible(v) for k, v in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_to_json_compatible(item) for item in value]
    return value
