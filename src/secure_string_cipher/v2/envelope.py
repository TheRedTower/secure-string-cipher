"""Envelope value types for SSC v2 encrypted objects."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from types import MappingProxyType

__all__ = [
    "AccessBlock",
    "AccessGrant",
    "AccessPolicy",
    "CommitmentDescriptor",
    "GrantType",
    "MetadataPolicy",
    "PayloadDescriptor",
    "PayloadType",
    "V2Header",
    "VALID_CHUNK_SIZES",
    "canonical_json",
    "deep_freeze",
]

# Initial permitted chunk sizes: 64 KiB, 128 KiB, 256 KiB, 512 KiB, 1 MiB, 2 MiB, 4 MiB
VALID_CHUNK_SIZES: frozenset[int] = frozenset(
    {
        65536,
        131072,
        262144,
        524288,
        1048576,
        2097152,
        4194304,
    }
)

MAX_CONTAINER_DEPTH: int = 16
MAX_TOTAL_NODES: int = 1024


def deep_freeze(value: object) -> object:
    """Recursively freeze mappings and sequences into immutable snapshots."""
    if isinstance(value, MappingProxyType):
        return value
    if isinstance(value, Mapping):
        return MappingProxyType({k: deep_freeze(v) for k, v in value.items()})
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(deep_freeze(item) for item in value)
    return value


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
class CommitmentDescriptor:
    """Explicit grant key commitment descriptor."""

    alg: str
    kdf: Mapping[str, object]
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.alg, str) or not self.alg:
            raise ValueError("CommitmentDescriptor alg must be a non-empty string")
        if not isinstance(self.kdf, Mapping):
            raise TypeError("CommitmentDescriptor kdf must be a Mapping")
        if not isinstance(self.value, str):
            raise TypeError("CommitmentDescriptor value must be a string")
        object.__setattr__(self, "kdf", deep_freeze(self.kdf))


@dataclass(frozen=True, slots=True)
class PayloadDescriptor:
    """Protected description of an encrypted payload."""

    type: PayloadType
    alg: str
    kdf: Mapping[str, object]
    metadata_policy: MetadataPolicy
    chunk_size: int | None = None
    nonce_prefix: str | None = None
    nonce: str | None = None
    plaintext_length: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.type, PayloadType):
            raise TypeError(f"Invalid payload type: {self.type}")
        if not isinstance(self.alg, str) or not self.alg:
            raise ValueError("PayloadDescriptor alg must be a non-empty string")
        if not isinstance(self.kdf, Mapping):
            raise TypeError("PayloadDescriptor kdf must be a Mapping")
        if not isinstance(self.metadata_policy, MetadataPolicy):
            raise TypeError(f"Invalid metadata policy: {self.metadata_policy}")

        object.__setattr__(self, "kdf", deep_freeze(self.kdf))

        if self.type == PayloadType.FILE:
            if self.chunk_size is not None and self.chunk_size not in VALID_CHUNK_SIZES:
                raise ValueError(
                    f"chunk_size {self.chunk_size} not in legal allowlist {sorted(VALID_CHUNK_SIZES)}"
                )
            if self.nonce is not None or self.plaintext_length is not None:
                raise ValueError(
                    "Text payload fields (nonce, plaintext_length) forbidden on file payload"
                )
        elif self.type == PayloadType.TEXT:
            if self.chunk_size is not None or self.nonce_prefix is not None:
                raise ValueError(
                    "File payload fields (chunk_size, nonce_prefix) forbidden on text payload"
                )
            if self.plaintext_length is not None and (
                self.plaintext_length < 0 or self.plaintext_length > 1048576
            ):
                raise ValueError(
                    f"Text plaintext_length {self.plaintext_length} out of bounds (0..1048576)"
                )


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
    commitment: CommitmentDescriptor | Mapping[str, object] | None = None
    key_fingerprint: str | None = None
    password_kdf: Mapping[str, object] | None = None
    combined_kdf: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.grant_id, str):
            raise TypeError("grant_id must be a string")
        if not isinstance(self.type, GrantType):
            raise TypeError(f"Invalid grant type: {self.type}")
        if not isinstance(self.kek_derivation, Mapping):
            raise TypeError("AccessGrant kek_derivation must be a Mapping")
        if not isinstance(self.wrap_alg, str):
            raise TypeError("wrap_alg must be a string")
        if not isinstance(self.wrap_nonce, str):
            raise TypeError("wrap_nonce must be a string")
        if not isinstance(self.wrapped_dek, str):
            raise TypeError("wrapped_dek must be a string")
        if not isinstance(self.tag, str):
            raise TypeError("tag must be a string")

        if self.key_fingerprint is not None:
            if not isinstance(self.key_fingerprint, str):
                raise TypeError("key_fingerprint must be a string")
            if (
                not self.key_fingerprint.startswith("ssc-k1-")
                or len(self.key_fingerprint) != 59
            ):
                raise ValueError("Invalid key fingerprint format in AccessGrant")

        object.__setattr__(self, "kek_derivation", deep_freeze(self.kek_derivation))

        if self.commitment is not None:
            if isinstance(self.commitment, CommitmentDescriptor):
                pass
            elif isinstance(self.commitment, Mapping):
                object.__setattr__(self, "commitment", deep_freeze(self.commitment))
            else:
                raise TypeError(
                    "AccessGrant commitment must be a CommitmentDescriptor or Mapping"
                )

        if self.password_kdf is not None:
            if not isinstance(self.password_kdf, Mapping):
                raise TypeError("password_kdf must be a Mapping")
            object.__setattr__(self, "password_kdf", deep_freeze(self.password_kdf))

        if self.combined_kdf is not None:
            if not isinstance(self.combined_kdf, Mapping):
                raise TypeError("combined_kdf must be a Mapping")
            object.__setattr__(self, "combined_kdf", deep_freeze(self.combined_kdf))


@dataclass(frozen=True, slots=True)
class AccessBlock:
    """Future-compatible access container for v2 encrypted objects."""

    version: int
    policy: AccessPolicy
    grants: Sequence[AccessGrant]

    def __post_init__(self) -> None:
        if self.version != 1:
            raise ValueError("AccessBlock version must be 1")
        if self.policy != AccessPolicy.SINGLE_GRANT:
            raise ValueError("AccessBlock policy must be single-grant in v2.0.0")
        if len(self.grants) != 1:
            raise ValueError(
                "AccessBlock grants must contain exactly one grant in v2.0.0"
            )
        object.__setattr__(self, "grants", tuple(self.grants))


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

    def __post_init__(self) -> None:
        if self.format != "SSC2":
            raise ValueError("V2Header format must be 'SSC2'")
        if self.version != 2:
            raise ValueError("V2Header version must be 2")
        if not isinstance(self.payload, PayloadDescriptor):
            raise TypeError("payload must be a PayloadDescriptor")
        if self.object_type != self.payload.type.value:
            raise ValueError(
                f"object_type '{self.object_type}' does not match payload.type '{self.payload.type.value}'"
            )
        if not isinstance(self.access, AccessBlock):
            raise TypeError("access must be an AccessBlock")
        if not isinstance(self.metadata, Mapping):
            raise TypeError("metadata must be a Mapping")
        object.__setattr__(self, "metadata", deep_freeze(self.metadata))


def canonical_json(value: object) -> bytes:
    """Serialize protected header data as deterministic UTF-8 JSON bytes."""
    counter = [0]
    plain_object = _to_json_compatible(value, depth=0, counter=counter)
    return json.dumps(
        plain_object,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _to_json_compatible(
    value: object, depth: int = 0, counter: list[int] | None = None
) -> object:
    """Convert v2 value objects into plain JSON-compatible containers.

    Enforces:
    - Maximum container nesting depth: 16
    - Maximum total nodes: 1024
    - Strict string dictionary keys (never coerced with str(k))
    - Rejection of floating-point numbers, NaN, and Infinity
    """
    if counter is None:
        counter = [0]

    counter[0] += 1
    if counter[0] > MAX_TOTAL_NODES:
        raise ValueError(
            f"JSON container exceeds maximum node limit ({MAX_TOTAL_NODES})"
        )
    if depth > MAX_CONTAINER_DEPTH:
        raise ValueError(
            f"JSON container exceeds maximum depth limit ({MAX_CONTAINER_DEPTH})"
        )

    if isinstance(value, Enum):
        unwrapped = value.value
        if isinstance(unwrapped, float):
            raise TypeError(
                "Floating-point numbers are not permitted in SSC canonical JSON"
            )
        # pyrefly: ignore [no-any-return-implicit]
        return unwrapped
    if is_dataclass(value) and not isinstance(value, type):
        result: dict[str, object] = {}
        for f in fields(value):
            val = getattr(value, f.name)
            if val is not None:
                result[f.name] = _to_json_compatible(val, depth + 1, counter)
        return result
    if isinstance(value, (Mapping, MappingProxyType)):
        mapping_result: dict[str, object] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise TypeError(
                    f"Dictionary keys must be strings, got {type(k).__name__}"
                )
            mapping_result[k] = _to_json_compatible(v, depth + 1, counter)
        return mapping_result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_to_json_compatible(item, depth + 1, counter) for item in value]
    if isinstance(value, float):
        raise TypeError(
            "Floating-point numbers are not permitted in SSC canonical JSON"
        )
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, str) or value is None:
        return value

    raise TypeError(f"Unsupported type in canonical JSON: {type(value).__name__}")
