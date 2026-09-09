"""Pure structured V2 vault schema and validation.

This module defines the schema dataclasses and pure validators for V2 vault documents.
It has no filesystem, OS, or vault backend dependencies.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any

from secure_string_cipher.v2.envelope import canonical_json, deep_freeze
from secure_string_cipher.v2.key_identity import (
    ExternalKeyReference,
    KeyIdentity,
    KeyPublicMetadata,
    KeyStatus,
    KeyStorageMode,
    KeyType,
)

__all__ = [
    "V2VaultDocument",
    "V2VaultKdf",
    "V2VaultMeta",
    "V2VaultSecretContainer",
    "b64url_decode",
    "b64url_encode",
    "dispatch_vault_document",
    "validate_v2_vault_document",
]


def b64url_encode(data: bytes) -> str:
    """Encode bytes to strict unpadded URL-safe Base64."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(token: str, expected_length: int | None = None) -> bytes:
    """Decode strict unpadded URL-safe Base64 with length validation."""
    if not isinstance(token, str):
        raise TypeError("Base64 token must be a string")
    if "=" in token:
        raise ValueError("Base64 padding is not permitted")
    if "+" in token or "/" in token:
        raise ValueError("Standard Base64 characters are not permitted")
    if any(c.isspace() for c in token):
        raise ValueError("Whitespace in Base64 is not permitted")

    padded = token + "=" * (-len(token) % 4)
    decoded = base64.urlsafe_b64decode(padded)

    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != token:
        raise ValueError("Invalid Base64 trailing bits")

    if expected_length is not None and len(decoded) != expected_length:
        raise ValueError(
            f"Expected {expected_length} decoded bytes, got {len(decoded)}"
        )

    return decoded


def _validate_iso_utc_timestamp(timestamp: str) -> None:
    """Validate that timestamp is a strict ISO-8601 UTC string ending in 'Z'."""
    if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
        raise ValueError(
            f"Timestamp must be an ISO-8601 UTC string ending with 'Z', got {timestamp!r}"
        )
    try:
        dt = datetime.fromisoformat(timestamp[:-1])
        if dt.tzinfo is not None:
            raise ValueError("Timestamp contains embedded timezone offset before 'Z'")
    except ValueError as e:
        raise ValueError(f"Invalid timestamp format: {timestamp!r}") from e


@dataclass(frozen=True, slots=True)
class V2VaultKdf:
    """Argon2id KDF descriptor for inner vault-copy root key derivation."""

    alg: str
    version: int
    memory_kib: int
    time_cost: int
    parallelism: int
    hash_len: int
    salt: str

    def __post_init__(self) -> None:
        if self.alg != "argon2id":
            raise ValueError(f"vault_kdf alg must be 'argon2id', got {self.alg!r}")
        if (
            not (isinstance(self.version, int) and not isinstance(self.version, bool))
            or self.version != 19
        ):
            raise ValueError(f"vault_kdf version must be 19, got {self.version}")
        if (
            not (
                isinstance(self.memory_kib, int)
                and not isinstance(self.memory_kib, bool)
            )
            or self.memory_kib != 65536
        ):
            raise ValueError(
                f"vault_kdf memory_kib must be 65536, got {self.memory_kib}"
            )
        if (
            not (
                isinstance(self.time_cost, int) and not isinstance(self.time_cost, bool)
            )
            or self.time_cost != 3
        ):
            raise ValueError(f"vault_kdf time_cost must be 3, got {self.time_cost}")
        if (
            not (
                isinstance(self.parallelism, int)
                and not isinstance(self.parallelism, bool)
            )
            or self.parallelism != 4
        ):
            raise ValueError(f"vault_kdf parallelism must be 4, got {self.parallelism}")
        if (
            not (isinstance(self.hash_len, int) and not isinstance(self.hash_len, bool))
            or self.hash_len != 32
        ):
            raise ValueError(f"vault_kdf hash_len must be 32, got {self.hash_len}")
        b64url_decode(self.salt, expected_length=16)

    def to_dict(self) -> dict[str, object]:
        return {
            "alg": self.alg,
            "hash_len": self.hash_len,
            "memory_kib": self.memory_kib,
            "parallelism": self.parallelism,
            "salt": self.salt,
            "time_cost": self.time_cost,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class V2VaultMeta:
    """Metadata container for V2 structured vault."""

    vault_id: str
    revision: int
    wrap_generation: int
    vault_kdf: V2VaultKdf

    def __post_init__(self) -> None:
        if not isinstance(self.vault_id, str):
            raise TypeError("vault_meta vault_id must be a string")
        b64url_decode(self.vault_id, expected_length=16)
        if (
            not (isinstance(self.revision, int) and not isinstance(self.revision, bool))
            or self.revision < 1
        ):
            raise ValueError("vault_meta revision must be a positive integer >= 1")
        if (
            not (
                isinstance(self.wrap_generation, int)
                and not isinstance(self.wrap_generation, bool)
            )
            or self.wrap_generation < 1
        ):
            raise ValueError(
                "vault_meta wrap_generation must be a positive integer >= 1"
            )
        if not isinstance(self.vault_kdf, V2VaultKdf):
            raise TypeError("vault_meta vault_kdf must be a V2VaultKdf instance")

    def to_dict(self) -> dict[str, object]:
        return {
            "revision": self.revision,
            "vault_id": self.vault_id,
            "vault_kdf": self.vault_kdf.to_dict(),
            "wrap_generation": self.wrap_generation,
        }


@dataclass(frozen=True, slots=True)
class V2VaultSecretContainer:
    """Inner-wrap container for vault-copy managed keys."""

    protection: str
    wrap_alg: str
    kek_derivation: Mapping[str, object]
    nonce: str
    encrypted_key_material: str
    tag: str

    def __post_init__(self) -> None:
        if self.protection != "vault-wrapped":
            raise ValueError(
                f"vault_secret protection must be 'vault-wrapped', got {self.protection!r}"
            )
        if self.wrap_alg != "aes-256-gcm":
            raise ValueError(
                f"vault_secret wrap_alg must be 'aes-256-gcm', got {self.wrap_alg!r}"
            )
        if not isinstance(self.kek_derivation, (dict, MappingProxyType)):
            raise TypeError("kek_derivation must be a mapping")

        kek_alg = self.kek_derivation.get("alg")
        if kek_alg != "hkdf-sha256":
            raise ValueError(
                f"kek_derivation alg must be 'hkdf-sha256', got {kek_alg!r}"
            )
        salt_val = self.kek_derivation.get("salt")
        if not isinstance(salt_val, str):
            raise ValueError("kek_derivation salt must be a string")
        b64url_decode(salt_val, expected_length=32)

        if not isinstance(self.nonce, str):
            raise TypeError("vault_secret nonce must be a string")
        b64url_decode(self.nonce, expected_length=12)

        if not isinstance(self.encrypted_key_material, str):
            raise TypeError("vault_secret encrypted_key_material must be a string")
        b64url_decode(self.encrypted_key_material, expected_length=32)

        if not isinstance(self.tag, str):
            raise TypeError("vault_secret tag must be a string")
        b64url_decode(self.tag, expected_length=16)

        object.__setattr__(self, "kek_derivation", deep_freeze(self.kek_derivation))

    def to_dict(self) -> dict[str, object]:
        return {
            "encrypted_key_material": self.encrypted_key_material,
            "kek_derivation": dict(self.kek_derivation),
            "nonce": self.nonce,
            "protection": self.protection,
            "tag": self.tag,
            "wrap_alg": self.wrap_alg,
        }


@dataclass(frozen=True, slots=True)
class V2VaultDocument:
    """Complete validated V2 structured vault document."""

    schema_version: int
    vault_meta: V2VaultMeta
    passphrases: Mapping[str, str]
    keys: Mapping[str, KeyIdentity]

    def __post_init__(self) -> None:
        if self.schema_version != 2:
            raise ValueError(
                f"V2VaultDocument schema_version must be 2, got {self.schema_version}"
            )
        if not isinstance(self.vault_meta, V2VaultMeta):
            raise TypeError("vault_meta must be a V2VaultMeta instance")
        if not isinstance(self.passphrases, (dict, MappingProxyType)):
            raise TypeError("passphrases must be a mapping")
        if not isinstance(self.keys, (dict, MappingProxyType)):
            raise TypeError("keys must be a mapping")

        for k, v in self.passphrases.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise TypeError("passphrase labels and values must strictly be strings")

        for fp, key_record in self.keys.items():
            if not isinstance(fp, str):
                raise TypeError("items.keys keys must be fingerprint strings")
            if not isinstance(key_record, KeyIdentity):
                raise TypeError(
                    f"items.keys value for {fp} must be a KeyIdentity instance"
                )
            if key_record.fingerprint != fp:
                raise ValueError(
                    f"items.keys index '{fp}' does not match record fingerprint '{key_record.fingerprint}'"
                )

        object.__setattr__(self, "passphrases", deep_freeze(self.passphrases))
        object.__setattr__(self, "keys", deep_freeze(self.keys))

    def to_dict(self) -> dict[str, object]:
        """Convert to canonical document dictionary ready for canonical_json serialization."""
        serialized_keys: dict[str, object] = {}
        for fp, key_record in self.keys.items():
            key_dict: dict[str, object] = {
                "created_at": key_record.created_at,
                "external": {"path_hint": key_record.external.path_hint},
                "fingerprint": key_record.fingerprint,
                "id": key_record.id,
                "last_used_at": key_record.last_used_at,
                "public_metadata": {
                    "algorithm": key_record.public_metadata.algorithm,
                    "format": key_record.public_metadata.format,
                    "key_length": key_record.public_metadata.key_length,
                    "label": key_record.public_metadata.label,
                },
                "record_id": key_record.record_id,
                "schema_version": key_record.schema_version,
                "status": key_record.status.value,
                "storage": key_record.storage.value,
                "type": key_record.type.value,
                "updated_at": key_record.updated_at,
                "vault_secret": (
                    dict(key_record.vault_secret)
                    if key_record.vault_secret is not None
                    else None
                ),
            }
            serialized_keys[fp] = key_dict

        return {
            "items": {
                "keys": serialized_keys,
                "passphrases": dict(self.passphrases),
            },
            "schema_version": 2,
            "vault_meta": self.vault_meta.to_dict(),
        }


def _as_int(val: Any, default: int = 0) -> int:
    return val if isinstance(val, int) and not isinstance(val, bool) else default


def _as_str(val: Any, default: str = "") -> str:
    return val if isinstance(val, str) else default


def _reject_duplicate_object_hook(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate key in JSON: {key!r}")
        result[key] = value
    return result


def parse_duplicate_free_json(json_str: str) -> Any:
    """Parse JSON string, rejecting duplicate keys at any depth."""
    return json.loads(json_str, object_pairs_hook=_reject_duplicate_object_hook)


def validate_v2_vault_document(
    doc: dict[str, Any], raw_json_text: str | None = None
) -> V2VaultDocument:
    """Validate a parsed dictionary as an exact V2 vault document.

    If raw_json_text is provided, enforces that raw_json_text exactly matches
    the canonical JSON serialization of the document.
    """
    if not isinstance(doc, dict):
        raise TypeError("V2 vault document must be a dictionary")

    expected_top_keys = {"schema_version", "vault_meta", "items"}
    extra_top = set(doc.keys()) - expected_top_keys
    if extra_top:
        raise ValueError(
            f"Unexpected top-level keys in V2 vault document: {sorted(extra_top)}"
        )

    schema_version = doc.get("schema_version")
    if (
        not (isinstance(schema_version, int) and not isinstance(schema_version, bool))
        or schema_version != 2
    ):
        raise ValueError(f"Expected schema_version 2, got {schema_version!r}")

    # Validate vault_meta
    meta_dict = doc.get("vault_meta")
    if not isinstance(meta_dict, dict):
        raise ValueError("vault_meta must be a dictionary")

    expected_meta_keys = {"vault_id", "revision", "wrap_generation", "vault_kdf"}
    extra_meta = set(meta_dict.keys()) - expected_meta_keys
    if extra_meta:
        raise ValueError(f"Unexpected keys in vault_meta: {sorted(extra_meta)}")

    kdf_dict = meta_dict.get("vault_kdf")
    if not isinstance(kdf_dict, dict):
        raise ValueError("vault_meta.vault_kdf must be a dictionary")

    expected_kdf_keys = {
        "alg",
        "version",
        "memory_kib",
        "time_cost",
        "parallelism",
        "hash_len",
        "salt",
    }
    extra_kdf = set(kdf_dict.keys()) - expected_kdf_keys
    if extra_kdf:
        raise ValueError(f"Unexpected keys in vault_kdf: {sorted(extra_kdf)}")

    vault_kdf = V2VaultKdf(
        alg=_as_str(kdf_dict.get("alg")),
        version=_as_int(kdf_dict.get("version")),
        memory_kib=_as_int(kdf_dict.get("memory_kib")),
        time_cost=_as_int(kdf_dict.get("time_cost")),
        parallelism=_as_int(kdf_dict.get("parallelism")),
        hash_len=_as_int(kdf_dict.get("hash_len")),
        salt=_as_str(kdf_dict.get("salt")),
    )

    vault_meta = V2VaultMeta(
        vault_id=_as_str(meta_dict.get("vault_id")),
        revision=_as_int(meta_dict.get("revision")),
        wrap_generation=_as_int(meta_dict.get("wrap_generation")),
        vault_kdf=vault_kdf,
    )

    # Validate items
    items_dict = doc.get("items")
    if not isinstance(items_dict, dict):
        raise ValueError("items must be a dictionary")

    expected_items_keys = {"passphrases", "keys"}
    extra_items = set(items_dict.keys()) - expected_items_keys
    if extra_items:
        raise ValueError(f"Unexpected keys in items: {sorted(extra_items)}")

    passphrases_dict = items_dict.get("passphrases")
    if not isinstance(passphrases_dict, dict):
        raise ValueError("items.passphrases must be a dictionary")

    for k, v in passphrases_dict.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise TypeError("items.passphrases must contain string keys and values")

    keys_dict = items_dict.get("keys")
    if not isinstance(keys_dict, dict):
        raise ValueError("items.keys must be a dictionary")

    parsed_keys: dict[str, KeyIdentity] = {}
    for fp, rec in keys_dict.items():
        if not isinstance(fp, str):
            raise TypeError("items.keys key must be string")
        if not isinstance(rec, dict):
            raise TypeError(f"Key record for '{fp}' must be a dictionary")

        rec_schema_version = rec.get("schema_version")
        if (
            not (
                isinstance(rec_schema_version, int)
                and not isinstance(rec_schema_version, bool)
            )
            or rec_schema_version != 1
        ):
            raise ValueError(
                f"Key record schema_version must be 1, got {rec_schema_version!r}"
            )

        record_id = rec.get("record_id")
        if not isinstance(record_id, str):
            raise TypeError("Key record record_id must be a string")
        b64url_decode(record_id, expected_length=16)

        human_id = rec.get("id")
        if not isinstance(human_id, str):
            raise TypeError("Key record id must be a string")

        rec_type_str = rec.get("type")
        try:
            rec_type = KeyType(rec_type_str)
        except ValueError:
            raise ValueError(f"Unknown key type: {rec_type_str!r}") from None

        rec_fp = rec.get("fingerprint")
        if not isinstance(rec_fp, str):
            raise TypeError("Key record fingerprint must be a string")
        if rec_fp != fp:
            raise ValueError(
                f"Key record fingerprint '{rec_fp}' does not match index key '{fp}'"
            )

        storage_str = rec.get("storage")
        try:
            storage = KeyStorageMode(storage_str)
        except ValueError:
            raise ValueError(f"Unknown storage mode: {storage_str!r}") from None

        status_str = rec.get("status")
        try:
            status = KeyStatus(status_str)
        except ValueError:
            raise ValueError(f"Unknown key status: {status_str!r}") from None

        created_at = rec.get("created_at")
        if not isinstance(created_at, str):
            raise TypeError("Key record created_at must be an ISO-8601 UTC string")
        _validate_iso_utc_timestamp(created_at)

        updated_at = rec.get("updated_at")
        if not isinstance(updated_at, str):
            raise TypeError("Key record updated_at must be an ISO-8601 UTC string")
        _validate_iso_utc_timestamp(updated_at)

        last_used_at = rec.get("last_used_at")
        if last_used_at is not None:
            if not isinstance(last_used_at, str):
                raise TypeError(
                    "Key record last_used_at must be an ISO-8601 UTC string or None"
                )
            _validate_iso_utc_timestamp(last_used_at)

        # public_metadata
        pub_meta_raw = rec.get("public_metadata")
        if not isinstance(pub_meta_raw, dict):
            raise TypeError("public_metadata must be a dictionary")
        pub_meta = KeyPublicMetadata(
            label=_as_str(pub_meta_raw.get("label")),
            algorithm=_as_str(pub_meta_raw.get("algorithm")),
            key_length=_as_int(pub_meta_raw.get("key_length")),
            format=_as_str(pub_meta_raw.get("format")),
        )

        # external
        ext_raw = rec.get("external")
        if not isinstance(ext_raw, dict):
            raise TypeError("external must be a dictionary")
        path_hint = ext_raw.get("path_hint")
        if path_hint is not None:
            if not isinstance(path_hint, str):
                raise TypeError("path_hint must be string or None")
            if len(path_hint.encode("utf-8")) > 4096:
                raise ValueError("path_hint exceeds maximum length of 4096 bytes")
        external = ExternalKeyReference(path_hint=path_hint)

        # vault_secret
        secret_raw = rec.get("vault_secret")
        vault_secret: dict[str, object] | None = None
        if storage == KeyStorageMode.EXTERNAL_ONLY:
            if secret_raw is not None:
                raise ValueError(
                    "external-only key records must have vault_secret set to null"
                )
        elif storage == KeyStorageMode.VAULT_COPY:
            if status == KeyStatus.DESTROYED:
                if secret_raw is not None:
                    raise ValueError(
                        "destroyed key records must have vault_secret set to null"
                    )
            else:
                if not isinstance(secret_raw, dict):
                    raise ValueError(
                        "vault-copy active/archived/revoked key records require vault_secret container"
                    )
                raw_kek = secret_raw.get("kek_derivation")
                kek_derivation: Mapping[str, object] = (
                    raw_kek if isinstance(raw_kek, (dict, MappingProxyType)) else {}
                )
                sec_container = V2VaultSecretContainer(
                    protection=_as_str(secret_raw.get("protection")),
                    wrap_alg=_as_str(secret_raw.get("wrap_alg")),
                    kek_derivation=kek_derivation,
                    nonce=_as_str(secret_raw.get("nonce")),
                    encrypted_key_material=_as_str(
                        secret_raw.get("encrypted_key_material")
                    ),
                    tag=_as_str(secret_raw.get("tag")),
                )
                vault_secret = sec_container.to_dict()

        key_identity = KeyIdentity(
            schema_version=rec_schema_version,
            record_id=record_id,
            id=human_id,
            type=rec_type,
            fingerprint=rec_fp,
            storage=storage,
            status=status,
            created_at=created_at,
            updated_at=updated_at,
            last_used_at=last_used_at,
            public_metadata=pub_meta,
            external=external,
            vault_secret=vault_secret,
        )
        parsed_keys[fp] = key_identity

    v2_doc = V2VaultDocument(
        schema_version=2,
        vault_meta=vault_meta,
        passphrases=passphrases_dict,
        keys=parsed_keys,
    )

    if raw_json_text is not None:
        expected_canonical = canonical_json(v2_doc.to_dict())
        if expected_canonical != raw_json_text.encode("utf-8"):
            raise ValueError(
                "V2 vault document does not match canonical JSON representation"
            )

    return v2_doc


def dispatch_vault_document(
    raw_decrypted: str,
) -> tuple[int, dict[str, str] | V2VaultDocument]:
    """Parse and dispatch decrypted vault plaintext to Schema 1 or Schema 2.

    Returns:
        (1, dict[str, str]) for legacy flat dictionary vaults.
        (2, V2VaultDocument) for Schema 2 structured vaults.

    Raises:
        ValueError if parsing or validation fails.
    """
    if not isinstance(raw_decrypted, str):
        raise TypeError("raw_decrypted must be a string")

    try:
        parsed = parse_duplicate_free_json(raw_decrypted)
    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError(f"Invalid JSON document: {e}") from e

    if not isinstance(parsed, dict):
        raise ValueError("Vault document must be a JSON object")

    # Detect valid legacy all-string dictionary first (Section 11.2 line 703):
    # Legacy flat vaults may have keys named 'schema_version', 'items', or 'vault_meta',
    # and a string value "2" is not a Schema 2 discriminator.
    is_legacy_flat = all(
        isinstance(k, str) and isinstance(v, str) for k, v in parsed.items()
    )
    if is_legacy_flat:
        return 1, dict(parsed)

    # If not all-string, check for Schema 2 discriminator
    if "schema_version" in parsed:
        ver = parsed["schema_version"]
        if ver == 2 and isinstance(ver, int) and not isinstance(ver, bool):
            try:
                return 2, validate_v2_vault_document(parsed, raw_decrypted)
            except (TypeError, ValueError) as e:
                raise ValueError(f"Invalid Schema 2 vault document: {e}") from e
        raise ValueError(f"Unsupported vault schema_version: {ver!r}")

    raise ValueError(
        "Vault document is neither a valid legacy flat dictionary nor a supported structured schema"
    )
