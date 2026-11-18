"""Unit tests for pure V2 vault schema and validation."""

from __future__ import annotations

import json
from types import MappingProxyType

import pytest

from secure_string_cipher.v2.envelope import canonical_json
from secure_string_cipher.v2.key_identity import (
    ExternalKeyReference,
    KeyIdentity,
    KeyPublicMetadata,
    KeyStatus,
    KeyStorageMode,
    KeyType,
    compute_fingerprint,
)
from secure_string_cipher.v2.vault_schema import (
    V2VaultDocument,
    V2VaultKdf,
    V2VaultMeta,
    V2VaultSecretContainer,
    b64url_decode,
    b64url_encode,
    dispatch_vault_document,
    validate_v2_vault_document,
)


def _sample_kdf() -> V2VaultKdf:
    return V2VaultKdf(
        alg="argon2id",
        version=19,
        memory_kib=65536,
        time_cost=3,
        parallelism=4,
        hash_len=32,
        salt=b64url_encode(b"0" * 16),
    )


def _sample_meta() -> V2VaultMeta:
    return V2VaultMeta(
        vault_id=b64url_encode(b"v" * 16),
        revision=1,
        wrap_generation=1,
        vault_kdf=_sample_kdf(),
    )


def _sample_key_record(
    key_id: str = "test-key",
    storage: KeyStorageMode = KeyStorageMode.EXTERNAL_ONLY,
    status: KeyStatus = KeyStatus.ACTIVE,
    secret_container: V2VaultSecretContainer | None = None,
) -> KeyIdentity:
    secret_bytes = b"k" * 32
    fp = compute_fingerprint(secret_bytes)
    return KeyIdentity(
        schema_version=1,
        record_id=b64url_encode(b"r" * 16),
        id=key_id,
        type=KeyType.SYMMETRIC,
        fingerprint=fp,
        storage=storage,
        status=status,
        created_at="2026-09-09T00:00:00Z",
        updated_at="2026-09-09T00:00:00Z",
        last_used_at=None,
        public_metadata=KeyPublicMetadata(
            label=key_id,
            algorithm="hkdf-sha256",
            key_length=32,
            format="ssckey-v1",
        ),
        external=ExternalKeyReference(path_hint="keys/test.ssckey"),
        vault_secret=secret_container.to_dict() if secret_container else None,
    )


def test_b64url_roundtrip() -> None:
    data = b"hello\x00world\xff"
    token = b64url_encode(data)
    assert "=" not in token
    assert "+" not in token
    assert "/" not in token
    assert b64url_decode(token) == data
    assert b64url_decode(token, expected_length=len(data)) == data


def test_b64url_decode_rejections() -> None:
    with pytest.raises(ValueError, match="padding"):
        b64url_decode("YQ==")
    with pytest.raises(ValueError, match="Standard Base64"):
        b64url_decode("a+b/")
    with pytest.raises(ValueError, match="Whitespace"):
        b64url_decode("a b")
    with pytest.raises(ValueError, match="Expected 16 decoded bytes"):
        b64url_decode(b64url_encode(b"too-short"), expected_length=16)


def test_vault_kdf_validation() -> None:
    kdf = _sample_kdf()
    assert kdf.alg == "argon2id"
    assert kdf.memory_kib == 65536

    with pytest.raises(ValueError, match="alg"):
        V2VaultKdf(
            alg="pbkdf2",
            version=19,
            memory_kib=65536,
            time_cost=3,
            parallelism=4,
            hash_len=32,
            salt=b64url_encode(b"0" * 16),
        )

    with pytest.raises(ValueError, match="version"):
        V2VaultKdf(
            alg="argon2id",
            version=18,
            memory_kib=65536,
            time_cost=3,
            parallelism=4,
            hash_len=32,
            salt=b64url_encode(b"0" * 16),
        )

    with pytest.raises(ValueError, match="memory_kib"):
        V2VaultKdf(
            alg="argon2id",
            version=19,
            memory_kib=32768,
            time_cost=3,
            parallelism=4,
            hash_len=32,
            salt=b64url_encode(b"0" * 16),
        )


def test_vault_meta_validation() -> None:
    meta = _sample_meta()
    assert meta.revision == 1

    with pytest.raises(ValueError, match="revision"):
        V2VaultMeta(
            vault_id=b64url_encode(b"v" * 16),
            revision=0,
            wrap_generation=1,
            vault_kdf=_sample_kdf(),
        )

    with pytest.raises(ValueError, match="wrap_generation"):
        V2VaultMeta(
            vault_id=b64url_encode(b"v" * 16),
            revision=1,
            wrap_generation=0,
            vault_kdf=_sample_kdf(),
        )


def test_secret_container_validation() -> None:
    container = V2VaultSecretContainer(
        protection="vault-wrapped",
        wrap_alg="aes-256-gcm",
        kek_derivation=MappingProxyType(
            {"alg": "hkdf-sha256", "salt": b64url_encode(b"s" * 32)}
        ),
        nonce=b64url_encode(b"n" * 12),
        encrypted_key_material=b64url_encode(b"c" * 32),
        tag=b64url_encode(b"t" * 16),
    )
    assert container.protection == "vault-wrapped"

    with pytest.raises(ValueError, match="wrap_alg"):
        V2VaultSecretContainer(
            protection="vault-wrapped",
            wrap_alg="chacha20",
            kek_derivation=MappingProxyType(
                {"alg": "hkdf-sha256", "salt": b64url_encode(b"s" * 32)}
            ),
            nonce=b64url_encode(b"n" * 12),
            encrypted_key_material=b64url_encode(b"c" * 32),
            tag=b64url_encode(b"t" * 16),
        )


def test_v2_vault_document_validation() -> None:
    key_rec = _sample_key_record()
    v2_doc = V2VaultDocument(
        schema_version=2,
        vault_meta=_sample_meta(),
        passphrases={"alpha": "pass-123"},
        keys={key_rec.fingerprint: key_rec},
    )

    doc_dict = v2_doc.to_dict()
    canonical_bytes = canonical_json(doc_dict)

    # Valid round-trip
    parsed_doc = validate_v2_vault_document(
        doc_dict, raw_json_text=canonical_bytes.decode("utf-8")
    )
    assert parsed_doc.schema_version == 2
    assert parsed_doc.passphrases["alpha"] == "pass-123"
    assert key_rec.fingerprint in parsed_doc.keys

    # Non-canonical formatting rejected when raw_json_text is provided
    non_canonical = json.dumps(doc_dict, indent=2)
    with pytest.raises(ValueError, match="canonical JSON"):
        validate_v2_vault_document(doc_dict, raw_json_text=non_canonical)


def test_dispatch_vault_document_schema_1() -> None:
    flat_json = json.dumps({"github": "secret1", "aws": "secret2"})
    doc_type, doc = dispatch_vault_document(flat_json)
    assert doc_type == 1
    assert doc == {"github": "secret1", "aws": "secret2"}


def test_dispatch_legacy_vault_with_reserved_keys() -> None:
    # Section 11.2: Detect legacy all-string dictionary first; string "2" is not a schema discriminator
    legacy_reserved = json.dumps(
        {
            "schema_version": "my_password",
            "items": "stored_item",
            "vault_meta": "custom_meta",
        }
    )
    doc_type, doc = dispatch_vault_document(legacy_reserved)
    assert doc_type == 1
    assert doc == {
        "schema_version": "my_password",
        "items": "stored_item",
        "vault_meta": "custom_meta",
    }

    # String value "2" is not a schema discriminator
    legacy_str_two = json.dumps({"schema_version": "2"})
    doc_type2, doc2 = dispatch_vault_document(legacy_str_two)
    assert doc_type2 == 1
    assert doc2 == {"schema_version": "2"}


def test_dispatch_vault_document_schema_2() -> None:
    v2_doc = V2VaultDocument(
        schema_version=2,
        vault_meta=_sample_meta(),
        passphrases={"github": "secret1"},
        keys={},
    )
    canonical_str = canonical_json(v2_doc.to_dict()).decode("utf-8")
    doc_type, doc = dispatch_vault_document(canonical_str)
    assert doc_type == 2
    assert isinstance(doc, V2VaultDocument)
    assert doc.passphrases["github"] == "secret1"


def test_dispatch_duplicate_keys_rejected() -> None:
    duplicate_json = '{"a":"1","a":"2"}'
    with pytest.raises(ValueError, match="Duplicate key"):
        dispatch_vault_document(duplicate_json)


def test_dispatch_invalid_types_rejected() -> None:
    with pytest.raises(ValueError):
        dispatch_vault_document('{"a": 123}')
    with pytest.raises(ValueError):
        dispatch_vault_document('{"a": ["nested"]}')
    with pytest.raises(ValueError, match="schema_version"):
        dispatch_vault_document('{"schema_version": 3}')


def test_vault_kdf_edge_cases() -> None:
    kdf = _sample_kdf()
    assert kdf.to_dict()["alg"] == "argon2id"
    with pytest.raises(ValueError, match="alg"):
        V2VaultKdf(
            alg="pbkdf2",
            version=19,
            memory_kib=65536,
            time_cost=3,
            parallelism=4,
            hash_len=32,
            salt=b64url_encode(b"0" * 16),
        )
    with pytest.raises(ValueError, match="memory_kib"):
        V2VaultKdf(
            alg="argon2id",
            version=19,
            memory_kib=100,
            time_cost=3,
            parallelism=4,
            hash_len=32,
            salt=b64url_encode(b"0" * 16),
        )
    with pytest.raises(ValueError, match="time_cost"):
        V2VaultKdf(
            alg="argon2id",
            version=19,
            memory_kib=65536,
            time_cost=0,
            parallelism=4,
            hash_len=32,
            salt=b64url_encode(b"0" * 16),
        )
    with pytest.raises(ValueError, match="parallelism"):
        V2VaultKdf(
            alg="argon2id",
            version=19,
            memory_kib=65536,
            time_cost=3,
            parallelism=0,
            hash_len=32,
            salt=b64url_encode(b"0" * 16),
        )
    with pytest.raises(ValueError, match="Expected 16 decoded bytes"):
        V2VaultKdf(
            alg="argon2id",
            version=19,
            memory_kib=65536,
            time_cost=3,
            parallelism=4,
            hash_len=32,
            salt=b64url_encode(b"short"),
        )


def test_vault_meta_edge_cases() -> None:
    with pytest.raises(ValueError, match="revision"):
        V2VaultMeta(
            vault_id=b64url_encode(b"v" * 16),
            revision=0,
            wrap_generation=1,
            vault_kdf=_sample_kdf(),
        )
    with pytest.raises(ValueError, match="wrap_generation"):
        V2VaultMeta(
            vault_id=b64url_encode(b"v" * 16),
            revision=1,
            wrap_generation=0,
            vault_kdf=_sample_kdf(),
        )
    with pytest.raises(TypeError, match="vault_kdf"):
        V2VaultMeta(
            vault_id=b64url_encode(b"v" * 16),
            revision=1,
            wrap_generation=1,
            vault_kdf="not-kdf",  # type: ignore[arg-type]
        )


def test_vault_document_edge_cases() -> None:
    with pytest.raises(ValueError, match="schema_version"):
        V2VaultDocument(
            schema_version=1,
            vault_meta=_sample_meta(),
            passphrases={},
            keys={},
        )
    with pytest.raises(TypeError, match="vault_meta"):
        V2VaultDocument(
            schema_version=2,
            vault_meta="invalid",  # type: ignore[arg-type]
            passphrases={},
            keys={},
        )
    with pytest.raises(TypeError, match="passphrase labels"):
        V2VaultDocument(
            schema_version=2,
            vault_meta=_sample_meta(),
            passphrases={"label": 123},  # type: ignore[dict-item]
            keys={},
        )
    key_rec = _sample_key_record()
    with pytest.raises(ValueError, match="does not match record fingerprint"):
        V2VaultDocument(
            schema_version=2,
            vault_meta=_sample_meta(),
            passphrases={},
            keys={"wrong-fp": key_rec},
        )


def test_validate_v2_vault_document_rejections() -> None:
    with pytest.raises(TypeError, match="dictionary"):
        validate_v2_vault_document("not-a-dict")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="schema_version"):
        validate_v2_vault_document({"schema_version": 1})
    with pytest.raises(ValueError, match="vault_meta"):
        validate_v2_vault_document({"schema_version": 2, "vault_meta": "not-a-dict"})
    valid_meta_dict = _sample_meta().to_dict()
    with pytest.raises(ValueError, match="items"):
        validate_v2_vault_document(
            {
                "schema_version": 2,
                "vault_meta": valid_meta_dict,
                "items": "not-a-dict",
            }
        )
    with pytest.raises(ValueError, match="items.passphrases"):
        validate_v2_vault_document(
            {
                "schema_version": 2,
                "vault_meta": valid_meta_dict,
                "items": {"passphrases": "not-a-dict", "keys": {}},
            }
        )
    with pytest.raises(ValueError, match="items.keys"):
        validate_v2_vault_document(
            {
                "schema_version": 2,
                "vault_meta": valid_meta_dict,
                "items": {"passphrases": {}, "keys": "not-a-dict"},
            }
        )


def test_schema_comprehensive_validation_errors() -> None:
    # V2VaultSecretContainer edge cases
    with pytest.raises(ValueError, match="protection"):
        V2VaultSecretContainer(
            protection="insecure",
            wrap_alg="aes-256-gcm",
            kek_derivation={"alg": "hkdf-sha256", "salt": b64url_encode(b"s" * 32)},
            nonce=b64url_encode(b"n" * 12),
            encrypted_key_material=b64url_encode(b"e" * 32),
            tag=b64url_encode(b"t" * 16),
        )
    with pytest.raises(ValueError, match="wrap_alg"):
        V2VaultSecretContainer(
            protection="vault-wrapped",
            wrap_alg="chacha20-poly1305",
            kek_derivation={"alg": "hkdf-sha256", "salt": b64url_encode(b"s" * 32)},
            nonce=b64url_encode(b"n" * 12),
            encrypted_key_material=b64url_encode(b"e" * 32),
            tag=b64url_encode(b"t" * 16),
        )
    with pytest.raises(TypeError, match="kek_derivation"):
        V2VaultSecretContainer(
            protection="vault-wrapped",
            wrap_alg="aes-256-gcm",
            kek_derivation="not-dict",  # type: ignore[arg-type]
            nonce=b64url_encode(b"n" * 12),
            encrypted_key_material=b64url_encode(b"e" * 32),
            tag=b64url_encode(b"t" * 16),
        )
    with pytest.raises(ValueError, match="kek_derivation alg"):
        V2VaultSecretContainer(
            protection="vault-wrapped",
            wrap_alg="aes-256-gcm",
            kek_derivation={"alg": "pbkdf2", "salt": b64url_encode(b"s" * 32)},
            nonce=b64url_encode(b"n" * 12),
            encrypted_key_material=b64url_encode(b"e" * 32),
            tag=b64url_encode(b"t" * 16),
        )
    with pytest.raises(ValueError, match="kek_derivation salt"):
        V2VaultSecretContainer(
            protection="vault-wrapped",
            wrap_alg="aes-256-gcm",
            kek_derivation={"alg": "hkdf-sha256", "salt": 123},
            nonce=b64url_encode(b"n" * 12),
            encrypted_key_material=b64url_encode(b"e" * 32),
            tag=b64url_encode(b"t" * 16),
        )

    # Document validation edge cases
    with pytest.raises(TypeError, match="passphrases must be a mapping"):
        V2VaultDocument(
            schema_version=2,
            vault_meta=_sample_meta(),
            passphrases="not-map",  # type: ignore[arg-type]
            keys={},
        )
    with pytest.raises(TypeError, match="keys must be a mapping"):
        V2VaultDocument(
            schema_version=2,
            vault_meta=_sample_meta(),
            passphrases={},
            keys="not-map",  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError, match="items.keys keys must be fingerprint strings"):
        V2VaultDocument(
            schema_version=2,
            vault_meta=_sample_meta(),
            passphrases={},
            keys={123: _sample_key_record()},  # type: ignore[dict-item]
        )
    with pytest.raises(TypeError, match="must be a KeyIdentity instance"):
        V2VaultDocument(
            schema_version=2,
            vault_meta=_sample_meta(),
            passphrases={},
            keys={"ssc-k1-test": "not-key-identity"},  # type: ignore[dict-item]
        )


def test_validate_key_record_field_errors() -> None:
    valid_meta = _sample_meta()
    key_rec = _sample_key_record()
    fp = key_rec.fingerprint
    valid_doc = V2VaultDocument(
        schema_version=2,
        vault_meta=valid_meta,
        passphrases={},
        keys={fp: key_rec},
    )

    def _make_doc(rec_dict: object) -> dict[str, object]:
        d = valid_doc.to_dict()
        assert isinstance(d["items"], dict)
        d["items"]["keys"] = {fp: rec_dict}
        return d

    # Non-dict key record
    with pytest.raises(TypeError, match="must be a dictionary"):
        validate_v2_vault_document(_make_doc("not-dict"))

    doc_keys = valid_doc.to_dict()["items"]["keys"]  # type: ignore[index]
    base_rec = dict(doc_keys[fp])  # type: ignore[index]

    # Invalid schema_version
    r = dict(base_rec)
    r["schema_version"] = 2
    with pytest.raises(ValueError, match="schema_version must be 1"):
        validate_v2_vault_document(_make_doc(r))

    # Invalid record_id
    r = dict(base_rec)
    r["record_id"] = 123
    with pytest.raises(TypeError, match="record_id must be a string"):
        validate_v2_vault_document(_make_doc(r))

    # Invalid id
    r = dict(base_rec)
    r["id"] = 123
    with pytest.raises(TypeError, match="id must be a string"):
        validate_v2_vault_document(_make_doc(r))

    # Invalid type
    r = dict(base_rec)
    r["type"] = "unknown-type"
    with pytest.raises(ValueError, match="Unknown key type"):
        validate_v2_vault_document(_make_doc(r))

    # Fingerprint not string
    r = dict(base_rec)
    r["fingerprint"] = 123
    with pytest.raises(TypeError, match="fingerprint must be a string"):
        validate_v2_vault_document(_make_doc(r))

    # Fingerprint mismatch
    r = dict(base_rec)
    r["fingerprint"] = "other-fp"
    with pytest.raises(ValueError, match="does not match index key"):
        validate_v2_vault_document(_make_doc(r))

    # Invalid storage
    r = dict(base_rec)
    r["storage"] = "unknown-storage"
    with pytest.raises(ValueError, match="Unknown storage mode"):
        validate_v2_vault_document(_make_doc(r))

    # Invalid status
    r = dict(base_rec)
    r["status"] = "unknown-status"
    with pytest.raises(ValueError, match="Unknown key status"):
        validate_v2_vault_document(_make_doc(r))

    # Invalid created_at
    r = dict(base_rec)
    r["created_at"] = 123
    with pytest.raises(TypeError, match="created_at must be an ISO-8601 UTC string"):
        validate_v2_vault_document(_make_doc(r))

    # Invalid updated_at
    r = dict(base_rec)
    r["updated_at"] = 123
    with pytest.raises(TypeError, match="updated_at must be an ISO-8601 UTC string"):
        validate_v2_vault_document(_make_doc(r))

    # Invalid last_used_at
    r = dict(base_rec)
    r["last_used_at"] = 123
    with pytest.raises(
        TypeError, match="last_used_at must be an ISO-8601 UTC string or None"
    ):
        validate_v2_vault_document(_make_doc(r))
