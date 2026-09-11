import dataclasses

import pytest

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
    V2VaultKdf,
    V2VaultMeta,
    b64url_encode,
)
from secure_string_cipher.v2.vault_service import V2VaultService


class DummyVaultAdapter:
    def __init__(self):
        self.doc = None


def get_service():
    return V2VaultService(DummyVaultAdapter())


def get_base_meta():
    kdf = V2VaultKdf(
        alg="argon2id",
        version=19,
        memory_kib=65536,
        time_cost=3,
        parallelism=4,
        hash_len=32,
        salt=b64url_encode(b"A" * 16),
    )
    return V2VaultMeta(
        vault_id=b64url_encode(b"V" * 16), revision=1, wrap_generation=1, vault_kdf=kdf
    )


def container_to_dict(container):
    return {
        "protection": container.protection,
        "wrap_alg": container.wrap_alg,
        "kek_derivation": dict(container.kek_derivation),
        "nonce": container.nonce,
        "encrypted_key_material": container.encrypted_key_material,
        "tag": container.tag,
    }


def create_test_record(managed_secret: bytes, key_type: KeyType = KeyType.SYMMETRIC):
    return KeyIdentity(
        schema_version=1,
        record_id=b64url_encode(b"R" * 16),
        id="test-key",
        type=key_type,
        fingerprint=compute_fingerprint(managed_secret),
        storage=KeyStorageMode.VAULT_COPY,
        status=KeyStatus.ACTIVE,
        created_at="2026-09-09T00:00:00Z",
        updated_at="2026-09-09T00:00:00Z",
        last_used_at=None,
        public_metadata=KeyPublicMetadata(
            label="test", algorithm="aes-256-gcm", key_length=256, format="raw"
        ),
        external=ExternalKeyReference(),
    )


def test_inner_record_wrap_unwrap_success():
    svc = get_service()
    meta = get_base_meta()

    root_key = b"R" * 32
    managed_secret = b"M" * 32

    record = create_test_record(managed_secret)

    wrapped_container = svc._wrap_secret(
        root_key,
        managed_secret,
        meta,
        record.record_id,
        record.type,
        record.fingerprint,
    )
    record = dataclasses.replace(
        record, vault_secret=container_to_dict(wrapped_container)
    )

    unwrapped = svc._unwrap_secret(root_key, record, meta)
    assert unwrapped == managed_secret


def test_inner_record_aad_tamper_key_type():
    svc = get_service()
    meta = get_base_meta()

    root_key = b"R" * 32
    managed_secret = b"M" * 32

    record = create_test_record(managed_secret)

    wrapped_container = svc._wrap_secret(
        root_key,
        managed_secret,
        meta,
        record.record_id,
        record.type,
        record.fingerprint,
    )
    record = dataclasses.replace(
        record, vault_secret=container_to_dict(wrapped_container)
    )

    from collections import namedtuple

    FakeType = namedtuple("FakeType", ["value"])

    tampered_record = create_test_record(managed_secret)
    tampered_record = dataclasses.replace(
        tampered_record, vault_secret=container_to_dict(wrapped_container)
    )
    object.__setattr__(tampered_record, "type", FakeType("some-other-type"))

    with pytest.raises(ValueError, match="authentication failed"):
        svc._unwrap_secret(root_key, tampered_record, meta)


def test_inner_record_aad_tamper_vault_id():
    svc = get_service()
    meta = get_base_meta()

    root_key = b"R" * 32
    managed_secret = b"M" * 32

    record = create_test_record(managed_secret)

    wrapped_container = svc._wrap_secret(
        root_key,
        managed_secret,
        meta,
        record.record_id,
        record.type,
        record.fingerprint,
    )
    record = dataclasses.replace(
        record, vault_secret=container_to_dict(wrapped_container)
    )

    tampered_meta = dataclasses.replace(meta, vault_id=b64url_encode(b"W" * 16))

    with pytest.raises(ValueError, match="authentication failed"):
        svc._unwrap_secret(root_key, record, tampered_meta)


def test_inner_record_aad_tamper_fingerprint():
    svc = get_service()
    meta = get_base_meta()

    root_key = b"R" * 32
    managed_secret = b"M" * 32

    record = create_test_record(managed_secret)

    wrapped_container = svc._wrap_secret(
        root_key,
        managed_secret,
        meta,
        record.record_id,
        record.type,
        record.fingerprint,
    )
    record = dataclasses.replace(
        record, vault_secret=container_to_dict(wrapped_container)
    )

    tampered_record = create_test_record(managed_secret)
    tampered_record = dataclasses.replace(
        tampered_record, vault_secret=container_to_dict(wrapped_container)
    )
    object.__setattr__(tampered_record, "fingerprint", "ssc-k1-" + "A" * 52)

    with pytest.raises(ValueError, match="authentication failed"):
        svc._unwrap_secret(root_key, tampered_record, meta)


def test_inner_record_fingerprint_mismatch():
    svc = get_service()
    meta = get_base_meta()

    root_key = b"R" * 32
    managed_secret = b"M" * 32
    fake_secret = b"F" * 32

    record = create_test_record(fake_secret)

    wrapped_container = svc._wrap_secret(
        root_key,
        managed_secret,
        meta,
        record.record_id,
        record.type,
        record.fingerprint,
    )
    record = dataclasses.replace(
        record, vault_secret=container_to_dict(wrapped_container)
    )

    with pytest.raises(ValueError, match="fingerprint mismatch"):
        svc._unwrap_secret(root_key, record, meta)
