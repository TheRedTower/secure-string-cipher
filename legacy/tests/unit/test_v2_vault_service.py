"""Unit tests for V2VaultService key lifecycle and inner-wrap security."""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_string_cipher.passphrase_manager import PassphraseVault
from secure_string_cipher.v2.key_identity import (
    KeyIdentity,
    KeyStatus,
    KeyStorageMode,
    compute_fingerprint,
)
from secure_string_cipher.v2.keyfile import KeyFileData, load_keyfile
from secure_string_cipher.v2.vault_lock import hold_vault_lock
from secure_string_cipher.v2.vault_schema import (
    V2VaultDocument,
    b64url_decode,
    b64url_encode,
)
from secure_string_cipher.v2.vault_service import (
    KeyExportSurvivedRegistrationFailureError,
    V2VaultService,
)

TEST_MASTER = "Master-Passphrase-Vault-2026!"  # pragma: allowlist secret


@pytest.fixture
def vault_service(tmp_path: Path) -> V2VaultService:
    vault_file = tmp_path / "test_vault.enc"
    vault = PassphraseVault(vault_path=str(vault_file), backend="file")
    return V2VaultService(vault=vault)


def test_create_external_only_key(vault_service: V2VaultService) -> None:
    key_record, secret = vault_service.create_key(
        "laptop-external",
        KeyStorageMode.EXTERNAL_ONLY,
        path_hint="~/keys/laptop.ssckey",
        master_password=TEST_MASTER,
    )
    assert key_record.id == "laptop-external"
    assert key_record.storage == KeyStorageMode.EXTERNAL_ONLY
    assert key_record.vault_secret is None
    assert secret is not None
    assert len(secret) == 32
    assert compute_fingerprint(secret) == key_record.fingerprint

    # Fetch key from vault
    fetched_rec, fetched_sec = vault_service.get_key("laptop-external", TEST_MASTER)
    assert fetched_rec.id == "laptop-external"
    assert fetched_sec is None


def test_create_vault_copy_key_and_unwrap(vault_service: V2VaultService) -> None:
    key_record, secret = vault_service.create_key(
        "backup-key",
        KeyStorageMode.VAULT_COPY,
        master_password=TEST_MASTER,
    )
    assert key_record.id == "backup-key"
    assert key_record.storage == KeyStorageMode.VAULT_COPY
    assert key_record.vault_secret is not None
    assert secret is not None
    assert len(secret) == 32

    # Fetch and unwrap
    fetched_rec, fetched_sec = vault_service.get_key("backup-key", TEST_MASTER)
    assert fetched_rec.id == "backup-key"
    assert fetched_sec is not None
    assert fetched_sec == secret
    assert compute_fingerprint(fetched_sec) == fetched_rec.fingerprint


def test_import_and_export_key(vault_service: V2VaultService, tmp_path: Path) -> None:
    secret_bytes = b"x" * 32
    fp = compute_fingerprint(secret_bytes)
    keyfile = KeyFileData(
        version=1,
        key_id="imported-key",
        key_type="symmetric-key",
        kdf="hkdf-sha256",
        fingerprint=fp,
        created_at="2026-09-09T00:00:00Z",
        secret_bytes=secret_bytes,
    )

    imported_rec = vault_service.import_key(
        keyfile,
        KeyStorageMode.VAULT_COPY,
        master_password=TEST_MASTER,
    )
    assert imported_rec.id == "imported-key"
    assert imported_rec.fingerprint == fp

    # Verify import worked
    fetched_rec, fetched_sec = vault_service.get_key("imported-key", TEST_MASTER)
    assert fetched_rec.id == "imported-key"
    assert fetched_sec == secret_bytes

    # Export to path
    export_path = tmp_path / "exported.ssckey"
    vault_service.export_key("imported-key", export_path, TEST_MASTER)
    assert export_path.is_file()

    loaded_keyfile = load_keyfile(export_path)
    assert loaded_keyfile.key_id == "imported-key"
    assert loaded_keyfile.secret_bytes == secret_bytes


def test_duplicate_key_rejection(vault_service: V2VaultService) -> None:
    vault_service.create_key(
        "unique-key",
        KeyStorageMode.EXTERNAL_ONLY,
        master_password=TEST_MASTER,
    )
    with pytest.raises(ValueError, match="already exists"):
        vault_service.create_key(
            "unique-key",
            KeyStorageMode.EXTERNAL_ONLY,
            master_password=TEST_MASTER,
        )


def test_key_lifecycle_transitions(vault_service: V2VaultService) -> None:
    rec, sec = vault_service.create_key(
        "lifecycle-key",
        KeyStorageMode.VAULT_COPY,
        master_password=TEST_MASTER,
    )

    # Archive
    archived = vault_service.archive_key("lifecycle-key", TEST_MASTER)
    assert archived.status == KeyStatus.ARCHIVED
    fetched_archived, unwrap_archived = vault_service.get_key(
        "lifecycle-key", TEST_MASTER
    )
    assert fetched_archived.status == KeyStatus.ARCHIVED
    assert unwrap_archived == sec

    # Revoke
    revoked = vault_service.revoke_key("lifecycle-key", TEST_MASTER)
    assert revoked.status == KeyStatus.REVOKED
    with pytest.raises(ValueError, match="revoked"):
        vault_service.get_key("lifecycle-key", TEST_MASTER)

    # Override revoke
    fetched_revoked, unwrap_revoked = vault_service.get_key(
        "lifecycle-key", TEST_MASTER, allow_revoked=True
    )
    assert fetched_revoked.status == KeyStatus.REVOKED
    assert unwrap_revoked == sec

    # Destroy
    destroyed = vault_service.destroy_key("lifecycle-key", TEST_MASTER)
    assert destroyed.status == KeyStatus.DESTROYED
    assert destroyed.vault_secret is None

    fetched_destroyed, unwrap_destroyed = vault_service.get_key(
        "lifecycle-key", TEST_MASTER
    )
    assert fetched_destroyed.status == KeyStatus.DESTROYED
    assert unwrap_destroyed is None


def test_inner_wrap_tamper_rejection(vault_service: V2VaultService) -> None:
    rec, sec = vault_service.create_key(
        "tamper-target",
        KeyStorageMode.VAULT_COPY,
        master_password=TEST_MASTER,
    )

    # Mutate ciphertext in vault document while holding lock
    with hold_vault_lock(vault_service.lock_target):
        doc_type, v2_doc = vault_service._load_document_locked(TEST_MASTER)
        assert doc_type == 2
        assert isinstance(v2_doc, V2VaultDocument)

        key_rec = v2_doc.keys[rec.fingerprint]
        assert key_rec.vault_secret is not None
        tampered_secret = dict(key_rec.vault_secret)

        # Flip a bit in the encrypted key material
        enc_material = bytearray(
            b64url_decode(str(tampered_secret["encrypted_key_material"]))
        )
        enc_material[0] ^= 1
        tampered_secret["encrypted_key_material"] = b64url_encode(bytes(enc_material))

        tampered_keys = dict(v2_doc.keys)
        tampered_keys[rec.fingerprint] = KeyIdentity(
            schema_version=key_rec.schema_version,
            record_id=key_rec.record_id,
            id=key_rec.id,
            type=key_rec.type,
            fingerprint=key_rec.fingerprint,
            storage=key_rec.storage,
            status=key_rec.status,
            created_at=key_rec.created_at,
            updated_at=key_rec.updated_at,
            last_used_at=key_rec.last_used_at,
            public_metadata=key_rec.public_metadata,
            external=key_rec.external,
            vault_secret=tampered_secret,
        )

        tampered_doc = V2VaultDocument(
            schema_version=2,
            vault_meta=v2_doc.vault_meta,
            passphrases=dict(v2_doc.passphrases),
            keys=tampered_keys,
        )
        # Construct authenticated hostile storage directly; production saves now
        # reject unusable inner records before publishing.
        vault_service.vault.write_raw_vault(
            vault_service.vault._encode_document(2, tampered_doc, TEST_MASTER)
        )

    # Unwrapping must fail authentication
    with pytest.raises(ValueError, match="authentication failed"):
        vault_service.get_key("tamper-target", TEST_MASTER)


def test_service_key_not_found(tmp_path: Path) -> None:
    vault_file = tmp_path / "vault.enc"
    vault_service = V2VaultService(PassphraseVault(vault_path=str(vault_file)))

    with pytest.raises(KeyError, match="not found"):
        vault_service.get_key("nonexistent", TEST_MASTER)

    with pytest.raises(KeyError, match="not found"):
        vault_service.archive_key("nonexistent", TEST_MASTER)

    with pytest.raises(KeyError, match="not found"):
        vault_service.revoke_key("nonexistent", TEST_MASTER)

    with pytest.raises(KeyError, match="not found"):
        vault_service.destroy_key("nonexistent", TEST_MASTER)

    with pytest.raises(KeyError, match="not found"):
        vault_service.export_key("nonexistent", tmp_path / "out.ssckey", TEST_MASTER)


def test_service_unwrap_external_only_raises(tmp_path: Path) -> None:
    vault_file = tmp_path / "vault.enc"
    vault_service = V2VaultService(PassphraseVault(vault_path=str(vault_file)))

    rec, _ = vault_service.create_key(
        key_id="ext-key",
        storage=KeyStorageMode.EXTERNAL_ONLY,
        path_hint="keys/ext.ssckey",
        master_password=TEST_MASTER,
    )

    with hold_vault_lock(vault_service.lock_target):
        doc_type, doc = vault_service._load_document_locked(TEST_MASTER)
        assert doc_type == 2
        assert isinstance(doc, V2VaultDocument)

        root_key = vault_service._derive_vault_root_key(
            TEST_MASTER, doc.vault_meta.vault_kdf
        )
        # unwrap_secret raises ValueError when record has no vault_secret
        with pytest.raises(ValueError, match="has no vault_secret"):
            vault_service._unwrap_secret(root_key, rec, doc.vault_meta)

    # export_key also raises ValueError for external-only keys
    with pytest.raises(ValueError, match="external-only"):
        vault_service.export_key("ext-key", tmp_path / "out.ssckey", TEST_MASTER)


def test_service_list_keys(tmp_path: Path) -> None:
    vault_file = tmp_path / "vault.enc"
    vault_service = V2VaultService(PassphraseVault(vault_path=str(vault_file)))

    vault_service.create_key(
        key_id="key-b",
        storage=KeyStorageMode.VAULT_COPY,
        master_password=TEST_MASTER,
    )
    vault_service.create_key(
        key_id="key-a",
        storage=KeyStorageMode.EXTERNAL_ONLY,
        master_password=TEST_MASTER,
    )

    all_keys = vault_service.list_keys(TEST_MASTER)
    assert len(all_keys) == 2
    assert [k.id for k in all_keys] == ["key-a", "key-b"]


def test_create_key_invalid_id_rejected(vault_service: V2VaultService) -> None:
    for invalid_id in [
        "UPPERCASE",
        "1starts-with-digit",
        "-starts-with-dash",
        "has spaces",
        "has_special$char",
        "",
        "a" * 65,
    ]:
        with pytest.raises(ValueError, match="key_id must match pattern"):
            vault_service.create_key(
                invalid_id,
                KeyStorageMode.EXTERNAL_ONLY,
                master_password=TEST_MASTER,
            )


def test_create_vault_copy_without_password_rejected(
    vault_service: V2VaultService,
) -> None:
    with pytest.raises(
        ValueError, match="master_password is required to create a vault-copy key"
    ):
        vault_service.create_key(
            "no-pw-key",
            KeyStorageMode.VAULT_COPY,
        )


def test_inner_wrap_aad_tamper_rejection(vault_service: V2VaultService) -> None:
    rec, sec = vault_service.create_key(
        "aad-tamper-target",
        KeyStorageMode.VAULT_COPY,
        master_password=TEST_MASTER,
    )

    with hold_vault_lock(vault_service.lock_target):
        doc_type, v2_doc = vault_service._load_document_locked(TEST_MASTER)
        assert doc_type == 2
        assert isinstance(v2_doc, V2VaultDocument)

        key_rec = v2_doc.keys[rec.fingerprint]
        tampered_keys = dict(v2_doc.keys)
        # Tamper record_id in KeyIdentity (which binds to AAD)
        tampered_record_id = b64url_encode(b"t" * 16)
        tampered_keys[rec.fingerprint] = KeyIdentity(
            schema_version=key_rec.schema_version,
            record_id=tampered_record_id,
            id=key_rec.id,
            type=key_rec.type,
            fingerprint=key_rec.fingerprint,
            storage=key_rec.storage,
            status=key_rec.status,
            created_at=key_rec.created_at,
            updated_at=key_rec.updated_at,
            last_used_at=key_rec.last_used_at,
            public_metadata=key_rec.public_metadata,
            external=key_rec.external,
            vault_secret=key_rec.vault_secret,
        )

        tampered_doc = V2VaultDocument(
            schema_version=2,
            vault_meta=v2_doc.vault_meta,
            passphrases=dict(v2_doc.passphrases),
            keys=tampered_keys,
        )
        vault_service.vault.write_raw_vault(
            vault_service.vault._encode_document(2, tampered_doc, TEST_MASTER)
        )

    # AAD mismatch must cause unwrap authentication failure
    with pytest.raises(ValueError, match="authentication failed"):
        vault_service.get_key("aad-tamper-target", TEST_MASTER)


# ---------------------------------------------------------------------------
# create_key(export_path=...) — regression coverage for the P0-1 fix: an
# EXTERNAL_ONLY key created without a real export destination previously
# discarded its generated secret, unrecoverably.
# ---------------------------------------------------------------------------


def test_create_key_export_path_writes_recoverable_keyfile(
    vault_service: V2VaultService, tmp_path: Path
) -> None:
    dest = tmp_path / "exported.ssckey"
    key_record, secret = vault_service.create_key(
        "export-me",
        KeyStorageMode.EXTERNAL_ONLY,
        master_password=TEST_MASTER,
        export_path=dest,
    )

    assert dest.exists()
    loaded = load_keyfile(dest)
    assert loaded.fingerprint == key_record.fingerprint
    assert loaded.secret_bytes == secret
    # The written path becomes the identity's path_hint automatically.
    assert key_record.external is not None
    assert key_record.external.path_hint == str(dest)


def test_create_key_export_path_existing_destination_leaves_vault_untouched(
    vault_service: V2VaultService, tmp_path: Path
) -> None:
    dest = tmp_path / "taken.ssckey"
    dest.write_bytes(b"not a real keyfile")

    with pytest.raises(FileExistsError):
        vault_service.create_key(
            "should-not-exist",
            KeyStorageMode.EXTERNAL_ONLY,
            master_password=TEST_MASTER,
            export_path=dest,
        )

    # The failed write must not have registered a now-unrecoverable key.
    assert vault_service.list_keys(TEST_MASTER) == []


def test_create_key_export_path_optional_for_vault_copy(
    vault_service: V2VaultService, tmp_path: Path
) -> None:
    dest = tmp_path / "backup.ssckey"
    key_record, secret = vault_service.create_key(
        "vault-copy-with-backup",
        KeyStorageMode.VAULT_COPY,
        master_password=TEST_MASTER,
        export_path=dest,
    )
    assert key_record.vault_secret is not None
    assert dest.exists()
    assert load_keyfile(dest).secret_bytes == secret


def test_create_key_export_path_survives_vault_registration_failure(
    vault_service: V2VaultService, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the keyfile write succeeds but the subsequent vault commit fails,
    the caller must be told the file is real and recoverable, not just that
    creation failed — losing that distinction is how a generated secret
    gets silently discarded."""
    dest = tmp_path / "orphaned.ssckey"

    def _boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("synthetic vault backend failure")

    monkeypatch.setattr(vault_service, "_save_document_locked", _boom)

    with pytest.raises(KeyExportSurvivedRegistrationFailureError) as exc_info:
        vault_service.create_key(
            "orphaned-key",
            KeyStorageMode.EXTERNAL_ONLY,
            master_password=TEST_MASTER,
            export_path=dest,
        )

    assert exc_info.value.export_path == dest
    # The keyfile itself must genuinely be there and usable, not just claimed.
    assert dest.exists()
    loaded = load_keyfile(dest)
    assert loaded.key_id == "orphaned-key"

    # And the vault must NOT have registered a record it can't back up —
    # no orphaned fingerprint left behind for a secret the vault doesn't own.
    assert vault_service.list_keys(TEST_MASTER) == []


# ---------------------------------------------------------------------------
# rename_key — regression coverage for the P0-6 fix: previously unimplemented,
# the CLI's `ssc key rename` unconditionally failed.
# ---------------------------------------------------------------------------


def test_rename_key_by_id_updates_id_and_preserves_fingerprint(
    vault_service: V2VaultService,
) -> None:
    original, secret = vault_service.create_key(
        "old-name",
        KeyStorageMode.VAULT_COPY,
        master_password=TEST_MASTER,
    )

    renamed = vault_service.rename_key("old-name", "new-name", TEST_MASTER)

    assert renamed.id == "new-name"
    assert renamed.fingerprint == original.fingerprint
    assert renamed.record_id == original.record_id

    keys = vault_service.list_keys(TEST_MASTER)
    assert [k.id for k in keys] == ["new-name"]

    # The secret itself is untouched by rename.
    _, unwrapped = vault_service.get_key("new-name", TEST_MASTER)
    assert unwrapped == secret


def test_rename_key_by_fingerprint_also_works(vault_service: V2VaultService) -> None:
    original, _ = vault_service.create_key(
        "fp-lookup", KeyStorageMode.VAULT_COPY, master_password=TEST_MASTER
    )
    renamed = vault_service.rename_key(original.fingerprint, "fp-renamed", TEST_MASTER)
    assert renamed.id == "fp-renamed"


def test_rename_key_rejects_collision_with_existing_id(
    vault_service: V2VaultService,
) -> None:
    vault_service.create_key(
        "first", KeyStorageMode.VAULT_COPY, master_password=TEST_MASTER
    )
    vault_service.create_key(
        "second", KeyStorageMode.VAULT_COPY, master_password=TEST_MASTER
    )

    with pytest.raises(ValueError, match="already exists"):
        vault_service.rename_key("second", "first", TEST_MASTER)

    # Neither record should have been mutated by the rejected rename.
    keys = {k.id for k in vault_service.list_keys(TEST_MASTER)}
    assert keys == {"first", "second"}


def test_rename_key_rejects_invalid_new_id(vault_service: V2VaultService) -> None:
    vault_service.create_key(
        "valid-id", KeyStorageMode.VAULT_COPY, master_password=TEST_MASTER
    )
    with pytest.raises(ValueError, match="new_id"):
        vault_service.rename_key("valid-id", "Not Valid!", TEST_MASTER)


def test_rename_key_not_found(vault_service: V2VaultService) -> None:
    with pytest.raises(KeyError):
        vault_service.rename_key("does-not-exist", "whatever", TEST_MASTER)
