"""V2VaultService adapter for structured V2 vault operations.

Provides lifecycle management for managed keys, parallel inner-root derivation,
inner secret wrapping/unwrapping with AES-256-GCM and cryptographic context AAD binding,
and atomic migration from V1 flat vaults to V2 structured vaults.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from secure_string_cipher.passphrase_manager import (
    _UNSPECIFIED_SNAPSHOT,
    PassphraseVault,
)
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
from secure_string_cipher.v2.keyfile import KeyFileData, save_keyfile
from secure_string_cipher.v2.vault_lock import hold_vault_lock
from secure_string_cipher.v2.vault_schema import (
    V2VaultDocument,
    V2VaultKdf,
    V2VaultMeta,
    V2VaultSecretContainer,
    b64url_decode,
    b64url_encode,
)

_KEY_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")

__all__ = [
    "KeyExportSurvivedRegistrationFailureError",
    "V2VaultService",
]


class KeyExportSurvivedRegistrationFailureError(RuntimeError):
    """A key's .ssckey file was written, but vault registration then failed.

    The exported secret is real and recoverable at ``export_path`` even
    though the operation as a whole did not complete — callers must not
    report a plain failure without also surfacing that fact.
    """

    def __init__(self, export_path: Path, original: BaseException) -> None:
        self.export_path = export_path
        self.original = original
        # Deliberately omits str(original): callers must not forward raw
        # exception text to logs/output (see tools/check_sensitive_output.py).
        super().__init__(
            f"Key file was written to {export_path}, but vault registration failed."
        )


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class V2VaultService:
    """Adapter managing structured V2 vault documents and managed key lifecycles."""

    def __init__(
        self,
        vault: PassphraseVault | None = None,
        *,
        vault_path: str | None = None,
        backend: str | None = None,
    ) -> None:
        if vault is not None:
            self._vault = vault
        else:
            self._vault = PassphraseVault(vault_path=vault_path, backend=backend)

    @property
    def vault(self) -> PassphraseVault:
        """Underlying PassphraseVault instance."""
        return self._vault

    @property
    def lock_target(self) -> Path | str:
        """Lock target for cross-process synchronization."""
        return self._vault.lock_target

    def _derive_vault_root_key(
        self, master_password: str, vault_kdf: V2VaultKdf
    ) -> bytes:
        """Derive the operation-scoped parallel inner-wrap root key."""
        self._validate_password(master_password)
        salt_bytes = b64url_decode(vault_kdf.salt, expected_length=16)
        try:
            return hash_secret_raw(
                secret=master_password.encode("utf-8"),
                salt=salt_bytes,
                time_cost=vault_kdf.time_cost,
                memory_cost=vault_kdf.memory_kib,
                parallelism=vault_kdf.parallelism,
                hash_len=vault_kdf.hash_len,
                type=Type.ID,
                version=19,
            )
        except Exception:
            raise ValueError("Vault root key derivation failed") from None

    @staticmethod
    def _validate_password(master_password: str) -> None:
        if not isinstance(master_password, str):
            raise TypeError("Master password must be a string")
        if len(master_password) > 65536 or len(master_password.encode("utf-8")) > 65536:
            raise ValueError("Master password exceeds V2 input limit")

    def _validate_inner_secrets(
        self,
        doc: V2VaultDocument,
        master_password: str,
        *,
        root_key: bytes | None = None,
    ) -> None:
        """Verify all wrapped records using at most one operation-scoped root."""
        self._validate_password(master_password)
        for record in doc.keys.values():
            if record.vault_secret is not None:
                if root_key is None:
                    root_key = self._derive_vault_root_key(
                        master_password, doc.vault_meta.vault_kdf
                    )
                secret = self._unwrap_secret(root_key, record, doc.vault_meta)
                del secret

    def _derive_vault_copy_kek(self, vault_root_key: bytes, salt_bytes: bytes) -> bytes:
        """Derive the per-record vault_copy_kek via HKDF-SHA256."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            info=b"secure-string-cipher/v2/vault-copy/key-material-wrap/aes-256-gcm",
        )
        return hkdf.derive(vault_root_key)

    def _compute_vault_copy_aad(
        self,
        vault_meta: V2VaultMeta,
        record_id: str,
        key_type: KeyType,
        fingerprint: str,
        sec_container: V2VaultSecretContainer,
    ) -> bytes:
        """Compute the inner-wrap AEAD AAD binding context."""
        v_context: dict[str, object] = {
            "fingerprint": fingerprint,
            "kek_derivation": dict(sec_container.kek_derivation),
            "key_type": key_type.value,
            "nonce": sec_container.nonce,
            "protection": sec_container.protection,
            "record_id": record_id,
            "schema_version": 2,
            "storage": "vault-copy",
            "vault_id": vault_meta.vault_id,
            "vault_kdf": vault_meta.vault_kdf.to_dict(),
            "wrap_alg": sec_container.wrap_alg,
            "wrap_generation": vault_meta.wrap_generation,
        }
        v_context_canonical = canonical_json(v_context)
        return b"SSC2/vault-copy/v1\0" + hashlib.sha256(v_context_canonical).digest()

    def _wrap_secret(
        self,
        vault_root_key: bytes,
        secret_bytes: bytes,
        vault_meta: V2VaultMeta,
        record_id: str,
        key_type: KeyType,
        fingerprint: str,
    ) -> V2VaultSecretContainer:
        """Wrap a 32-byte managed secret with AES-256-GCM and cryptographic context AAD."""
        if len(secret_bytes) != 32:
            raise ValueError("Managed secret must be exactly 32 bytes")

        salt_bytes = secrets.token_bytes(32)
        nonce_bytes = secrets.token_bytes(12)

        kek = self._derive_vault_copy_kek(vault_root_key, salt_bytes)

        sec_container_pre = V2VaultSecretContainer(
            protection="vault-wrapped",
            wrap_alg="aes-256-gcm",
            kek_derivation=MappingProxyType(
                {"alg": "hkdf-sha256", "salt": b64url_encode(salt_bytes)}
            ),
            nonce=b64url_encode(nonce_bytes),
            encrypted_key_material=b64url_encode(b"\x00" * 32),
            tag=b64url_encode(b"\x00" * 16),
        )
        aad = self._compute_vault_copy_aad(
            vault_meta, record_id, key_type, fingerprint, sec_container_pre
        )

        aesgcm = AESGCM(kek)
        ciphertext_and_tag = aesgcm.encrypt(nonce_bytes, secret_bytes, aad)
        ciphertext = ciphertext_and_tag[:-16]
        tag = ciphertext_and_tag[-16:]

        return V2VaultSecretContainer(
            protection="vault-wrapped",
            wrap_alg="aes-256-gcm",
            kek_derivation=MappingProxyType(
                {"alg": "hkdf-sha256", "salt": b64url_encode(salt_bytes)}
            ),
            nonce=b64url_encode(nonce_bytes),
            encrypted_key_material=b64url_encode(ciphertext),
            tag=b64url_encode(tag),
        )

    def _unwrap_secret(
        self,
        vault_root_key: bytes,
        record: KeyIdentity,
        vault_meta: V2VaultMeta,
    ) -> bytes:
        """Unwrap a managed secret and verify its fingerprint."""
        if record.vault_secret is None:
            raise ValueError(f"Key record '{record.id}' has no vault_secret")

        kek_raw = record.vault_secret.get("kek_derivation")
        kek_dict: dict[str, object] = (
            dict(kek_raw) if isinstance(kek_raw, Mapping) else {}
        )

        sec_container = V2VaultSecretContainer(
            protection=str(record.vault_secret.get("protection", "")),
            wrap_alg=str(record.vault_secret.get("wrap_alg", "")),
            kek_derivation=kek_dict,
            nonce=str(record.vault_secret.get("nonce", "")),
            encrypted_key_material=str(
                record.vault_secret.get("encrypted_key_material", "")
            ),
            tag=str(record.vault_secret.get("tag", "")),
        )

        salt_bytes = b64url_decode(
            str(sec_container.kek_derivation.get("salt")), expected_length=32
        )
        nonce_bytes = b64url_decode(sec_container.nonce, expected_length=12)
        ciphertext = b64url_decode(
            sec_container.encrypted_key_material, expected_length=32
        )
        tag = b64url_decode(sec_container.tag, expected_length=16)

        kek = self._derive_vault_copy_kek(vault_root_key, salt_bytes)
        aad = self._compute_vault_copy_aad(
            vault_meta,
            record.record_id,
            record.type,
            record.fingerprint,
            sec_container,
        )

        aesgcm = AESGCM(kek)
        try:
            secret_bytes = aesgcm.decrypt(nonce_bytes, ciphertext + tag, aad)
        except Exception as e:
            raise ValueError(
                f"Failed to unwrap managed secret for '{record.id}': authentication failed"
            ) from e

        computed_fp = compute_fingerprint(secret_bytes)
        if computed_fp != record.fingerprint:
            raise ValueError(
                f"Unwrapped secret fingerprint mismatch for key '{record.id}'"
            )

        return secret_bytes

    def _load_document_locked(
        self, master_password: str
    ) -> tuple[int, dict[str, str] | V2VaultDocument]:
        """Load and authenticate document from active backend."""
        return self._vault._load_document(master_password)

    def _save_document_locked(
        self,
        doc_type: int,
        doc: dict[str, str] | V2VaultDocument,
        master_password: str,
        *,
        expected_raw: str | None | object = _UNSPECIFIED_SNAPSHOT,
        root_key: bytes | None = None,
    ) -> None:
        """Save document to active backend holding lock."""
        self._vault._save_document(
            doc_type,
            doc,
            master_password,
            expected_raw=expected_raw,
            validate_document=(
                lambda candidate: self._validate_inner_secrets(
                    candidate, master_password, root_key=root_key
                )
            )
            if doc_type == 2
            else None,
        )

    def _ensure_schema_2(
        self, master_password: str
    ) -> tuple[V2VaultDocument, bool, str | None]:
        """Prepare a Schema 2 candidate without publishing an intermediate migration."""
        self._validate_password(master_password)
        doc_type, doc, raw = self._vault._read_document_snapshot(master_password)
        if doc_type == 2:
            assert isinstance(doc, V2VaultDocument)
            return doc, False, raw

        # Migrate Schema 1 to Schema 2
        assert isinstance(doc, dict)
        vault_id = b64url_encode(secrets.token_bytes(16))
        root_salt = b64url_encode(secrets.token_bytes(16))
        vault_kdf = V2VaultKdf(
            alg="argon2id",
            version=19,
            memory_kib=65536,
            time_cost=3,
            parallelism=4,
            hash_len=32,
            salt=root_salt,
        )
        vault_meta = V2VaultMeta(
            vault_id=vault_id,
            revision=1,
            wrap_generation=1,
            vault_kdf=vault_kdf,
        )
        v2_doc = V2VaultDocument(
            schema_version=2,
            vault_meta=vault_meta,
            passphrases=doc,
            keys={},
        )
        return v2_doc, True, raw

    def create_key(
        self,
        key_id: str,
        storage: KeyStorageMode,
        *,
        path_hint: str | None = None,
        master_password: str | None = None,
        export_path: Path | None = None,
    ) -> tuple[KeyIdentity, bytes]:
        """Create a new managed key identity and commit it to the vault.

        ``path_hint`` is informational metadata only (a display string; no
        file is written from it). Pass ``export_path`` to actually write a
        ``.ssckey`` file for the generated secret — required in practice for
        ``EXTERNAL_ONLY`` storage, since that mode does not persist the
        secret anywhere else and an unexported external-only key is
        unrecoverable the moment this method returns. The keyfile is written
        (durably, refusing to overwrite an existing file) *before* the vault
        document is committed, so a failed vault commit still leaves a
        recoverable external key file; conversely a failed keyfile write
        leaves the vault untouched.
        """
        if not isinstance(key_id, str) or not _KEY_ID_RE.match(key_id):
            raise ValueError("key_id must match pattern ^[a-z][a-z0-9._-]{0,63}$")
        if storage == KeyStorageMode.VAULT_COPY and master_password is None:
            raise ValueError("master_password is required to create a vault-copy key")

        with hold_vault_lock(self.lock_target):
            # Resolve master password for vault access
            auth_password = master_password or ""
            v2_doc, _, raw = self._ensure_schema_2(auth_password)

            # Ensure human id is unique among existing keys
            for existing in v2_doc.keys.values():
                if existing.id == key_id:
                    raise ValueError(
                        f"A key with id '{key_id}' already exists in the vault"
                    )

            secret_bytes = secrets.token_bytes(32)
            fingerprint = compute_fingerprint(secret_bytes)
            record_id = b64url_encode(secrets.token_bytes(16))
            now = _utc_now_iso()

            if export_path is not None:
                # Written before any vault mutation: on failure (e.g. the
                # destination already exists) nothing above has been
                # committed, so create_key simply raises with no side effect.
                save_keyfile(
                    KeyFileData(
                        version=1,
                        key_id=key_id,
                        key_type="symmetric-key",
                        kdf="hkdf-sha256",
                        fingerprint=fingerprint,
                        created_at=now,
                        secret_bytes=secret_bytes,
                    ),
                    export_path,
                )

            try:
                public_meta = KeyPublicMetadata(
                    label=key_id,
                    algorithm="hkdf-sha256",
                    key_length=32,
                    format="ssckey-v1",
                )
                external_ref = ExternalKeyReference(
                    path_hint=str(export_path) if export_path is not None else path_hint
                )

                vault_secret_dict: dict[str, object] | None = None
                root_key = None
                if storage == KeyStorageMode.VAULT_COPY:
                    assert master_password is not None
                    root_key = self._derive_vault_root_key(
                        master_password, v2_doc.vault_meta.vault_kdf
                    )
                    sec_container = self._wrap_secret(
                        root_key,
                        secret_bytes,
                        v2_doc.vault_meta,
                        record_id,
                        KeyType.SYMMETRIC,
                        fingerprint,
                    )
                    vault_secret_dict = sec_container.to_dict()

                key_record = KeyIdentity(
                    schema_version=1,
                    record_id=record_id,
                    id=key_id,
                    type=KeyType.SYMMETRIC,
                    fingerprint=fingerprint,
                    storage=storage,
                    status=KeyStatus.ACTIVE,
                    created_at=now,
                    updated_at=now,
                    last_used_at=None,
                    public_metadata=public_meta,
                    external=external_ref,
                    vault_secret=vault_secret_dict,
                )

                updated_keys = dict(v2_doc.keys)
                updated_keys[fingerprint] = key_record

                new_meta = V2VaultMeta(
                    vault_id=v2_doc.vault_meta.vault_id,
                    revision=v2_doc.vault_meta.revision + 1,
                    wrap_generation=v2_doc.vault_meta.wrap_generation,
                    vault_kdf=v2_doc.vault_meta.vault_kdf,
                )
                new_doc = V2VaultDocument(
                    schema_version=2,
                    vault_meta=new_meta,
                    passphrases=dict(v2_doc.passphrases),
                    keys=updated_keys,
                )

                self._save_document_locked(
                    2, new_doc, auth_password, expected_raw=raw, root_key=root_key
                )
            except Exception as e:
                if export_path is not None:
                    # The keyfile above is already durably written; the
                    # caller must be told it survives this failure and is
                    # the real, recoverable secret, not "creation failed".
                    raise KeyExportSurvivedRegistrationFailureError(
                        export_path, e
                    ) from e
                raise
            return key_record, secret_bytes

    def import_key(
        self,
        keyfile_data: KeyFileData,
        storage: KeyStorageMode,
        *,
        path_hint: str | None = None,
        master_password: str | None = None,
    ) -> KeyIdentity:
        """Import an existing .ssckey into the vault."""
        if not isinstance(keyfile_data, KeyFileData):
            raise TypeError("keyfile_data must be a KeyFileData instance")
        if storage == KeyStorageMode.VAULT_COPY and master_password is None:
            raise ValueError("master_password is required to import a vault-copy key")

        with hold_vault_lock(self.lock_target):
            auth_password = master_password or ""
            v2_doc, _, raw = self._ensure_schema_2(auth_password)

            for existing in v2_doc.keys.values():
                if existing.id == keyfile_data.key_id:
                    raise ValueError(
                        f"A key with id '{keyfile_data.key_id}' already exists in the vault"
                    )
                if existing.fingerprint == keyfile_data.fingerprint:
                    raise ValueError(
                        f"A key with fingerprint '{keyfile_data.fingerprint}' already exists in the vault"
                    )

            record_id = b64url_encode(secrets.token_bytes(16))
            now = _utc_now_iso()

            public_meta = KeyPublicMetadata(
                label=keyfile_data.key_id,
                algorithm=keyfile_data.kdf,
                key_length=len(keyfile_data.secret_bytes),
                format="ssckey-v1",
            )
            external_ref = ExternalKeyReference(path_hint=path_hint)

            vault_secret_dict: dict[str, object] | None = None
            root_key = None
            if storage == KeyStorageMode.VAULT_COPY:
                assert master_password is not None
                root_key = self._derive_vault_root_key(
                    master_password, v2_doc.vault_meta.vault_kdf
                )
                sec_container = self._wrap_secret(
                    root_key,
                    keyfile_data.secret_bytes,
                    v2_doc.vault_meta,
                    record_id,
                    KeyType.SYMMETRIC,
                    keyfile_data.fingerprint,
                )
                vault_secret_dict = sec_container.to_dict()

            key_record = KeyIdentity(
                schema_version=1,
                record_id=record_id,
                id=keyfile_data.key_id,
                type=KeyType.SYMMETRIC,
                fingerprint=keyfile_data.fingerprint,
                storage=storage,
                status=KeyStatus.ACTIVE,
                created_at=keyfile_data.created_at,
                updated_at=now,
                last_used_at=None,
                public_metadata=public_meta,
                external=external_ref,
                vault_secret=vault_secret_dict,
            )

            updated_keys = dict(v2_doc.keys)
            updated_keys[keyfile_data.fingerprint] = key_record

            new_meta = V2VaultMeta(
                vault_id=v2_doc.vault_meta.vault_id,
                revision=v2_doc.vault_meta.revision + 1,
                wrap_generation=v2_doc.vault_meta.wrap_generation,
                vault_kdf=v2_doc.vault_meta.vault_kdf,
            )
            new_doc = V2VaultDocument(
                schema_version=2,
                vault_meta=new_meta,
                passphrases=dict(v2_doc.passphrases),
                keys=updated_keys,
            )

            self._save_document_locked(
                2, new_doc, auth_password, expected_raw=raw, root_key=root_key
            )
            return key_record

    def get_key(
        self,
        identifier: str,
        master_password: str,
        *,
        allow_revoked: bool = False,
    ) -> tuple[KeyIdentity, bytes | None]:
        """Look up key by id or fingerprint and optionally unwrap secret."""
        doc_type, doc = self._load_document_locked(master_password)
        if doc_type != 2:
            raise KeyError(f"Key '{identifier}' not found")
        assert isinstance(doc, V2VaultDocument)

        target_record: KeyIdentity | None = None
        if identifier in doc.keys:
            target_record = doc.keys[identifier]
        else:
            matches = [k for k in doc.keys.values() if k.id == identifier]
            if len(matches) == 1:
                target_record = matches[0]
            elif len(matches) > 1:
                raise ValueError(
                    f"Ambiguous key identifier '{identifier}': matches multiple keys"
                )

        if target_record is None:
            raise KeyError(f"Key '{identifier}' not found in vault")

        if target_record.storage == KeyStorageMode.EXTERNAL_ONLY:
            return target_record, None

        if target_record.status == KeyStatus.DESTROYED:
            return target_record, None

        if target_record.status == KeyStatus.REVOKED and not allow_revoked:
            raise ValueError(
                f"Key '{target_record.id}' is revoked. Decryption requires explicit recovery override."
            )

        # Unwrap vault-copy secret
        root_key = self._derive_vault_root_key(
            master_password, doc.vault_meta.vault_kdf
        )
        secret_bytes = self._unwrap_secret(root_key, target_record, doc.vault_meta)
        return target_record, secret_bytes

    def list_keys(self, master_password: str) -> list[KeyIdentity]:
        """List all managed key metadata records in the vault without unwrapping."""
        doc_type, doc = self._load_document_locked(master_password)
        if doc_type != 2:
            return []
        assert isinstance(doc, V2VaultDocument)
        return sorted(doc.keys.values(), key=lambda k: k.id)

    def export_key(self, identifier: str, out_path: Path, master_password: str) -> None:
        """Export a vault-copy managed key to an external .ssckey file."""
        record, secret_bytes = self.get_key(identifier, master_password)
        if record.storage == KeyStorageMode.EXTERNAL_ONLY:
            raise ValueError(
                f"Cannot export key '{record.id}': external-only identities store no secret in the vault"
            )
        if record.status == KeyStatus.DESTROYED or secret_bytes is None:
            raise ValueError(f"Cannot export key '{record.id}': key is destroyed")

        keyfile_data = KeyFileData(
            version=1,
            key_id=record.id,
            key_type=record.type.value,
            kdf=record.public_metadata.algorithm,
            fingerprint=record.fingerprint,
            created_at=record.created_at,
            secret_bytes=secret_bytes,
        )
        save_keyfile(keyfile_data, out_path)

    def _update_key_status(
        self, identifier: str, new_status: KeyStatus, master_password: str
    ) -> KeyIdentity:
        with hold_vault_lock(self.lock_target):
            v2_doc, _, raw = self._ensure_schema_2(master_password)

            target_fp: str | None = None
            if identifier in v2_doc.keys:
                target_fp = identifier
            else:
                matches = [fp for fp, k in v2_doc.keys.items() if k.id == identifier]
                if len(matches) == 1:
                    target_fp = matches[0]
                elif len(matches) > 1:
                    raise ValueError(f"Ambiguous key identifier '{identifier}'")

            if target_fp is None:
                raise KeyError(f"Key '{identifier}' not found")

            old_record = v2_doc.keys[target_fp]
            now = _utc_now_iso()

            vault_secret = old_record.vault_secret
            if new_status == KeyStatus.DESTROYED:
                vault_secret = None  # Tombstone

            new_record = KeyIdentity(
                schema_version=old_record.schema_version,
                record_id=old_record.record_id,
                id=old_record.id,
                type=old_record.type,
                fingerprint=old_record.fingerprint,
                storage=old_record.storage,
                status=new_status,
                created_at=old_record.created_at,
                updated_at=now,
                last_used_at=old_record.last_used_at,
                public_metadata=old_record.public_metadata,
                external=old_record.external,
                vault_secret=vault_secret,
            )

            updated_keys = dict(v2_doc.keys)
            updated_keys[target_fp] = new_record

            new_meta = V2VaultMeta(
                vault_id=v2_doc.vault_meta.vault_id,
                revision=v2_doc.vault_meta.revision + 1,
                wrap_generation=v2_doc.vault_meta.wrap_generation,
                vault_kdf=v2_doc.vault_meta.vault_kdf,
            )
            new_doc = V2VaultDocument(
                schema_version=2,
                vault_meta=new_meta,
                passphrases=dict(v2_doc.passphrases),
                keys=updated_keys,
            )

            self._save_document_locked(2, new_doc, master_password, expected_raw=raw)
            return new_record

    def rename_key(
        self, identifier: str, new_id: str, master_password: str
    ) -> KeyIdentity:
        """Change a managed key's human-readable id.

        The fingerprint, which is derived from the key's own secret material,
        never changes. Only the ``id`` label used for lookup and display is
        updated.
        """
        if not isinstance(new_id, str) or not _KEY_ID_RE.match(new_id):
            raise ValueError("new_id must match pattern ^[a-z][a-z0-9._-]{0,63}$")

        with hold_vault_lock(self.lock_target):
            v2_doc, _, raw = self._ensure_schema_2(master_password)

            target_fp: str | None = None
            if identifier in v2_doc.keys:
                target_fp = identifier
            else:
                matches = [fp for fp, k in v2_doc.keys.items() if k.id == identifier]
                if len(matches) == 1:
                    target_fp = matches[0]
                elif len(matches) > 1:
                    raise ValueError(f"Ambiguous key identifier '{identifier}'")

            if target_fp is None:
                raise KeyError(f"Key '{identifier}' not found")

            old_record = v2_doc.keys[target_fp]

            for fp, existing in v2_doc.keys.items():
                if fp != target_fp and existing.id == new_id:
                    raise ValueError(
                        f"A key with id '{new_id}' already exists in the vault"
                    )

            now = _utc_now_iso()
            new_record = KeyIdentity(
                schema_version=old_record.schema_version,
                record_id=old_record.record_id,
                id=new_id,
                type=old_record.type,
                fingerprint=old_record.fingerprint,
                storage=old_record.storage,
                status=old_record.status,
                created_at=old_record.created_at,
                updated_at=now,
                last_used_at=old_record.last_used_at,
                public_metadata=old_record.public_metadata,
                external=old_record.external,
                vault_secret=old_record.vault_secret,
            )

            updated_keys = dict(v2_doc.keys)
            updated_keys[target_fp] = new_record

            new_meta = V2VaultMeta(
                vault_id=v2_doc.vault_meta.vault_id,
                revision=v2_doc.vault_meta.revision + 1,
                wrap_generation=v2_doc.vault_meta.wrap_generation,
                vault_kdf=v2_doc.vault_meta.vault_kdf,
            )
            new_doc = V2VaultDocument(
                schema_version=2,
                vault_meta=new_meta,
                passphrases=dict(v2_doc.passphrases),
                keys=updated_keys,
            )

            self._save_document_locked(2, new_doc, master_password, expected_raw=raw)
            return new_record

    def archive_key(self, identifier: str, master_password: str) -> KeyIdentity:
        """Archive a managed key."""
        return self._update_key_status(identifier, KeyStatus.ARCHIVED, master_password)

    def revoke_key(self, identifier: str, master_password: str) -> KeyIdentity:
        """Revoke a managed key."""
        return self._update_key_status(identifier, KeyStatus.REVOKED, master_password)

    def destroy_key(self, identifier: str, master_password: str) -> KeyIdentity:
        """Destroy managed key secret, leaving an explicit tombstone record."""
        return self._update_key_status(identifier, KeyStatus.DESTROYED, master_password)

    def migrate_schema(self, master_password: str) -> V2VaultDocument:
        """Migrate a flat V1 vault to a structured V2 vault idempotently."""
        with hold_vault_lock(self.lock_target):
            v2_doc, migrated, raw = self._ensure_schema_2(master_password)
            if migrated:
                self._save_document_locked(2, v2_doc, master_password, expected_raw=raw)
            else:
                self._validate_inner_secrets(v2_doc, master_password)
            return v2_doc

    def change_master_password(self, old_password: str, new_password: str) -> None:
        """Change master password and re-wrap all inner vault-copy secrets."""
        with hold_vault_lock(self.lock_target):
            doc_type, doc, raw = self._vault._read_document_snapshot(old_password)

            if doc_type == 1:
                assert isinstance(doc, dict)
                # Flat vault: re-save under new password
                self._save_document_locked(1, doc, new_password, expected_raw=raw)
                return

            assert isinstance(doc, V2VaultDocument)
            self._validate_password(new_password)

            # Derive old root key if wrapped keys exist
            wrapped_keys = [
                k
                for k in doc.keys.values()
                if k.storage == KeyStorageMode.VAULT_COPY
                and k.status != KeyStatus.DESTROYED
                and k.vault_secret is not None
            ]

            old_root_key: bytes | None = None
            if wrapped_keys:
                old_root_key = self._derive_vault_root_key(
                    old_password, doc.vault_meta.vault_kdf
                )
                # Validation pass: sequentially unwrap and verify every key
                for k in wrapped_keys:
                    secret_bytes = self._unwrap_secret(old_root_key, k, doc.vault_meta)
                    # Discard secret buffer immediately
                    del secret_bytes

            # Generate fresh inner Argon2 salt and increment wrap_generation
            new_root_salt = b64url_encode(secrets.token_bytes(16))
            new_wrap_gen = doc.vault_meta.wrap_generation + 1
            new_kdf = V2VaultKdf(
                alg=doc.vault_meta.vault_kdf.alg,
                version=doc.vault_meta.vault_kdf.version,
                memory_kib=doc.vault_meta.vault_kdf.memory_kib,
                time_cost=doc.vault_meta.vault_kdf.time_cost,
                parallelism=doc.vault_meta.vault_kdf.parallelism,
                hash_len=doc.vault_meta.vault_kdf.hash_len,
                salt=new_root_salt,
            )
            new_meta = V2VaultMeta(
                vault_id=doc.vault_meta.vault_id,
                revision=doc.vault_meta.revision + 1,
                wrap_generation=new_wrap_gen,
                vault_kdf=new_kdf,
            )

            new_root_key: bytes | None = None
            if wrapped_keys:
                new_root_key = self._derive_vault_root_key(new_password, new_kdf)

            # Re-wrap records sequentially
            re_wrapped_keys: dict[str, KeyIdentity] = {}
            for fp, k in doc.keys.items():
                if (
                    k.storage == KeyStorageMode.VAULT_COPY
                    and k.status != KeyStatus.DESTROYED
                    and k.vault_secret is not None
                ):
                    assert old_root_key is not None
                    assert new_root_key is not None
                    unwrapped_secret = self._unwrap_secret(
                        old_root_key, k, doc.vault_meta
                    )
                    new_sec_container = self._wrap_secret(
                        new_root_key,
                        unwrapped_secret,
                        new_meta,
                        k.record_id,
                        k.type,
                        k.fingerprint,
                    )
                    del unwrapped_secret

                    updated_record = KeyIdentity(
                        schema_version=k.schema_version,
                        record_id=k.record_id,
                        id=k.id,
                        type=k.type,
                        fingerprint=k.fingerprint,
                        storage=k.storage,
                        status=k.status,
                        created_at=k.created_at,
                        updated_at=_utc_now_iso(),
                        last_used_at=k.last_used_at,
                        public_metadata=k.public_metadata,
                        external=k.external,
                        vault_secret=new_sec_container.to_dict(),
                    )
                    re_wrapped_keys[fp] = updated_record
                else:
                    re_wrapped_keys[fp] = k

            new_doc = V2VaultDocument(
                schema_version=2,
                vault_meta=new_meta,
                passphrases=dict(doc.passphrases),
                keys=re_wrapped_keys,
            )

            # Pre-publication validation: verify all re-wrapped secrets
            if wrapped_keys:
                assert new_root_key is not None
                for k in new_doc.keys.values():
                    if (
                        k.storage == KeyStorageMode.VAULT_COPY
                        and k.status != KeyStatus.DESTROYED
                        and k.vault_secret is not None
                    ):
                        unwrapped = self._unwrap_secret(new_root_key, k, new_meta)
                        del unwrapped

            self._save_document_locked(
                2, new_doc, new_password, expected_raw=raw, root_key=new_root_key
            )
