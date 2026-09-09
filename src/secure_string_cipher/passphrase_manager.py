"""
Passphrase management module for secure storage and retrieval.

This module encrypts generated passphrases with a master password and stores them
in an encrypted vault file or OS keychain. Users can retrieve their passphrases
by providing the master password.

Vault Format (file backend):
    SSCVAULT
    <hmac_salt_hex>
    ---DATA---
    <encrypted_vault_data>
    ---HMAC---
    <hmac_hex>

The HMAC key is derived using Argon2id with a random salt, providing
memory-hard protection against brute-force attacks on integrity verification.

Storage Backends:
    - "file" (default): Encrypted vault file on disk
    - "keychain": OS keychain (macOS Keychain, Windows Credential Vault,
      Linux Secret Service). Install with:
      python -m pip install 'secure-string-cipher[keychain]'
"""

import hashlib
import hmac
import json
import os
import secrets
import stat
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from .atomic_io import atomic_binary_writer
from .config import (
    MAX_FILE_SIZE,
    VAULT_BACKEND_FILE,
    VAULT_BACKEND_KEYCHAIN,
    get_default_backup_dir,
    load_vault_settings,
)
from .core import _decode_canonical_base64, decrypt_text, derive_key, encrypt_text
from .security import secure_atomic_write

# Vault format constants
_VAULT_HEADER = "SSCVAULT"
_HMAC_SALT_SIZE = 32  # 256 bits
_VAULT_HMAC_SIZE = 32
_VAULT_FAILURE_MESSAGE = (
    "Failed to decrypt vault. Wrong master password or corrupted vault file."
)
_BACKUP_ATTEMPTS = 10
_TEXT_BOUND_CHUNK_SIZE = 64 * 1024
_UNSPECIFIED_SNAPSHOT = object()

# Backend type literals
BACKEND_FILE = VAULT_BACKEND_FILE
BACKEND_KEYCHAIN = VAULT_BACKEND_KEYCHAIN


@dataclass(frozen=True)
class VaultBackup:
    """Stable backup identity and filesystem modification time used for ordering."""

    identifier: str
    created_at: datetime
    path: Path


class VaultTransactionError(ValueError):
    """Generic transaction failure with non-secret recovery state."""

    def __init__(
        self,
        category: str,
        message: str,
        *,
        rollback_attempted: bool = False,
        rollback_succeeded: bool | None = None,
        backup_identifier: str | None = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.rollback_attempted = rollback_attempted
        self.rollback_succeeded = rollback_succeeded
        self.backup_identifier = backup_identifier


class _VaultInputTooLarge(ValueError):
    """Internal signal for vault text outside the raw-byte ingestion cap."""


def _vault_descriptor_regular_file_size(candidate_stream: BinaryIO) -> int:
    """Return a vault candidate's size from its opened regular descriptor."""
    try:
        file_status = os.fstat(candidate_stream.fileno())
    except (AttributeError, OSError, ValueError) as error:
        raise ValueError from error
    if not stat.S_ISREG(file_status.st_mode):
        raise ValueError
    return file_status.st_size


def read_bounded_vault_file(path: str | Path) -> bytes:
    """Read a regular-file vault value without allocating beyond the bound."""
    candidate_path = Path(path)
    try:
        if candidate_path.is_symlink() or not candidate_path.is_file():
            raise ValueError

        with open(candidate_path, "rb") as candidate_stream:
            candidate_size = _vault_descriptor_regular_file_size(candidate_stream)
            if candidate_size > MAX_FILE_SIZE:
                raise VaultTransactionError(
                    "candidate_too_large",
                    "Vault candidate exceeds the allowed input size.",
                )
            contents = candidate_stream.read(MAX_FILE_SIZE + 1)

        if len(contents) > MAX_FILE_SIZE:
            raise VaultTransactionError(
                "candidate_too_large",
                "Vault candidate exceeds the allowed input size.",
            )
        return contents
    except VaultTransactionError:
        raise
    except Exception:
        raise VaultTransactionError(
            "candidate_read_failed", "Vault candidate could not be read."
        ) from None


def _require_bounded_vault_text(vault_contents: str) -> str:
    """Validate a text vault's UTF-8 size without a full oversize allocation."""
    if len(vault_contents) > MAX_FILE_SIZE:
        raise _VaultInputTooLarge

    encoded_size = 0
    for offset in range(0, len(vault_contents), _TEXT_BOUND_CHUNK_SIZE):
        chunk = vault_contents[offset : offset + _TEXT_BOUND_CHUNK_SIZE]
        encoded_size += len(chunk.encode("utf-8", errors="strict"))
        if encoded_size > MAX_FILE_SIZE:
            raise _VaultInputTooLarge
    return vault_contents


def _bounded_vault_bytes(vault_contents: str) -> bytes:
    """Encode vault text only after its byte length is known to be bounded."""
    return _require_bounded_vault_text(vault_contents).encode("utf-8")


def _bounded_candidate_text(vault_contents: str | bytes) -> str:
    """Normalize a bounded raw candidate to strict UTF-8 text."""
    try:
        if isinstance(vault_contents, bytes):
            if len(vault_contents) > MAX_FILE_SIZE:
                raise VaultTransactionError(
                    "candidate_too_large",
                    "Vault candidate exceeds the allowed input size.",
                )
            return vault_contents.decode("utf-8", errors="strict")
        return _require_bounded_vault_text(vault_contents)
    except _VaultInputTooLarge:
        raise VaultTransactionError(
            "candidate_too_large",
            "Vault candidate exceeds the allowed input size.",
        ) from None
    except VaultTransactionError:
        raise
    except UnicodeError:
        raise VaultTransactionError(
            "candidate_validation_failed", "Vault candidate validation failed."
        ) from None


def _new_backup_identifier() -> str:
    """Return a UTC microsecond and random-suffix backup identifier."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    return f"vault_backup_{timestamp}_{secrets.token_hex(4)}.enc"


class _DuplicateVaultEntry(ValueError):
    """Internal signal for duplicate decrypted vault entry names."""


def _vault_entries_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Build a JSON object while rejecting duplicate member names."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateVaultEntry
        result[key] = value
    return result


def _compute_vault_hmac(data: str, master_password: str, salt: bytes) -> str:
    """Compute the current vault format's Argon2id-derived HMAC."""
    key = derive_key(master_password, salt)
    return hmac.new(key, data.encode(), hashlib.sha256).hexdigest()


def validate_raw_vault_document(
    vault_contents: str | bytes, master_password: str
) -> tuple[int, dict[str, str] | Any]:
    """Validate and decode supplied vault contents into Schema 1 or Schema 2 document.

    This function is side-effect free: it does not access a storage backend or
    mutate active vault state.
    """
    try:
        vault_contents = _bounded_candidate_text(vault_contents)

        lines = vault_contents.split("\n")
        if (
            len(lines) != 6
            or lines[0] != _VAULT_HEADER
            or lines[2] != "---DATA---"
            or lines[4] != "---HMAC---"
        ):
            raise ValueError

        salt_hex = lines[1]
        if len(salt_hex) != _HMAC_SALT_SIZE * 2 or any(
            char not in "0123456789abcdef" for char in salt_hex
        ):
            raise ValueError
        hmac_salt = bytes.fromhex(salt_hex)
        if len(hmac_salt) != _HMAC_SALT_SIZE:
            raise ValueError

        encrypted_vault = lines[3]
        _decode_canonical_base64(encrypted_vault)

        stored_hmac = lines[5]
        if len(stored_hmac) != _VAULT_HMAC_SIZE * 2 or any(
            char not in "0123456789abcdef" for char in stored_hmac
        ):
            raise ValueError
        if len(bytes.fromhex(stored_hmac)) != _VAULT_HMAC_SIZE:
            raise ValueError

        computed_hmac = _compute_vault_hmac(encrypted_vault, master_password, hmac_salt)
        if not hmac.compare_digest(computed_hmac, stored_hmac):
            raise ValueError

        decrypted_json = decrypt_text(encrypted_vault, master_password)
        from .v2.vault_schema import dispatch_vault_document

        return dispatch_vault_document(decrypted_json)
    except Exception:
        raise ValueError(_VAULT_FAILURE_MESSAGE) from None


def validate_raw_vault(
    vault_contents: str | bytes, master_password: str
) -> dict[str, str]:
    """Validate and decode supplied current-format vault contents.

    This function is side-effect free: it does not access a storage backend or
    mutate active vault state. The legacy current format has no version or
    entry-count field, so this reader adds no semantic entry limit. The shared
    raw-byte ingestion cap is enforced before parsing.

    All validation failures intentionally expose one generic message.
    """
    doc_type, doc = validate_raw_vault_document(vault_contents, master_password)
    if doc_type == 2:
        raise ValueError(_VAULT_FAILURE_MESSAGE)
    assert isinstance(doc, dict)
    return dict(doc)


class PassphraseVault:
    """Manages encrypted passphrase storage with integrity protection.

    Supports two storage backends:
    - "file": Traditional encrypted vault file on disk
    - "keychain": OS keychain via the keyring library

    When no backend is configured explicitly, a usable keychain is preferred
    and the file backend is the fallback.
    """

    def __init__(self, vault_path: str | None = None, backend: str | None = None):
        """Initialize the passphrase vault.

        Args:
            vault_path: Path to the vault file. If None, uses configured/default
                location. Used for file storage and file/keychain migration.
            backend: Storage backend - "file", "keychain", or None to use
                configured/default backend.

        Raises:
            ValueError: If backend is not recognized.
        """
        settings = load_vault_settings()
        explicit_vault_path = vault_path is not None
        if backend is None:
            backend = settings.vault_backend

        if backend not in (BACKEND_FILE, BACKEND_KEYCHAIN):
            raise ValueError(
                f"Unknown backend '{backend}'. Use '{BACKEND_FILE}' or '{BACKEND_KEYCHAIN}'."
            )

        self._backend = backend
        self._keychain = None

        if vault_path is None:
            vault_path = settings.vault_path
        if vault_path is None:
            vault_path = str(load_vault_settings().vault_path)

        self.vault_path = Path(vault_path)

        backup_dir: str | None
        backup_dir_env = os.environ.get("CIPHER_BACKUP_DIR")
        if backup_dir_env:
            backup_dir = backup_dir_env
        elif explicit_vault_path:
            backup_dir = str(get_default_backup_dir(self.vault_path))
        else:
            backup_dir = settings.backup_dir
        if backup_dir is None:
            backup_dir = str(get_default_backup_dir(self.vault_path))
        self.backup_dir = Path(backup_dir)

        if backend == BACKEND_FILE:
            self.vault_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        if backend == BACKEND_KEYCHAIN:
            from .keychain_backend import KeychainVaultBackend

            self._keychain = KeychainVaultBackend()

    @property
    def backend(self) -> str:
        """Return the current storage backend name."""
        return self._backend

    def _compute_hmac(self, data: str, master_password: str, salt: bytes) -> str:
        """Compute HMAC for integrity verification using Argon2id-derived key.

        Uses Argon2id with a random salt to derive the HMAC key, providing
        memory-hard protection against brute-force attacks on integrity verification.

        Args:
            data: Data to compute HMAC for
            master_password: Password for key derivation
            salt: Random salt for Argon2id key derivation

        Returns:
            Hex-encoded HMAC
        """
        return _compute_vault_hmac(data, master_password, salt)

    def _publish_backup(
        self,
        vault_contents: str,
        *,
        preserve_identifiers: frozenset[str] = frozenset(),
    ) -> str:
        """Publish exact raw vault contents under a collision-resistant name."""
        raw = _bounded_vault_bytes(vault_contents)
        if self.backup_dir.is_symlink():
            raise ValueError("Unsafe backup directory.")
        self.backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        for _ in range(_BACKUP_ATTEMPTS):
            identifier = _new_backup_identifier()
            backup_path = self.backup_dir / identifier
            if backup_path.exists() or backup_path.is_symlink():
                continue
            try:
                with atomic_binary_writer(
                    backup_path, overwrite=False, mode=0o600
                ) as writer:
                    writer.write(raw)
            except Exception:
                if backup_path.exists() or backup_path.is_symlink():
                    continue
                raise
            self._rotate_backups(
                preserve_identifiers=preserve_identifiers | frozenset({identifier})
            )
            return identifier
        raise ValueError("Unable to allocate a unique vault backup identifier.")

    def _rotate_backups(
        self, *, preserve_identifiers: frozenset[str] = frozenset()
    ) -> None:
        """Retain five backups without removing an active restore source."""
        backups = sorted(
            (
                path
                for path in self.backup_dir.glob("vault_backup_*.enc")
                if not path.is_symlink() and path.is_file()
            ),
            key=lambda path: path.stat().st_mtime_ns,
            reverse=True,
        )
        protected = [path for path in backups if path.name in preserve_identifiers]
        unprotected = [
            path for path in backups if path.name not in preserve_identifiers
        ]
        retained = set(protected + unprotected[: max(0, 5 - len(protected))])
        for old_backup in backups:
            if old_backup in retained:
                continue
            old_backup.unlink()

    def _create_backup(self) -> str | None:
        """Create a timestamped backup of the vault file.

        Keeps last 5 backups and removes older ones.
        """
        if self._backend != BACKEND_FILE or not self.vault_path.exists():
            return None
        vault_contents = self.read_raw_vault()
        if vault_contents is None:
            return None
        return self._publish_backup(vault_contents)

    @property
    def lock_target(self) -> Path | str:
        """Return stable lock target for cooperative locking."""
        if getattr(self, "_backend", None) == BACKEND_KEYCHAIN:
            return "keychain:secure-string-cipher:__ssc_vault_data__"
        if hasattr(self, "vault_path") and self.vault_path is not None:
            return self.vault_path
        return f"transient_vault:{id(self)}"

    def _load_document(self, master_password: str) -> tuple[int, dict[str, str] | Any]:
        """Load and authenticate complete vault document."""
        doc_type, doc, _ = self._read_document_snapshot(master_password)
        return doc_type, doc

    def _read_document_snapshot(
        self, master_password: str, *, allow_empty_legacy: bool = False
    ) -> tuple[int, Any, str | None]:
        """Authenticate one backend read and retain its exact transaction snapshot."""
        try:
            vault_contents = self.read_raw_vault()
        except Exception:
            raise ValueError(_VAULT_FAILURE_MESSAGE) from None

        if vault_contents is None or (allow_empty_legacy and vault_contents == ""):
            return 1, {}, vault_contents
        doc_type, doc = validate_raw_vault_document(vault_contents, master_password)
        return doc_type, doc, vault_contents

    def _save_document(
        self,
        doc_type: int,
        doc: dict[str, str] | Any,
        master_password: str,
        *,
        expected_raw: str | None | object = _UNSPECIFIED_SNAPSHOT,
        validate_document: Callable[[Any], None] | None = None,
    ) -> None:
        """Publish a complete document with validation, backup and rollback."""
        from .v2.vault_lock import hold_vault_lock

        with hold_vault_lock(self.lock_target):
            if expected_raw is _UNSPECIFIED_SNAPSHOT:
                expected_raw = self.read_raw_vault()
            candidate = self._encode_document(doc_type, doc, master_password)
            self._transact_raw_vault(
                candidate,
                master_password,
                backup_current=True,
                expected_raw=expected_raw,
                validate_document=validate_document,
                intended_document=(doc_type, doc),
            )

    def _encode_document(self, doc_type: int, doc: Any, master_password: str) -> str:
        """Validate and encode a candidate using the unchanged outer vault codec."""
        if doc_type == 2:
            from .v2.vault_schema import (
                V2VaultDocument,
                canonical_vault_json,
                validate_v2_vault_document,
            )

            assert isinstance(doc, V2VaultDocument)
            validate_v2_vault_document(doc.to_dict())
            json_data = canonical_vault_json(doc.to_dict()).decode("utf-8")
        else:
            if (
                doc_type != 1
                or not isinstance(doc, dict)
                or not all(
                    isinstance(k, str) and isinstance(v, str) for k, v in doc.items()
                )
            ):
                raise ValueError(_VAULT_FAILURE_MESSAGE)
            json_data = json.dumps(doc, indent=2)

        document_size = len(json_data.encode("utf-8"))
        if 161 + 4 * ((document_size + 78) // 3) > MAX_FILE_SIZE:
            raise _VaultInputTooLarge("Vault candidate exceeds the raw size limit.")
        encrypted_vault = encrypt_text(json_data, master_password)

        hmac_salt = secrets.token_bytes(_HMAC_SALT_SIZE)
        vault_hmac = self._compute_hmac(encrypted_vault, master_password, hmac_salt)

        vault_contents = (
            f"{_VAULT_HEADER}\n"
            f"{hmac_salt.hex()}\n"
            f"---DATA---\n"
            f"{encrypted_vault}\n"
            f"---HMAC---\n"
            f"{vault_hmac}"
        )
        _bounded_vault_bytes(vault_contents)
        return vault_contents

    def _load_vault(self, master_password: str) -> dict[str, str]:
        """Load and decrypt the vault with integrity verification.

        Args:
            master_password: Master password to decrypt the vault

        Returns:
            Dictionary mapping labels to encrypted passphrases

        Raises:
            ValueError: If vault is corrupted or tampered with
        """
        try:
            vault_contents = self.read_raw_vault()
        except Exception:
            raise ValueError(_VAULT_FAILURE_MESSAGE) from None

        if vault_contents is None or not vault_contents:
            return {}

        doc_type, doc = validate_raw_vault_document(vault_contents, master_password)
        if doc_type == 2:
            from .v2.vault_schema import V2VaultDocument

            assert isinstance(doc, V2VaultDocument)
            return dict(doc.passphrases)
        return dict(doc)

    def _save_vault(
        self,
        vault_data: dict[str, str],
        master_password: str,
        *,
        snapshot: tuple[int, Any, str | None] | None = None,
    ) -> None:
        """Encrypt and save the vault with Argon2id HMAC, preserving V2 structure if active.

        Args:
            vault_data: Dictionary mapping labels to passphrases
            master_password: Master password to encrypt the vault
        """
        if snapshot is None:
            snapshot = self._read_document_snapshot(
                master_password, allow_empty_legacy=True
            )
        doc_type, doc, raw = snapshot

        if doc_type == 2:
            from .v2.vault_schema import V2VaultDocument, V2VaultMeta

            assert isinstance(doc, V2VaultDocument)
            new_meta = V2VaultMeta(
                vault_id=doc.vault_meta.vault_id,
                revision=doc.vault_meta.revision + 1,
                wrap_generation=doc.vault_meta.wrap_generation,
                vault_kdf=doc.vault_meta.vault_kdf,
            )
            new_doc = V2VaultDocument(
                schema_version=2,
                vault_meta=new_meta,
                passphrases=vault_data,
                keys=dict(doc.keys),
            )
            self._save_document(
                2,
                new_doc,
                master_password,
                expected_raw=raw,
                validate_document=lambda _: None,
            )
        else:
            self._save_document(1, vault_data, master_password, expected_raw=raw)

    def store_passphrase(
        self, label: str, passphrase: str, master_password: str
    ) -> None:
        """Store a passphrase in the vault.

        Args:
            label: Label/name for this passphrase (e.g., "project-x", "backup-2025")
            passphrase: The passphrase to store
            master_password: Master password to encrypt the vault

        Raises:
            ValueError: If label is empty or already exists
        """
        if not label or not label.strip():
            raise ValueError("Label cannot be empty")

        label = label.strip()
        from .v2.vault_lock import hold_vault_lock

        with hold_vault_lock(self.lock_target):
            snapshot = self._read_document_snapshot(
                master_password, allow_empty_legacy=True
            )
            doc_type, doc, _ = snapshot
            vault_data = dict(doc.passphrases) if doc_type == 2 else dict(doc)

            if label in vault_data:
                raise ValueError(
                    f"Label '{label}' already exists. Use a different label or delete the existing one."
                )

            vault_data[label] = passphrase

            self._save_vault(vault_data, master_password, snapshot=snapshot)

    def retrieve_passphrase(self, label: str, master_password: str) -> str:
        """Retrieve a passphrase from the vault.

        Args:
            label: Label of the passphrase to retrieve
            master_password: Master password to decrypt the vault

        Returns:
            The decrypted passphrase

        Raises:
            ValueError: If label not found or decryption fails
        """
        from .v2.vault_lock import hold_vault_lock

        with hold_vault_lock(self.lock_target):
            vault_data = self._load_vault(master_password)

            if label not in vault_data:
                raise ValueError(f"Passphrase with label '{label}' not found")

            return vault_data[label]

    def list_labels(self, master_password: str) -> list[str]:
        """List all passphrase labels in the vault.

        Args:
            master_password: Master password to decrypt the vault

        Returns:
            List of passphrase labels
        """
        vault_data = self._load_vault(master_password)
        return sorted(vault_data.keys())

    def delete_passphrase(self, label: str, master_password: str) -> None:
        """Delete a passphrase from the vault.

        Args:
            label: Label of the passphrase to delete
            master_password: Master password to decrypt the vault

        Raises:
            ValueError: If label not found or decryption fails
        """
        from .v2.vault_lock import hold_vault_lock

        with hold_vault_lock(self.lock_target):
            snapshot = self._read_document_snapshot(
                master_password, allow_empty_legacy=True
            )
            doc_type, doc, _ = snapshot
            vault_data = dict(doc.passphrases) if doc_type == 2 else dict(doc)

            if label not in vault_data:
                raise ValueError(f"Passphrase with label '{label}' not found")

            del vault_data[label]
            self._save_vault(vault_data, master_password, snapshot=snapshot)

    def update_passphrase(
        self, label: str, new_passphrase: str, master_password: str
    ) -> None:
        """Update an existing passphrase in the vault.

        Args:
            label: Label of the passphrase to update
            new_passphrase: The new passphrase value
            master_password: Master password to decrypt the vault

        Raises:
            ValueError: If label not found or decryption fails
        """
        from .v2.vault_lock import hold_vault_lock

        with hold_vault_lock(self.lock_target):
            snapshot = self._read_document_snapshot(
                master_password, allow_empty_legacy=True
            )
            doc_type, doc, _ = snapshot
            vault_data = dict(doc.passphrases) if doc_type == 2 else dict(doc)

            if label not in vault_data:
                raise ValueError(f"Passphrase with label '{label}' not found")

            vault_data[label] = new_passphrase
            self._save_vault(vault_data, master_password, snapshot=snapshot)

    def vault_exists(self) -> bool:
        """Check if the vault exists (file or keychain).

        Returns:
            True if vault exists, False otherwise
        """
        if self._backend == BACKEND_KEYCHAIN:
            assert self._keychain is not None
            return self._keychain.vault_exists()
        return self.vault_path.exists()

    def get_vault_path(self) -> str:
        """Get the path/location of the vault.

        Returns:
            Path to the vault file or "keychain" indicator as a string
        """
        if self._backend == BACKEND_KEYCHAIN:
            return "OS Keychain"
        return str(self.vault_path)

    def read_raw_vault(self) -> str | None:
        """Read raw encrypted vault contents from the active backend."""
        if self._backend == BACKEND_KEYCHAIN:
            assert self._keychain is not None
            vault_contents = self._keychain.load_vault()
            if vault_contents is None:
                return None
            return _require_bounded_vault_text(vault_contents)
        if not self.vault_path.exists():
            return None
        contents = read_bounded_vault_file(self.vault_path)
        try:
            return contents.decode("utf-8", errors="strict")
        except UnicodeError:
            raise ValueError(_VAULT_FAILURE_MESSAGE) from None

    def write_raw_vault(self, vault_contents: str) -> None:
        """Write raw encrypted vault contents to the active backend."""
        from .v2.vault_lock import hold_vault_lock

        with hold_vault_lock(self.lock_target):
            raw_vault = _bounded_vault_bytes(vault_contents)
            if self._backend == BACKEND_KEYCHAIN:
                assert self._keychain is not None
                self._keychain.store_vault(vault_contents)
                return
            secure_atomic_write(self.vault_path, raw_vault, mode=0o600)

    def delete_vault_storage(self) -> None:
        """Delete vault data from the active backend."""
        from .v2.vault_lock import hold_vault_lock

        with hold_vault_lock(self.lock_target):
            if self._backend == BACKEND_KEYCHAIN:
                assert self._keychain is not None
                self._keychain.delete_vault()
                return
            if self.vault_path.exists():
                self.vault_path.unlink()

    def import_raw_vault(
        self,
        vault_contents: str | bytes,
        master_password: str,
        *,
        backup_current: bool = True,
    ) -> str | None:
        """Validate, publish, verify, and if necessary roll back a raw vault.

        Filesystem writes use atomic publication. Credential-store writes use
        best-effort rollback because native backends do not expose a transaction.

        Returns:
            The backup identifier for the previous active vault, if created.
        """
        candidate = _bounded_candidate_text(vault_contents)
        return self._transact_raw_vault(
            candidate,
            master_password,
            backup_current=backup_current,
        )

    def _transact_raw_vault(
        self,
        candidate: str,
        master_password: str,
        *,
        backup_current: bool,
        preserve_backup_identifiers: frozenset[str] = frozenset(),
        expected_raw: str | None | object = _UNSPECIFIED_SNAPSHOT,
        validate_document: Callable[[Any], None] | None = None,
        intended_document: tuple[int, Any] | None = None,
    ) -> str | None:
        """Publish a normalized raw candidate with verification and rollback."""
        from .v2.vault_lock import hold_vault_lock

        with hold_vault_lock(self.lock_target):
            try:
                expected_document = validate_raw_vault_document(
                    candidate, master_password
                )
                if (
                    intended_document is not None
                    and expected_document != intended_document
                ):
                    raise ValueError(
                        "Encoded candidate differs from the intended document."
                    )
                doc_type, doc = expected_document
                if validate_document is not None:
                    validate_document(doc)
                elif doc_type == 2:
                    from .v2.vault_schema import V2VaultDocument
                    from .v2.vault_service import V2VaultService

                    assert isinstance(doc, V2VaultDocument)
                    V2VaultService(vault=self)._validate_inner_secrets(
                        doc, master_password
                    )
            except (ValueError, TypeError):
                raise VaultTransactionError(
                    "candidate_validation_failed", "Vault candidate validation failed."
                ) from None

            try:
                previous_raw = self.read_raw_vault()
            except Exception:
                raise VaultTransactionError(
                    "active_read_failed",
                    "Vault transaction failed before publication.",
                ) from None

            if (
                expected_raw is not _UNSPECIFIED_SNAPSHOT
                and previous_raw != expected_raw
            ):
                raise VaultTransactionError(
                    "stale_snapshot", "Vault changed before publication."
                )

            backup_identifier = None
            if previous_raw is not None and backup_current:
                try:
                    backup_identifier = self._publish_backup(
                        previous_raw,
                        preserve_identifiers=preserve_backup_identifiers,
                    )
                except Exception:
                    raise VaultTransactionError(
                        "backup_failed",
                        "Vault transaction failed before publication.",
                    ) from None

            try:
                current_raw = self.read_raw_vault()
            except Exception:
                raise VaultTransactionError(
                    "active_read_failed",
                    "Vault transaction failed before publication.",
                    backup_identifier=backup_identifier,
                ) from None
            if current_raw != previous_raw:
                raise VaultTransactionError(
                    "stale_snapshot",
                    "Vault changed before publication.",
                    backup_identifier=backup_identifier,
                )
            try:
                self.write_raw_vault(candidate)
                published_raw = self.read_raw_vault()
                if published_raw is None or published_raw != candidate:
                    raise ValueError
                # Exact bytes preserve the candidate's inner-secret validation;
                # authenticate and compare the complete outer document again.
                published_document = validate_raw_vault_document(
                    published_raw, master_password
                )
                if published_document != expected_document:
                    raise ValueError
            except BaseException as publication_error:
                try:
                    if previous_raw is None:
                        self.delete_vault_storage()
                        if self.read_raw_vault() is not None:
                            raise ValueError
                    else:
                        self.write_raw_vault(previous_raw)
                        if self.read_raw_vault() != previous_raw:
                            raise ValueError
                except Exception:
                    raise VaultTransactionError(
                        "rollback_failed",
                        "Vault transaction failed and rollback failed; active vault may be inconsistent.",
                        rollback_attempted=True,
                        rollback_succeeded=False,
                        backup_identifier=backup_identifier,
                    ) from None

                if not isinstance(publication_error, Exception):
                    raise
                raise VaultTransactionError(
                    "publication_failed",
                    "Vault transaction failed; previous vault restored.",
                    rollback_attempted=True,
                    rollback_succeeded=True,
                    backup_identifier=backup_identifier,
                ) from None

            return backup_identifier

    def migrate_to_keychain(self, master_password: str) -> None:
        """Migrate vault data from file backend to keychain.

        Args:
            master_password: Master password to decrypt/re-encrypt the vault

        Raises:
            ValueError: If file vault doesn't exist or can't be read
        """
        self._copy_backend(BACKEND_FILE, BACKEND_KEYCHAIN, master_password)

    def migrate_to_file(self, master_password: str) -> None:
        """Migrate vault data from keychain to file backend.

        Args:
            master_password: Master password to decrypt/re-encrypt the vault

        Raises:
            ValueError: If keychain vault doesn't exist or can't be read
        """
        self._copy_backend(BACKEND_KEYCHAIN, BACKEND_FILE, master_password)

    def _copy_backend(
        self, source_backend: str, destination_backend: str, master_password: str
    ) -> None:
        """Lock both backends in a stable order and transactionally copy the blob."""
        from .v2.vault_lock import get_vault_lock_path, hold_vault_lock

        if source_backend == BACKEND_FILE:
            if not self.vault_path.exists():
                raise ValueError("No file vault found to migrate.")
            source_size = self.vault_path.stat().st_size
            if source_size > MAX_FILE_SIZE:
                raise VaultTransactionError(
                    "candidate_too_large", "Vault candidate exceeds the raw size limit."
                )
            if source_size == 0:
                raise ValueError("Vault file is empty.")
        source = PassphraseVault(str(self.vault_path), backend=source_backend)
        destination = PassphraseVault(str(self.vault_path), backend=destination_backend)
        destination.backup_dir = self.backup_dir
        targets = sorted(
            [source.lock_target, destination.lock_target],
            key=lambda target: str(get_vault_lock_path(target)),
        )
        with ExitStack() as stack:
            for target in targets:
                stack.enter_context(hold_vault_lock(target))
            raw = source.read_raw_vault()
            if raw is None:
                raise ValueError(f"No {source_backend} vault found to migrate.")
            if not raw:
                raise ValueError("Vault file is empty.")
            destination.import_raw_vault(raw, master_password)

    def list_backup_records(self) -> list[VaultBackup]:
        """List backups by stable identifier and mtime-derived UTC ordering time."""
        records = []
        for path in self.backup_dir.glob("vault_backup_*.enc"):
            if path.is_symlink() or not path.is_file():
                continue
            created_at = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
            records.append(VaultBackup(path.name, created_at, path))
        return sorted(records, key=lambda record: record.created_at, reverse=True)

    def list_backups(self) -> list[str]:
        """List available backup files.

        Returns:
            List of backup file paths sorted by date (newest first)
        """
        return [str(record.path) for record in self.list_backup_records()]

    def _read_backup(self, backup_identifier: str) -> bytes:
        """Resolve an exact stable identifier and read it with the import bound."""
        if Path(backup_identifier).name != backup_identifier:
            raise VaultTransactionError(
                "backup_not_found", "Selected vault backup was not found."
            )
        records = {record.identifier: record for record in self.list_backup_records()}
        record = records.get(backup_identifier)
        if record is None:
            raise VaultTransactionError(
                "backup_not_found", "Selected vault backup was not found."
            )
        return read_bounded_vault_file(record.path)

    def validate_backup(self, backup_identifier: str, master_password: str) -> None:
        """Validate a selected backup without changing active storage."""
        candidate = self._read_backup(backup_identifier)
        try:
            doc_type, doc = validate_raw_vault_document(candidate, master_password)
            if doc_type == 2:
                from .v2.vault_schema import V2VaultDocument
                from .v2.vault_service import V2VaultService

                assert isinstance(doc, V2VaultDocument)
                V2VaultService(vault=self)._validate_inner_secrets(doc, master_password)
        except ValueError:
            raise VaultTransactionError(
                "candidate_validation_failed", "Vault candidate validation failed."
            ) from None

    def restore_from_backup(
        self, backup_identifier: str, master_password: str
    ) -> str | None:
        """Transactionally restore an exactly identified backup.

        Args:
            backup_identifier: Exact identifier returned by list_backup_records().
            master_password: Password for the selected backup.

        Returns:
            Identifier of the backup made from the prior active vault, if any.
        """
        from .v2.vault_lock import hold_vault_lock

        with hold_vault_lock(self.lock_target):
            candidate = self._read_backup(backup_identifier)
            candidate_text = _bounded_candidate_text(candidate)
            return self._transact_raw_vault(
                candidate_text,
                master_password,
                backup_current=True,
                preserve_backup_identifiers=frozenset({backup_identifier}),
            )
