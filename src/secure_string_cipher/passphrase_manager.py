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
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

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


def read_bounded_vault_file(path: str | Path) -> bytes:
    """Read a candidate vault into the existing 100 MiB bounded buffer."""
    candidate_path = Path(path)
    try:
        if candidate_path.is_symlink() or not candidate_path.is_file():
            raise ValueError
        if candidate_path.stat().st_size > MAX_FILE_SIZE:
            raise VaultTransactionError(
                "candidate_too_large",
                "Vault candidate exceeds the allowed input size.",
            )
        contents = candidate_path.read_bytes()
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
        if len(vault_contents.encode("utf-8")) > MAX_FILE_SIZE:
            raise VaultTransactionError(
                "candidate_too_large",
                "Vault candidate exceeds the allowed input size.",
            )
        return vault_contents
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


def validate_raw_vault(
    vault_contents: str | bytes, master_password: str
) -> dict[str, str]:
    """Validate and decode supplied current-format vault contents.

    This function is side-effect free: it does not access a storage backend or
    mutate active vault state. The legacy current format has no version field,
    encoded size bound, or entry-count bound, so this reader does not invent
    limits that could reject an existing valid vault.

    All validation failures intentionally expose one generic message.
    """
    try:
        if isinstance(vault_contents, bytes):
            vault_contents = vault_contents.decode("utf-8", errors="strict")

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
        entries = json.loads(
            decrypted_json,
            object_pairs_hook=_vault_entries_object,
        )
        if not isinstance(entries, dict) or any(
            type(label) is not str or type(passphrase) is not str
            for label, passphrase in entries.items()
        ):
            raise ValueError

        return dict(entries)
    except Exception:
        raise ValueError(_VAULT_FAILURE_MESSAGE) from None


class PassphraseVault:
    """Manages encrypted passphrase storage with integrity protection.

    Supports two storage backends:
    - "file": Traditional encrypted vault file on disk (default)
    - "keychain": OS keychain via the keyring library
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
        raw = vault_contents.encode("utf-8")
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
            self.backup_dir.glob("vault_backup_*.enc"),
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
        return self._publish_backup(self.vault_path.read_text())

    def _load_vault(self, master_password: str) -> dict[str, str]:
        """Load and decrypt the vault with integrity verification.

        Args:
            master_password: Master password to decrypt the vault

        Returns:
            Dictionary mapping labels to encrypted passphrases

        Raises:
            ValueError: If vault is corrupted or tampered with
        """
        # Load vault contents from appropriate backend
        if self._backend == BACKEND_KEYCHAIN:
            assert self._keychain is not None
            vault_contents = self._keychain.load_vault()
            if vault_contents is None:
                return {}
        else:
            if not self.vault_path.exists():
                return {}
            try:
                with open(self.vault_path) as f:
                    vault_contents = f.read()
            except Exception:
                raise ValueError(_VAULT_FAILURE_MESSAGE) from None

        if not vault_contents:
            return {}

        return validate_raw_vault(vault_contents, master_password)

    def _save_vault(self, vault_data: dict[str, str], master_password: str) -> None:
        """Encrypt and save the vault with Argon2id HMAC.

        Args:
            vault_data: Dictionary mapping labels to passphrases
            master_password: Master password to encrypt the vault
        """
        self._create_backup()

        json_data = json.dumps(vault_data, indent=2)
        encrypted_vault = encrypt_text(json_data, master_password)

        # Generate random salt for HMAC key derivation
        hmac_salt = secrets.token_bytes(_HMAC_SALT_SIZE)
        vault_hmac = self._compute_hmac(encrypted_vault, master_password, hmac_salt)

        # Build vault format
        vault_contents = (
            f"{_VAULT_HEADER}\n"
            f"{hmac_salt.hex()}\n"
            f"---DATA---\n"
            f"{encrypted_vault}\n"
            f"---HMAC---\n"
            f"{vault_hmac}"
        )

        if self._backend == BACKEND_KEYCHAIN:
            assert self._keychain is not None
            self._keychain.store_vault(vault_contents)
        else:
            # Use atomic write to prevent corruption during write
            secure_atomic_write(
                self.vault_path, vault_contents.encode("utf-8"), mode=0o600
            )

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

        try:
            vault_data = self._load_vault(master_password)
        except ValueError:
            # Only initialize a fresh vault when there is no existing storage.
            # Wrong master passwords or corrupted existing vaults must never
            # overwrite keychain/file contents.
            if self.vault_exists():
                if (
                    self._backend == BACKEND_FILE
                    and self.vault_path.exists()
                    and self.vault_path.stat().st_size == 0
                ):
                    vault_data = {}
                else:
                    raise
            else:
                vault_data = {}

        if label in vault_data:
            raise ValueError(
                f"Label '{label}' already exists. Use a different label or delete the existing one."
            )

        vault_data[label] = passphrase

        self._save_vault(vault_data, master_password)

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
        vault_data = self._load_vault(master_password)

        if label not in vault_data:
            raise ValueError(f"Passphrase with label '{label}' not found")

        del vault_data[label]
        self._save_vault(vault_data, master_password)

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
        vault_data = self._load_vault(master_password)

        if label not in vault_data:
            raise ValueError(f"Passphrase with label '{label}' not found")

        vault_data[label] = new_passphrase
        self._save_vault(vault_data, master_password)

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
            return self._keychain.load_vault()
        if not self.vault_path.exists():
            return None
        return self.vault_path.read_text()

    def write_raw_vault(self, vault_contents: str) -> None:
        """Write raw encrypted vault contents to the active backend."""
        if self._backend == BACKEND_KEYCHAIN:
            assert self._keychain is not None
            self._keychain.store_vault(vault_contents)
            return
        secure_atomic_write(self.vault_path, vault_contents.encode("utf-8"), mode=0o600)

    def delete_vault_storage(self) -> None:
        """Delete vault data from the active backend."""
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
    ) -> str | None:
        """Publish a normalized raw candidate with verification and rollback."""
        try:
            expected_entries = validate_raw_vault(candidate, master_password)
        except ValueError:
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
            self.write_raw_vault(candidate)
            published_raw = self.read_raw_vault()
            if published_raw is None or published_raw != candidate:
                raise ValueError
            published_entries = validate_raw_vault(published_raw, master_password)
            if published_entries != expected_entries:
                raise ValueError
        except Exception:
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
        from .keychain_backend import KeychainVaultBackend

        # Load from file
        if not self.vault_path.exists():
            raise ValueError("No file vault found to migrate.")

        with open(self.vault_path) as f:
            vault_contents = f.read()

        if not vault_contents:
            raise ValueError("Vault file is empty.")

        # Validate the supplied candidate without consulting active backend state.
        validate_raw_vault(vault_contents, master_password)

        # Store in keychain
        keychain = KeychainVaultBackend()
        keychain.store_vault(vault_contents)

    def migrate_to_file(self, master_password: str) -> None:
        """Migrate vault data from keychain to file backend.

        Args:
            master_password: Master password to decrypt/re-encrypt the vault

        Raises:
            ValueError: If keychain vault doesn't exist or can't be read
        """
        from .keychain_backend import KeychainVaultBackend

        keychain = KeychainVaultBackend()
        vault_contents = keychain.load_vault()

        if vault_contents is None:
            raise ValueError("No keychain vault found to migrate.")

        # Validate the supplied candidate without changing the active backend.
        validate_raw_vault(vault_contents, master_password)

        # Write to file
        self.vault_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        secure_atomic_write(self.vault_path, vault_contents.encode("utf-8"), mode=0o600)

    def list_backup_records(self) -> list[VaultBackup]:
        """List backups by stable identifier and filesystem creation time."""
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
            validate_raw_vault(candidate, master_password)
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
        candidate = self._read_backup(backup_identifier)
        candidate_text = _bounded_candidate_text(candidate)
        return self._transact_raw_vault(
            candidate_text,
            master_password,
            backup_current=True,
            preserve_backup_identifiers=frozenset({backup_identifier}),
        )
