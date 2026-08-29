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

import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
from datetime import datetime
from pathlib import Path

from .config import (
    VAULT_BACKEND_FILE,
    VAULT_BACKEND_KEYCHAIN,
    get_default_backup_dir,
    load_vault_settings,
)
from .core import decrypt_text, derive_key, encrypt_text
from .security import secure_atomic_write

# Vault format constants
_VAULT_HEADER = "SSCVAULT"
_HMAC_SALT_SIZE = 32  # 256 bits
_VAULT_HMAC_SIZE = 32
_VAULT_FAILURE_MESSAGE = (
    "Failed to decrypt vault. Wrong master password or corrupted vault file."
)

# Backend type literals
BACKEND_FILE = VAULT_BACKEND_FILE
BACKEND_KEYCHAIN = VAULT_BACKEND_KEYCHAIN


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
        base64.b64decode(encrypted_vault, validate=True)

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

    def _create_backup(self) -> None:
        """Create a timestamped backup of the vault file.

        Keeps last 5 backups and removes older ones.
        """
        if self._backend != BACKEND_FILE or not self.vault_path.exists():
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.backup_dir / f"vault_backup_{timestamp}.enc"

        shutil.copy2(self.vault_path, backup_path)
        os.chmod(backup_path, 0o600)

        backups = sorted(self.backup_dir.glob("vault_backup_*.enc"))
        if len(backups) > 5:
            for old_backup in backups[:-5]:
                old_backup.unlink()

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

    def list_backups(self) -> list[str]:
        """List available backup files.

        Returns:
            List of backup file paths sorted by date (newest first)
        """
        backups = sorted(self.backup_dir.glob("vault_backup_*.enc"), reverse=True)
        return [str(b) for b in backups]

    def restore_from_backup(self, backup_index: int = 0) -> None:
        """Restore vault from a backup file.

        Args:
            backup_index: Index of backup to restore (0 = most recent)

        Raises:
            ValueError: If no backups available or index out of range
        """
        backups = sorted(self.backup_dir.glob("vault_backup_*.enc"), reverse=True)

        if not backups:
            raise ValueError("No backups available")

        if backup_index >= len(backups):
            raise ValueError(
                f"Backup index {backup_index} out of range. "
                f"Only {len(backups)} backup(s) available."
            )

        backup_file = backups[backup_index]
        shutil.copy2(backup_file, self.vault_path)
        os.chmod(self.vault_path, 0o600)
