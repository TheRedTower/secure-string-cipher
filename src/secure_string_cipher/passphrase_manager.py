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
      Linux Secret Service). Install with: pip install secure-string-cipher[keychain]
"""

import hashlib
import hmac
import json
import os
import secrets
import shutil
from datetime import datetime
from pathlib import Path

from .core import decrypt_text, derive_key, encrypt_text
from .security import secure_atomic_write

# Vault format constants
_VAULT_HEADER = "SSCVAULT"
_HMAC_SALT_SIZE = 32  # 256 bits

# Backend type literals
BACKEND_FILE = "file"
BACKEND_KEYCHAIN = "keychain"


class PassphraseVault:
    """Manages encrypted passphrase storage with integrity protection.

    Supports two storage backends:
    - "file": Traditional encrypted vault file on disk (default)
    - "keychain": OS keychain via the keyring library
    """

    def __init__(self, vault_path: str | None = None, backend: str | None = None):
        """Initialize the passphrase vault.

        Args:
            vault_path: Path to the vault file. If None, uses default location.
                Ignored when backend is "keychain".
            backend: Storage backend - "file" or "keychain". If None, reads from
                the persisted backend config (defaults to "file" if not set).

        Raises:
            ValueError: If backend is not recognized.
        """
        if vault_path is None:
            # Default to user's home directory
            home = Path.home()
            vault_dir = home / ".secure-cipher"
            vault_dir.mkdir(exist_ok=True, mode=0o700)
            self.vault_path = vault_dir / "passphrase_vault.enc"
            self.backup_dir = vault_dir / "backups"
            self.backup_dir.mkdir(exist_ok=True, mode=0o700)
        else:
            self.vault_path = Path(vault_path)
            backup_dir_env = os.environ.get("CIPHER_BACKUP_DIR")
            if backup_dir_env:
                self.backup_dir = Path(backup_dir_env)
            else:
                self.backup_dir = self.vault_path.parent / "backups"
            self.backup_dir.mkdir(exist_ok=True, mode=0o700)

        # Resolve backend: explicit > persisted config > default (file)
        if backend is None:
            backend = self._load_backend_config()

        if backend not in (BACKEND_FILE, BACKEND_KEYCHAIN):
            raise ValueError(
                f"Unknown backend '{backend}'. Use '{BACKEND_FILE}' or '{BACKEND_KEYCHAIN}'."
            )

        self._backend = backend
        self._keychain = None

        if backend == BACKEND_KEYCHAIN:
            from .keychain_backend import KeychainVaultBackend

            self._keychain = KeychainVaultBackend()

    @property
    def backend(self) -> str:
        """Return the current storage backend name."""
        return self._backend

    @staticmethod
    def _backend_config_path() -> Path:
        """Return path to the backend configuration file."""
        return Path.home() / ".secure-cipher" / "backend.conf"

    @classmethod
    def _load_backend_config(cls) -> str:
        """Load the persisted backend choice from config file.

        Returns:
            The backend name, or BACKEND_FILE if no config exists.
        """
        config_path = cls._backend_config_path()
        try:
            if config_path.exists():
                value = config_path.read_text().strip()
                if value in (BACKEND_FILE, BACKEND_KEYCHAIN):
                    return value
        except OSError:
            pass
        return BACKEND_FILE

    @classmethod
    def save_backend_config(cls, backend: str) -> None:
        """Persist the backend choice to config file.

        Args:
            backend: The backend name to persist ("file" or "keychain").
        """
        config_path = cls._backend_config_path()
        config_path.parent.mkdir(exist_ok=True, mode=0o700)
        config_path.write_text(backend + "\n")
        os.chmod(config_path, 0o600)

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
        key = derive_key(master_password, salt)
        return hmac.new(key, data.encode(), hashlib.sha256).hexdigest()

    def _create_backup(self) -> None:
        """Create a timestamped backup of the vault file.

        Keeps last 5 backups and removes older ones.
        """
        if not self.vault_path.exists():
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
            vault_contents = vault_contents.strip()
        else:
            if not self.vault_path.exists():
                return {}
            try:
                with open(self.vault_path) as f:
                    vault_contents = f.read().strip()
            except Exception:
                raise ValueError(
                    "Failed to decrypt vault. Wrong master password or corrupted vault file."
                ) from None

        if not vault_contents:
            return {}

        try:
            # Parse vault format: SSCVAULT / hmac_salt_hex / ---DATA--- / encrypted / ---HMAC--- / hmac
            lines = vault_contents.split("\n")

            if not vault_contents.startswith(_VAULT_HEADER + "\n"):
                raise ValueError(
                    "Unrecognized vault format. This vault may be from an older version."
                )

            if len(lines) < 6 or lines[2] != "---DATA---":
                raise ValueError("Corrupted vault file format")

            hmac_salt_hex = lines[1]
            try:
                hmac_salt = bytes.fromhex(hmac_salt_hex)
            except ValueError:
                raise ValueError("Corrupted vault file: invalid HMAC salt") from None

            # Find data and HMAC sections
            data_start = 3
            hmac_separator_idx = None
            for i, line in enumerate(lines[data_start:], start=data_start):
                if line == "---HMAC---":
                    hmac_separator_idx = i
                    break

            if hmac_separator_idx is None:
                raise ValueError("Corrupted vault file: missing HMAC")

            encrypted_vault = "\n".join(lines[data_start:hmac_separator_idx])
            stored_hmac = "\n".join(lines[hmac_separator_idx + 1 :])

            # Verify HMAC with Argon2id-derived key.
            # NOTE: We intentionally do NOT attempt decryption here to avoid
            # a timing side-channel (Argon2id key derivation is ~50-100ms,
            # easily distinguishable from a fast HMAC failure).
            computed_hmac = self._compute_hmac(
                encrypted_vault, master_password, hmac_salt
            )
            if not hmac.compare_digest(computed_hmac, stored_hmac):
                raise ValueError(
                    "Wrong master password or corrupted vault file"
                ) from None

            decrypted_json = decrypt_text(encrypted_vault, master_password)
            return json.loads(decrypted_json)

        except json.JSONDecodeError:
            raise ValueError("Vault file is corrupted. Check backups.") from None
        except ValueError:
            raise
        except Exception:
            raise ValueError(
                "Failed to decrypt vault. Wrong master password or corrupted vault file."
            ) from None

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
            # If vault doesn't exist or is empty, start fresh.
            # Use backend-aware existence check to avoid overwriting
            # a keychain vault when the master password is wrong.
            if self.vault_exists():
                raise  # Re-raise if vault exists but can't decrypt
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

    def export_raw(self) -> str:
        """Export the raw vault contents from the active backend.

        Returns:
            The raw vault contents string.

        Raises:
            ValueError: If no vault exists in the active backend.
        """
        if self._backend == BACKEND_KEYCHAIN:
            assert self._keychain is not None
            contents = self._keychain.load_vault()
            if contents is None:
                raise ValueError("No vault found in keychain.")
            return contents
        if not self.vault_path.exists():
            raise ValueError("No vault file found.")
        return self.vault_path.read_text()

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
            vault_contents = f.read().strip()

        if not vault_contents:
            raise ValueError("Vault file is empty.")

        # Verify we can decrypt it (validates master password)
        self._load_vault(master_password)

        # Store in keychain
        keychain = KeychainVaultBackend()
        keychain.store_vault(vault_contents)

        # Persist backend choice so subsequent commands use keychain
        self.save_backend_config(BACKEND_KEYCHAIN)

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

        # Verify we can decrypt it (validates master password)
        # Temporarily switch to keychain to load
        old_backend = self._backend
        old_keychain = self._keychain
        self._backend = BACKEND_KEYCHAIN
        self._keychain = keychain
        try:
            self._load_vault(master_password)
        finally:
            self._backend = old_backend
            self._keychain = old_keychain

        # Write to file
        secure_atomic_write(self.vault_path, vault_contents.encode("utf-8"), mode=0o600)

        # Persist backend choice so subsequent commands use file
        self.save_backend_config(BACKEND_FILE)

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
