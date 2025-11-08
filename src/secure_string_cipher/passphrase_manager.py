"""
Passphrase management module for secure storage and retrieval.

This module encrypts generated passphrases with a master password and stores them
in an encrypted vault file. Users can retrieve their passphrases by providing
the master password.
"""

import hashlib
import hmac
import json
import os
import shutil
from datetime import datetime
from pathlib import Path

from .core import decrypt_text, encrypt_text
from .security import secure_atomic_write


class PassphraseVault:
    """Manages encrypted passphrase storage with integrity protection."""

    def __init__(self, vault_path: str | None = None):
        """Initialize the passphrase vault.

        Args:
            vault_path: Path to the vault file. If None, uses default location.
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

    def _compute_hmac(self, data: str, master_password: str) -> str:
        """Compute HMAC for integrity verification.

        Args:
            data: Data to compute HMAC for
            master_password: Key for HMAC

        Returns:
            Hex-encoded HMAC
        """
        key = hashlib.sha256(master_password.encode()).digest()
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
        if not self.vault_path.exists():
            return {}

        try:
            with open(self.vault_path) as f:
                vault_contents = f.read().strip()

            if not vault_contents:
                return {}

            if "\n---HMAC---\n" in vault_contents:
                encrypted_vault, stored_hmac = vault_contents.split("\n---HMAC---\n")

                # Verify HMAC integrity
                computed_hmac = self._compute_hmac(encrypted_vault, master_password)
                if not hmac.compare_digest(computed_hmac, stored_hmac):
                    # HMAC mismatch could be wrong password OR tampering
                    # Try to decrypt to differentiate
                    try:
                        decrypt_text(encrypted_vault, master_password)
                        # If decryption succeeds, file was tampered (HMAC wrong but decrypt works)
                        raise ValueError(
                            "Vault integrity check failed! File may have been tampered with. "
                            "Check backups in ~/.secure-cipher/backups/"
                        )
                    except Exception:
                        # If decryption also fails, it's likely wrong password
                        raise ValueError(
                            "Wrong master password or corrupted vault file"
                        ) from None
            else:
                # Legacy vault without HMAC (from older version)
                encrypted_vault = vault_contents

            decrypted_json = decrypt_text(encrypted_vault, master_password)
            return json.loads(decrypted_json)
        except json.JSONDecodeError:
            raise ValueError("Vault file is corrupted. Check backups.") from None
        except ValueError:
            # Re-raise our custom error messages
            raise
        except Exception:
            # If decryption fails (wrong password or corrupted), return empty
            raise ValueError(
                "Failed to decrypt vault. Wrong master password or corrupted vault file."
            ) from None

    def _save_vault(self, vault_data: dict[str, str], master_password: str) -> None:
        """Encrypt and save the vault with integrity protection.

        Args:
            vault_data: Dictionary mapping labels to passphrases
            master_password: Master password to encrypt the vault
        """
        self._create_backup()

        json_data = json.dumps(vault_data, indent=2)

        encrypted_vault = encrypt_text(json_data, master_password)

        # Compute HMAC for integrity verification
        vault_hmac = self._compute_hmac(encrypted_vault, master_password)

        vault_contents = f"{encrypted_vault}\n---HMAC---\n{vault_hmac}"

        # Use atomic write to prevent corruption during write
        secure_atomic_write(self.vault_path, vault_contents.encode("utf-8"), mode=0o600)

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
            # If vault doesn't exist or is empty, start fresh
            if self.vault_path.exists() and self.vault_path.stat().st_size > 0:
                raise  # Re-raise if file exists but can't decrypt
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
        """Check if the vault file exists.

        Returns:
            True if vault file exists, False otherwise
        """
        return self.vault_path.exists()

    def get_vault_path(self) -> str:
        """Get the path to the vault file.

        Returns:
            Path to the vault file as a string
        """
        return str(self.vault_path)

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
