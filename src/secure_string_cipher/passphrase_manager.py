"""
Passphrase management module for secure storage and retrieval.

This module encrypts generated passphrases with a master password and stores them
in an encrypted vault file. Users can retrieve their passphrases by providing
the master password.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional

from .core import decrypt_text, encrypt_text


class PassphraseVault:
    """Manages encrypted passphrase storage."""

    def __init__(self, vault_path: Optional[str] = None):
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
        else:
            self.vault_path = Path(vault_path)

    def _load_vault(self, master_password: str) -> Dict[str, str]:
        """Load and decrypt the vault.

        Args:
            master_password: Master password to decrypt the vault

        Returns:
            Dictionary mapping labels to encrypted passphrases
        """
        if not self.vault_path.exists():
            return {}

        try:
            with open(self.vault_path, "r") as f:
                encrypted_vault = f.read().strip()

            if not encrypted_vault:
                return {}

            # Decrypt the vault contents
            decrypted_json = decrypt_text(encrypted_vault, master_password)
            return json.loads(decrypted_json)
        except Exception:
            # If decryption fails (wrong password or corrupted), return empty
            raise ValueError(
                "Failed to decrypt vault. Wrong master password or corrupted vault file."
            )

    def _save_vault(self, vault_data: Dict[str, str], master_password: str) -> None:
        """Encrypt and save the vault.

        Args:
            vault_data: Dictionary mapping labels to passphrases
            master_password: Master password to encrypt the vault
        """
        # Convert to JSON
        json_data = json.dumps(vault_data, indent=2)

        # Encrypt the entire vault
        encrypted_vault = encrypt_text(json_data, master_password)

        # Save to file with restricted permissions
        with open(self.vault_path, "w") as f:
            f.write(encrypted_vault)

        # Set file permissions to 600 (owner read/write only)
        os.chmod(self.vault_path, 0o600)

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

        # Load existing vault
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

        # Add new passphrase
        vault_data[label] = passphrase

        # Save vault
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

    def list_labels(self, master_password: str) -> List[str]:
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
