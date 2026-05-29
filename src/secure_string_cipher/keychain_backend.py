"""
Keychain backend for passphrase vault storage.

Provides cross-platform OS keychain integration using the `keyring` library:
- macOS: Keychain Access
- Windows: Windows Credential Vault
- Linux: Secret Service (GNOME Keyring / KDE Wallet via D-Bus)

The keychain stores individual vault entries (label → encrypted passphrase)
or the entire vault blob, depending on the storage mode.

Install with: pip install secure-string-cipher[keychain]
"""

from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)

# Service name used in the OS keychain
_SERVICE_NAME = "secure-string-cipher"
_VAULT_KEY = "__ssc_vault_data__"


class KeychainError(Exception):
    """Raised when keychain operations fail."""


class KeychainUnavailableError(KeychainError):
    """Raised when the keyring library is not installed or no backend is available."""


def _get_keyring():
    """Import and return the keyring module.

    Raises:
        KeychainUnavailableError: If keyring is not installed or has no usable backend.
    """
    try:
        import keyring
        import keyring.errors
    except ImportError:
        raise KeychainUnavailableError(
            "The 'keyring' package is not installed. "
            "Install it with: pip install secure-string-cipher[keychain]"
        ) from None

    # Verify a usable backend is available
    backend = keyring.get_keyring()
    backend_module = type(backend).__module__ or ""
    backend_name = type(backend).__name__
    # The fail backend (keyring.backends.fail.Keyring) and null backend
    # indicate no real keychain is available. Check module path for reliable
    # detection since the class name alone ("Keyring") is ambiguous.
    if (
        backend_module.startswith("keyring.backends.fail")
        or backend_module.startswith("keyring.backends.null")
        or "Fail" in backend_name
        or "null" in backend_name.lower()
    ):
        raise KeychainUnavailableError(
            f"No usable keychain backend found (got: {backend_module}.{backend_name}). "
            "Ensure your OS keychain service is running."
        )

    return keyring


def is_keychain_available() -> bool:
    """Check if a usable OS keychain backend is available.

    Returns:
        True if keyring is installed and has a usable backend.
    """
    try:
        _get_keyring()
        return True
    except KeychainUnavailableError:
        return False


def get_keychain_backend_name() -> str:
    """Get the name of the active keychain backend.

    Returns:
        Human-readable name of the keychain backend.

    Raises:
        KeychainUnavailableError: If keychain is not available.
    """
    keyring = _get_keyring()
    backend = keyring.get_keyring()
    return type(backend).__name__


class KeychainVaultBackend:
    """Vault storage backend using OS keychain.

    Stores the entire encrypted vault JSON blob in the OS keychain
    as a single credential entry, indexed by a fixed key.

    This approach ensures:
    - All vault data is protected by OS-level keychain security
    - The master password still encrypts the data (defense in depth)
    - Atomic read/write operations
    - No plaintext vault file on disk
    """

    def __init__(self, service_name: str = _SERVICE_NAME):
        """Initialize the keychain backend.

        Args:
            service_name: Service identifier in the keychain.

        Raises:
            KeychainUnavailableError: If keychain is not available.
        """
        self._keyring = _get_keyring()
        self._service = service_name

    def store_vault(self, vault_contents: str) -> None:
        """Store the full vault contents in the keychain.

        Args:
            vault_contents: The complete vault file contents (encrypted).

        Raises:
            KeychainError: If the keychain write operation fails.
        """
        try:
            self._keyring.set_password(self._service, _VAULT_KEY, vault_contents)
        except Exception as e:
            raise KeychainError(f"Failed to store vault in keychain: {e}") from e

    def load_vault(self) -> str | None:
        """Load the full vault contents from the keychain.

        Returns:
            The vault contents string, or None if no vault is stored.

        Raises:
            KeychainError: If the keychain read operation fails.
        """
        try:
            result = self._keyring.get_password(self._service, _VAULT_KEY)
            return result
        except Exception as e:
            raise KeychainError(f"Failed to load vault from keychain: {e}") from e

    def delete_vault(self) -> None:
        """Delete the vault from the keychain.

        Raises:
            KeychainError: If the keychain delete operation fails.
        """
        try:
            self._keyring.delete_password(self._service, _VAULT_KEY)
        except self._keyring.errors.PasswordDeleteError:
            pass  # Already deleted or doesn't exist
        except Exception as e:
            raise KeychainError(f"Failed to delete vault from keychain: {e}") from e

    def vault_exists(self) -> bool:
        """Check if a vault entry exists in the keychain.

        Returns:
            True if vault data exists in the keychain.
        """
        try:
            return self.load_vault() is not None
        except KeychainError:
            return False

    def store_metadata(self, metadata: dict) -> None:
        """Store vault metadata (e.g., creation date, backend info).

        Args:
            metadata: Dictionary of metadata to store.
        """
        try:
            self._keyring.set_password(
                self._service, "__ssc_metadata__", json.dumps(metadata)
            )
        except Exception:
            pass  # Metadata storage is best-effort

    def load_metadata(self) -> dict:
        """Load vault metadata from keychain.

        Returns:
            Dictionary of metadata, or empty dict if not found.
        """
        try:
            data = self._keyring.get_password(self._service, "__ssc_metadata__")
            if data:
                return json.loads(data)
        except Exception:
            pass
        return {}
