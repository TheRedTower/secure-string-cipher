"""Unit tests for keychain backend module."""

from unittest.mock import MagicMock, patch

import pytest

from secure_string_cipher.keychain_backend import (
    _SERVICE_NAME,
    _VAULT_KEY,
    KeychainError,
    KeychainUnavailableError,
    KeychainVaultBackend,
    _get_keyring,
    get_keychain_backend_name,
    is_keychain_available,
)


class TestIsKeychainAvailable:
    """Tests for is_keychain_available()."""

    def test_returns_false_when_keyring_not_installed(self):
        with patch.dict("sys.modules", {"keyring": None, "keyring.errors": None}):
            # Force reimport
            with patch(
                "secure_string_cipher.keychain_backend._get_keyring",
                side_effect=KeychainUnavailableError("not installed"),
            ):
                assert is_keychain_available() is False

    def test_returns_true_when_keyring_available(self):
        mock_keyring = MagicMock()
        mock_keyring.get_keyring.return_value = MagicMock(
            __class__=type("MacOSKeyring", (), {})
        )
        with patch(
            "secure_string_cipher.keychain_backend._get_keyring",
            return_value=mock_keyring,
        ):
            assert is_keychain_available() is True

    def test_returns_false_when_fail_backend(self):
        with patch(
            "secure_string_cipher.keychain_backend._get_keyring",
            side_effect=KeychainUnavailableError("no backend"),
        ):
            assert is_keychain_available() is False


class TestGetKeychainBackendName:
    """Tests for get_keychain_backend_name()."""

    def test_returns_backend_name(self):
        mock_keyring = MagicMock()

        class MacOSKeyring:
            pass

        mock_keyring.get_keyring.return_value = MacOSKeyring()
        with patch(
            "secure_string_cipher.keychain_backend._get_keyring",
            return_value=mock_keyring,
        ):
            assert get_keychain_backend_name() == "MacOSKeyring"

    def test_raises_when_unavailable(self):
        with patch(
            "secure_string_cipher.keychain_backend._get_keyring",
            side_effect=KeychainUnavailableError("not installed"),
        ):
            with pytest.raises(KeychainUnavailableError):
                get_keychain_backend_name()


class TestGetKeyring:
    """Tests for keyring loading and unavailable guidance."""

    def test_missing_keyring_error_includes_pipx_and_quoted_pip_help(self):
        with patch.dict("sys.modules", {"keyring": None, "keyring.errors": None}):
            with pytest.raises(KeychainUnavailableError) as exc_info:
                _get_keyring()

        message = str(exc_info.value)
        assert "pipx inject secure-string-cipher keyring" in message
        assert "python -m pip install 'secure-string-cipher[keychain]'" in message
        assert "pip install secure-string-cipher[keychain]" not in message


class TestKeychainVaultBackend:
    """Tests for KeychainVaultBackend class."""

    @pytest.fixture
    def mock_keyring(self):
        """Create a mock keyring module."""
        mock = MagicMock()
        mock.get_keyring.return_value = MagicMock(__class__=type("TestKeyring", (), {}))
        mock.errors = MagicMock()
        mock.errors.PasswordDeleteError = type("PasswordDeleteError", (Exception,), {})
        return mock

    @pytest.fixture
    def backend(self, mock_keyring):
        """Create a KeychainVaultBackend with mocked keyring."""
        with patch(
            "secure_string_cipher.keychain_backend._get_keyring",
            return_value=mock_keyring,
        ):
            return KeychainVaultBackend()

    def test_store_vault(self, backend, mock_keyring):
        backend.store_vault("vault_contents_here")
        mock_keyring.set_password.assert_called_once_with(
            _SERVICE_NAME, _VAULT_KEY, "vault_contents_here"
        )

    def test_store_vault_failure(self, backend, mock_keyring):
        mock_keyring.set_password.side_effect = Exception("access denied")
        with pytest.raises(KeychainError, match="Failed to store"):
            backend.store_vault("data")

    def test_load_vault(self, backend, mock_keyring):
        mock_keyring.get_password.return_value = "stored_data"
        result = backend.load_vault()
        assert result == "stored_data"
        mock_keyring.get_password.assert_called_once_with(_SERVICE_NAME, _VAULT_KEY)

    def test_load_vault_not_found(self, backend, mock_keyring):
        mock_keyring.get_password.return_value = None
        result = backend.load_vault()
        assert result is None

    def test_load_vault_failure(self, backend, mock_keyring):
        mock_keyring.get_password.side_effect = Exception("access denied")
        with pytest.raises(KeychainError, match="Failed to load"):
            backend.load_vault()

    def test_delete_vault(self, backend, mock_keyring):
        backend.delete_vault()
        mock_keyring.delete_password.assert_called_once_with(_SERVICE_NAME, _VAULT_KEY)

    def test_delete_vault_already_gone(self, backend, mock_keyring):
        mock_keyring.delete_password.side_effect = (
            mock_keyring.errors.PasswordDeleteError("not found")
        )
        # Should not raise
        backend.delete_vault()

    def test_vault_exists_true(self, backend, mock_keyring):
        mock_keyring.get_password.return_value = "data"
        assert backend.vault_exists() is True

    def test_vault_exists_false(self, backend, mock_keyring):
        mock_keyring.get_password.return_value = None
        assert backend.vault_exists() is False

    def test_vault_exists_error(self, backend, mock_keyring):
        mock_keyring.get_password.side_effect = Exception("err")
        assert backend.vault_exists() is False

    def test_store_metadata(self, backend, mock_keyring):
        backend.store_metadata({"created": "2025-01-01"})
        mock_keyring.set_password.assert_called_once()

    def test_load_metadata_found(self, backend, mock_keyring):
        mock_keyring.get_password.return_value = '{"created": "2025-01-01"}'
        result = backend.load_metadata()
        assert result == {"created": "2025-01-01"}

    def test_load_metadata_not_found(self, backend, mock_keyring):
        mock_keyring.get_password.return_value = None
        result = backend.load_metadata()
        assert result == {}


class TestPassphraseVaultKeychainBackend:
    """Tests for PassphraseVault with keychain backend."""

    @pytest.fixture
    def mock_keyring(self):
        """Create a mock keyring with storage."""
        mock = MagicMock()
        mock.get_keyring.return_value = MagicMock(__class__=type("TestKeyring", (), {}))
        mock.errors = MagicMock()
        mock.errors.PasswordDeleteError = type("PasswordDeleteError", (Exception,), {})
        # Simulated storage
        storage = {}

        def set_password(service, key, value):
            storage[(service, key)] = value

        def get_password(service, key):
            return storage.get((service, key))

        def delete_password(service, key):
            if (service, key) not in storage:
                raise mock.errors.PasswordDeleteError("not found")
            del storage[(service, key)]

        mock.set_password = set_password
        mock.get_password = get_password
        mock.delete_password = delete_password
        return mock

    @pytest.fixture
    def vault(self, mock_keyring, tmp_path):
        """Create a PassphraseVault with keychain backend."""
        from secure_string_cipher.passphrase_manager import PassphraseVault

        with patch(
            "secure_string_cipher.keychain_backend._get_keyring",
            return_value=mock_keyring,
        ):
            return PassphraseVault(
                vault_path=str(tmp_path / "vault.enc"), backend="keychain"
            )

    def test_backend_property(self, vault):
        assert vault.backend == "keychain"

    def test_store_and_retrieve(self, vault):
        vault.store_passphrase("test-label", "secret123", "MasterPass123!@#")
        result = vault.retrieve_passphrase("test-label", "MasterPass123!@#")
        assert result == "secret123"

    def test_vault_exists_after_store(self, vault):
        assert vault.vault_exists() is False
        vault.store_passphrase("test-label", "secret123", "MasterPass123!@#")
        assert vault.vault_exists() is True

    def test_list_labels(self, vault):
        vault.store_passphrase("label-a", "pass1", "MasterPass123!@#")
        vault.store_passphrase("label-b", "pass2", "MasterPass123!@#")
        labels = vault.list_labels("MasterPass123!@#")
        assert "label-a" in labels
        assert "label-b" in labels

    def test_delete_passphrase(self, vault):
        vault.store_passphrase("to-delete", "pass", "MasterPass123!@#")
        vault.delete_passphrase("to-delete", "MasterPass123!@#")
        with pytest.raises(ValueError, match="not found"):
            vault.retrieve_passphrase("to-delete", "MasterPass123!@#")

    def test_get_vault_path_keychain(self, vault):
        assert vault.get_vault_path() == "OS Keychain"

    def test_invalid_backend_raises(self, tmp_path):
        from secure_string_cipher.passphrase_manager import PassphraseVault

        with pytest.raises(ValueError, match="Unknown backend"):
            PassphraseVault(vault_path=str(tmp_path / "v.enc"), backend="invalid")
