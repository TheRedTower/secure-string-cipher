"""Tests for runtime vault configuration."""

from unittest.mock import MagicMock, patch

from secure_string_cipher.config import (
    load_vault_settings,
    set_vault_backend,
)
from secure_string_cipher.passphrase_manager import PassphraseVault


def test_vault_settings_env_overrides(monkeypatch, tmp_path):
    vault_path = tmp_path / "env_vault.enc"
    backup_dir = tmp_path / "env_backups"

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CIPHER_VAULT_PATH", str(vault_path))
    monkeypatch.setenv("CIPHER_BACKUP_DIR", str(backup_dir))
    monkeypatch.setenv("CIPHER_VAULT_BACKEND", "file")

    settings = load_vault_settings()
    vault = PassphraseVault()

    assert settings.vault_path == str(vault_path)
    assert settings.backup_dir == str(backup_dir)
    assert vault.vault_path == vault_path
    assert vault.backup_dir == backup_dir


def test_set_vault_backend_persists_for_default_vault(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))

    settings = set_vault_backend("file")
    vault = PassphraseVault()

    assert settings.vault_backend == "file"
    assert vault.backend == "file"
    assert load_vault_settings().vault_backend == "file"


def test_default_vault_prefers_keychain_when_available(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("CIPHER_VAULT_BACKEND", raising=False)

    with patch(
        "secure_string_cipher.keychain_backend.is_keychain_available",
        return_value=True,
    ):
        settings = load_vault_settings()

    assert settings.vault_backend == "keychain"


def test_default_vault_uses_persisted_keychain_backend(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("CIPHER_VAULT_BACKEND", raising=False)
    set_vault_backend("keychain")

    mock_keyring = MagicMock()
    mock_keyring.get_keyring.return_value = MagicMock(
        __class__=type("TestKeyring", (), {})
    )
    mock_keyring.errors = MagicMock()
    mock_keyring.errors.PasswordDeleteError = type(
        "PasswordDeleteError", (Exception,), {}
    )

    with patch(
        "secure_string_cipher.keychain_backend._get_keyring",
        return_value=mock_keyring,
    ):
        vault = PassphraseVault()

    assert vault.backend == "keychain"
    assert vault.get_vault_path() == "OS Keychain"
