"""
Unit tests to increase coverage for cli_args.py.

Covers:
- _prompt_password_with_validation
- _get_vault initialization flow
- _get_password_from_vault
- _get_password_from_key_file
- _load_file_metadata
- _determine_output_path
- _validate_vault_format
- cmd_decrypt paths
- cmd_store
- cmd_vault_list, cmd_vault_delete, cmd_vault_export
- cmd_vault_import, cmd_vault_reset, cmd_vault_migrate
- cmd_shred
"""

from __future__ import annotations

import argparse
from unittest.mock import MagicMock, patch

import pytest

from secure_string_cipher.cli_args import (
    EXIT_AUTH_ERROR,
    EXIT_FILE_ERROR,
    EXIT_INPUT_ERROR,
    EXIT_SUCCESS,
    EXIT_VAULT_ERROR,
    _get_password_from_key_file,
    _validate_vault_format,
    cmd_decrypt,
    cmd_encrypt,
    cmd_shred,
    cmd_store,
    cmd_vault_delete,
    cmd_vault_export,
    cmd_vault_import,
    cmd_vault_list,
    cmd_vault_migrate,
    cmd_vault_reset,
)
from secure_string_cipher.core import CryptoError, encrypt_file, encrypt_text

# =============================================================================
# _validate_vault_format
# =============================================================================


class TestValidateVaultFormat:
    """Tests for vault format validation."""

    def test_valid_format(self):
        """Should accept valid vault format."""
        content = (
            "SSCVAULT\nabcdef01\n---DATA---\nencrypted_data\n---HMAC---\nhmac_value"
        )
        assert _validate_vault_format(content) is True

    def test_too_few_lines(self):
        """Should reject content with too few lines."""
        content = "SSCVAULT\ndata"
        assert _validate_vault_format(content) is False

    def test_missing_header(self):
        """Should reject content without SSCVAULT header."""
        content = "INVALID\nabcdef01\n---DATA---\ndata\n---HMAC---\nhmac"
        assert _validate_vault_format(content) is False

    def test_missing_data_separator(self):
        """Should reject content without ---DATA--- separator."""
        content = "SSCVAULT\nabcdef01\nNOSEP\ndata\n---HMAC---\nhmac"
        assert _validate_vault_format(content) is False

    def test_missing_hmac_separator(self):
        """Should reject content without ---HMAC--- separator."""
        content = "SSCVAULT\nabcdef01\n---DATA---\ndata\nno_hmac\nvalue"
        assert _validate_vault_format(content) is False

    def test_invalid_hex_salt(self):
        """Should reject content with non-hex salt."""
        content = "SSCVAULT\nNOT_HEX_$$$\n---DATA---\ndata\n---HMAC---\nhmac"
        assert _validate_vault_format(content) is False


# =============================================================================
# _get_password_from_key_file
# =============================================================================


class TestGetPasswordFromKeyFile:
    """Tests for key file password derivation."""

    def test_key_file_success(self, tmp_path):
        """Should derive password from key file."""
        key_file = tmp_path / "test.key"
        key_file.write_bytes(b"secret key content")

        result = _get_password_from_key_file(str(key_file))

        from hashlib import sha256

        expected = sha256(b"secret key content").hexdigest()
        assert result == expected

    def test_key_file_not_found(self):
        """Should exit with error for missing key file."""
        with pytest.raises(SystemExit) as exc_info:
            _get_password_from_key_file("/nonexistent/key.file")
        assert exc_info.value.code == EXIT_FILE_ERROR

    def test_key_file_empty(self, tmp_path):
        """Should exit with error for empty key file."""
        key_file = tmp_path / "empty.key"
        key_file.write_bytes(b"")

        with pytest.raises(SystemExit) as exc_info:
            _get_password_from_key_file(str(key_file))
        assert exc_info.value.code == EXIT_FILE_ERROR


# =============================================================================
# cmd_encrypt additional paths
# =============================================================================


class TestCmdEncryptPaths:
    """Additional tests for cmd_encrypt."""

    @patch("secure_string_cipher.cli_args._prompt_password")
    def test_encrypt_text_success(self, mock_prompt, capsys):
        """Should encrypt text successfully."""
        mock_prompt.return_value = "StrongPass1!@#ab"
        args = argparse.Namespace(
            text="hello world",
            file=None,
            vault=None,
            key_file=None,
            force=False,
        )
        result = cmd_encrypt(args)
        assert result == EXIT_SUCCESS

    def test_encrypt_no_input(self):
        """Should exit on no text or file."""
        args = argparse.Namespace(
            text=None,
            file=None,
            vault=None,
            key_file=None,
            force=False,
        )
        with pytest.raises(SystemExit) as exc_info:
            cmd_encrypt(args)
        assert exc_info.value.code == EXIT_INPUT_ERROR

    def test_encrypt_both_text_and_file(self):
        """Should exit when both text and file specified."""
        args = argparse.Namespace(
            text="hello",
            file="file.txt",
            vault=None,
            key_file=None,
            force=False,
        )
        with pytest.raises(SystemExit) as exc_info:
            cmd_encrypt(args)
        assert exc_info.value.code == EXIT_INPUT_ERROR

    def test_encrypt_vault_and_key_file(self):
        """Should exit when both vault and key-file specified."""
        args = argparse.Namespace(
            text="hello",
            file=None,
            vault="label",
            key_file="/some/key",
            force=False,
        )
        with pytest.raises(SystemExit) as exc_info:
            cmd_encrypt(args)
        assert exc_info.value.code == EXIT_INPUT_ERROR

    def test_encrypt_file_not_found(self):
        """Should exit on missing file."""
        args = argparse.Namespace(
            text=None,
            file="/nonexistent/file.txt",
            vault=None,
            key_file=None,
            force=False,
        )
        with pytest.raises(SystemExit) as exc_info:
            cmd_encrypt(args)
        assert exc_info.value.code == EXIT_FILE_ERROR

    @patch("secure_string_cipher.cli_args._prompt_password")
    def test_encrypt_file_exists_no_force(self, mock_prompt, tmp_path):
        """Should exit when output exists and no --force."""
        mock_prompt.return_value = "StrongPass1!@#ab"
        source = tmp_path / "file.txt"
        source.write_text("data")
        output = tmp_path / "file.txt.enc"
        output.write_text("existing")

        args = argparse.Namespace(
            text=None,
            file=str(source),
            vault=None,
            key_file=None,
            force=False,
        )
        with pytest.raises(SystemExit) as exc_info:
            cmd_encrypt(args)
        assert exc_info.value.code == EXIT_FILE_ERROR

    @patch("secure_string_cipher.cli_args._prompt_password")
    def test_encrypt_file_success(self, mock_prompt, tmp_path):
        """Should encrypt file successfully."""
        mock_prompt.return_value = "StrongPass1!@#ab"
        source = tmp_path / "file.txt"
        source.write_text("data")

        args = argparse.Namespace(
            text=None,
            file=str(source),
            vault=None,
            key_file=None,
            force=False,
        )
        result = cmd_encrypt(args)
        assert result == EXIT_SUCCESS
        assert (tmp_path / "file.txt.enc").exists()

    @patch("secure_string_cipher.cli_args._prompt_password")
    def test_encrypt_file_force_overwrite(self, mock_prompt, tmp_path):
        """Should overwrite with --force."""
        mock_prompt.return_value = "StrongPass1!@#ab"
        source = tmp_path / "file.txt"
        source.write_text("data")
        output = tmp_path / "file.txt.enc"
        output.write_text("old")

        args = argparse.Namespace(
            text=None,
            file=str(source),
            vault=None,
            key_file=None,
            force=True,
        )
        result = cmd_encrypt(args)
        assert result == EXIT_SUCCESS

    def test_encrypt_with_key_file(self, tmp_path):
        """Should encrypt using key file."""
        key_file = tmp_path / "test.key"
        key_file.write_bytes(b"secret key data content here!")

        args = argparse.Namespace(
            text="hello world",
            file=None,
            vault=None,
            key_file=str(key_file),
            force=False,
        )
        result = cmd_encrypt(args)
        assert result == EXIT_SUCCESS


# =============================================================================
# cmd_decrypt paths
# =============================================================================


class TestCmdDecryptPaths:
    """Tests for cmd_decrypt."""

    def test_decrypt_no_input(self):
        """Should exit on no text or file."""
        args = argparse.Namespace(
            text=None,
            file=None,
            vault=None,
            key_file=None,
            force=False,
            output=None,
            restore_filename=True,
        )
        with pytest.raises(SystemExit) as exc_info:
            cmd_decrypt(args)
        assert exc_info.value.code == EXIT_INPUT_ERROR

    def test_decrypt_both_text_and_file(self):
        """Should exit when both specified."""
        args = argparse.Namespace(
            text="data",
            file="file.txt",
            vault=None,
            key_file=None,
            force=False,
            output=None,
            restore_filename=True,
        )
        with pytest.raises(SystemExit) as exc_info:
            cmd_decrypt(args)
        assert exc_info.value.code == EXIT_INPUT_ERROR

    def test_decrypt_vault_and_key_file(self):
        """Should exit when both vault and key-file specified."""
        args = argparse.Namespace(
            text="data",
            file=None,
            vault="label",
            key_file="/some/key",
            force=False,
            output=None,
            restore_filename=True,
        )
        with pytest.raises(SystemExit) as exc_info:
            cmd_decrypt(args)
        assert exc_info.value.code == EXIT_INPUT_ERROR

    def test_decrypt_file_not_found(self):
        """Should exit on missing file."""
        args = argparse.Namespace(
            text=None,
            file="/nonexistent/file.enc",
            vault=None,
            key_file=None,
            force=False,
            output=None,
            restore_filename=True,
        )
        with pytest.raises(SystemExit) as exc_info:
            cmd_decrypt(args)
        assert exc_info.value.code == EXIT_FILE_ERROR

    @patch("secure_string_cipher.cli_args._prompt_password")
    def test_decrypt_text_success(self, mock_prompt):
        """Should decrypt text successfully."""
        mock_prompt.return_value = "StrongPass1!@#ab"
        ciphertext = encrypt_text("hello world", "StrongPass1!@#ab")

        args = argparse.Namespace(
            text=ciphertext,
            file=None,
            vault=None,
            key_file=None,
            force=False,
            output=None,
            restore_filename=True,
        )
        result = cmd_decrypt(args)
        assert result == EXIT_SUCCESS

    @patch("secure_string_cipher.cli_args._prompt_password")
    def test_decrypt_text_wrong_password(self, mock_prompt):
        """Should exit on wrong password."""
        mock_prompt.return_value = "WrongPass1!@#xyz"
        ciphertext = encrypt_text("hello world", "StrongPass1!@#ab")

        args = argparse.Namespace(
            text=ciphertext,
            file=None,
            vault=None,
            key_file=None,
            force=False,
            output=None,
            restore_filename=True,
        )
        with pytest.raises(SystemExit) as exc_info:
            cmd_decrypt(args)
        assert exc_info.value.code == EXIT_AUTH_ERROR

    @patch("secure_string_cipher.cli_args._prompt_password")
    def test_decrypt_file_success(self, mock_prompt, tmp_path):
        """Should decrypt file successfully."""
        mock_prompt.return_value = "StrongPass1!@#ab"

        source = tmp_path / "test.txt"
        source.write_text("secret data")
        enc_file = tmp_path / "test.txt.enc"
        encrypt_file(str(source), str(enc_file), "StrongPass1!@#ab")

        args = argparse.Namespace(
            text=None,
            file=str(enc_file),
            vault=None,
            key_file=None,
            force=False,
            output=None,
            restore_filename=False,
        )
        result = cmd_decrypt(args)
        assert result == EXIT_SUCCESS

    @patch("secure_string_cipher.cli_args._prompt_password")
    def test_decrypt_file_wrong_password(self, mock_prompt, tmp_path):
        """Should exit on wrong password for file."""
        mock_prompt.return_value = "WrongPass1!@#xyz"

        source = tmp_path / "test.txt"
        source.write_text("secret data")
        enc_file = tmp_path / "test.txt.enc"
        encrypt_file(str(source), str(enc_file), "StrongPass1!@#ab")

        args = argparse.Namespace(
            text=None,
            file=str(enc_file),
            vault=None,
            key_file=None,
            force=False,
            output=None,
            restore_filename=False,
        )
        with pytest.raises(SystemExit) as exc_info:
            cmd_decrypt(args)
        assert exc_info.value.code == EXIT_AUTH_ERROR

    @patch("secure_string_cipher.cli_args._prompt_password")
    def test_decrypt_file_output_exists_no_force(self, mock_prompt, tmp_path):
        """Should exit when output file exists without --force."""
        mock_prompt.return_value = "StrongPass1!@#ab"

        source = tmp_path / "test.txt"
        source.write_text("secret data")
        enc_file = tmp_path / "test.txt.enc"
        encrypt_file(str(source), str(enc_file), "StrongPass1!@#ab")

        # Create the expected output file
        dec_file = tmp_path / "test.txt.dec"
        dec_file.write_text("existing")

        args = argparse.Namespace(
            text=None,
            file=str(enc_file),
            vault=None,
            key_file=None,
            force=False,
            output=None,
            restore_filename=False,
        )
        with pytest.raises(SystemExit) as exc_info:
            cmd_decrypt(args)
        assert exc_info.value.code == EXIT_FILE_ERROR

    def test_decrypt_with_key_file(self, tmp_path):
        """Should decrypt using key file."""
        from hashlib import sha256

        key_file = tmp_path / "test.key"
        key_data = b"secret key data content here!"
        key_file.write_bytes(key_data)
        password = sha256(key_data).hexdigest()

        ciphertext = encrypt_text("hello world", password)

        args = argparse.Namespace(
            text=ciphertext,
            file=None,
            vault=None,
            key_file=str(key_file),
            force=False,
            output=None,
            restore_filename=True,
        )
        result = cmd_decrypt(args)
        assert result == EXIT_SUCCESS


# =============================================================================
# cmd_store
# =============================================================================


class TestCmdStore:
    """Tests for cmd_store."""

    @patch("secure_string_cipher.cli_args._prompt_master_password")
    @patch("secure_string_cipher.cli_args._prompt_password_with_validation")
    @patch("secure_string_cipher.cli_args._get_vault")
    def test_store_manual(self, mock_get_vault, mock_prompt_pw, mock_prompt_master):
        """Should store manually entered password."""
        mock_vault = MagicMock()
        mock_get_vault.return_value = mock_vault
        mock_prompt_pw.return_value = "MyPassword123!@#"
        mock_prompt_master.return_value = "MasterPw123!@#"

        args = argparse.Namespace(label="my-label", generate=False)
        result = cmd_store(args)

        assert result == EXIT_SUCCESS
        mock_vault.store_passphrase.assert_called_once_with(
            "my-label", "MyPassword123!@#", "MasterPw123!@#"
        )

    @patch("secure_string_cipher.cli_args._prompt_master_password")
    @patch("secure_string_cipher.cli_args._get_vault")
    def test_store_generate(self, mock_get_vault, mock_prompt_master):
        """Should store generated password."""
        mock_vault = MagicMock()
        mock_get_vault.return_value = mock_vault
        mock_prompt_master.return_value = "MasterPw123!@#"

        args = argparse.Namespace(label="gen-label", generate=True)
        result = cmd_store(args)

        assert result == EXIT_SUCCESS
        mock_vault.store_passphrase.assert_called_once()

    @patch("secure_string_cipher.cli_args._prompt_master_password")
    @patch("secure_string_cipher.cli_args._get_vault")
    def test_store_crypto_error(self, mock_get_vault, mock_prompt_master):
        """Should exit on wrong master password."""
        mock_vault = MagicMock()
        mock_get_vault.return_value = mock_vault
        mock_prompt_master.return_value = "wrong"
        mock_vault.store_passphrase.side_effect = CryptoError("auth failed")

        args = argparse.Namespace(label="label", generate=True)
        with pytest.raises(SystemExit) as exc_info:
            cmd_store(args)
        assert exc_info.value.code == EXIT_AUTH_ERROR


# =============================================================================
# cmd_vault_list
# =============================================================================


class TestCmdVaultList:
    """Tests for cmd_vault_list."""

    @patch("secure_string_cipher.cli_args._prompt_master_password")
    @patch("secure_string_cipher.cli_args._get_vault")
    def test_list_success(self, mock_get_vault, mock_prompt_master, capsys):
        """Should list vault entries."""
        mock_vault = MagicMock()
        mock_get_vault.return_value = mock_vault
        mock_prompt_master.return_value = "master"
        mock_vault.list_labels.return_value = ["label-a", "label-b"]

        args = argparse.Namespace()
        result = cmd_vault_list(args)

        assert result == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "label-a" in captured.out
        assert "label-b" in captured.out

    @patch("secure_string_cipher.cli_args._prompt_master_password")
    @patch("secure_string_cipher.cli_args._get_vault")
    def test_list_empty(self, mock_get_vault, mock_prompt_master, capsys):
        """Should show empty message."""
        mock_vault = MagicMock()
        mock_get_vault.return_value = mock_vault
        mock_prompt_master.return_value = "master"
        mock_vault.list_labels.return_value = []

        args = argparse.Namespace()
        result = cmd_vault_list(args)

        assert result == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "empty" in captured.out.lower()

    @patch("secure_string_cipher.cli_args._prompt_master_password")
    @patch("secure_string_cipher.cli_args._get_vault")
    def test_list_wrong_password(self, mock_get_vault, mock_prompt_master):
        """Should exit on wrong password."""
        mock_vault = MagicMock()
        mock_get_vault.return_value = mock_vault
        mock_prompt_master.return_value = "wrong"
        mock_vault.list_labels.side_effect = CryptoError("auth failed")

        args = argparse.Namespace()
        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_list(args)
        assert exc_info.value.code == EXIT_AUTH_ERROR


# =============================================================================
# cmd_vault_delete
# =============================================================================


class TestCmdVaultDelete:
    """Tests for cmd_vault_delete."""

    @patch("secure_string_cipher.cli_args._prompt_master_password")
    @patch("secure_string_cipher.cli_args._get_vault")
    def test_delete_success(self, mock_get_vault, mock_prompt_master):
        """Should delete vault entry."""
        mock_vault = MagicMock()
        mock_get_vault.return_value = mock_vault
        mock_prompt_master.return_value = "master"

        args = argparse.Namespace(label="my-label")
        result = cmd_vault_delete(args)

        assert result == EXIT_SUCCESS
        mock_vault.delete_passphrase.assert_called_once()

    @patch("secure_string_cipher.cli_args._prompt_master_password")
    @patch("secure_string_cipher.cli_args._get_vault")
    def test_delete_not_found(self, mock_get_vault, mock_prompt_master):
        """Should exit when label not found."""
        mock_vault = MagicMock()
        mock_get_vault.return_value = mock_vault
        mock_prompt_master.return_value = "master"
        mock_vault.delete_passphrase.side_effect = KeyError("not found")

        args = argparse.Namespace(label="missing")
        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_delete(args)
        assert exc_info.value.code == EXIT_VAULT_ERROR

    @patch("secure_string_cipher.cli_args._prompt_master_password")
    @patch("secure_string_cipher.cli_args._get_vault")
    def test_delete_wrong_password(self, mock_get_vault, mock_prompt_master):
        """Should exit on wrong password."""
        mock_vault = MagicMock()
        mock_get_vault.return_value = mock_vault
        mock_prompt_master.return_value = "wrong"
        mock_vault.delete_passphrase.side_effect = CryptoError("auth")

        args = argparse.Namespace(label="label")
        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_delete(args)
        assert exc_info.value.code == EXIT_AUTH_ERROR


# =============================================================================
# cmd_vault_export
# =============================================================================


class TestCmdVaultExport:
    """Tests for cmd_vault_export."""

    @patch("secure_string_cipher.cli_args._prompt_master_password")
    @patch("secure_string_cipher.cli_args._get_vault")
    def test_export_success(self, mock_get_vault, mock_prompt_master, tmp_path, capsys):
        """Should export vault content."""
        mock_vault = MagicMock()
        mock_get_vault.return_value = mock_vault
        mock_prompt_master.return_value = "master"
        mock_vault.list_labels.return_value = ["label1"]
        vault_file = tmp_path / "vault.dat"
        vault_file.write_text("SSCVAULT\ndata")
        mock_vault.vault_path = vault_file

        args = argparse.Namespace()
        result = cmd_vault_export(args)

        assert result == EXIT_SUCCESS

    @patch("secure_string_cipher.cli_args._prompt_master_password")
    @patch("secure_string_cipher.cli_args._get_vault")
    def test_export_wrong_password(self, mock_get_vault, mock_prompt_master):
        """Should exit on wrong password."""
        mock_vault = MagicMock()
        mock_get_vault.return_value = mock_vault
        mock_prompt_master.return_value = "wrong"
        mock_vault.list_labels.side_effect = CryptoError("auth")

        args = argparse.Namespace()
        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_export(args)
        assert exc_info.value.code == EXIT_AUTH_ERROR


# =============================================================================
# cmd_vault_import
# =============================================================================


class TestCmdVaultImport:
    """Tests for cmd_vault_import."""

    def test_import_file_not_found(self):
        """Should exit when import file missing."""
        args = argparse.Namespace(file="/nonexistent/vault.bak")
        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_import(args)
        assert exc_info.value.code == EXIT_FILE_ERROR

    def test_import_invalid_format(self, tmp_path):
        """Should exit on invalid vault format."""
        bad_file = tmp_path / "bad.vault"
        bad_file.write_text("not a valid vault")

        args = argparse.Namespace(file=str(bad_file))
        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_import(args)
        assert exc_info.value.code == EXIT_FILE_ERROR

    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_import_success_no_existing(self, mock_vault_cls, tmp_path):
        """Should import vault when no existing vault."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        vault_path = tmp_path / "vault.dat"
        mock_vault.vault_path = vault_path

        import_file = tmp_path / "backup.vault"
        import_file.write_text(
            "SSCVAULT\nabcdef01\n---DATA---\nencrypted\npayload\n---HMAC---\nhmac_val"
        )

        args = argparse.Namespace(file=str(import_file))
        result = cmd_vault_import(args)

        assert result == EXIT_SUCCESS


# =============================================================================
# cmd_vault_reset
# =============================================================================


class TestCmdVaultReset:
    """Tests for cmd_vault_reset."""

    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_reset_no_vault(self, mock_vault_cls):
        """Should exit when vault doesn't exist."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_path = MagicMock()
        mock_vault.vault_path.exists.return_value = False

        args = argparse.Namespace()
        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_reset(args)
        assert exc_info.value.code == EXIT_VAULT_ERROR

    @patch("builtins.input", return_value="nope")
    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_reset_cancelled(self, mock_vault_cls, mock_input):
        """Should exit when user doesn't type RESET."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_path = MagicMock()
        mock_vault.vault_path.exists.return_value = True

        args = argparse.Namespace()
        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_reset(args)
        assert exc_info.value.code == EXIT_INPUT_ERROR

    @patch("builtins.input", return_value="RESET")
    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_reset_confirmed(self, mock_vault_cls, mock_input):
        """Should delete vault on RESET confirmation."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_path = MagicMock()
        mock_vault.vault_path.exists.return_value = True

        args = argparse.Namespace()
        result = cmd_vault_reset(args)

        assert result == EXIT_SUCCESS
        mock_vault.vault_path.unlink.assert_called_once()


# =============================================================================
# cmd_vault_migrate
# =============================================================================


class TestCmdVaultMigrate:
    """Tests for cmd_vault_migrate."""

    @patch("secure_string_cipher.cli_args._prompt_master_password")
    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_migrate_to_file(self, mock_vault_cls, mock_prompt_master):
        """Should migrate to file backend."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_prompt_master.return_value = "master"
        mock_vault.vault_path = MagicMock()

        args = argparse.Namespace(target_backend="file")
        result = cmd_vault_migrate(args)

        assert result == EXIT_SUCCESS
        mock_vault.migrate_to_file.assert_called_once()

    @patch("secure_string_cipher.cli_args._prompt_master_password")
    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_migrate_to_keychain(self, mock_vault_cls, mock_prompt_master):
        """Should migrate to keychain backend."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_prompt_master.return_value = "master"

        args = argparse.Namespace(target_backend="keychain")
        result = cmd_vault_migrate(args)

        assert result == EXIT_SUCCESS
        mock_vault.migrate_to_keychain.assert_called_once()

    @patch("secure_string_cipher.cli_args._prompt_master_password")
    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_migrate_value_error(self, mock_vault_cls, mock_prompt_master):
        """Should exit on ValueError."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_prompt_master.return_value = "master"
        mock_vault.migrate_to_keychain.side_effect = ValueError("wrong password")

        args = argparse.Namespace(target_backend="keychain")
        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_migrate(args)
        assert exc_info.value.code == EXIT_AUTH_ERROR


# =============================================================================
# cmd_shred
# =============================================================================


class TestCmdShred:
    """Tests for cmd_shred."""

    def test_shred_file_not_found(self):
        """Should exit when file doesn't exist."""
        args = argparse.Namespace(paths=["/nonexistent/file.txt"], force=True)
        with pytest.raises(SystemExit) as exc_info:
            cmd_shred(args)
        assert exc_info.value.code == EXIT_FILE_ERROR

    def test_shred_force_success(self, tmp_path):
        """Should shred file with --force."""
        test_file = tmp_path / "secret.txt"
        test_file.write_text("secret data")

        args = argparse.Namespace(paths=[str(test_file)], force=True)
        result = cmd_shred(args)

        assert result == EXIT_SUCCESS
        assert not test_file.exists()

    @patch("builtins.input", return_value="no")
    def test_shred_declined(self, mock_input, tmp_path):
        """Should skip file when user declines."""
        test_file = tmp_path / "secret.txt"
        test_file.write_text("secret data")

        args = argparse.Namespace(paths=[str(test_file)], force=False)
        result = cmd_shred(args)

        assert result == EXIT_SUCCESS
        assert test_file.exists()

    @patch("builtins.input", return_value="yes")
    def test_shred_confirmed(self, mock_input, tmp_path):
        """Should shred file when user confirms."""
        test_file = tmp_path / "secret.txt"
        test_file.write_text("secret data")

        args = argparse.Namespace(paths=[str(test_file)], force=False)
        result = cmd_shred(args)

        assert result == EXIT_SUCCESS
        assert not test_file.exists()


# =============================================================================
# _prompt_password_with_validation
# =============================================================================


class TestPromptPasswordWithValidation:
    """Tests for _prompt_password_with_validation."""

    @patch("getpass.getpass")
    def test_valid_first_try(self, mock_getpass):
        """Should accept valid password on first try."""
        from secure_string_cipher.cli_args import _prompt_password_with_validation

        mock_getpass.side_effect = ["StrongPass1!@#ab", "StrongPass1!@#ab"]
        result = _prompt_password_with_validation()
        assert result == "StrongPass1!@#ab"

    @patch("getpass.getpass")
    def test_weak_then_strong(self, mock_getpass):
        """Should reject weak then accept strong."""
        from secure_string_cipher.cli_args import _prompt_password_with_validation

        mock_getpass.side_effect = [
            "weak",  # Too weak
            "StrongPass1!@#ab",  # Strong
            "StrongPass1!@#ab",  # Confirm
        ]
        result = _prompt_password_with_validation()
        assert result == "StrongPass1!@#ab"

    @patch("getpass.getpass")
    def test_mismatch_then_match(self, mock_getpass):
        """Should retry on mismatch."""
        from secure_string_cipher.cli_args import _prompt_password_with_validation

        mock_getpass.side_effect = [
            "StrongPass1!@#ab",  # Strong
            "Mismatch1!@#xyz",  # Doesn't match
            "StrongPass1!@#ab",  # Strong again
            "StrongPass1!@#ab",  # Confirms
        ]
        result = _prompt_password_with_validation()
        assert result == "StrongPass1!@#ab"
