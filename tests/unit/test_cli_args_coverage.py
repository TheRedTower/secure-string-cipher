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
import io
import sys
from unittest.mock import MagicMock, patch

import pytest

import secure_string_cipher.cli_args as cli_args
from secure_string_cipher.core import (
    CryptoError,
    encrypt_bytes,
    encrypt_file,
    encrypt_text,
)

EXIT_AUTH_ERROR = cli_args.EXIT_AUTH_ERROR
EXIT_FILE_ERROR = cli_args.EXIT_FILE_ERROR
EXIT_INPUT_ERROR = cli_args.EXIT_INPUT_ERROR
EXIT_SUCCESS = cli_args.EXIT_SUCCESS
EXIT_VAULT_ERROR = cli_args.EXIT_VAULT_ERROR
_get_password_from_key_file = cli_args._get_password_from_key_file
_get_password_from_vault = cli_args._get_password_from_vault
_get_vault = cli_args._get_vault
_prompt_password_with_validation = cli_args._prompt_password_with_validation
_validate_vault_format = cli_args._validate_vault_format
cmd_decrypt = cli_args.cmd_decrypt
cmd_encrypt = cli_args.cmd_encrypt
cmd_shred = cli_args.cmd_shred
cmd_store = cli_args.cmd_store
cmd_vault_backend = cli_args.cmd_vault_backend
cmd_vault_backups = cli_args.cmd_vault_backups
cmd_vault_delete = cli_args.cmd_vault_delete
cmd_vault_export = cli_args.cmd_vault_export
cmd_vault_import = cli_args.cmd_vault_import
cmd_vault_list = cli_args.cmd_vault_list
cmd_vault_migrate = cli_args.cmd_vault_migrate
cmd_vault_reset = cli_args.cmd_vault_reset
cmd_vault_restore = cli_args.cmd_vault_restore
cmd_vault_status = cli_args.cmd_vault_status


class _BinaryInput:
    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)


class _BinaryOutput:
    def __init__(self):
        self.buffer = io.BytesIO()

    def isatty(self):
        return False


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

    def test_key_file_directory_rejected(self, tmp_path):
        """Should reject directories passed as key files."""
        key_dir = tmp_path / "key-dir"
        key_dir.mkdir()

        with pytest.raises(SystemExit) as exc_info:
            _get_password_from_key_file(str(key_dir))
        assert exc_info.value.code == EXIT_FILE_ERROR

    def test_key_file_too_large_rejected(self, tmp_path, monkeypatch):
        """Should reject key files above the shared max-size limit."""
        key_file = tmp_path / "large.key"
        key_file.write_bytes(b"12345")
        monkeypatch.setattr("secure_string_cipher.core.MAX_FILE_SIZE", 4)

        with pytest.raises(SystemExit) as exc_info:
            _get_password_from_key_file(str(key_file))
        assert exc_info.value.code == EXIT_FILE_ERROR


# =============================================================================
# vault helper flows
# =============================================================================


class TestVaultHelpers:
    """Tests for vault helper functions."""

    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_get_vault_returns_existing_vault(self, mock_vault_cls):
        """Should return existing vault without prompting."""
        mock_vault = MagicMock()
        mock_vault.vault_exists.return_value = True
        mock_vault_cls.return_value = mock_vault

        assert _get_vault() is mock_vault

    @patch("secure_string_cipher.cli_args._prompt_password_with_validation")
    @patch("builtins.input", return_value="y")
    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_get_vault_initializes_missing_vault(
        self, mock_vault_cls, mock_input, mock_prompt
    ):
        """Should initialize a missing vault when the user accepts."""
        mock_vault = MagicMock()
        mock_vault.vault_exists.return_value = False
        mock_vault_cls.return_value = mock_vault
        mock_prompt.return_value = "master"

        assert _get_vault() is mock_vault
        mock_vault.store_passphrase.assert_called_once_with(
            "__init__", "init", "master"
        )
        mock_vault.delete_passphrase.assert_called_once_with("__init__", "master")

    @patch("builtins.input", return_value="n")
    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_get_vault_exits_when_initialization_declined(
        self, mock_vault_cls, mock_input
    ):
        """Should exit when the missing vault initialization is declined."""
        mock_vault = MagicMock()
        mock_vault.vault_exists.return_value = False
        mock_vault_cls.return_value = mock_vault

        with pytest.raises(SystemExit) as exc_info:
            _get_vault()
        assert exc_info.value.code == EXIT_VAULT_ERROR

    @patch(
        "secure_string_cipher.cli_args._prompt_master_password", return_value="master"
    )
    @patch("secure_string_cipher.cli_args._get_vault")
    def test_get_password_from_vault_success(self, mock_get_vault, mock_prompt_master):
        """Should retrieve vault password and record a successful unlock."""
        mock_vault = MagicMock()
        mock_vault.vault_path = "vault.enc"
        mock_vault.retrieve_passphrase.return_value = "stored"
        mock_get_vault.return_value = mock_vault
        limiter = MagicMock()
        limiter.check_rate_limit.return_value = (True, 0)

        with patch("secure_string_cipher.cli_args._cli_limiter", limiter):
            assert _get_password_from_vault("label") == "stored"

        mock_vault.retrieve_passphrase.assert_called_once_with("label", "master")
        limiter.record_attempt.assert_called_once_with(
            "vault_unlock", "vault.enc", success=True
        )

    @patch("secure_string_cipher.cli_args._get_vault")
    def test_get_password_from_vault_rate_limited(self, mock_get_vault):
        """Should exit before prompting when vault unlock is rate limited."""
        mock_vault = MagicMock()
        mock_vault.vault_path = "vault.enc"
        mock_get_vault.return_value = mock_vault
        limiter = MagicMock()
        limiter.check_rate_limit.return_value = (False, 30.0)

        with patch("secure_string_cipher.cli_args._cli_limiter", limiter):
            with pytest.raises(SystemExit) as exc_info:
                _get_password_from_vault("label")

        assert exc_info.value.code == EXIT_AUTH_ERROR

    @patch(
        "secure_string_cipher.cli_args._prompt_master_password", return_value="master"
    )
    @patch("secure_string_cipher.cli_args._get_vault")
    def test_get_password_from_vault_missing_label(
        self, mock_get_vault, mock_prompt_master
    ):
        """Should map missing vault labels to a vault exit error."""
        mock_vault = MagicMock()
        mock_vault.vault_path = "vault.enc"
        mock_vault.retrieve_passphrase.side_effect = ValueError("not found")
        mock_get_vault.return_value = mock_vault
        limiter = MagicMock()
        limiter.check_rate_limit.return_value = (True, 0)

        with patch("secure_string_cipher.cli_args._cli_limiter", limiter):
            with pytest.raises(SystemExit) as exc_info:
                _get_password_from_vault("missing")

        assert exc_info.value.code == EXIT_VAULT_ERROR

    @patch(
        "secure_string_cipher.cli_args._prompt_master_password", return_value="master"
    )
    @patch("secure_string_cipher.cli_args._get_vault")
    def test_get_password_from_vault_crypto_error(
        self, mock_get_vault, mock_prompt_master
    ):
        """Should map vault authentication failures to auth errors."""
        mock_vault = MagicMock()
        mock_vault.vault_path = "vault.enc"
        mock_vault.retrieve_passphrase.side_effect = CryptoError("auth")
        mock_get_vault.return_value = mock_vault
        limiter = MagicMock()
        limiter.check_rate_limit.return_value = (True, 0)

        with patch("secure_string_cipher.cli_args._cli_limiter", limiter):
            with pytest.raises(SystemExit) as exc_info:
                _get_password_from_vault("label")

        assert exc_info.value.code == EXIT_AUTH_ERROR


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

    @patch("secure_string_cipher.cli_args._prompt_password")
    def test_encrypt_file_force_failure_preserves_existing_output(
        self, mock_prompt, tmp_path
    ):
        """A forced CLI encryption failure must not remove the old output."""
        mock_prompt.return_value = "StrongPass1!@#ab"
        source = tmp_path / "file.txt"
        source.write_text("data")
        output = tmp_path / "file.txt.enc"
        output.write_bytes(b"existing ciphertext")
        args = argparse.Namespace(
            text=None,
            file=str(source),
            vault=None,
            key_file=None,
            force=True,
        )

        with (
            patch(
                "secure_string_cipher.cli_args.encrypt_file",
                side_effect=CryptoError("injected failure"),
            ),
            pytest.raises(SystemExit) as exc_info,
        ):
            cmd_encrypt(args)

        assert exc_info.value.code == EXIT_AUTH_ERROR
        assert output.read_bytes() == b"existing ciphertext"

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

    @patch("secure_string_cipher.cli_args._prompt_password", return_value="pw")
    def test_encrypt_stdin_binary_to_stdout(self, mock_prompt):
        """Should encrypt raw stdin bytes to stdout."""
        stdout = _BinaryOutput()
        args = argparse.Namespace(
            text=None,
            file="-",
            vault=None,
            key_file=None,
            force=False,
        )

        with (
            patch.object(sys, "stdin", _BinaryInput(b"\x00payload")),
            patch.object(sys, "stdout", stdout),
        ):
            result = cmd_encrypt(args)

        assert result == EXIT_SUCCESS
        assert stdout.buffer.getvalue().strip()

    @patch("secure_string_cipher.cli_args._prompt_password", return_value="pw")
    @patch(
        "secure_string_cipher.cli_args.encrypt_bytes", side_effect=CryptoError("bad")
    )
    def test_encrypt_stdin_crypto_error(self, mock_encrypt_bytes, mock_prompt):
        """Should map stdin encryption failures to auth errors."""
        args = argparse.Namespace(
            text=None,
            file="-",
            vault=None,
            key_file=None,
            force=False,
        )

        with (
            patch.object(sys, "stdin", _BinaryInput(b"payload")),
            patch.object(sys, "stdout", _BinaryOutput()),
            pytest.raises(SystemExit) as exc_info,
        ):
            cmd_encrypt(args)

        assert exc_info.value.code == EXIT_AUTH_ERROR


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

    @patch("secure_string_cipher.cli_args._prompt_password", return_value="pw")
    def test_decrypt_stdin_binary_to_stdout(self, mock_prompt):
        """Should decrypt stdin bytes without requiring a real input file."""
        token = encrypt_bytes(b"\x00payload", "pw")
        stdout = _BinaryOutput()
        limiter = MagicMock()
        limiter.check_rate_limit.return_value = (True, 0)
        args = argparse.Namespace(
            text=None,
            file="-",
            vault=None,
            key_file=None,
            force=False,
            output=None,
            restore_filename=True,
        )

        with (
            patch.object(sys, "stdin", _BinaryInput(token + b"\n")),
            patch.object(sys, "stdout", stdout),
            patch("secure_string_cipher.cli_args._cli_limiter", limiter),
        ):
            result = cmd_decrypt(args)

        assert result == EXIT_SUCCESS
        assert stdout.buffer.getvalue() == b"\x00payload"
        limiter.record_attempt.assert_called_once_with(
            "decrypt_file", "-", success=True
        )

    @patch("secure_string_cipher.cli_args._prompt_password", return_value="pw")
    def test_decrypt_stdin_crypto_error(self, mock_prompt):
        """Should map stdin decryption failures to auth errors."""
        limiter = MagicMock()
        limiter.check_rate_limit.return_value = (True, 0)
        args = argparse.Namespace(
            text=None,
            file="-",
            vault=None,
            key_file=None,
            force=False,
            output=None,
            restore_filename=True,
        )

        with (
            patch.object(sys, "stdin", _BinaryInput(b"not-base64")),
            patch.object(sys, "stdout", _BinaryOutput()),
            patch("secure_string_cipher.cli_args._cli_limiter", limiter),
            pytest.raises(SystemExit) as exc_info,
        ):
            cmd_decrypt(args)

        assert exc_info.value.code == EXIT_AUTH_ERROR
        limiter.record_attempt.assert_called_once_with(
            "decrypt_file", "-", success=False
        )


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

    @patch("secure_string_cipher.cli_args._prompt_master_password")
    @patch("secure_string_cipher.cli_args._get_vault")
    def test_store_unexpected_error_does_not_include_secret(
        self, mock_get_vault, mock_prompt_master, monkeypatch, capsys
    ):
        """Unexpected store errors should not print raw exception text."""

        leaked_detail = "DO_NOT_PRINT_STORE_FAILURE_SECRET"  # pragma: allowlist secret
        mock_vault = MagicMock()
        mock_get_vault.return_value = mock_vault
        mock_prompt_master.return_value = "MasterPw123!@#"
        mock_vault.store_passphrase.side_effect = Exception(leaked_detail)
        monkeypatch.setattr(cli_args, "_no_color", True)

        args = argparse.Namespace(label="label", generate=True)
        with pytest.raises(SystemExit) as exc_info:
            cmd_store(args)

        captured = capsys.readouterr()
        assert exc_info.value.code == EXIT_VAULT_ERROR
        assert leaked_detail not in captured.err
        assert "Failed to store passphrase." in captured.err


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
    def test_export_success(self, mock_get_vault, mock_prompt_master, capsys):
        """Should export vault content."""
        mock_vault = MagicMock()
        mock_get_vault.return_value = mock_vault
        mock_prompt_master.return_value = "master"
        mock_vault.list_labels.return_value = ["label1"]
        mock_vault.read_raw_vault.return_value = "SSCVAULT\ndata"

        args = argparse.Namespace()
        result = cmd_vault_export(args)

        assert result == EXIT_SUCCESS
        assert "SSCVAULT\ndata" in capsys.readouterr().out
        mock_vault.read_raw_vault.assert_called_once()

    @patch("secure_string_cipher.cli_args._prompt_master_password")
    @patch("secure_string_cipher.cli_args._get_vault")
    def test_export_missing_raw_vault(self, mock_get_vault, mock_prompt_master):
        """Should not fall back to file paths when active raw vault is missing."""
        mock_vault = MagicMock()
        mock_get_vault.return_value = mock_vault
        mock_prompt_master.return_value = "master"
        mock_vault.list_labels.return_value = ["label1"]
        mock_vault.read_raw_vault.return_value = None

        args = argparse.Namespace()
        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_export(args)

        assert exc_info.value.code == EXIT_VAULT_ERROR
        mock_vault.read_raw_vault.assert_called_once()

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
        mock_vault.vault_exists.return_value = False

        import_file = tmp_path / "backup.vault"
        import_file.write_text(
            "SSCVAULT\nabcdef01\n---DATA---\nencrypted\npayload\n---HMAC---\nhmac_val"
        )

        args = argparse.Namespace(file=str(import_file))
        result = cmd_vault_import(args)

        assert result == EXIT_SUCCESS
        mock_vault.write_raw_vault.assert_called_once()


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
        mock_vault.vault_exists.return_value = False

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
        mock_vault.vault_exists.return_value = True

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
        mock_vault.vault_exists.return_value = True

        args = argparse.Namespace()
        result = cmd_vault_reset(args)

        assert result == EXIT_SUCCESS
        mock_vault.delete_vault_storage.assert_called_once()


# =============================================================================
# cmd_vault_migrate
# =============================================================================


class TestCmdVaultMigrate:
    """Tests for cmd_vault_migrate."""

    @patch("secure_string_cipher.cli_args.set_vault_backend")
    @patch("secure_string_cipher.cli_args._prompt_master_password")
    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_migrate_to_file(
        self, mock_vault_cls, mock_prompt_master, mock_set_backend
    ):
        """Should migrate to file backend."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_prompt_master.return_value = "master"
        mock_vault.vault_path = MagicMock()

        args = argparse.Namespace(target_backend="file")
        result = cmd_vault_migrate(args)

        assert result == EXIT_SUCCESS
        mock_vault.migrate_to_file.assert_called_once()
        mock_set_backend.assert_called_once_with("file")

    @patch("secure_string_cipher.cli_args.set_vault_backend")
    @patch("secure_string_cipher.cli_args._prompt_master_password")
    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_migrate_to_keychain(
        self, mock_vault_cls, mock_prompt_master, mock_set_backend
    ):
        """Should migrate to keychain backend."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_prompt_master.return_value = "master"

        args = argparse.Namespace(target_backend="keychain")
        result = cmd_vault_migrate(args)

        assert result == EXIT_SUCCESS
        mock_vault.migrate_to_keychain.assert_called_once()
        mock_set_backend.assert_called_once_with("keychain")

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

    @patch("secure_string_cipher.cli_args._prompt_master_password")
    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_migrate_keychain_unavailable(self, mock_vault_cls, mock_prompt_master):
        """Should map unavailable keychain backend to vault error."""
        from secure_string_cipher.keychain_backend import KeychainUnavailableError

        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_prompt_master.return_value = "master"
        mock_vault.migrate_to_keychain.side_effect = KeychainUnavailableError("no key")

        args = argparse.Namespace(target_backend="keychain")
        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_migrate(args)
        assert exc_info.value.code == EXIT_VAULT_ERROR

    @patch("secure_string_cipher.cli_args._prompt_master_password")
    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_migrate_unexpected_error(self, mock_vault_cls, mock_prompt_master):
        """Should map unexpected migration failures to vault error."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_prompt_master.return_value = "master"
        mock_vault.migrate_to_file.side_effect = RuntimeError("boom")

        args = argparse.Namespace(target_backend="file")
        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_migrate(args)
        assert exc_info.value.code == EXIT_VAULT_ERROR


# =============================================================================
# vault status/backend/backups/restore
# =============================================================================


class TestCmdVaultManagement:
    """Tests for newer vault management commands."""

    @patch("secure_string_cipher.cli_args.load_vault_settings")
    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_status_prints_backend_and_paths(
        self, mock_vault_cls, mock_load_settings, capsys
    ):
        """Should print current backend, locations, and existence."""
        settings = MagicMock()
        settings.vault_backend = "file"
        mock_load_settings.return_value = settings
        mock_vault = MagicMock()
        mock_vault.backend = "file"
        mock_vault.vault_path = "/vault.enc"
        mock_vault.backup_dir = "/backups"
        mock_vault.get_vault_path.return_value = "/vault.enc"
        mock_vault.vault_exists.return_value = True
        mock_vault_cls.return_value = mock_vault

        result = cmd_vault_status(argparse.Namespace())

        assert result == EXIT_SUCCESS
        output = capsys.readouterr().out
        assert "Backend: file" in output
        assert "Vault exists: yes" in output

    @patch("secure_string_cipher.cli_args.load_vault_settings")
    def test_backend_prints_current_backend(self, mock_load_settings, capsys):
        """Should print active backend when no backend is supplied."""
        settings = MagicMock()
        settings.vault_backend = "keychain"
        mock_load_settings.return_value = settings

        result = cmd_vault_backend(argparse.Namespace(backend=None))

        assert result == EXIT_SUCCESS
        assert capsys.readouterr().out.strip() == "keychain"

    @patch("secure_string_cipher.cli_args.set_vault_backend")
    def test_backend_sets_active_backend(self, mock_set_backend):
        """Should persist a requested active backend."""
        settings = MagicMock()
        settings.vault_backend = "file"
        mock_set_backend.return_value = settings

        result = cmd_vault_backend(argparse.Namespace(backend="file"))

        assert result == EXIT_SUCCESS
        mock_set_backend.assert_called_once_with("file")

    @patch(
        "secure_string_cipher.cli_args.set_vault_backend", side_effect=ValueError("bad")
    )
    def test_backend_invalid_backend_exits(self, mock_set_backend):
        """Should map invalid backend settings to input errors."""
        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_backend(argparse.Namespace(backend="invalid"))
        assert exc_info.value.code == EXIT_INPUT_ERROR

    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_backups_prints_empty_message(self, mock_vault_cls, capsys):
        """Should print a clear message when no backups exist."""
        mock_vault = MagicMock()
        mock_vault.list_backups.return_value = []
        mock_vault_cls.return_value = mock_vault

        result = cmd_vault_backups(argparse.Namespace())

        assert result == EXIT_SUCCESS
        assert "No backups" in capsys.readouterr().out
        mock_vault_cls.assert_called_once_with(backend="file")

    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_backups_prints_indexed_list(self, mock_vault_cls, capsys):
        """Should print available backups with indexes."""
        mock_vault = MagicMock()
        mock_vault.list_backups.return_value = ["/backup/new.enc", "/backup/old.enc"]
        mock_vault_cls.return_value = mock_vault

        result = cmd_vault_backups(argparse.Namespace())

        assert result == EXIT_SUCCESS
        output = capsys.readouterr().out
        assert "[0] /backup/new.enc" in output
        assert "[1] /backup/old.enc" in output

    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_restore_success(self, mock_vault_cls):
        """Should restore a selected backup."""
        mock_vault = MagicMock()
        mock_vault.vault_path = "/vault.enc"
        mock_vault_cls.return_value = mock_vault

        result = cmd_vault_restore(argparse.Namespace(index=2))

        assert result == EXIT_SUCCESS
        mock_vault.restore_from_backup.assert_called_once_with(2)

    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_restore_value_error(self, mock_vault_cls):
        """Should map restore validation failures to vault errors."""
        mock_vault = MagicMock()
        mock_vault.restore_from_backup.side_effect = ValueError("no backups")
        mock_vault_cls.return_value = mock_vault

        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_restore(argparse.Namespace(index=0))
        assert exc_info.value.code == EXIT_VAULT_ERROR

    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_restore_os_error(self, mock_vault_cls):
        """Should map filesystem restore failures to file errors."""
        mock_vault = MagicMock()
        mock_vault.restore_from_backup.side_effect = OSError("denied")
        mock_vault_cls.return_value = mock_vault

        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_restore(argparse.Namespace(index=0))
        assert exc_info.value.code == EXIT_FILE_ERROR


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

        mock_getpass.side_effect = ["StrongPass1!@#ab", "StrongPass1!@#ab"]
        result = _prompt_password_with_validation()
        assert result == "StrongPass1!@#ab"

    @patch("getpass.getpass")
    def test_weak_then_strong(self, mock_getpass):
        """Should reject weak then accept strong."""

        mock_getpass.side_effect = [
            "weak",  # Too weak
            "StrongPass1!@#ab",  # Strong
            "StrongPass1!@#ab",  # Confirm
        ]
        result = _prompt_password_with_validation()
        assert result == "StrongPass1!@#ab"

    @patch("getpass.getpass")
    def test_weak_password_output_does_not_include_secret_or_detail(
        self, mock_getpass, capsys
    ):
        """Weak-password validation should avoid password-derived output."""

        submitted_secret = "DO_NOT_PRINT_THIS_SECRET_123"  # pragma: allowlist secret
        mock_getpass.side_effect = [
            submitted_secret,
            "StrongPass1!@#ab",
            "StrongPass1!@#ab",
        ]

        result = _prompt_password_with_validation()

        captured = capsys.readouterr()
        assert result == "StrongPass1!@#ab"
        assert submitted_secret not in captured.err
        assert "Password must include:" not in captured.err
        assert "Password requirements:" in captured.err

    @patch("getpass.getpass")
    def test_mismatch_then_match(self, mock_getpass):
        """Should retry on mismatch."""

        mock_getpass.side_effect = [
            "StrongPass1!@#ab",  # Strong
            "Mismatch1!@#xyz",  # Doesn't match
            "StrongPass1!@#ab",  # Strong again
            "StrongPass1!@#ab",  # Confirms
        ]
        result = _prompt_password_with_validation()
        assert result == "StrongPass1!@#ab"
