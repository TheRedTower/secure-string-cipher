"""Unit tests for non-interactive CLI (cli_args.py)."""

from __future__ import annotations

import argparse
import sys
from unittest.mock import MagicMock, patch

import pytest

from secure_string_cipher.cli_args import (
    EXIT_AUTH_ERROR,
    EXIT_FILE_ERROR,
    EXIT_INPUT_ERROR,
    EXIT_SUCCESS,
    EXIT_VAULT_ERROR,
    _print_error,
    _print_info,
    _print_warning,
    cmd_decrypt,
    cmd_encrypt,
    cmd_vault_delete,
    cmd_vault_import,
    cmd_vault_list,
    cmd_vault_reset,
    create_parser,
)
from secure_string_cipher.core import encrypt_file

# =============================================================================
# Parser Tests
# =============================================================================


class TestParserCreation:
    """Tests for argument parser creation."""

    def test_parser_creates_successfully(self):
        """Parser should create without errors."""
        parser = create_parser()
        assert parser is not None
        assert parser.prog == "ssc"

    def test_version_flag(self, capsys):
        """--version should show version and exit."""
        parser = create_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0

    def test_help_flag(self, capsys):
        """--help should show help and exit."""
        parser = create_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--help"])
        assert exc_info.value.code == 0

    def test_global_quiet_flag(self):
        """--quiet flag should be parsed globally."""
        parser = create_parser()
        args = parser.parse_args(["--quiet", "encrypt", "-t", "test"])
        assert args.quiet is True

    def test_global_no_color_flag(self):
        """--no-color flag should be parsed globally."""
        parser = create_parser()
        args = parser.parse_args(["--no-color", "encrypt", "-t", "test"])
        assert args.no_color is True


class TestEncryptParser:
    """Tests for encrypt subcommand parser."""

    def test_encrypt_text_flag(self):
        """encrypt -t should set text argument."""
        parser = create_parser()
        args = parser.parse_args(["encrypt", "-t", "secret message"])
        assert args.command == "encrypt"
        assert args.text == "secret message"
        assert args.file is None

    def test_encrypt_file_flag(self):
        """encrypt -f should set file argument."""
        parser = create_parser()
        args = parser.parse_args(["encrypt", "-f", "/path/to/file.txt"])
        assert args.command == "encrypt"
        assert args.file == "/path/to/file.txt"
        assert args.text is None

    def test_encrypt_vault_flag(self):
        """encrypt --vault should set vault label."""
        parser = create_parser()
        args = parser.parse_args(["encrypt", "-t", "test", "--vault", "my-key"])
        assert args.vault == "my-key"

    def test_encrypt_force_flag(self):
        """encrypt --force should set force flag."""
        parser = create_parser()
        args = parser.parse_args(["encrypt", "-f", "file.txt", "--force"])
        assert args.force is True


class TestDecryptParser:
    """Tests for decrypt subcommand parser."""

    def test_decrypt_text_flag(self):
        """decrypt -t should set text argument."""
        parser = create_parser()
        args = parser.parse_args(["decrypt", "-t", "ciphertext"])
        assert args.command == "decrypt"
        assert args.text == "ciphertext"
        assert args.file is None

    def test_decrypt_file_flag(self):
        """decrypt -f should set file argument."""
        parser = create_parser()
        args = parser.parse_args(["decrypt", "-f", "/path/to/file.enc"])
        assert args.command == "decrypt"
        assert args.file == "/path/to/file.enc"

    def test_decrypt_vault_flag(self):
        """decrypt --vault should set vault label."""
        parser = create_parser()
        args = parser.parse_args(["decrypt", "-t", "test", "--vault", "my-key"])
        assert args.vault == "my-key"

    def test_decrypt_output_flag(self):
        """decrypt --output should set output path."""
        parser = create_parser()
        args = parser.parse_args(["decrypt", "-f", "file.enc", "--output", "out.txt"])
        assert args.output == "out.txt"

    def test_decrypt_restore_toggle(self):
        """decrypt --no-restore-filename should disable restore."""
        parser = create_parser()
        args = parser.parse_args(["decrypt", "-f", "file.enc", "--no-restore-filename"])
        assert args.restore_filename is False


class TestStoreParser:
    """Tests for store subcommand parser."""

    def test_store_label_argument(self):
        """store should require label argument."""
        parser = create_parser()
        args = parser.parse_args(["store", "my-label"])
        assert args.command == "store"
        assert args.label == "my-label"

    def test_store_generate_flag(self):
        """store --generate should set generate flag."""
        parser = create_parser()
        args = parser.parse_args(["store", "my-label", "--generate"])
        assert args.generate is True

    def test_store_generate_short_flag(self):
        """store -g should set generate flag."""
        parser = create_parser()
        args = parser.parse_args(["store", "my-label", "-g"])
        assert args.generate is True


class TestVaultParser:
    """Tests for vault subcommand parser."""

    def test_vault_list(self):
        """vault list should parse correctly."""
        parser = create_parser()
        args = parser.parse_args(["vault", "list"])
        assert args.command == "vault"
        assert args.vault_command == "list"

    def test_vault_delete_label(self):
        """vault delete should require label argument."""
        parser = create_parser()
        args = parser.parse_args(["vault", "delete", "my-label"])
        assert args.command == "vault"
        assert args.vault_command == "delete"
        assert args.label == "my-label"

    def test_vault_export(self):
        """vault export should parse correctly."""
        parser = create_parser()
        args = parser.parse_args(["vault", "export"])
        assert args.command == "vault"
        assert args.vault_command == "export"

    def test_vault_import_file(self):
        """vault import should require file argument."""
        parser = create_parser()
        args = parser.parse_args(["vault", "import", "backup.json"])
        assert args.command == "vault"
        assert args.vault_command == "import"
        assert args.file == "backup.json"

    def test_vault_reset(self):
        """vault reset should parse correctly."""
        parser = create_parser()
        args = parser.parse_args(["vault", "reset"])
        assert args.command == "vault"
        assert args.vault_command == "reset"


# =============================================================================
# Output Function Tests
# =============================================================================


class TestOutputFunctions:
    """Tests for output helper functions."""

    def test_print_info_normal_mode(self, capsys):
        """_print_info should print in normal mode."""
        import secure_string_cipher.cli_args as cli_args

        # Save and set state
        orig_quiet = cli_args._quiet_mode
        orig_color = cli_args._no_color
        cli_args._quiet_mode = False
        cli_args._no_color = True

        try:
            _print_info("Test message")
            captured = capsys.readouterr()
            assert "Test message" in captured.err
        finally:
            cli_args._quiet_mode = orig_quiet
            cli_args._no_color = orig_color

    def test_print_info_quiet_mode(self, capsys):
        """_print_info should not print in quiet mode."""
        import secure_string_cipher.cli_args as cli_args

        orig_quiet = cli_args._quiet_mode
        cli_args._quiet_mode = True

        try:
            _print_info("Test message")
            captured = capsys.readouterr()
            assert "Test message" not in captured.err
        finally:
            cli_args._quiet_mode = orig_quiet

    def test_print_warning_quiet_mode(self, capsys):
        """_print_warning should not print in quiet mode."""
        import secure_string_cipher.cli_args as cli_args

        orig_quiet = cli_args._quiet_mode
        cli_args._quiet_mode = True

        try:
            _print_warning("Warning message")
            captured = capsys.readouterr()
            assert "Warning message" not in captured.err
        finally:
            cli_args._quiet_mode = orig_quiet

    def test_print_error_always_shows(self, capsys):
        """_print_error should always print, even in quiet mode."""
        import secure_string_cipher.cli_args as cli_args

        orig_quiet = cli_args._quiet_mode
        orig_color = cli_args._no_color
        cli_args._quiet_mode = True
        cli_args._no_color = True

        try:
            _print_error("Error message")
            captured = capsys.readouterr()
            assert "Error message" in captured.err
        finally:
            cli_args._quiet_mode = orig_quiet
            cli_args._no_color = orig_color


# =============================================================================
# Exit Code Tests
# =============================================================================


class TestExitCodes:
    """Tests for exit code constants."""

    def test_exit_codes_are_distinct(self):
        """All exit codes should be unique."""
        codes = [
            EXIT_SUCCESS,
            EXIT_INPUT_ERROR,
            EXIT_AUTH_ERROR,
            EXIT_VAULT_ERROR,
            EXIT_FILE_ERROR,
        ]
        assert len(codes) == len(set(codes))

    def test_exit_success_is_zero(self):
        """EXIT_SUCCESS should be 0."""
        assert EXIT_SUCCESS == 0


# =============================================================================
# Command Validation Tests
# =============================================================================


class TestEncryptValidation:
    """Tests for encrypt command validation."""

    def test_encrypt_requires_text_or_file(self):
        """encrypt should exit if neither -t nor -f provided."""
        args = argparse.Namespace(
            text=None, file=None, vault=None, force=False, quiet=False, no_color=True
        )
        with pytest.raises(SystemExit) as exc_info:
            cmd_encrypt(args)
        assert exc_info.value.code == EXIT_INPUT_ERROR

    def test_encrypt_rejects_both_text_and_file(self):
        """encrypt should exit if both -t and -f provided."""
        args = argparse.Namespace(
            text="message",
            file="file.txt",
            vault=None,
            force=False,
            quiet=False,
            no_color=True,
        )
        with pytest.raises(SystemExit) as exc_info:
            cmd_encrypt(args)
        assert exc_info.value.code == EXIT_INPUT_ERROR


class TestDecryptValidation:
    """Tests for decrypt command validation."""

    def test_decrypt_requires_text_or_file(self):
        """decrypt should exit if neither -t nor -f provided."""
        args = argparse.Namespace(
            text=None, file=None, vault=None, force=False, quiet=False, no_color=True
        )
        with pytest.raises(SystemExit) as exc_info:
            cmd_decrypt(args)
        assert exc_info.value.code == EXIT_INPUT_ERROR

    def test_decrypt_rejects_both_text_and_file(self):
        """decrypt should exit if both -t and -f provided."""
        args = argparse.Namespace(
            text="ciphertext",
            file="file.enc",
            vault=None,
            force=False,
            quiet=False,
            no_color=True,
        )
        with pytest.raises(SystemExit) as exc_info:
            cmd_decrypt(args)
        assert exc_info.value.code == EXIT_INPUT_ERROR


# =============================================================================
# File Operation Tests
# =============================================================================


class TestFileEncryption:
    """Tests for file encryption operations."""

    def test_encrypt_file_not_found(self):
        """encrypt should exit with FILE_ERROR for missing file."""
        args = argparse.Namespace(
            text=None,
            file="/nonexistent/path/file.txt",
            vault=None,
            force=False,
            quiet=False,
            no_color=True,
        )
        with patch(
            "secure_string_cipher.cli_args._prompt_password",
            return_value="Password123!",
        ):
            with pytest.raises(SystemExit) as exc_info:
                cmd_encrypt(args)
            assert exc_info.value.code == EXIT_FILE_ERROR

    def test_decrypt_file_not_found(self):
        """decrypt should exit with FILE_ERROR for missing file."""
        args = argparse.Namespace(
            text=None,
            file="/nonexistent/path/file.enc",
            vault=None,
            force=False,
            quiet=False,
            no_color=True,
            output=None,
            restore_filename=True,
        )
        with patch(
            "secure_string_cipher.cli_args._prompt_password",
            return_value="Password123!",
        ):
            with pytest.raises(SystemExit) as exc_info:
                cmd_decrypt(args)
            assert exc_info.value.code == EXIT_FILE_ERROR

    def test_decrypt_restores_original_filename(self, tmp_path):
        """decrypt should restore original filename from metadata when not overridden."""
        original = tmp_path / "secret.txt"
        encrypted = tmp_path / "secret.txt.enc"
        password = "SecurePassword123!@#"  # pragma: allowlist secret

        original.write_text("classified")
        encrypt_file(str(original), str(encrypted), password)
        original.unlink()

        args = argparse.Namespace(
            text=None,
            file=str(encrypted),
            vault=None,
            force=False,
            quiet=True,
            no_color=True,
            output=None,
            restore_filename=True,
        )

        with patch(
            "secure_string_cipher.cli_args._prompt_password",
            return_value=password,
        ):
            result = cmd_decrypt(args)

        assert result == EXIT_SUCCESS
        restored_path = tmp_path / "secret.txt"
        assert restored_path.exists()
        assert restored_path.read_text() == "classified"

    def test_decrypt_respects_no_restore_flag(self, tmp_path):
        """decrypt should use .dec fallback when restore is disabled and no output provided."""
        original = tmp_path / "notes.txt"
        encrypted = tmp_path / "notes.txt.enc"
        password = "SecurePassword123!@#"  # pragma: allowlist secret

        original.write_text("data")
        encrypt_file(str(original), str(encrypted), password)
        original.unlink()

        args = argparse.Namespace(
            text=None,
            file=str(encrypted),
            vault=None,
            force=False,
            quiet=True,
            no_color=True,
            output=None,
            restore_filename=False,
        )

        with patch(
            "secure_string_cipher.cli_args._prompt_password",
            return_value=password,
        ):
            result = cmd_decrypt(args)

        assert result == EXIT_SUCCESS
        fallback_path = tmp_path / "notes.txt.dec"
        assert fallback_path.exists()
        assert fallback_path.read_text() == "data"


class TestOverwriteProtection:
    """Tests for file overwrite protection."""

    def test_encrypt_refuses_overwrite_without_force(self, tmp_path):
        """encrypt should refuse to overwrite existing output file."""
        # Create source and existing output files
        source = tmp_path / "test.txt"
        source.write_text("content")
        output = tmp_path / "test.txt.enc"
        output.write_text("existing")

        args = argparse.Namespace(
            text=None,
            file=str(source),
            vault=None,
            force=False,
            quiet=False,
            no_color=True,
        )
        with patch(
            "secure_string_cipher.cli_args._prompt_password",
            return_value="Password123!",
        ):
            with pytest.raises(SystemExit) as exc_info:
                cmd_encrypt(args)
            assert exc_info.value.code == EXIT_FILE_ERROR


# =============================================================================
# Text Encryption/Decryption Tests
# =============================================================================


class TestTextEncryption:
    """Tests for text encryption/decryption operations."""

    @patch("secure_string_cipher.cli_args._prompt_password")
    def test_encrypt_text_success(self, mock_prompt, capsys):
        """encrypt -t should output ciphertext to stdout."""
        import secure_string_cipher.cli_args as cli_args

        cli_args._quiet_mode = False
        cli_args._no_color = True

        mock_prompt.return_value = "SecurePassword123!"

        args = argparse.Namespace(
            text="Hello World",
            file=None,
            vault=None,
            force=False,
            quiet=False,
            no_color=True,
        )

        result = cmd_encrypt(args)
        assert result == EXIT_SUCCESS

        captured = capsys.readouterr()
        # Output should contain base64 ciphertext
        assert len(captured.out.strip()) > 0

    @patch("secure_string_cipher.cli_args._prompt_password")
    def test_encrypt_decrypt_roundtrip(self, mock_prompt, capsys):
        """encrypt and decrypt should round-trip correctly."""
        import secure_string_cipher.cli_args as cli_args

        cli_args._quiet_mode = True
        cli_args._no_color = True

        password = "SecurePassword123!"  # pragma: allowlist secret
        original_text = "Secret message for testing"
        mock_prompt.return_value = password

        # Encrypt
        encrypt_args = argparse.Namespace(
            text=original_text,
            file=None,
            vault=None,
            force=False,
            quiet=True,
            no_color=True,
        )
        cmd_encrypt(encrypt_args)
        encrypted = capsys.readouterr().out.strip()

        # Decrypt
        decrypt_args = argparse.Namespace(
            text=encrypted,
            file=None,
            vault=None,
            force=False,
            quiet=True,
            no_color=True,
        )
        cmd_decrypt(decrypt_args)
        decrypted = capsys.readouterr().out.strip()

        assert decrypted == original_text

    @patch("secure_string_cipher.cli_args._prompt_password")
    def test_decrypt_wrong_password(self, mock_prompt, capsys):
        """decrypt with wrong password should exit with AUTH_ERROR."""
        import secure_string_cipher.cli_args as cli_args

        cli_args._quiet_mode = True
        cli_args._no_color = True

        # First encrypt with one password
        mock_prompt.return_value = "CorrectPassword123!"
        encrypt_args = argparse.Namespace(
            text="Secret",
            file=None,
            vault=None,
            force=False,
            quiet=True,
            no_color=True,
        )
        cmd_encrypt(encrypt_args)
        encrypted = capsys.readouterr().out.strip()

        # Try to decrypt with wrong password
        mock_prompt.return_value = "WrongPassword123!"
        decrypt_args = argparse.Namespace(
            text=encrypted,
            file=None,
            vault=None,
            force=False,
            quiet=True,
            no_color=True,
        )

        with pytest.raises(SystemExit) as exc_info:
            cmd_decrypt(decrypt_args)
        assert exc_info.value.code == EXIT_AUTH_ERROR


# =============================================================================
# Vault Command Tests (with mocked vault)
# =============================================================================


class TestVaultCommands:
    """Tests for vault subcommand operations."""

    @patch("secure_string_cipher.cli_args._get_vault")
    @patch("secure_string_cipher.cli_args._prompt_master_password")
    def test_vault_list_empty(self, mock_master, mock_vault, capsys):
        """vault list should show empty message for empty vault."""
        mock_master.return_value = "MasterPassword123!"
        mock_vault_instance = MagicMock()
        mock_vault_instance.list_labels.return_value = []
        mock_vault.return_value = mock_vault_instance

        args = argparse.Namespace()
        result = cmd_vault_list(args)

        assert result == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "empty" in captured.out.lower()

    @patch("secure_string_cipher.cli_args._get_vault")
    @patch("secure_string_cipher.cli_args._prompt_master_password")
    def test_vault_list_with_entries(self, mock_master, mock_vault, capsys):
        """vault list should show labels."""
        mock_master.return_value = "MasterPassword123!"
        mock_vault_instance = MagicMock()
        mock_vault_instance.list_labels.return_value = ["label1", "label2"]
        mock_vault.return_value = mock_vault_instance

        args = argparse.Namespace()
        result = cmd_vault_list(args)

        assert result == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "label1" in captured.out
        assert "label2" in captured.out

    @patch("secure_string_cipher.cli_args._get_vault")
    @patch("secure_string_cipher.cli_args._prompt_master_password")
    def test_vault_delete_success(self, mock_master, mock_vault, capsys):
        """vault delete should delete entry and show success."""
        import secure_string_cipher.cli_args as cli_args

        cli_args._quiet_mode = False
        cli_args._no_color = True

        mock_master.return_value = "MasterPassword123!"
        mock_vault_instance = MagicMock()
        mock_vault.return_value = mock_vault_instance

        args = argparse.Namespace(label="my-label")
        result = cmd_vault_delete(args)

        assert result == EXIT_SUCCESS
        mock_vault_instance.delete_passphrase.assert_called_once_with(
            "my-label", "MasterPassword123!"
        )

    @patch("secure_string_cipher.cli_args._get_vault")
    @patch("secure_string_cipher.cli_args._prompt_master_password")
    def test_vault_delete_not_found(self, mock_master, mock_vault):
        """vault delete should exit with VAULT_ERROR for missing label."""
        mock_master.return_value = "MasterPassword123!"
        mock_vault_instance = MagicMock()
        mock_vault_instance.delete_passphrase.side_effect = KeyError("Label not found")
        mock_vault.return_value = mock_vault_instance

        args = argparse.Namespace(label="nonexistent")

        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_delete(args)
        assert exc_info.value.code == EXIT_VAULT_ERROR


class TestVaultImportReset:
    """Tests for vault import and reset commands."""

    def test_vault_import_file_not_found(self):
        """vault import should exit with FILE_ERROR for missing file."""
        args = argparse.Namespace(file="/nonexistent/backup.json")

        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_import(args)
        assert exc_info.value.code == EXIT_FILE_ERROR

    def test_vault_import_invalid_format(self, tmp_path):
        """vault import should exit with FILE_ERROR for invalid vault format."""
        bad_file = tmp_path / "bad_backup.txt"
        bad_file.write_text("not a vault file")

        args = argparse.Namespace(file=str(bad_file))

        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_import(args)
        assert exc_info.value.code == EXIT_FILE_ERROR

    def test_vault_import_invalid_salt(self, tmp_path):
        """vault import should exit with FILE_ERROR for non-hex salt."""
        bad_file = tmp_path / "bad_backup.txt"
        bad_file.write_text("SSCVAULT\nnothex\n---DATA---\nfoo\n---HMAC---\nbar")

        args = argparse.Namespace(file=str(bad_file))

        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_import(args)
        assert exc_info.value.code == EXIT_FILE_ERROR

    def test_vault_import_missing_hmac_separator(self, tmp_path):
        """vault import should exit with FILE_ERROR for missing HMAC separator."""
        bad_file = tmp_path / "bad_backup.txt"
        bad_file.write_text("SSCVAULT\nabcd1234\n---DATA---\nfoo")

        args = argparse.Namespace(file=str(bad_file))

        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_import(args)
        assert exc_info.value.code == EXIT_FILE_ERROR

    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_vault_import_valid_format(self, mock_vault_class, tmp_path):
        """vault import should succeed with valid vault format."""
        mock_vault_instance = MagicMock()
        mock_vault_instance.vault_path.exists.return_value = False
        mock_vault_class.return_value = mock_vault_instance

        valid_file = tmp_path / "valid_backup.txt"
        valid_file.write_text(
            "SSCVAULT\nabcd1234\n---DATA---\nencrypted_payload\n---HMAC---\nhmac_value"
        )

        args = argparse.Namespace(file=str(valid_file))
        result = cmd_vault_import(args)
        assert result == EXIT_SUCCESS

    @patch("builtins.input", return_value="NOT_RESET")
    @patch("secure_string_cipher.cli_args.PassphraseVault")
    def test_vault_reset_requires_confirmation(self, mock_vault_class, mock_input):
        """vault reset should require typing RESET."""
        mock_vault_instance = MagicMock()
        mock_vault_instance.vault_path.exists.return_value = True
        mock_vault_class.return_value = mock_vault_instance

        args = argparse.Namespace()

        with pytest.raises(SystemExit) as exc_info:
            cmd_vault_reset(args)
        assert exc_info.value.code == EXIT_INPUT_ERROR


# =============================================================================
# Integration-style Tests
# =============================================================================


class TestStartCommand:
    """Tests for the start command (interactive mode)."""

    @patch("secure_string_cipher.cli_args.run_interactive_menu")
    def test_start_launches_interactive(self, mock_menu):
        """start command should launch interactive menu."""
        from secure_string_cipher.cli_args import cmd_start

        args = argparse.Namespace()
        result = cmd_start(args)

        assert result == EXIT_SUCCESS
        mock_menu.assert_called_once()


class TestMainFunction:
    """Tests for the main entry point."""

    def test_main_no_command_shows_help(self, capsys):
        """main with no arguments should show help."""
        from secure_string_cipher.cli_args import main

        with patch.object(sys, "argv", ["ssc"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == EXIT_SUCCESS

    def test_main_keyboard_interrupt_handled(self, capsys):
        """main should handle KeyboardInterrupt gracefully."""
        from secure_string_cipher.cli_args import main

        with patch.object(sys, "argv", ["ssc", "encrypt", "-t", "test"]):
            with patch(
                "secure_string_cipher.cli_args._prompt_password",
                side_effect=KeyboardInterrupt,
            ):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == EXIT_INPUT_ERROR


# =============================================================================
# Shred Command Tests
# =============================================================================


class TestShredCommand:
    """Tests for the shred command."""

    @patch("secure_string_cipher.cli_args.secure_overwrite")
    @patch("secure_string_cipher.cli_args._print_info")
    def test_shred_single_file(self, mock_print_info, mock_secure_overwrite):
        """shred should overwrite and delete a single file."""
        from secure_string_cipher.cli_args import cmd_shred

        with patch("builtins.input", return_value="yes"):
            with patch("pathlib.Path.exists", return_value=True):
                args = argparse.Namespace(paths=["test.txt"], force=False)
                result = cmd_shred(args)

        assert result == EXIT_SUCCESS
        mock_secure_overwrite.assert_called_once_with("test.txt")

    @patch("secure_string_cipher.cli_args.secure_overwrite")
    @patch("secure_string_cipher.cli_args._print_info")
    def test_shred_force_skip_confirmation(
        self, mock_print_info, mock_secure_overwrite
    ):
        """shred with --force should skip confirmation."""
        from secure_string_cipher.cli_args import cmd_shred

        with patch("pathlib.Path.exists", return_value=True):
            args = argparse.Namespace(paths=["a.txt", "b.txt"], force=True)
            result = cmd_shred(args)

        assert result == EXIT_SUCCESS
        assert mock_secure_overwrite.call_count == 2

    def test_shred_file_not_found(self):
        """shred should exit with FILE_ERROR if file doesn't exist."""
        from secure_string_cipher.cli_args import cmd_shred

        args = argparse.Namespace(paths=["nonexistent.txt"], force=True)

        with pytest.raises(SystemExit) as exc_info:
            cmd_shred(args)
        assert exc_info.value.code == EXIT_FILE_ERROR

    @patch("secure_string_cipher.cli_args.secure_overwrite")
    @patch("secure_string_cipher.cli_args._print_info")
    def test_shred_skip_on_no_confirmation(
        self, mock_print_info, mock_secure_overwrite
    ):
        """shred should skip file if user doesn't confirm."""
        from secure_string_cipher.cli_args import cmd_shred

        with patch("builtins.input", return_value="no"):
            with patch("pathlib.Path.exists", return_value=True):
                args = argparse.Namespace(paths=["test.txt"], force=False)
                result = cmd_shred(args)

        assert result == EXIT_SUCCESS
        mock_secure_overwrite.assert_not_called()
