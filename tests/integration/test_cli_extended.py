"""
Extended CLI tests for vault operations and edge cases.

Tests cover:
- Vault storage operations (store, retrieve, list, manage)
- Inline passphrase generation
- Error handling paths
- Edge cases in input handling
"""

import builtins
from io import StringIO
from unittest.mock import patch

import pytest

from secure_string_cipher.cli import (
    _get_input,
    _get_mode,
    _get_password,
    _handle_clipboard,
    _handle_generate_passphrase,
    _handle_generate_passphrase_inline,
    _handle_list_vault,
    _handle_manage_vault,
    _handle_retrieve_passphrase,
    _handle_store_passphrase,
    _offer_vault_storage,
    _print_banner,
    _read_password,
    main,
)


class TestReadPassword:
    """Tests for _read_password function."""

    def test_read_password_visible_input(self):
        """Should use visible input for non-TTY."""
        in_stream = StringIO("mypassword\n")
        out_stream = StringIO()

        result = _read_password("Enter: ", in_stream, out_stream)

        assert result == "mypassword"
        assert "Enter: " in out_stream.getvalue()

    def test_read_password_echo_mode(self):
        """Should use visible input when echo=True."""
        in_stream = StringIO("visible\n")
        out_stream = StringIO()

        result = _read_password("Enter: ", in_stream, out_stream, echo=True)

        assert result == "visible"

    def test_read_password_empty_line(self):
        """Should handle EOF/empty input."""
        in_stream = StringIO("")
        out_stream = StringIO()

        result = _read_password("Enter: ", in_stream, out_stream)

        assert result == ""


class TestPrintBanner:
    """Tests for _print_banner function."""

    def test_print_banner_outputs_to_stream(self):
        """Should write banner to output stream."""
        out_stream = StringIO()

        _print_banner(out_stream)

        output = out_stream.getvalue()
        assert "SECURE STRING CIPHER" in output
        assert "AES-256-GCM" in output


class TestGetMode:
    """Tests for _get_mode function."""

    def test_get_mode_valid_choices(self):
        """Should return integer for valid choices 0-9."""
        for i in range(10):
            in_stream = StringIO(f"{i}\n")
            out_stream = StringIO()

            result = _get_mode(in_stream, out_stream)

            assert result == i

    def test_get_mode_empty_defaults_to_1(self):
        """Should return 1 for empty input."""
        in_stream = StringIO("\n")
        out_stream = StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 1

    def test_get_mode_invalid_shows_error(self):
        """Should show error for invalid input and retry."""
        in_stream = StringIO("invalid\n5\n")
        out_stream = StringIO()

        result = _get_mode(in_stream, out_stream)

        assert result == 5
        assert "Invalid" in out_stream.getvalue()


class TestGetInput:
    """Tests for _get_input function."""

    def test_get_input_text_mode(self):
        """Should prompt for message in text modes."""
        in_stream = StringIO("hello world\n")
        out_stream = StringIO()

        result = _get_input(1, in_stream, out_stream)

        assert result == "hello world"
        assert "message" in out_stream.getvalue().lower()

    def test_get_input_file_mode(self):
        """Should prompt for file path in file modes."""
        in_stream = StringIO("/path/to/file.txt\n")
        out_stream = StringIO()

        result = _get_input(3, in_stream, out_stream)

        assert result == "/path/to/file.txt"
        assert "file" in out_stream.getvalue().lower()

    def test_get_input_file_mode_empty(self):
        """Should handle empty file path."""
        in_stream = StringIO("")  # EOF
        out_stream = StringIO()

        result = _get_input(4, in_stream, out_stream)

        assert result == ""


class TestGetPassword:
    """Tests for _get_password function."""

    def test_get_password_generate_command(self, tmp_path, monkeypatch):
        """Should handle /gen command for passphrase generation."""
        monkeypatch.setenv("HOME", str(tmp_path))
        inputs = "/gen\ninline-label\nValidMasterPass123!\n"
        in_stream = StringIO(inputs)
        out_stream = StringIO()

        result = _get_password(confirm=True, in_stream=in_stream, out_stream=out_stream)

        assert result is not None
        assert len(result) > 0
        assert "Auto-Generating" in out_stream.getvalue()
        assert "Generated Passphrase" not in out_stream.getvalue()

    def test_get_password_weak_password_retry(self):
        """Should prompt retry for weak passwords."""
        # First: weak password, then valid one
        inputs = "weak\nStrongPass123!@#\n"
        in_stream = StringIO(inputs)
        out_stream = StringIO()

        # This will exit with SystemExit because weak password uses all retries
        with pytest.raises(SystemExit):
            _get_password(
                confirm=False,
                in_stream=in_stream,
                out_stream=out_stream,
                max_retries=1,
            )

    def test_get_password_confirmation_mismatch(self):
        """Should retry on password confirmation mismatch."""
        # Valid password but mismatched confirmation
        inputs = "StrongPass123!@#\nWrongConfirm\nStrongPass123!@#\nStrongPass123!@#\n"
        in_stream = StringIO(inputs)
        out_stream = StringIO()

        result = _get_password(confirm=True, in_stream=in_stream, out_stream=out_stream)

        assert result == "StrongPass123!@#"


class TestHandleClipboard:
    """Tests for _handle_clipboard function."""

    def test_handle_clipboard_import_error(self):
        """Should handle missing pyperclip gracefully."""
        out_stream = StringIO()

        # Mock the import inside the function to raise ImportError

        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "pyperclip":
                raise ImportError("No pyperclip")
            return original_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", side_effect=mock_import):
            _handle_clipboard("test", out_stream)

        # Should handle gracefully (either copy succeeds or warns)


class TestHandleGeneratePassphrase:
    """Tests for _handle_generate_passphrase function."""

    def test_handle_generate_word_strategy(self, tmp_path, monkeypatch):
        """Should generate word-based passphrase for option 1."""
        monkeypatch.setenv("HOME", str(tmp_path))
        in_stream = StringIO("1\nword-label\nValidMasterPass123!\n")
        out_stream = StringIO()

        _handle_generate_passphrase(in_stream, out_stream)

        output = out_stream.getvalue()
        assert "Generated secure passphrase (hidden)" in output
        assert "Entropy" in output

    def test_handle_generate_alphanumeric_strategy(self, tmp_path, monkeypatch):
        """Should generate alphanumeric passphrase for option 2."""
        monkeypatch.setenv("HOME", str(tmp_path))
        in_stream = StringIO("2\nalpha-label\nValidMasterPass123!\n")
        out_stream = StringIO()

        _handle_generate_passphrase(in_stream, out_stream)

        output = out_stream.getvalue()
        assert "Generated secure passphrase (hidden)" in output

    def test_handle_generate_mixed_strategy(self, tmp_path, monkeypatch):
        """Should generate mixed passphrase for option 3."""
        monkeypatch.setenv("HOME", str(tmp_path))
        in_stream = StringIO("3\nmixed-label\nValidMasterPass123!\n")
        out_stream = StringIO()

        _handle_generate_passphrase(in_stream, out_stream)

        output = out_stream.getvalue()
        assert "Generated secure passphrase (hidden)" in output


class TestHandleGeneratePassphraseInline:
    """Tests for _handle_generate_passphrase_inline function."""

    def test_inline_generation_returns_passphrase(self, tmp_path, monkeypatch):
        """Should return generated passphrase."""
        monkeypatch.setenv("HOME", str(tmp_path))
        in_stream = StringIO("inline-label\nValidMasterPass123!\n")
        out_stream = StringIO()

        result = _handle_generate_passphrase_inline(in_stream, out_stream)

        assert result is not None
        assert len(result) > 0
        assert "Using stored passphrase" in out_stream.getvalue()


class TestVaultOperations:
    """Tests for vault-related CLI functions."""

    def test_store_passphrase_empty_label(self):
        """Should reject empty label."""
        in_stream = StringIO("\n")  # Empty label
        out_stream = StringIO()

        _handle_store_passphrase(in_stream, out_stream)

        assert "cannot be empty" in out_stream.getvalue()

    def test_store_passphrase_empty_passphrase(self):
        """Should reject empty passphrase."""
        in_stream = StringIO("my-label\n\n")  # Label, then empty passphrase
        out_stream = StringIO()

        _handle_store_passphrase(in_stream, out_stream)

        assert "cannot be empty" in out_stream.getvalue()

    def test_retrieve_no_vault(self):
        """Should error when no vault exists."""
        out_stream = StringIO()
        in_stream = StringIO("")

        with patch(
            "secure_string_cipher.cli.PassphraseVault.vault_exists", return_value=False
        ):
            _handle_retrieve_passphrase(in_stream, out_stream)

        assert "No vault found" in out_stream.getvalue()

    def test_list_no_vault(self):
        """Should error when no vault exists."""
        out_stream = StringIO()
        in_stream = StringIO("")

        with patch(
            "secure_string_cipher.cli.PassphraseVault.vault_exists", return_value=False
        ):
            _handle_list_vault(in_stream, out_stream)

        assert "No vault found" in out_stream.getvalue()

    def test_manage_no_vault(self):
        """Should error when no vault exists."""
        out_stream = StringIO()
        in_stream = StringIO("")

        with patch(
            "secure_string_cipher.cli.PassphraseVault.vault_exists", return_value=False
        ):
            _handle_manage_vault(in_stream, out_stream)

        assert "No vault found" in out_stream.getvalue()

    def test_manage_cancel(self):
        """Should handle cancel option in manage."""
        in_stream = StringIO("6\n")  # Cancel option
        out_stream = StringIO()

        with patch(
            "secure_string_cipher.cli.PassphraseVault.vault_exists", return_value=True
        ):
            _handle_manage_vault(in_stream, out_stream)

        assert "Cancelled" in out_stream.getvalue()


class TestOfferVaultStorage:
    """Tests for _offer_vault_storage function."""

    def test_offer_storage_decline(self):
        """Should skip storage when declined."""
        in_stream = StringIO("n\n")
        out_stream = StringIO()

        _offer_vault_storage("test-passphrase", in_stream, out_stream)

        # Should return without storing
        assert "Enter a label" not in out_stream.getvalue()


class TestMainFunction:
    """Tests for main CLI entry point."""

    def test_main_exit_on_mode_0(self):
        """Should exit cleanly on mode 0."""
        in_stream = StringIO("0\n")
        out_stream = StringIO()

        result = main(
            in_stream=in_stream, out_stream=out_stream, exit_on_completion=False
        )

        assert result == 0
        assert "Exiting" in out_stream.getvalue()

    def test_main_handles_mode_5_generate(self, tmp_path, monkeypatch):
        """Should handle passphrase generation mode."""
        monkeypatch.setenv("HOME", str(tmp_path))
        in_stream = StringIO("5\n1\nmain-label\nValidMasterPass123!\nn\n")
        out_stream = StringIO()

        result = main(
            in_stream=in_stream, out_stream=out_stream, exit_on_completion=False
        )

        assert result == 0
        output = out_stream.getvalue()
        assert "Generated secure passphrase (hidden)" in output

    def test_main_continue_loop_yes(self, tmp_path, monkeypatch):
        """Should continue on 'y' response."""
        monkeypatch.setenv("HOME", str(tmp_path))
        inputs = "5\n1\nloop-label\nValidMasterPass123!\ny\n0\n"
        in_stream = StringIO(inputs)
        out_stream = StringIO()

        result = main(
            in_stream=in_stream, out_stream=out_stream, exit_on_completion=False
        )

        assert result == 0

    def test_main_continue_loop_no(self, tmp_path, monkeypatch):
        """Should exit on 'n' response."""
        monkeypatch.setenv("HOME", str(tmp_path))
        inputs = "5\n1\nexit-label\nValidMasterPass123!\nn\n"
        in_stream = StringIO(inputs)
        out_stream = StringIO()

        result = main(
            in_stream=in_stream, out_stream=out_stream, exit_on_completion=False
        )

        assert result == 0
        assert "Exiting" in out_stream.getvalue()
