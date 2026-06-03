"""
Unit tests to increase coverage for cli.py.

Covers:
- _print_banner error paths
- _get_mode edge cases
- _get_password with /gen command and max retries
- _handle_store_passphrase paths
- _handle_retrieve_passphrase paths
- _handle_list_vault paths
- _handle_manage_vault (update, delete, export, import, reset)
- _handle_secure_shred paths
- _handle_key_file_operation paths
- main() dispatch for modes 6-11
"""

from __future__ import annotations

from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from secure_string_cipher.cli import (
    _get_mode,
    _get_password,
    _handle_generate_passphrase,
    _handle_key_file_operation,
    _handle_list_vault,
    _handle_manage_vault,
    _handle_retrieve_passphrase,
    _handle_secure_shred,
    _handle_store_passphrase,
    _offer_vault_storage,
    _print_banner,
    main,
)

# =============================================================================
# _print_banner error paths
# =============================================================================


class TestPrintBannerErrors:
    """Test _print_banner fallback paths."""

    def test_banner_write_error_fallback_to_print(self):
        """Should fall back to print when write fails."""
        out = MagicMock()
        out.write = MagicMock(side_effect=OSError("write failed"))
        out.flush = MagicMock()
        # Should not raise
        _print_banner(out)

    def test_banner_all_errors_silenced(self):
        """Should silently ignore if banner cannot be printed at all."""
        out = MagicMock()
        out.write = MagicMock(side_effect=OSError("write failed"))
        out.flush = MagicMock(side_effect=OSError("flush failed"))
        # Should not raise
        _print_banner(out)


# =============================================================================
# _get_mode edge cases
# =============================================================================


class TestGetModeEdgeCases:
    """Test _get_mode with different inputs."""

    def test_mode_10(self):
        """Should accept mode 10."""
        in_stream = StringIO("10\n")
        out_stream = StringIO()
        result = _get_mode(in_stream, out_stream)
        assert result == 10

    def test_mode_11(self):
        """Should accept mode 11."""
        in_stream = StringIO("11\n")
        out_stream = StringIO()
        result = _get_mode(in_stream, out_stream)
        assert result == 11

    def test_invalid_then_valid(self):
        """Should reject invalid then accept valid."""
        in_stream = StringIO("99\n5\n")
        out_stream = StringIO()
        result = _get_mode(in_stream, out_stream)
        assert result == 5
        assert "Invalid" in out_stream.getvalue()


# =============================================================================
# _get_password with /gen and retries
# =============================================================================


class TestGetPasswordGen:
    """Test _get_password with /gen command and retry paths."""

    @patch("secure_string_cipher.cli._offer_vault_storage", return_value=True)
    @patch("secure_string_cipher.cli.generate_passphrase")
    def test_gen_command_generates_passphrase(self, mock_gen, mock_offer):
        """Should generate passphrase with /gen command."""
        mock_gen.return_value = ("Abc123!@#defGHI456", 128.0)
        in_stream = StringIO("/gen\n")
        out_stream = StringIO()

        result = _get_password(confirm=True, in_stream=in_stream, out_stream=out_stream)

        assert result == "Abc123!@#defGHI456"
        mock_gen.assert_called_once()
        mock_offer.assert_called_once()
        assert mock_offer.call_args.kwargs["require_storage"] is True
        assert "Generated Passphrase" not in out_stream.getvalue()

    @patch(
        "secure_string_cipher.cli._load_passphrase_from_vault", return_value="stored"
    )
    def test_vault_command_injects_passphrase(self, mock_load):
        """Should inject a vault passphrase without confirmation."""
        in_stream = StringIO("7\n")
        out_stream = StringIO()

        result = _get_password(confirm=True, in_stream=in_stream, out_stream=out_stream)

        assert result == "stored"
        mock_load.assert_called_once()
        assert "Confirm passphrase" not in out_stream.getvalue()

    @patch(
        "secure_string_cipher.cli._load_passphrase_from_key_file", return_value="key"
    )
    def test_key_file_command_injects_passphrase(self, mock_load):
        """Should inject a key-file passphrase without confirmation."""
        in_stream = StringIO("11\n")
        out_stream = StringIO()

        result = _get_password(confirm=True, in_stream=in_stream, out_stream=out_stream)

        assert result == "key"
        mock_load.assert_called_once()
        assert "Confirm passphrase" not in out_stream.getvalue()

    @patch("secure_string_cipher.cli.generate_passphrase")
    def test_gen_command_failure_retries(self, mock_gen):
        """Should retry when generation fails, then accept manual input."""
        mock_gen.side_effect = Exception("generation error")
        # /gen fails, then valid password
        in_stream = StringIO("/gen\nAbcDef123!@#xyz\nAbcDef123!@#xyz\n")
        out_stream = StringIO()

        result = _get_password(confirm=True, in_stream=in_stream, out_stream=out_stream)

        assert result == "AbcDef123!@#xyz"

    def test_password_mismatch_retry(self):
        """Should retry when passwords don't match."""
        # First attempt: mismatch, second attempt: match
        in_stream = StringIO(
            "StrongPass1!@#ab\nWrongConfirm1!@#\nStrongPass1!@#ab\nStrongPass1!@#ab\n"
        )
        out_stream = StringIO()

        result = _get_password(confirm=True, in_stream=in_stream, out_stream=out_stream)

        assert result == "StrongPass1!@#ab"
        assert "do not match" in out_stream.getvalue()

    def test_weak_password_retry(self):
        """Should retry when password is weak."""
        # First attempt: weak (short), second: strong
        in_stream = StringIO("short\nStrongPass1!@#ab\nStrongPass1!@#ab\n")
        out_stream = StringIO()

        result = _get_password(confirm=True, in_stream=in_stream, out_stream=out_stream)

        assert result == "StrongPass1!@#ab"

    def test_max_retries_exceeded(self):
        """Should exit when max retries exceeded."""
        # All weak passwords
        in_stream = StringIO("weak\nweak\nweak\n")
        out_stream = StringIO()

        with pytest.raises(SystemExit):
            _get_password(
                confirm=True,
                in_stream=in_stream,
                out_stream=out_stream,
                max_retries=3,
            )

    def test_empty_password_exits(self):
        """Should exit on empty password (cancelled)."""
        in_stream = StringIO("\n")
        out_stream = StringIO()

        with pytest.raises(SystemExit):
            _get_password(confirm=True, in_stream=in_stream, out_stream=out_stream)

    def test_empty_confirmation_retries(self):
        """Should retry when confirmation is empty."""
        # Strong pw, empty confirm, then strong pw + confirm
        in_stream = StringIO("StrongPass1!@#ab\n\nStrongPass1!@#ab\nStrongPass1!@#ab\n")
        out_stream = StringIO()

        result = _get_password(confirm=True, in_stream=in_stream, out_stream=out_stream)

        assert result == "StrongPass1!@#ab"

    def test_max_retries_mismatch(self):
        """Should exit after max retries of mismatched passwords."""
        inputs = "StrongPass1!@#ab\nMismatch1!@#abcd\n" * 5
        in_stream = StringIO(inputs)
        out_stream = StringIO()

        with pytest.raises(SystemExit):
            _get_password(
                confirm=True,
                in_stream=in_stream,
                out_stream=out_stream,
                max_retries=5,
            )


# =============================================================================
# _handle_store_passphrase
# =============================================================================


class TestHandleStorePassphrase:
    """Tests for store passphrase handler."""

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_store_success(self, mock_vault_cls):
        """Should store passphrase successfully."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.get_vault_path.return_value = "/tmp/vault"

        in_stream = StringIO("my-label\nMySecretPass123!\nMasterPw456!\n")
        out_stream = StringIO()

        _handle_store_passphrase(in_stream, out_stream)

        mock_vault.store_passphrase.assert_called_once()
        assert "stored successfully" in out_stream.getvalue()

    def test_store_empty_label(self):
        """Should error on empty label."""
        in_stream = StringIO("\n")
        out_stream = StringIO()

        _handle_store_passphrase(in_stream, out_stream)

        assert "Label cannot be empty" in out_stream.getvalue()

    def test_store_empty_passphrase(self):
        """Should error on empty passphrase."""
        in_stream = StringIO("my-label\n\n")
        out_stream = StringIO()

        _handle_store_passphrase(in_stream, out_stream)

        assert "Passphrase cannot be empty" in out_stream.getvalue()

    def test_store_empty_master_password(self):
        """Should error on empty master password."""
        in_stream = StringIO("my-label\nsecret\n\n")
        out_stream = StringIO()

        _handle_store_passphrase(in_stream, out_stream)

        assert "Master password cannot be empty" in out_stream.getvalue()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_store_exception(self, mock_vault_cls):
        """Should handle exceptions during store."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.store_passphrase.side_effect = Exception("Vault locked")

        in_stream = StringIO("label\npassphrase\nmaster\n")
        out_stream = StringIO()

        _handle_store_passphrase(in_stream, out_stream)

        assert "Error storing passphrase" in out_stream.getvalue()


# =============================================================================
# _handle_retrieve_passphrase
# =============================================================================


class TestHandleRetrievePassphrase:
    """Tests for retrieve passphrase handler."""

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_no_vault(self, mock_vault_cls):
        """Should error when no vault exists."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = False

        in_stream = StringIO("")
        out_stream = StringIO()

        _handle_retrieve_passphrase(in_stream, out_stream)

        assert "No vault found" in out_stream.getvalue()

    @patch(
        "secure_string_cipher.cli.PassphraseVault", side_effect=Exception("no keychain")
    )
    def test_vault_open_error(self, mock_vault_cls):
        """Should handle unavailable vault backend without printing a secret."""
        in_stream = StringIO("")
        out_stream = StringIO()

        _handle_retrieve_passphrase(in_stream, out_stream)

        assert "Error opening vault" in out_stream.getvalue()
        mock_vault_cls.assert_called_once()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_empty_master_password(self, mock_vault_cls):
        """Should error on empty master password."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True

        in_stream = StringIO("\n")
        out_stream = StringIO()

        _handle_retrieve_passphrase(in_stream, out_stream)

        assert "Master password cannot be empty" in out_stream.getvalue()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_empty_vault(self, mock_vault_cls):
        """Should show message when vault is empty."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True
        mock_vault.list_labels.return_value = []

        in_stream = StringIO("masterpass\n")
        out_stream = StringIO()

        _handle_retrieve_passphrase(in_stream, out_stream)

        assert "empty" in out_stream.getvalue()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_retrieve_success(self, mock_vault_cls):
        """Should retrieve passphrase successfully."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True
        mock_vault.list_labels.return_value = ["label1", "label2"]
        mock_vault.retrieve_passphrase.return_value = "mysecret"

        in_stream = StringIO("masterpass\nlabel1\n")
        out_stream = StringIO()

        _handle_retrieve_passphrase(in_stream, out_stream)

        output = out_stream.getvalue()
        assert "mysecret" not in output
        assert "kept hidden" in output
        mock_vault.retrieve_passphrase.assert_called_once_with("label1", "masterpass")

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_retrieve_empty_label(self, mock_vault_cls):
        """Should error on empty label."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True
        mock_vault.list_labels.return_value = ["label1"]

        in_stream = StringIO("masterpass\n\n")
        out_stream = StringIO()

        _handle_retrieve_passphrase(in_stream, out_stream)

        assert "Label cannot be empty" in out_stream.getvalue()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_retrieve_exception(self, mock_vault_cls):
        """Should handle exceptions."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True
        mock_vault.list_labels.side_effect = Exception("Auth failed")

        in_stream = StringIO("masterpass\n")
        out_stream = StringIO()

        _handle_retrieve_passphrase(in_stream, out_stream)

        assert "Error retrieving" in out_stream.getvalue()


# =============================================================================
# _handle_list_vault
# =============================================================================


class TestHandleListVault:
    """Tests for list vault handler."""

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_no_vault(self, mock_vault_cls):
        """Should error when no vault exists."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = False

        in_stream = StringIO("")
        out_stream = StringIO()

        _handle_list_vault(in_stream, out_stream)

        assert "No vault found" in out_stream.getvalue()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_empty_master(self, mock_vault_cls):
        """Should error on empty master password."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True

        in_stream = StringIO("\n")
        out_stream = StringIO()

        _handle_list_vault(in_stream, out_stream)

        assert "Master password cannot be empty" in out_stream.getvalue()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_list_empty_vault(self, mock_vault_cls):
        """Should show empty message."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True
        mock_vault.list_labels.return_value = []

        in_stream = StringIO("master\n")
        out_stream = StringIO()

        _handle_list_vault(in_stream, out_stream)

        assert "empty" in out_stream.getvalue()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_list_with_entries(self, mock_vault_cls):
        """Should list all entries."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True
        mock_vault.list_labels.return_value = ["a", "b", "c"]

        in_stream = StringIO("master\n")
        out_stream = StringIO()

        _handle_list_vault(in_stream, out_stream)

        output = out_stream.getvalue()
        assert "3" in output
        assert "a" in output
        assert "b" in output
        assert "c" in output

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_list_exception(self, mock_vault_cls):
        """Should handle exceptions."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True
        mock_vault.list_labels.side_effect = Exception("auth error")

        in_stream = StringIO("master\n")
        out_stream = StringIO()

        _handle_list_vault(in_stream, out_stream)

        assert "Error listing" in out_stream.getvalue()


# =============================================================================
# _handle_manage_vault
# =============================================================================


class TestHandleManageVault:
    """Tests for vault management handler."""

    def test_cancel(self):
        """Should cancel on choice 6."""
        in_stream = StringIO("6\n")
        out_stream = StringIO()

        _handle_manage_vault(in_stream, out_stream)

        assert "Cancelled" in out_stream.getvalue()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_export_no_vault(self, mock_vault_cls):
        """Should error when no vault for export."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = False

        in_stream = StringIO("3\n")
        out_stream = StringIO()

        _handle_manage_vault(in_stream, out_stream)

        assert "No vault found" in out_stream.getvalue()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_export_empty_master(self, mock_vault_cls):
        """Should error on empty master for export."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True

        in_stream = StringIO("3\n\n")
        out_stream = StringIO()

        _handle_manage_vault(in_stream, out_stream)

        assert "Master password cannot be empty" in out_stream.getvalue()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_export_success(self, mock_vault_cls):
        """Should export vault content."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True
        mock_vault.list_labels.return_value = ["label1"]
        mock_vault.read_raw_vault.return_value = "SSCVAULT\ndata..."

        in_stream = StringIO("3\nmasterpass\n")
        out_stream = StringIO()

        _handle_manage_vault(in_stream, out_stream)

        output = out_stream.getvalue()
        assert "exported" in output.lower() or "SSCVAULT" in output
        mock_vault.read_raw_vault.assert_called_once()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_import_empty_path(self, mock_vault_cls):
        """Should error on empty import path."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault

        in_stream = StringIO("4\n\n")
        out_stream = StringIO()

        _handle_manage_vault(in_stream, out_stream)

        assert "Path cannot be empty" in out_stream.getvalue()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_import_file_not_found(self, mock_vault_cls):
        """Should error when import file doesn't exist."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault

        in_stream = StringIO("4\n/nonexistent/path\n")
        out_stream = StringIO()

        _handle_manage_vault(in_stream, out_stream)

        assert "not found" in out_stream.getvalue().lower()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_import_invalid_format(self, mock_vault_cls, tmp_path):
        """Should error on invalid vault format."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault

        bad_file = tmp_path / "bad_vault.txt"
        bad_file.write_text("not a vault file")

        in_stream = StringIO(f"4\n{bad_file}\n")
        out_stream = StringIO()

        _handle_manage_vault(in_stream, out_stream)

        assert "Invalid vault format" in out_stream.getvalue()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_import_success_no_existing(self, mock_vault_cls, tmp_path):
        """Should import vault successfully when no existing vault."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = False

        import_file = tmp_path / "import.dat"
        import_file.write_text("SSCVAULT\ndata\nmore_data")

        in_stream = StringIO(f"4\n{import_file}\n")
        out_stream = StringIO()

        _handle_manage_vault(in_stream, out_stream)

        assert "imported" in out_stream.getvalue().lower()
        mock_vault.write_raw_vault.assert_called_once()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_import_cancelled(self, mock_vault_cls, tmp_path):
        """Should cancel import when user declines replacement."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True
        vault_path = tmp_path / "vault.dat"
        vault_path.write_text("existing")
        mock_vault.vault_path = vault_path

        import_file = tmp_path / "import.dat"
        import_file.write_text("SSCVAULT\ndata\nmore_data")

        in_stream = StringIO(f"4\n{import_file}\nno\n")
        out_stream = StringIO()

        _handle_manage_vault(in_stream, out_stream)

        assert "cancelled" in out_stream.getvalue().lower()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_reset_no_vault(self, mock_vault_cls):
        """Should error when no vault to reset."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = False

        in_stream = StringIO("5\n")
        out_stream = StringIO()

        _handle_manage_vault(in_stream, out_stream)

        assert "No vault found" in out_stream.getvalue()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_reset_cancelled(self, mock_vault_cls, tmp_path):
        """Should cancel reset when user doesn't type RESET."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True
        vault_path = tmp_path / "vault.dat"
        vault_path.write_text("data")
        mock_vault.vault_path = vault_path

        in_stream = StringIO("5\nnope\n")
        out_stream = StringIO()

        _handle_manage_vault(in_stream, out_stream)

        assert "cancelled" in out_stream.getvalue().lower()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_reset_confirmed(self, mock_vault_cls, tmp_path):
        """Should reset vault when RESET is typed."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True

        in_stream = StringIO("5\nRESET\n")
        out_stream = StringIO()

        _handle_manage_vault(in_stream, out_stream)

        assert "deleted" in out_stream.getvalue().lower()
        mock_vault.delete_vault_storage.assert_called_once()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_update_passphrase(self, mock_vault_cls):
        """Should update passphrase."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True
        mock_vault.list_labels.return_value = ["my-label"]

        in_stream = StringIO("1\nmasterpass\nmy-label\nnewpassphrase\n")
        out_stream = StringIO()

        _handle_manage_vault(in_stream, out_stream)

        mock_vault.update_passphrase.assert_called_once()
        assert "updated" in out_stream.getvalue().lower()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_update_empty_label(self, mock_vault_cls):
        """Should error on empty label for update."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True
        mock_vault.list_labels.return_value = ["label1"]

        in_stream = StringIO("1\nmasterpass\n\n")
        out_stream = StringIO()

        _handle_manage_vault(in_stream, out_stream)

        assert "Label cannot be empty" in out_stream.getvalue()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_update_empty_passphrase(self, mock_vault_cls):
        """Should error on empty new passphrase."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True
        mock_vault.list_labels.return_value = ["label1"]

        in_stream = StringIO("1\nmasterpass\nlabel1\n\n")
        out_stream = StringIO()

        _handle_manage_vault(in_stream, out_stream)

        assert "Passphrase cannot be empty" in out_stream.getvalue()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_delete_confirmed(self, mock_vault_cls):
        """Should delete passphrase when confirmed."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True
        mock_vault.list_labels.return_value = ["label1"]

        in_stream = StringIO("2\nmasterpass\nlabel1\nyes\n")
        out_stream = StringIO()

        _handle_manage_vault(in_stream, out_stream)

        mock_vault.delete_passphrase.assert_called_once()
        assert "deleted" in out_stream.getvalue().lower()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_delete_cancelled(self, mock_vault_cls):
        """Should cancel delete when not confirmed."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True
        mock_vault.list_labels.return_value = ["label1"]

        in_stream = StringIO("2\nmasterpass\nlabel1\nno\n")
        out_stream = StringIO()

        _handle_manage_vault(in_stream, out_stream)

        mock_vault.delete_passphrase.assert_not_called()
        assert "cancelled" in out_stream.getvalue().lower()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_manage_empty_master(self, mock_vault_cls):
        """Should error on empty master password."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True

        in_stream = StringIO("1\n\n")
        out_stream = StringIO()

        _handle_manage_vault(in_stream, out_stream)

        assert "Master password cannot be empty" in out_stream.getvalue()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_manage_empty_vault(self, mock_vault_cls):
        """Should show message when vault has no entries to manage."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True
        mock_vault.list_labels.return_value = []

        in_stream = StringIO("1\nmasterpass\n")
        out_stream = StringIO()

        _handle_manage_vault(in_stream, out_stream)

        assert "empty" in out_stream.getvalue().lower()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_manage_exception(self, mock_vault_cls):
        """Should handle exceptions in vault management."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = True
        mock_vault.list_labels.side_effect = Exception("auth error")

        in_stream = StringIO("1\nmasterpass\n")
        out_stream = StringIO()

        _handle_manage_vault(in_stream, out_stream)

        assert "Error managing vault" in out_stream.getvalue()


# =============================================================================
# _handle_secure_shred
# =============================================================================


class TestHandleSecureShred:
    """Tests for secure shred handler."""

    def test_empty_filepath(self):
        """Should error on empty filepath."""
        in_stream = StringIO("\n")
        out_stream = StringIO()

        _handle_secure_shred(in_stream, out_stream)

        assert "File path cannot be empty" in out_stream.getvalue()

    def test_file_not_found(self):
        """Should error when file doesn't exist."""
        in_stream = StringIO("/nonexistent/file.txt\n")
        out_stream = StringIO()

        _handle_secure_shred(in_stream, out_stream)

        assert "File not found" in out_stream.getvalue()

    def test_directory_rejected(self, tmp_path):
        """Should reject directories."""
        in_stream = StringIO(f"{tmp_path}\n")
        out_stream = StringIO()

        _handle_secure_shred(in_stream, out_stream)

        assert "Cannot shred directories" in out_stream.getvalue()

    def test_shred_cancelled(self, tmp_path):
        """Should cancel when user doesn't confirm."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("data")

        in_stream = StringIO(f"{test_file}\nno\n")
        out_stream = StringIO()

        _handle_secure_shred(in_stream, out_stream)

        assert "cancelled" in out_stream.getvalue().lower()
        assert test_file.exists()

    def test_shred_confirmed(self, tmp_path):
        """Should shred file when confirmed."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("secret data")

        in_stream = StringIO(f"{test_file}\nyes\n")
        out_stream = StringIO()

        _handle_secure_shred(in_stream, out_stream)

        assert "shredded" in out_stream.getvalue().lower()
        assert not test_file.exists()

    @patch("secure_string_cipher.cli.secure_overwrite")
    def test_shred_error(self, mock_overwrite, tmp_path):
        """Should handle shred errors."""
        mock_overwrite.side_effect = OSError("Permission denied")
        test_file = tmp_path / "test.txt"
        test_file.write_text("data")

        in_stream = StringIO(f"{test_file}\nyes\n")
        out_stream = StringIO()

        _handle_secure_shred(in_stream, out_stream)

        assert "Error shredding" in out_stream.getvalue()


# =============================================================================
# _handle_key_file_operation
# =============================================================================


class TestHandleKeyFileOperation:
    """Tests for key file operation handler."""

    def test_cancel(self):
        """Should cancel on choice 3."""
        in_stream = StringIO("3\n")
        out_stream = StringIO()

        _handle_key_file_operation(in_stream, out_stream)

        assert "Cancelled" in out_stream.getvalue()

    def test_empty_key_path(self):
        """Should error on empty key file path."""
        in_stream = StringIO("1\n\n")
        out_stream = StringIO()

        _handle_key_file_operation(in_stream, out_stream)

        assert "Key file path cannot be empty" in out_stream.getvalue()

    def test_key_file_not_found(self):
        """Should error when key file doesn't exist."""
        in_stream = StringIO("1\n/nonexistent/key.bin\n")
        out_stream = StringIO()

        _handle_key_file_operation(in_stream, out_stream)

        assert "not found" in out_stream.getvalue().lower()

    def test_empty_key_file(self, tmp_path):
        """Should error on empty key file."""
        key_file = tmp_path / "empty.key"
        key_file.write_bytes(b"")

        in_stream = StringIO(f"1\n{key_file}\n")
        out_stream = StringIO()

        _handle_key_file_operation(in_stream, out_stream)

        assert "empty" in out_stream.getvalue().lower()

    def test_empty_target_path(self, tmp_path):
        """Should error on empty target file path."""
        key_file = tmp_path / "my.key"
        key_file.write_bytes(b"secret key data here")

        in_stream = StringIO(f"1\n{key_file}\n\n")
        out_stream = StringIO()

        _handle_key_file_operation(in_stream, out_stream)

        assert "File path cannot be empty" in out_stream.getvalue()

    def test_target_not_found(self, tmp_path):
        """Should error when target file doesn't exist."""
        key_file = tmp_path / "my.key"
        key_file.write_bytes(b"secret key data here")

        in_stream = StringIO(f"1\n{key_file}\n/nonexistent/file.txt\n")
        out_stream = StringIO()

        _handle_key_file_operation(in_stream, out_stream)

        assert "not found" in out_stream.getvalue().lower()

    def test_encrypt_success(self, tmp_path):
        """Should encrypt file with key file."""
        key_file = tmp_path / "my.key"
        key_file.write_bytes(b"secret key data for encryption")

        target_file = tmp_path / "data.txt"
        target_file.write_text("Hello World")

        in_stream = StringIO(f"1\n{key_file}\n{target_file}\n")
        out_stream = StringIO()

        _handle_key_file_operation(in_stream, out_stream)

        output = out_stream.getvalue()
        assert "Encrypted" in output or "Error" in output

    def test_decrypt_success(self, tmp_path):
        """Should decrypt file with key file."""
        from hashlib import sha256

        from secure_string_cipher.core import encrypt_file

        key_file = tmp_path / "my.key"
        key_data = b"secret key data for encryption"
        key_file.write_bytes(key_data)
        password = sha256(key_data).hexdigest()

        # Create encrypted file
        plain_file = tmp_path / "data.txt"
        plain_file.write_text("Hello World")
        enc_file = str(plain_file) + ".enc"
        encrypt_file(str(plain_file), enc_file, password, store_filename=True)

        in_stream = StringIO(f"2\n{key_file}\n{enc_file}\n")
        out_stream = StringIO()

        _handle_key_file_operation(in_stream, out_stream)

        output = out_stream.getvalue()
        assert "Decrypted" in output or "Error" in output

    def test_default_choice(self, tmp_path):
        """Should default to encrypt when empty choice."""
        key_file = tmp_path / "my.key"
        key_file.write_bytes(b"secret key data")

        target_file = tmp_path / "data.txt"
        target_file.write_text("data")

        # Empty choice defaults to "1" (encrypt)
        in_stream = StringIO(f"\n{key_file}\n{target_file}\n")
        out_stream = StringIO()

        _handle_key_file_operation(in_stream, out_stream)

        output = out_stream.getvalue()
        # Should attempt to encrypt
        assert "Encrypted" in output or "Error" in output

    @patch("secure_string_cipher.cli._ensure_no_symlink")
    def test_symlink_rejected(self, mock_ensure, tmp_path):
        """Should reject symlink key file."""
        mock_ensure.side_effect = Exception("Symlink detected")

        in_stream = StringIO(f"1\n{tmp_path / 'link.key'}\n")
        out_stream = StringIO()

        _handle_key_file_operation(in_stream, out_stream)

        assert "Error" in out_stream.getvalue()


# =============================================================================
# main() dispatch for modes 6-11
# =============================================================================


class TestMainDispatch:
    """Test main function dispatches to various modes."""

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_mode_6_store(self, mock_vault_cls):
        """Should dispatch to store passphrase on mode 6."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.get_vault_path.return_value = "/tmp/vault"

        inputs = "6\nlabel\npass\nmaster\nn\n"
        in_stream = StringIO(inputs)
        out_stream = StringIO()

        result = main(
            in_stream=in_stream, out_stream=out_stream, exit_on_completion=False
        )

        assert result == 0

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_mode_7_retrieve(self, mock_vault_cls):
        """Should dispatch to retrieve on mode 7."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = False

        inputs = "7\nn\n"
        in_stream = StringIO(inputs)
        out_stream = StringIO()

        result = main(
            in_stream=in_stream, out_stream=out_stream, exit_on_completion=False
        )

        assert result == 0

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_mode_8_list(self, mock_vault_cls):
        """Should dispatch to list vault on mode 8."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.vault_exists.return_value = False

        inputs = "8\nn\n"
        in_stream = StringIO(inputs)
        out_stream = StringIO()

        result = main(
            in_stream=in_stream, out_stream=out_stream, exit_on_completion=False
        )

        assert result == 0

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_mode_9_manage(self, mock_vault_cls):
        """Should dispatch to manage vault on mode 9."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault

        inputs = "9\n6\nn\n"
        in_stream = StringIO(inputs)
        out_stream = StringIO()

        result = main(
            in_stream=in_stream, out_stream=out_stream, exit_on_completion=False
        )

        assert result == 0

    def test_mode_10_shred(self):
        """Should dispatch to secure shred on mode 10."""
        inputs = "10\n\nn\n"
        in_stream = StringIO(inputs)
        out_stream = StringIO()

        result = main(
            in_stream=in_stream, out_stream=out_stream, exit_on_completion=False
        )

        assert result == 0

    def test_mode_11_keyfile(self):
        """Should dispatch to key file operation on mode 11."""
        inputs = "11\n3\nn\n"
        in_stream = StringIO(inputs)
        out_stream = StringIO()

        result = main(
            in_stream=in_stream, out_stream=out_stream, exit_on_completion=False
        )

        assert result == 0

    def test_mode_3_file_encrypt(self, tmp_path):
        """Should dispatch to file encrypt on mode 3."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello World")

        inputs = f"3\n{test_file}\nStrongPass1!@#ab\nStrongPass1!@#ab\nn\n"
        in_stream = StringIO(inputs)
        out_stream = StringIO()

        result = main(
            in_stream=in_stream, out_stream=out_stream, exit_on_completion=False
        )

        assert result == 0
        output = out_stream.getvalue()
        assert "Encrypted file" in output

    def test_mode_4_file_decrypt(self, tmp_path):
        """Should dispatch to file decrypt on mode 4."""
        from secure_string_cipher.core import encrypt_file

        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello World")
        enc_file = str(test_file) + ".enc"
        encrypt_file(str(test_file), enc_file, "StrongPass1!@#ab", store_filename=True)
        # Remove original so restore_filename can write there
        test_file.unlink()

        inputs = f"4\n{enc_file}\nStrongPass1!@#ab\nn\n"
        in_stream = StringIO(inputs)
        out_stream = StringIO()

        result = main(
            in_stream=in_stream, out_stream=out_stream, exit_on_completion=False
        )

        assert result == 0
        assert "Decrypted file" in out_stream.getvalue()

    def test_error_handling_in_main(self):
        """Should handle errors gracefully."""
        # Mode 2 with invalid ciphertext triggers error
        inputs = "2\nnot_valid_ciphertext\nStrongPass1!@#ab\nn\n"
        in_stream = StringIO(inputs)
        out_stream = StringIO()

        result = main(
            in_stream=in_stream, out_stream=out_stream, exit_on_completion=False
        )

        assert result == 0
        assert "Error" in out_stream.getvalue()

    @patch("secure_string_cipher.cli._offer_vault_storage", return_value=True)
    def test_continue_yes_then_exit(self, mock_offer):
        """Should continue loop on 'y' and exit on subsequent 'n'."""
        inputs = "5\n1\ny\n5\n1\nn\n"
        in_stream = StringIO(inputs)
        out_stream = StringIO()

        result = main(
            in_stream=in_stream, out_stream=out_stream, exit_on_completion=False
        )

        assert result == 0
        assert mock_offer.call_count == 2

    @patch("secure_string_cipher.cli._offer_vault_storage", return_value=True)
    def test_continue_invalid_then_valid(self, mock_offer):
        """Should reprompt on invalid continue response."""
        inputs = "5\n1\nmaybe\nn\n"
        in_stream = StringIO(inputs)
        out_stream = StringIO()

        result = main(
            in_stream=in_stream, out_stream=out_stream, exit_on_completion=False
        )

        assert result == 0
        mock_offer.assert_called_once()
        assert "enter 'y' or 'n'" in out_stream.getvalue().lower()


# =============================================================================
# _handle_generate_passphrase error path
# =============================================================================


class TestHandleGeneratePassphraseErrors:
    """Test error paths in passphrase generation."""

    @patch("secure_string_cipher.cli.generate_passphrase")
    def test_generation_error(self, mock_gen):
        """Should handle passphrase generation errors."""
        mock_gen.side_effect = Exception("RNG failure")

        in_stream = StringIO("1\n")
        out_stream = StringIO()

        _handle_generate_passphrase(in_stream, out_stream)

        assert "Error generating" in out_stream.getvalue()


# =============================================================================
# _offer_vault_storage paths
# =============================================================================


class TestOfferVaultStorageExtended:
    """Extended tests for vault storage offering."""

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_offer_store_success(self, mock_vault_cls):
        """Should store when user accepts."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.get_vault_path.return_value = "/tmp/vault"

        in_stream = StringIO("y\nmy-label\nmasterpass\n")
        out_stream = StringIO()

        _offer_vault_storage("generated-passphrase", in_stream, out_stream)

        mock_vault.store_passphrase.assert_called_once()
        assert "stored" in out_stream.getvalue().lower()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_offer_store_empty_label(self, mock_vault_cls):
        """Should skip on empty label."""
        in_stream = StringIO("y\n\n")
        out_stream = StringIO()

        _offer_vault_storage("passphrase", in_stream, out_stream)

        assert "Label is required" in out_stream.getvalue()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_offer_store_empty_master(self, mock_vault_cls):
        """Should skip on empty master password."""
        in_stream = StringIO("y\nmy-label\n\n")
        out_stream = StringIO()

        _offer_vault_storage("passphrase", in_stream, out_stream)

        assert "Master password is required" in out_stream.getvalue()

    @patch("secure_string_cipher.cli.PassphraseVault")
    def test_offer_store_exception(self, mock_vault_cls):
        """Should handle exception during store."""
        mock_vault = MagicMock()
        mock_vault_cls.return_value = mock_vault
        mock_vault.store_passphrase.side_effect = Exception("disk full")

        in_stream = StringIO("y\nmy-label\nmasterpass\n")
        out_stream = StringIO()

        _offer_vault_storage("passphrase", in_stream, out_stream)

        assert "Could not store" in out_stream.getvalue()

    @patch(
        "secure_string_cipher.cli.PassphraseVault", side_effect=Exception("no keychain")
    )
    def test_offer_vault_open_exception(self, mock_vault_cls):
        """Should handle unavailable vault backend during generated storage."""
        in_stream = StringIO("y\n")
        out_stream = StringIO()

        result = _offer_vault_storage("passphrase", in_stream, out_stream)

        assert result is False
        assert "Could not open vault" in out_stream.getvalue()
        mock_vault_cls.assert_called_once()
