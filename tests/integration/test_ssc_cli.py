"""Integration tests for non-interactive CLI (ssc command)."""

from __future__ import annotations

import subprocess
import sys
from importlib.metadata import version
from unittest.mock import patch

import pytest

import secure_string_cipher.cli_args as cli_args

# =============================================================================
# CLI Integration Tests using subprocess
# =============================================================================


class TestCLIHelp:
    """Tests for CLI help output."""

    def test_ssc_help(self):
        """ssc --help should show main help."""
        result = subprocess.run(
            [sys.executable, "-m", "secure_string_cipher.cli_args", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "Secure String Cipher" in result.stdout
        assert "encrypt" in result.stdout
        assert "decrypt" in result.stdout
        assert "vault" in result.stdout

    def test_ssc_version(self):
        """ssc --version should show version."""
        result = subprocess.run(
            [sys.executable, "-m", "secure_string_cipher.cli_args", "--version"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        expected = version("secure-string-cipher")
        assert expected in result.stdout

    def test_encrypt_help(self):
        """ssc encrypt --help should show encrypt help."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "secure_string_cipher.cli_args",
                "encrypt",
                "--help",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "--text" in result.stdout or "-t" in result.stdout
        assert "--file" in result.stdout or "-f" in result.stdout
        assert "--vault" in result.stdout
        assert "--force" in result.stdout

    def test_decrypt_help(self):
        """ssc decrypt --help should show decrypt help."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "secure_string_cipher.cli_args",
                "decrypt",
                "--help",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "--text" in result.stdout or "-t" in result.stdout
        assert "--file" in result.stdout or "-f" in result.stdout

    def test_store_help(self):
        """ssc store --help should show store help."""
        result = subprocess.run(
            [sys.executable, "-m", "secure_string_cipher.cli_args", "store", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "LABEL" in result.stdout
        assert "--generate" in result.stdout or "-g" in result.stdout

    def test_vault_help(self):
        """ssc vault --help should show vault help."""
        result = subprocess.run(
            [sys.executable, "-m", "secure_string_cipher.cli_args", "vault", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "list" in result.stdout
        assert "delete" in result.stdout
        assert "export" in result.stdout
        assert "import" in result.stdout
        assert "reset" in result.stdout


class TestCLIValidation:
    """Tests for CLI argument validation."""

    def test_encrypt_requires_text_or_file(self):
        """ssc encrypt without -t or -f should error."""
        result = subprocess.run(
            [sys.executable, "-m", "secure_string_cipher.cli_args", "encrypt"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1  # EXIT_INPUT_ERROR
        assert "Error" in result.stderr

    def test_decrypt_requires_text_or_file(self):
        """ssc decrypt without -t or -f should error."""
        result = subprocess.run(
            [sys.executable, "-m", "secure_string_cipher.cli_args", "decrypt"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1  # EXIT_INPUT_ERROR
        assert "Error" in result.stderr

    def test_store_requires_label(self):
        """ssc store without label should error."""
        result = subprocess.run(
            [sys.executable, "-m", "secure_string_cipher.cli_args", "store"],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        # argparse will show error about required argument

    def test_vault_without_subcommand_errors(self):
        """ssc vault without subcommand should error."""
        result = subprocess.run(
            [sys.executable, "-m", "secure_string_cipher.cli_args", "vault"],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0


class TestCLIFileOperations:
    """Tests for CLI file operations."""

    def test_encrypt_file_not_found(self):
        """ssc encrypt -f with missing file should error."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "secure_string_cipher.cli_args",
                "encrypt",
                "-f",
                "/nonexistent/file.txt",
            ],
            capture_output=True,
            text=True,
            input="Password123!\nPassword123!\n",
        )
        assert result.returncode == 4  # EXIT_FILE_ERROR
        assert "not found" in result.stderr.lower()

    def test_decrypt_file_not_found(self):
        """ssc decrypt -f with missing file should error."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "secure_string_cipher.cli_args",
                "decrypt",
                "-f",
                "/nonexistent/file.enc",
            ],
            capture_output=True,
            text=True,
            input="Password123!\n",
        )
        assert result.returncode == 4  # EXIT_FILE_ERROR
        assert "not found" in result.stderr.lower()


# =============================================================================
# Programmatic Integration Tests
# =============================================================================


class TestProgrammaticEncryptDecrypt:
    """Tests for encrypt/decrypt using the module directly."""

    def test_text_encrypt_decrypt_roundtrip(self):
        """encrypt_text and decrypt_text should round-trip correctly."""
        from secure_string_cipher.core import decrypt_text, encrypt_text

        original = "Test message for roundtrip"
        password = "SecurePassword123!"  # pragma: allowlist secret

        encrypted = encrypt_text(original, password)
        decrypted = decrypt_text(encrypted, password)

        assert decrypted == original

    def test_file_encrypt_decrypt_roundtrip(self, tmp_path):
        """encrypt_file and decrypt_file should round-trip correctly."""
        from secure_string_cipher.core import decrypt_file, encrypt_file

        # Create test file
        test_file = tmp_path / "test.txt"
        original_content = b"Binary content for testing"
        test_file.write_bytes(original_content)

        password = "SecurePassword123!"  # pragma: allowlist secret
        encrypted_file = tmp_path / "test.txt.enc"

        # Encrypt
        encrypt_file(str(test_file), str(encrypted_file), password)
        assert encrypted_file.exists()

        # Remove original to test decryption
        test_file.unlink()

        # Decrypt
        decrypt_file(str(encrypted_file), str(test_file), password)
        assert test_file.exists()

        # Verify content
        assert test_file.read_bytes() == original_content


class TestCLIWithMockedInput:
    """Tests using mocked getpass to simulate password input."""

    @patch("getpass.getpass")
    def test_encrypt_text_with_mocked_password(self, mock_getpass, capsys):
        """encrypt -t with mocked password should succeed."""
        mock_getpass.side_effect = [
            "SecurePassword123!",  # Enter password
            "SecurePassword123!",  # Confirm password
        ]

        import argparse

        cli_args._quiet_mode = True
        cli_args._no_color = True

        args = argparse.Namespace(
            text="Secret message",
            file=None,
            vault=None,
            force=False,
            quiet=True,
            no_color=True,
        )

        result = cli_args.cmd_encrypt(args)
        assert result == 0  # EXIT_SUCCESS

        captured = capsys.readouterr()
        # Should have base64 ciphertext output
        assert len(captured.out.strip()) > 20

    @patch("getpass.getpass")
    def test_decrypt_text_wrong_password(self, mock_getpass, capsys):
        """decrypt -t with wrong password should fail."""
        import argparse

        from secure_string_cipher.core import encrypt_text

        cli_args._quiet_mode = True
        cli_args._no_color = True

        # Encrypt with correct password
        ciphertext = encrypt_text("Secret", "CorrectPassword123!")

        # Try to decrypt with wrong password
        mock_getpass.return_value = "WrongPassword123!"

        args = argparse.Namespace(
            text=ciphertext,
            file=None,
            vault=None,
            force=False,
            quiet=True,
            no_color=True,
        )

        with pytest.raises(SystemExit) as exc_info:
            cli_args.cmd_decrypt(args)
        assert exc_info.value.code == 2  # EXIT_AUTH_ERROR


class TestCLIFileEncryption:
    """Integration tests for file encryption via CLI."""

    @patch("getpass.getpass")
    def test_encrypt_file_creates_enc_file(self, mock_getpass, tmp_path):
        """encrypt -f should create .enc file."""
        mock_getpass.side_effect = ["TestPassword123!", "TestPassword123!"]

        import argparse

        cli_args._quiet_mode = True
        cli_args._no_color = True

        # Create source file
        source = tmp_path / "document.txt"
        source.write_text("Confidential content")

        args = argparse.Namespace(
            text=None,
            file=str(source),
            vault=None,
            force=False,
            quiet=True,
            no_color=True,
        )

        result = cli_args.cmd_encrypt(args)
        assert result == 0

        # Verify .enc file created
        enc_file = tmp_path / "document.txt.enc"
        assert enc_file.exists()

    @patch("getpass.getpass")
    def test_encrypt_file_refuses_overwrite(self, mock_getpass, tmp_path):
        """encrypt -f should refuse to overwrite existing .enc file."""
        mock_getpass.side_effect = ["TestPassword123!", "TestPassword123!"]

        import argparse

        cli_args._quiet_mode = True
        cli_args._no_color = True

        # Create source and pre-existing output
        source = tmp_path / "document.txt"
        source.write_text("Content")
        output = tmp_path / "document.txt.enc"
        output.write_text("Existing encrypted file")

        args = argparse.Namespace(
            text=None,
            file=str(source),
            vault=None,
            force=False,
            quiet=True,
            no_color=True,
        )

        with pytest.raises(SystemExit) as exc_info:
            cli_args.cmd_encrypt(args)
        assert exc_info.value.code == 4  # EXIT_FILE_ERROR

    @patch("getpass.getpass")
    def test_encrypt_file_with_force_overwrites(self, mock_getpass, tmp_path):
        """encrypt -f --force should overwrite existing .enc file."""
        mock_getpass.side_effect = ["TestPassword123!", "TestPassword123!"]

        import argparse

        cli_args._quiet_mode = True
        cli_args._no_color = True

        # Create source and pre-existing output
        source = tmp_path / "document.txt"
        source.write_text("New content to encrypt")
        output = tmp_path / "document.txt.enc"
        output.write_text("Old content")

        args = argparse.Namespace(
            text=None,
            file=str(source),
            vault=None,
            force=True,  # Force overwrite
            quiet=True,
            no_color=True,
        )

        result = cli_args.cmd_encrypt(args)
        assert result == 0

        from secure_string_cipher.core import decrypt_file

        decrypted = tmp_path / "decrypted.txt"
        decrypt_file(str(output), str(decrypted), "TestPassword123!")
        assert decrypted.read_text() == "New content to encrypt"

    @patch("getpass.getpass")
    def test_decrypt_file_removes_enc_suffix(self, mock_getpass, tmp_path):
        """decrypt -f should create file without .enc suffix."""
        import argparse

        from secure_string_cipher.core import encrypt_file

        cli_args._quiet_mode = True
        cli_args._no_color = True

        password = "TestPassword123!"  # pragma: allowlist secret
        mock_getpass.return_value = password

        # Create and encrypt a file
        source = tmp_path / "secret.txt"
        enc_file = tmp_path / "secret.txt.enc"
        source.write_text("Secret content")
        encrypt_file(str(source), str(enc_file), password)

        # Remove original to test decryption
        source.unlink()
        assert enc_file.exists()

        args = argparse.Namespace(
            text=None,
            file=str(enc_file),
            vault=None,
            force=False,
            quiet=True,
            no_color=True,
        )

        result = cli_args.cmd_decrypt(args)
        assert result == 0

        # Verify decrypted file created without .enc
        decrypted = tmp_path / "secret.txt"
        assert decrypted.exists()
        assert decrypted.read_text() == "Secret content"


# =============================================================================
# Quiet and Color Mode Tests
# =============================================================================


class TestQuietMode:
    """Tests for --quiet flag behavior."""

    @patch("getpass.getpass")
    def test_quiet_mode_suppresses_info(self, mock_getpass, capsys):
        """--quiet should suppress info messages."""
        mock_getpass.side_effect = ["TestPassword123!", "TestPassword123!"]

        import argparse

        cli_args._quiet_mode = True
        cli_args._no_color = True

        args = argparse.Namespace(
            text="Test",
            file=None,
            vault=None,
            force=False,
            quiet=True,
            no_color=True,
        )

        cli_args.cmd_encrypt(args)
        captured = capsys.readouterr()

        # stderr should NOT have success message in quiet mode
        assert "✓" not in captured.err


class TestNoColorMode:
    """Tests for --no-color flag behavior."""

    @patch("getpass.getpass")
    def test_no_color_removes_ansi(self, mock_getpass, capsys):
        """--no-color should remove ANSI escape codes."""
        mock_getpass.side_effect = ["TestPassword123!", "TestPassword123!"]

        import argparse

        cli_args._quiet_mode = False
        cli_args._no_color = True

        args = argparse.Namespace(
            text="Test",
            file=None,
            vault=None,
            force=False,
            quiet=False,
            no_color=True,
        )

        cli_args.cmd_encrypt(args)
        captured = capsys.readouterr()

        # Should NOT have ANSI escape codes
        assert "\033[" not in captured.err
