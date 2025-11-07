"""
Test suite for string_cipher.py CLI functionality
"""

import os
from io import StringIO
from unittest.mock import patch

import pytest

from secure_string_cipher import decrypt_file, encrypt_file
from secure_string_cipher.cli import main


@pytest.fixture
def mock_stdio():
    """Mock standard input/output for testing."""
    with patch("sys.stdout", new_callable=StringIO) as mock_out:
        with patch("sys.stdin", new_callable=StringIO) as mock_in:
            yield mock_in, mock_out


class TestCLI:
    """Test command-line interface functionality."""

    def test_text_encryption_mode(self, mock_stdio):
        """Test text encryption through CLI."""
        mock_in, mock_out = mock_stdio

        # Setup input: mode, message, password, confirm password
        inputs = [
            "1",  # Encrypt text mode
            "Hello, World!",  # Message
            "G7$hV9!mK2#xp",  # Password (meets strength requirements)
            "G7$hV9!mK2#xp",  # Confirm
        ]
        mock_in.write("\n".join(inputs) + "\n")
        mock_in.seek(0)

        # Run main function
        main(in_stream=mock_in, out_stream=mock_out, exit_on_completion=False)

        # Check output
        output = mock_out.getvalue()
        assert "🔐" in output  # Check for banner
        assert "Hello, World!" not in output  # Shouldn't contain plaintext in output

    def test_invalid_mode(self):
        """Test invalid mode selection in CLI."""
        mock_in = StringIO("99\n0\n")
        mock_out = StringIO()
        with pytest.raises(SystemExit):
            main(in_stream=mock_in, out_stream=mock_out)
        output = mock_out.getvalue()
        assert "Invalid choice" in output
        assert "Exiting" in output

    def test_text_decryption_mode(self, mock_stdio):
        """Test text decryption through CLI."""
        from secure_string_cipher import encrypt_text

        # First create encrypted text directly
        plaintext = "Hello, World!"
        password = "G7$hV9!mK2#xp"
        encrypted = encrypt_text(plaintext, password)

        # Now test decryption through CLI
        mock_in, mock_out = mock_stdio
        inputs = [
            "2",  # Decrypt text mode
            encrypted,  # Encrypted message
            password,  # Password
        ]
        mock_in.write("\n".join(inputs) + "\n")
        mock_in.seek(0)

        # Run main function
        main(in_stream=mock_in, out_stream=mock_out, exit_on_completion=False)

        # Check output
        output = mock_out.getvalue()
        assert "🔐" in output  # Check for banner
        # Decrypt result should print (plaintext may appear in output lines)
        assert plaintext in output

    def test_file_operations(self, tmp_path):
        """Test file operations directly."""

        # Create a test file
        test_file = tmp_path / "test.txt"
        test_content = "Test content\n" * 100
        test_file.write_text(test_content)

        password = "SecurePassword123!@#"
        enc_file = str(test_file) + ".enc"
        dec_file = str(test_file) + ".dec"

        # Test direct encryption
        encrypt_file(str(test_file), enc_file, password)
        assert os.path.exists(enc_file)
        assert os.path.getsize(enc_file) > 0

        # Test direct decryption
        decrypt_file(enc_file, dec_file, password)
        assert os.path.exists(dec_file)
        with open(dec_file) as f:
            assert f.read() == test_content

    def test_invalid_mode_selection(self, mock_stdio):
        """Test handling of invalid mode selection."""
        mock_in, mock_out = mock_stdio

        mock_in.write("invalid\n")
        mock_in.seek(0)

        with pytest.raises(SystemExit):
            main(in_stream=mock_in, out_stream=mock_out)
        assert "Invalid selection" in mock_out.getvalue()

    def test_empty_input_handling(self, mock_stdio):
        """Test handling of empty inputs."""
        mock_in, mock_out = mock_stdio

        # Test empty message
        mock_in.write("1\n\n")  # Select encrypt text mode, then empty message
        mock_in.seek(0)

        with pytest.raises(SystemExit):
            main(in_stream=mock_in, out_stream=mock_out)
        assert "No message provided" in mock_out.getvalue()

    def test_password_validation(self, mock_stdio):
        """Test password validation in CLI."""
        mock_in, mock_out = mock_stdio

        # Test with weak password
        inputs = [
            "1",  # Encrypt text mode
            "test message",  # Message
            "weak",  # Weak password
        ]
        mock_in.write("\n".join(inputs))
        mock_in.seek(0)

        with pytest.raises(SystemExit):
            main(in_stream=mock_in, out_stream=mock_out)
        assert "Password" in mock_out.getvalue()  # Should show password requirements

    def test_continue_loop_functionality(self):
        """Test continue loop allows multiple operations."""
        inputs = [
            "1",  # Text encryption mode
            "test message",  # Message
            "G7$hV9!mK2#xp",  # Password (strong, no common patterns)
            "G7$hV9!mK2#xp",  # Confirm
            "y",  # Continue
            "1",  # Encrypt again
            "another message",  # Second message
            "G7$hV9!mK2#xp",  # Same password
            "G7$hV9!mK2#xp",  # Confirm
            "n",  # Don't continue (exit)
        ]

        in_stream = StringIO("\n".join(inputs))
        out_stream = StringIO()

        with pytest.raises(SystemExit):  # Should exit cleanly after 'n'
            main(in_stream=in_stream, out_stream=out_stream)

        output = out_stream.getvalue()
        assert "Continue? (y/n):" in output
        assert output.count("Continue? (y/n):") >= 1  # Should appear at least once

    def test_continue_loop_exit_on_n(self):
        """Test continue loop exits properly on 'n'."""
        inputs = [
            "1",  # Text encryption mode
            "test",  # Message
            "G7$hV9!mK2#xp",  # Password
            "G7$hV9!mK2#xp",  # Confirm
            "n",  # Don't continue - should exit
        ]

        in_stream = StringIO("\n".join(inputs))
        out_stream = StringIO()

        with pytest.raises(SystemExit) as exc_info:
            main(in_stream=in_stream, out_stream=out_stream)

        # Should exit with code 0 (clean exit)
        assert exc_info.value.code == 0
        output = out_stream.getvalue()
        assert "Continue? (y/n):" in output

    def test_password_retry_limit(self):
        """Test password retry logic with 5-attempt limit."""
        inputs = [
            "1",  # Text encryption mode
            "test message",  # Message
            "wrong1",  # Wrong password 1
            "wrong1",  # Confirm
            "wrong2",  # Wrong password 2
            "wrong2",  # Confirm
            "wrong3",  # Wrong password 3
            "wrong3",  # Confirm
            "wrong4",  # Wrong password 4
            "wrong4",  # Confirm
            "wrong5",  # Wrong password 5
            "wrong5",  # Confirm
            # Should exit before any more attempts
        ]

        in_stream = StringIO("\n".join(inputs))
        out_stream = StringIO()

        with pytest.raises(SystemExit) as exc_info:
            main(in_stream=in_stream, out_stream=out_stream)

        assert exc_info.value.code == 1  # Should exit with error
        output = out_stream.getvalue()
        assert "Maximum password attempts" in output or "5" in output
        assert "attempts remaining" in output

    def test_password_retry_success_on_retry(self):
        """Test password retry succeeds on valid attempt."""
        inputs = [
            "1",  # Text encryption mode
            "test message",  # Message
            "wrong1",  # Wrong password
            "wrong1",  # Confirm
            "G7$hV9!mK2#xp",  # Correct password
            "G7$hV9!mK2#xp",  # Confirm
            "n",  # Don't continue
        ]

        in_stream = StringIO("\n".join(inputs))
        out_stream = StringIO()

        with pytest.raises(SystemExit) as exc_info:
            main(in_stream=in_stream, out_stream=out_stream)

        # Should complete successfully and exit cleanly
        assert exc_info.value.code == 0
        output = out_stream.getvalue()
        assert "attempts remaining" in output  # Should show retry message
        assert "Continue? (y/n):" in output  # Should reach continue prompt

    @patch("pyperclip.copy")
    def test_clipboard_integration_success(self, mock_copy):
        """Test clipboard integration works when pyperclip available."""
        mock_copy.return_value = None  # Successful copy

        inputs = [
            "1",  # Text encryption mode
            "test message",  # Message
            "G7$hV9!mK2#xp",  # Password
            "G7$hV9!mK2#xp",  # Confirm password
            "n",  # Don't continue
        ]

        in_stream = StringIO("\n".join(inputs))
        out_stream = StringIO()

        with pytest.raises(SystemExit):
            main(in_stream=in_stream, out_stream=out_stream)

        output = out_stream.getvalue()
        assert "📋 Copied to clipboard!" in output
        mock_copy.assert_called_once()

    @patch("pyperclip.copy")
    def test_clipboard_integration_import_error(self, mock_copy):
        """Test clipboard handles ImportError gracefully."""
        # Simulate ImportError when trying to copy
        mock_copy.side_effect = ImportError("No module named 'pyperclip'")

        inputs = [
            "1",  # Text encryption mode
            "test message",  # Message
            "G7$hV9!mK2#xp",  # Password
            "G7$hV9!mK2#xp",  # Confirm password
            "n",  # Don't continue
        ]

        in_stream = StringIO("\n".join(inputs))
        out_stream = StringIO()

        with pytest.raises(SystemExit):
            main(in_stream=in_stream, out_stream=out_stream)

        output = out_stream.getvalue()
        assert "⚠️  Clipboard unavailable" in output

    @patch("pyperclip.copy")
    def test_clipboard_integration_general_error(self, mock_copy):
        """Test clipboard handles general exceptions gracefully."""
        mock_copy.side_effect = Exception("Clipboard error")

        inputs = [
            "1",  # Text encryption mode
            "test message",  # Message
            "G7$hV9!mK2#xp",  # Password
            "G7$hV9!mK2#xp",  # Confirm password
            "n",  # Don't continue
        ]

        in_stream = StringIO("\n".join(inputs))
        out_stream = StringIO()

        with pytest.raises(SystemExit):
            main(in_stream=in_stream, out_stream=out_stream)

        output = out_stream.getvalue()
        assert "⚠️  Could not copy to clipboard" in output

    def test_continue_loop_multiple_operations(self):
        """Test continue loop handles multiple consecutive operations."""
        inputs = [
            "1",  # Text encryption mode
            "first message",  # Message
            "G7$hV9!mK2#xp",  # Password
            "G7$hV9!mK2#xp",  # Confirm password
            "y",  # Continue
            "1",  # Text encryption mode again
            "second message",  # Different message
            "G7$hV9!mK2#xp",  # Same password
            "G7$hV9!mK2#xp",  # Confirm password
            "y",  # Continue again
            "1",  # Text encryption mode third time
            "third message",  # Third message
            "G7$hV9!mK2#xp",  # Same password
            "G7$hV9!mK2#xp",  # Confirm password
            "n",  # Finally exit
        ]

        in_stream = StringIO("\n".join(inputs))
        out_stream = StringIO()

        with pytest.raises(SystemExit) as exc_info:
            main(in_stream=in_stream, out_stream=out_stream)

        assert exc_info.value.code == 0  # Should exit cleanly
        output = out_stream.getvalue()
        # Should see continue prompt multiple times
        assert output.count("Continue? (y/n):") >= 3
