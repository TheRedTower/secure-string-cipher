"""Tests for inline passphrase generation feature."""

import io

import pytest

from secure_string_cipher.cli import main


class TestInlinePassphraseGeneration:
    """Test the /gen inline command during password entry."""

    def test_gen_command_alphanumeric_no_vault(self):
        """Test /gen auto-generates alphanumeric passphrase."""
        input_data = "\n".join([
            "1",           # Encrypt text
            "Hello World", # Message
            "/gen",        # Generate passphrase inline
            "n",           # Don't store in vault
            "n",           # Don't continue
        ])

        in_stream = io.StringIO(input_data)
        out_stream = io.StringIO()

        result = main(in_stream=in_stream, out_stream=out_stream, exit_on_completion=False)
        output = out_stream.getvalue()

        # Verify the inline generation flow
        assert "💡 Tip: Type '/gen'" in output
        assert "Auto-Generating Secure Passphrase" in output
        assert "Generated Passphrase:" in output
        assert "Entropy:" in output
        assert "Store this passphrase in vault?" in output
        assert "Using this passphrase for current operation" in output
        assert "Encrypted" in output
        assert result == 0

    def test_gen_command_with_test_message(self):
        """Test /gen with a different test message."""
        input_data = "\n".join([
            "1",
            "Test message",
            "/gen",
            "n",
            "n",
        ])

        in_stream = io.StringIO(input_data)
        out_stream = io.StringIO()

        result = main(in_stream=in_stream, out_stream=out_stream, exit_on_completion=False)
        output = out_stream.getvalue()

        assert "Auto-Generating Secure Passphrase" in output
        assert "Generated Passphrase:" in output
        assert result == 0

    def test_gen_command_with_vault_storage(self, tmp_path):
        """Test /gen with vault storage."""
        import os
        vault_path = tmp_path / "test_vault.enc"
        
        input_data = "\n".join([
            "1",                    # Encrypt text
            "Test message",
            "/gen",                 # Generate passphrase inline
            "y",                    # Store in vault
            "test-label",           # Label
            "ValidMasterPass123!",  # Master password
            "n",                    # Don't continue
        ])

        in_stream = io.StringIO(input_data)
        out_stream = io.StringIO()

        # Set HOME to temp directory to use default vault location
        original_home = os.environ.get("HOME")
        try:
            os.environ["HOME"] = str(tmp_path)
            result = main(in_stream=in_stream, out_stream=out_stream, exit_on_completion=False)
            output = out_stream.getvalue()

            assert "Auto-Generating Secure Passphrase" in output
            assert "Store this passphrase in vault?" in output
            assert "Passphrase 'test-label' stored in vault!" in output
            assert "Vault location:" in output
            assert "Using this passphrase for current operation" in output
            assert "Encrypted" in output
            assert result == 0
        finally:
            if original_home:
                os.environ["HOME"] = original_home
            else:
                del os.environ["HOME"]

    def test_gen_command_aliases(self):
        """Test that /generate and /g also work."""
        for alias in ["/generate", "/g"]:
            input_data = "\n".join([
                "1",
                "Test message",
                alias,         # Alternative command
                "n",
                "n",
            ])

            in_stream = io.StringIO(input_data)
            out_stream = io.StringIO()

            result = main(in_stream=in_stream, out_stream=out_stream, exit_on_completion=False)
            output = out_stream.getvalue()

            assert "Auto-Generating Secure Passphrase" in output, f"Failed for alias: {alias}"
            assert result == 0

    def test_gen_no_confirmation_required(self):
        """Test that generated passwords skip confirmation prompt."""
        # This test ensures that after /gen, there's no "Confirm passphrase:" prompt
        input_data = "\n".join([
            "1",
            "Test message",
            "/gen",
            "n",
            "n",
        ])

        in_stream = io.StringIO(input_data)
        out_stream = io.StringIO()

        result = main(in_stream=in_stream, out_stream=out_stream, exit_on_completion=False)
        output = out_stream.getvalue()

        # Should NOT ask for confirmation since password was generated
        assert output.count("Confirm passphrase:") == 0
        assert "Encrypted" in output
        assert result == 0

    def test_normal_password_still_requires_confirmation(self):
        """Test that manual passwords still require confirmation for encryption."""
        input_data = "\n".join([
            "1",
            "Test message",
            "SecurePhrase123!@#",  # Manual password (avoiding common patterns)
            "SecurePhrase123!@#",  # Confirmation
            "n",
        ])

        in_stream = io.StringIO(input_data)
        out_stream = io.StringIO()

        result = main(in_stream=in_stream, out_stream=out_stream, exit_on_completion=False)
        output = out_stream.getvalue()

        # Should ask for confirmation for manual entry
        assert "Confirm passphrase:" in output
        assert "Encrypted" in output
        assert result == 0
