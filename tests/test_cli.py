"""
Test suite for string_cipher.py CLI functionality
"""
import os
import sys
import pytest
from unittest.mock import patch
from io import StringIO
from secure_string_cipher import encrypt_file, decrypt_file
from secure_string_cipher.cli import main

@pytest.fixture
def mock_stdio():
    """Mock standard input/output for testing."""
    with patch('sys.stdout', new_callable=StringIO) as mock_out:
        with patch('sys.stdin', new_callable=StringIO) as mock_in:
            yield mock_in, mock_out

class TestCLI:
    """Test command-line interface functionality."""
    
    @pytest.mark.skip(reason="Input capture not working in test environment")
    def test_text_encryption_mode(self, mock_stdio):
        """Test text encryption through CLI."""
        mock_in, mock_out = mock_stdio
        
        # Setup input
        inputs = [
            "1",  # Encrypt text mode
            "Hello, World!",  # Message
            "SecurePassword123!@#",  # Password
            "n"  # Don't copy to clipboard
        ]
        mock_in.write("\n".join(inputs))
        mock_in.seek(0)
        
        # Run main function
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code != 1  # Should not exit with error
        
        # Check output
        output = mock_out.getvalue()
        assert "🔐" in output  # Check for banner
        assert "Hello, World!" not in output  # Shouldn't contain plaintext in output
        
    def test_invalid_mode(self):
        """Test invalid mode selection in CLI."""
        mock_in = StringIO("6\n5\n")
        mock_out = StringIO()
        with pytest.raises(SystemExit):
            main(in_stream=mock_in, out_stream=mock_out)
        output = mock_out.getvalue()
        assert "Invalid choice" in output
        assert "Exiting" in output

    @pytest.mark.skip(reason="Input capture not working in test environment")
    def test_text_decryption_mode(self, mock_stdio):
        """Test text decryption through CLI."""
        from secure_string_cipher import encrypt_text, decrypt_text
        
        # First create encrypted text directly
        plaintext = "Hello, World!"
        password = "SecurePassword123!@#"
        encrypted = encrypt_text(plaintext, password)
        
        # Now test decryption through CLI
        mock_in, mock_out = mock_stdio
        inputs = [
            "2",  # Decrypt text mode
            encrypted,  # Encrypted message
            password,  # Password
            "n"  # Don't copy to clipboard
        ]
        mock_in.write("\n".join(inputs))
        mock_in.seek(0)
        
        # Run main function
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code != 1  # Should not exit with error
        
        # Check output
        output = mock_out.getvalue()
        assert "🔐" in output  # Check for banner
        assert any("🔓" in line for line in output.split('\n'))  # Check for decrypt mode

    @pytest.mark.skip(reason="File operations need direct testing")
    def test_file_operations(self, tmp_path):
        """Test file operations directly."""
        from secure_string_cipher import encrypt_file, decrypt_file
        
        # Create a test file
        test_file = tmp_path / "test.txt"
        test_content = "Test content\n" * 100
        test_file.write_text(test_content)
        
        password = "SecurePassword123!@#"
        enc_file = str(test_file) + '.enc'
        dec_file = str(test_file) + '.dec'
        
        # Test direct encryption
        encrypt_file(str(test_file), enc_file, password)
        assert os.path.exists(enc_file)
        assert os.path.getsize(enc_file) > 0
        
        # Test direct decryption
        decrypt_file(enc_file, dec_file, password)
        assert os.path.exists(dec_file)
        with open(dec_file, 'r') as f:
            assert f.read() == test_content

    def test_invalid_mode_selection(self, mock_stdio):
        """Test handling of invalid mode selection."""
        mock_in, mock_out = mock_stdio
        
        mock_in.write("invalid\n")
        mock_in.seek(0)
        
        with pytest.raises(SystemExit) as e:
            main(in_stream=mock_in, out_stream=mock_out)
        assert "Invalid selection" in mock_out.getvalue()

    def test_empty_input_handling(self, mock_stdio):
        """Test handling of empty inputs."""
        mock_in, mock_out = mock_stdio
        
        # Test empty message
        mock_in.write("1\n\n")  # Select encrypt text mode, then empty message
        mock_in.seek(0)
        
        with pytest.raises(SystemExit) as e:
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
        
        with pytest.raises(SystemExit) as e:
            main(in_stream=mock_in, out_stream=mock_out)
        assert "Password" in mock_out.getvalue()  # Should show password requirements