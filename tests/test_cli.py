"""
Test suite for string_cipher.py CLI functionality
"""
import os
import sys
import pytest
from unittest.mock import patch
from io import StringIO

# Import main function
from string_cipher import main

@pytest.fixture
def mock_stdio():
    """Mock standard input/output for testing."""
    with patch('sys.stdout', new_callable=StringIO) as mock_out:
        with patch('sys.stdin', new_callable=StringIO) as mock_in:
            yield mock_in, mock_out

class TestCLI:
    """Test command-line interface functionality."""
    
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
        assert "Result:" in output
        assert "Hello, World!" not in output  # Shouldn't contain plaintext
        
    def test_text_decryption_mode(self, mock_stdio):
        """Test text decryption through CLI."""
        mock_in, mock_out = mock_stdio
        
        # First encrypt something
        plaintext = "Hello, World!"
        password = "SecurePassword123!@#"
        with patch('sys.stdin', new_callable=StringIO) as mock_in_enc:
            mock_in_enc.write(f"1\n{plaintext}\n{password}\nn\n")
            mock_in_enc.seek(0)
            
            # Capture encrypted output
            with patch('sys.stdout', new_callable=StringIO) as mock_out_enc:
                try:
                    main()
                except SystemExit:
                    pass
                
                # Extract encrypted text
                output_lines = mock_out_enc.getvalue().split("\n")
                for line in output_lines:
                    if line.strip() and not line.startswith(("🔐", "Select", "Enter", "Copy")):
                        encrypted = line.strip()
                        break
        
        # Now test decryption
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
        assert plaintext in output

    def test_file_operations(self, tmp_path):
        """Test file encryption/decryption through CLI."""
        # Create a test file
        test_file = tmp_path / "test.txt"
        test_content = "Test content\n" * 100
        test_file.write_text(test_content)
        
        password = "SecurePassword123!@#"
        
        # Test file encryption
        with patch('sys.stdin', new_callable=StringIO) as mock_in:
            mock_in.write(f"3\n{test_file}\n{password}\n")
            mock_in.seek(0)
            
            try:
                main()
            except SystemExit:
                pass
            
            # Check if encrypted file exists
            enc_file = str(test_file) + '.enc'
            assert os.path.exists(enc_file)
            assert os.path.getsize(enc_file) > 0
        
        # Test file decryption
        with patch('sys.stdin', new_callable=StringIO) as mock_in:
            mock_in.write(f"4\n{enc_file}\n{password}\n")
            mock_in.seek(0)
            
            try:
                main()
            except SystemExit:
                pass
            
            # Check if decrypted file exists and matches original
            dec_file = str(test_file) + '.enc.dec'
            assert os.path.exists(dec_file)
            assert test_file.read_text() == open(dec_file).read()

    def test_invalid_mode_selection(self, mock_stdio):
        """Test handling of invalid mode selection."""
        mock_in, mock_out = mock_stdio
        
        mock_in.write("invalid\n")
        mock_in.seek(0)
        
        with pytest.raises(SystemExit) as e:
            main()
        assert "Invalid selection" in mock_out.getvalue()

    def test_empty_input_handling(self, mock_stdio):
        """Test handling of empty inputs."""
        mock_in, mock_out = mock_stdio
        
        # Test empty message
        mock_in.write("1\n\n")  # Select encrypt text mode, then empty message
        mock_in.seek(0)
        
        with pytest.raises(SystemExit) as e:
            main()
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
            main()
        assert "Password" in mock_out.getvalue()  # Should show password requirements