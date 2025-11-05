"""
Test suite for string_cipher.py core functionality
"""
import os
import tempfile
import pytest
from pathlib import Path
from string_cipher import (
    _derive_key, _check_password_strength, _encrypt_text, _decrypt_text,
    _encrypt_stream, _decrypt_stream, CryptoError, StreamProcessor
)

@pytest.fixture
def temp_file():
    """Create a temporary file for testing."""
    fd, path = tempfile.mkstemp()
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass

class TestPasswordValidation:
    """Test password strength validation."""
    
    def test_password_minimum_length(self):
        """Test password length requirements."""
        short_pass = "Ab1!defgh"  # 9 chars
        valid, msg = _check_password_strength(short_pass)
        assert not valid
        assert "12 characters" in msg

    def test_password_complexity(self):
        """Test password complexity requirements."""
        test_cases = [
            ("ABCD1234!@#$", False, "lowercase"),
            ("abcd1234!@#$", False, "uppercase"),
            ("ABCDabcd!@#$", False, "digits"),
            ("ABCDabcd1234", False, "symbols"),
            ("ABCDabcd1234!@#$", True, "acceptable"),
        ]
        
        for password, expected_valid, expected_msg in test_cases:
            valid, msg = _check_password_strength(password)
            assert valid == expected_valid
            if not valid:
                assert expected_msg in msg.lower()

    def test_common_patterns(self):
        """Test rejection of common password patterns."""
        weak_passwords = [
            "Password123!@#",
            "Admin123!@#$",
            "Qwerty123!@#",
        ]
        
        for password in weak_passwords:
            valid, msg = _check_password_strength(password)
            assert not valid
            assert "common patterns" in msg.lower()

class TestKeyDerivation:
    """Test key derivation functionality."""
    
    def test_key_length(self):
        """Test if derived key has correct length."""
        key = _derive_key("testpassword123!@#", b"salt"*4)
        assert len(key) == 32  # AES-256 key length

    def test_key_consistency(self):
        """Test if same password+salt produces same key."""
        password = "testpassword123!@#"
        salt = b"salt"*4
        key1 = _derive_key(password, salt)
        key2 = _derive_key(password, salt)
        assert key1 == key2

    def test_salt_impact(self):
        """Test if different salts produce different keys."""
        password = "testpassword123!@#"
        salt1 = b"salt1"*4
        salt2 = b"salt2"*4
        key1 = _derive_key(password, salt1)
        key2 = _derive_key(password, salt2)
        assert key1 != key2

class TestTextEncryption:
    """Test text encryption/decryption."""
    
    @pytest.mark.parametrize("text", [
        "Hello, World!",
        "Special chars: !@#$%^&*()",
        "Unicode: 🔒🔑📝",
        "A" * 1000,  # Long text
        "",  # Empty string
    ])
    def test_text_roundtrip(self, text):
        """Test if text can be encrypted and decrypted correctly."""
        password = "SecurePassword123!@#"
        encrypted = _encrypt_text(text, password)
        decrypted = _decrypt_text(encrypted, password)
        assert decrypted == text

    def test_wrong_password(self):
        """Test decryption with wrong password."""
        text = "Hello, World!"
        encrypted = _encrypt_text(text, "correctpass123!@#")
        with pytest.raises(CryptoError):
            _decrypt_text(encrypted, "wrongpass123!@#")

    def test_corrupted_data(self):
        """Test handling of corrupted encrypted data."""
        with pytest.raises(CryptoError):
            _decrypt_text("invalid base64!", "password123!@#")

class TestFileEncryption:
    """Test file encryption/decryption."""
    
    def test_file_roundtrip(self, temp_file):
        """Test if file can be encrypted and decrypted correctly."""
        original_data = b"Hello, World!\n" * 1000
        password = "SecurePassword123!@#"
        
        # Write original data
        with open(temp_file, 'wb') as f:
            f.write(original_data)
        
        # Encrypt
        enc_file = temp_file + '.enc'
        with StreamProcessor(temp_file, 'rb') as r, StreamProcessor(enc_file, 'wb') as w:
            _encrypt_stream(r, w, password)
        
        # Decrypt
        dec_file = temp_file + '.dec'
        with StreamProcessor(enc_file, 'rb') as r, StreamProcessor(dec_file, 'wb') as w:
            _decrypt_stream(r, w, password)
        
        # Verify
        with open(dec_file, 'rb') as f:
            decrypted_data = f.read()
        
        assert decrypted_data == original_data
        
        # Cleanup
        os.unlink(enc_file)
        os.unlink(dec_file)

    def test_streaming_large_file(self, temp_file):
        """Test encryption/decryption of large file in chunks."""
        # Create 10MB file
        chunk_size = 64 * 1024  # 64 KiB
        chunks = 160  # ~10 MB
        original_data = os.urandom(chunk_size * chunks)
        
        with open(temp_file, 'wb') as f:
            f.write(original_data)
        
        password = "SecurePassword123!@#"
        enc_file = temp_file + '.enc'
        dec_file = temp_file + '.dec'
        
        # Encrypt
        with StreamProcessor(temp_file, 'rb') as r, StreamProcessor(enc_file, 'wb') as w:
            _encrypt_stream(r, w, password)
        
        # Decrypt
        with StreamProcessor(enc_file, 'rb') as r, StreamProcessor(dec_file, 'wb') as w:
            _decrypt_stream(r, w, password)
        
        # Verify
        with open(dec_file, 'rb') as f:
            decrypted_data = f.read()
        
        assert decrypted_data == original_data
        
        # Cleanup
        os.unlink(enc_file)
        os.unlink(dec_file)

class TestStreamProcessor:
    """Test StreamProcessor functionality."""
    
    def test_overwrite_protection(self, temp_file):
        """Test that overwrite protection works."""
        # Create existing file
        with open(temp_file, 'wb') as f:
            f.write(b"existing data")
        
        # Try to open for writing without confirmation
        with pytest.raises(CryptoError, match="Operation cancelled"):
            with StreamProcessor(temp_file, 'wb') as _:
                pass  # Should not reach here

    def test_progress_tracking(self, temp_file):
        """Test progress tracking functionality."""
        test_data = b"test data" * 1000
        
        # Write test file
        with open(temp_file, 'wb') as f:
            f.write(test_data)
        
        # Read with progress tracking
        with StreamProcessor(temp_file, 'rb') as sp:
            data = b""
            while True:
                chunk = sp.read(1024)
                if not chunk:
                    break
                data += chunk
                assert sp.bytes_processed <= len(test_data)
            
            assert sp.bytes_processed == len(test_data)
            assert data == test_data