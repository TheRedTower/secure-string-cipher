"""
Core encryption and decryption functions for secure-string-cipher
"""
import base64
import io

from .secure_memory import SecureString, SecureBytes
from .utils import InMemoryStreamProcessor

from .cipher import (
    encrypt_stream, decrypt_stream
)
from .errors import CryptoError

def encrypt_text(plain_text: str, passphrase: str) -> str:
    """
    Encrypt plain text using AES-256-GCM.
    
    Args:
        plain_text: The text to encrypt
        passphrase: Encryption password
        
    Returns:
        Base64-encoded encrypted text
        
    Raises:
        CryptoError: If encryption fails
    """
    # ... existing encryption code ...

def decrypt_text(token: str, passphrase: str) -> str:
    """
    Decrypt text using AES-256-GCM.
    
    Args:
        token: Base64-encoded encrypted text
        passphrase: Decryption password
        
    Returns:
        Decrypted text
        
    Raises:
        CryptoError: If decryption fails
    """
    # Use a single, clean implementation that works with StreamProcessor
    try:
        encrypted = base64.b64decode(token)
    except Exception as e:
        raise CryptoError(f"Invalid base64 data: {e}")

    ri = io.BytesIO(encrypted)
    wi = io.BytesIO()

    try:
        with StreamProcessor(ri, 'rb') as r, StreamProcessor(wi, 'wb') as w:
            decrypt_stream(r, w, passphrase)

        wi.seek(0)
        return wi.getvalue().decode('utf-8', 'ignore')
    except Exception as e:
        raise CryptoError(f"Text decryption failed: {e}")
    finally:
        ri.close()
        wi.close()

def encrypt_file(input_path: str, output_path: str, passphrase: str) -> None:
    """
    Encrypt a file using AES-256-GCM.
    
    Args:
        input_path: Path to the file to encrypt
        output_path: Path where the encrypted file will be saved
        passphrase: Encryption password
        
    Raises:
        CryptoError: If encryption fails
    """
    # ... existing file encryption code ...

def decrypt_file(input_path: str, output_path: str, passphrase: str) -> None:
    """
    Decrypt a file using AES-256-GCM.
    
    Args:
        input_path: Path to the encrypted file
        output_path: Path where the decrypted file will be saved
        passphrase: Decryption password
        
    Raises:
        CryptoError: If decryption fails
    """
    # ... existing file decryption code ...