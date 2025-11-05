"""
secure_string_cipher - Core encryption functionality
"""
from secure_string_cipher.core import (
    encrypt_text, decrypt_text,
    encrypt_file, decrypt_file,
    CryptoError
)
from secure_string_cipher.cli import main

__version__ = "1.0.0"
__author__ = "TheRedTower"
__email__ = "security@avondenecloud.uk"

__all__ = [
    'encrypt_text',
    'decrypt_text',
    'encrypt_file',
    'decrypt_file',
    'CryptoError',
    'main',
]