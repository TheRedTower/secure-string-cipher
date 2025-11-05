"""
secure_string_cipher - Core encryption functionality
"""
from .core import (
    encrypt_text, decrypt_text,
    encrypt_file, decrypt_file,
    encrypt_stream, decrypt_stream,
    derive_key,
    CryptoError, StreamProcessor
)
from .cli import main
from .timing_safe import (
    check_password_strength,
    constant_time_compare,
    add_timing_jitter
)
from .utils import (
    colorize,
    handle_timeout,
    secure_overwrite,
    ProgressBar
)
from .secure_memory import (
    SecureString,
    SecureBytes,
    secure_wipe
)

__version__ = "1.0.0"
__author__ = "TheRedTower"
__email__ = "security@avondenecloud.uk"

__all__ = [
    # Core encryption
    'encrypt_text',
    'decrypt_text',
    'encrypt_file',
    'decrypt_file',
    'encrypt_stream',
    'decrypt_stream',
    'derive_key',
    'CryptoError',
    'StreamProcessor',
    
    # Security features
    'check_password_strength',
    'constant_time_compare',
    'add_timing_jitter',
    'SecureString',
    'SecureBytes',
    'secure_wipe',
    
    # Utilities
    'colorize',
    'handle_timeout',
    'secure_overwrite',
    'ProgressBar',
    
    # CLI
    'main',
]