"""
secure_string_cipher - Core encryption functionality
"""

from importlib.metadata import PackageNotFoundError, version

from .audit_log import (
    AuditEvent,
    AuditLevel,
    AuditLogger,
    audit_auth_failure,
    audit_event,
    audit_rate_limit,
    get_audit_logger,
)
from .cli import main
from .core import (
    CryptoError,
    FileMetadata,
    StreamProcessor,
    compute_key_commitment,
    decrypt_file,
    decrypt_text,
    derive_key,
    derive_key_from_key_file,
    encrypt_file,
    encrypt_text,
    generate_key_pair,
    verify_key_commitment,
)
from .keychain_backend import (
    KeychainError,
    KeychainUnavailableError,
    KeychainVaultBackend,
    is_keychain_available,
)
from .passphrase_generator import generate_passphrase
from .passphrase_manager import BACKEND_FILE, BACKEND_KEYCHAIN, PassphraseVault
from .rate_limiter import RateLimiter, RateLimitError, get_global_limiter, rate_limited
from .secure_memory import SecureBytes, SecureString, has_secure_memory, secure_wipe
from .security import SecurityError
from .timing_safe import (
    add_timing_jitter,
    check_password_strength,
    constant_time_compare,
)
from .utils import ProgressBar, colorize, secure_overwrite

try:
    __version__ = version("secure-string-cipher")
except PackageNotFoundError:
    __version__ = "0.0.0"
__author__ = "TheRedTower"
__email__ = "security@avondenecloud.uk"

__all__ = [
    # Encryption
    "encrypt_text",
    "decrypt_text",
    "encrypt_file",
    "decrypt_file",
    "derive_key",
    "derive_key_from_key_file",
    "generate_key_pair",
    "StreamProcessor",
    "FileMetadata",
    # Key commitment
    "compute_key_commitment",
    "verify_key_commitment",
    # Exceptions
    "CryptoError",
    "SecurityError",
    # Security utilities
    "check_password_strength",
    "constant_time_compare",
    "add_timing_jitter",
    # Secure memory
    "SecureString",
    "SecureBytes",
    "secure_wipe",
    "has_secure_memory",
    # Passphrase management
    "generate_passphrase",
    "PassphraseVault",
    "BACKEND_FILE",
    "BACKEND_KEYCHAIN",
    # Keychain
    "KeychainVaultBackend",
    "KeychainError",
    "KeychainUnavailableError",
    "is_keychain_available",
    # Rate limiting
    "RateLimiter",
    "RateLimitError",
    "rate_limited",
    "get_global_limiter",
    # Audit logging
    "AuditLogger",
    "AuditEvent",
    "AuditLevel",
    "get_audit_logger",
    "audit_event",
    "audit_auth_failure",
    "audit_rate_limit",
    # CLI utilities
    "colorize",
    "secure_overwrite",
    "ProgressBar",
    "main",
]
