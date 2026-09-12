"""
secure_string_cipher - Core encryption functionality
"""

from importlib.metadata import PackageNotFoundError, version

from . import v2
from .audit_log import (
    AuditEvent,
    AuditLevel,
    AuditLogger,
    audit_auth_failure,
    audit_event,
    audit_rate_limit,
    get_audit_logger,
)
from .config import (
    VaultSettings,
    load_vault_settings,
    save_vault_settings,
    set_vault_backend,
)
from .core import (
    CryptoError,
    FileMetadata,
    StreamProcessor,
    compute_key_commitment,
    decrypt_bytes,
    decrypt_file,
    decrypt_text,
    derive_key,
    derive_key_from_key_file,
    encrypt_bytes,
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
from .rate_limiter import (
    PersistentRateLimiter,
    RateLimiter,
    RateLimitError,
    get_global_limiter,
    rate_limited,
)
from .secure_memory import SecureBytes, SecureString, has_secure_memory, secure_wipe
from .security import SecurityError
from .timing_safe import (
    add_timing_jitter,
    check_password_strength,
    constant_time_compare,
)
from .utils import secure_overwrite

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
    "encrypt_bytes",
    "decrypt_bytes",
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
    "VaultSettings",
    "load_vault_settings",
    "save_vault_settings",
    "set_vault_backend",
    # Keychain
    "KeychainVaultBackend",
    "KeychainError",
    "KeychainUnavailableError",
    "is_keychain_available",
    # Rate limiting
    "RateLimiter",
    "PersistentRateLimiter",
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
    "secure_overwrite",
    # The v2 container format, as a submodule rather than flattened here
    "v2",
    # Deprecated: terminal presentation and the interactive menu's entry
    # point. Still importable, with a warning; see _DEPRECATED_EXPORTS.
    "colorize",
    "ProgressBar",
    "main",
]

# Terminal presentation and an application entry point are not part of what a
# string-encryption library offers, and `main` is the worse problem: it is
# `cli.main` (the interactive menu), while the installed `ssc` command is
# `cli_args:main` — two different functions reachable under one name. Keeping
# them importable, with a warning, until the next major version; removing them
# now would be a breaking change in a minor release.
#
# They are served lazily so that importing this package no longer pulls in the
# interactive CLI module, which it did solely to satisfy `main`.
_DEPRECATED_EXPORTS = {
    "colorize": ("secure_string_cipher.utils", "colorize"),
    "ProgressBar": ("secure_string_cipher.utils", "ProgressBar"),
    "main": ("secure_string_cipher.cli", "main"),
}


def __getattr__(name: str) -> object:
    """Serve a deprecated export, warning at the point of use.

    Reached only for names this module does not define, so the warning fires
    for exactly the deprecated set — including via ``import *``, which
    consults ``__all__`` and so comes back through here.
    """
    target = _DEPRECATED_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    import importlib
    import warnings

    module_name, attribute = target
    warnings.warn(
        f"secure_string_cipher.{name} is deprecated and will be removed in "
        f"3.0.0. It is an internal of the command-line interface, not part of "
        f"the library's API"
        + (
            "; the installed `ssc` command is secure_string_cipher.cli_args:"
            "main, which is a different function from this one"
            if name == "main"
            else f". Import it from {module_name} if you still need it"
        ),
        DeprecationWarning,
        stacklevel=2,
    )
    return getattr(importlib.import_module(module_name), attribute)
