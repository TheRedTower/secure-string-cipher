"""SSC v2 managed-key implementation package.

This package is introduced as a parallel implementation path for the v2
managed-key architecture. It exports the v2 dataclasses and helpers listed
in ``__all__``; these symbols are available under ``secure_string_cipher.v2``
and are not re-exported from the package root.
"""

from .decrypt import decrypt_v2_file, decrypt_v2_text
from .encrypt import (
    CombinedCredential,
    KeyCredential,
    PasswordCredential,
    V2Credential,
    encrypt_v2_file,
    encrypt_v2_text,
)
from .envelope import V2Header
from .vault_service import V2VaultService

__all__ = [
    "decrypt_v2_file",
    "decrypt_v2_text",
    "encrypt_v2_file",
    "encrypt_v2_text",
    "CombinedCredential",
    "KeyCredential",
    "PasswordCredential",
    "V2Credential",
    "V2Header",
    "V2VaultService",
]
