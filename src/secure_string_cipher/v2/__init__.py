"""SSC v2 managed-key container format — public, semver-covered API.

Everything listed in ``__all__`` here, and in ``secure_string_cipher.v2.app``,
is public API covered by this package's version guarantees: it will not change
incompatibly outside a major version bump. Anything reached through a deeper
module path (``v2.envelope``, ``v2.keyfile``, ``v2.vault_service`` …) is
internal, and may change in a minor release — so if you find yourself needing
something from one of those, that is worth raising as an issue rather than
importing, because it means this surface is missing something.

``v2`` is not re-exported into the package root's flat namespace: the root is
v1's API, and flattening two container formats into one namespace would make
``encrypt_file`` ambiguous to a reader. Import the submodule instead::

    from secure_string_cipher import v2
    from secure_string_cipher.v2 import encrypt_v2_file, PasswordCredential

The ``app`` submodule is the layer above these primitives: it resolves a key
reference to a keyfile, decides what credential an object requires, and
enforces managed-key lifecycle policy, without prompting or exiting. Use it
when building an interface; use the primitives here when you already hold a
credential.
"""

from . import app
from .decrypt import decrypt_v2_file, decrypt_v2_text
from .encrypt import (
    CombinedCredential,
    KeyCredential,
    PasswordCredential,
    V2Credential,
    encrypt_v2_file,
    encrypt_v2_text,
)
from .envelope import GrantType, V2Header
from .key_identity import KeyStatus, KeyStorageMode, compute_fingerprint
from .keyfile import KeyFileData, load_keyfile, save_keyfile
from .vault_service import V2VaultService

__all__ = [
    # Encrypt / decrypt
    "decrypt_v2_file",
    "decrypt_v2_text",
    "encrypt_v2_file",
    "encrypt_v2_text",
    # Credentials
    "CombinedCredential",
    "KeyCredential",
    "PasswordCredential",
    "V2Credential",
    # Managed keys and their identity
    "KeyFileData",
    "KeyStatus",
    "KeyStorageMode",
    "compute_fingerprint",
    "load_keyfile",
    "save_keyfile",
    # Container metadata and key lifecycle
    "GrantType",
    "V2Header",
    "V2VaultService",
    # The application layer
    "app",
]
