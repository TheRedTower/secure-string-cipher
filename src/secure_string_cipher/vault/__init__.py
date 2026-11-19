"""The vault (VAULT.md): named secrets for SSC files, in a local SSC file."""

from secure_string_cipher.vault.document import Document, Entry, Profile, Ref
from secure_string_cipher.vault.store import Session, create, default_path, edit, load

__all__ = [
    "Document",
    "Entry",
    "Profile",
    "Ref",
    "Session",
    "create",
    "default_path",
    "edit",
    "load",
]
