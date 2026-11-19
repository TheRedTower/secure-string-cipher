"""Key files (CLI.md section 3.4): `ssc key new`, `import` and `export`."""

from __future__ import annotations

import secrets
from pathlib import Path

from secure_string_cipher.engine import access, keyfile
from secure_string_cipher.service import vaults
from secure_string_cipher.service.context import Context
from secure_string_cipher.vault import entries


def new(path: Path, label: str | None = None) -> keyfile.KeyFile:
    """A standalone `.ssckey`, with no vault involved."""
    if label is not None:
        vaults.check_label(label)
    made = keyfile.KeyFile(
        label or _label_from(path), keyfile.timestamp(), secrets.token_bytes(32)
    )
    keyfile.write(path, made)
    return made


def _label_from(path: Path) -> str:
    """A label from the file name, or "key" if the name will not do."""
    stem = path.name.removesuffix(".ssckey").lower()
    return stem if keyfile.LABEL.fullmatch(stem) else "key"


def import_(ctx: Context, path: Path, label: str | None = None) -> str:
    """Add a key file as a vault key entry, with the key unchanged."""
    if label is not None:
        vaults.check_label(label)
    read = keyfile.read(path)
    with vaults.edit(ctx) as session:
        session.document, entry = entries.import_keyfile(session.document, read, label)
    return entry.label


def export(ctx: Context, label: str, path: Path) -> bytes:
    """Write a vault key entry as a key file. Returns its key_id."""
    with vaults.edit(ctx) as session:
        made = entries.export_keyfile(session.document, label)
    keyfile.write(path, made)
    return access.key_id(made.key)
