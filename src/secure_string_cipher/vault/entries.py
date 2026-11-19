"""Password and key entries (VAULT.md section 3.1), and the factors they
make for files (ACCESS.md sections 2.1 and 2.2).

Every function takes a document and returns a new one: documents are
immutable, and a Session writes whatever document it ends up holding.
"""

from __future__ import annotations

import dataclasses
import secrets
import unicodedata
from datetime import datetime

from secure_string_cipher.engine import access, keyfile
from secure_string_cipher.errors import VaultError
from secure_string_cipher.vault.document import Document, Entry


def find(document: Document, label: str) -> Entry:
    """The entry called `label`, of any status."""
    for entry in document.entries:
        if entry.label == label:
            return entry
    raise VaultError(f'There is no vault entry "{label}".')


def by_id(document: Document, entry_id: bytes) -> Entry | None:
    return next((e for e in document.entries if e.id == entry_id), None)


def _new_id(document: Document) -> bytes:
    """16 random bytes, unique in the vault and so never reused: entries
    are never deleted, only archived or revoked."""
    taken = {e.id for e in document.entries}
    while (entry_id := secrets.token_bytes(access.ENTRY_ID_SIZE)) in taken:
        pass  # pragma: no cover - 2**-128
    return entry_id


def _add(document: Document, entry: Entry) -> Document:
    if any(e.label == entry.label for e in document.entries):
        raise VaultError(f'There is already a vault entry "{entry.label}".')
    return dataclasses.replace(document, entries=(*document.entries, entry))


def add_password(
    document: Document, label: str, password: str, *, created: datetime | None = None
) -> tuple[Document, Entry]:
    """Add a password entry. The password is stored NFC-normalised, which
    is also what the factor hashes (ACCESS.md section 2.1)."""
    entry = Entry(
        id=_new_id(document),
        label=label,
        kind="password",
        secret=unicodedata.normalize("NFC", password),
        created=keyfile.timestamp(created),
    )
    return _add(document, entry), entry


def add_key(
    document: Document,
    label: str,
    key: bytes | None = None,
    *,
    created: datetime | None = None,
) -> tuple[Document, Entry]:
    """Add a key entry: a new random key, or `key` when importing one."""
    entry = Entry(
        id=_new_id(document),
        label=label,
        kind="key",
        secret=secrets.token_bytes(access.KEY_SIZE) if key is None else key,
        created=keyfile.timestamp(created),
    )
    return _add(document, entry), entry


def import_keyfile(
    document: Document, key_file: keyfile.KeyFile, label: str | None = None
) -> tuple[Document, Entry]:
    """`ssc key import`: the same key, so its `key_id` and the files it opens
    do not change. The label defaults to the key file's, and the entry keeps
    the key file's creation time."""
    for entry in document.entries:
        if entry.kind == "key" and entry.secret == key_file.key:
            raise VaultError(f'This key is already the vault entry "{entry.label}".')
    entry = Entry(
        id=_new_id(document),
        label=key_file.label if label is None else label,
        kind="key",
        secret=key_file.key,
        created=key_file.created,
    )
    return _add(document, entry), entry


def export_keyfile(document: Document, label: str) -> keyfile.KeyFile:
    """`ssc key export`: a key entry as a key file. A revoked entry is not
    exported, since SSC refuses to use it."""
    entry = find(document, label)
    if entry.kind != "key" or not isinstance(entry.secret, bytes):
        raise VaultError(f'The vault entry "{label}" is not a key.')
    _refuse_revoked(entry)
    return keyfile.KeyFile(entry.label, entry.created, entry.secret)


def _set_status(document: Document, label: str, status: str) -> Document:
    entry = find(document, label)
    changed = dataclasses.replace(entry, status=status)
    return dataclasses.replace(
        document,
        entries=tuple(changed if e is entry else e for e in document.entries),
    )


def archive(document: Document, label: str) -> Document:
    """Stop offering an entry for new files. It still decrypts."""
    entry = find(document, label)
    if entry.status != "active":
        raise VaultError(f'The vault entry "{label}" is already {entry.status}.')
    return _set_status(document, label, "archived")


def revoke(document: Document, label: str) -> Document:
    """Refuse an entry from now on. This is advisory: a copy of the secret
    still opens every file it opened (ACCESS.md section 6). Revoking is
    final."""
    entry = find(document, label)
    if entry.status == "revoked":
        raise VaultError(f'The vault entry "{label}" is already revoked.')
    return _set_status(document, label, "revoked")


def _refuse_revoked(entry: Entry) -> None:
    if entry.status == "revoked":
        raise VaultError(f'The vault entry "{entry.label}" is revoked.')


def factor(document: Document, label: str) -> access.NewFactor:
    """The factor `vault:<label>` adds to a new file (CLI.md section 2).
    Only an active entry is offered for new files."""
    entry = find(document, label)
    _refuse_revoked(entry)
    if entry.status != "active":
        raise VaultError(
            f'The vault entry "{label}" is archived, so it is not used for new files.'
        )
    if isinstance(entry.secret, str):
        return access.new_vault_password(entry.id, entry.secret)
    if entry.kind == "key":
        return access.new_key(entry.secret)
    return access.new_recovery(entry.secret)


def credentials(document: Document) -> access.Credentials:
    """What the vault can supply to open a file: every entry that is not
    revoked. Password entries are found by the `entry_id` a file names,
    keys by their `key_id`, and recovery codes are each tried."""
    usable = [e for e in document.entries if e.status != "revoked"]
    return access.Credentials(
        entry_passwords={e.id: e.secret for e in usable if isinstance(e.secret, str)},
        keys=[
            e.secret for e in usable if e.kind == "key" and isinstance(e.secret, bytes)
        ],
        recovery_codes=[
            e.secret
            for e in usable
            if e.kind == "recovery" and isinstance(e.secret, bytes)
        ],
    )
