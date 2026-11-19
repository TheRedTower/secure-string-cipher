"""Password and key entries, and the vault-entry factor (VAULT.md section
3.1, ACCESS.md sections 2.1 and 2.2)."""

from __future__ import annotations

import io
import secrets
import shutil
import unicodedata
from datetime import UTC, datetime
from pathlib import Path

import pytest

from secure_string_cipher.engine import access, container, keyfile
from secure_string_cipher.errors import CannotOpen, VaultError
from secure_string_cipher.vault import document as doc
from secure_string_cipher.vault import entries, store
from tests import vectorkit

CREDS = vectorkit.manifest()["credentials"]
VAULT = vectorkit.manifest()["vault"]
EMPTY = doc.Document()
WHEN = datetime(2026, 11, 18, 9, 30, tzinfo=UTC)


def open_file(data: bytes, creds: access.Credentials) -> bytes:
    out = io.BytesIO()
    container.decrypt(io.BytesIO(data), out, creds)
    return out.getvalue()


def seal(*factors: access.NewFactor) -> bytes:
    out = io.BytesIO()
    container.encrypt(io.BytesIO(b"secret"), out, [list(factors)])
    return out.getvalue()


def test_add_password_and_key_entries() -> None:
    d, work = entries.add_password(EMPTY, "work", "pass", created=WHEN)
    d, laptop = entries.add_key(d, "laptop", created=WHEN)
    assert [e.label for e in d.entries] == ["work", "laptop"]
    assert work.kind == "password" and work.secret == "pass"
    assert work.created == "2026-11-18T09:30:00Z" and work.status == "active"
    assert isinstance(laptop.secret, bytes) and len(laptop.secret) == 32
    assert work.id != laptop.id
    assert doc.parse(doc.encode(d)) == d


def test_a_password_entry_is_stored_nfc() -> None:
    _, entry = entries.add_password(EMPTY, "u", CREDS["unicode_password_nfd"])
    nfd = CREDS["unicode_password_nfd"]
    assert entry.secret == unicodedata.normalize("NFC", nfd) != nfd


def test_labels_are_unique_and_valid() -> None:
    d, _ = entries.add_password(EMPTY, "work", "pass")
    with pytest.raises(VaultError):
        entries.add_key(d, "work")
    with pytest.raises(ValueError):
        entries.add_key(d, "Not Valid")
    with pytest.raises(ValueError):
        entries.add_password(d, "empty", "")


def test_the_vault_opens_the_vault_password_vector() -> None:
    """A password entry opens a file by the entry_id it carries."""
    vector = vectorkit.valid("access-vault-password-entry")
    entry = doc.Entry(
        bytes.fromhex(CREDS["vault_entry_id"]),
        "work",
        "password",
        CREDS["password"],
        "2026-11-18T09:30:00Z",
    )
    d = doc.Document(entries=(entry,))
    data = vectorkit.read(vector["file"])
    assert open_file(data, entries.credentials(d)) == b"access\n"


def test_the_vault_opens_the_key_vector() -> None:
    d, _ = entries.add_key(EMPTY, "a", bytes.fromhex(CREDS["key_a"]))
    data = vectorkit.read(vectorkit.valid("access-key")["file"])
    assert open_file(data, entries.credentials(d)) == b"access\n"


def test_factors_round_trip_through_files() -> None:
    d, _ = entries.add_password(EMPTY, "work", "pass")
    d, _ = entries.add_key(d, "laptop")
    data = seal(entries.factor(d, "work"), entries.factor(d, "laptop"))
    assert open_file(data, entries.credentials(d)) == b"secret"
    grant = container.read_header(io.BytesIO(data)).grants[0]
    assert grant.factors is not None
    kinds = sorted(f.kind for f in grant.factors)
    assert kinds == [access.VAULT_PASSWORD, access.KEY]


def test_a_lost_vault_falls_back_to_the_typed_password() -> None:
    d, _ = entries.add_password(EMPTY, "work", "pass")
    data = seal(entries.factor(d, "work"))
    assert open_file(data, access.Credentials(passwords=["pass"])) == b"secret"


def test_archived_entries_decrypt_but_are_not_offered() -> None:
    d, _ = entries.add_key(EMPTY, "old")
    data = seal(entries.factor(d, "old"))
    d = entries.archive(d, "old")
    assert entries.find(d, "old").status == "archived"
    assert open_file(data, entries.credentials(d)) == b"secret"
    with pytest.raises(VaultError):
        entries.factor(d, "old")
    with pytest.raises(VaultError):
        entries.archive(d, "old")


def test_revoked_entries_are_refused() -> None:
    d, _ = entries.add_key(EMPTY, "lost")
    data = seal(entries.factor(d, "lost"))
    d = entries.revoke(d, "lost")
    with pytest.raises(CannotOpen):
        open_file(data, entries.credentials(d))
    for refuse in (entries.factor, entries.export_keyfile, entries.revoke):
        with pytest.raises(VaultError):
            refuse(d, "lost")
    with pytest.raises(VaultError):
        entries.archive(d, "lost")


def test_a_revoked_archived_entry_and_status_survive_a_round_trip() -> None:
    d, _ = entries.add_key(EMPTY, "k")
    d = entries.revoke(entries.archive(d, "k"), "k")
    assert doc.parse(doc.encode(d)).entries[0].status == "revoked"


def test_missing_entries_are_vault_errors() -> None:
    for call in (entries.find, entries.factor, entries.archive, entries.revoke):
        with pytest.raises(VaultError):
            call(EMPTY, "nope")


def test_a_password_entry_cannot_be_exported_as_a_key() -> None:
    d, _ = entries.add_password(EMPTY, "work", "pass")
    with pytest.raises(VaultError):
        entries.export_keyfile(d, "work")


def test_import_and_export_keep_the_key() -> None:
    parsed = keyfile.parse(vectorkit.read(vectorkit.manifest()["keyfiles"][0]["file"]))
    d, entry = entries.import_keyfile(EMPTY, parsed)
    assert entry.label == parsed.label and entry.created == parsed.created
    assert entry.secret == parsed.key
    assert entries.export_keyfile(d, entry.label) == parsed
    with pytest.raises(VaultError):  # the same key twice
        entries.import_keyfile(d, parsed, "other")
    other = keyfile.KeyFile("other", parsed.created, secrets.token_bytes(32))
    d, renamed = entries.import_keyfile(d, other, "renamed")
    assert renamed.label == "renamed"


def test_entries_persist_through_the_vault(tmp_path: Path) -> None:
    path = tmp_path / "vault.ssc"
    shutil.copyfile(vectorkit.VECTORS / VAULT["file"], path)
    device = access.Credentials(keys=[bytes.fromhex(VAULT["device_key"])])
    with store.edit(device, path) as session:
        session.document, _ = entries.add_key(session.document, "usb")
    loaded = store.load(device, path)
    assert entries.find(loaded, "usb").kind == "key"
    data = seal(entries.factor(loaded, "usb"), entries.factor(loaded, "work"))
    assert open_file(data, entries.credentials(loaded)) == b"secret"
