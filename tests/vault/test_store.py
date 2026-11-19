"""The vault file and its master-password grant (VAULT.md sections 1 and 2,
FORMAT.md sections 7.3 to 7.5)."""

from __future__ import annotations

import errno
import os
import shutil
import sys
import threading
from pathlib import Path

import pytest

from secure_string_cipher import fs
from secure_string_cipher.engine import access
from secure_string_cipher.errors import CannotOpen, FormatError, Reason, VaultError
from secure_string_cipher.vault import document as doc
from secure_string_cipher.vault import store
from tests import vectorkit

VAULT = vectorkit.manifest()["vault"]
MASTER = access.Credentials(passwords=[VAULT["master_password"]])
DEVICE = access.Credentials(keys=[bytes.fromhex(VAULT["device_key"])])
WHEN = "2026-11-18T09:30:00Z"


@pytest.fixture
def vector_vault(tmp_path: Path) -> Path:
    path = tmp_path / "vault.ssc"
    shutil.copyfile(vectorkit.VECTORS / VAULT["file"], path)
    return path


def entry(label: str) -> doc.Entry:
    return doc.Entry(os.urandom(16), label, "password", "pw " + label, WHEN)


def test_the_default_path_is_the_user_data_folder() -> None:
    path = store.default_path()
    assert path.name == "vault.ssc"
    assert "ssc" in path.parent.parts[-2:]


def test_loads_the_vector_vault(vector_vault: Path) -> None:
    for creds in (MASTER, DEVICE):
        loaded = store.load(creds, vector_vault)
        assert loaded.to_json() == VAULT["document"]


def test_a_wrong_master_password_cannot_open(vector_vault: Path) -> None:
    with pytest.raises(CannotOpen):
        store.load(access.Credentials(passwords=["nope"]), vector_vault)


def test_no_vault_is_a_vault_error(tmp_path: Path) -> None:
    for path in (tmp_path / "vault.ssc", tmp_path / "missing" / "vault.ssc"):
        with pytest.raises(VaultError):
            store.load(MASTER, path)
        with pytest.raises(VaultError), store.edit(MASTER, path):
            pass
    assert list(tmp_path.iterdir()) == []


def test_create_then_load(tmp_path: Path) -> None:
    path = tmp_path / "data" / "ssc" / "vault.ssc"
    store.create("hunter2 but longer", path)
    assert store.load(access.Credentials(passwords=["hunter2 but longer"]), path) == (
        doc.Document()
    )
    grants = store._read(
        path, access.Credentials(passwords=["hunter2 but longer"])
    ).grants
    assert len(grants) == 1 and store._is_master(grants[0])


def test_create_is_owner_only(tmp_path: Path) -> None:
    if os.name != "posix":
        pytest.skip("POSIX modes")
    path = tmp_path / "new" / "vault.ssc"
    store.create("pw", path)
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert store.lock_path(path).stat().st_mode & 0o777 == 0o600


def test_create_never_replaces_a_vault(vector_vault: Path) -> None:
    before = vector_vault.read_bytes()
    with pytest.raises(VaultError):
        store.create("pw", vector_vault)
    assert vector_vault.read_bytes() == before


def test_create_refuses_an_empty_master_password(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        store.create("", tmp_path / "vault.ssc")


# --- changing the master password (the Phase 3 gate) -----------------------------


def test_changing_the_master_password_rewraps_one_grant(vector_vault: Path) -> None:
    before = vectorkit.split(vector_vault.read_bytes())
    with store.edit(DEVICE, vector_vault) as session:
        old_key = session._opened.file_key
        session.change_master_password(VAULT["master_password"], "a new one")
    after_bytes = vector_vault.read_bytes()
    after = vectorkit.split(after_bytes)

    # History is not recorded yet (Phase 3, step 5), so the payload and the
    # fixed header are untouched; only the master grant is new.
    assert after.fixed_header == before.fixed_header
    assert after.payload == before.payload
    old = store._read(vector_vault, DEVICE)
    assert old._opened.file_key == old_key
    old_grants = access.parse_access_body(before.access_body)
    new_grants = access.parse_access_body(after.access_body)
    assert len(new_grants) == len(old_grants)
    changed = [
        i for i, (a, b) in enumerate(zip(old_grants, new_grants, strict=True)) if a != b
    ]
    assert changed == [0]
    assert store._is_master(new_grants[0])

    with pytest.raises(CannotOpen):
        store.load(MASTER, vector_vault)
    new = access.Credentials(passwords=["a new one"])
    assert store.load(new, vector_vault).to_json() == VAULT["document"]
    assert store.load(DEVICE, vector_vault).to_json() == VAULT["document"]


def test_changing_needs_the_current_master_password(vector_vault: Path) -> None:
    before = vector_vault.read_bytes()
    with pytest.raises(CannotOpen), store.edit(DEVICE, vector_vault) as session:
        session.change_master_password("not it", "a new one")
    assert vector_vault.read_bytes() == before


def test_changing_refuses_an_empty_new_password(vector_vault: Path) -> None:
    with pytest.raises(ValueError), store.edit(MASTER, vector_vault) as session:
        session.change_master_password(VAULT["master_password"], "")


# --- changing the contents (FORMAT.md section 7.4) ---------------------------------


def test_new_contents_keep_the_file_key_and_grants(vector_vault: Path) -> None:
    before = vectorkit.split(vector_vault.read_bytes())
    with store.edit(MASTER, vector_vault) as session:
        old_key = session._opened.file_key
        session.document = doc.Document(entries=(entry("home"),))
    after = vectorkit.split(vector_vault.read_bytes())
    assert after.access_body == before.access_body
    assert after.fixed_header != before.fixed_header  # a fresh payload nonce
    assert after.access_mac != before.access_mac
    reopened = store._read(vector_vault, DEVICE)
    assert reopened._opened.file_key == old_key
    assert [e.label for e in reopened.document.entries] == ["home"]


def test_every_content_change_gets_a_fresh_nonce(tmp_path: Path) -> None:
    path = tmp_path / "vault.ssc"
    store.create("pw", path)
    creds = access.Credentials(passwords=["pw"])
    nonces = {vectorkit.split(path.read_bytes()).fixed_header}
    for label in ("a", "b", "c"):
        with store.edit(creds, path) as session:
            session.document = doc.Document(entries=(entry(label),))
        nonces.add(vectorkit.split(path.read_bytes()).fixed_header)
    assert len(nonces) == 4


def test_contents_and_password_change_in_one_write(vector_vault: Path) -> None:
    with store.edit(MASTER, vector_vault) as session:
        session.document = doc.Document()
        session.change_master_password(VAULT["master_password"], "both")
    assert store.load(access.Credentials(passwords=["both"]), vector_vault) == (
        doc.Document()
    )
    assert store.load(DEVICE, vector_vault) == doc.Document()


def test_an_unchanged_edit_writes_nothing(vector_vault: Path) -> None:
    before = vector_vault.stat().st_mtime_ns, vector_vault.read_bytes()
    with store.edit(MASTER, vector_vault):
        pass
    assert (vector_vault.stat().st_mtime_ns, vector_vault.read_bytes()) == before


def test_an_error_in_the_block_writes_nothing(vector_vault: Path) -> None:
    before = vector_vault.read_bytes()
    with pytest.raises(RuntimeError), store.edit(MASTER, vector_vault) as session:
        session.document = doc.Document()
        raise RuntimeError
    assert vector_vault.read_bytes() == before


def test_a_failed_write_leaves_the_vault_as_it_was(
    vector_vault: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = vector_vault.read_bytes()

    def full(fd: int) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "fsync", full)
    with pytest.raises(OSError), store.edit(MASTER, vector_vault) as session:
        session.document = doc.Document()
    monkeypatch.undo()
    assert vector_vault.read_bytes() == before
    assert sorted(p.name for p in vector_vault.parent.iterdir()) == [
        "vault.ssc",
        "vault.ssc.lock",
    ]


def test_a_damaged_vault_is_a_format_error(vector_vault: Path) -> None:
    data = bytearray(vector_vault.read_bytes())
    data[-1] ^= 1
    vector_vault.write_bytes(bytes(data))
    with pytest.raises(FormatError) as caught:
        store.load(MASTER, vector_vault)
    assert caught.value.reason == Reason.CHUNK_AUTH


def test_a_payload_over_16_mib_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "vault.ssc"
    store.create("pw", path, doc.Document(entries=(entry("a"),)))
    monkeypatch.setattr(doc, "MAX_SIZE", 10)
    with pytest.raises(FormatError) as caught:
        store.load(access.Credentials(passwords=["pw"]), path)
    assert caught.value.reason == Reason.VAULT_DOCUMENT


# --- the lock ------------------------------------------------------------------


def test_a_held_lock_is_a_vault_error(
    vector_vault: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store, "LOCK_TIMEOUT", 0.2)
    with fs.locked(store.lock_path(vector_vault)), pytest.raises(VaultError):
        store.load(MASTER, vector_vault)


def test_two_writers_never_lose_a_change(vector_vault: Path) -> None:
    errors: list[BaseException] = []

    def add(label: str) -> None:
        try:
            with store.edit(DEVICE, vector_vault) as session:
                current = session.document
                session.document = doc.Document(
                    entries=(*current.entries, entry(label)),
                    profiles=current.profiles,
                    history=current.history,
                )
        except BaseException as error:  # pragma: no cover - reported below
            errors.append(error)

    threads = [threading.Thread(target=add, args=(f"t{i}",)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    labels = {e.label for e in store.load(DEVICE, vector_vault).entries}
    assert {"t0", "t1", "t2", "t3"} <= labels


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_an_existing_folder_is_left_as_it_is(tmp_path: Path) -> None:
    folder = tmp_path / "shared"
    folder.mkdir(mode=0o755)
    folder.chmod(0o755)
    store.create("pw", folder / "vault.ssc")
    assert folder.stat().st_mode & 0o777 == 0o755
