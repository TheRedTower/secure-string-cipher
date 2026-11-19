"""The vault file and its master-password grant (VAULT.md sections 1 and 2,
FORMAT.md sections 7.3 to 7.5)."""

from __future__ import annotations

import errno
import io
import os
import shutil
import sys
import threading
from pathlib import Path

import pytest

from secure_string_cipher import fs
from secure_string_cipher.engine import access, armor, container
from secure_string_cipher.errors import CannotOpen, FormatError, Reason, VaultError
from secure_string_cipher.vault import document as doc
from secure_string_cipher.vault import history, store
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


def without_history(path: Path) -> Path:
    with store.edit(MASTER, path) as session:
        session.document = history.turn_off(session.document)
    return path


def other_grants_unchanged(before: bytes, after: bytes) -> list[access.Grant]:
    """Only grant 0, the master grant, differs."""
    old = access.parse_access_body(vectorkit.split(before).access_body)
    new = access.parse_access_body(vectorkit.split(after).access_body)
    assert len(new) == len(old)
    changed = [i for i, (a, b) in enumerate(zip(old, new, strict=True)) if a != b]
    assert changed == [0]
    assert store._is_master(new[0])
    return new


@pytest.mark.parametrize("history_on", [False, True], ids=["history-off", "history-on"])
def test_changing_the_master_password_rewraps_one_grant(
    vector_vault: Path, history_on: bool
) -> None:
    """The Phase 3 gate's first half (VAULT.md section 2)."""
    if not history_on:
        without_history(vector_vault)
    before = vector_vault.read_bytes()
    expected = store.load(DEVICE, vector_vault)
    with store.edit(DEVICE, vector_vault) as session:
        old_key = session._opened.file_key
        session.change_master_password(VAULT["master_password"], "a new one")
    after = vector_vault.read_bytes()

    other_grants_unchanged(before, after)
    assert store._read(vector_vault, DEVICE)._opened.file_key == old_key
    old_parts, new_parts = vectorkit.split(before), vectorkit.split(after)
    loaded = store.load(DEVICE, vector_vault)
    if history_on:
        # The same write appends a vault-access-change event, which means
        # replacing the payload with a fresh nonce (FORMAT.md section 7.4).
        assert new_parts.fixed_header != old_parts.fixed_header
        assert loaded.history is not None and expected.history is not None
        assert loaded.history.events[:-1] == expected.history.events
        assert loaded.history.events[-1].action == "vault-access-change"
        assert loaded.entries == expected.entries
    else:
        assert new_parts.fixed_header == old_parts.fixed_header
        assert new_parts.payload == old_parts.payload
        assert loaded == expected

    with pytest.raises(CannotOpen):
        store.load(MASTER, vector_vault)
    new = access.Credentials(passwords=["a new one"])
    assert store.load(new, vector_vault) == loaded


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


def test_an_oversized_file_is_refused_without_reading_it_all(
    vector_vault: Path,
) -> None:
    with vector_vault.open("r+b") as handle:
        handle.truncate(store.max_file_size() + 1)  # sparse where supported
    with pytest.raises(FormatError) as caught:
        store.load(MASTER, vector_vault)
    assert caught.value.reason == Reason.VAULT_DOCUMENT


def test_the_largest_vault_fits_the_file_limit() -> None:
    """An armoured vault holding the largest document is still accepted."""
    out = io.BytesIO()
    writer = armor.ArmorWriter(out)
    container.encrypt(
        io.BytesIO(bytes(doc.MAX_SIZE)),
        writer,
        [[access.new_key(bytes(32))]],
    )
    writer.close()
    crlf = out.getvalue().replace(b"\n", b"\r\n")
    assert len(crlf) <= store.max_file_size()


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


# --- owner-only on Windows (VAULT.md section 1) ----------------------------------

# Well-known SIDs that would make a file readable beyond its owner.
_BROAD_SIDS = {
    "S-1-1-0": "Everyone",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
}


def _acl_sids(path: Path) -> set[str]:
    """The SIDs in a path's ACL, by number so the check does not depend on
    the language Windows is set to."""
    import subprocess

    script = (
        "(Get-Acl -LiteralPath $env:SSC_ACL_PATH).Access | ForEach-Object "
        "{ $_.IdentityReference.Translate("
        "[System.Security.Principal.SecurityIdentifier]).Value }"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "SSC_ACL_PATH": str(path)},
    )
    return set(result.stdout.split())


@pytest.mark.skipif(sys.platform != "win32", reason="Windows ACLs")
def test_the_vault_is_owner_only_on_windows(tmp_path: Path) -> None:
    """SSC sets no ACLs itself: the vault inherits its folder's, and the
    folder it lives in by default is under the user's own profile."""
    path = tmp_path / "ssc" / "vault.ssc"
    store.create("pw", path)
    for target in (path, store.lock_path(path), store.default_path().parent.parent):
        sids = _acl_sids(target)
        assert sids, target
        broad = sorted(_BROAD_SIDS[s] for s in sids & _BROAD_SIDS.keys())
        assert broad == [], f"{target} is readable by {broad}"
