"""Unlocking the vault with this device's key in the OS keychain
(VAULT.md section 2)."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import keyring
import keyring.errors
import pytest
from keyring.backends import fail

from secure_string_cipher.engine import access, armor
from secure_string_cipher.errors import CannotOpen, FormatError, Reason, VaultError
from secure_string_cipher.vault import keychain, store
from secure_string_cipher.vault.document import b64
from tests import vectorkit

VAULT = vectorkit.manifest()["vault"]
MASTER_PASSWORD: str = VAULT["master_password"]
MASTER = access.Credentials(passwords=[MASTER_PASSWORD])


class Memory:
    """An in-memory keychain with the keyring interface."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], str] = {}
        self.refuse = False

    def get_password(self, service: str, username: str) -> str | None:
        return self.items.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        if self.refuse:
            raise keyring.errors.PasswordSetError("locked")
        self.items[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        if (service, username) not in self.items:
            raise keyring.errors.PasswordDeleteError("missing")
        del self.items[(service, username)]


@pytest.fixture
def vector_vault(tmp_path: Path) -> Path:
    path = tmp_path / "vault.ssc"
    shutil.copyfile(vectorkit.VECTORS / VAULT["file"], path)
    return path


def test_the_vector_vault_unlocks_from_its_keychain_item(vector_vault: Path) -> None:
    chain = Memory()
    key = bytes.fromhex(VAULT["device_key"])
    chain.set_password("ssc", VAULT["keychain_account"], b64(key))
    creds = keychain.credentials(vector_vault, chain)
    assert creds.keys == [key]
    assert store.load(creds, vector_vault).to_json() == VAULT["document"]


def test_the_account_names_the_key_id() -> None:
    key = bytes.fromhex(VAULT["device_key"])
    assert keychain.account(access.key_id(key)) == VAULT["keychain_account"]


def test_an_empty_keychain_gives_no_keys(vector_vault: Path) -> None:
    creds = keychain.credentials(vector_vault, Memory())
    assert creds.keys == []
    with pytest.raises(CannotOpen):
        store.load(creds, vector_vault)


def test_a_wrong_or_damaged_keychain_item_is_ignored(vector_vault: Path) -> None:
    chain = Memory()
    for text in ("not base64!", b64(bytes(32)), b64(bytes(16))):
        chain.set_password("ssc", VAULT["keychain_account"], text)
        assert keychain.credentials(vector_vault, chain).keys == []


class Broken(Memory):
    """A backend failing with its own exception type, as Secret Service's
    SecretStorageException does, rather than a KeyringError."""

    def get_password(self, service: str, username: str) -> str | None:
        raise RuntimeError("org.freedesktop.Secret.Error.IsLocked")

    def set_password(self, service: str, username: str, password: str) -> None:
        raise RuntimeError("org.freedesktop.Secret.Error.IsLocked")


def test_a_failing_backend_falls_back_to_the_master_password(
    vector_vault: Path,
) -> None:
    assert keychain.credentials(vector_vault, Broken()).keys == []
    before = vector_vault.read_bytes()
    with store.edit(MASTER, vector_vault) as session:
        with pytest.raises(VaultError):
            keychain.add_device(session, Broken())
        assert len(session.grants) == 2
    assert vector_vault.read_bytes() == before


def test_an_oversized_armoured_vault_is_refused_before_decoding(
    vector_vault: Path,
) -> None:
    with vector_vault.open("wb") as handle:
        handle.write(armor.BEGIN + b"\n")
        handle.truncate(store.max_file_size() + 1)
    with pytest.raises(FormatError) as caught:
        keychain.credentials(vector_vault, Memory())
    assert caught.value.reason == Reason.VAULT_DOCUMENT


def test_add_device_then_unlock_with_it(vector_vault: Path) -> None:
    chain = Memory()
    with store.edit(MASTER, vector_vault) as session:
        index = keychain.add_device(session, chain)
    assert index == 2
    assert len(chain.items) == 1
    creds = keychain.credentials(vector_vault, chain)
    assert len(creds.keys) == 1
    assert (
        store.load(creds, vector_vault).to_json()["entries"]
        == VAULT["document"]["entries"]
    )
    with store.edit(creds, vector_vault) as session:
        assert keychain.this_device(session, chain) == 2
        with pytest.raises(VaultError):  # once per device
            keychain.add_device(session, chain)


def test_a_failed_vault_write_forgets_the_new_key(vector_vault: Path) -> None:
    chain = Memory()
    before = vector_vault.read_bytes()
    with pytest.raises(RuntimeError), store.edit(MASTER, vector_vault) as session:
        keychain.add_device(session, chain)
        assert len(chain.items) == 1
        raise RuntimeError
    assert chain.items == {}
    assert vector_vault.read_bytes() == before


def test_a_refused_keychain_adds_no_grant(vector_vault: Path) -> None:
    chain = Memory()
    chain.refuse = True
    before = vector_vault.read_bytes()
    with store.edit(MASTER, vector_vault) as session:
        with pytest.raises(VaultError):
            keychain.add_device(session, chain)
        assert len(session.grants) == 2
    assert vector_vault.read_bytes() == before


def test_remove_device_drops_the_grant_and_the_item(vector_vault: Path) -> None:
    chain = Memory()
    with store.edit(MASTER, vector_vault) as session:
        keychain.add_device(session, chain)
    with store.edit(MASTER, vector_vault) as session:
        keychain.remove_device(session, 2, chain)
        assert len(chain.items) == 1  # not until the vault is written
    assert chain.items == {}
    with pytest.raises(CannotOpen):
        store.load(keychain.credentials(vector_vault, chain), vector_vault)


def test_remove_device_is_only_for_device_grants(vector_vault: Path) -> None:
    with store.edit(MASTER, vector_vault) as session:
        for index in (0, 5, -1):
            with pytest.raises(VaultError):
                keychain.remove_device(session, index, Memory())
        # Another device's grant, with no item in this keychain.
        keychain.remove_device(session, 1, Memory())
        assert len(session.grants) == 1


def test_the_master_grant_cannot_be_removed(vector_vault: Path) -> None:
    with store.edit(MASTER, vector_vault) as session, pytest.raises(VaultError):
        session.remove_grant(0)


def test_no_keychain_means_the_master_password(
    vector_vault: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(keyring, "get_keyring", lambda: fail.Keyring())  # type: ignore[no-untyped-call]
    assert keychain.os_keychain() is None
    assert keychain.credentials(vector_vault).keys == []
    with store.edit(MASTER, vector_vault) as session, pytest.raises(VaultError):
        keychain.add_device(session)


def test_a_plain_file_backend_is_never_used(monkeypatch: pytest.MonkeyPatch) -> None:
    class PlaintextKeyring(Memory):
        pass

    PlaintextKeyring.__module__ = "keyrings.alt.file"
    monkeypatch.setattr(keyring, "get_keyring", PlaintextKeyring)
    assert keychain.os_keychain() is None


def test_the_vault_holds_at_most_16_grants(vector_vault: Path) -> None:
    with store.edit(MASTER, vector_vault) as session:
        for _ in range(14):
            session.add_grant([access.new_key(os.urandom(32))])
        with pytest.raises(VaultError):
            session.add_grant([access.new_key(os.urandom(32))])


@pytest.mark.skipif(
    not os.environ.get("SSC_KEYCHAIN_TESTS"),
    reason="writes to the real OS keychain; CI sets SSC_KEYCHAIN_TESTS=1",
)
def test_the_real_os_keychain(vector_vault: Path) -> None:
    """The gate's "works on all three platforms": a real device key round
    trip through macOS Keychain, Windows Credential Manager or Secret
    Service."""
    chain = keychain.os_keychain()
    assert chain is not None, f"no OS keychain: {keyring.get_keyring()!r}"
    with store.edit(MASTER, vector_vault) as session:
        index = keychain.add_device(session)
    try:
        creds = keychain.credentials(vector_vault)
        assert len(creds.keys) == 1
        assert (
            store.load(creds, vector_vault).to_json()["entries"]
            == VAULT["document"]["entries"]
        )
    finally:
        with store.edit(MASTER, vector_vault) as session:
            keychain.remove_device(session, index)
    assert keychain.credentials(vector_vault).keys == []
