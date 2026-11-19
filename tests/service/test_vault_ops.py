"""Vault, key, profile and settings operations through the service layer
(CLI.md sections 3.3 and 3.4)."""

from __future__ import annotations

import io
import os
from pathlib import Path

import pytest

from secure_string_cipher.engine import access, keyfile, recovery
from secure_string_cipher.errors import CannotOpen, InputError, VaultError
from secure_string_cipher.service import (
    files,
    keys,
    profile_ops,
    settings,
    shred,
    vaults,
)
from secure_string_cipher.service.context import Context
from secure_string_cipher.service.files import Choice
from secure_string_cipher.service.vaults import State
from secure_string_cipher.vault import store
from tests.service.fakes import Keychain, Prompter

PASSWORD = "a strong test passphrase"
MASTER = "master password for tests"
NEW_MASTER = "a new master password"


@pytest.fixture
def vault(ctx: Context, prompter: Prompter) -> Context:
    prompter.new_masters.append(MASTER)
    vaults.init(ctx)
    return ctx


def test_init_adds_this_device(vault: Context, chain: Keychain) -> None:
    assert len(chain.items) == 1
    assert vaults.status(vault) == vaults.Status(State.DEVICE, 0, 0, False)


def test_status_without_a_vault_or_keychain(ctx: Context, prompter: Prompter) -> None:
    assert vaults.status(ctx).state == State.NONE
    prompter.new_masters.append(MASTER)
    ctx.use_keychain = False
    vaults.init(ctx)
    assert vaults.status(ctx).state == State.LOCKED
    assert prompter.notices[-1].startswith("No OS keychain is available")


def test_init_with_a_recovery_code(ctx: Context, prompter: Prompter) -> None:
    prompter.new_masters.append(MASTER)
    vaults.init(ctx, device_key=False, recovery_code=True)
    ((title, code),) = prompter.shown
    assert title == "Vault recovery code"
    prompter.new_masters.append(NEW_MASTER)
    vaults.reset_password(ctx, code)
    assert (
        store.load(access.Credentials(passwords=[NEW_MASTER]), ctx.vault_path)
        is not None
    )
    with pytest.raises(VaultError):
        vaults.init(ctx)


def test_without_the_device_the_master_password_is_asked(
    vault: Context, prompter: Prompter
) -> None:
    vault.use_keychain = False
    prompter.secrets.append(MASTER)
    vaults.add_password(vault, "work", PASSWORD)
    assert prompter.asked[-1] == "Vault master password"
    with pytest.raises(VaultError), vaults.edit(vault, ask=False):
        pass


def test_change_password(vault: Context, prompter: Prompter) -> None:
    prompter.secrets.append(MASTER)
    prompter.new_masters.append(NEW_MASTER)
    vaults.change_password(vault)
    with pytest.raises(CannotOpen):
        store.load(access.Credentials(passwords=[MASTER]), vault.vault_path)
    prompter.secrets.append("wrong")
    prompter.new_masters.append("whatever it is")
    with pytest.raises(CannotOpen):
        vaults.change_password(vault)


def test_add_key_offers_a_recovery_code(vault: Context, prompter: Prompter) -> None:
    prompter.confirms.append(True)
    vaults.add_key(vault, "laptop")
    labels = [e.label for e in vaults.list_entries(vault)]
    assert labels == ["laptop", "laptop-recovery"]
    assert prompter.shown[0][0] == 'Recovery code "laptop-recovery"'


def test_revoke_finds_the_files_it_opens(
    vault: Context, prompter: Prompter, tmp_path: Path
) -> None:
    vaults.add_password(vault, "work", PASSWORD)
    folder = tmp_path / "docs"
    folder.mkdir()
    for name, label in (("a.ssc", "work"), ("b.ssc", None)):
        prompter.new_passwords.append(PASSWORD)
        choice = (
            Choice(vault_label=label) if label else Choice(grant_specs=["password"])
        )
        files.encrypt(vault, io.BytesIO(b"x"), folder / name, choice)
    (folder / "notes.txt").write_text("not SSC")
    found = vaults.revoke(vault, "work", scan=folder)
    assert found == [folder / "a.ssc"]
    assert "anyone with a copy" in prompter.notices[-1]
    assert [e.status for e in vaults.list_entries(vault)] == ["revoked"]


def test_devices(vault: Context, chain: Keychain) -> None:
    with pytest.raises(VaultError):
        vaults.add_device(vault)  # already this device
    vaults.remove_device(vault, "g2")
    assert chain.items == {}
    assert vaults.status(vault).state == State.LOCKED
    with pytest.raises(InputError):
        vaults.remove_device(vault, "two")


def test_backup(vault: Context, tmp_path: Path) -> None:
    copy = tmp_path / "backup.ssc"
    vaults.backup(vault, copy)
    assert copy.read_bytes() == vault.vault_path.read_bytes()
    with pytest.raises(FileExistsError):
        vaults.backup(vault, copy)


def test_history(vault: Context) -> None:
    assert vaults.history_show(vault) is None
    vaults.history_on(vault)
    vaults.add_password(vault, "work", PASSWORD)
    shown = vaults.history_show(vault)
    assert shown is not None
    assert [e.action for e in shown.events] == [
        "vault-unlock",
        "entry-create",
        "vault-unlock",
    ]
    vaults.history_off(vault)
    assert vaults.history_show(vault) is None


def test_keys(vault: Context, tmp_path: Path) -> None:
    path = tmp_path / "Laptop Key.ssckey"
    made = keys.new(path)
    assert made.label == "key" and keyfile.read(path) == made
    assert keys.import_(vault, path, "laptop") == "laptop"
    out = tmp_path / "out.ssckey"
    assert keys.export(vault, "laptop", out) == made.key_id
    assert keyfile.read(out).key == made.key


def test_profiles_and_the_default(
    vault: Context, prompter: Prompter, settings_path: Path, tmp_path: Path
) -> None:
    vaults.add_password(vault, "work", PASSWORD)
    profile_ops.create(vault, "backup", ["vault:work", "password+recovery"])
    assert len(prompter.shown) == 1  # the recovery entry it resolved to
    assert profile_ops.show(vault, "backup") == [
        'g1: vault entry "work"',
        'g2: a password typed at encrypt time + vault entry "recovery"',
    ]
    with pytest.raises(InputError):
        profile_ops.create(vault, "k", [f"keyfile:{tmp_path / 'k.ssckey'}"])
    profile_ops.set_default(vault, "backup", settings_path)
    assert settings.load(settings_path).default_profile == "backup"
    profile_ops.delete(vault, "backup", settings_path)
    assert settings.load(settings_path).default_profile is None
    with pytest.raises(VaultError):
        profile_ops.set_default(vault, "missing", settings_path)


def test_bad_settings_are_an_input_error(settings_path: Path) -> None:
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text('{"default_profile": 3}')
    with pytest.raises(InputError):
        settings.load(settings_path)


def test_shred(tmp_path: Path) -> None:
    path = tmp_path / "old.txt"
    path.write_bytes(b"secret" * 1000)
    shred.shred(path)
    assert not path.exists()
    with pytest.raises(IsADirectoryError):
        shred.shred(tmp_path)


def test_recovery_codes_are_read_in_any_case(vault: Context) -> None:
    entry = vaults.add_recovery(vault, "paper")
    assert isinstance(entry.secret, bytes)
    assert recovery.decode(recovery.encode(entry.secret).lower()) == entry.secret
    assert os.path.exists(vault.vault_path)
