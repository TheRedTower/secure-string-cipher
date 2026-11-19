"""`ssc access` through the service layer (CLI.md section 3.2)."""

from __future__ import annotations

import io
import shutil
from pathlib import Path

import pytest

from secure_string_cipher.engine import keyfile
from secure_string_cipher.errors import CannotOpen, InputError
from secure_string_cipher.service import access_ops, files, keys, profile_ops, vaults
from secure_string_cipher.service.context import Context
from secure_string_cipher.service.files import Choice
from tests import vectorkit
from tests.service.fakes import Prompter

PASSWORD = "a strong test passphrase"
OTHER = "another strong passphrase"
MASTER = "master password for tests"


def sealed(ctx: Context, tmp_path: Path, choice: Choice) -> Path:
    out = tmp_path / "file.ssc"
    files.encrypt(ctx, io.BytesIO(b"contents"), out, choice)
    return out


def opens(ctx: Context, path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            files.decrypt(ctx, handle, io.BytesIO())
    except (CannotOpen, InputError):
        return False
    return True


@pytest.fixture
def keyed(ctx: Context, prompter: Prompter, tmp_path: Path) -> Path:
    """A file opened by a password and key file together."""
    key = tmp_path / "usb.ssckey"
    keys.new(key)
    prompter.new_passwords.append(PASSWORD)
    out = sealed(ctx, tmp_path, Choice(grant_specs=[f"password+keyfile:{key}"]))
    ctx.key_files = [key]
    ctx.passwords = [PASSWORD]
    return out


def test_show_needs_nothing(ctx: Context, prompter: Prompter, keyed: Path) -> None:
    lines = access_ops.show(ctx, keyed)
    assert len(lines) == 1 and lines[0].startswith("g1: password + key ")
    assert prompter.asked == ["New password for this file"]


def test_show_uses_vault_labels(
    ctx: Context, prompter: Prompter, tmp_path: Path
) -> None:
    prompter.new_masters.append(MASTER)
    vaults.init(ctx)
    prompter.confirms.append(False)
    vaults.add_key(ctx, "laptop")
    vaults.add_password(ctx, "work", PASSWORD)
    out = sealed(ctx, tmp_path, Choice(grant_specs=["vault:laptop", "vault:work"]))
    assert access_ops.show(ctx, out) == ['g1: key "laptop"', 'g2: vault entry "work"']


def test_show_an_unknown_grant() -> None:
    path = vectorkit.VECTORS / vectorkit.valid("access-unknown-grant-skipped")["file"]
    ctx = Context(Prompter(), use_keychain=False, vault_path=Path("/nonexistent/v.ssc"))
    assert access_ops.show(ctx, path)[0].startswith("g1: a kind of grant")


def test_add_then_remove(ctx: Context, prompter: Prompter, keyed: Path) -> None:
    prompter.new_passwords.append(OTHER)
    access_ops.add(ctx, keyed, "password")
    assert prompter.notices[-1].startswith("Adding a password-only way in")
    only_other = Context(Prompter(), passwords=[OTHER], use_keychain=False)
    only_other.vault_path = ctx.vault_path
    assert opens(only_other, keyed)
    access_ops.remove(ctx, keyed, "g2")
    assert prompter.notices[-1].startswith("Removed g2. Anyone who already")
    assert not opens(only_other, keyed)
    assert opens(ctx, keyed)
    with pytest.raises(InputError):
        access_ops.remove(ctx, keyed, "g1")  # the last one
    with pytest.raises(InputError):
        access_ops.remove(ctx, keyed, "g5")


def test_only_someone_who_can_open_can_add(
    ctx: Context, prompter: Prompter, keyed: Path
) -> None:
    ctx.key_files = []
    before = keyed.read_bytes()
    prompter.secrets.append(PASSWORD)
    with pytest.raises(CannotOpen):
        access_ops.add(ctx, keyed, "password")
    assert keyed.read_bytes() == before


def test_rotate_rebuilds_every_grant(
    ctx: Context, prompter: Prompter, keyed: Path
) -> None:
    before = keyed.read_bytes()
    access_ops.rotate(ctx, keyed)
    assert keyed.read_bytes()[9:25] != before[9:25]  # a new payload nonce
    assert opens(ctx, keyed)
    assert len(access_ops.show(ctx, keyed)) == 1


def test_rotate_asks_before_dropping_what_it_cannot_rebuild(
    ctx: Context, prompter: Prompter, tmp_path: Path
) -> None:
    vector = vectorkit.valid("access-unknown-grant-skipped")
    path = tmp_path / "unknown.ssc"
    shutil.copyfile(vectorkit.VECTORS / vector["file"], path)
    key_a = tmp_path / "a.ssckey"
    keyfile.write(
        key_a,
        keyfile.KeyFile(
            "a",
            keyfile.timestamp(),
            bytes.fromhex(vectorkit.manifest()["credentials"]["key_a"]),
        ),
    )
    ctx.key_files = [key_a]
    before = path.read_bytes()
    prompter.confirms.append(False)
    with pytest.raises(InputError):
        access_ops.rotate(ctx, path)
    assert path.read_bytes() == before
    access_ops.rotate(ctx, path, force=True)
    assert len(access_ops.show(ctx, path)) == 1  # the unknown grant is gone
    assert opens(ctx, path)


def test_apply_replaces_the_grants(
    ctx: Context, prompter: Prompter, keyed: Path
) -> None:
    prompter.new_masters.append(MASTER)
    vaults.init(ctx)
    vaults.add_password(ctx, "work", PASSWORD)
    profile_ops.create(ctx, "work-only", ["vault:work"])
    access_ops.apply(ctx, keyed, "work-only")
    assert access_ops.show(ctx, keyed) == ['g1: vault entry "work"']
    ctx.key_files, ctx.passwords = [], []
    assert opens(ctx, keyed)
