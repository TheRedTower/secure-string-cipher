"""Encrypting and decrypting through the service layer (CLI.md sections 1
and 3.1), asking only for what is missing."""

from __future__ import annotations

import io
from collections.abc import Buffer
from pathlib import Path

import pytest

from secure_string_cipher import fs
from secure_string_cipher.engine import armor, recovery
from secure_string_cipher.errors import CannotOpen, FormatError, InputError
from secure_string_cipher.service import access_ops, files, keys, profile_ops, vaults
from secure_string_cipher.service.context import Context
from secure_string_cipher.service.files import Choice
from tests.service.fakes import Prompter

PASSWORD = "a strong test passphrase"
MASTER = "master password for tests"
PLAIN = b"the secret report\n" * 1000


@pytest.fixture
def report(tmp_path: Path) -> Path:
    path = tmp_path / "report.txt"
    path.write_bytes(PLAIN)
    return path


def encrypt(
    ctx: Context,
    src: Path,
    choice: Choice | None = None,
    *,
    force: bool = False,
    settings_path: Path | None = None,
) -> Path:
    out = src.with_name(src.name + ".ssc")
    with src.open("rb") as handle:
        files.encrypt(
            ctx, handle, out, choice, force=force, settings_path=settings_path
        )
    return out


def decrypt(ctx: Context, src: Path) -> bytes:
    sink = io.BytesIO()
    with src.open("rb") as handle:
        files.decrypt(ctx, handle, sink)
    return sink.getvalue()


def with_vault(ctx: Context, prompter: Prompter) -> None:
    prompter.new_masters.append(MASTER)
    vaults.init(ctx)


def test_a_typed_password_round_trip(
    ctx: Context, prompter: Prompter, report: Path, settings_path: Path
) -> None:
    prompter.new_passwords.append(PASSWORD)
    out = encrypt(ctx, report, settings_path=settings_path)
    prompter.secrets.append(PASSWORD)
    assert decrypt(ctx, out) == PLAIN
    assert prompter.asked == ["New password for this file", "Password for this file"]


def test_supplied_passwords_are_tried_before_asking(
    ctx: Context, prompter: Prompter, report: Path, settings_path: Path
) -> None:
    prompter.new_passwords.append(PASSWORD)
    out = encrypt(ctx, report, settings_path=settings_path)
    ctx.passwords = ["a wrong one first", PASSWORD]
    assert decrypt(ctx, out) == PLAIN
    assert prompter.asked == ["New password for this file"]


def test_a_wrong_password_cannot_open(
    ctx: Context, prompter: Prompter, report: Path, settings_path: Path
) -> None:
    prompter.new_passwords.append(PASSWORD)
    out = encrypt(ctx, report, settings_path=settings_path)
    prompter.secrets.append("not the password")
    with pytest.raises(CannotOpen):
        decrypt(ctx, out)


def test_never_overwrites_without_force(
    ctx: Context, prompter: Prompter, report: Path, settings_path: Path
) -> None:
    out = report.with_name("report.txt.ssc")
    out.write_bytes(b"keep me")
    with pytest.raises(FileExistsError):
        encrypt(ctx, report, settings_path=settings_path)
    assert prompter.asked == []  # refused before asking anything
    assert out.read_bytes() == b"keep me"
    prompter.new_passwords.append(PASSWORD)
    encrypt(ctx, report, force=True, settings_path=settings_path)
    assert out.read_bytes().startswith(b"\x89SSC")


def test_a_vault_entry_opens_without_asking(
    ctx: Context, prompter: Prompter, report: Path
) -> None:
    with_vault(ctx, prompter)
    prompter.confirms.append(False)  # no recovery code for the key
    vaults.add_key(ctx, "laptop")
    out = encrypt(ctx, report, Choice(vault_label="laptop"))
    prompter.asked.clear()
    assert decrypt(ctx, out) == PLAIN
    assert prompter.asked == []


def test_a_locked_vault_asks_for_the_master_password(
    ctx: Context, prompter: Prompter, report: Path
) -> None:
    with_vault(ctx, prompter)
    prompter.confirms.append(False)
    vaults.add_key(ctx, "laptop")
    out = encrypt(ctx, report, Choice(vault_label="laptop"))
    ctx.use_keychain = False
    prompter.asked.clear()
    prompter.secrets.append(MASTER)
    assert decrypt(ctx, out) == PLAIN
    assert prompter.asked == ["Vault master password"]


def test_history_records_entry_use(
    ctx: Context, prompter: Prompter, report: Path
) -> None:
    with_vault(ctx, prompter)
    vaults.history_on(ctx)
    entry = vaults.add_password(ctx, "work", PASSWORD)
    out = encrypt(ctx, report, Choice(vault_label="work"))
    assert decrypt(ctx, out) == PLAIN
    shown = vaults.history_show(ctx)
    assert shown is not None
    used = [(e.action, e.entry) for e in shown.events if e.entry]
    assert used == [
        ("entry-create", entry.id),
        ("encrypt", entry.id),
        ("decrypt", entry.id),
    ]


def test_password_and_key_file(
    ctx: Context, prompter: Prompter, report: Path, tmp_path: Path
) -> None:
    key = tmp_path / "usb.ssckey"
    keys.new(key)
    prompter.new_passwords.append(PASSWORD)
    out = encrypt(ctx, report, Choice(grant_specs=[f"password+keyfile:{key}"]))
    ctx.key_files = [key]
    prompter.secrets.append(PASSWORD)
    assert decrypt(ctx, out) == PLAIN
    ctx.key_files = []
    prompter.secrets.append(PASSWORD)
    with pytest.raises(CannotOpen):
        decrypt(ctx, out)


def test_the_same_key_twice_in_a_grant_is_refused(
    ctx: Context, report: Path, tmp_path: Path
) -> None:
    key = tmp_path / "usb.ssckey"
    keys.new(key)
    copy = tmp_path / "copy.ssckey"
    copy.write_bytes(key.read_bytes())
    copy.chmod(0o600)
    with pytest.raises(InputError):
        encrypt(ctx, report, Choice(grant_specs=[f"keyfile:{key}+keyfile:{copy}"]))


def test_a_recovery_code_is_made_shown_and_opens(
    ctx: Context, prompter: Prompter, report: Path
) -> None:
    with_vault(ctx, prompter)
    prompter.new_passwords.append(PASSWORD)
    out = encrypt(ctx, report, Choice(grant_specs=["password"], recovery_code=True))
    ((title, code),) = prompter.shown
    assert title == 'Recovery code "recovery"'
    recovery.decode(code)
    # Without the vault, SSC asks which way to open it.
    ctx.vault_path.unlink()
    prompter.choices.append(1)
    prompter.secrets.append(code.lower())
    assert decrypt(ctx, out) == PLAIN
    assert any("your password" in q and "a recovery code" in q for q in prompter.asked)


def test_the_default_profile_is_used(
    ctx: Context, prompter: Prompter, report: Path, settings_path: Path
) -> None:
    with_vault(ctx, prompter)
    vaults.add_password(ctx, "work", PASSWORD)
    profile_ops.create(ctx, "daily", ["vault:work"])
    profile_ops.set_default(ctx, "daily", settings_path)
    out = encrypt(ctx, report, settings_path=settings_path)
    prompter.asked.clear()
    assert decrypt(ctx, out) == PLAIN
    assert prompter.asked == []


def test_only_one_way_to_choose(ctx: Context, report: Path) -> None:
    with pytest.raises(InputError):
        encrypt(ctx, report, Choice(grant_specs=["password"], vault_label="x"))


def test_streams_and_armour(
    ctx: Context, prompter: Prompter, settings_path: Path
) -> None:
    ctx.passwords = [PASSWORD]
    prompter.new_passwords.append(PASSWORD)
    sealed = io.BytesIO()
    files.encrypt(
        ctx, io.BytesIO(b"text"), sealed, armored=True, settings_path=settings_path
    )
    assert sealed.getvalue().startswith(armor.BEGIN)
    out = io.BytesIO()
    files.decrypt(ctx, io.BytesIO(sealed.getvalue()), out)
    assert out.getvalue() == b"text"


def test_a_damaged_file_writes_nothing(
    ctx: Context, prompter: Prompter, report: Path, settings_path: Path
) -> None:
    prompter.new_passwords.append(PASSWORD)
    out = encrypt(ctx, report, settings_path=settings_path)
    data = bytearray(out.read_bytes())
    data[-1] ^= 1
    ctx.passwords = [PASSWORD]
    sink = io.BytesIO()
    with pytest.raises(FormatError):
        files.decrypt(ctx, io.BytesIO(bytes(data)), sink)
    assert sink.getvalue() == b""
    target = report.with_name("restored.txt")
    with pytest.raises(FormatError):
        files.decrypt(ctx, io.BytesIO(bytes(data)), target)
    assert not target.exists()
    assert [p.name for p in report.parent.iterdir() if p.name.startswith(".")] == []


def test_large_output_is_spooled_until_authenticated(
    ctx: Context,
    prompter: Prompter,
    monkeypatch: pytest.MonkeyPatch,
    settings_path: Path,
) -> None:
    monkeypatch.setattr(files, "HOLD_IN_MEMORY", 1024)
    ctx.passwords = [PASSWORD]
    prompter.new_passwords.append(PASSWORD)
    sealed = io.BytesIO()
    files.encrypt(ctx, io.BytesIO(PLAIN), sealed, settings_path=settings_path)
    out = io.BytesIO()
    files.decrypt(ctx, io.BytesIO(sealed.getvalue()), out)
    assert out.getvalue() == PLAIN


def test_a_late_sync_failure_keeps_the_new_recovery_entry(
    ctx: Context, prompter: Prompter, report: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The output is in place when its folder fails to sync, so the vault
    entry made for it is saved and its code shown before the error."""
    with_vault(ctx, prompter)
    real = fs.write_atomic

    def not_durable(path: Path, *args: object, **kwargs: object) -> None:
        real(path, *args, **kwargs)  # type: ignore[arg-type]
        if path.name == "report.txt.ssc":
            raise fs.NotDurable("folder not synced")

    monkeypatch.setattr(fs, "write_atomic", not_durable)
    prompter.new_passwords.append(PASSWORD)
    with pytest.raises(fs.NotDurable):
        encrypt(ctx, report, Choice(grant_specs=["password"], recovery_code=True))
    monkeypatch.setattr(fs, "write_atomic", real)
    assert [title for title, _ in prompter.shown] == ['Recovery code "recovery"']
    assert [e.kind for e in vaults.list_entries(ctx)] == ["recovery"]
    assert decrypt(ctx, report.with_name("report.txt.ssc")) == PLAIN


def test_a_wrong_master_password_does_not_stop_a_key_file(
    ctx: Context, prompter: Prompter, report: Path, tmp_path: Path
) -> None:
    with_vault(ctx, prompter)
    key = tmp_path / "usb.ssckey"
    keys.new(key)
    out = encrypt(ctx, report, Choice(grant_specs=[f"keyfile:{key}"]))
    ctx.use_keychain = False
    ctx.master_password = "not the master password"
    ctx.key_files = [key]
    assert decrypt(ctx, out) == PLAIN


def test_history_records_a_recovery_entry_used_to_decrypt(
    ctx: Context, prompter: Prompter, report: Path
) -> None:
    with_vault(ctx, prompter)
    vaults.history_on(ctx)
    prompter.new_passwords.append(PASSWORD)
    out = encrypt(ctx, report, Choice(grant_specs=["password"], recovery_code=True))
    (entry,) = vaults.list_entries(ctx)
    assert decrypt(ctx, out) == PLAIN  # by the vault's recovery code
    shown = vaults.history_show(ctx)
    assert shown is not None
    assert ("decrypt", entry.id) in [(e.action, e.entry) for e in shown.events]


def test_no_output_if_the_new_recovery_entry_is_not_saved(
    ctx: Context, prompter: Prompter, report: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The vault is saved before the output is published, so a file that
    only a new recovery code opens never outlives that code."""
    with_vault(ctx, prompter)
    real = fs.write_atomic

    def vault_full(path: Path, *args: object, **kwargs: object) -> None:
        if path == ctx.vault_path:
            raise OSError(28, "No space left on device")
        real(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(fs, "write_atomic", vault_full)
    with pytest.raises(OSError):
        encrypt(ctx, report, Choice(grant_specs=["recovery"]))
    monkeypatch.setattr(fs, "write_atomic", real)
    assert not report.with_name("report.txt.ssc").exists()
    assert prompter.shown == []
    assert vaults.list_entries(ctx) == ()


def test_an_unused_recovery_entry_is_kept_if_the_output_fails(
    ctx: Context, prompter: Prompter, report: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with_vault(ctx, prompter)
    real = fs.write_atomic

    def output_fails(path: Path, *args: object, **kwargs: object) -> None:
        if path.name == "report.txt.ssc":
            raise OSError(28, "No space left on device")
        real(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(fs, "write_atomic", output_fails)
    with pytest.raises(OSError):
        encrypt(ctx, report, Choice(grant_specs=["recovery"]))
    monkeypatch.setattr(fs, "write_atomic", real)
    assert not report.with_name("report.txt.ssc").exists()
    assert [e.kind for e in vaults.list_entries(ctx)] == ["recovery"]
    assert len(prompter.shown) == 1


def test_a_failed_supplied_master_password_lets_the_person_type_one(
    ctx: Context, prompter: Prompter, report: Path
) -> None:
    with_vault(ctx, prompter)
    prompter.confirms.append(False)
    vaults.add_key(ctx, "laptop")
    out = encrypt(ctx, report, Choice(vault_label="laptop"))
    ctx.use_keychain = False
    ctx.master_password = "a stale master password"
    prompter.asked.clear()
    prompter.secrets.append(MASTER)
    assert decrypt(ctx, out) == PLAIN
    assert prompter.asked == ["Vault master password"]
    assert "did not open the vault" in prompter.notices[-1]


def test_a_damaged_vault_does_not_block_another_way_in(
    ctx: Context, prompter: Prompter, report: Path, tmp_path: Path
) -> None:
    with_vault(ctx, prompter)
    key = tmp_path / "usb.ssckey"
    keys.new(key)
    out = encrypt(ctx, report, Choice(grant_specs=[f"keyfile:{key}"]))
    ctx.vault_path.write_bytes(b"\x89SSC damaged")
    ctx.key_files = [key]
    assert decrypt(ctx, out) == PLAIN
    assert "Trying without the vault" in prompter.notices[-1]


def test_the_vault_is_not_locked_while_the_payload_streams(
    ctx: Context, prompter: Prompter, report: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from secure_string_cipher.vault import store

    with_vault(ctx, prompter)
    vaults.history_on(ctx)
    vaults.add_password(ctx, "work", PASSWORD)
    out = encrypt(ctx, report, Choice(vault_label="work"))
    monkeypatch.setattr(store, "LOCK_TIMEOUT", 0.1)

    class Probe(io.BytesIO):
        def write(self, data: Buffer, /) -> int:
            with store.locked(ctx.vault_path):  # another ssc could use the vault
                pass
            return super().write(data)

    sink = Probe()
    with out.open("rb") as handle:
        files.decrypt(ctx, handle, sink)
    assert sink.getvalue() == PLAIN
    shown = vaults.history_show(ctx)
    assert shown is not None
    assert [e.action for e in shown.events][-2:] == ["decrypt", "vault-unlock"]


def test_an_unreadable_vault_does_not_block_another_way_in(
    ctx: Context,
    prompter: Prompter,
    report: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secure_string_cipher.vault import store

    with_vault(ctx, prompter)
    key = tmp_path / "usb.ssckey"
    keys.new(key)
    out = encrypt(ctx, report, Choice(grant_specs=[f"keyfile:{key}"]))

    def denied(path: Path) -> bytes:
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(store, "read_file", denied)
    ctx.key_files = [key]
    assert decrypt(ctx, out) == PLAIN
    assert "(Permission denied)" in prompter.notices[-1]
    assert access_ops.show(ctx, out)[0].startswith("g1: key ")


def test_a_failed_vault_unlock_write_leaves_no_snapshot(
    ctx: Context,
    prompter: Prompter,
    report: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With history on, reading the vault writes a `vault-unlock` event. If
    that write fails, the vault counts as unavailable, so the file's own
    credentials still open it and nothing is recorded later."""
    with_vault(ctx, prompter)
    vaults.history_on(ctx)
    key = tmp_path / "usb.ssckey"
    keys.new(key)
    out = encrypt(ctx, report, Choice(grant_specs=[f"keyfile:{key}"]))
    real = fs.write_atomic

    def vault_full(path: Path, *args: object, **kwargs: object) -> None:
        if path == ctx.vault_path:
            raise OSError(28, "No space left on device")
        real(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(fs, "write_atomic", vault_full)
    ctx.key_files = [key]
    assert decrypt(ctx, out) == PLAIN
    assert "(No space left on device)" in prompter.notices[-1]
