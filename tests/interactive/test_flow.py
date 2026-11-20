"""The guided flow end to end (CLI.md section 4), on the real service layer
with a scripted Ui."""

from __future__ import annotations

import io
import re
from pathlib import Path

import pytest

from secure_string_cipher.cli import main
from secure_string_cipher.errors import CannotOpen
from secure_string_cipher.interactive import flow
from secure_string_cipher.service import (
    access_ops,
    files,
    passwords,
    profile_ops,
    vaults,
)
from secure_string_cipher.service.context import Context
from tests.interactive.conftest import BACK, ScriptedUi, last_group

PASSWORD = "a strong test passphrase"
MASTER = "master password for tests"
PLAIN = b"the secret report\n" * 100
START = "What do you want to do?"


@pytest.fixture
def report(tmp_path: Path) -> Path:
    path = tmp_path / "report.txt"
    path.write_bytes(PLAIN)
    return path


def run(ctx: Context, ui: ScriptedUi, *answers: object) -> None:
    ui.answers += [*answers, "Quit"]
    assert flow.run(ctx, ui) == 0
    ui.done()


def with_vault(ctx: Context, ui: ScriptedUi) -> None:
    ui.answers += [MASTER, MASTER]
    vaults.init(ctx)


def opens(ctx: Context, path: Path) -> bytes:
    sink = io.BytesIO()
    with path.open("rb") as handle:
        files.decrypt(ctx, handle, sink)
    return sink.getvalue()


def test_start_screen(ctx: Context, ui: ScriptedUi) -> None:
    run(ctx, ui)
    assert ui.said == ["SSC  ·  no vault yet"]
    ui.answers.append(BACK)  # Ctrl-C quits too
    assert flow.run(ctx, ui) == 0


def test_encrypt_and_decrypt_with_a_typed_password(
    ctx: Context, ui: ScriptedUi, report: Path
) -> None:
    run(
        ctx, ui,
        "Encrypt", "report.txt", "A password I'll type", True,
        PASSWORD, PASSWORD,
        "Decrypt", "report.txt.ssc", PASSWORD,
        True,  # report.txt exists: replace it
        True,  # Decrypt to report.txt?
    )  # fmt: skip
    assert (
        "Encrypt report.txt to report.txt.ssc, unlocked by a password. Go?" in ui.asked
    )
    assert "report.txt exists. Replace it?" in ui.asked
    assert report.read_bytes() == PLAIN
    assert sum(s.startswith("✓ Wrote") for s in ui.said) == 2


def test_a_weak_password_offers_a_passphrase(
    ctx: Context, ui: ScriptedUi, report: Path
) -> None:
    run(
        ctx, ui,
        "Encrypt", "report.txt", "A password I'll type", True,
        "password1", True, True,  # weak; generate one instead; use it
    )  # fmt: skip
    shown = next(s for s in ui.said if "Your passphrase" in s)
    phrase = re.search(r"\n {4}(.+)\n", shown)
    assert phrase is not None
    assert passwords.WEAK in ui.said
    ctx.passwords = [phrase.group(1)]
    assert opens(ctx, report.with_name("report.txt.ssc")) == PLAIN


def test_a_weak_password_kept_is_warned_about_once(
    ctx: Context, ui: ScriptedUi, report: Path
) -> None:
    run(
        ctx, ui,
        "Encrypt", "report.txt", "A password I'll type", True,
        "password1", False, "password1",
    )  # fmt: skip
    assert ui.said.count(passwords.WEAK) == 1


def test_the_vault_screen(
    ctx: Context, ui: ScriptedUi, report: Path, tmp_path: Path
) -> None:
    run(
        ctx, ui,
        "Vault", True, False, MASTER, MASTER,  # create it, no vault code
        "Add a key", "laptop", True, last_group(ui),  # with a recovery code
        "Add a password", "work", PASSWORD, PASSWORD,
        "Show entries",
        "Back up the vault", "",
        "Back",
        "Encrypt", "report.txt", "A saved vault entry", '"laptop"', True,
        "Decrypt", "report.txt.ssc", True, True,
    )  # fmt: skip
    assert "Vault  ·  3 entries, 0 profiles, unlocked with this device" in ui.said
    assert '  "laptop-recovery"  recovery, active' in "\n".join(ui.said)
    assert 'This file opens with your key "laptop".' in ui.said
    assert (tmp_path / "vault-backup.ssc").exists()
    assert report.read_bytes() == PLAIN


def test_profiles_come_first(ctx: Context, ui: ScriptedUi, report: Path) -> None:
    with_vault(ctx, ui)
    vaults.add_password(ctx, "work", PASSWORD)
    profile_ops.create(ctx, "daily", ["vault:work"])
    run(ctx, ui, "Encrypt", "report.txt", 'daily  (vault entry "work")', True)
    assert 'Encrypt report.txt to report.txt.ssc, unlocked by profile "daily". Go?' in (
        ui.asked
    )


def test_something_else_builds_ways_in(
    ctx: Context, ui: ScriptedUi, report: Path
) -> None:
    with_vault(ctx, ui)
    ui.answers.append(False)  # no recovery code for the key
    vaults.add_key(ctx, "laptop")
    run(
        ctx, ui,
        "Encrypt", "report.txt", "Something else",
        ["A password", 'Vault entry "laptop"'], True,
        ["A recovery code"], False,
        True,  # Go
        PASSWORD, PASSWORD, last_group(ui),
    )  # fmt: skip
    assert access_ops.show(ctx, report.with_name("report.txt.ssc")) == [
        'g1: password + key "laptop"',
        "g2: recovery code",
    ]
    assert (
        "Encrypt report.txt to report.txt.ssc, unlocked by a password + vault "
        'entry "laptop" or a recovery code. Go?'
    ) in ui.asked


def test_revoke_with_a_scan_and_rotate(
    ctx: Context, ui: ScriptedUi, tmp_path: Path
) -> None:
    with_vault(ctx, ui)
    ui.answers += [False, False]
    vaults.add_key(ctx, "laptop")
    vaults.add_key(ctx, "usb")
    docs = tmp_path / "docs"
    docs.mkdir()
    out = docs / "a.ssc"
    files.encrypt(
        ctx,
        io.BytesIO(b"x"),
        out,
        files.Choice(grant_specs=["vault:laptop", "vault:usb"]),
    )
    run(
        ctx, ui,
        "Vault", "Archive or revoke", '"laptop"', "Revoke", "docs", True,
        "Back",
    )  # fmt: skip
    assert access_ops.show(ctx, out) == ['g1: key "usb"']
    assert 'Dropping g1, which used "laptop".' in ui.said


def test_the_keys_screen(ctx: Context, ui: ScriptedUi, tmp_path: Path) -> None:
    with_vault(ctx, ui)
    run(
        ctx, ui,
        "Keys", "Create", "usb.ssckey", "",
        "Keys", "Import", "usb.ssckey", "",
        "Keys", "Export", '"usb"', "",  # the default exists: refused
        "Keys", "Export", '"usb"', "copy.ssckey",
    )  # fmt: skip
    assert (tmp_path / "copy.ssckey").read_bytes() == (
        tmp_path / "usb.ssckey"
    ).read_bytes()
    assert any(s.startswith("✗ ") for s in ui.said)


def test_the_settings_screen(ctx: Context, ui: ScriptedUi) -> None:
    run(ctx, ui, "Settings")
    assert "Create one under Vault first" in ui.said[-2]
    with_vault(ctx, ui)
    vaults.add_password(ctx, "work", PASSWORD)
    profile_ops.create(ctx, "daily", ["vault:work"])
    run(
        ctx, ui,
        "Settings", "Default profile", "daily",
        "Settings", "Use this device's keychain: on", True,
        "Settings", "Use this device's keychain: off", MASTER,
        "Settings", "History", "Turn it on",
        "Settings", "History", "Show it",
        "Settings", "History", "Turn it off", True,
    )  # fmt: skip
    assert "✓ Default profile: daily" in ui.said
    assert "✓ This device's keychain now unlocks the vault" in ui.said
    assert any("vault-unlock" in s for s in ui.said)
    assert vaults.history_show(ctx) is None


def test_errors_are_shown_and_the_flow_goes_on(
    ctx: Context, ui: ScriptedUi, report: Path
) -> None:
    run(
        ctx, ui,
        "Decrypt", "missing.ssc",
        "Encrypt", "report.txt", BACK,  # Ctrl-C at a question: back to the start
        "Encrypt", "",  # no file
    )  # fmt: skip
    assert any(s.startswith("✗ missing.ssc") for s in ui.said)
    assert "✗ No file was given." in ui.said


def test_a_name_without_ssc_asks_where_to_decrypt(
    ctx: Context, ui: ScriptedUi, report: Path, tmp_path: Path
) -> None:
    ctx.passwords = [PASSWORD]
    ui.answers += [PASSWORD, PASSWORD]
    with report.open("rb") as handle:
        files.encrypt(ctx, handle, tmp_path / "sealed.bin")
    run(ctx, ui, "Decrypt", "'sealed.bin'", "", True)  # dragged in: quoted
    assert (tmp_path / "sealed.bin.out").read_bytes() == PLAIN


def test_ssc_with_no_arguments_runs_the_flow(ui: ScriptedUi) -> None:
    ui.answers.append("Quit")
    assert main([], ui=ui) == 0
    assert ui.said == ["SSC  ·  no vault yet"]


def test_a_locked_vault_can_be_unlocked_for_its_profiles(
    ctx: Context, ui: ScriptedUi, report: Path
) -> None:
    """Codex on #185: with no keychain, the profiles are one unlock away."""
    with_vault(ctx, ui)
    vaults.add_password(ctx, "work", PASSWORD)
    profile_ops.create(ctx, "daily", ["vault:work"])
    ctx.use_keychain = False
    run(
        ctx, ui,
        "Encrypt", "report.txt", "Unlock the vault", "wrong password",
        "Unlock the vault", MASTER, "daily", True,
    )  # fmt: skip
    assert "✗ That master password did not open the vault." in ui.said
    assert 'Encrypt report.txt to report.txt.ssc, unlocked by profile "daily". Go?' in (
        ui.asked
    )


def test_an_archived_entry_can_still_be_revoked(ctx: Context, ui: ScriptedUi) -> None:
    """Codex on #185: archived entries still open files, so revoking them
    must stay possible."""
    with_vault(ctx, ui)
    vaults.add_password(ctx, "work", PASSWORD)
    vaults.archive(ctx, "work")
    run(
        ctx,
        ui,
        "Vault",
        "Archive or revoke",
        '"work"  (password, archived)',
        "Revoke",
        "",
        "Back",
    )
    assert [e.status for e in vaults.list_entries(ctx)] == ["revoked"]


def test_a_standalone_key_file_is_asked_for_when_decrypting(
    ctx: Context, ui: ScriptedUi, report: Path, tmp_path: Path
) -> None:
    """Codex on #185: a file made with "A key file…" opens in the flow."""
    from secure_string_cipher.service import keys

    keys.new(tmp_path / "usb.ssckey")
    run(
        ctx, ui,
        "Encrypt", "report.txt", "A key file", "usb.ssckey", True,
        "Decrypt", "report.txt.ssc", "usb.ssckey", True, True,
    )  # fmt: skip
    assert "Which key file?" in ui.asked
    assert report.read_bytes() == PLAIN


def test_the_cli_never_asks_for_a_key_file(
    ctx: Context, ui: ScriptedUi, report: Path, tmp_path: Path
) -> None:
    from secure_string_cipher.service import keys

    keys.new(tmp_path / "usb.ssckey")
    ctx.ask_key_file = None
    with report.open("rb") as handle:
        files.encrypt(
            ctx,
            handle,
            tmp_path / "f.ssc",
            files.Choice(grant_specs=["keyfile:usb.ssckey"]),
        )
    with pytest.raises(CannotOpen):
        opens(ctx, tmp_path / "f.ssc")


def test_the_vault_still_opens_after_its_master_password_changes(
    ctx: Context, ui: ScriptedUi, report: Path
) -> None:
    """Codex on #185: an unlocked session keeps the new master password."""
    with_vault(ctx, ui)
    vaults.add_password(ctx, "work", PASSWORD)
    profile_ops.create(ctx, "daily", ["vault:work"])
    ctx.use_keychain = False
    new = "a new master password"
    run(
        ctx, ui,
        "Encrypt", "report.txt", "Unlock the vault", MASTER, "daily", True,
        "Vault", "Change master password", new, new,
        "Show entries",
        "Back",
    )  # fmt: skip
    assert "✓ Changed the master password" in ui.said
    assert '  "work"  password, active' in "\n".join(ui.said)
    assert ctx.master_password == new


def test_resetting_with_the_recovery_code_updates_the_held_password(
    ctx: Context, ui: ScriptedUi
) -> None:
    ui.answers += [MASTER, MASTER, last_group(ui)]
    vaults.init(ctx, recovery_code=True)
    code = re.findall(r"[0-9A-Z]{4}(?:-[0-9A-Z]{4}){7}", "\n".join(ui.said))[-1]
    ctx.use_keychain = False
    ctx.master_password = MASTER
    new = "a new master password"
    ui.answers += [new, new]
    vaults.reset_password(ctx, code)
    assert ctx.master_password == new
    vaults.add_password(ctx, "after", PASSWORD)  # opens with what it holds
    assert [e.label for e in vaults.list_entries(ctx)] == ["after"]


def test_every_key_file_an_all_of_grant_needs_is_asked_for(
    ctx: Context, ui: ScriptedUi, report: Path, tmp_path: Path
) -> None:
    """Codex on #185: two key files in one grant are both asked for."""
    from secure_string_cipher.service import keys

    keys.new(tmp_path / "usb.ssckey")
    keys.new(tmp_path / "card.ssckey")
    with report.open("rb") as handle:
        files.encrypt(
            ctx,
            handle,
            tmp_path / "both.ssc",
            files.Choice(grant_specs=["keyfile:usb.ssckey+keyfile:card.ssckey"]),
        )
    run(ctx, ui, "Decrypt", "both.ssc", "usb.ssckey", "card.ssckey", True)
    assert ui.asked.count("Which key file?") == 2
    assert (tmp_path / "both").read_bytes() == PLAIN


def test_a_wrong_key_file_uses_up_a_try(
    ctx: Context, ui: ScriptedUi, report: Path, tmp_path: Path
) -> None:
    from secure_string_cipher.service import keys

    keys.new(tmp_path / "usb.ssckey")
    keys.new(tmp_path / "other.ssckey")
    with report.open("rb") as handle:
        files.encrypt(
            ctx,
            handle,
            tmp_path / "f.ssc",
            files.Choice(grant_specs=["keyfile:usb.ssckey"]),
        )
    run(ctx, ui, "Decrypt", "f.ssc", "other.ssckey")
    assert ui.asked.count("Which key file?") == 1
    assert any(s.startswith("✗ ") for s in ui.said)


def test_a_vault_that_cannot_be_read_leaves_the_rest_usable(
    ctx: Context, ui: ScriptedUi, report: Path
) -> None:
    """Codex on #185: a damaged vault must not stop password-only work."""
    with_vault(ctx, ui)
    ctx.vault_path.write_bytes(b"not a vault")
    run(
        ctx, ui,
        "Encrypt", "report.txt", "A password I'll type", True, PASSWORD, PASSWORD,
    )  # fmt: skip
    assert ui.said[0].startswith("SSC  ·  vault unavailable: ")
    assert any(s.startswith("✓ Wrote") for s in ui.said)


def test_a_key_file_path_with_a_plus_is_kept_whole(
    ctx: Context, ui: ScriptedUi, report: Path, tmp_path: Path
) -> None:
    """Codex on #185: the flow never reads a path as grant syntax."""
    from secure_string_cipher.service import keys

    (tmp_path / "C++").mkdir()
    keys.new(tmp_path / "C++" / "usb.ssckey")
    run(
        ctx, ui,
        "Encrypt", "report.txt", "A key file", "C++/usb.ssckey", True,
        "Encrypt", "report.txt", "Something else", ["A key file"],
        "C++/usb.ssckey", False, True, True,
    )  # fmt: skip
    assert sum(s.startswith("✓ Wrote") for s in ui.said) == 2
    ctx.key_files = [tmp_path / "C++" / "usb.ssckey"]
    assert opens(ctx, report.with_name("report.txt.ssc")) == PLAIN


def test_something_else_needs_at_least_one_way_in(
    ctx: Context, ui: ScriptedUi, report: Path
) -> None:
    run(ctx, ui, "Encrypt", "report.txt", "Something else", [])
    assert "✗ Choose at least one way to unlock it." in ui.said


def test_something_else_offers_an_unlock_for_vault_entries(
    ctx: Context, ui: ScriptedUi, report: Path
) -> None:
    """Codex on #185: a locked vault does not block the other ways in."""
    with_vault(ctx, ui)
    vaults.add_password(ctx, "work", PASSWORD)
    ctx.use_keychain = False
    run(
        ctx, ui,
        "Encrypt", "report.txt", "Something else", False,  # no unlock
        ["A password"], False, True, PASSWORD, PASSWORD,
        "Encrypt", "report.txt", "Something else", True, MASTER,  # unlock
        ['Vault entry "work"'], False, True, True,
    )  # fmt: skip
    assert sum(s.startswith("✓ Wrote") for s in ui.said) == 2
    assert access_ops.show(ctx, report.with_name("report.txt.ssc")) == [
        'g1: vault entry "work"'
    ]


def test_something_else_works_with_a_damaged_vault(
    ctx: Context, ui: ScriptedUi, report: Path
) -> None:
    with_vault(ctx, ui)
    ctx.vault_path.write_bytes(b"not a vault")
    run(
        ctx, ui,
        "Encrypt", "report.txt", "Something else", True, MASTER,
        ["A password"], False, True, PASSWORD, PASSWORD,
    )  # fmt: skip
    assert "✗ This is not an SSC file." in ui.said  # why, not "wrong password"
    assert any(s.startswith("✓ Wrote") for s in ui.said)


def test_profiles_are_listed_from_one_read_of_the_vault(
    ctx: Context, ui: ScriptedUi, report: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Self-review: not one unlock, and Argon2id run, per profile."""
    with_vault(ctx, ui)
    vaults.add_password(ctx, "work", PASSWORD)
    profile_ops.create(ctx, "daily", ["vault:work"])
    profile_ops.create(ctx, "spare", ["vault:work"])

    def no_reopen(*_: object) -> None:
        raise AssertionError("the vault was opened again for a profile")

    monkeypatch.setattr(profile_ops, "show", no_reopen)
    run(ctx, ui, "Encrypt", "report.txt", "spare", True)
    assert 'Encrypt report.txt to report.txt.ssc, unlocked by profile "spare". Go?' in (
        ui.asked
    )


def test_with_no_vault_only_the_ways_in_that_need_none_are_offered(
    ctx: Context, ui: ScriptedUi, report: Path
) -> None:
    run(ctx, ui, "Encrypt", "report.txt", "Something else", ["A password"], BACK)
    with pytest.raises(AssertionError, match="not one option"):
        run(ctx, ui, "Encrypt", "report.txt", "A saved vault entry")
    ui.answers.clear()
    with pytest.raises(AssertionError, match="not one option"):
        run(ctx, ui, "Encrypt", "report.txt", "Something else", ["A recovery code"])


def test_one_file_failing_to_rotate_does_not_stop_the_rest(
    ctx: Context, ui: ScriptedUi, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with_vault(ctx, ui)
    ui.answers += [False, False]
    vaults.add_key(ctx, "laptop")
    vaults.add_key(ctx, "usb")
    docs = tmp_path / "docs"
    docs.mkdir()
    for name in ("a.ssc", "b.ssc"):
        files.encrypt(
            ctx,
            io.BytesIO(b"x"),
            docs / name,
            files.Choice(grant_specs=["vault:laptop", "vault:usb"]),
        )
    real = access_ops.rotate

    def flaky(ctx: Context, path: Path, *, without: str | None = None) -> None:
        if path.name == "a.ssc":
            raise PermissionError(13, "Permission denied", str(path))
        real(ctx, path, without=without)

    monkeypatch.setattr(access_ops, "rotate", flaky)
    run(
        ctx, ui,
        "Vault", "Archive or revoke", '"laptop"', "Revoke", "docs", True,
        "Back",
    )  # fmt: skip
    assert any(s.endswith("a.ssc: Permission denied.") for s in ui.said)
    assert access_ops.show(ctx, docs / "b.ssc") == ['g1: key "usb"']


def test_turning_the_keychain_off_says_so(ctx: Context, ui: ScriptedUi) -> None:
    with_vault(ctx, ui)
    run(ctx, ui, "Settings", "Use this device's keychain: on", True)
    assert "✓ This device's keychain no longer unlocks the vault" in ui.said
