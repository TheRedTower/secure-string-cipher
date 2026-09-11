"""End-to-end CLI tests for the ``ssc key`` subcommand group.

Unlike test_v2_vault_service.py (which tests V2VaultService's methods
directly) and test_cli_args.py's argument-parsing tests (which never touch a
real vault), these tests run the actual cmd_key_* functions in cli_args.py
against a real, hermetic, file-backed vault: create/import/show/export/
list/rename/archive/revoke/destroy, plus the interaction between
revoke/destroy and the --vault key-status enforcement added for encrypt and
decrypt. Only the master-password prompt, the destroy confirmation prompt,
and HOME are mocked/redirected.

Note: cmd_key_*'s "✓ ..." confirmation messages go through _print_info,
which prints to stderr (not stdout) — assertions below check .err for those,
and .out only for cmd_key_list/cmd_key_show's plain print() output.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import secure_string_cipher.cli_args as cli_args
from secure_string_cipher.rate_limiter import PersistentRateLimiter
from secure_string_cipher.v2.key_identity import compute_fingerprint
from secure_string_cipher.v2.keyfile import KeyFileData, load_keyfile, save_keyfile

MASTER = "vault-master-password-2026!"  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def _hermetic_cli_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate every test from the real ~/.secure-cipher and ~/.ssc state.

    Mirrors test_v2_cli_e2e.py's fixture of the same purpose.
    """
    home = tmp_path / "hermetic-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(
        cli_args,
        "_cli_limiter",
        PersistentRateLimiter(state_path=str(tmp_path / "rate_limits.json")),
    )
    monkeypatch.setattr(cli_args, "get_audit_logger", MagicMock())
    monkeypatch.setattr(cli_args, "_prompt_master_password", lambda: MASTER)


def _create_args(id_: str, **overrides: object) -> argparse.Namespace:
    base: dict[str, object] = {
        "id": id_,
        "external_file": None,
        "vault_copy": False,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def _import_args(file: str, **overrides: object) -> argparse.Namespace:
    base: dict[str, object] = {"file": file, "vault_copy": False}
    base.update(overrides)
    return argparse.Namespace(**base)


def _id_args(id_: str) -> argparse.Namespace:
    return argparse.Namespace(id=id_)


def _export_args(id_: str, dest: str) -> argparse.Namespace:
    return argparse.Namespace(id=id_, dest=dest)


def _rename_args(id_: str, new_id: str) -> argparse.Namespace:
    return argparse.Namespace(id=id_, new_id=new_id)


def _destroy_args(id_: str, confirm: bool = True) -> argparse.Namespace:
    return argparse.Namespace(id=id_, confirm=confirm)


def _encrypt_args(**overrides: object) -> argparse.Namespace:
    base: dict[str, object] = {
        "text": None,
        "file": None,
        "positional_path": None,
        "vault": None,
        "key_file": None,
        "force": False,
        "with_sources": None,
        "require": "any",
        "output": None,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def _standalone_keyfile(path: Path, key_id: str) -> KeyFileData:
    """A .ssckey file that was never created through cmd_key_create, for
    testing `ssc key import` as a genuinely standalone operation."""
    secret = key_id.encode("utf-8").ljust(32, b"\x00")[:32]
    data = KeyFileData(
        version=1,
        key_id=key_id,
        key_type="symmetric-key",
        kdf="hkdf-sha256",
        fingerprint=compute_fingerprint(secret),
        created_at="2026-09-11T00:00:00Z",
        secret_bytes=secret,
    )
    save_keyfile(data, path)
    return data


# =============================================================================
# create / list / show
# =============================================================================


def test_key_create_external_only_persists_and_is_listable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dest = tmp_path / "laptop.ssckey"
    rc = cli_args.cmd_key_create(_create_args("laptop", external_file=str(dest)))
    assert rc == cli_args.EXIT_SUCCESS
    assert dest.exists()
    assert "Key created" in capsys.readouterr().err

    loaded = load_keyfile(dest)
    assert loaded.key_id == "laptop"

    rc = cli_args.cmd_key_list(argparse.Namespace())
    assert rc == cli_args.EXIT_SUCCESS
    listing = capsys.readouterr().out
    assert "laptop" in listing
    assert loaded.fingerprint in listing
    assert "(active)" in listing


def test_key_create_vault_copy_persists_and_is_listable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = cli_args.cmd_key_create(_create_args("backup", vault_copy=True))
    assert rc == cli_args.EXIT_SUCCESS
    capsys.readouterr()

    rc = cli_args.cmd_key_list(argparse.Namespace())
    assert rc == cli_args.EXIT_SUCCESS
    assert "backup" in capsys.readouterr().out


def test_key_create_requires_a_storage_target(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_key_create(_create_args("no-target"))
    assert excinfo.value.code == cli_args.EXIT_INPUT_ERROR
    assert "no key was created" in capsys.readouterr().err


def test_key_list_reports_no_keys_found(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli_args.cmd_key_list(argparse.Namespace())
    assert rc == cli_args.EXIT_SUCCESS
    assert "No keys found." in capsys.readouterr().err


def test_key_show_displays_details(capsys: pytest.CaptureFixture[str]) -> None:
    cli_args.cmd_key_create(_create_args("shown", vault_copy=True))
    capsys.readouterr()

    rc = cli_args.cmd_key_show(_id_args("shown"))
    assert rc == cli_args.EXIT_SUCCESS
    out = capsys.readouterr().out
    assert "ID: shown" in out
    assert "Status: active" in out
    assert "Storage: vault-copy" in out


def test_key_show_unknown_id_exits_vault_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_key_show(_id_args("nonexistent"))
    assert excinfo.value.code == cli_args.EXIT_VAULT_ERROR
    assert "Failed to get key details." in capsys.readouterr().err


# =============================================================================
# import / export
# =============================================================================


def test_key_import_registers_a_standalone_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    src = tmp_path / "standalone.ssckey"
    keyfile = _standalone_keyfile(src, "standalone")

    rc = cli_args.cmd_key_import(_import_args(str(src)))
    assert rc == cli_args.EXIT_SUCCESS
    assert "Key imported" in capsys.readouterr().err

    rc = cli_args.cmd_key_list(argparse.Namespace())
    listing = capsys.readouterr().out
    assert "standalone" in listing
    assert keyfile.fingerprint in listing


def test_key_export_vault_copy_roundtrips_secret(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cli_args.cmd_key_create(_create_args("exportable", vault_copy=True))
    capsys.readouterr()

    dest = tmp_path / "exported.ssckey"
    rc = cli_args.cmd_key_export(_export_args("exportable", str(dest)))
    assert rc == cli_args.EXIT_SUCCESS
    assert dest.exists()
    loaded = load_keyfile(dest)
    assert loaded.key_id == "exportable"
    assert len(loaded.secret_bytes) == 32


def test_key_export_rejects_external_only_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    src = tmp_path / "ext.ssckey"
    cli_args.cmd_key_create(_create_args("ext-only", external_file=str(src)))
    capsys.readouterr()

    dest = tmp_path / "copy.ssckey"
    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_key_export(_export_args("ext-only", str(dest)))
    assert excinfo.value.code == cli_args.EXIT_VAULT_ERROR
    assert "Key export failed." in capsys.readouterr().err
    assert not dest.exists()


# =============================================================================
# rename
# =============================================================================


def test_key_rename_changes_id(capsys: pytest.CaptureFixture[str]) -> None:
    cli_args.cmd_key_create(_create_args("old-name", vault_copy=True))
    capsys.readouterr()

    rc = cli_args.cmd_key_rename(_rename_args("old-name", "new-name"))
    assert rc == cli_args.EXIT_SUCCESS
    assert "renamed to new-name" in capsys.readouterr().err

    rc = cli_args.cmd_key_show(_id_args("new-name"))
    assert rc == cli_args.EXIT_SUCCESS
    assert "ID: new-name" in capsys.readouterr().out

    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_key_show(_id_args("old-name"))
    assert excinfo.value.code == cli_args.EXIT_VAULT_ERROR


# =============================================================================
# archive / revoke / destroy, and their interaction with --vault enforcement
# =============================================================================


def test_key_archive_sets_status_but_never_blocks_use(
    capsys: pytest.CaptureFixture[str],
) -> None:
    keys_dir = Path(os.environ["HOME"]) / ".ssc" / "keys"
    keys_dir.mkdir(parents=True)
    dest = keys_dir / "archived-key.ssckey"

    # --external-file both writes the .ssckey file AND registers the key
    # in the vault in one step; no separate import is needed or possible
    # (importing the same key_id again would conflict).
    cli_args.cmd_key_create(_create_args("archived-key", external_file=str(dest)))
    capsys.readouterr()

    rc = cli_args.cmd_key_archive(_id_args("archived-key"))
    assert rc == cli_args.EXIT_SUCCESS
    assert "archived" in capsys.readouterr().err

    rc = cli_args.cmd_key_show(_id_args("archived-key"))
    assert "Status: archived" in capsys.readouterr().out

    # Archived is bookkeeping only: still usable even with --vault set.
    rc = cli_args.cmd_encrypt(
        _encrypt_args(
            text="secret", with_sources=["key:archived-key"], vault="anything"
        )
    )
    assert rc == cli_args.EXIT_SUCCESS


def test_key_revoke_blocks_use_only_with_vault_flag(
    capsys: pytest.CaptureFixture[str],
) -> None:
    keys_dir = Path(os.environ["HOME"]) / ".ssc" / "keys"
    keys_dir.mkdir(parents=True)
    dest = keys_dir / "revoked-key.ssckey"

    cli_args.cmd_key_create(_create_args("revoked-key", external_file=str(dest)))
    capsys.readouterr()

    rc = cli_args.cmd_key_revoke(_id_args("revoked-key"))
    assert rc == cli_args.EXIT_SUCCESS
    assert "revoked" in capsys.readouterr().err

    # Without --vault: the CLI's default offline behavior is unchanged.
    rc = cli_args.cmd_encrypt(
        _encrypt_args(text="secret", with_sources=["key:revoked-key"])
    )
    assert rc == cli_args.EXIT_SUCCESS

    # With --vault: the revoke set by this exact CLI command is enforced.
    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_encrypt(
            _encrypt_args(
                text="secret", with_sources=["key:revoked-key"], vault="anything"
            )
        )
    assert excinfo.value.code == cli_args.EXIT_AUTH_ERROR
    assert "revoked" in capsys.readouterr().err.lower()


def test_key_destroy_with_confirm_flag_removes_recoverable_secret(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cli_args.cmd_key_create(_create_args("doomed", vault_copy=True))
    capsys.readouterr()

    rc = cli_args.cmd_key_destroy(_destroy_args("doomed", confirm=True))
    assert rc == cli_args.EXIT_SUCCESS
    assert "destroyed" in capsys.readouterr().err

    rc = cli_args.cmd_key_show(_id_args("doomed"))
    assert "Status: destroyed" in capsys.readouterr().out

    # The vault-copy secret is gone: export must fail now.
    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_key_export(
            _export_args("doomed", str(tmp_path / "should-not-exist.ssckey"))
        )
    assert excinfo.value.code == cli_args.EXIT_VAULT_ERROR


def test_key_destroy_without_confirm_prompts_and_can_be_cancelled(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cli_args.cmd_key_create(_create_args("maybe-doomed", vault_copy=True))
    capsys.readouterr()

    monkeypatch.setattr("builtins.input", lambda: "n")
    with pytest.raises(SystemExit) as excinfo:
        cli_args.cmd_key_destroy(_destroy_args("maybe-doomed", confirm=False))
    assert excinfo.value.code == cli_args.EXIT_INPUT_ERROR
    assert "cancelled" in capsys.readouterr().err.lower()

    # Still alive: the cancelled prompt never called destroy_key.
    cli_args.cmd_key_show(_id_args("maybe-doomed"))
    assert "Status: active" in capsys.readouterr().out


def test_key_destroy_without_confirm_prompts_and_can_proceed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cli_args.cmd_key_create(_create_args("prompted-doomed", vault_copy=True))
    capsys.readouterr()

    monkeypatch.setattr("builtins.input", lambda: "y")
    rc = cli_args.cmd_key_destroy(_destroy_args("prompted-doomed", confirm=False))
    assert rc == cli_args.EXIT_SUCCESS

    rc = cli_args.cmd_key_show(_id_args("prompted-doomed"))
    assert "Status: destroyed" in capsys.readouterr().out
