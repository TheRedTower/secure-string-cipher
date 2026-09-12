"""Tests for non-interactive credential sources.

Before these existed there was no `--password`, `--password-file` or
environment variable, so v2 password mode and v2 combined mode could not be
scripted at all, and anything using the vault needed an interactive master
password. Piping worked only through CPython's degraded `getpass` fallback,
which emits a warning and has no equivalent on Windows.
"""

import os
from pathlib import Path

import pytest

from secure_string_cipher import cli_args

STRONG = "Str0ngScriptPass!2026"  # pragma: allowlist secret
WEAK = "short"  # pragma: allowlist secret
OTHER = "Different!Pass2026"  # pragma: allowlist secret
CRLF_AND_CONTROL_Z = "ab\r\ncd\x1aef"  # pragma: allowlist secret


def _password_file(directory: Path, value: str, *, mode: int = 0o600) -> Path:
    path = directory / "pw.txt"
    path.write_text(value + "\n")
    path.chmod(mode)
    return path


def _args(**overrides: object) -> object:
    import argparse

    defaults = {
        "quiet": False,
        "no_color": False,
        "debug": False,
        "password_file": None,
        "master_password_file": None,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestPasswordFile:
    def test_password_file_supplies_the_password_without_prompting(
        self, tmp_path: Path
    ) -> None:
        cli_args._resolve_credential_sources(
            _args(password_file=str(_password_file(tmp_path, STRONG)))
        )
        # No getpass patching: if this prompted, the test would hang or raise.
        assert cli_args._prompt_password() == STRONG

    def test_one_trailing_newline_is_removed(self, tmp_path: Path) -> None:
        """A file written with `echo` has a newline the operator did not intend."""
        path = tmp_path / "pw.txt"
        path.write_bytes(STRONG.encode() + b"\n")
        path.chmod(0o600)
        cli_args._resolve_credential_sources(_args(password_file=str(path)))
        assert cli_args._prompt_password() == STRONG

    def test_a_file_without_a_trailing_newline_works(self, tmp_path: Path) -> None:
        path = tmp_path / "pw.txt"
        path.write_bytes(STRONG.encode())
        path.chmod(0o600)
        cli_args._resolve_credential_sources(_args(password_file=str(path)))
        assert cli_args._prompt_password() == STRONG

    def test_confirmation_is_skipped_for_a_supplied_password(
        self, tmp_path: Path
    ) -> None:
        """There is nothing to confirm a file against."""
        cli_args._resolve_credential_sources(
            _args(password_file=str(_password_file(tmp_path, STRONG)))
        )
        assert cli_args._prompt_password(confirm=True) == STRONG

    @pytest.mark.skipif(os.name != "posix", reason="POSIX permission semantics")
    def test_group_or_other_readable_file_is_refused(self, tmp_path: Path) -> None:
        """A password file is a bearer secret, held to the same standard as
        a .ssckey: refused rather than used with a warning."""
        path = _password_file(tmp_path, STRONG, mode=0o644)
        with pytest.raises(SystemExit) as excinfo:
            cli_args._resolve_credential_sources(_args(password_file=str(path)))
        assert excinfo.value.code == cli_args.EXIT_FILE_ERROR

    def test_empty_file_is_refused_rather_than_read_as_an_empty_password(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "empty.txt"
        path.write_bytes(b"")
        path.chmod(0o600)
        with pytest.raises(SystemExit) as excinfo:
            cli_args._resolve_credential_sources(_args(password_file=str(path)))
        assert excinfo.value.code == cli_args.EXIT_INPUT_ERROR

    def test_newline_only_file_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "nl.txt"
        path.write_bytes(b"\n")
        path.chmod(0o600)
        with pytest.raises(SystemExit):
            cli_args._resolve_credential_sources(_args(password_file=str(path)))

    def test_missing_file_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit) as excinfo:
            cli_args._resolve_credential_sources(
                _args(password_file=str(tmp_path / "absent.txt"))
            )
        assert excinfo.value.code == cli_args.EXIT_FILE_ERROR

    def test_a_directory_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit):
            cli_args._resolve_credential_sources(_args(password_file=str(tmp_path)))

    def test_non_utf8_file_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "bin.txt"
        path.write_bytes(b"\xff\xfe not text")
        path.chmod(0o600)
        with pytest.raises(SystemExit) as excinfo:
            cli_args._resolve_credential_sources(_args(password_file=str(path)))
        assert excinfo.value.code == cli_args.EXIT_INPUT_ERROR

    def test_oversized_file_is_refused_before_reaching_the_kdf(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "big.txt"
        path.write_bytes(b"A" * (cli_args._MAX_PASSWORD_FILE_BYTES + 10))
        path.chmod(0o600)
        with pytest.raises(SystemExit) as excinfo:
            cli_args._resolve_credential_sources(_args(password_file=str(path)))
        assert excinfo.value.code == cli_args.EXIT_INPUT_ERROR

    @pytest.mark.skipif(os.name != "posix", reason="requires symlink support")
    def test_a_symlinked_password_file_is_refused(self, tmp_path: Path) -> None:
        real = _password_file(tmp_path, STRONG)
        link = tmp_path / "link.txt"
        link.symlink_to(real)
        with pytest.raises(SystemExit) as excinfo:
            cli_args._resolve_credential_sources(_args(password_file=str(link)))
        assert excinfo.value.code == cli_args.EXIT_FILE_ERROR


class TestEnvironmentVariables:
    def test_ssc_password_supplies_the_password(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SSC_PASSWORD", STRONG)
        cli_args._resolve_credential_sources(_args())
        assert cli_args._prompt_password() == STRONG

    def test_ssc_master_password_supplies_the_master_password(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SSC_MASTER_PASSWORD", STRONG)
        cli_args._resolve_credential_sources(_args())
        assert cli_args._prompt_master_password() == STRONG

    def test_an_empty_variable_is_treated_as_unset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SSC_PASSWORD", "")
        cli_args._resolve_credential_sources(_args())
        assert cli_args._password_source is None

    def test_the_flag_wins_over_the_variable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Naming a file is the more deliberate act, and it stops a stale
        exported variable quietly overriding the command line."""
        monkeypatch.setenv("SSC_PASSWORD", OTHER)
        cli_args._resolve_credential_sources(
            _args(password_file=str(_password_file(tmp_path, STRONG)))
        )
        assert cli_args._prompt_password() == STRONG

    def test_the_two_roles_are_independent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A data password and a vault master password are different secrets."""
        monkeypatch.setenv("SSC_MASTER_PASSWORD", OTHER)
        cli_args._resolve_credential_sources(
            _args(password_file=str(_password_file(tmp_path, STRONG)))
        )
        assert cli_args._prompt_password() == STRONG
        assert cli_args._prompt_master_password() == OTHER


class TestStrengthValidationStillApplies:
    def test_a_weak_supplied_password_is_refused_not_retried(
        self, tmp_path: Path
    ) -> None:
        """The interactive path loops until the password is strong enough.

        A supplied source cannot be re-prompted, so it must fail rather than
        loop forever.
        """
        cli_args._resolve_credential_sources(
            _args(password_file=str(_password_file(tmp_path, WEAK)))
        )
        with pytest.raises(SystemExit) as excinfo:
            cli_args._prompt_password_with_validation()
        assert excinfo.value.code == cli_args.EXIT_INPUT_ERROR

    def test_a_strong_supplied_password_is_accepted(self, tmp_path: Path) -> None:
        cli_args._resolve_credential_sources(
            _args(password_file=str(_password_file(tmp_path, STRONG)))
        )
        assert cli_args._prompt_password_with_validation() == STRONG


class TestParser:
    def test_both_flags_are_accepted_and_default_to_none(self) -> None:
        parser = cli_args.create_parser()
        args = parser.parse_args(["encrypt", "-t", "x"])
        assert args.password_file is None
        assert args.master_password_file is None

        args = parser.parse_args(
            [
                "--password-file",
                "/p",
                "--master-password-file",
                "/m",
                "encrypt",
                "-t",
                "x",
            ]
        )
        assert args.password_file == "/p"
        assert args.master_password_file == "/m"


class TestTheTwoMasterPasswordRolesAreDistinct:
    """Setting a master password and using one are different roles.

    A single supplied value read as both would let `vault change-password`
    re-encrypt the vault with the password it already has and report a
    successful rotation — an operator rotating a compromised password would
    believe it had been replaced.
    """

    def test_change_password_refuses_to_reuse_the_supplied_current_password(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import argparse

        monkeypatch.setenv("SSC_MASTER_PASSWORD", STRONG)
        cli_args._resolve_credential_sources(_args())

        with pytest.raises(SystemExit) as excinfo:
            cli_args.cmd_vault_change_password(argparse.Namespace())
        assert excinfo.value.code == cli_args.EXIT_INPUT_ERROR

    def test_the_new_password_has_its_own_source(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SSC_MASTER_PASSWORD", STRONG)
        monkeypatch.setenv("SSC_NEW_MASTER_PASSWORD", OTHER)
        cli_args._resolve_credential_sources(_args())

        assert cli_args._prompt_master_password() == STRONG
        assert (
            cli_args._prompt_master_password_to_set(
                "unused: ",
                supplied=cli_args._new_master_password_source,
                source_flag="",
            )
            == OTHER
        )

    def test_a_weak_password_being_set_fails_rather_than_prompting(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SSC_NEW_MASTER_PASSWORD", WEAK)
        cli_args._resolve_credential_sources(_args())
        with pytest.raises(SystemExit) as excinfo:
            cli_args._prompt_master_password_to_set(
                "unused: ",
                supplied=cli_args._new_master_password_source,
                source_flag="SSC_NEW_MASTER_PASSWORD",
            )
        assert excinfo.value.code == cli_args.EXIT_INPUT_ERROR

    def test_vault_initialisation_uses_the_master_source_not_the_data_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With both files supplied, initialising from the data password
        would leave the very next unlock failing against the master one."""
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("SSC_PASSWORD", OTHER)
        monkeypatch.setenv("SSC_MASTER_PASSWORD", STRONG)
        cli_args._resolve_credential_sources(_args())
        monkeypatch.setattr("builtins.input", lambda: "y")

        vault = cli_args._get_vault()
        assert vault.vault_exists()
        # Proof of which password the vault was built with: the master one
        # opens it, and a store/retrieve round-trip completes.
        vault.store_passphrase("label", "value", STRONG)
        assert vault.retrieve_passphrase("label", STRONG) == "value"


class TestTheFileIsCheckedOnTheDescriptor:
    """The permission and type checks must apply to what was opened.

    Checking the path and then opening it leaves a window in which another
    local process can replace the final component, so the checks would
    describe the old inode while the read consumes a substituted one. The
    race is not deterministically reproducible from a test, so these assert
    the mechanism that closes it instead of staging a fake reproduction.
    """

    @pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="POSIX-only flag")
    def test_the_file_is_opened_with_o_nofollow(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorded: list[int] = []
        real_open = os.open

        def spy(path: object, flags: int, *args: object, **kwargs: object) -> int:
            recorded.append(flags)
            return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(os, "open", spy)
        cli_args._resolve_credential_sources(
            _args(password_file=str(_password_file(tmp_path, STRONG)))
        )
        assert recorded, "the password file was not opened through os.open"
        assert all(flags & os.O_NOFOLLOW for flags in recorded)

    @pytest.mark.skipif(os.name != "posix", reason="requires mkfifo")
    def test_a_fifo_is_refused_by_the_descriptor_type_check(
        self, tmp_path: Path
    ) -> None:
        """A named pipe is not a file to read a password from, and reading
        one would block or return an attacker-fed value."""
        fifo = tmp_path / "pipe"
        os.mkfifo(fifo, 0o600)
        with pytest.raises(SystemExit) as excinfo:
            cli_args._resolve_credential_sources(_args(password_file=str(fifo)))
        assert excinfo.value.code == cli_args.EXIT_FILE_ERROR

    @pytest.mark.skipif(not hasattr(os, "O_BINARY"), reason="Windows-only flag")
    def test_the_file_is_opened_in_binary_mode(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorded: list[int] = []
        real_open = os.open

        def spy(path: object, flags: int, *args: object, **kwargs: object) -> int:
            recorded.append(flags)
            return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(os, "open", spy)
        cli_args._resolve_credential_sources(
            _args(password_file=str(_password_file(tmp_path, STRONG)))
        )
        assert recorded
        assert all(flags & os.O_BINARY for flags in recorded)

    def test_a_password_containing_cr_or_control_z_survives_verbatim(
        self, tmp_path: Path
    ) -> None:
        """Text-mode translation would rewrite the file's actual bytes.

        On Windows a descriptor opened without `O_BINARY` has CRLF collapsed
        to LF and is truncated at a control-Z, so a password containing
        either would be silently changed before this code ever saw it — and
        the file would then decrypt nothing it had encrypted. Meaningful on
        Windows; on POSIX it simply documents that only *one trailing* line
        ending is removed.
        """
        password = CRLF_AND_CONTROL_Z
        path = tmp_path / "pw.txt"
        path.write_bytes(password.encode() + b"\n")
        path.chmod(0o600)

        cli_args._resolve_credential_sources(_args(password_file=str(path)))
        assert cli_args._prompt_password() == password
