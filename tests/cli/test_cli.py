"""`ssc` end to end in-process: every command in CLI.md section 3, the exit
codes and credential sources of section 1, and that no secret reaches
output."""

from __future__ import annotations

import base64
import io
import os
import re
import sys
from pathlib import Path

import pytest

from secure_string_cipher.engine import keyfile, recovery
from secure_string_cipher.service import passwords
from tests.cli.conftest import Run, Terminal, secret_file
from tests.service.fakes import Keychain

PASSWORD = "a strong test passphrase"
OTHER = "another strong passphrase"
MASTER = "master password for tests"
PLAIN = b"the secret report\n" * 100
POSIX = os.name == "posix"
CODE = re.compile(r"[0-9A-Z]{4}(?:-[0-9A-Z]{4}){7}")


def shown_code(said: list[str] | str) -> str:
    """The recovery code a terminal was shown."""
    text = said if isinstance(said, str) else "\n".join(said)
    found = CODE.search(text)
    assert found, "no recovery code was shown"
    return found.group()


@pytest.fixture
def report(tmp_path: Path) -> Path:
    path = tmp_path / "report.txt"
    path.write_bytes(PLAIN)
    return path


@pytest.fixture
def pw(tmp_path: Path) -> Path:
    return secret_file(tmp_path / "pw.txt", PASSWORD)


@pytest.fixture
def vault(ssc: Run, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSC_NEW_MASTER_PASSWORD", MASTER)
    assert ssc("vault", "init").code == 0
    monkeypatch.delenv("SSC_NEW_MASTER_PASSWORD")


# --- files and exit codes -------------------------------------------------------------


def test_round_trip_with_password_files(ssc: Run, report: Path, pw: Path) -> None:
    made = ssc("encrypt", "report.txt", "--new-password-file", str(pw))
    assert made.code == 0, made.err
    assert "Wrote report.txt.ssc" in made.said
    report.unlink()
    opened = ssc("decrypt", "report.txt.ssc", "--password-file", str(pw))
    assert opened.code == 0, opened.err
    assert report.read_bytes() == PLAIN


def test_exit_codes(ssc: Run, report: Path, pw: Path, tmp_path: Path) -> None:
    assert ssc("encrypt", "report.txt", "--new-password-file", str(pw)).code == 0
    # 1: bad arguments, and a needed credential with no terminal.
    assert ssc("encrypt").code == 1
    assert ssc("frobnicate").code == 1
    asked = ssc("decrypt", "report.txt.ssc", "-o", "out.txt")
    assert asked.code == 1 and "--password-file" in asked.err
    assert ssc("decrypt", "report.txt", "--password-file", str(pw)).code == 1
    # 2: the same message, whatever was wrong.
    wrong = secret_file(tmp_path / "wrong.txt", OTHER)
    denied = ssc("decrypt", "report.txt.ssc", "-o", "o", "--password-file", str(wrong))
    assert denied.code == 2
    assert "cannot be opened with what was supplied" in denied.err
    # 3: no vault.
    assert ssc("vault", "list").code == 3
    # 4: an existing output, a missing file, and not an SSC file.
    again = ssc("encrypt", "report.txt", "--new-password-file", str(pw))
    assert again.code == 4 and "--force" in again.err
    assert ssc("decrypt", "nothing.ssc").code == 4
    junk = tmp_path / "junk.ssc"
    junk.write_bytes(b"not an ssc file at all")
    assert ssc("decrypt", "junk.ssc", "--password-file", str(pw)).code == 4


def test_errors_are_one_sentence_unless_debug(
    ssc: Run, monkeypatch: pytest.MonkeyPatch
) -> None:
    from secure_string_cipher.cli import commands

    def broken(*_: object) -> None:
        raise RuntimeError("an internal detail")

    monkeypatch.setitem(commands.HANDLERS, "generate", broken)
    quiet = ssc("generate")
    assert quiet.code == 70
    assert "internal detail" not in quiet.err and "Traceback" not in quiet.err
    loud = ssc("generate", "--debug")
    assert loud.code == 70 and "Traceback" in loud.err


def test_streams_and_armour(
    ssc: Run,
    pw: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secure_string_cipher.cli import commands

    monkeypatch.setattr(commands, "_stdin", lambda: io.BytesIO(b"some text"))
    made = ssc(
        "encrypt", "-", "-o", "note.ssc", "--armor", "--new-password-file", str(pw)
    )
    assert made.code == 0, made.err
    assert Path("note.ssc").read_bytes().startswith(b"-----BEGIN SSC MESSAGE-----")
    assert ssc("encrypt", "-").code == 1  # stdin has no name to add .ssc to
    sink = io.BytesIO()
    monkeypatch.setattr(commands, "_stdout", lambda: sink)
    assert ssc("decrypt", "note.ssc", "-o", "-", "--password-file", str(pw)).code == 0
    assert sink.getvalue() == b"some text"


# --- credential sources ---------------------------------------------------------------


@pytest.mark.skipif(not POSIX, reason="POSIX permission bits and symlinks")
def test_credential_files_must_be_private(
    ssc: Run, report: Path, pw: Path, tmp_path: Path
) -> None:
    pw.chmod(0o644)
    refused = ssc("encrypt", "report.txt", "--new-password-file", str(pw))
    assert refused.code == 1 and "chmod 600" in refused.err
    pw.chmod(0o600)
    link = tmp_path / "link.txt"
    link.symlink_to(pw)
    assert ssc("encrypt", "report.txt", "--new-password-file", str(link)).code == 1
    assert not Path("report.txt.ssc").exists()


def test_one_trailing_newline_is_removed(
    ssc: Run, report: Path, tmp_path: Path
) -> None:
    two = tmp_path / "two.txt"
    two.write_text(PASSWORD + "\n\n")
    two.chmod(0o600)
    assert ssc("encrypt", "report.txt", "--new-password-file", str(two)).code == 0
    one = secret_file(tmp_path / "one.txt", PASSWORD)
    assert (
        ssc("decrypt", "report.txt.ssc", "-o", "a", "--password-file", str(one)).code
        == 2
    )
    keep = secret_file(tmp_path / "keep.txt", PASSWORD + "\n")
    assert (
        ssc("decrypt", "report.txt.ssc", "-o", "b", "--password-file", str(keep)).code
        == 0
    )


def test_environment_variables(
    ssc: Run, report: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert ssc("key", "new", "usb.ssckey").code == 0
    monkeypatch.setenv("SSC_NEW_PASSWORD", PASSWORD)
    grant = "password+keyfile:usb.ssckey"
    assert ssc("encrypt", "report.txt", "--grant", grant).code == 0
    monkeypatch.setenv("SSC_PASSWORD", PASSWORD)
    assert ssc("decrypt", "report.txt.ssc", "-o", "a").code == 2  # no key yet
    monkeypatch.setenv(
        "SSC_KEY_FILES", os.pathsep.join(["missing.ssckey", "usb.ssckey"])
    )
    assert ssc("decrypt", "report.txt.ssc", "-o", "a").code == 4  # one is missing
    monkeypatch.setenv("SSC_KEY_FILES", "usb.ssckey")
    assert ssc("decrypt", "report.txt.ssc", "-o", "b").code == 0
    # A flag beats its variable.
    bad = secret_file(tmp_path / "bad.txt", OTHER)
    assert (
        ssc(
            "encrypt", "report.txt", "-o", "c.ssc", "--new-password-file", str(bad)
        ).code
        == 0
    )
    monkeypatch.delenv("SSC_PASSWORD")
    assert ssc("decrypt", "c.ssc", "-o", "c", "--password-file", str(bad)).code == 0


def test_a_terminal_is_asked_only_for_what_is_missing(
    ssc: Run, terminal: Terminal, report: Path
) -> None:
    terminal.tty = True
    terminal.hidden_answers += [PASSWORD, "typo", PASSWORD, PASSWORD]
    assert ssc("encrypt", "report.txt").code == 0
    assert "Those did not match." in terminal.said
    terminal.hidden_answers.append(PASSWORD)
    terminal.asked.clear()
    assert ssc("decrypt", "report.txt.ssc", "-o", "back.txt").code == 0
    assert terminal.asked == ["Password for this file: "]


# --- the vault ------------------------------------------------------------------------


def test_vault_entries_open_files_without_asking(
    ssc: Run, vault: None, report: Path, chain: Keychain
) -> None:
    status = ssc("vault", "status")
    assert "unlocked with this device" in status.out
    made = ssc("vault", "add", "work", "--password", "--generate", "--show")
    assert made.code == 0, made.err
    generated = made.out.strip()
    assert len(generated.split()) == passwords.DEFAULT_WORDS
    assert ssc("vault", "add", "laptop", "--key").code == 0  # no TTY: no offer
    listed = ssc("vault", "list").out
    assert "work\tpassword\tactive" in listed and "laptop\tkey\tactive" in listed
    assert ssc("encrypt", "report.txt", "--grant", "vault:work+vault:laptop").code == 0
    assert ssc("decrypt", "report.txt.ssc", "-o", "back.txt").code == 0
    assert generated not in ssc("vault", "list").out


def test_recovery_codes_need_a_terminal(
    ssc: Run, terminal: Terminal, vault: None, report: Path, tmp_path: Path
) -> None:
    refused = ssc("encrypt", "report.txt", "--vault", "x", "--recovery-code")
    assert refused.code == 3  # no entry "x"
    refused = ssc("vault", "add", "paper", "--recovery-code")
    assert refused.code == 1 and "terminal" in refused.err
    terminal.tty = True

    def typed_back(prompt: str) -> str:
        terminal.asked.append(prompt)
        if terminal.asked.count(prompt) == 1:
            return "WRONG"  # a slip first, then the right group
        return shown_code(terminal.said).rsplit("-", 1)[-1]

    terminal.line = typed_back  # type: ignore[method-assign]
    made = ssc("vault", "add", "paper", "--recovery-code")
    assert made.code == 0, made.err
    code = shown_code(made.said)
    recovery.decode(code)
    assert "That is not its last group" in made.said
    assert code not in made.out and code not in made.err
    # The code then opens a file made with it, with no vault at all.
    terminal.tty = False
    pw = secret_file(tmp_path / "pw.txt", PASSWORD)
    grant = ["--grant", "password", "--grant", "vault:paper"]
    assert (
        ssc("encrypt", "report.txt", *grant, "--new-password-file", str(pw)).code == 0
    )
    Path("data/vault.ssc").unlink()
    rc = secret_file(tmp_path / "rc.txt", code.lower())
    assert (
        ssc(
            "decrypt", "report.txt.ssc", "-o", "b", "--recovery-code-file", str(rc)
        ).code
        == 0
    )


def test_change_password_and_reset_with_the_vault_recovery_code(
    ssc: Run, terminal: Terminal, tmp_path: Path, chain: Keychain
) -> None:
    terminal.tty = True
    terminal.hidden_answers += [MASTER, MASTER]
    shown: list[str] = []

    def last_group(prompt: str) -> str:
        shown.append(shown_code(terminal.said))
        return shown[-1].rsplit("-", 1)[-1]

    terminal.line = last_group  # type: ignore[method-assign]
    assert ssc("vault", "init", "--no-device-key", "--recovery-code").code == 0
    terminal.tty = False
    rc = secret_file(tmp_path / "rc.txt", shown[0])
    new = secret_file(tmp_path / "new.txt", OTHER)
    reset = ssc(
        "vault",
        "change-password",
        "--recovery-code-file",
        str(rc),
        "--new-master-password-file",
        str(new),
    )
    assert reset.code == 0, reset.err
    master = secret_file(tmp_path / "m.txt", OTHER)
    assert ssc("vault", "list", "--master-password-file", str(master)).code == 0
    # Without the new one, change-password refuses rather than reusing the old.
    assert (
        ssc("vault", "change-password", "--master-password-file", str(master)).code == 1
    )


def test_access_commands(ssc: Run, vault: None, report: Path, pw: Path) -> None:
    assert ssc("vault", "add", "laptop", "--key").code == 0
    assert ssc("encrypt", "report.txt", "--vault", "laptop").code == 0
    assert ssc("access", "show", "report.txt.ssc").out == 'g1: key "laptop"\n'
    added = ssc(
        "access",
        "add",
        "report.txt.ssc",
        "--grant",
        "password",
        "--new-password-file",
        str(pw),
    )
    assert added.code == 0, added.err
    assert "only as strong as that password" in added.said
    assert ssc("access", "show", "report.txt.ssc").out.splitlines()[1] == "g2: password"
    assert (
        ssc("access", "rotate", "report.txt.ssc", "--password-file", str(pw)).code == 0
    )
    removed = ssc("access", "remove", "report.txt.ssc", "--grant", "g2")
    assert removed.code == 0 and "ssc access rotate" in removed.said
    assert "revoked" not in removed.said.lower()
    assert ssc("access", "remove", "report.txt.ssc", "--grant", "g1").code == 1
    assert ssc("profile", "create", "daily", "--grant", "vault:laptop").code == 0
    assert ssc("access", "apply", "report.txt.ssc", "--profile", "daily").code == 0
    assert ssc("decrypt", "report.txt.ssc", "-o", "back.txt").code == 0


def test_revoke_scans_and_offers_to_rotate(ssc: Run, vault: None, report: Path) -> None:
    assert ssc("vault", "add", "laptop", "--key").code == 0
    assert ssc("vault", "add", "usb", "--key").code == 0
    Path("docs").mkdir()
    for name, grants in (("a", ["vault:laptop", "vault:usb"]), ("b", ["vault:usb"])):
        flags = [x for g in grants for x in ("--grant", g)]
        assert ssc("encrypt", "report.txt", "-o", f"docs/{name}.ssc", *flags).code == 0
    found = ssc("vault", "revoke", "laptop", "--scan", "docs")
    assert found.code == 0
    assert found.out.split() == [str(Path("docs/a.ssc"))]
    assert "anyone with a copy" in found.said


def test_keys_profiles_generate_and_shred(
    ssc: Run, terminal: Terminal, vault: None, report: Path
) -> None:
    assert ssc("key", "new", "usb.ssckey", "--label", "usb").code == 0
    assert ssc("key", "import", "usb.ssckey").code == 0
    assert ssc("key", "export", "usb", "copy.ssckey").code == 0
    assert Path("copy.ssckey").read_bytes() == Path("usb.ssckey").read_bytes()
    assert ssc("key", "new", "bad.ssckey", "--label", "Bad Label").code == 1
    assert ssc("profile", "create", "daily", "--grant", "vault:usb").code == 0
    assert ssc("profile", "create", "x", "--grant", "keyfile:usb.ssckey").code == 1
    assert ssc("profile", "default", "daily").code == 0
    assert ssc("profile", "list").out == "daily\t(default)\n"
    assert ssc("profile", "show", "daily").out == 'g1: vault entry "usb"\n'
    assert ssc("encrypt", "report.txt").code == 0  # by the default profile
    assert ssc("profile", "default", "--none").code == 0
    assert ssc("profile", "delete", "daily").code == 0
    assert ssc("profile", "list").out == ""
    words = ssc("generate", "--words", "4").out.split()
    assert len(words) == 4 and all(w in passwords.wordlist() for w in words)
    assert ssc("generate", "--words", "3").code == 1
    assert ssc("shred", "report.txt").code == 1  # no terminal to ask
    assert report.exists()
    terminal.tty = True
    terminal.lines.append("y")
    shredded = ssc("shred", "report.txt")
    assert shredded.code == 0 and "SSDs" in shredded.said
    assert not report.exists()


def test_history_and_devices(
    ssc: Run, vault: None, chain: Keychain, tmp_path: Path
) -> None:
    assert ssc("vault", "history", "show").said.startswith("History is off")
    assert ssc("vault", "history", "on").code == 0
    assert ssc("vault", "add", "laptop", "--key").code == 0
    lines = ssc("vault", "history", "show").out.splitlines()
    # Turning history on is not itself recorded; it starts with the next unlock.
    assert [line.split("\t")[1:] for line in lines] == [
        ["vault-unlock"],
        ["entry-create", "laptop"],
        ["vault-unlock"],
    ]
    assert ssc("vault", "add-device").code == 3  # already this device
    assert ssc("vault", "remove-device", "g2").code == 0
    assert chain.items == {}
    assert ssc("vault", "status").out.startswith("Vault: locked")
    master = secret_file(tmp_path / "m.txt", MASTER)
    assert ssc("vault", "add-device", "--master-password-file", str(master)).code == 0
    assert ssc("vault", "backup", "backup.ssc").code == 0
    assert Path("backup.ssc").read_bytes() == Path("data/vault.ssc").read_bytes()


def test_no_secret_reaches_output(
    ssc: Run, terminal: Terminal, vault: None, report: Path, pw: Path, tmp_path: Path
) -> None:
    """CLI.md section 1: no password, key or code in stdout or stderr."""
    results = [
        ssc("vault", "add", "work", "--password", "--new-password-file", str(pw)),
        ssc("vault", "add", "laptop", "--key"),
        ssc("encrypt", "report.txt", "--vault", "work"),
        ssc("decrypt", "report.txt.ssc", "-o", "back.txt"),
        ssc("access", "show", "report.txt.ssc"),
        ssc("vault", "list"),
        ssc("vault", "status"),
        ssc(
            "decrypt",
            "report.txt.ssc",
            "-o",
            "x",
            "--password-file",
            str(pw),
            "--debug",
        ),
    ]
    results.append(ssc("key", "export", "laptop", "laptop.ssckey"))
    key = keyfile.read(Path("laptop.ssckey")).key
    key_text = base64.urlsafe_b64encode(key).rstrip(b"=").decode()
    for r in results:
        assert r.code == 0, r.err
        for text in (r.out, r.err, r.said):
            assert PASSWORD not in text and MASTER not in text
            assert key_text not in text and key.hex() not in text


def test_python_m_runs_the_cli(tmp_path: Path) -> None:
    import subprocess

    done = subprocess.run(
        [sys.executable, "-m", "secure_string_cipher", "generate"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0 and len(done.stdout.split()) == 6
    usage = subprocess.run(
        [sys.executable, "-m", "secure_string_cipher"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert usage.returncode == 1 and "usage: ssc" in usage.stderr
