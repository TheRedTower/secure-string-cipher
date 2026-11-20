"""The Phase 4 gate (GAME_PLAN.md section 11): every flow in the CLI
contract, end to end, through the installed `ssc` command as a separate
process, on each OS CI runs. tests/cli covers the same commands in-process,
with fakes; this checks the real entry point, real stdin and stdout, and
the exit codes a script sees.

Each test gets its own vault and settings folder: platformdirs honours
XDG_DATA_HOME and XDG_CONFIG_HOME on Linux and macOS, and
WIN_PD_OVERRIDE_LOCAL_APPDATA on Windows. Nothing here writes to the OS
keychain: the vault is made with --no-device-key. Flows that need a TTY, such
as showing a new recovery code, or the keychain, such as add-device, are
covered in-process (tests/cli, tests/interactive) and by the real-keychain
test; here they are checked to fail cleanly without one."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

import pytest

PASSWORD = "a strong test passphrase"
OTHER = "another strong passphrase"
MASTER = "master password for tests"
NEW_MASTER = "a new master password"
PLAIN = b"the secret report\n" * 5000
SECRETS = (PASSWORD, OTHER, MASTER, NEW_MASTER)


class Master(TypedDict):
    """`**master`, typed so it cannot be read as `stdin`."""

    SSC_MASTER_PASSWORD: str


def _installed() -> str:
    found = shutil.which("ssc", path=str(Path(sys.executable).parent))
    if found is None:
        pytest.skip("the ssc command is not installed next to this Python")
    return found


@dataclass
class Result:
    code: int
    out: bytes
    err: str

    @property
    def text(self) -> str:
        """stdout as text. Text output ends lines with CRLF on Windows, as
        `print` does there; `out` stays as written, for binary output."""
        return self.out.decode().replace("\r\n", "\n")


@dataclass
class Ssc:
    """`ssc` in `work`, with its vault and settings under `state`."""

    exe: str
    work: Path
    state: Path

    def env(self, extra: dict[str, str]) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith("SSC_")}
        env.update(
            XDG_DATA_HOME=str(self.state / "data"),
            XDG_CONFIG_HOME=str(self.state / "config"),
            WIN_PD_OVERRIDE_LOCAL_APPDATA=str(self.state / "local"),
            WIN_PD_OVERRIDE_APPDATA=str(self.state / "roaming"),
        )
        env.update(extra)
        return env

    def __call__(self, *argv: str, stdin: bytes = b"", **env: str) -> Result:
        done = subprocess.run(
            [self.exe, *argv],
            input=stdin,
            capture_output=True,
            cwd=self.work,
            env=self.env(env),
            timeout=120,
            check=False,
        )
        err = done.stderr.decode()
        for secret in SECRETS:  # CLI.md section 1: secrets never reach output
            assert secret not in err
            assert secret.encode() not in done.stdout
        assert "Traceback" not in err  # one plain sentence, no traceback
        return Result(done.returncode, done.stdout, err)

    def ok(self, *argv: str, stdin: bytes = b"", **env: str) -> Result:
        result = self(*argv, stdin=stdin, **env)
        assert result.code == 0, f"{argv}: {result.err}"
        return result

    def secret(self, name: str, text: str) -> str:
        path = self.work / name
        path.write_text(text + "\n", encoding="utf-8")
        path.chmod(0o600)
        return name


@pytest.fixture
def ssc(tmp_path: Path) -> Ssc:
    work, state = tmp_path / "work", tmp_path / "state"
    work.mkdir()
    state.mkdir()
    (work / "report.txt").write_bytes(PLAIN)
    return Ssc(_installed(), work, state)


@pytest.fixture
def vault(ssc: Ssc) -> Ssc:
    ssc.ok("vault", "init", "--no-device-key", SSC_NEW_MASTER_PASSWORD=MASTER)
    return ssc


# --- section 1: conventions, exit codes and credentials --------------------------


def test_files_streams_and_exit_codes(ssc: Ssc) -> None:
    pw = ssc.secret("pw.txt", PASSWORD)
    # Positional files; <input>.ssc; the input name without .ssc.
    ssc.ok("encrypt", "report.txt", "--new-password-file", pw)
    assert ssc("encrypt", "report.txt", "--new-password-file", pw).code == 4
    ssc.ok("encrypt", "report.txt", "--new-password-file", pw, "--force")
    assert ssc("decrypt", "report.txt.ssc", "--password-file", pw).code == 4
    ssc.ok("decrypt", "report.txt.ssc", "--password-file", pw, "--force")
    assert (ssc.work / "report.txt").read_bytes() == PLAIN

    # stdin and stdout, armour detected on its own.
    sealed = ssc.ok(
        "encrypt", "-", "-o", "-", "--armor", stdin=PLAIN, SSC_NEW_PASSWORD=PASSWORD
    ).out
    assert sealed.startswith(b"-----BEGIN")
    out = ssc.ok("decrypt", "-", "-o", "-", stdin=sealed, SSC_PASSWORD=PASSWORD)
    assert out.out == PLAIN

    # Exit codes: 1 input, 2 cannot open, 3 vault, 4 file.
    assert ssc("encrypt", "report.txt", "-o", "n.ssc", "--grant", "nonsense").code == 1
    assert ssc("decrypt", "report.txt.ssc", "-o", "n").code == 1  # needed, no TTY
    wrong = ssc("decrypt", "report.txt.ssc", "-o", "-", SSC_PASSWORD=OTHER)
    assert (wrong.code, wrong.out) == (2, b"")
    assert ssc("vault", "list").code == 3  # no vault
    assert ssc("decrypt", "missing.ssc", "-o", "x", SSC_PASSWORD=PASSWORD).code == 4
    (ssc.work / "junk.ssc").write_bytes(b"not an SSC file")
    assert ssc("decrypt", "junk.ssc", SSC_PASSWORD=PASSWORD).code == 4


def test_nothing_reaches_stdout_before_the_whole_file_authenticates(
    ssc: Ssc,
) -> None:
    ssc.ok("encrypt", "report.txt", SSC_NEW_PASSWORD=PASSWORD)
    sealed = bytearray((ssc.work / "report.txt.ssc").read_bytes())
    sealed[-1] ^= 1  # the final chunk's tag
    (ssc.work / "bad.ssc").write_bytes(bytes(sealed))
    bad = ssc("decrypt", "bad.ssc", "-o", "-", SSC_PASSWORD=PASSWORD)
    assert (bad.code, bad.out) == (4, b"")
    assert not (ssc.work / "bad").exists()


def test_password_files_environment_and_key_files(ssc: Ssc) -> None:
    a, b = ssc.secret("a.txt", PASSWORD), ssc.secret("b.txt", OTHER)
    ssc.ok("key", "new", "usb.ssckey")
    ssc.ok(
        "encrypt", "report.txt", "--grant", "password+keyfile:usb.ssckey",
        "--new-password-file", a,
    )  # fmt: skip
    # Up to 5 opening passwords, each tried, plus SSC_PASSWORD; SSC_KEY_FILES.
    ssc.ok(
        "decrypt", "report.txt.ssc", "-o", "one.txt",
        "--password-file", b, "--password-file", a, "--key-file", "usb.ssckey",
    )  # fmt: skip
    ssc.ok(
        "decrypt", "report.txt.ssc", "-o", "two.txt",
        SSC_PASSWORD=PASSWORD, SSC_KEY_FILES=os.pathsep.join(["usb.ssckey"]),
    )  # fmt: skip
    assert (ssc.work / "one.txt").read_bytes() == PLAIN
    assert (ssc.work / "two.txt").read_bytes() == PLAIN
    many = [x for _ in range(6) for x in ("--password-file", a)]
    assert ssc("decrypt", "report.txt.ssc", "-o", "x", *many).code == 1
    if os.name == "posix":  # credential files must not be readable by others
        (ssc.work / a).chmod(0o644)
        assert ssc("decrypt", "report.txt.ssc", "--password-file", a).code == 1


# --- sections 2 and 3.1: grant specs, encrypt and decrypt ------------------------


def test_grants_profiles_and_the_vault_in_files(vault: Ssc) -> None:
    ssc, master = vault, Master(SSC_MASTER_PASSWORD=MASTER)
    ssc.ok("vault", "add", "work", "--password", SSC_NEW_PASSWORD=OTHER, **master)
    ssc.ok("vault", "add", "laptop", "--key", **master)
    ssc.ok("encrypt", "report.txt", "-o", "v.ssc", "--vault", "work", **master)
    ssc.ok(
        "encrypt", "report.txt", "-o", "g.ssc",
        "--grant", "vault:laptop", "--grant", "password",
        SSC_NEW_PASSWORD=PASSWORD, **master,
    )  # fmt: skip
    # recovery with no active recovery entry needs a TTY to show the new code.
    assert ssc("encrypt", "report.txt", "-o", "r.ssc", "--recovery-code").code == 1
    ssc.ok("profile", "create", "daily", "--grant", "vault:laptop", **master)
    assert ssc("profile", "create", "bad", "--grant", "keyfile:x", **master).code == 1
    ssc.ok("profile", "default", "daily", **master)
    ssc.ok("encrypt", "report.txt", "-o", "p.ssc", **master)  # the default profile
    for name in ("v.ssc", "g.ssc", "p.ssc"):
        out = ssc.ok("decrypt", name, "-o", "-", **master).out
        assert out == PLAIN
    assert ssc.ok("access", "show", "p.ssc", **master).text.splitlines() == [
        'g1: key "laptop"'
    ]


def test_grant_spec_limits(ssc: Ssc) -> None:
    """CLI.md section 2: a factor once per grant, at most 5 factors, and at
    most 16 grants."""
    for i in range(6):
        ssc.ok("key", "new", f"k{i}.ssckey")
    keys = [f"keyfile:k{i}.ssckey" for i in range(6)]
    assert ssc("encrypt", "report.txt", "--grant", "+".join(keys)).code == 1
    twice = "keyfile:k0.ssckey+keyfile:k0.ssckey"
    assert ssc("encrypt", "report.txt", "--grant", twice).code == 1
    many = [x for _ in range(17) for x in ("--grant", "keyfile:k0.ssckey")]
    assert ssc("encrypt", "report.txt", *many).code == 1
    ssc.ok("encrypt", "report.txt", "--grant", "+".join(keys[:5]))


def test_rotate_drops_what_it_cannot_rebuild_only_with_force(ssc: Ssc) -> None:
    ssc.ok("key", "new", "usb.ssckey")
    ssc.ok(
        "encrypt", "report.txt", "--grant", "password", "--grant", "keyfile:usb.ssckey",
        SSC_NEW_PASSWORD=PASSWORD,
    )  # fmt: skip
    # Opened with the key alone, the password grant cannot be rebuilt; with
    # no TTY to ask, the safe answer is not to drop it.
    keyed = ("--key-file", "usb.ssckey")
    assert ssc("access", "rotate", "report.txt.ssc", *keyed).code == 1
    assert len(ssc.ok("access", "show", "report.txt.ssc").text.splitlines()) == 2
    ssc.ok("access", "rotate", "report.txt.ssc", "--force", *keyed)
    assert ssc.ok("access", "show", "report.txt.ssc").text.startswith("g1: key ")
    assert len(ssc.ok("access", "show", "report.txt.ssc").text.splitlines()) == 1


# --- section 3.2: access ---------------------------------------------------------


def test_access_show_add_remove_rotate_apply(vault: Ssc) -> None:
    ssc, master = vault, Master(SSC_MASTER_PASSWORD=MASTER)
    ssc.ok("vault", "add", "laptop", "--key", **master)
    ssc.ok("profile", "create", "both", "--grant", "vault:laptop", **master)
    ssc.ok("encrypt", "report.txt", SSC_NEW_PASSWORD=PASSWORD)
    assert ssc.ok("access", "show", "report.txt.ssc").text == "g1: password\n"
    added = ssc.ok(
        "access", "add", "report.txt.ssc", "--grant", "vault:laptop",
        SSC_PASSWORD=PASSWORD, **master,
    )  # fmt: skip
    assert "Added a way in" in added.err
    removed = ssc.ok(
        "access", "remove", "report.txt.ssc", "--grant", "g1", **master
    )  # opens with the vault key now
    assert "ssc access rotate" in removed.err
    assert "revoked" not in removed.err.lower()
    before = (ssc.work / "report.txt.ssc").read_bytes()
    rotated = ssc.ok("access", "rotate", "report.txt.ssc", **master)
    assert "Old copies of this file still open" in rotated.err
    assert (ssc.work / "report.txt.ssc").read_bytes() != before
    ssc.ok("access", "apply", "report.txt.ssc", "--profile", "both", **master)
    assert ssc.ok("decrypt", "report.txt.ssc", "-o", "-", **master).out == PLAIN


# --- section 3.3: the vault ------------------------------------------------------


def test_the_vault_commands(vault: Ssc) -> None:
    ssc, master = vault, Master(SSC_MASTER_PASSWORD=MASTER)
    assert "locked" in ssc.ok("vault", "status").text  # no device key here
    generated = ssc.ok(
        "vault", "add", "web", "--password", "--generate", "--show", **master
    ).text.split()
    assert len(generated) == 6  # --show prints it, the one time it is shown
    ssc.ok("vault", "add", "laptop", "--key", **master)
    assert ssc("vault", "add", "code", "--recovery-code", **master).code == 1  # TTY
    listed = ssc.ok("vault", "list", **master).text.splitlines()
    assert [line.split("\t")[:3] for line in listed] == [
        ["web", "password", "active"],
        ["laptop", "key", "active"],
    ]
    ssc.ok("vault", "archive", "web", **master)
    ssc.ok("encrypt", "report.txt", "--vault", "laptop", **master)
    (ssc.work / "docs").mkdir()
    shutil.copy(ssc.work / "report.txt.ssc", ssc.work / "docs" / "a.ssc")
    revoked = ssc.ok("vault", "revoke", "laptop", "--scan", "docs", **master)
    assert revoked.text.split() == [str(Path("docs") / "a.ssc")]
    assert "anyone with a copy" in revoked.err
    assert ssc("decrypt", "report.txt.ssc", "-o", "x", **master).code == 2

    ssc.ok("vault", "backup", "backup.ssc", **master)
    assert (ssc.work / "backup.ssc").is_file()
    assert ssc("vault", "change-password", **master).code == 1  # no new one
    ssc.ok("vault", "change-password", SSC_NEW_MASTER_PASSWORD=NEW_MASTER, **master)
    assert ssc("vault", "list", **master).code == 2
    ssc.ok("vault", "list", SSC_MASTER_PASSWORD=NEW_MASTER)
    assert ssc("vault", "remove-device", "gx", SSC_MASTER_PASSWORD=NEW_MASTER).code == 1


def test_history_on_show_off(vault: Ssc) -> None:
    ssc, master = vault, Master(SSC_MASTER_PASSWORD=MASTER)
    assert "History is off" in ssc.ok("vault", "history", "show", **master).err
    ssc.ok("vault", "history", "on", **master)
    ssc.ok("vault", "add", "laptop", "--key", **master)
    ssc.ok("encrypt", "report.txt", "--vault", "laptop", **master)
    ssc.ok("decrypt", "report.txt.ssc", "-o", "-", **master)
    shown = ssc.ok("vault", "history", "show", **master).text
    actions = [line.split("\t")[1] for line in shown.splitlines()]
    assert {"vault-unlock", "entry-create", "encrypt", "decrypt"} <= set(actions)
    assert "report" not in shown  # no file names or paths, ever
    ssc.ok("vault", "history", "off", **master)
    assert "History is off" in ssc.ok("vault", "history", "show", **master).err


# --- section 3.4: keys, profiles, generate and shred -----------------------------


def test_keys_profiles_generate_and_shred(vault: Ssc) -> None:
    ssc, master = vault, Master(SSC_MASTER_PASSWORD=MASTER)
    ssc.ok("key", "new", "usb.ssckey", "--label", "usb")
    ssc.ok("key", "import", "usb.ssckey", **master)
    ssc.ok("key", "export", "usb", "copy.ssckey", **master)
    assert (ssc.work / "copy.ssckey").read_bytes() == (
        ssc.work / "usb.ssckey"
    ).read_bytes()
    ssc.ok("profile", "create", "daily", "--grant", "vault:usb+password", **master)
    assert ssc.ok("profile", "list", **master).text == "daily\n"
    assert ssc.ok("profile", "show", "daily", **master).text == (
        'g1: vault entry "usb" + a password typed at encrypt time\n'
    )
    ssc.ok("profile", "default", "daily", **master)
    assert "(default)" in ssc.ok("profile", "list", **master).text
    ssc.ok("profile", "default", "--none", **master)
    ssc.ok("profile", "delete", "daily", **master)
    assert ssc.ok("profile", "list", **master).text == ""

    assert len(ssc.ok("generate").text.split()) == 6
    assert len(ssc.ok("generate", "--words", "8").text.split()) == 8
    assert ssc("generate", "--words", "3").code == 1

    assert ssc("shred", "report.txt").code == 1  # asks; no TTY, so not shredded
    assert (ssc.work / "report.txt").exists()
    warned = ssc.ok("shred", "report.txt", "--force")
    assert not (ssc.work / "report.txt").exists()
    assert re.search(r"Shredded", warned.err)


def test_no_arguments_without_a_terminal_prints_help(ssc: Ssc) -> None:
    result = ssc()
    assert result.code == 1
    assert "usage" in result.err.lower()
