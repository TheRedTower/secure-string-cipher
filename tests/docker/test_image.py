"""The Docker image end to end (GAME_PLAN.md section 9): each test runs
`ssc` in a fresh, locked-down container, as `docker run --rm` would.

Skipped unless SSC_DOCKER_IMAGE names an image built from the Dockerfile;
CI's Docker job sets it."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

IMAGE = os.environ.get("SSC_DOCKER_IMAGE", "")
pytestmark = pytest.mark.skipif(
    not IMAGE or shutil.which("docker") is None,
    reason="set SSC_DOCKER_IMAGE to an image built from the Dockerfile",
)

PASSWORD = "a strong test passphrase"
MASTER = "master password for tests"
PLAIN = b"the secret report\n" * 1000


@dataclass
class Result:
    code: int
    out: bytes
    err: str


@dataclass
class Container:
    """`/work` and `/ssc` are folders of the test's own, mounted in. The
    container runs as the test's user, as the README says to, so the files
    it writes belong to them."""

    work: Path
    state: Path

    def args(self, env: dict[str, str]) -> list[str]:
        user: list[str] = []
        if sys.platform != "win32":
            user = ["--user", f"{os.getuid()}:{os.getgid()}"]
        flags = [f"--env={k}" for k in env]
        return [
            "docker", "run", "--rm", "-i",
            "--network=none", "--read-only", "--tmpfs=/tmp",
            "--cap-drop=ALL", "--security-opt=no-new-privileges",
            *user, *flags,
            f"--volume={self.work}:/work", f"--volume={self.state}:/ssc",
        ]  # fmt: skip

    def run(self, *argv: str, stdin: bytes = b"", **env: str) -> Result:
        done = subprocess.run(
            [*self.args(env), IMAGE, *argv],
            input=stdin,
            capture_output=True,
            env={**os.environ, **env},
            timeout=120,
            check=False,
        )
        return Result(done.returncode, done.stdout, done.stderr.decode())

    def ok(self, *argv: str, stdin: bytes = b"", **env: str) -> Result:
        result = self.run(*argv, stdin=stdin, **env)
        assert result.code == 0, result.err
        return result


@pytest.fixture
def box(tmp_path: Path) -> Container:
    work, state = tmp_path / "work", tmp_path / "ssc"
    work.mkdir()
    state.mkdir(mode=0o700)
    (work / "report.txt").write_bytes(PLAIN)
    return Container(work, state)


def test_it_runs_unprivileged_with_no_compiler() -> None:
    probe = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint=sh", IMAGE, "-c",
         "id -u; command -v gcc cc make || echo none"],
        capture_output=True, text=True, timeout=60, check=True,
    )  # fmt: skip
    assert probe.stdout.split() == ["1000", "none"]


def test_the_wordlist_ships_in_the_image(box: Container) -> None:
    assert len(box.ok("generate").out.split()) == 6


def test_a_standalone_key_file(box: Container) -> None:
    """CLI.md section 1: how a container decrypts with no vault at all."""
    box.ok("key", "new", "usb.ssckey")
    box.ok("encrypt", "report.txt", "--grant", "keyfile:usb.ssckey")
    (box.work / "report.txt").unlink()
    box.ok("decrypt", "report.txt.ssc", "--key-file", "usb.ssckey")
    assert (box.work / "report.txt").read_bytes() == PLAIN


def test_the_vault_lives_in_ssc_and_asks_for_the_master_password(
    box: Container,
) -> None:
    """No keychain in a container: the master password, never a plain file
    (VAULT.md section 2). The vault outlives each container."""
    init = box.ok("vault", "init", SSC_NEW_MASTER_PASSWORD=MASTER)
    assert "No OS keychain is available" in init.err
    assert (box.state / "data" / "ssc" / "vault.ssc").is_file()
    box.ok(
        "vault", "add", "work", "--password",
        SSC_MASTER_PASSWORD=MASTER, SSC_NEW_PASSWORD=PASSWORD,
    )  # fmt: skip
    box.ok("encrypt", "report.txt", "--vault", "work", SSC_MASTER_PASSWORD=MASTER)
    locked = box.run("decrypt", "report.txt.ssc", "-o", "out.txt")
    assert locked.code == 1  # needed, not supplied, no TTY: never a hang
    box.ok("decrypt", "report.txt.ssc", "-o", "out.txt", SSC_MASTER_PASSWORD=MASTER)
    assert (box.work / "out.txt").read_bytes() == PLAIN


def test_stdin_to_stdout(box: Container) -> None:
    sealed = box.ok(
        "encrypt", "-", "-o", "-", "--armor", stdin=b"a note", SSC_NEW_PASSWORD=PASSWORD
    ).out
    assert sealed.startswith(b"-----BEGIN")
    opened = box.ok("decrypt", "-", "-o", "-", stdin=sealed, SSC_PASSWORD=PASSWORD)
    assert opened.out == b"a note"
    wrong = box.run("decrypt", "-", "-o", "-", stdin=sealed, SSC_PASSWORD="not it!!")
    assert (wrong.code, wrong.out) == (2, b"")


def test_the_guided_flow_runs_in_a_terminal(box: Container) -> None:
    """CLI.md section 4: it works inside Docker. Ctrl-C at the start quits."""
    if sys.platform == "win32":
        pytest.skip("needs a pseudo-terminal")
    import pty
    import select

    pid, fd = pty.fork()
    if pid == 0:  # the child: docker, attached to the terminal
        argv = [*box.args({}), "-t", IMAGE]
        os.execvp(argv[0], argv)
    seen = b""
    try:
        while b"What do you want to do?" not in seen:
            ready, _, _ = select.select([fd], [], [], 60)
            assert ready, f"no start screen: {seen!r}"
            seen += os.read(fd, 4096)
        os.write(fd, b"\x03")
        _, status = os.waitpid(pid, 0)
    finally:
        os.close(fd)
    assert b"no vault yet" in seen
    assert os.waitstatus_to_exitcode(status) == 0
