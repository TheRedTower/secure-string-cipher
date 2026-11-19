"""Running `ssc` in-process: a scripted terminal, an in-memory keychain, and
the vault and settings kept under the test's own folder."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from secure_string_cipher.cli import main
from tests.service.fakes import Keychain


@dataclass
class Terminal:
    """Answers from lists; `tty` False is a script or a pipe."""

    tty: bool = False
    hidden_answers: list[str] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)
    said: list[str] = field(default_factory=list)
    asked: list[str] = field(default_factory=list)

    def interactive(self) -> bool:
        return self.tty

    def hidden(self, prompt: str) -> str:
        self.asked.append(prompt)
        if not self.hidden_answers:
            raise AssertionError(f"Unexpected question: {prompt}")
        return self.hidden_answers.pop(0)

    def line(self, prompt: str) -> str:
        self.asked.append(prompt)
        if not self.lines:
            raise AssertionError(f"Unexpected question: {prompt}")
        return self.lines.pop(0)

    def say(self, text: str) -> None:
        self.said.append(text)


@dataclass
class Result:
    code: int
    out: str
    err: str
    said: str


Run = Callable[..., Result]


@pytest.fixture
def chain(monkeypatch: pytest.MonkeyPatch) -> Keychain:
    from secure_string_cipher.vault import keychain

    memory = Keychain()
    monkeypatch.setattr(keychain, "os_keychain", lambda: memory)
    return memory


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, chain: Keychain) -> None:
    from secure_string_cipher.service import settings
    from secure_string_cipher.vault import store

    monkeypatch.setattr(store, "default_path", lambda: tmp_path / "data" / "vault.ssc")
    monkeypatch.setattr(
        settings, "default_path", lambda: tmp_path / "config" / "settings.json"
    )
    for name in list(os.environ):
        if name.startswith("SSC_"):
            monkeypatch.delenv(name)
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def terminal() -> Terminal:
    return Terminal()


@pytest.fixture
def ssc(capsys: pytest.CaptureFixture[str], terminal: Terminal) -> Run:
    def run(*argv: str) -> Result:
        terminal.said.clear()
        code = main(list(argv), terminal)
        captured = capsys.readouterr()
        return Result(code, captured.out, captured.err, "\n".join(terminal.said))

    return run


def secret_file(path: Path, text: str) -> Path:
    path.write_text(text + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path
