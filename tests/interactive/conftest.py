"""A scripted Ui for the guided flow, and a vault under the test's folder."""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from secure_string_cipher.interactive.prompter import UiPrompter
from secure_string_cipher.interactive.ui import Back
from secure_string_cipher.service.context import Context
from tests.service.fakes import Keychain

BACK = object()  # an answer that presses Ctrl-C


@dataclass
class ScriptedUi:
    """Answers in order; any question it was not told to expect fails.

    A select answer is the start of the option's text, or its index; a
    checkbox answer is a list of those. A callable is called when the
    question comes, such as to type back a recovery code just shown."""

    answers: list[Any] = field(default_factory=list)
    said: list[str] = field(default_factory=list)
    asked: list[str] = field(default_factory=list)

    def _next(self, question: str) -> Any:
        self.asked.append(question)
        if not self.answers:
            raise AssertionError(f"Unexpected question: {question}")
        answer = self.answers.pop(0)
        if answer is BACK:
            raise Back()
        if callable(answer):  # worked out when asked, from what was said
            return answer()
        return answer

    @staticmethod
    def _index(answer: Any, options: Sequence[str], question: str) -> int:
        if isinstance(answer, int):
            return answer
        if answer in options:
            return options.index(answer)
        matches = [i for i, o in enumerate(options) if o.startswith(answer)]
        if len(matches) != 1:
            raise AssertionError(
                f"{answer!r} is not one option of {question}: {options}"
            )
        return matches[0]

    def select(self, question: str, options: Sequence[str], default: int = 0) -> int:
        return self._index(self._next(question), options, question)

    def checkbox(self, question: str, options: Sequence[str]) -> list[int]:
        return [self._index(a, options, question) for a in self._next(question)]

    def path(self, question: str, default: str = "") -> str:
        answer = self._next(question)
        return default if answer == "" else str(answer)

    def text(self, question: str, default: str = "") -> str:
        answer = self._next(question)
        return default if answer == "" else str(answer)

    def password(self, question: str) -> str:
        return str(self._next(question))

    def confirm(self, question: str, *, default: bool) -> bool:
        answer = self._next(question)
        return default if answer == "" else bool(answer)

    def say(self, text: str) -> None:
        self.said.append(text)

    def done(self) -> None:
        assert not self.answers, f"Answers left over: {self.answers}"


@pytest.fixture
def ui() -> ScriptedUi:
    return ScriptedUi()


@pytest.fixture
def chain() -> Keychain:
    return Keychain()


@pytest.fixture
def ctx(tmp_path: Path, ui: ScriptedUi, chain: Keychain) -> Context:
    from secure_string_cipher.interactive import flow

    return Context(
        UiPrompter(ui),
        vault_path=tmp_path / "data" / "vault.ssc",
        keychain=chain,
        ask_key_file=lambda: flow.ask_path(ui, "Which key file?"),  # as main does
    )


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from secure_string_cipher.service import settings
    from secure_string_cipher.vault import store

    monkeypatch.setattr(
        settings, "default_path", lambda: tmp_path / "config" / "settings.json"
    )
    monkeypatch.setattr(store, "default_path", lambda: tmp_path / "data" / "vault.ssc")
    for name in list(os.environ):
        if name.startswith("SSC_"):
            monkeypatch.delenv(name)
    monkeypatch.chdir(tmp_path)


def last_group(ui: ScriptedUi) -> Any:
    """An answer that types back the last group of the code just shown."""
    import re

    def answer() -> str:
        codes = re.findall(r"[0-9A-Z]{4}(?:-[0-9A-Z]{4}){7}", "\n".join(ui.said))
        assert codes, "no recovery code was shown"
        return str(codes[-1].rsplit("-", 1)[-1])

    return answer
