"""What the guided flow needs from a terminal, and questionary's version of
it (CLI.md section 4): arrow-key selects, path completion, and hidden
input, in any plain terminal, over SSH and inside Docker."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol

import questionary


class Back(Exception):
    """The person pressed Ctrl-C at a question: go back one screen."""


class Ui(Protocol):
    def select(self, question: str, options: Sequence[str], default: int = 0) -> int:
        """The index picked."""
        ...

    def checkbox(self, question: str, options: Sequence[str]) -> list[int]: ...
    def path(self, question: str, default: str = "") -> str: ...
    def text(self, question: str, default: str = "") -> str: ...
    def password(self, question: str) -> str: ...
    def confirm(self, question: str, *, default: bool) -> bool: ...
    def say(self, text: str) -> None: ...


class QuestionaryUi:
    """`options` are passed to every prompt; tests give prompt_toolkit a pipe
    for `input` and a dummy `output`."""

    def __init__(self, **options: Any) -> None:
        self.options = options

    def _ask(self, question: questionary.Question) -> Any:
        answer = question.ask()
        if answer is None:
            raise Back()
        return answer

    def select(self, question: str, options: Sequence[str], default: int = 0) -> int:
        choices = [questionary.Choice(title=o, value=i) for i, o in enumerate(options)]
        picked: int = self._ask(
            questionary.select(
                question, choices=choices, default=choices[default], **self.options
            )
        )
        return picked

    def checkbox(self, question: str, options: Sequence[str]) -> list[int]:
        choices = [questionary.Choice(title=o, value=i) for i, o in enumerate(options)]
        picked: list[int] = self._ask(
            questionary.checkbox(question, choices=choices, **self.options)
        )
        return picked

    def path(self, question: str, default: str = "") -> str:
        answer: str = self._ask(
            questionary.path(question, default=default, **self.options)
        )
        return answer

    def text(self, question: str, default: str = "") -> str:
        answer: str = self._ask(
            questionary.text(question, default=default, **self.options)
        )
        return answer

    def password(self, question: str) -> str:
        answer: str = self._ask(questionary.password(question, **self.options))
        return answer

    def confirm(self, question: str, *, default: bool) -> bool:
        answer: bool = self._ask(
            questionary.confirm(question, default=default, **self.options)
        )
        return answer

    def say(self, text: str) -> None:
        if "output" in self.options:
            questionary.print(text, output=self.options["output"])
        else:
            questionary.print(text)
