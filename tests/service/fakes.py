"""A scripted Prompter and an in-memory keychain for service tests."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from secure_string_cipher.errors import InputError


@dataclass
class Prompter:
    """Answers from lists, in order; an unexpected question is an error, so
    a test also proves SSC asks only for what it needs."""

    secrets: list[str] = field(default_factory=list)
    new_passwords: list[str] = field(default_factory=list)
    new_masters: list[str] = field(default_factory=list)
    choices: list[int] = field(default_factory=list)
    confirms: list[bool] = field(default_factory=list)
    shown: list[tuple[str, str]] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)
    asked: list[str] = field(default_factory=list)

    def _next[T](self, answers: list[T], question: str) -> T:
        self.asked.append(question)
        if not answers:
            raise InputError(f"Unexpected question: {question}")
        return answers.pop(0)

    def secret(self, prompt: str) -> str:
        return self._next(self.secrets, prompt)

    def new_password(self, prompt: str) -> str:
        return self._next(self.new_passwords, prompt)

    def new_master_password(self) -> str:
        return self._next(self.new_masters, "new master password")

    def choose(self, question: str, options: Sequence[str]) -> int:
        self.asked.append(f"{question} {list(options)}")
        if not self.choices:
            raise InputError(f"Unexpected choice: {question} {list(options)}")
        return self.choices.pop(0)

    def confirm(self, question: str, *, default: bool) -> bool:
        return self._next(self.confirms, question)

    def show_once(self, title: str, secret: str) -> None:
        self.shown.append((title, secret))

    def notice(self, message: str) -> None:
        self.notices.append(message)


class Keychain:
    def __init__(self) -> None:
        self.items: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.items.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.items[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.items.pop((service, username), None)
