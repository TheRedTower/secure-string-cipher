"""The interactive mode's Prompter: it always asks, through the Ui."""

from __future__ import annotations

from collections.abc import Sequence

from secure_string_cipher.errors import InputError
from secure_string_cipher.interactive.ui import Ui
from secure_string_cipher.service import passwords

TRIES = 3


class UiPrompter:
    def __init__(self, ui: Ui) -> None:
        self.ui = ui
        self._kept_weak = False  # warned once already; say it only once

    def secret(self, prompt: str) -> str:
        return self.ui.password(prompt)

    def new_password(self, prompt: str) -> str:
        """Typed twice. A weak one gets the warning and the offer of a
        generated passphrase instead (CLI.md section 4.2)."""
        for _ in range(TRIES):
            first = self.ui.password(prompt)
            if len(first) < passwords.MIN_LENGTH:
                self.ui.say(
                    f"A password must be at least {passwords.MIN_LENGTH} characters."
                )
                continue
            if passwords.is_weak(first):
                self.ui.say(passwords.WEAK)
                if self.ui.confirm("Generate a passphrase instead?", default=True):
                    return self._generated()
                self._kept_weak = True
            if self.ui.password("Type it again") == first:
                return first
            self._kept_weak = False
            self.ui.say("Those did not match.")
        raise InputError("No password was set.")

    def _generated(self) -> str:
        while True:
            phrase = passwords.generate()
            self.ui.say(f"\nYour passphrase:\n\n    {phrase}\n")
            if self.ui.confirm("Use it? Write it down first.", default=True):
                return phrase

    def new_master_password(self) -> str:
        for _ in range(TRIES):
            first = self.ui.password("New master password")
            if not first:
                self.ui.say("It cannot be empty.")
                continue
            if self.ui.password("Type it again") == first:
                return first
            self.ui.say("Those did not match.")
        raise InputError("No master password was set.")

    def choose(self, question: str, options: Sequence[str]) -> int:
        return self.ui.select(question, options)

    def confirm(self, question: str, *, default: bool) -> bool:
        return self.ui.confirm(question, default=default)

    def can_show(self) -> bool:
        return True

    def show_once(self, title: str, secret: str) -> None:
        """Shown once, then its last group typed back (CLI.md section 4.4)."""
        self.ui.say(f"\n{title}:\n\n    {secret}\n")
        self.ui.say("Write it down now. SSC will not show it again.")
        last = secret.rsplit("-", 1)[-1].upper()
        while self.ui.text("Type its last group to confirm").strip().upper() != last:
            self.ui.say("That is not its last group. Check what you wrote.")

    def notice(self, message: str) -> None:
        if message == passwords.WEAK and self._kept_weak:
            self._kept_weak = False  # already warned, and kept anyway
            return
        self.ui.say(message)
