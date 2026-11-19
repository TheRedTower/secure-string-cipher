"""The CLI's Prompter: it answers from flags and environment variables
first, asks on the terminal only when there is one, and otherwise fails
with an exit 1 error, never a hang (CLI.md section 1).

Everything it says goes to stderr, so stdout carries only a command's
output, such as decrypted data or `ssc generate`'s passphrase.
"""

from __future__ import annotations

import getpass
import sys
from collections.abc import Sequence
from typing import Protocol, TextIO

from secure_string_cipher.cli.sources import Sources
from secure_string_cipher.errors import InputError

TRIES = 3

# Where to supply, without a prompt, what the service layer asks for.
WHERE = {
    "Password for this file": "--password-file or SSC_PASSWORD",
    "Vault master password": "--master-password-file or SSC_MASTER_PASSWORD",
    "Recovery code": "--recovery-code-file or SSC_RECOVERY_CODE",
}


class Terminal(Protocol):
    def interactive(self) -> bool: ...
    def hidden(self, prompt: str) -> str: ...
    def line(self, prompt: str) -> str: ...
    def say(self, text: str) -> None: ...


class StdTerminal:
    """stdin and stderr, when both are a TTY. stdin carrying data (`-`) is
    not a TTY, so nothing is ever asked on it."""

    def __init__(self, stdin: TextIO | None = None, stderr: TextIO | None = None):
        self.stdin = stdin or sys.stdin
        self.stderr = stderr or sys.stderr

    def interactive(self) -> bool:
        return self.stdin.isatty() and self.stderr.isatty()

    def hidden(self, prompt: str) -> str:
        return getpass.getpass(prompt, stream=self.stderr)

    def line(self, prompt: str) -> str:
        self.stderr.write(prompt)
        self.stderr.flush()
        return self.stdin.readline().rstrip("\r\n")

    def say(self, text: str) -> None:
        print(text, file=self.stderr, flush=True)


class CliPrompter:
    def __init__(self, sources: Sources, terminal: Terminal | None = None) -> None:
        self.sources = sources
        self.terminal = terminal or StdTerminal()

    def _need_terminal(self, what: str, where: str) -> None:
        if not self.terminal.interactive():
            raise InputError(
                f"{what} is needed, and there is no terminal to ask on: "
                f"supply it with {where}."
            )

    def secret(self, prompt: str) -> str:
        self._need_terminal(prompt, WHERE.get(prompt, "a flag or variable"))
        return self.terminal.hidden(f"{prompt}: ")

    def _twice(self, prompt: str) -> str:
        for _ in range(TRIES):
            first = self.terminal.hidden(f"{prompt}: ")
            if not first:
                self.terminal.say("It cannot be empty.")
                continue
            if self.terminal.hidden("Type it again: ") == first:
                return first
            self.terminal.say("Those did not match.")
        raise InputError("The two entries did not match.")

    def new_password(self, prompt: str) -> str:
        if self.sources.new_password is not None:
            return self.sources.new_password
        self._need_terminal("A new password", "--new-password-file or SSC_NEW_PASSWORD")
        return self._twice(prompt)

    def new_master_password(self) -> str:
        if self.sources.new_master_password is not None:
            return self.sources.new_master_password
        self._need_terminal(
            "A new master password",
            "--new-master-password-file or SSC_NEW_MASTER_PASSWORD",
        )
        return self._twice("New master password")

    def choose(self, question: str, options: Sequence[str]) -> int:
        if not self.terminal.interactive():
            raise InputError(
                f"{question} One of {', '.join(options)} is needed, and there is "
                "no terminal to ask on: supply it with a flag or variable."
            )
        self.terminal.say(question)
        for i, option in enumerate(options, 1):
            self.terminal.say(f"  {i}. {option}")
        for _ in range(TRIES):
            answer = self.terminal.line(f"Choose 1-{len(options)} [1]: ").strip()
            if not answer:
                return 0
            if answer.isdigit() and 1 <= int(answer) <= len(options):
                return int(answer) - 1
        raise InputError("No choice was made.")

    def confirm(self, question: str, *, default: bool) -> bool:
        """Without a terminal, the default, which is always the safe one."""
        if not self.terminal.interactive():
            return default
        hint = "(Y/n)" if default else "(y/N)"
        for _ in range(TRIES):
            answer = self.terminal.line(f"{question} {hint} ").strip().lower()
            if not answer:
                return default
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no"):
                return False
        return default

    def can_show(self) -> bool:
        return self.terminal.interactive()

    def show_once(self, title: str, secret: str) -> None:
        """A new recovery code, shown once on the terminal, then its last
        group typed back to confirm it was written down (CLI.md section 2)."""
        self._need_terminal("A terminal to show the new recovery code", "a TTY")
        self.terminal.say(f"\n{title}:\n\n    {secret}\n")
        self.terminal.say("Write it down now. SSC will not show it again.")
        last = secret.rsplit("-", 1)[-1].upper()
        while (
            self.terminal.line("Type its last group to confirm: ").strip().upper()
            != last
        ):
            self.terminal.say("That is not its last group. Check what you wrote.")

    def notice(self, message: str) -> None:
        self.terminal.say(message)
