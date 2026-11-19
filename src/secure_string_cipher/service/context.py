"""What every service operation is given: where things live, what the
caller already supplied, and how to ask for the rest.

The CLI and the interactive mode differ only in their Prompter: the CLI
answers from flags, files and environment variables and fails with an
InputError when it would have to ask without a TTY (CLI.md section 1); the
interactive mode asks.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from secure_string_cipher.vault import keychain as kc
from secure_string_cipher.vault import store


class Prompter(Protocol):
    def secret(self, prompt: str) -> str:
        """A password, master password or recovery code that opens
        something. Never echoed."""
        ...

    def new_password(self, prompt: str) -> str:
        """A password being set: typed twice, or from its own source."""
        ...

    def new_master_password(self) -> str:
        """A new master password, from its own source (CLI.md section 1)."""
        ...

    def choose(self, question: str, options: Sequence[str]) -> int:
        """The index of the option picked."""
        ...

    def confirm(self, question: str, *, default: bool) -> bool: ...

    def show_once(self, title: str, secret: str) -> None:
        """Show a new recovery code or generated password, once, on screen.
        The interactive mode asks for the last group to be typed back."""
        ...

    def notice(self, message: str) -> None:
        """A warning or a note for the person, never containing a secret."""
        ...


@dataclass
class Context:
    prompter: Prompter
    vault_path: Path = field(default_factory=store.default_path)
    # Opening credentials supplied up front, so they are tried before
    # anything is asked (CLI.md section 1).
    passwords: Sequence[str] = ()
    recovery_codes: Sequence[str] = ()
    key_files: Sequence[Path] = ()
    master_password: str | None = None
    use_keychain: bool = True
    keychain: kc.Keychain | None = None  # None: the OS keychain

    def chain(self) -> kc.Keychain | None:
        """The keychain to use, or None when there is none or it is off."""
        if not self.use_keychain:
            return None
        return self.keychain if self.keychain is not None else kc.os_keychain()
