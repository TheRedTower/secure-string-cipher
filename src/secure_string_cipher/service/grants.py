"""Grant specs (CLI.md section 2): one grant as factors joined by `+`.

    password            a new password, typed or from --new-password-file
    vault:<label>       a vault entry (password, key or recovery)
    keyfile:<path>      the key in a .ssckey file
    recovery            the vault's recovery entry, chosen by CLI.md's rule

Each `--grant` is one grant, so several mean "any of".
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from secure_string_cipher.engine import access
from secure_string_cipher.engine.keyfile import LABEL
from secure_string_cipher.errors import InputError

Kind = Literal["password", "vault", "keyfile", "recovery"]


@dataclass(frozen=True)
class Token:
    kind: Kind
    value: str = ""

    def __str__(self) -> str:
        return f"{self.kind}:{self.value}" if self.value else self.kind


def parse_grant(spec: str) -> tuple[Token, ...]:
    """One `--grant` value. A spec may name a factor only once, and may have
    at most 5 factors."""
    tokens: list[Token] = []
    for part in spec.split("+"):
        part = part.strip()
        if part == "password":
            tokens.append(Token("password"))
        elif part == "recovery":
            tokens.append(Token("recovery"))
        elif part.startswith("vault:"):
            label = part.removeprefix("vault:")
            if not LABEL.fullmatch(label):
                raise InputError(f'"{label}" is not a vault entry label.')
            tokens.append(Token("vault", label))
        elif part.startswith("keyfile:"):
            path = part.removeprefix("keyfile:")
            if not path:
                raise InputError("keyfile: needs a path.")
            tokens.append(Token("keyfile", path))
        else:
            raise InputError(
                f'"{part}" is not a factor. Use password, vault:<label>, '
                "keyfile:<path> or recovery."
            )
    return check_grant(tokens)


def check_grant(tokens: Sequence[Token]) -> tuple[Token, ...]:
    """A grant names a factor only once, and has at most 5 factors."""
    if len(set(tokens)) != len(tokens):
        raise InputError(
            f'The grant "{"+".join(map(str, tokens))}" names a factor twice.'
        )
    if len(tokens) > access.MAX_FACTORS:
        raise InputError(f"A grant has at most {access.MAX_FACTORS} factors.")
    return tuple(tokens)


def parse_grants(specs: Sequence[str]) -> list[tuple[Token, ...]]:
    """Every `--grant` given. A file may have at most 16 grants."""
    if not specs:
        raise InputError("Give at least one --grant.")
    if len(specs) > access.MAX_GRANTS:
        raise InputError(f"A file has at most {access.MAX_GRANTS} grants.")
    return [parse_grant(spec) for spec in specs]


def check_grants(grants: Sequence[Sequence[Token]]) -> list[tuple[Token, ...]]:
    """Grants built as tokens, not parsed from specs, checked the same way."""
    if len(grants) > access.MAX_GRANTS:
        raise InputError(f"A file has at most {access.MAX_GRANTS} grants.")
    return [check_grant(g) for g in grants]
