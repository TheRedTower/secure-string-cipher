"""Grant specs (CLI.md section 2) and password rules (section 3.4)."""

from __future__ import annotations

import pytest

from secure_string_cipher.errors import InputError
from secure_string_cipher.service import grants, passwords
from secure_string_cipher.service.context import Context
from secure_string_cipher.service.grants import Token
from tests.service.fakes import Prompter


def test_parses_each_token() -> None:
    assert grants.parse_grant("password+vault:laptop+keyfile:/k.ssckey+recovery") == (
        Token("password"),
        Token("vault", "laptop"),
        Token("keyfile", "/k.ssckey"),
        Token("recovery"),
    )


@pytest.mark.parametrize(
    "spec",
    [
        "",
        "pass",
        "vault:",
        "vault:Bad Label",
        "keyfile:",
        "password+password",
        "vault:a+vault:a",
        "+".join(f"vault:e{i}" for i in range(6)),
    ],
)
def test_rejects_a_bad_spec(spec: str) -> None:
    with pytest.raises(InputError):
        grants.parse_grant(spec)


def test_limits_the_number_of_grants() -> None:
    assert len(grants.parse_grants(["password"] * 16)) == 16
    with pytest.raises(InputError):
        grants.parse_grants(["password"] * 17)
    with pytest.raises(InputError):
        grants.parse_grants([])


def test_a_short_password_is_refused_and_a_weak_one_warned(ctx: Context) -> None:
    with pytest.raises(InputError):
        passwords.check(ctx, "short")
    passwords.check(ctx, "password1")
    assert isinstance(ctx.prompter, Prompter)
    assert len(ctx.prompter.notices) == 1
    passwords.check(ctx, passwords.generate())
    assert len(ctx.prompter.notices) == 1


def test_generated_passphrases() -> None:
    words = passwords.generate().split(" ")
    assert len(words) == 6 and all(w in passwords.wordlist() for w in words)
    assert len(passwords.generate(4).split(" ")) == 4
    with pytest.raises(InputError):
        passwords.generate(3)
    assert len(set(passwords.wordlist())) == 7776
