"""Setting passwords (CLI.md section 3.4) and generating passphrases.

A password typed for encryption must be at least 8 characters, and SSC
warns when zxcvbn rates it weak. Passwords are never checked when
decrypting.
"""

from __future__ import annotations

import secrets
from functools import cache
from importlib import resources

import zxcvbn

from secure_string_cipher.errors import InputError
from secure_string_cipher.service.context import Context

MIN_LENGTH = 8
WEAK_SCORE = 2  # zxcvbn scores 0 to 4; below 3 is weak
DEFAULT_WORDS = 6
MIN_WORDS = 4


def check(ctx: Context, password: str) -> str:
    """Refuse a password under 8 characters, and warn about a weak one."""
    if len(password) < MIN_LENGTH:
        raise InputError(f"A password must be at least {MIN_LENGTH} characters.")
    # zxcvbn's cost grows with length; its first 100 characters are plenty.
    if zxcvbn.zxcvbn(password[:100])["score"] <= WEAK_SCORE:
        ctx.prompter.notice(
            "That password is weak: it could be guessed. A generated "
            "passphrase (ssc generate) is stronger."
        )
    return password


def new_password(ctx: Context, prompt: str) -> str:
    """A new password for a file, checked."""
    return check(ctx, ctx.prompter.new_password(prompt))


@cache
def wordlist() -> tuple[str, ...]:
    """The EFF large wordlist: 7,776 words, so 12.9 bits each.

    From https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases
    by the Electronic Frontier Foundation, under CC BY 3.0 US.
    """
    text = (
        resources.files("secure_string_cipher.service")
        .joinpath("eff_large_wordlist.txt")
        .read_text(encoding="utf-8")
    )
    words = tuple(line.split("\t")[1] for line in text.splitlines() if line)
    assert len(words) == 7776 and len(set(words)) == 7776
    return words


def generate(words: int = DEFAULT_WORDS) -> str:
    """`ssc generate`: a passphrase of `words` random words, at least 4."""
    if words < MIN_WORDS:
        raise InputError(f"A passphrase needs at least {MIN_WORDS} words.")
    return " ".join(secrets.choice(wordlist()) for _ in range(words))
