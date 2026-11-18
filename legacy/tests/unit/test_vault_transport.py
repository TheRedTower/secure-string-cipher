"""CLI-only raw vault transport compatibility tests."""

from __future__ import annotations

import pytest

from secure_string_cipher.vault_transport import canonicalize_cli_vault_candidate

CANONICAL = b"line-1\nline-2\nline-3\nline-4\nline-5\nline-6"


@pytest.mark.parametrize("ending", [b"", b"\n", b"\r\n"])
def test_one_legacy_terminal_ending_is_canonicalized(ending: bytes) -> None:
    assert canonicalize_cli_vault_candidate(CANONICAL + ending) == CANONICAL


@pytest.mark.parametrize(
    "candidate",
    [
        CANONICAL + b"\n\n",
        CANONICAL + b"\r\n\r\n",
        CANONICAL + b"\r",
        CANONICAL + b" ",
        CANONICAL + b"\t",
        b"\n" + CANONICAL,
        CANONICAL.replace(b"\n", b"\r\n"),
    ],
)
def test_other_transport_bytes_are_not_normalized(candidate: bytes) -> None:
    normalized = canonicalize_cli_vault_candidate(candidate)

    assert normalized != CANONICAL
