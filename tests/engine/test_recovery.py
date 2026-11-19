"""The printed form of a recovery code (ACCESS.md section 2.3)."""

from __future__ import annotations

from typing import Any

import pytest

from secure_string_cipher.engine import recovery
from secure_string_cipher.errors import Reason, RecoveryCodeError
from tests import vectorkit

R = bytes.fromhex(vectorkit.manifest()["credentials"]["recovery_r"])
TEXT: str = vectorkit.manifest()["credentials"]["recovery_text"]


@pytest.mark.parametrize("vector", vectorkit.manifest()["recovery_codes"])
def test_recovery_code_vector(vector: dict[str, Any]) -> None:
    if vector["valid"]:
        assert recovery.decode(vector["text"]) == bytes.fromhex(vector["r"])
        assert recovery.encode(bytes.fromhex(vector["r"])) == TEXT
    else:
        with pytest.raises(RecoveryCodeError) as caught:
            recovery.decode(vector["text"])
        assert caught.value.reason == vector["reason"]


def test_the_printed_form() -> None:
    assert recovery.encode(R) == TEXT
    groups = TEXT.split("-")
    assert len(groups) == 8 and all(len(g) == 4 for g in groups)


def test_round_trips() -> None:
    for _ in range(200):
        r = recovery.new()
        assert len(r) == 18
        assert recovery.decode(recovery.encode(r)) == r


def test_lookalikes_are_read_as_digits() -> None:
    plain = TEXT.replace("-", "")
    assert "0" in plain and "1" not in plain  # the vector has a 0 to swap
    assert recovery.decode(plain.replace("0", "O")) == R
    assert recovery.decode(plain.replace("0", "o")) == R


def test_i_and_l_are_read_as_one() -> None:
    r = next(r for r in iter(recovery.new, None) if "1" in recovery.encode(r))
    text = recovery.encode(r)
    assert recovery.decode(text.replace("1", "I")) == r
    assert recovery.decode(text.replace("1", "l")) == r


@pytest.mark.parametrize(
    "text",
    ["", TEXT[:-1], TEXT + "0", TEXT.replace("7", "U", 1), TEXT.replace("-", "_")],
)
def test_rejects_what_is_not_a_code(text: str) -> None:
    with pytest.raises(RecoveryCodeError) as caught:
        recovery.decode(text)
    assert caught.value.reason == Reason.RECOVERY_CODE


def test_a_swapped_pair_is_a_typo() -> None:
    swapped = TEXT[:1] + TEXT[2] + TEXT[1] + TEXT[3:]
    with pytest.raises(RecoveryCodeError) as caught:
        recovery.decode(swapped)
    assert caught.value.reason == Reason.RECOVERY_CHECK


def test_encode_needs_18_bytes() -> None:
    with pytest.raises(ValueError):
        recovery.encode(bytes(17))
