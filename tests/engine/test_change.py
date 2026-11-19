"""Changing access (FORMAT.md section 7.3): add, remove and rotate."""

from __future__ import annotations

import io
import secrets

import pytest

from secure_string_cipher.engine import access, armor, container
from secure_string_cipher.errors import CannotOpen, FormatError, Reason
from tests import vectorkit

KEY_A = secrets.token_bytes(32)
KEY_B = secrets.token_bytes(32)
A = access.Credentials(keys=[KEY_A])
B = access.Credentials(keys=[KEY_B])
PLAIN = secrets.token_bytes(70_000)


def sealed(*, armored: bool = False) -> bytes:
    out = io.BytesIO()
    container.encrypt(
        io.BytesIO(PLAIN), out, [[access.new_key(KEY_A)]], armored=armored
    )
    return out.getvalue()


def plaintext(data: bytes, creds: access.Credentials) -> bytes:
    out = io.BytesIO()
    container.decrypt(io.BytesIO(data), out, creds)
    return out.getvalue()


def unlock(data: bytes, creds: access.Credentials) -> container.Opened:
    return container.unlock(io.BytesIO(data), creds)


def add(data: bytes, creds: access.Credentials, key: bytes) -> bytes:
    out = io.BytesIO()
    container.add_grant(io.BytesIO(data), out, creds, [access.new_key(key)])
    return out.getvalue()


def remove(data: bytes, creds: access.Credentials, index: int) -> bytes:
    out = io.BytesIO()
    container.remove_grant(io.BytesIO(data), out, creds, index)
    return out.getvalue()


def rotate(data: bytes, creds: access.Credentials, *keys: bytes) -> bytes:
    out = io.BytesIO()
    policy = [[access.new_key(k)] for k in keys]
    assert container.rotate(io.BytesIO(data), out, creds, policy) == len(PLAIN)
    return out.getvalue()


def payload_bytes(data: bytes) -> bytes:
    return vectorkit.split(data).payload


# --- add ------------------------------------------------------------------------


def test_add_opens_with_old_and_new() -> None:
    before = sealed()
    after = add(before, A, KEY_B)
    assert plaintext(after, A) == PLAIN
    assert plaintext(after, B) == PLAIN
    assert vectorkit.split(after).fixed_header == vectorkit.split(before).fixed_header
    assert payload_bytes(after) == payload_bytes(before)
    assert unlock(after, B).file_key == unlock(before, A).file_key


def test_only_someone_who_can_open_can_add() -> None:
    with pytest.raises(CannotOpen):
        add(sealed(), B, KEY_B)


def test_add_keeps_existing_grants_byte_for_byte() -> None:
    vector = vectorkit.valid("access-unknown-grant-skipped")
    before = vectorkit.read(vector["file"])
    after = add(
        before,
        access.Credentials(
            keys=[bytes.fromhex(vectorkit.manifest()["credentials"]["key_a"])]
        ),
        KEY_B,
    )
    old = vectorkit.split(before).access_body
    new = vectorkit.split(after).access_body
    assert new[0] == old[0] + 1
    assert new[1 : len(old)] == old[1:]
    assert plaintext(after, B) == b"access\n"


def test_add_stops_at_16_grants() -> None:
    data = sealed()
    for _ in range(15):
        data = add(data, A, secrets.token_bytes(32))
    with pytest.raises(ValueError):
        add(data, A, KEY_B)


def test_add_keeps_the_armoured_form() -> None:
    after = add(sealed(armored=True), A, KEY_B)
    assert after.startswith(armor.BEGIN)
    assert plaintext(after, B) == PLAIN


# --- remove ------------------------------------------------------------------------


def test_remove_drops_only_that_grant() -> None:
    both = add(sealed(), A, KEY_B)
    after = remove(both, B, 0)
    assert plaintext(after, B) == PLAIN
    with pytest.raises(CannotOpen):
        plaintext(after, A)
    assert payload_bytes(after) == payload_bytes(both)


def test_remove_is_not_revocation() -> None:
    """The file key is unchanged, so whoever knew it still does."""
    both = add(sealed(), A, KEY_B)
    after = remove(both, B, 0)
    assert unlock(after, B).file_key == unlock(both, A).file_key


def test_cannot_remove_the_last_grant_or_a_missing_one() -> None:
    with pytest.raises(ValueError):
        remove(sealed(), A, 0)
    with pytest.raises(IndexError):
        remove(add(sealed(), A, KEY_B), A, 2)
    with pytest.raises(IndexError):
        remove(add(sealed(), A, KEY_B), A, -1)


# --- rotate ------------------------------------------------------------------------


def test_rotate_changes_the_file_key_and_nonce() -> None:
    before = add(sealed(), A, KEY_B)
    after = rotate(before, A, KEY_B)
    assert plaintext(after, B) == PLAIN
    with pytest.raises(CannotOpen):
        plaintext(after, A)
    old, new = unlock(before, A), unlock(after, B)
    assert new.file_key != old.file_key
    assert new.header.fixed != old.header.fixed
    assert payload_bytes(after) != payload_bytes(before)


def test_old_file_key_cannot_open_the_rotated_file() -> None:
    """A grant built from the old file key fails the new access MAC."""
    before = sealed()
    old_key = unlock(before, A).file_key
    after = rotate(before, A, KEY_A)
    opened = unlock(after, A)
    forged = access.new_grant(old_key, [access.new_key(KEY_B)])
    with pytest.raises(CannotOpen):
        access.open_file_key(
            [forged],
            opened.header.fixed.to_bytes(),
            opened.header.access_body,
            opened.header.access_mac,
            B,
        )


def test_rotate_keeps_the_armoured_form() -> None:
    after = rotate(sealed(armored=True), A, KEY_A)
    assert after.startswith(armor.BEGIN)
    assert plaintext(after, A) == PLAIN


def test_rotate_fails_on_a_damaged_payload() -> None:
    data = bytearray(sealed())
    data[-1] ^= 1
    with pytest.raises(FormatError) as caught:
        rotate(bytes(data), A, KEY_A)
    assert caught.value.reason == Reason.CHUNK_AUTH
