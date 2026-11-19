"""Whole files against the frozen vectors (Phase 2, step 2): the access
layer, the container and the armoured form.

Vectors that need a managed key or a recovery code are listed in
`PENDING` with the step that brings their factor in;
tests/engine/test_vector_coverage.py checks that nothing is left out.
"""

from __future__ import annotations

import io
from typing import Any

import pytest

from secure_string_cipher.engine import access, armor, container
from secure_string_cipher.engine.header import FixedHeader
from secure_string_cipher.errors import CannotOpen, FormatError
from tests import vectorkit

CREDS = vectorkit.manifest()["credentials"]
PASSWORD: str = CREDS["password"]
ENTRY_ID = bytes.fromhex(CREDS["vault_entry_id"])

# Valid vectors this step opens with the credentials the manifest gives.
OPENS = ["access-password", "access-vault-password-entry", "access-password-nfc"]

# Rejected while parsing, before any secret is derived.
PARSE_REJECTS = [
    "magic",
    "version",
    "access-length-zero",
    "access-length-too-big",
    "grant-count-zero",
    "grant-count-seventeen",
    "grant-length",
    "access-body-trailing",
    "factor-count-six",
    "factor-order",
    "factor-duplicate",
    "argon-params",
]

ARMOR_REJECTS = [
    "armor-mixed-line-endings",
    "armor-long-line",
    "armor-after-end",
    "armor-noncanonical-base64",
]

# Everything else, by the step that can test it.
PENDING = {
    "Phase 2, step 3 (key factor)": [
        "format-0-bytes",
        "format-1-bytes",
        "format-65536-bytes",
        "format-65537-bytes",
        "format-armored",
        "access-key",
        "access-password-and-key",
        "access-unknown-grant-skipped",
        "access-mac",
        "payload-nonce-flipped",
        "truncated-at-chunk-boundary",
        "appended-byte",
        "empty-trailing-chunk",
        "trailing-partial-chunk",
        "wrong-key",
    ],
    "Phase 3, step 4 (recovery code factor)": [
        "access-recovery-code",
        "access-password-key-recovery",
        "access-any-of-three-grants",
    ],
}


def credentials(open_with: dict[str, Any]) -> access.Credentials:
    """The password parts of a manifest `open_with`; keys and recovery codes
    are ignored until their factors exist."""
    return access.Credentials(
        passwords=open_with.get("passwords", []),
        entry_passwords={
            bytes.fromhex(k): v for k, v in open_with.get("vault_entries", {}).items()
        },
    )


def open_vector(data: bytes, creds: access.Credentials) -> bytes:
    out = io.BytesIO()
    container.decrypt(io.BytesIO(data), out, creds)
    return out.getvalue()


@pytest.mark.parametrize("name", OPENS)
def test_opens_valid_vector(name: str) -> None:
    vector = vectorkit.valid(name)
    data = vectorkit.read(vector["file"])
    plain = open_vector(data, credentials(vector["open_with"]))
    assert plain == vectorkit.plaintext(vector["plaintext"])


def test_vault_password_entry_falls_back_to_a_typed_password() -> None:
    data = vectorkit.read(vectorkit.valid("access-vault-password-entry")["file"])
    assert open_vector(data, access.Credentials(passwords=[PASSWORD])) == b"access\n"


def test_any_of_three_opens_with_the_password_grant() -> None:
    data = vectorkit.read(vectorkit.valid("access-any-of-three-grants")["file"])
    assert open_vector(data, access.Credentials(passwords=[PASSWORD])) == b"access\n"


def test_a_mistyped_then_correct_password_opens() -> None:
    data = vectorkit.read(vectorkit.valid("access-password")["file"])
    creds = access.Credentials(passwords=["correct horse battery stapel", PASSWORD])
    assert open_vector(data, creds) == b"access\n"


@pytest.mark.parametrize("name", OPENS)
def test_wrong_password_cannot_open(name: str) -> None:
    data = vectorkit.read(vectorkit.valid(name)["file"])
    with pytest.raises(CannotOpen):
        open_vector(data, access.Credentials(passwords=["wrong"]))


def _new_factor(name: str, salt: bytes) -> access.NewFactor:
    if name == "access-vault-password-entry":
        return access.new_vault_password(ENTRY_ID, PASSWORD, salt=salt)
    if name == "access-password-nfc":
        return access.new_password(CREDS["unicode_password_nfd"], salt=salt)
    return access.new_password(PASSWORD, salt=salt)


@pytest.mark.parametrize("name", OPENS)
def test_reproduces_valid_vector_byte_for_byte(name: str) -> None:
    vector = vectorkit.valid(name)
    rnd = {k: bytes.fromhex(v) for k, v in vector["random"].items()}
    factor = _new_factor(name, rnd["password_salt"])
    grant = access.new_grant(rnd["file_key"], [factor], salt=rnd["grant_salt"])
    out = io.BytesIO()
    container.seal(
        rnd["file_key"],
        FixedHeader(rnd["payload_nonce"]),
        [grant],
        io.BytesIO(vectorkit.plaintext(vector["plaintext"])),
        out,
    )
    assert out.getvalue() == vectorkit.read(vector["file"])


@pytest.mark.parametrize("name", PARSE_REJECTS + ARMOR_REJECTS)
def test_rejects_vector(name: str) -> None:
    vector = vectorkit.reject(name)
    data = vectorkit.read(vector["file"])
    with pytest.raises(FormatError) as caught:
        open_vector(data, credentials(vector["open_with"]))
    assert caught.value.reason == vector["reason"]


def test_armored_vector_round_trips_through_the_armour() -> None:
    data = vectorkit.read(vectorkit.valid("format-armored")["file"])
    binary = armor.decode(data)
    assert armor.encode(binary) == data
    sink = io.BytesIO()
    writer = armor.ArmorWriter(sink)
    for i in range(0, len(binary), 7):
        writer.write(binary[i : i + 7])
    writer.close()
    assert sink.getvalue() == data
    assert armor.decode(data.replace(b"\n", b"\r\n")) == binary


def test_armored_vector_header_parses() -> None:
    data = vectorkit.read(vectorkit.valid("format-armored")["file"])
    header = container.read_header(io.BytesIO(armor.decode(data)))
    [grant] = header.grants
    assert grant.factors is not None
    assert [f.kind for f in grant.factors] == [access.KEY]
