"""Whole files against the frozen vectors: the access layer, the container
and the armoured form (Phase 2, steps 2 and 3).

Vectors that need the recovery code factor are listed in `PENDING` with the
step that brings it in; tests/engine/test_vector_coverage.py checks that
nothing is left out.
"""

from __future__ import annotations

import io
from typing import Any

import pytest

from secure_string_cipher.engine import access, armor, container, keyfile
from secure_string_cipher.engine.header import FixedHeader
from secure_string_cipher.errors import CannotOpen, SSCError
from tests import vectorkit

CREDS = vectorkit.manifest()["credentials"]
PASSWORD: str = CREDS["password"]
ENTRY_ID = bytes.fromhex(CREDS["vault_entry_id"])
KEY_A = bytes.fromhex(CREDS["key_a"])

# Valid vectors opened with the credentials the manifest gives, and the
# factors of each grant that reproduce them byte for byte. None stands for
# the vector's recorded unknown grant.
OPENS: dict[str, list[list[str] | None]] = {
    "format-0-bytes": [["key_a"]],
    "format-1-bytes": [["key_a"]],
    "format-65536-bytes": [["key_a"]],
    "format-65537-bytes": [["key_a"]],
    "format-armored": [["key_a"]],
    "access-password": [["password"]],
    "access-vault-password-entry": [["vault_password"]],
    "access-key": [["key_a"]],
    "access-password-and-key": [["password", "key_a"]],
    "access-unknown-grant-skipped": [None, ["key_a"]],
    "access-password-nfc": [["nfd_password"]],
}

PENDING = {
    "Phase 3, step 4 (recovery code factor)": [
        "access-recovery-code",
        "access-password-key-recovery",
        "access-any-of-three-grants",
    ],
}

REJECTS = [
    v["name"]
    for v in vectorkit.manifest()["reject"]
    if v["name"] not in PENDING["Phase 3, step 4 (recovery code factor)"]
]


def credentials(open_with: dict[str, Any]) -> access.Credentials:
    """A manifest `open_with`, less recovery codes until their factor exists."""
    return access.Credentials(
        passwords=open_with.get("passwords", []),
        entry_passwords={
            bytes.fromhex(k): v for k, v in open_with.get("vault_entries", {}).items()
        },
        keys=[bytes.fromhex(k) for k in open_with.get("keys", [])],
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


@pytest.mark.parametrize("name", OPENS)
def test_without_credentials_cannot_open(name: str) -> None:
    data = vectorkit.read(vectorkit.valid(name)["file"])
    with pytest.raises(CannotOpen):
        open_vector(data, access.Credentials(passwords=["wrong"]))


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


def test_password_and_key_needs_both() -> None:
    data = vectorkit.read(vectorkit.valid("access-password-and-key")["file"])
    for creds in (
        access.Credentials(passwords=[PASSWORD]),
        access.Credentials(keys=[KEY_A]),
    ):
        with pytest.raises(CannotOpen):
            open_vector(data, creds)


def _factor(name: str, salt: bytes) -> access.NewFactor:
    match name:
        case "password":
            return access.new_password(PASSWORD, salt=salt)
        case "nfd_password":
            return access.new_password(CREDS["unicode_password_nfd"], salt=salt)
        case "vault_password":
            return access.new_vault_password(ENTRY_ID, PASSWORD, salt=salt)
        case "key_a":
            return access.new_key(KEY_A)
    raise AssertionError(name)


@pytest.mark.parametrize("name", OPENS)
def test_reproduces_valid_vector_byte_for_byte(name: str) -> None:
    vector = vectorkit.valid(name)
    rnd = {k: bytes.fromhex(v) for k, v in vector["random"].items()}
    grants = []
    for spec in OPENS[name]:
        if spec is None:
            grants.append(access.Grant(rnd["unknown_grant"][2:], None))
            continue
        factors = [_factor(f, rnd.get("password_salt", b"")) for f in spec]
        grants.append(
            access.new_grant(rnd["file_key"], factors, salt=rnd["grant_salt"])
        )
    out = io.BytesIO()
    sink = armor.ArmorWriter(out) if "armored" in name else out
    container.seal(
        rnd["file_key"],
        FixedHeader(rnd["payload_nonce"]),
        grants,
        io.BytesIO(vectorkit.plaintext(vector["plaintext"])),
        sink,
    )
    if isinstance(sink, armor.ArmorWriter):
        sink.close()
    assert out.getvalue() == vectorkit.read(vector["file"])


@pytest.mark.parametrize("name", REJECTS)
def test_rejects_vector(name: str) -> None:
    vector = vectorkit.reject(name)
    data = vectorkit.read(vector["file"])
    with pytest.raises(SSCError) as caught:
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


@pytest.mark.parametrize("entry", vectorkit.manifest()["keyfiles"])
def test_keyfile_vector(entry: dict[str, str]) -> None:
    data = vectorkit.read(entry["file"])
    parsed = keyfile.parse(data)
    assert parsed.key == bytes.fromhex(entry["key"])
    assert parsed.key_id == bytes.fromhex(entry["key_id"])
    assert parsed.to_bytes() == data
    assert keyfile.parse(data.replace(b"\n", b"\r\n")) == parsed
