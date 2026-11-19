"""The payload layer against the frozen vectors (Phase 2, step 1)."""

import io

import pytest

from secure_string_cipher.engine import payload
from secure_string_cipher.engine.header import FixedHeader
from secure_string_cipher.errors import FormatError
from tests import vectorkit

BINARY_VALID = [
    v["name"] for v in vectorkit.manifest()["valid"] if "armored" not in v["name"]
]

# The rejection vectors this layer is responsible for. The rest belong to
# the access layer and the armoured form (Phase 2, step 2).
HEADER_REJECTS = ["magic", "version"]
PAYLOAD_REJECTS = [
    "truncated-at-chunk-boundary",
    "appended-byte",
    "empty-trailing-chunk",
    "trailing-partial-chunk",
]


@pytest.mark.parametrize("name", BINARY_VALID)
def test_decrypts_valid_vector(name: str) -> None:
    vector = vectorkit.valid(name)
    parts = vectorkit.split(vectorkit.read(vector["file"]))
    key = payload.payload_key(
        bytes.fromhex(vector["random"]["file_key"]),
        FixedHeader.parse(parts.fixed_header),
    )
    out = io.BytesIO()
    payload.decrypt(key, io.BytesIO(parts.payload), out)
    assert out.getvalue() == vectorkit.plaintext(vector["plaintext"])


@pytest.mark.parametrize("name", BINARY_VALID)
def test_reproduces_valid_vector_byte_for_byte(name: str) -> None:
    vector = vectorkit.valid(name)
    parts = vectorkit.split(vectorkit.read(vector["file"]))
    header = FixedHeader(bytes.fromhex(vector["random"]["payload_nonce"]))
    assert header.to_bytes() == parts.fixed_header
    key = payload.payload_key(bytes.fromhex(vector["random"]["file_key"]), header)
    out = io.BytesIO()
    payload.encrypt(key, io.BytesIO(vectorkit.plaintext(vector["plaintext"])), out)
    assert out.getvalue() == parts.payload


def test_decrypts_and_reproduces_the_vault_payload() -> None:
    vault = vectorkit.manifest()["vault"]
    parts = vectorkit.split(vectorkit.read(vault["file"]))
    header = FixedHeader.parse(parts.fixed_header)
    key = payload.payload_key(bytes.fromhex(vault["random"]["file_key"]), header)
    out = io.BytesIO()
    payload.decrypt(key, io.BytesIO(parts.payload), out)
    again = io.BytesIO()
    payload.encrypt(key, io.BytesIO(out.getvalue()), again)
    assert again.getvalue() == parts.payload


@pytest.mark.parametrize("name", HEADER_REJECTS)
def test_rejects_bad_header(name: str) -> None:
    vector = vectorkit.reject(name)
    with pytest.raises(FormatError) as caught:
        FixedHeader.parse(vectorkit.read(vector["file"]))
    assert caught.value.reason == vector["reason"]


@pytest.mark.parametrize("name", PAYLOAD_REJECTS)
def test_rejects_bad_payload(name: str) -> None:
    vector = vectorkit.reject(name)
    parts = vectorkit.split(vectorkit.read(vector["file"]))
    key = payload.payload_key(
        bytes.fromhex(vector["random"]["file_key"]),
        FixedHeader.parse(parts.fixed_header),
    )
    with pytest.raises(FormatError) as caught:
        payload.decrypt(key, io.BytesIO(parts.payload), io.BytesIO())
    assert caught.value.reason == vector["reason"]
