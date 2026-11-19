"""Payload-layer behaviour beyond the vectors (FORMAT.md section 6)."""

import io

import pytest

from secure_string_cipher.engine import payload
from secure_string_cipher.engine.header import FixedHeader
from secure_string_cipher.errors import FormatError, Reason

C = payload.CHUNK_SIZE
SIZES = [0, 1, C - 1, C, C + 1, 3 * C, 3 * C + 5]


def key() -> bytes:
    return payload.payload_key(bytes(range(32)), FixedHeader(bytes(16)))


def seal(data: bytes) -> bytes:
    out = io.BytesIO()
    assert payload.encrypt(key(), io.BytesIO(data), out) == len(data)
    return out.getvalue()


def open_(sealed: bytes) -> bytes:
    out = io.BytesIO()
    payload.decrypt(key(), io.BytesIO(sealed), out)
    return out.getvalue()


class Trickle:
    """A stream that returns at most 1,000 bytes per read, like a pipe."""

    def __init__(self, data: bytes) -> None:
        self._data = io.BytesIO(data)

    def read(self, size: int, /) -> bytes:
        return self._data.read(min(size, 1000))


@pytest.mark.parametrize("size", SIZES)
def test_round_trip(size: int) -> None:
    data = bytes(i % 256 for i in range(size))
    sealed = seal(data)
    chunks = max(1, -(-size // C))
    assert len(sealed) == size + chunks * payload.TAG_SIZE
    assert open_(sealed) == data


@pytest.mark.parametrize("size", [C + 1, 3 * C + 5])
def test_short_reads_do_not_end_the_stream(size: int) -> None:
    data = bytes(i % 256 for i in range(size))
    sealed = io.BytesIO()
    payload.encrypt(key(), Trickle(data), sealed)
    assert sealed.getvalue() == seal(data)
    out = io.BytesIO()
    payload.decrypt(key(), Trickle(sealed.getvalue()), out)
    assert out.getvalue() == data


def test_every_byte_is_authenticated() -> None:
    sealed = seal(b"x" * (C + 10))
    for at in (0, C, C + payload.TAG_SIZE, len(sealed) - 1):
        damaged = bytearray(sealed)
        damaged[at] ^= 1
        with pytest.raises(FormatError) as caught:
            open_(bytes(damaged))
        assert caught.value.reason == Reason.CHUNK_AUTH


def test_swapped_chunks_fail() -> None:
    sealed = seal(b"a" * C + b"b" * C + b"c")
    s = payload.SEALED_CHUNK_SIZE
    swapped = sealed[s : 2 * s] + sealed[:s] + sealed[2 * s :]
    with pytest.raises(FormatError):
        open_(swapped)


def test_wrong_key_fails() -> None:
    sealed = seal(b"secret")
    other = payload.payload_key(bytes(32), FixedHeader(bytes(16)))
    with pytest.raises(FormatError):
        payload.decrypt(other, io.BytesIO(sealed), io.BytesIO())


def test_empty_payload_is_truncated() -> None:
    with pytest.raises(FormatError) as caught:
        open_(b"")
    assert caught.value.reason == Reason.TRUNCATED


def test_payload_key_depends_on_nonce_and_file_key() -> None:
    a = payload.payload_key(bytes(32), FixedHeader(bytes(16)))
    b = payload.payload_key(bytes(32), FixedHeader(b"\x01" + bytes(15)))
    c = payload.payload_key(b"\x01" + bytes(31), FixedHeader(bytes(16)))
    assert len({a, b, c}) == 3


def test_payload_key_rejects_a_short_file_key() -> None:
    with pytest.raises(ValueError):
        payload.payload_key(bytes(31), FixedHeader(bytes(16)))


def test_chunk_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    sealed = seal(b"z" * (2 * C + 1))
    monkeypatch.setattr(payload, "MAX_CHUNKS", 2)
    with pytest.raises(ValueError):
        seal(b"z" * (2 * C + 1))
    with pytest.raises(FormatError) as caught:
        open_(sealed)
    assert caught.value.reason == Reason.TOO_MANY_CHUNKS


def test_header_round_trip_and_fresh_nonces() -> None:
    a, b = FixedHeader.new(), FixedHeader.new()
    assert a.payload_nonce != b.payload_nonce
    assert FixedHeader.parse(a.to_bytes()) == a
    with pytest.raises(ValueError):
        FixedHeader(bytes(15))


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"", Reason.MAGIC),
        (b"\x89SSC\r\n\x1a", Reason.MAGIC),
        (b"\x89SSC\r\n\x1a\n", Reason.VERSION),
        (b"\x89SSC\r\n\x1a\n\x01" + bytes(15), Reason.TRUNCATED),
    ],
)
def test_header_rejects(data: bytes, reason: Reason) -> None:
    with pytest.raises(FormatError) as caught:
        FixedHeader.parse(data)
    assert caught.value.reason == reason
