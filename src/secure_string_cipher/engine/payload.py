"""The payload layer (FORMAT.md section 6).

The plaintext is split into 64 KiB chunks. Each chunk is sealed with
AES-256-GCM under the payload key, with a nonce made of an 11-byte
big-endian chunk counter and a last-chunk flag. The payload key comes from
the file key and the fixed header only, so it never depends on who has
access (FORMAT.md section 3).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from secure_string_cipher.engine.header import FixedHeader
from secure_string_cipher.errors import FormatError, Reason

CHUNK_SIZE = 65536
TAG_SIZE = 16
SEALED_CHUNK_SIZE = CHUNK_SIZE + TAG_SIZE
MAX_CHUNKS = 2**32
FILE_KEY_SIZE = 32


class Readable(Protocol):
    def read(self, size: int, /) -> bytes: ...


class Writable(Protocol):
    def write(self, data: bytes, /) -> int: ...


def payload_key(file_key: bytes, header: FixedHeader) -> bytes:
    """HKDF(file_key, payload_nonce, "ssc3/payload-key" || fixed_header)."""
    if len(file_key) != FILE_KEY_SIZE:
        raise ValueError(f"file_key must be {FILE_KEY_SIZE} bytes")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=header.payload_nonce,
        info=b"ssc3/payload-key" + header.to_bytes(),
    )
    return hkdf.derive(file_key)


def _nonce(index: int, final: bool) -> bytes:
    return index.to_bytes(11, "big") + (b"\x01" if final else b"\x00")


def read_exactly(source: Readable, size: int) -> bytes:
    """Read `size` bytes, or fewer only at the end of the stream.

    A pipe or socket may return short reads, so a short read alone does not
    mean the stream has ended.
    """
    parts: list[bytes] = []
    remaining = size
    while remaining:
        part = source.read(remaining)
        if not part:
            break
        parts.append(part)
        remaining -= len(part)
    return b"".join(parts)


def write_all(sink: Writable, data: bytes) -> None:
    """Write all of `data`, since a raw stream may accept only part of it."""
    view = memoryview(data)
    while view:
        written = sink.write(bytes(view))
        if not written:
            raise OSError("The output stream accepted no bytes.")
        view = view[written:]


def encrypt(key: bytes, source: Readable, sink: Writable) -> int:
    """Encrypt everything in `source` to `sink`. Returns the plaintext size.

    Writers MUST use a payload key that has never sealed another payload,
    which a fresh payload nonce guarantees (FORMAT.md section 4.3).
    """
    aead = AESGCM(key)
    current = read_exactly(source, CHUNK_SIZE)
    index, total = 0, 0
    while True:
        following = (
            read_exactly(source, CHUNK_SIZE) if len(current) == CHUNK_SIZE else b""
        )
        final = not following
        if index >= MAX_CHUNKS:
            raise ValueError("The payload is too large: at most 2^32 chunks.")
        write_all(sink, aead.encrypt(_nonce(index, final), current, None))
        total += len(current)
        if final:
            return total
        current, index = following, index + 1


def chunks(key: bytes, source: Readable) -> Iterator[bytes]:
    """Yield each plaintext chunk of the payload as it authenticates.

    The payload as a whole is authenticated only when this finishes without
    raising: a missing final chunk is only detected at the end.
    """
    aead = AESGCM(key)
    current = read_exactly(source, SEALED_CHUNK_SIZE)
    index = 0
    while True:
        following = (
            read_exactly(source, SEALED_CHUNK_SIZE)
            if len(current) == SEALED_CHUNK_SIZE
            else b""
        )
        final = not following
        if len(current) < TAG_SIZE:
            raise FormatError(Reason.TRUNCATED, "This SSC file is truncated.")
        if final and len(current) == TAG_SIZE and index > 0:
            raise FormatError(
                Reason.EMPTY_FINAL_CHUNK, "This SSC file ends with an empty chunk."
            )
        if index >= MAX_CHUNKS:
            raise FormatError(Reason.TOO_MANY_CHUNKS, "This SSC file is too large.")
        try:
            yield aead.decrypt(_nonce(index, final), current, None)
        except InvalidTag:
            raise FormatError(
                Reason.CHUNK_AUTH,
                "This SSC file is damaged, truncated or has been changed.",
            ) from None
        if final:
            return
        current, index = following, index + 1


def decrypt(key: bytes, source: Readable, sink: Writable) -> int:
    """Decrypt the payload in `source` to `sink`. Returns the plaintext size.

    Each chunk is written as soon as it authenticates. Until this returns,
    though, the payload as a whole is not yet authenticated. Callers MUST
    discard what was written if this raises (FORMAT.md section 7.2).
    """
    total = 0
    for plaintext in chunks(key, source):
        write_all(sink, plaintext)
        total += len(plaintext)
    return total


class ChunkReader:
    """A `Readable` over an iterator of byte strings, such as `chunks`, so
    one payload can be decrypted straight into the encryption of another."""

    def __init__(self, parts: Iterator[bytes]) -> None:
        self._parts = parts
        self._buffer = b""

    def read(self, size: int, /) -> bytes:
        while len(self._buffer) < size:
            part = next(self._parts, None)
            if part is None:
                break
            self._buffer += part
        out, self._buffer = self._buffer[:size], self._buffer[size:]
        return out
