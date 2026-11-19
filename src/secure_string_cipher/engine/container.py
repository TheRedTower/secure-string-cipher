"""A whole SSC file (FORMAT.md section 4): header, access block and payload."""

from __future__ import annotations

import io
import secrets
import struct
from collections.abc import Sequence
from dataclasses import dataclass

from secure_string_cipher.engine import access, armor, payload
from secure_string_cipher.engine.header import SIZE as FIXED_HEADER_SIZE
from secure_string_cipher.engine.header import FixedHeader
from secure_string_cipher.engine.payload import Readable, Writable, read_exactly
from secure_string_cipher.errors import FormatError, Reason

MAC_SIZE = 32


@dataclass(frozen=True)
class Header:
    """Everything before the payload, parsed strictly."""

    fixed: FixedHeader
    access_body: bytes
    access_mac: bytes
    grants: list[access.Grant]


def read_header(source: Readable) -> Header:
    """Read and check the fixed header and the access block. The source is
    left positioned at the start of the payload."""
    fixed = FixedHeader.parse(read_exactly(source, FIXED_HEADER_SIZE))
    length_field = read_exactly(source, 4)
    if len(length_field) < 4:
        raise FormatError(Reason.TRUNCATED, "This SSC file is truncated.")
    (length,) = struct.unpack(">I", length_field)
    if not 1 <= length <= access.MAX_ACCESS_BODY:
        raise FormatError(Reason.ACCESS_LENGTH, "The access block has a bad length.")
    body = read_exactly(source, length)
    mac = read_exactly(source, MAC_SIZE)
    if len(body) < length or len(mac) < MAC_SIZE:
        raise FormatError(Reason.TRUNCATED, "This SSC file is truncated.")
    return Header(fixed, body, mac, access.parse_access_body(body))


def seal(
    file_key: bytes,
    fixed: FixedHeader,
    grants: Sequence[access.Grant],
    source: Readable,
    sink: Writable,
) -> int:
    """Write a whole file from given keys and grants. `encrypt` is the normal
    entry point; this exists so tests can reproduce vectors byte for byte."""
    body = access.encode_access_body(grants)
    header = fixed.to_bytes()
    sink.write(header + struct.pack(">I", len(body)) + body)
    sink.write(access.access_mac(file_key, header, body))
    return payload.encrypt(payload.payload_key(file_key, fixed), source, sink)


def encrypt(
    source: Readable,
    sink: Writable,
    policy: Sequence[Sequence[access.NewFactor]],
    *,
    armored: bool = False,
) -> int:
    """Encrypt `source` under a fresh file key. `policy` lists the grants,
    each as the factors it needs. Returns the plaintext size."""
    file_key = secrets.token_bytes(payload.FILE_KEY_SIZE)
    grants = [access.new_grant(file_key, factors) for factors in policy]
    if not armored:
        return seal(file_key, FixedHeader.new(), grants, source, sink)
    writer = armor.ArmorWriter(sink)
    size = seal(file_key, FixedHeader.new(), grants, source, writer)
    writer.close()
    return size


class _Prefixed:
    """A stream with some already-read bytes put back in front."""

    def __init__(self, prefix: bytes, rest: Readable) -> None:
        self._prefix = prefix
        self._rest = rest

    def read(self, size: int, /) -> bytes:
        if self._prefix:
            out, self._prefix = self._prefix[:size], self._prefix[size:]
            return out
        return self._rest.read(size)


def _binary(source: Readable) -> Readable:
    """Detect the armoured form by its first bytes (FORMAT.md section 8).

    Armour is decoded in memory, since it is meant for text-sized messages.
    """
    start = read_exactly(source, len(armor.BEGIN))
    if start == armor.BEGIN:
        rest = b"".join(iter(lambda: source.read(1 << 16), b""))
        return io.BytesIO(armor.decode(start + rest))
    return _Prefixed(start, source)


def decrypt(source: Readable, sink: Writable, credentials: access.Credentials) -> int:
    """Open and decrypt a file. Returns the plaintext size.

    As with `payload.decrypt`, output is only valid once this returns;
    callers MUST discard it if this raises (FORMAT.md section 7.2).
    """
    stream = _binary(source)
    header = read_header(stream)
    file_key = access.open_file_key(
        header.grants,
        header.fixed.to_bytes(),
        header.access_body,
        header.access_mac,
        credentials,
    )
    return payload.decrypt(payload.payload_key(file_key, header.fixed), stream, sink)
