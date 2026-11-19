"""A whole SSC file (FORMAT.md section 4): header, access block and payload."""

from __future__ import annotations

import io
import secrets
import struct
from collections.abc import Sequence
from dataclasses import dataclass, field

from secure_string_cipher.engine import access, armor, payload
from secure_string_cipher.engine.header import SIZE as FIXED_HEADER_SIZE
from secure_string_cipher.engine.header import FixedHeader
from secure_string_cipher.engine.payload import (
    Readable,
    Writable,
    read_exactly,
    write_all,
)
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
    mac = access.access_mac(file_key, header, body)
    write_all(sink, header + struct.pack(">I", len(body)) + body + mac)
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


def _binary(source: Readable) -> tuple[Readable, bool]:
    """Detect the armoured form by its first bytes (FORMAT.md section 8).
    Returns the binary stream and whether the input was armoured.

    Armour is decoded in memory, since it is meant for text-sized messages.
    """
    start = read_exactly(source, len(armor.BEGIN))
    if start == armor.BEGIN:
        rest = b"".join(iter(lambda: source.read(1 << 16), b""))
        return io.BytesIO(armor.decode(start + rest)), True
    return _Prefixed(start, source), False


@dataclass(frozen=True)
class Opened:
    """A file whose access block has been opened and confirmed. `payload` is
    positioned at the start of the payload, which is not yet checked."""

    header: Header
    file_key: bytes = field(repr=False)
    payload: Readable
    armored: bool


def unlock(source: Readable, credentials: access.Credentials) -> Opened:
    """FORMAT.md section 7.2, steps 1 to 4: parse everything before the
    payload, then recover and confirm the file key."""
    stream, armored = _binary(source)
    header = read_header(stream)
    file_key = access.open_file_key(
        header.grants,
        header.fixed.to_bytes(),
        header.access_body,
        header.access_mac,
        credentials,
    )
    return Opened(header, file_key, stream, armored)


def decrypt(source: Readable, sink: Writable, credentials: access.Credentials) -> int:
    """Open and decrypt a file. Returns the plaintext size.

    As with `payload.decrypt`, output is only valid once this returns;
    callers MUST discard it if this raises (FORMAT.md section 7.2).
    """
    opened = unlock(source, credentials)
    key = payload.payload_key(opened.file_key, opened.header.fixed)
    return payload.decrypt(key, opened.payload, sink)


# --- changing access (FORMAT.md section 7.3) -------------------------------


def _output(sink: Writable, armored: bool) -> tuple[Writable, armor.ArmorWriter | None]:
    if not armored:
        return sink, None
    writer = armor.ArmorWriter(sink)
    return writer, writer


def _rewrite_access(
    opened: Opened, grants: Sequence[access.Grant], sink: Writable
) -> None:
    """Write the file with a new access block and the payload bytes as they
    were. The output keeps the input's form, binary or armoured."""
    out, writer = _output(sink, opened.armored)
    header = opened.header.fixed.to_bytes()
    body = access.encode_access_body(grants)
    mac = access.access_mac(opened.file_key, header, body)
    write_all(out, header + struct.pack(">I", len(body)) + body + mac)
    for part in iter(lambda: opened.payload.read(1 << 16), b""):
        write_all(out, part)
    if writer:
        writer.close()


def add_grant(
    source: Readable,
    sink: Writable,
    credentials: access.Credentials,
    factors: Sequence[access.NewFactor],
) -> None:
    """Append a grant needing all of `factors`. Existing grants, unknown ones
    included, are kept byte for byte (ACCESS.md section 5)."""
    opened = unlock(source, credentials)
    grant = access.new_grant(opened.file_key, factors)
    _rewrite_access(opened, [*opened.header.grants, grant], sink)


def remove_grant(
    source: Readable, sink: Writable, credentials: access.Credentials, index: int
) -> None:
    """Drop the grant at `index` (0-based; the CLI's g1 is index 0).

    This is not revocation: the file key and payload are unchanged, so an
    old copy still opens as before (FORMAT.md section 7.3).
    """
    opened = unlock(source, credentials)
    grants = list(opened.header.grants)
    if not 0 <= index < len(grants):
        raise IndexError(f"There is no grant g{index + 1}.")
    if len(grants) == 1:
        raise ValueError("A file must keep at least one grant.")
    del grants[index]
    _rewrite_access(opened, grants, sink)


def rotate(
    source: Readable,
    sink: Writable,
    credentials: access.Credentials,
    policy: Sequence[Sequence[access.NewFactor]],
) -> int:
    """Re-encrypt under a new file key and payload nonce, with every kept
    grant rebuilt from `policy`. Returns the plaintext size.

    As with `decrypt`, the output is only valid once this returns: the old
    payload is authenticated as it is re-encrypted.
    """
    opened = unlock(source, credentials)
    old = payload.payload_key(opened.file_key, opened.header.fixed)
    plaintext = payload.ChunkReader(payload.chunks(old, opened.payload))
    return encrypt(plaintext, sink, policy, armored=opened.armored)
