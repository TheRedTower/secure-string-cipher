"""The armoured form (FORMAT.md section 8): a whole SSC file as Base64 text."""

from __future__ import annotations

import base64
import binascii

from secure_string_cipher.engine.payload import Writable
from secure_string_cipher.errors import FormatError, Reason

BEGIN = b"-----BEGIN SSC MESSAGE-----"
END = b"-----END SSC MESSAGE-----"
LINE = 64
_LINE_BYTES = LINE // 4 * 3  # 48 bytes encode to one full line


class ArmorWriter:
    """Armours bytes as they are written, so encrypting to armour streams."""

    def __init__(self, sink: Writable) -> None:
        self._sink = sink
        self._pending = b""
        self._sink.write(BEGIN + b"\n")

    def write(self, data: bytes, /) -> int:
        self._pending += data
        whole = len(self._pending) // _LINE_BYTES * _LINE_BYTES
        for i in range(0, whole, _LINE_BYTES):
            line = self._pending[i : i + _LINE_BYTES]
            self._sink.write(base64.b64encode(line) + b"\n")
        self._pending = self._pending[whole:]
        return len(data)

    def close(self) -> None:
        if self._pending:
            self._sink.write(base64.b64encode(self._pending) + b"\n")
            self._pending = b""
        self._sink.write(END + b"\n")


def encode(data: bytes) -> bytes:
    lines = [
        base64.b64encode(data[i : i + _LINE_BYTES])
        for i in range(0, len(data), _LINE_BYTES)
    ]
    return b"\n".join([BEGIN, *lines, END]) + b"\n"


def decode(text: bytes) -> bytes:
    """Decode an armoured file strictly, returning the binary SSC file."""
    if b"\r\n" in text:
        if b"\n" in text.replace(b"\r\n", b""):
            raise FormatError(Reason.ARMOR_LINE_ENDINGS, "Mixed line endings.")
        text = text.replace(b"\r\n", b"\n")
    if b"\r" in text:
        raise FormatError(Reason.ARMOR_LINE_ENDINGS, "Stray carriage return.")
    if text.endswith(b"\n"):
        text = text[:-1]
    lines = text.split(b"\n")
    if (
        len(lines) < 3
        or lines[0] != BEGIN
        or lines[-1] != END
        or any(line in (BEGIN, END) for line in lines[1:-1])
    ):
        raise FormatError(Reason.ARMOR_FRAME, "This is not one armoured SSC block.")
    body = lines[1:-1]
    if not 1 <= len(body[-1]) <= LINE or any(len(line) != LINE for line in body[:-1]):
        raise FormatError(
            Reason.ARMOR_LINE_LENGTH, "An armour line has the wrong length."
        )
    joined = b"".join(body)
    try:
        decoded = base64.b64decode(joined, validate=True)
    except (binascii.Error, ValueError):
        raise FormatError(
            Reason.ARMOR_BASE64, "The armour is not valid Base64."
        ) from None
    if base64.b64encode(decoded) != joined:
        raise FormatError(Reason.ARMOR_BASE64, "The armour is not canonical Base64.")
    return decoded
