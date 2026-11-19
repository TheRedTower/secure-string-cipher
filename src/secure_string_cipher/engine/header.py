"""The fixed header (FORMAT.md section 4).

The fixed header is the first 25 bytes of every SSC file. It never changes
while the payload stays the same, and the payload key is derived from it.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from secure_string_cipher.errors import FormatError, Reason

MAGIC = b"\x89SSC\r\n\x1a\n"
VERSION = 0x01
NONCE_SIZE = 16
SIZE = len(MAGIC) + 1 + NONCE_SIZE  # 25


@dataclass(frozen=True)
class FixedHeader:
    payload_nonce: bytes

    def __post_init__(self) -> None:
        if len(self.payload_nonce) != NONCE_SIZE:
            raise ValueError(f"payload_nonce must be {NONCE_SIZE} bytes")

    @classmethod
    def new(cls) -> FixedHeader:
        """A header with a fresh payload nonce, as every payload write needs
        (FORMAT.md section 4.3)."""
        return cls(secrets.token_bytes(NONCE_SIZE))

    def to_bytes(self) -> bytes:
        return MAGIC + bytes([VERSION]) + self.payload_nonce

    @classmethod
    def parse(cls, data: bytes) -> FixedHeader:
        """Parse the first 25 bytes of a file. Extra bytes are ignored."""
        if data[: len(MAGIC)] != MAGIC:
            raise FormatError(Reason.MAGIC, "This is not an SSC file.")
        if len(data) <= len(MAGIC) or data[len(MAGIC)] != VERSION:
            raise FormatError(
                Reason.VERSION, "This SSC file uses a version this SSC cannot read."
            )
        if len(data) < SIZE:
            raise FormatError(Reason.TRUNCATED, "This SSC file is truncated.")
        return cls(data[len(MAGIC) + 1 : SIZE])
