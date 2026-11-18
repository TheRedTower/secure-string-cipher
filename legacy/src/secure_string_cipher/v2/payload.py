"""File payload frame formatting and AEAD operations."""

import hashlib
import os
import struct
from collections.abc import Iterator
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from secure_string_cipher.v2.envelope import (
    MAX_PLAINTEXT_FILE_SIZE,
    PayloadType,
    V2Header,
    canonical_json,
)
from secure_string_cipher.v2.kdf import derive_payload_key
from secure_string_cipher.v2.keywrap import build_projection_m_context
from secure_string_cipher.v2.vault_schema import b64url_decode

FRAME_MAGIC: bytes = b"S2FR"
FRAME_FLAG_FINAL: int = 0x01
FRAME_AAD_DOMAIN: bytes = b"SSC2/frame/v2\0"
# Wire header: S2FR || frame_index(8) || pt_len(4) || pad_len(2) || flags(1)
FRAME_HEADER_LEN: int = 4 + 8 + 4 + 2 + 1


def _m_context_digest(header: V2Header) -> bytes:
    """SHA-256 digest of the canonical M_context projection (owned by keywrap)."""
    return hashlib.sha256(
        canonical_json(build_projection_m_context(header).mapping)
    ).digest()


class FrameWriter:
    """Writes chunked and padded frames for a file payload."""

    def __init__(self, header: V2Header, dek: bytes, out_stream: BinaryIO):
        if header.payload.type != PayloadType.FILE:
            raise ValueError("FrameWriter only supports FILE payload type")

        chunk_size = header.payload.chunk_size
        if chunk_size is None:
            raise ValueError("FILE payload must specify chunk_size")
        self.chunk_size: int = chunk_size

        self.out_stream = out_stream

        kdf_block = header.payload.kdf
        if not isinstance(kdf_block, dict) and not hasattr(kdf_block, "get"):
            raise TypeError("Payload kdf block missing or invalid")

        kdf_salt = kdf_block.get("salt")  # type: ignore[union-attr]
        if not isinstance(kdf_salt, str):
            raise TypeError("Payload kdf salt missing or invalid")

        self.k_payload = derive_payload_key(
            dek, b64url_decode(kdf_salt, expected_length=32), PayloadType.FILE
        )
        self.m_context_digest = _m_context_digest(header)

        nonce_prefix_b64 = header.payload.nonce_prefix
        if not isinstance(nonce_prefix_b64, str):
            raise TypeError("Payload nonce_prefix missing or invalid")

        self.nonce_prefix = b64url_decode(nonce_prefix_b64, expected_length=4)
        self.frame_index = 0
        self.aead = AESGCM(self.k_payload)

    def write_frame(
        self, chunk: bytes, is_final: bool = False, padding_len: int | None = None
    ) -> None:
        plaintext_len = len(chunk)
        if plaintext_len > self.chunk_size:
            raise ValueError(
                f"Chunk size {plaintext_len} exceeds max {self.chunk_size}"
            )

        if not is_final:
            expected_padding = self.chunk_size - plaintext_len
            if padding_len is None:
                padding_len = expected_padding
            elif padding_len != expected_padding:
                raise ValueError(
                    f"Non-final frame must be padded to chunk_size ({self.chunk_size})"
                )
        else:
            if padding_len is None:
                padding_len = 0
            if plaintext_len + padding_len > self.chunk_size:
                raise ValueError(
                    f"Final frame padding exceeds chunk_size ({self.chunk_size})"
                )

        padding = os.urandom(padding_len)
        padded_chunk = chunk + padding

        flags_bytes = bytes([FRAME_FLAG_FINAL if is_final else 0x00])

        frame_index_bytes = struct.pack("<Q", self.frame_index)
        nonce = self.nonce_prefix + frame_index_bytes

        pt_len_bytes = struct.pack("<I", plaintext_len)
        pad_len_bytes = struct.pack("<H", padding_len)

        aad = (
            FRAME_AAD_DOMAIN
            + self.m_context_digest
            + frame_index_bytes
            + pt_len_bytes
            + pad_len_bytes
            + flags_bytes
        )

        ciphertext = self.aead.encrypt(nonce, padded_chunk, aad)

        frame_header = (
            FRAME_MAGIC + frame_index_bytes + pt_len_bytes + pad_len_bytes + flags_bytes
        )
        self.out_stream.write(frame_header)
        self.out_stream.write(ciphertext)

        self.frame_index += 1


class FrameReader:
    """Reads and decrypts chunked frames for a file payload."""

    def __init__(self, header: V2Header, dek: bytes, in_stream: BinaryIO):
        if header.payload.type != PayloadType.FILE:
            raise ValueError("FrameReader only supports FILE payload type")

        chunk_size = header.payload.chunk_size
        if chunk_size is None:
            raise ValueError("FILE payload must specify chunk_size")
        self.chunk_size: int = chunk_size

        self.in_stream = in_stream

        kdf_block = header.payload.kdf
        if not isinstance(kdf_block, dict) and not hasattr(kdf_block, "get"):
            raise TypeError("Payload kdf block missing or invalid")

        kdf_salt = kdf_block.get("salt")  # type: ignore[union-attr]
        if not isinstance(kdf_salt, str):
            raise TypeError("Payload kdf salt missing or invalid")

        self.k_payload = derive_payload_key(
            dek, b64url_decode(kdf_salt, expected_length=32), PayloadType.FILE
        )
        self.m_context_digest = _m_context_digest(header)

        nonce_prefix_b64 = header.payload.nonce_prefix
        if not isinstance(nonce_prefix_b64, str):
            raise TypeError("Payload nonce_prefix missing or invalid")

        self.nonce_prefix = b64url_decode(nonce_prefix_b64, expected_length=4)
        self.frame_index = 0
        self.aead = AESGCM(self.k_payload)

        # Spec §5: bound frame count and cumulative plaintext independently
        # of any declared/stored size, so a crafted container with far more
        # frames (or far more total plaintext) than the 100 MiB design limit
        # allows cannot be decrypted to completion. Computed per this
        # object's own chunk_size, matching "max(1, ceil(MAX / chunk_size))".
        self.max_frames = max(1, -(-MAX_PLAINTEXT_FILE_SIZE // self.chunk_size))
        self._cumulative_plaintext = 0

    def read_frames(self) -> Iterator[bytes]:
        """Yields decrypted chunks (with padding removed).

        Finality invariants (fail-closed):
        - clean EOF before a FINAL frame is an error;
        - non-final frames MUST satisfy pt_len + pad_len == chunk_size;
        - after a FINAL frame the stream MUST be at exact EOF (no trailing bytes);
        - a second FINAL or any frame after FINAL is therefore an error;
        - flags bits other than 0x01 (FINAL) are rejected.

        Also enforces (spec §5, independent of any declared size): the frame
        index never reaches ``max_frames``, and cumulative plaintext bytes
        across all frames never exceed ``MAX_PLAINTEXT_FILE_SIZE`` — checked
        before each frame's ciphertext body is read, not after.
        """
        while True:
            frame_magic = self.in_stream.read(4)
            if not frame_magic:
                raise ValueError("Stream ended before a FINAL frame was consumed")
            if frame_magic != FRAME_MAGIC:
                raise ValueError(f"Invalid frame magic: {frame_magic.hex()}")

            frame_index_bytes = self.in_stream.read(8)
            if len(frame_index_bytes) < 8:
                raise ValueError("Truncated frame index")
            frame_index = struct.unpack("<Q", frame_index_bytes)[0]

            if frame_index != self.frame_index:
                raise ValueError(
                    f"Expected frame index {self.frame_index}, got {frame_index}"
                )

            if self.frame_index >= self.max_frames:
                raise ValueError(
                    f"Frame index {self.frame_index} reaches the maximum of "
                    f"{self.max_frames} frames for chunk_size {self.chunk_size}"
                )

            pt_len_bytes = self.in_stream.read(4)
            if len(pt_len_bytes) < 4:
                raise ValueError("Truncated plaintext length")
            plaintext_len = struct.unpack("<I", pt_len_bytes)[0]

            pad_len_bytes = self.in_stream.read(2)
            if len(pad_len_bytes) < 2:
                raise ValueError("Truncated padding length")
            padding_len = struct.unpack("<H", pad_len_bytes)[0]

            flags_bytes = self.in_stream.read(1)
            if len(flags_bytes) < 1:
                raise ValueError("Truncated frame flags")
            flags = flags_bytes[0]
            if flags & ~FRAME_FLAG_FINAL:
                raise ValueError(f"Unsupported frame flags: {flags:#04x}")
            is_final = bool(flags & FRAME_FLAG_FINAL)

            if plaintext_len + padding_len > self.chunk_size:
                raise ValueError(
                    f"Frame length {plaintext_len + padding_len} exceeds chunk_size {self.chunk_size}"
                )
            if not is_final and plaintext_len + padding_len != self.chunk_size:
                raise ValueError(
                    f"Non-final frame length {plaintext_len + padding_len} "
                    f"does not equal chunk_size {self.chunk_size}"
                )

            self._cumulative_plaintext += plaintext_len
            if self._cumulative_plaintext > MAX_PLAINTEXT_FILE_SIZE:
                raise ValueError(
                    f"Cumulative plaintext {self._cumulative_plaintext} bytes "
                    f"exceeds maximum {MAX_PLAINTEXT_FILE_SIZE} bytes"
                )

            # AESGCM ciphertext includes 16 byte tag
            expected_ct_len = plaintext_len + padding_len + 16
            ciphertext = self.in_stream.read(expected_ct_len)
            if len(ciphertext) < expected_ct_len:
                raise ValueError("Truncated frame ciphertext")

            nonce = self.nonce_prefix + frame_index_bytes
            aad = (
                FRAME_AAD_DOMAIN
                + self.m_context_digest
                + frame_index_bytes
                + pt_len_bytes
                + pad_len_bytes
                + flags_bytes
            )

            try:
                padded_chunk = self.aead.decrypt(nonce, ciphertext, aad)
            except Exception as e:
                raise ValueError(f"Frame {frame_index} authentication failed") from e

            if is_final:
                # The FINAL frame MUST be the last bytes of the stream; any
                # trailing bytes (incl. a second FINAL frame) are an error.
                if self.in_stream.read(1):
                    raise ValueError("Trailing bytes after FINAL frame")

            chunk = padded_chunk[:plaintext_len]
            yield chunk

            self.frame_index += 1

            if is_final:
                return
