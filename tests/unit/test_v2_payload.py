import io
import os
import struct

import pytest

from secure_string_cipher.v2.envelope import (
    AccessBlock,
    AccessGrant,
    AccessPolicy,
    GrantType,
    MetadataPolicy,
    PayloadDescriptor,
    PayloadType,
    V2Header,
)
from secure_string_cipher.v2.payload import FrameReader, FrameWriter
from secure_string_cipher.v2.vault_schema import b64url_encode


def get_test_header(chunk_size: int = 65536) -> V2Header:
    return V2Header(
        format="SSC2",
        version=2,
        object_id="00000000-0000-0000-0000-000000000000",
        object_type="file",
        payload=PayloadDescriptor(
            type=PayloadType.FILE,
            alg="aes-256-gcm",
            kdf={"alg": "hkdf-sha256", "salt": b64url_encode(b"2" * 32)},
            metadata_policy=MetadataPolicy.ENCRYPTED,
            chunk_size=chunk_size,
            nonce_prefix=b64url_encode(b"N" * 4),
        ),
        access=AccessBlock(
            version=1,
            policy=AccessPolicy.SINGLE_GRANT,
            grants=[
                AccessGrant(
                    grant_id="g1",
                    type=GrantType.PASSWORD,
                    kek_derivation={"alg": "argon2id"},
                    wrap_alg="aes-256-gcm",
                    wrap_nonce=b64url_encode(b"3" * 12),
                    wrapped_dek=b64url_encode(b"4" * 32),
                    tag=b64url_encode(b"5" * 16),
                )
            ],
        ),
        metadata={},
    )


def test_frame_writer_reader_roundtrip():
    header = get_test_header(chunk_size=65536)
    dek = os.urandom(32)
    stream = io.BytesIO()

    writer = FrameWriter(header, dek, stream)

    # Write frames
    writer.write_frame(b"A" * 65536, is_final=False)
    writer.write_frame(b"B" * 60000, is_final=False)  # internally padded to 65536
    writer.write_frame(b"C" * 1000, is_final=True, padding_len=500)

    stream.seek(0)

    reader = FrameReader(header, dek, stream)
    chunks = list(reader.read_frames())

    assert len(chunks) == 3
    assert chunks[0] == b"A" * 65536
    assert chunks[1] == b"B" * 60000
    assert chunks[2] == b"C" * 1000


def test_frame_writer_validates_chunk_size():
    header = get_test_header(chunk_size=65536)
    dek = os.urandom(32)
    stream = io.BytesIO()
    writer = FrameWriter(header, dek, stream)

    with pytest.raises(ValueError, match="exceeds max"):
        writer.write_frame(b"A" * 65537, is_final=False)

    with pytest.raises(
        ValueError, match="Non-final frame must be padded to chunk_size"
    ):
        writer.write_frame(b"A" * 500, is_final=False, padding_len=100)

    with pytest.raises(ValueError, match="Final frame padding exceeds chunk_size"):
        writer.write_frame(b"A" * 65000, is_final=True, padding_len=1000)


def test_frame_reader_invalid_magic():
    header = get_test_header()
    dek = os.urandom(32)
    stream = io.BytesIO(b"X2FR" + b"\0" * 100)
    reader = FrameReader(header, dek, stream)

    with pytest.raises(ValueError, match="Invalid frame magic"):
        list(reader.read_frames())


def test_frame_reader_truncation():
    header = get_test_header()
    dek = os.urandom(32)
    stream = io.BytesIO(b"S2FR" + b"\0" * 7)  # truncated index
    reader = FrameReader(header, dek, stream)

    with pytest.raises(ValueError, match="Truncated frame index"):
        list(reader.read_frames())


def test_frame_reader_invalid_index():
    header = get_test_header(chunk_size=65536)
    dek = os.urandom(32)
    stream = io.BytesIO()
    writer = FrameWriter(header, dek, stream)
    writer.write_frame(b"A" * 65536, is_final=False)
    writer.write_frame(b"B" * 65536, is_final=True)

    # Tamper with the index of the second frame
    data = bytearray(stream.getvalue())
    # Frame 1 is: 19-byte header (magic 4 + index 8 + pt 4 + pad 2 + flags 1)
    # + 65536 (pt+pad) + 16 (tag) = 65571 bytes. Frame 2 starts at 65571.
    # Magic "S2FR" is 4 bytes. Index is at 65571 + 4 = 65575
    data[65575] = 99  # Change index from 1 to 99

    stream2 = io.BytesIO(data)
    reader = FrameReader(header, dek, stream2)
    iterator = reader.read_frames()

    # First chunk should be OK
    assert next(iterator) == b"A" * 65536

    with pytest.raises(ValueError, match="Expected frame index 1, got"):
        next(iterator)


def test_frame_reader_authentication_failure():
    header = get_test_header(chunk_size=65536)
    dek = os.urandom(32)
    stream = io.BytesIO()
    writer = FrameWriter(header, dek, stream)
    writer.write_frame(b"A" * 65536, is_final=True)

    data = bytearray(stream.getvalue())
    # Tamper with ciphertext (last byte of the file is part of the tag)
    data[-1] ^= 1

    stream2 = io.BytesIO(data)
    reader = FrameReader(header, dek, stream2)
    iterator = reader.read_frames()

    with pytest.raises(ValueError, match="authentication failed"):
        next(iterator)


def test_frame_reader_size_bounds():
    header = get_test_header(chunk_size=65536)
    dek = os.urandom(32)

    # Construct a fake frame with pt_len + pad_len > 65536
    frame_magic = b"S2FR"
    frame_index = struct.pack("<Q", 0)
    pt_len = struct.pack("<I", 65000)
    pad_len = struct.pack("<H", 1000)  # total 66000 > 65536
    flags = b"\x00"

    stream = io.BytesIO(
        frame_magic + frame_index + pt_len + pad_len + flags + b"\0" * 66050
    )
    reader = FrameReader(header, dek, stream)

    with pytest.raises(ValueError, match="exceeds chunk_size"):
        list(reader.read_frames())


def test_frame_reader_requires_final_frame():
    """Clean EOF before a FINAL frame is an error (truncation at frame boundary)."""
    header = get_test_header(chunk_size=65536)
    dek = os.urandom(32)
    stream = io.BytesIO()
    writer = FrameWriter(header, dek, stream)
    writer.write_frame(b"A" * 65536, is_final=False)
    writer.write_frame(b"B" * 1000, is_final=True)

    # Drop the FINAL frame entirely: container ends exactly at a frame boundary
    frame0_len = 19 + 65536 + 16
    truncated = stream.getvalue()[:frame0_len]

    reader = FrameReader(header, dek, io.BytesIO(truncated))
    iterator = reader.read_frames()
    assert next(iterator) == b"A" * 65536
    with pytest.raises(ValueError, match="before a FINAL frame"):
        next(iterator)


def test_frame_reader_rejects_trailing_bytes_after_final():
    header = get_test_header(chunk_size=65536)
    dek = os.urandom(32)
    stream = io.BytesIO()
    writer = FrameWriter(header, dek, stream)
    writer.write_frame(b"A" * 100, is_final=True, padding_len=500)

    data = stream.getvalue() + b"X"
    reader = FrameReader(header, dek, io.BytesIO(data))
    with pytest.raises(ValueError, match="Trailing bytes after FINAL frame"):
        list(reader.read_frames())


def test_frame_reader_rejects_second_final_frame():
    """Any frame after FINAL — including a second FINAL — is an error."""
    header = get_test_header(chunk_size=65536)
    dek = os.urandom(32)
    stream = io.BytesIO()
    writer = FrameWriter(header, dek, stream)
    writer.write_frame(b"A" * 100, is_final=True)
    writer.write_frame(b"B" * 100, is_final=True)

    reader = FrameReader(header, dek, io.BytesIO(stream.getvalue()))
    with pytest.raises(ValueError, match="Trailing bytes after FINAL frame"):
        list(reader.read_frames())


def test_frame_reader_rejects_reserved_flag_bits():
    """Flags bits other than 0x01 (FINAL) are rejected on read."""
    header = get_test_header(chunk_size=65536)
    dek = os.urandom(32)
    stream = io.BytesIO()
    writer = FrameWriter(header, dek, stream)
    writer.write_frame(b"A" * 100, is_final=True, padding_len=500)

    data = bytearray(stream.getvalue())
    data[18] = 0x02  # flags byte: set a reserved bit
    reader = FrameReader(header, dek, io.BytesIO(bytes(data)))
    with pytest.raises(ValueError, match="Unsupported frame flags"):
        list(reader.read_frames())


def test_frame_reader_rejects_short_nonfinal_frame():
    """Non-final frames MUST satisfy pt_len + pad_len == chunk_size."""
    header = get_test_header(chunk_size=65536)
    dek = os.urandom(32)
    stream = io.BytesIO()
    writer = FrameWriter(header, dek, stream)
    writer.write_frame(b"A" * 1000, is_final=True, padding_len=500)

    data = bytearray(stream.getvalue())
    data[18] = 0x00  # clear FINAL: now pt+pad (1500) != chunk_size (65536)
    reader = FrameReader(header, dek, io.BytesIO(bytes(data)))
    with pytest.raises(ValueError, match="does not equal chunk_size"):
        list(reader.read_frames())


def test_frame_reader_final_bit_flip_fails_aead():
    """Flipping FINAL on frame 0 of a 2-frame stream breaks AEAD (flags in AAD)."""
    header = get_test_header(chunk_size=65536)
    dek = os.urandom(32)
    stream = io.BytesIO()
    writer = FrameWriter(header, dek, stream)
    writer.write_frame(b"A" * 65536, is_final=False)
    writer.write_frame(b"B" * 1000, is_final=True)

    data = bytearray(stream.getvalue())
    data[18] = 0x01  # set FINAL on frame 0
    reader = FrameReader(header, dek, io.BytesIO(bytes(data)))
    with pytest.raises(ValueError, match="authentication failed"):
        list(reader.read_frames())


def test_frame_reader_and_writer_reject_text_payload():
    header = V2Header(
        format="SSC2",
        version=2,
        object_id="00000000-0000-0000-0000-000000000000",
        object_type="text",
        payload=PayloadDescriptor(
            type=PayloadType.TEXT,
            alg="aes-256-gcm",
            kdf={"alg": "hkdf-sha256", "salt": b64url_encode(b"2" * 32)},
            metadata_policy=MetadataPolicy.ENCRYPTED,
            nonce=b64url_encode(b"N" * 12),
            plaintext_length=100,
        ),
        access=AccessBlock(
            version=1,
            policy=AccessPolicy.SINGLE_GRANT,
            grants=[
                AccessGrant(
                    grant_id="g1",
                    type=GrantType.PASSWORD,
                    kek_derivation={"alg": "argon2id"},
                    wrap_alg="aes-256-gcm",
                    wrap_nonce=b64url_encode(b"3" * 12),
                    wrapped_dek=b64url_encode(b"4" * 32),
                    tag=b64url_encode(b"5" * 16),
                )
            ],
        ),
        metadata={},
    )
    dek = os.urandom(32)

    with pytest.raises(ValueError, match="only supports FILE payload type"):
        FrameWriter(header, dek, io.BytesIO())

    with pytest.raises(ValueError, match="only supports FILE payload type"):
        FrameReader(header, dek, io.BytesIO())


# ---------------------------------------------------------------------------
# Resource caps (spec §5): decrypt must bound frame count and cumulative
# plaintext independently of any declared/stored size, not just trust the
# stream to end. Regression coverage for a previously-unenforced gap.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("chunk_size", "expected_max_frames"),
    [
        (65536, 1600),  # 100 MiB / 64 KiB, spec's own worked example
        (4194304, 25),  # 100 MiB / 4 MiB
        (131072, 800),  # 100 MiB / 128 KiB
    ],
)
def test_max_frames_matches_spec_formula(chunk_size, expected_max_frames):
    """max_frames = ceil(MAX_PLAINTEXT_FILE_SIZE / chunk_size), per §5."""
    header = get_test_header(chunk_size=chunk_size)
    reader = FrameReader(header, os.urandom(32), io.BytesIO())
    assert reader.max_frames == expected_max_frames


def test_frame_count_exceeding_cap_is_rejected_before_completion():
    """A stream with more frames than max_frames must fail, not run forever
    trusting the writer to have stopped at a FINAL frame eventually."""
    header = get_test_header(chunk_size=65536)
    dek = os.urandom(32)
    stream = io.BytesIO()

    writer = FrameWriter(header, dek, stream)
    # One more non-final frame than the cap allows, then (never reached) a
    # final frame — the reader must reject before getting anywhere near it.
    writer.write_frame(b"A" * 65536, is_final=False)
    writer.write_frame(b"B" * 65536, is_final=False)
    writer.write_frame(b"C" * 1, is_final=True)
    stream.seek(0)

    reader = FrameReader(header, dek, stream)
    reader.max_frames = 2  # simulate the cap without writing 1,600 real frames

    chunks = []
    with pytest.raises(ValueError, match="reaches the maximum of 2 frames"):
        for chunk in reader.read_frames():
            chunks.append(chunk)

    # The rejection must happen at frame index 2, before decrypting/yielding
    # a third chunk — not merely "eventually" after consuming everything.
    assert len(chunks) == 2


def test_cumulative_plaintext_exceeding_cap_is_rejected():
    """Total plaintext across all frames must not exceed the design limit,
    even split across many frames each individually within chunk_size."""
    import secure_string_cipher.v2.payload as payload_module

    header = get_test_header(chunk_size=65536)
    dek = os.urandom(32)
    stream = io.BytesIO()

    writer = FrameWriter(header, dek, stream)
    writer.write_frame(b"A" * 65536, is_final=False)
    writer.write_frame(b"B" * 65536, is_final=False)
    writer.write_frame(b"C" * 1, is_final=True)
    stream.seek(0)

    reader = FrameReader(header, dek, stream)
    # Cap the byte budget below what the first frame alone already carries,
    # while leaving max_frames generous so only the byte check can trigger.
    reader.max_frames = 1000
    original_max = payload_module.MAX_PLAINTEXT_FILE_SIZE
    payload_module.MAX_PLAINTEXT_FILE_SIZE = 100
    try:
        with pytest.raises(ValueError, match="Cumulative plaintext"):
            list(reader.read_frames())
    finally:
        payload_module.MAX_PLAINTEXT_FILE_SIZE = original_max
