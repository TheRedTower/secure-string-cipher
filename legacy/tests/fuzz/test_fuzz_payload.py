import base64
import io
import secrets

from hypothesis import given, settings
from hypothesis import strategies as st

from secure_string_cipher.v2.envelope import (
    AccessBlock,
    AccessGrant,
    AccessPolicy,
    CommitmentDescriptor,
    GrantType,
    MetadataPolicy,
    PayloadDescriptor,
    PayloadType,
    V2Header,
)
from secure_string_cipher.v2.message import armor_message, unarmor_message
from secure_string_cipher.v2.payload import FrameReader, FrameWriter


def _build_dummy_header() -> V2Header:
    valid_salt = (
        "0000000000000000000000000000000000000000000"  # 43 chars = 32 bytes b64url
    )
    access = AccessBlock(
        version=1,
        policy=AccessPolicy.SINGLE_GRANT,
        grants=[
            AccessGrant(
                type=GrantType.PASSWORD,
                grant_id="grant-0",
                password_kdf={
                    "alg": "argon2id",
                    "version": 19,
                    "memory_kib": 65536,
                    "time_cost": 3,
                    "parallelism": 4,
                    "hash_len": 32,
                    "salt": valid_salt,
                },
                kek_derivation={
                    "alg": "hkdf-sha256",
                    "salt": valid_salt,
                },
                wrap_alg="aes-256-gcm",
                wrap_nonce="nonce",
                wrapped_dek="wrapped",
                tag="tag",
                commitment=CommitmentDescriptor(
                    alg="hmac-sha256",
                    kdf={"alg": "hkdf-sha256", "salt": valid_salt},
                    value="commit",
                ),
            )
        ],
    )
    payload = PayloadDescriptor(
        type=PayloadType.FILE,
        alg="aes-256-gcm",
        kdf={"alg": "hkdf-sha256", "salt": valid_salt},
        metadata_policy=MetadataPolicy.HIDDEN,
        chunk_size=65536,
        nonce_prefix="MDAwMA",
    )
    return V2Header(
        format="SSC2",
        version=2,
        object_id="obj_id",
        object_type="file",
        payload=payload,
        access=access,
        metadata={"policy": "hidden"},
    )


@settings(max_examples=50, deadline=None)
@given(
    payload_data=st.binary(min_size=0, max_size=200_000),
    chunk_size=st.sampled_from([65536, 131072, 262144]),
)
def test_payload_framing_roundtrip(payload_data: bytes, chunk_size: int):
    header = _build_dummy_header()
    from dataclasses import replace

    header = replace(header, payload=replace(header.payload, chunk_size=chunk_size))
    dek = secrets.token_bytes(32)

    stream = io.BytesIO()
    writer = FrameWriter(header, dek, stream)

    # Write chunks
    for i in range(0, len(payload_data), chunk_size):
        chunk = payload_data[i : i + chunk_size]
        is_final = i + chunk_size >= len(payload_data)
        writer.write_frame(chunk, is_final=is_final)

    # Handle empty case specifically
    if not payload_data:
        writer.write_frame(b"", is_final=True)

    stream.seek(0)
    reader = FrameReader(header, dek, stream)

    reconstructed = b""
    for frame in reader.read_frames():
        reconstructed += frame

    assert reconstructed == payload_data


@settings(max_examples=50, deadline=None)
@given(
    ciphertext=st.binary(min_size=0, max_size=10_000),
    tag=st.binary(min_size=16, max_size=16),
)
def test_message_armor_roundtrip(ciphertext: bytes, tag: bytes):
    header = _build_dummy_header()
    from dataclasses import replace

    header = replace(
        header,
        object_type="text",
        payload=replace(
            header.payload,
            type=PayloadType.TEXT,
            plaintext_length=len(ciphertext),
            chunk_size=None,
            nonce_prefix=None,
        ),
    )

    armored = armor_message(header, ciphertext, tag)

    assert armored.startswith("-----BEGIN SSC MESSAGE-----")
    assert armored.endswith("-----END SSC MESSAGE-----\n")

    unarmored = unarmor_message(armored)

    # Check that body is ciphertext + tag
    decoded_body = base64.b64decode(unarmored.body_b64)
    assert decoded_body == ciphertext + tag
