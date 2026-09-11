import base64
import os

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
from secure_string_cipher.v2.message import (
    decrypt_message,
    encrypt_message,
    unarmor_message,
)
from secure_string_cipher.v2.vault_schema import b64url_encode


def make_test_header(plaintext_length: int) -> V2Header:
    payload = PayloadDescriptor(
        type=PayloadType.TEXT,
        alg="aes-256-gcm",
        kdf={"alg": "hkdf-sha256", "salt": b64url_encode(os.urandom(32))},
        metadata_policy=MetadataPolicy.HIDDEN,
        nonce=b64url_encode(os.urandom(12)),
        plaintext_length=plaintext_length,
    )
    access = AccessBlock(
        version=1,
        policy=AccessPolicy.SINGLE_GRANT,
        grants=[
            AccessGrant(
                grant_id="test",
                type=GrantType.PASSWORD,
                kek_derivation={
                    "alg": "hkdf-sha256",
                    "salt": b64url_encode(os.urandom(32)),
                },
                wrap_alg="aes-256-gcm",
                wrap_nonce=b64url_encode(os.urandom(12)),
                wrapped_dek=b64url_encode(os.urandom(32)),
                tag=b64url_encode(os.urandom(16)),
                commitment=None,
                key_fingerprint=None,
                password_kdf={
                    "alg": "argon2id",
                    "salt": b64url_encode(os.urandom(16)),
                    "iterations": 1,
                    "memory": 1024,
                    "parallelism": 1,
                },
                combined_kdf=None,
            )
        ],
    )
    return V2Header(
        format="SSC2",
        version=2,
        object_id=b64url_encode(os.urandom(16)),
        object_type="text",
        payload=payload,
        metadata={},
        access=access,
    )


def test_message_encrypt_decrypt_empty() -> None:
    dek = os.urandom(32)
    header = make_test_header(0)

    armored = encrypt_message(header, dek, "")
    assert "-----BEGIN SSC MESSAGE-----" in armored

    decrypted = decrypt_message(header, dek, armored)
    assert decrypted == ""


def test_message_encrypt_decrypt_normal() -> None:
    dek = os.urandom(32)
    plaintext = "Hello, world! 🌍"
    pt_bytes = plaintext.encode("utf-8")
    header = make_test_header(len(pt_bytes))

    armored = encrypt_message(header, dek, plaintext)
    decrypted = decrypt_message(header, dek, armored)
    assert decrypted == plaintext


def test_invalid_utf8_plaintext() -> None:
    dek = os.urandom(32)
    header = make_test_header(5)
    # Using surrogates which fail strict utf-8 encoding
    with pytest.raises(ValueError, match="not valid UTF-8"):
        encrypt_message(header, dek, "Hello\ud800")


def test_malformed_armor_mixed_line_endings() -> None:
    dek = os.urandom(32)
    header = make_test_header(5)
    armored = encrypt_message(header, dek, "hello")
    # inject mixed line endings
    armored_mixed = armored.replace("\n", "\r\n", 2)

    with pytest.raises(ValueError, match="Mixed line endings"):
        unarmor_message(armored_mixed)


def test_malformed_armor_trailing_spaces() -> None:
    dek = os.urandom(32)
    header = make_test_header(5)
    armored = encrypt_message(header, dek, "hello")

    armored_bad = armored.replace(
        "-----BEGIN SSC MESSAGE-----", "-----BEGIN SSC MESSAGE----- "
    )
    with pytest.raises(ValueError, match="invalid begin marker"):
        unarmor_message(armored_bad)


def test_malformed_armor_missing_empty_line() -> None:
    dek = os.urandom(32)
    header = make_test_header(5)
    armored = encrypt_message(header, dek, "hello")
    lines = armored.splitlines()
    # lines[4] is the empty line
    lines.pop(4)
    armored_bad = "\n".join(lines)
    with pytest.raises(ValueError, match="too few lines"):
        unarmor_message(armored_bad)


def test_malformed_armor_extra_lines() -> None:
    dek = os.urandom(32)
    header = make_test_header(5)
    armored = encrypt_message(header, dek, "hello")
    lines = armored.splitlines()
    if lines[-1] == "":
        lines.pop()
    lines.append("Extra line")
    armored_bad = "\n".join(lines)
    with pytest.raises(ValueError, match="invalid end marker"):
        unarmor_message(armored_bad)


def test_altered_ciphertext() -> None:
    dek = os.urandom(32)
    plaintext = "Hello, world!"
    header = make_test_header(len(plaintext))

    armored = encrypt_message(header, dek, plaintext)
    parsed = unarmor_message(armored)

    # Flip a bit in the body
    body_bytes = bytearray(base64.b64decode(parsed.body_b64))
    body_bytes[0] ^= 1
    new_body = base64.b64encode(body_bytes).decode("ascii")

    bad_armored = armored.replace(parsed.body_b64, new_body)

    with pytest.raises(ValueError, match="Message authentication failed"):
        decrypt_message(header, dek, bad_armored)


def test_altered_aad_length() -> None:
    dek = os.urandom(32)
    plaintext = "Hello, world!"
    header = make_test_header(len(plaintext))

    armored = encrypt_message(header, dek, plaintext)

    # Change plaintext length in header for decryption
    assert header.payload.plaintext_length is not None
    bad_payload = PayloadDescriptor(
        type=header.payload.type,
        alg=header.payload.alg,
        kdf=header.payload.kdf,
        metadata_policy=header.payload.metadata_policy,
        nonce=header.payload.nonce,
        plaintext_length=header.payload.plaintext_length + 1,
    )
    bad_header = V2Header(
        format="SSC2",
        version=header.version,
        object_id=header.object_id,
        object_type="text",
        payload=bad_payload,
        metadata=header.metadata,
        access=header.access,
    )

    with pytest.raises(ValueError, match="Message authentication failed"):
        decrypt_message(bad_header, dek, armored)


def test_wrong_payload_type() -> None:
    header = make_test_header(5)
    bad_payload = PayloadDescriptor(
        type=PayloadType.FILE,
        alg=header.payload.alg,
        kdf=header.payload.kdf,
        metadata_policy=header.payload.metadata_policy,
        chunk_size=131072,
    )
    bad_header = V2Header(
        format="SSC2",
        version=header.version,
        object_id=header.object_id,
        object_type="file",
        payload=bad_payload,
        metadata=header.metadata,
        access=header.access,
    )

    with pytest.raises(ValueError, match="only for TEXT payload type"):
        encrypt_message(bad_header, os.urandom(32), "hello")


def test_decrypt_invalid_b64() -> None:
    dek = os.urandom(32)
    header = make_test_header(5)
    armored = encrypt_message(header, dek, "hello")
    parsed = unarmor_message(armored)

    bad_body = parsed.body_b64 + "!"
    bad_armored = armored.replace(parsed.body_b64, bad_body)

    with pytest.raises(ValueError, match="Invalid Base64 in message body"):
        decrypt_message(header, dek, bad_armored)
