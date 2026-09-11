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
from secure_string_cipher.v2.metadata import (
    decrypt_metadata,
    encrypt_metadata,
    get_metadata_aad,
    sanitize_filename,
)
from secure_string_cipher.v2.vault_schema import b64url_encode


def get_test_header(
    policy: str = "encrypted", metadata_overrides: dict = None
) -> V2Header:
    metadata_block = {
        "policy": policy,
        "alg": "aes-256-gcm",
        "kdf": {"alg": "hkdf-sha256", "salt": b64url_encode(b"0" * 32)},
        "nonce": b64url_encode(b"1" * 12),
    }
    if metadata_overrides:
        metadata_block.update(metadata_overrides)

    return V2Header(
        format="SSC2",
        version=2,
        object_id="00000000-0000-0000-0000-000000000000",
        object_type="file",
        payload=PayloadDescriptor(
            type=PayloadType.FILE,
            alg="aes-256-gcm",
            kdf={"alg": "hkdf-sha256", "salt": b64url_encode(b"2" * 32)},
            metadata_policy=MetadataPolicy(policy),
            chunk_size=1048576,
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
        metadata=metadata_block,
    )


def test_encrypt_decrypt_roundtrip():
    header = get_test_header()
    dek = os.urandom(32)

    ciphertext, tag = encrypt_metadata(
        header, dek, original_filename="test.txt", original_size=1234
    )

    header_with_ct = get_test_header(
        metadata_overrides={
            "ciphertext": b64url_encode(ciphertext),
            "tag": b64url_encode(tag),
        }
    )

    plaintext_dict = decrypt_metadata(header_with_ct, dek)
    assert plaintext_dict == {"original_filename": "test.txt", "original_size": 1234}


def test_aad_omits_ciphertext_and_tag():
    header1 = get_test_header()
    header2 = get_test_header(
        metadata_overrides={
            "ciphertext": b64url_encode(b"abc"),
            "tag": b64url_encode(b"def"),
        }
    )

    assert get_metadata_aad(header1) == get_metadata_aad(header2)


def test_decrypt_hidden_policy():
    header = get_test_header(policy="hidden")
    dek = os.urandom(32)
    assert decrypt_metadata(header, dek) == {}


def test_encrypt_rejects_hidden_policy():
    header = get_test_header(policy="hidden")
    dek = os.urandom(32)
    with pytest.raises(
        ValueError, match="Cannot encrypt metadata with policy != encrypted"
    ):
        encrypt_metadata(header, dek, original_filename="test.txt")


def test_encrypt_validation_errors():
    header = get_test_header()
    dek = os.urandom(32)

    with pytest.raises(TypeError, match="original_filename must be a string"):
        encrypt_metadata(header, dek, original_filename=123)  # type: ignore

    with pytest.raises(ValueError, match="original_filename exceeds 255 characters"):
        encrypt_metadata(header, dek, original_filename="a" * 256)

    with pytest.raises(TypeError, match="original_size must be an integer"):
        encrypt_metadata(header, dek, original_size="123")  # type: ignore

    with pytest.raises(TypeError, match="original_size must be an integer"):
        encrypt_metadata(header, dek, original_size=True)

    with pytest.raises(ValueError, match="original_size is out of bounds"):
        encrypt_metadata(header, dek, original_size=-1)

    with pytest.raises(ValueError, match="original_size is out of bounds"):
        encrypt_metadata(header, dek, original_size=200000000)


def test_decrypt_authentication_failure():
    header = get_test_header()
    dek = os.urandom(32)

    ciphertext, tag = encrypt_metadata(header, dek, original_filename="test.txt")

    # Tamper with ciphertext
    tampered_ct = bytearray(ciphertext)
    tampered_ct[0] ^= 1

    header_with_ct = get_test_header(
        metadata_overrides={
            "ciphertext": b64url_encode(tampered_ct),
            "tag": b64url_encode(tag),
        }
    )

    with pytest.raises(ValueError, match="Metadata authentication failed"):
        decrypt_metadata(header_with_ct, dek)


def test_sanitize_filename_valid():
    assert sanitize_filename("hello.txt") == "hello.txt"
    assert sanitize_filename("some_long-name 123.pdf") == "some_long-name 123.pdf"


def test_sanitize_filename_invalid():
    # Path traversal
    with pytest.raises(ValueError, match="path separators"):
        sanitize_filename("dir/file.txt")
    with pytest.raises(ValueError, match="path separators"):
        sanitize_filename("dir\\file.txt")

    # Traversal components
    with pytest.raises(ValueError, match="traversal component"):
        sanitize_filename(".")
    with pytest.raises(ValueError, match="traversal component"):
        sanitize_filename("..")

    # Control characters
    with pytest.raises(ValueError, match="control characters"):
        sanitize_filename("file\x00.txt")
    with pytest.raises(ValueError, match="control characters"):
        sanitize_filename("file\n.txt")

    # Windows reserved
    with pytest.raises(ValueError, match="Windows reserved name"):
        sanitize_filename("CON.txt")
    with pytest.raises(ValueError, match="Windows reserved name"):
        sanitize_filename("prn")
    with pytest.raises(ValueError, match="Windows reserved name"):
        sanitize_filename("COM1.exe")

    # Windows drive
    with pytest.raises(ValueError, match="Windows drive path"):
        sanitize_filename("C:file.txt")
