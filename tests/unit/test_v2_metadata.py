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

    # The character-count check this replaced was dead code: UTF-8 encodes
    # at most 4 bytes per code point, so 255 chars can never exceed the
    # 1020-byte limit below it, and the check rejected legitimate short
    # multi-byte filenames for no protective reason (see test below).
    with pytest.raises(ValueError, match="original_filename exceeds 1020 bytes"):
        encrypt_metadata(
            header, dek, original_filename="\U0001f600" * 256
        )  # 1024 bytes

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


def _forge_metadata_ciphertext(
    header: V2Header, dek: bytes, plaintext: bytes
) -> V2Header:
    """Produce a header whose metadata AEAD authenticates but whose plaintext
    is whatever the caller chooses -- exactly the situation the guards after
    `aead.decrypt()` in `decrypt_metadata` exist to handle: the attacker held
    the key (or a bug produced malformed plaintext), so authentication alone
    is not a safety property here. Uses the same key/nonce/AAD derivation
    `encrypt_metadata` does, but bypasses its plaintext construction so the
    forged bytes need not be valid canonical JSON at all.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from secure_string_cipher.v2.kdf import derive_metadata_key
    from secure_string_cipher.v2.vault_schema import b64url_decode

    metadata_block = header.metadata
    kdf_salt = metadata_block["kdf"]["salt"]  # type: ignore[index]
    nonce = b64url_decode(metadata_block["nonce"], expected_length=12)  # type: ignore[arg-type]
    k_metadata = derive_metadata_key(dek, b64url_decode(kdf_salt, expected_length=32))
    aad = get_metadata_aad(header)

    full_ciphertext = AESGCM(k_metadata).encrypt(nonce, plaintext, aad)
    return get_test_header(
        metadata_overrides={
            "ciphertext": b64url_encode(full_ciphertext[:-16]),
            "tag": b64url_encode(full_ciphertext[-16:]),
        }
    )


class TestPostAuthenticationGuards:
    """`v2/metadata.py` was 80.65% covered, and every missing line was a
    validation `raise` -- specifically the checks that run *after* the
    metadata AEAD has already authenticated. That is precisely the
    hardening layer for a decrypted-but-hostile blob: the case where the
    attacker held the key, or a bug produced malformed plaintext. None of
    it was exercised. Each guard here is proven both to reject its forged
    input and, by removing the guard, to actually be load-bearing.
    """

    def test_rejects_plaintext_over_the_4096_byte_limit(self) -> None:
        header = get_test_header()
        dek = os.urandom(32)
        # Not valid JSON at all -- the length check runs before json.loads,
        # so it must not require valid JSON to reach it.
        forged = _forge_metadata_ciphertext(header, dek, os.urandom(4097))

        with pytest.raises(ValueError, match="exceeds 4096 bytes limit"):
            decrypt_metadata(forged, dek)

    def test_rejects_plaintext_that_is_not_valid_utf8(self) -> None:
        header = get_test_header()
        dek = os.urandom(32)
        # A lone continuation byte: never valid UTF-8, well under 4096 bytes.
        forged = _forge_metadata_ciphertext(header, dek, b"\xff\xfe\xfd")

        with pytest.raises(ValueError, match="not valid UTF-8"):
            decrypt_metadata(forged, dek)

    def test_rejects_plaintext_that_is_valid_utf8_but_not_json(self) -> None:
        header = get_test_header()
        dek = os.urandom(32)
        forged = _forge_metadata_ciphertext(header, dek, b"not json at all {")

        with pytest.raises(ValueError, match="not valid JSON"):
            decrypt_metadata(forged, dek)

    def test_rejects_valid_json_that_is_not_an_object(self) -> None:
        header = get_test_header()
        dek = os.urandom(32)
        for payload in (b"[1, 2, 3]", b"42", b'"just a string"', b"null"):
            forged = _forge_metadata_ciphertext(header, dek, payload)
            with pytest.raises(ValueError, match="must be a JSON object"):
                decrypt_metadata(forged, dek)

    def test_rejects_unknown_metadata_policy(self) -> None:
        """Neither 'hidden' nor 'encrypted' -- a header field an attacker
        (or a future format version this build doesn't understand) could
        set to anything."""
        header = get_test_header(
            policy="hidden", metadata_overrides={"policy": "bogus"}
        )
        with pytest.raises(ValueError, match="Unknown metadata policy"):
            decrypt_metadata(header, os.urandom(32))

    @pytest.mark.parametrize(
        ("overrides", "match"),
        [
            ({"kdf": None}, "kdf block missing or invalid"),
            ({"kdf": {"alg": "hkdf-sha256"}}, "kdf salt missing or invalid"),
            ({"nonce": None}, "nonce missing or invalid"),
            ({"ciphertext": None}, "ciphertext missing or invalid"),
            (
                {"ciphertext": b64url_encode(b"x"), "tag": None},
                "tag missing or invalid",
            ),
        ],
    )
    def test_decrypt_rejects_malformed_field_shapes(self, overrides, match) -> None:
        """These run before the AEAD is ever touched: a header this
        malformed cannot be authenticated at all, so it must be rejected on
        shape alone rather than reaching `aead.decrypt()`."""
        header = get_test_header(metadata_overrides=overrides)
        with pytest.raises((TypeError, ValueError), match=match):
            decrypt_metadata(header, os.urandom(32))

    @pytest.mark.parametrize(
        ("overrides", "match"),
        [
            ({"kdf": None}, "kdf block missing or invalid"),
            ({"kdf": {"alg": "hkdf-sha256"}}, "kdf salt missing or invalid"),
            ({"nonce": None}, "nonce missing or invalid"),
        ],
    )
    def test_encrypt_rejects_malformed_field_shapes(self, overrides, match) -> None:
        header = get_test_header(metadata_overrides=overrides)
        with pytest.raises((TypeError, ValueError), match=match):
            encrypt_metadata(header, os.urandom(32), original_filename="x.txt")

    def test_a_cjk_filename_well_under_the_byte_limit_is_now_accepted(self) -> None:
        """Regression test for the bug the byte-limit fix above corrects:
        300 three-byte characters is 900 bytes -- comfortably inside the
        1020-byte budget -- but was previously rejected outright by the
        now-removed 255-*character* check, which had no byte-safety
        rationale behind it."""
        header = get_test_header()
        dek = os.urandom(32)
        filename = "中" * 300  # a CJK character, 3 bytes in UTF-8
        assert len(filename.encode("utf-8")) == 900

        ciphertext, tag = encrypt_metadata(header, dek, original_filename=filename)
        forged = get_test_header(
            metadata_overrides={
                "ciphertext": b64url_encode(ciphertext),
                "tag": b64url_encode(tag),
            }
        )
        assert decrypt_metadata(forged, dek)["original_filename"] == filename
