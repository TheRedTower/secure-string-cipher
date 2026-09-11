import io
import json
from pathlib import Path
from typing import Any

import pytest

from secure_string_cipher.v2.envelope import (
    AccessPolicy,
    GrantType,
    MetadataPolicy,
    PayloadType,
)
from secure_string_cipher.v2.header_parser import (
    _validate_argon2id,
    _validate_hkdf_sha256,
    parse_header_stream,
    validate_v2_header,
)
from secure_string_cipher.v2.vault_schema import b64url_encode

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "v2"
MANIFEST_PATH = FIXTURES_DIR / "manifest.json"


@pytest.fixture(scope="session")
def golden_manifest() -> dict[str, Any]:
    if not MANIFEST_PATH.exists():
        pytest.skip(
            "Golden vectors manifest not found. Run tools/generate_v2_vectors.py first."
        )
    data = json.loads(MANIFEST_PATH.read_text("utf-8"))
    assert isinstance(data, dict)
    return data


def _create_stream(header_json: dict[str, Any]) -> io.BytesIO:
    # From envelope.canonical_json, but we can just use the provided complete_header
    # Wait, the manifest includes 'complete_header' dict, we need to turn it into canonical JSON
    # to form the wire stream. But actually we should just encode it using canonical_json
    from secure_string_cipher.v2.envelope import canonical_json

    raw_bytes = canonical_json(header_json)

    stream = io.BytesIO()
    stream.write(b"SSC2")
    stream.write(len(raw_bytes).to_bytes(4, "little"))
    stream.write(raw_bytes)
    stream.seek(0)
    return stream


def test_parse_password_grant_header(golden_manifest) -> None:
    header_dict = golden_manifest["grants"]["password"]["complete_header"]
    stream = _create_stream(header_dict)

    header, raw_bytes = parse_header_stream(stream)

    assert header.format == "SSC2"
    assert header.version == 2
    assert header.object_type == "text"
    assert header.payload.type == PayloadType.TEXT
    assert header.payload.alg == "aes-256-gcm"
    assert header.payload.metadata_policy == MetadataPolicy.HIDDEN
    assert header.access.policy == AccessPolicy.SINGLE_GRANT

    assert len(header.access.grants) == 1
    grant = header.access.grants[0]
    assert grant.type == GrantType.PASSWORD
    assert grant.password_kdf is not None
    assert grant.password_kdf["alg"] == "argon2id"
    assert grant.commitment is not None


def test_parse_managed_key_grant_header(golden_manifest) -> None:
    header_dict = golden_manifest["grants"]["managed_key"]["complete_header"]
    stream = _create_stream(header_dict)

    header, raw_bytes = parse_header_stream(stream)

    assert header.format == "SSC2"

    grant = header.access.grants[0]
    assert grant.type == GrantType.MANAGED_KEY
    assert grant.key_fingerprint is not None
    assert grant.commitment is not None


def test_parse_combined_grant_header(golden_manifest) -> None:
    header_dict = golden_manifest["grants"]["combined"]["complete_header"]
    stream = _create_stream(header_dict)

    header, raw_bytes = parse_header_stream(stream)

    assert header.format == "SSC2"

    grant = header.access.grants[0]
    assert grant.type == GrantType.COMBINED_PASSWORD_MANAGED_KEY
    assert grant.password_kdf is not None
    assert grant.combined_kdf is not None
    assert grant.key_fingerprint is not None
    assert grant.commitment is not None


def test_validate_rejects_managed_key_grant_missing_fingerprint(
    golden_manifest,
) -> None:
    header_dict = json.loads(
        json.dumps(golden_manifest["grants"]["managed_key"]["complete_header"])
    )
    del header_dict["access"]["grants"][0]["key_fingerprint"]
    with pytest.raises(ValueError, match="key_fingerprint"):
        validate_v2_header(header_dict)


def test_validate_rejects_managed_key_grant_null_fingerprint(golden_manifest) -> None:
    header_dict = json.loads(
        json.dumps(golden_manifest["grants"]["managed_key"]["complete_header"])
    )
    header_dict["access"]["grants"][0]["key_fingerprint"] = None
    with pytest.raises(ValueError, match="key_fingerprint"):
        validate_v2_header(header_dict)


def test_validate_rejects_managed_key_grant_malformed_fingerprint(
    golden_manifest,
) -> None:
    header_dict = json.loads(
        json.dumps(golden_manifest["grants"]["managed_key"]["complete_header"])
    )
    header_dict["access"]["grants"][0]["key_fingerprint"] = "not-a-real-fingerprint"
    with pytest.raises(ValueError, match="key_fingerprint"):
        validate_v2_header(header_dict)


def test_validate_rejects_combined_grant_missing_fingerprint(golden_manifest) -> None:
    header_dict = json.loads(
        json.dumps(golden_manifest["grants"]["combined"]["complete_header"])
    )
    del header_dict["access"]["grants"][0]["key_fingerprint"]
    with pytest.raises(ValueError, match="key_fingerprint"):
        validate_v2_header(header_dict)


def test_parse_stream_rejects_empty():
    stream = io.BytesIO(b"")
    with pytest.raises(EOFError):
        parse_header_stream(stream)


def test_parse_stream_rejects_legacy_v2_preview():
    stream = io.BytesIO(b"SSCV2")
    with pytest.raises(ValueError, match="legacy V2 preview"):
        parse_header_stream(stream)


def test_parse_stream_rejects_bad_magic():
    stream = io.BytesIO(b"BAD1\x00\x00\x00\x05{}")
    with pytest.raises(ValueError, match="Invalid magic"):
        parse_header_stream(stream)


def test_parse_stream_rejects_truncated_length():
    stream = io.BytesIO(b"SSC2\x00\x00\x01")
    with pytest.raises(ValueError, match="Truncated header length"):
        parse_header_stream(stream)


def test_parse_stream_rejects_out_of_bounds_length():
    stream = io.BytesIO(b"SSC2\x01\x00\x01\x00" + b"A" * 65537)
    with pytest.raises(ValueError, match="Header length out of bounds"):
        parse_header_stream(stream)

    stream = io.BytesIO(b"SSC2\x00\x00\x00\x00")
    with pytest.raises(ValueError, match="Header length out of bounds"):
        parse_header_stream(stream)


def test_parse_stream_rejects_truncated_json():
    stream = io.BytesIO(b"SSC2\x05\x00\x00\x00{}")
    with pytest.raises(ValueError, match="Truncated header JSON"):
        parse_header_stream(stream)


def test_validate_rejects_unknown_top_level(golden_manifest) -> None:
    header_dict = dict(golden_manifest["grants"]["password"]["complete_header"])
    header_dict["unknown_field"] = "value"
    with pytest.raises(ValueError, match="Unexpected keys in header"):
        validate_v2_header(header_dict)


def test_validate_rejects_wrong_format(golden_manifest) -> None:
    header_dict = dict(golden_manifest["grants"]["password"]["complete_header"])
    header_dict["format"] = "BAD"
    with pytest.raises(ValueError, match="Header format must be"):
        validate_v2_header(header_dict)


def test_validate_rejects_wrong_version(golden_manifest) -> None:
    header_dict = dict(golden_manifest["grants"]["password"]["complete_header"])
    header_dict["version"] = 3
    with pytest.raises(ValueError, match="Header version must be 2"):
        validate_v2_header(header_dict)


def test_validate_rejects_mismatched_payload_type(golden_manifest) -> None:
    header_dict = dict(golden_manifest["grants"]["password"]["complete_header"])
    header_dict["object_type"] = "file"
    with pytest.raises(ValueError, match="does not match payload type"):
        validate_v2_header(header_dict)


def test_validate_rejects_bad_b64url(golden_manifest) -> None:
    header_dict = dict(golden_manifest["grants"]["password"]["complete_header"])
    header_dict["object_id"] = "invalid_b64!"
    with pytest.raises(ValueError):
        validate_v2_header(header_dict)


def test_validate_rejects_duplicate_keys():
    # json.loads with _reject_duplicate_object_hook should catch this
    dup_json = b'SSC2\x10\x00\x00\x00{"a": 1, "a": 2}'
    stream = io.BytesIO(dup_json)
    with pytest.raises(ValueError, match="Duplicate key in JSON"):
        parse_header_stream(stream)


# --- Negative-path tests for the pure KDF parameter validators ---
# These pin the spec-conformance constants (Argon2id v19/64MiB/3/4/32 and
# HKDF-SHA256 with 32-byte salt) against single-field mutations.


def _valid_hkdf_block() -> dict[str, Any]:
    return {"alg": "hkdf-sha256", "salt": b64url_encode(b"\xa5" * 32)}


def _valid_argon2id_block() -> dict[str, Any]:
    return {
        "alg": "argon2id",
        "version": 19,
        "memory_kib": 65536,
        "time_cost": 3,
        "parallelism": 4,
        "hash_len": 32,
        "salt": b64url_encode(b"\x5a" * 16),
    }


def test_validate_hkdf_sha256_accepts_valid_block() -> None:
    assert _validate_hkdf_sha256(_valid_hkdf_block(), "kdf") is None


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param("not-a-dict", id="non_dict"),
        pytest.param({**_valid_hkdf_block(), "alg": "hkdf-sha512"}, id="wrong_alg"),
        pytest.param({**_valid_hkdf_block(), "salt": 12345}, id="salt_not_str"),
        pytest.param(
            {**_valid_hkdf_block(), "salt": b64url_encode(b"\x00" * 16)},
            id="salt_wrong_length",
        ),
        pytest.param(
            {**_valid_hkdf_block(), "salt": "!!!not-b64!!!"}, id="salt_bad_b64"
        ),
        pytest.param({**_valid_hkdf_block(), "extra_key": "x"}, id="extra_key"),
    ],
)
def test_validate_hkdf_sha256_rejects_bad_input(bad: Any) -> None:
    with pytest.raises((TypeError, ValueError)):
        _validate_hkdf_sha256(bad, "kdf")


def test_validate_argon2id_accepts_valid_block() -> None:
    assert _validate_argon2id(_valid_argon2id_block(), "kdf") is None


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(["not", "a", "dict"], id="non_dict"),
        pytest.param({**_valid_argon2id_block(), "alg": "argon2i"}, id="wrong_alg"),
        pytest.param({**_valid_argon2id_block(), "version": 20}, id="wrong_version"),
        pytest.param(
            {**_valid_argon2id_block(), "version": "19"}, id="version_not_int"
        ),
        pytest.param(
            {**_valid_argon2id_block(), "memory_kib": 32768}, id="wrong_memory_kib"
        ),
        pytest.param({**_valid_argon2id_block(), "time_cost": 2}, id="wrong_time_cost"),
        pytest.param(
            {**_valid_argon2id_block(), "parallelism": 8}, id="wrong_parallelism"
        ),
        pytest.param({**_valid_argon2id_block(), "hash_len": 16}, id="wrong_hash_len"),
        pytest.param({**_valid_argon2id_block(), "salt": 999}, id="salt_not_str"),
        pytest.param(
            {**_valid_argon2id_block(), "salt": b64url_encode(b"\x00" * 32)},
            id="salt_wrong_length",
        ),
        pytest.param({**_valid_argon2id_block(), "unexpected": True}, id="extra_key"),
    ],
)
def test_validate_argon2id_rejects_bad_input(bad: Any) -> None:
    with pytest.raises((TypeError, ValueError)):
        _validate_argon2id(bad, "kdf")


# ---------------------------------------------------------------------------
# Encrypted metadata validation (previously unvalidated beyond isinstance(dict)):
# the metadata block's own "policy" field must agree with the authenticated
# payload.metadata_policy, and an "encrypted" block must match its exact
# alg/kdf/nonce/ciphertext/tag shape the same way "hidden" is already pinned.
# ---------------------------------------------------------------------------


def _real_encrypted_metadata_header(tmp_path: Path) -> dict[str, Any]:
    """Produce a real header dict with genuine encrypted metadata by
    round-tripping through the actual encrypt orchestrator, rather than
    hand-assembling a schema that could drift from what the encoder emits."""
    from secure_string_cipher.v2.encrypt import PasswordCredential, encrypt_v2_file

    input_path = tmp_path / "plain.bin"
    input_path.write_bytes(b"hello world")
    output_path = tmp_path / "out.ssc"
    encrypt_v2_file(
        input_path=input_path,
        credential=PasswordCredential("CorrectHorseBattery1!"),
        output_path=output_path,
        store_filename=True,
    )
    raw = output_path.read_bytes()
    header_len = int.from_bytes(raw[4:8], "little")
    header_bytes = raw[8 : 8 + header_len]
    result: dict[str, Any] = json.loads(header_bytes)
    return result


def test_validate_accepts_real_encrypted_metadata(tmp_path: Path) -> None:
    """Sanity check: the real encoder's own output must still validate,
    proving the new strict shape check isn't stricter than the encoder."""
    header_dict = _real_encrypted_metadata_header(tmp_path)
    header = validate_v2_header(header_dict)
    assert header.metadata["policy"] == "encrypted"


def test_validate_rejects_metadata_policy_disagreeing_with_payload(
    tmp_path: Path,
) -> None:
    """A header claiming payload.metadata_policy == 'encrypted' must not be
    accepted with a metadata block shaped like 'hidden' (or any other
    disagreement) — decrypt logic trusts metadata.policy alone to decide
    whether to attempt decryption, so the two fields must agree structurally
    before either is trusted."""
    header_dict = _real_encrypted_metadata_header(tmp_path)
    header_dict["metadata"] = {"policy": "hidden"}
    with pytest.raises(ValueError, match="does not match payload.metadata_policy"):
        validate_v2_header(header_dict)


def test_validate_rejects_hidden_payload_policy_with_encrypted_metadata(
    golden_manifest,
) -> None:
    """The reverse disagreement: payload says hidden, metadata block claims
    encrypted — also rejected by the same cross-check."""
    header_dict = dict(golden_manifest["grants"]["password"]["complete_header"])
    assert header_dict["payload"]["metadata_policy"] == "hidden"
    header_dict["metadata"] = {
        "policy": "encrypted",
        "alg": "aes-256-gcm",
        "kdf": {"alg": "hkdf-sha256", "salt": b64url_encode(b"S" * 32)},
        "nonce": b64url_encode(b"N" * 12),
        "ciphertext": b64url_encode(b"C" * 8),
        "tag": b64url_encode(b"T" * 16),
    }
    with pytest.raises(ValueError, match="does not match payload.metadata_policy"):
        validate_v2_header(header_dict)


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda m: m.pop("ciphertext"), "ciphertext"),
        (lambda m: m.pop("tag"), "tag"),
        (lambda m: m.pop("nonce"), "nonce"),
        (lambda m: m.update(alg="aes-128-gcm"), "alg"),
        (lambda m: m.update(extra_field="unexpected"), "Unexpected keys"),
    ],
)
def test_validate_rejects_malformed_encrypted_metadata_shape(
    tmp_path: Path, mutate, match
) -> None:
    header_dict = _real_encrypted_metadata_header(tmp_path)
    mutate(header_dict["metadata"])
    with pytest.raises((TypeError, ValueError), match=match):
        validate_v2_header(header_dict)
