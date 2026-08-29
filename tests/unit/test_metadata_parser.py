"""Strict legacy metadata and SSCV2 framing regression tests."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from secure_string_cipher.config import (
    FILENAME_MAX_LENGTH,
    MAX_METADATA_LENGTH,
    METADATA_MAGIC,
    NONCE_SIZE,
    SALT_SIZE,
    TAG_SIZE,
)
from secure_string_cipher.core import (
    CryptoError,
    FileMetadata,
    _MetadataValidationError,
    decrypt_file,
)

FIXTURE_DIRECTORY = Path(__file__).parents[1] / "fixtures" / "legacy"
MANIFEST: dict[str, Any] = json.loads(
    (FIXTURE_DIRECTORY / "manifest.json").read_text(encoding="utf-8")
)
PUBLIC_FIXTURE_CREDENTIAL: str = MANIFEST["public_test_credential"]
COMMITMENT = base64.b64encode(b"k" * 32).decode("ascii")


def _metadata_bytes(
    *,
    version: object = 5,
    filename: object = "safe-name.bin",
    commitment: object = COMMITMENT,
) -> bytes:
    data = {
        "version": version,
        "original_filename": filename,
        "key_commitment": commitment,
    }
    return json.dumps(data, separators=(",", ":")).encode("utf-8")


def _assert_category(data: bytes, category: str) -> None:
    with pytest.raises(
        _MetadataValidationError, match="^Invalid metadata format$"
    ) as caught:
        FileMetadata.from_bytes(data)
    assert caught.value.category == category


@pytest.mark.parametrize("version", [4, 5])
@pytest.mark.parametrize("filename", [None, "safe-name.bin", "日本語.bin"])
def test_supported_schema_is_typed(version: int, filename: str | None) -> None:
    metadata = FileMetadata.from_bytes(
        _metadata_bytes(version=version, filename=filename)
    )

    assert metadata == FileMetadata(
        version=version,
        original_filename=filename,
        key_commitment=COMMITMENT,
    )


@pytest.mark.parametrize("value", [b"[]", b"null", b"true", b"4", b'"text"'])
def test_non_object_json_is_rejected(value: bytes) -> None:
    _assert_category(value, "non_object")


def test_invalid_utf8_is_rejected() -> None:
    _assert_category(b'{"version":5,"bad":"\xff"}', "invalid_utf8")


@pytest.mark.parametrize("key", ["version", "original_filename", "key_commitment"])
def test_duplicate_keys_are_rejected(key: str) -> None:
    values = {
        "version": "5",
        "original_filename": '"safe.bin"',
        "key_commitment": json.dumps(COMMITMENT),
    }
    duplicate = (
        "{"
        f'"version":5,"original_filename":"safe.bin",'
        f'"key_commitment":{json.dumps(COMMITMENT)},'
        f'"{key}":{values[key]}'
        "}"
    ).encode()

    with pytest.raises(_MetadataValidationError) as caught:
        FileMetadata.from_bytes(duplicate)
    assert caught.value.category == "duplicate_key"
    assert caught.value.detail == key


@pytest.mark.parametrize("version", [True, False, 5.0, "5", None])
def test_wrong_version_types_are_rejected(version: object) -> None:
    _assert_category(_metadata_bytes(version=version), "invalid_version_type")


@pytest.mark.parametrize("version", [-1, 0, 3, 6, 99])
def test_unsupported_versions_are_rejected(version: int) -> None:
    _assert_category(_metadata_bytes(version=version), "unsupported_version")


def test_missing_version_is_rejected() -> None:
    data = json.dumps(
        {"original_filename": "safe.bin", "key_commitment": COMMITMENT}
    ).encode()
    _assert_category(data, "missing_version")


@pytest.mark.parametrize("version", [4, 5])
def test_missing_required_commitment_is_rejected(version: int) -> None:
    data = json.dumps({"version": version, "original_filename": "safe.bin"}).encode()
    _assert_category(data, "missing_key_commitment")


def test_unknown_field_is_rejected_with_category_detail() -> None:
    data = json.loads(_metadata_bytes())
    data["future"] = "value"

    with pytest.raises(_MetadataValidationError) as caught:
        FileMetadata.from_bytes(json.dumps(data).encode())
    assert str(caught.value) == "Invalid metadata format"
    assert caught.value.category == "unknown_field"
    assert caught.value.detail == "future"


@pytest.mark.parametrize("filename", [1, True, [], {}])
def test_wrong_filename_types_are_rejected(filename: object) -> None:
    _assert_category(_metadata_bytes(filename=filename), "invalid_filename_type")


def test_overlong_filename_is_rejected() -> None:
    _assert_category(
        _metadata_bytes(filename="a" * (FILENAME_MAX_LENGTH + 1)),
        "filename_too_long",
    )


@pytest.mark.parametrize(
    "filename",
    [
        ".",
        "..",
        "../victim",
        "subdir/victim",
        "/absolute/path",
        "..\\victim",
        "subdir\\victim",
        "C:\\absolute\\path",
        "C:relative-drive-path",
        "name\x00.bin",
        "name\u202e.bin",
    ],
)
def test_unsafe_filename_forms_are_rejected(filename: str) -> None:
    _assert_category(_metadata_bytes(filename=filename), "unsafe_filename")


@pytest.mark.parametrize("commitment", [None, 1, True, [], {}])
def test_wrong_commitment_types_are_rejected(commitment: object) -> None:
    _assert_category(
        _metadata_bytes(commitment=commitment), "invalid_key_commitment_type"
    )


@pytest.mark.parametrize(
    "commitment",
    ["%%%%", f"{COMMITMENT}#", f"{COMMITMENT}\n", f" {COMMITMENT}"],
)
def test_non_strict_base64_is_rejected(commitment: str) -> None:
    _assert_category(
        _metadata_bytes(commitment=commitment), "invalid_key_commitment_base64"
    )


@pytest.mark.parametrize("decoded_length", [0, 1, 31, 33, 64])
def test_wrong_commitment_lengths_are_rejected(decoded_length: int) -> None:
    commitment = base64.b64encode(b"k" * decoded_length).decode("ascii")
    _assert_category(
        _metadata_bytes(commitment=commitment), "invalid_key_commitment_length"
    )


def test_oversized_metadata_is_rejected_before_json_parsing() -> None:
    _assert_category(b"{" * (MAX_METADATA_LENGTH + 1), "oversized")


def test_writer_serialization_bytes_remain_locked() -> None:
    metadata = FileMetadata(
        version=5,
        original_filename="controlled.bin",
        key_commitment=COMMITMENT,
    )

    assert metadata.to_bytes() == (
        b'{"version":5,"original_filename":"controlled.bin",'
        b'"key_commitment":"' + COMMITMENT.encode("ascii") + b'"}'
    )


def _v5_fixture() -> bytes:
    return (FIXTURE_DIRECTORY / "file-v5.ssc").read_bytes()


def _framing_offsets(data: bytes) -> tuple[int, int, int]:
    metadata_start = len(METADATA_MAGIC) + 2
    metadata_length = int.from_bytes(data[len(METADATA_MAGIC) : metadata_start], "big")
    metadata_end = metadata_start + metadata_length
    ciphertext_start = metadata_end + SALT_SIZE + NONCE_SIZE
    return metadata_start, metadata_end, ciphertext_start


def _framing_mutations() -> list[Any]:
    data = _v5_fixture()
    metadata_start, metadata_end, ciphertext_start = _framing_offsets(data)
    corrupted = bytearray(data)
    corrupted[ciphertext_start] ^= 1
    impossible_length = bytearray(data)
    impossible_length[len(METADATA_MAGIC) : metadata_start] = (
        MAX_METADATA_LENGTH.to_bytes(2, "big")
    )
    mutations = [
        ("truncated metadata length", data[: len(METADATA_MAGIC) + 1]),
        ("truncated metadata", data[: metadata_end - 1]),
        ("impossible metadata length", bytes(impossible_length)),
        ("truncated salt", data[: metadata_end + SALT_SIZE - 1]),
        ("truncated nonce", data[: ciphertext_start - 1]),
        ("truncated ciphertext", data[:ciphertext_start] + data[-TAG_SIZE:]),
        ("truncated tag", data[:-1]),
        ("corrupt ciphertext", bytes(corrupted)),
        ("prohibited trailing byte", data + b"\x00"),
    ]
    return [pytest.param(case, damaged, id=case) for case, damaged in mutations]


@pytest.mark.parametrize(("case", "damaged"), _framing_mutations())
def test_malformed_framing_fails_without_replacing_destination(
    tmp_path: Path, case: str, damaged: bytes
) -> None:
    encrypted = tmp_path / f"{case.replace(' ', '-')}.ssc"
    encrypted.write_bytes(damaged)
    destination = tmp_path / "existing.bin"
    destination.write_bytes(b"preserve me")

    with pytest.raises(CryptoError):
        decrypt_file(
            str(encrypted),
            str(destination),
            PUBLIC_FIXTURE_CREDENTIAL,
            overwrite=True,
        )

    assert destination.read_bytes() == b"preserve me"
    assert list(tmp_path.glob(".existing.bin.*.tmp")) == []


def test_authentic_fixture_hashes_are_unchanged() -> None:
    for fixture in MANIFEST["fixtures"]:
        path = FIXTURE_DIRECTORY / fixture["filename"]
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert f"sha256:{digest}" == fixture["ciphertext_sha256"]
