"""Golden compatibility tests for authentic released v4 and v5 files."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from secure_string_cipher.core import decrypt_file
from secure_string_cipher.utils import CryptoError

FIXTURE_DIRECTORY = Path(__file__).parents[1] / "fixtures" / "legacy"
MANIFEST: dict[str, Any] = json.loads(
    (FIXTURE_DIRECTORY / "manifest.json").read_text(encoding="utf-8")
)
PAYLOAD = (FIXTURE_DIRECTORY / MANIFEST["payload"]["filename"]).read_bytes()
PUBLIC_FIXTURE_CREDENTIAL: str = MANIFEST["public_test_credential"]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("fixture", MANIFEST["fixtures"])
def test_authentic_fixture_decrypts_without_rewriting(
    tmp_path: Path, fixture: dict[str, Any]
) -> None:
    encrypted = FIXTURE_DIRECTORY / fixture["filename"]
    output = tmp_path / "payload.out"
    before_hash = _sha256(encrypted)

    actual_path, metadata = decrypt_file(
        str(encrypted), str(output), PUBLIC_FIXTURE_CREDENTIAL
    )

    assert actual_path == str(output)
    assert output.read_bytes() == PAYLOAD
    assert f"sha256:{_sha256(output)}" == MANIFEST["payload"]["sha256"]
    assert metadata is not None
    assert metadata.version == fixture["metadata_version"]
    assert encrypted.stat().st_size == fixture["ciphertext_byte_length"]
    assert f"sha256:{before_hash}" == fixture["ciphertext_sha256"]
    assert _sha256(encrypted) == before_hash


def test_v4_automatic_output_distrusts_stored_filename(tmp_path: Path) -> None:
    source = FIXTURE_DIRECTORY / "file-v4.ssc"
    encrypted = tmp_path / "copied-v4.ssc"
    shutil.copyfile(source, encrypted)

    actual_path, metadata = decrypt_file(
        str(encrypted), None, PUBLIC_FIXTURE_CREDENTIAL
    )

    expected = Path(f"{encrypted}.dec")
    assert actual_path == str(expected)
    assert expected.read_bytes() == PAYLOAD
    assert not (tmp_path / "legacy-fixture.bin").exists()
    assert metadata is not None
    assert metadata.version == 4


def test_v5_automatic_output_uses_authenticated_filename(tmp_path: Path) -> None:
    source = FIXTURE_DIRECTORY / "file-v5.ssc"
    encrypted = tmp_path / "copied-v5.ssc"
    shutil.copyfile(source, encrypted)

    actual_path, metadata = decrypt_file(
        str(encrypted), None, PUBLIC_FIXTURE_CREDENTIAL
    )

    expected = tmp_path / "legacy-fixture.bin"
    assert actual_path == str(expected)
    assert expected.read_bytes() == PAYLOAD
    assert metadata is not None
    assert metadata.version == 5


@pytest.mark.parametrize("fixture", MANIFEST["fixtures"])
def test_wrong_password_preserves_destination(
    tmp_path: Path, fixture: dict[str, Any]
) -> None:
    encrypted = FIXTURE_DIRECTORY / fixture["filename"]
    output = tmp_path / "existing.out"
    output.write_bytes(b"existing destination")

    with pytest.raises(CryptoError):
        decrypt_file(
            str(encrypted),
            str(output),
            "Wrong-Fixture-Password-2026!",
            overwrite=True,
        )

    assert output.read_bytes() == b"existing destination"
    assert list(tmp_path.glob(".existing.out.*.tmp")) == []


@pytest.mark.parametrize("fixture", MANIFEST["fixtures"])
def test_one_bit_corruption_preserves_destination(
    tmp_path: Path, fixture: dict[str, Any]
) -> None:
    damaged = bytearray((FIXTURE_DIRECTORY / fixture["filename"]).read_bytes())
    damaged[-1] ^= 1
    encrypted = tmp_path / fixture["filename"]
    encrypted.write_bytes(damaged)
    output = tmp_path / "existing.out"
    output.write_bytes(b"existing destination")

    with pytest.raises(CryptoError):
        decrypt_file(
            str(encrypted),
            str(output),
            PUBLIC_FIXTURE_CREDENTIAL,
            overwrite=True,
        )

    assert output.read_bytes() == b"existing destination"
    assert list(tmp_path.glob(".existing.out.*.tmp")) == []


def test_fixture_hashes_match_manifest() -> None:
    assert len(PAYLOAD) == MANIFEST["payload"]["byte_length"]
    assert len(PAYLOAD) > 4 * MANIFEST["payload"]["historical_chunk_size_bytes"]
    assert (
        f"sha256:{_sha256(FIXTURE_DIRECTORY / 'payload.bin')}"
        == MANIFEST["payload"]["sha256"]
    )
    for fixture in MANIFEST["fixtures"]:
        encrypted = FIXTURE_DIRECTORY / fixture["filename"]
        assert encrypted.stat().st_size == fixture["ciphertext_byte_length"]
        assert f"sha256:{_sha256(encrypted)}" == fixture["ciphertext_sha256"]
