"""Cross-platform filesystem safety checks for required CI runners."""

from __future__ import annotations

import argparse
import io
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from secure_string_cipher import cli_args, core
from secure_string_cipher.core import decrypt_file, encrypt_file
from secure_string_cipher.utils import CryptoError

PLATFORM_TEST_CREDENTIAL = "Platform-Test-Password-2026!"


def _assert_no_atomic_temporary_files(directory: Path) -> None:
    assert list(directory.glob(".*.tmp")) == []


def _create_symlink_or_skip(
    link: Path, target: Path, *, target_is_directory: bool = False
) -> None:
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"runner cannot create symbolic links: {error}")


def test_vault_export_bypasses_text_newline_translation() -> None:
    """Binary export must retain LF framing and omit a terminal newline."""
    raw = "SSCVAULT\nsalt\n---DATA---\ntoken\n---HMAC---\ndigest"
    backing = io.BytesIO()
    translated_stdout = io.TextIOWrapper(backing, encoding="utf-8", newline="\r\n")
    vault = MagicMock()
    vault.list_labels.return_value = ["label"]
    vault.read_raw_vault.return_value = raw

    try:
        with (
            patch("secure_string_cipher.cli_args._get_vault", return_value=vault),
            patch(
                "secure_string_cipher.cli_args._prompt_master_password",
                return_value=PLATFORM_TEST_CREDENTIAL,
            ),
            patch.object(cli_args.sys, "stdout", translated_stdout),
        ):
            assert (
                cli_args.cmd_vault_export(argparse.Namespace()) == cli_args.EXIT_SUCCESS
            )
        translated_stdout.flush()
        assert backing.getvalue() == raw.encode("utf-8")
    finally:
        translated_stdout.detach()


@pytest.mark.parametrize(
    "payload",
    [b"", bytes(range(256))],
    ids=["empty", "all-byte-values"],
)
def test_file_round_trip(tmp_path: Path, payload: bytes) -> None:
    source = tmp_path / "input.bin"
    encrypted = tmp_path / "input.ssc"
    output = tmp_path / "output.bin"
    source.write_bytes(payload)

    encrypt_file(str(source), str(encrypted), PLATFORM_TEST_CREDENTIAL)
    actual_path, metadata = decrypt_file(
        str(encrypted), str(output), PLATFORM_TEST_CREDENTIAL
    )

    assert actual_path == str(output)
    assert output.read_bytes() == payload
    assert metadata is not None
    assert metadata.version == 5
    _assert_no_atomic_temporary_files(tmp_path)


def test_plaintext_size_boundary_and_oversize_preservation(tmp_path: Path) -> None:
    """Every platform treats the shared limit as an inclusive plaintext bound."""
    exact_source = tmp_path / "exact.bin"
    oversized_source = tmp_path / "oversized.bin"
    exact_encrypted = tmp_path / "exact.ssc"
    exact_output = tmp_path / "exact.out"
    preserved_encrypted = tmp_path / "preserved.ssc"
    exact_source.write_bytes(b"abcd")
    oversized_source.write_bytes(b"abcde")
    preserved_encrypted.write_bytes(b"preserve me")

    with patch.object(core, "MAX_FILE_SIZE", 4):
        encrypt_file(str(exact_source), str(exact_encrypted), PLATFORM_TEST_CREDENTIAL)
        assert exact_encrypted.stat().st_size > 4
        decrypt_file(str(exact_encrypted), str(exact_output), PLATFORM_TEST_CREDENTIAL)

        with pytest.raises(CryptoError, match="Maximum plaintext size"):
            encrypt_file(
                str(oversized_source),
                str(preserved_encrypted),
                PLATFORM_TEST_CREDENTIAL,
                overwrite=True,
            )

    assert exact_output.read_bytes() == b"abcd"
    assert preserved_encrypted.read_bytes() == b"preserve me"
    _assert_no_atomic_temporary_files(tmp_path)


def test_force_replaces_ciphertext_with_decryptable_output(tmp_path: Path) -> None:
    source = tmp_path / "input.bin"
    encrypted = tmp_path / "input.ssc"
    output = tmp_path / "output.bin"
    source.write_bytes(b"replacement plaintext")
    encrypted.write_bytes(b"existing ciphertext")

    encrypt_file(str(source), str(encrypted), PLATFORM_TEST_CREDENTIAL, overwrite=True)
    decrypt_file(str(encrypted), str(output), PLATFORM_TEST_CREDENTIAL)

    assert output.read_bytes() == b"replacement plaintext"
    _assert_no_atomic_temporary_files(tmp_path)


@pytest.mark.parametrize("failure", ["wrong-password", "corrupt-tag"])
def test_failed_decryption_preserves_destination(tmp_path: Path, failure: str) -> None:
    source = tmp_path / "input.bin"
    encrypted = tmp_path / "input.ssc"
    output = tmp_path / "existing.bin"
    source.write_bytes(b"authenticated plaintext")
    output.write_bytes(b"existing destination bytes")
    encrypt_file(str(source), str(encrypted), PLATFORM_TEST_CREDENTIAL)

    credential = PLATFORM_TEST_CREDENTIAL
    if failure == "wrong-password":
        credential = "Wrong-Platform-Password-2026!"
    else:
        damaged = bytearray(encrypted.read_bytes())
        damaged[-1] ^= 1
        encrypted.write_bytes(damaged)

    with pytest.raises(CryptoError):
        decrypt_file(str(encrypted), str(output), credential, overwrite=True)

    assert output.read_bytes() == b"existing destination bytes"
    _assert_no_atomic_temporary_files(tmp_path)


def test_failed_encryption_leaves_no_output_or_temporary_file(
    tmp_path: Path,
) -> None:
    source = tmp_path / "input.bin"
    encrypted = tmp_path / "input.ssc"
    source.write_bytes(b"plaintext" * 1024)

    with (
        patch(
            "secure_string_cipher.timing_safe.add_timing_jitter",
            side_effect=RuntimeError("injected platform failure"),
        ),
        pytest.raises(CryptoError, match="Encryption failed"),
    ):
        encrypt_file(str(source), str(encrypted), PLATFORM_TEST_CREDENTIAL)

    assert not encrypted.exists()
    _assert_no_atomic_temporary_files(tmp_path)


def test_spaces_and_non_ascii_destination_names(tmp_path: Path) -> None:
    source = tmp_path / "source résumé data.bin"
    encrypted = tmp_path / "encrypted payload 🔒.ssc"
    output = tmp_path / "decrypted payload 🧪.bin"
    source.write_bytes(bytes(range(256)))

    encrypt_file(str(source), str(encrypted), PLATFORM_TEST_CREDENTIAL)
    decrypt_file(str(encrypted), str(output), PLATFORM_TEST_CREDENTIAL)

    assert output.read_bytes() == bytes(range(256))
    _assert_no_atomic_temporary_files(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission assertion")
def test_sensitive_outputs_use_owner_only_permissions(tmp_path: Path) -> None:
    source = tmp_path / "input.bin"
    encrypted = tmp_path / "input.ssc"
    output = tmp_path / "output.bin"
    source.write_bytes(b"sensitive bytes")

    encrypt_file(str(source), str(encrypted), PLATFORM_TEST_CREDENTIAL)
    decrypt_file(str(encrypted), str(output), PLATFORM_TEST_CREDENTIAL)

    assert encrypted.stat().st_mode & 0o777 == 0o600
    assert output.stat().st_mode & 0o777 == 0o600


def test_relative_final_component_symlink_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target.bin"
    link = tmp_path / "input-link.bin"
    target.write_bytes(b"plaintext")
    _create_symlink_or_skip(link, Path("target.bin"))
    monkeypatch.chdir(tmp_path)

    with pytest.raises(CryptoError, match="symlinked input path"):
        encrypt_file("input-link.bin", "output.ssc", PLATFORM_TEST_CREDENTIAL)

    assert not (tmp_path / "output.ssc").exists()
    _assert_no_atomic_temporary_files(tmp_path)


def test_relative_parent_directory_symlink_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_directory = tmp_path / "real-directory"
    linked_directory = tmp_path / "linked-directory"
    real_directory.mkdir()
    (real_directory / "input.bin").write_bytes(b"plaintext")
    _create_symlink_or_skip(
        linked_directory, Path("real-directory"), target_is_directory=True
    )
    monkeypatch.chdir(tmp_path)

    with pytest.raises(CryptoError, match="symlinked input path"):
        encrypt_file(
            "linked-directory/input.bin", "output.ssc", PLATFORM_TEST_CREDENTIAL
        )

    assert not (tmp_path / "output.ssc").exists()
    _assert_no_atomic_temporary_files(tmp_path)
