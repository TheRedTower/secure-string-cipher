"""Descriptor-backed file-size and growth-boundary regressions."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from secure_string_cipher import core
from secure_string_cipher import passphrase_manager as vault_module
from secure_string_cipher.core import CryptoError, StreamProcessor
from secure_string_cipher.passphrase_manager import (
    BACKEND_KEYCHAIN,
    PassphraseVault,
    VaultTransactionError,
    _bounded_candidate_text,
)

TEST_PASSWORD = "Bounded-Test-Password-2026!"  # pragma: allowlist secret


def _temporary_files(directory: Path, destination: Path) -> list[Path]:
    return list(directory.glob(f".{destination.name}.*.tmp"))


def test_exact_plaintext_limit_round_trips_with_larger_container(
    tmp_path: Path,
) -> None:
    limit = 32
    source = tmp_path / "source.bin"
    encrypted = tmp_path / "source.ssc"
    output = tmp_path / "output.bin"
    payload = b"x" * limit
    source.write_bytes(payload)

    with patch.object(core, "MAX_FILE_SIZE", limit):
        core.encrypt_file(str(source), str(encrypted), TEST_PASSWORD)
        assert encrypted.stat().st_size > limit
        core.decrypt_file(str(encrypted), str(output), TEST_PASSWORD)

    assert output.read_bytes() == payload


def test_limit_plus_one_decrypt_rejects_before_kdf_and_preserves_output(
    tmp_path: Path,
) -> None:
    limit = 32
    source = tmp_path / "source.bin"
    encrypted = tmp_path / "source.ssc"
    output = tmp_path / "output.bin"
    source.write_bytes(b"x" * (limit + 1))
    output.write_bytes(b"preserve me")
    core.encrypt_file(str(source), str(encrypted), TEST_PASSWORD)

    with (
        patch.object(core, "MAX_FILE_SIZE", limit),
        patch.object(core, "derive_key") as derive_key,
        pytest.raises(CryptoError, match="Maximum plaintext size"),
    ):
        core.decrypt_file(str(encrypted), str(output), TEST_PASSWORD, overwrite=True)

    derive_key.assert_not_called()
    assert output.read_bytes() == b"preserve me"
    assert _temporary_files(tmp_path, output) == []


@pytest.mark.parametrize("automatic_output", [False, True])
def test_cumulative_decrypt_bound_catches_underreported_growth(
    tmp_path: Path, automatic_output: bool
) -> None:
    limit = 32
    source = tmp_path / "source.bin"
    encrypted = tmp_path / "source.ssc"
    explicit_output = tmp_path / "output.bin"
    source.write_bytes(b"x" * (limit + 1))
    explicit_output.write_bytes(b"preserve me")
    core.encrypt_file(str(source), str(encrypted), TEST_PASSWORD)
    underreported_size = encrypted.stat().st_size - 1
    output_arg = None if automatic_output else str(explicit_output)

    with (
        patch.object(core, "MAX_FILE_SIZE", limit),
        patch.object(
            core,
            "_descriptor_regular_file_size",
            return_value=underreported_size,
        ),
        pytest.raises(CryptoError, match="Maximum plaintext size"),
    ):
        core.decrypt_file(str(encrypted), output_arg, TEST_PASSWORD, overwrite=True)

    assert source.read_bytes() == b"x" * (limit + 1)
    assert explicit_output.read_bytes() == b"preserve me"
    assert _temporary_files(tmp_path, explicit_output) == []
    assert _temporary_files(tmp_path, source) == []


def test_cumulative_encrypt_bound_preserves_destination_on_growth(
    tmp_path: Path,
) -> None:
    limit = 32
    source = tmp_path / "source.bin"
    encrypted = tmp_path / "source.ssc"
    source.write_bytes(b"x" * (limit + 1))
    encrypted.write_bytes(b"preserve me")

    with (
        patch.object(core, "MAX_FILE_SIZE", limit),
        patch.object(core, "_preflight_regular_file_size", return_value=limit),
        patch.object(core, "_descriptor_regular_file_size", return_value=limit),
        pytest.raises(CryptoError, match="Maximum plaintext size"),
    ):
        core.encrypt_file(str(source), str(encrypted), TEST_PASSWORD, overwrite=True)

    assert encrypted.read_bytes() == b"preserve me"
    assert _temporary_files(tmp_path, encrypted) == []


def test_stream_processor_closes_file_when_descriptor_validation_fails(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")
    processor = StreamProcessor(str(source), "rb")
    opened_files = []
    real_open = open

    def tracking_open(*args, **kwargs):
        opened = real_open(*args, **kwargs)
        opened_files.append(opened)
        return opened

    with (
        patch("builtins.open", side_effect=tracking_open),
        patch.object(
            core,
            "_descriptor_regular_file_size",
            side_effect=CryptoError("descriptor rejected"),
        ),
        pytest.raises(CryptoError, match="descriptor rejected"),
    ):
        processor.__enter__()

    assert len(opened_files) == 1
    assert opened_files[0].closed
    assert processor.file is None


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable")
def test_fifo_is_rejected_before_open_for_encrypt_and_decrypt(tmp_path: Path) -> None:
    fifo = tmp_path / "input.fifo"
    os.mkfifo(fifo)

    with pytest.raises(CryptoError, match="not a regular file"):
        core.encrypt_file(str(fifo), str(tmp_path / "output.ssc"), TEST_PASSWORD)
    with pytest.raises(CryptoError, match="not a regular file"):
        core.decrypt_file(str(fifo), str(tmp_path / "output.bin"), TEST_PASSWORD)


def test_key_file_exact_limit_and_growth_bound(tmp_path: Path) -> None:
    limit = 4
    exact = tmp_path / "exact.key"
    grown = tmp_path / "grown.key"
    exact.write_bytes(b"abcd")
    grown.write_bytes(b"abcde")

    with patch.object(core, "MAX_FILE_SIZE", limit):
        assert (
            core.derive_passphrase_from_key_file(exact)
            == hashlib.sha256(b"abcd").hexdigest()
        )

    with (
        patch.object(core, "MAX_FILE_SIZE", limit),
        patch.object(core, "_preflight_regular_file_size", return_value=limit),
        patch.object(core, "_descriptor_regular_file_size", return_value=limit),
        pytest.raises(CryptoError, match="Key file too large"),
    ):
        core.derive_passphrase_from_key_file(grown)


def test_vault_reader_accepts_exact_limit(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.vault"
    candidate.write_bytes(b"abcd")

    with patch.object(vault_module, "MAX_FILE_SIZE", 4):
        assert vault_module.read_bounded_vault_file(candidate) == b"abcd"


def test_vault_reader_rejects_snapshot_oversize(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.vault"
    candidate.write_bytes(b"abcde")

    with (
        patch.object(vault_module, "MAX_FILE_SIZE", 4),
        pytest.raises(VaultTransactionError) as caught,
    ):
        vault_module.read_bounded_vault_file(candidate)

    assert caught.value.category == "candidate_too_large"


def test_vault_reader_cumulative_bound_catches_underreported_growth(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "candidate.vault"
    candidate.write_bytes(b"abcde")

    with (
        patch.object(vault_module, "MAX_FILE_SIZE", 4),
        patch.object(
            vault_module,
            "_vault_descriptor_regular_file_size",
            return_value=4,
        ),
        pytest.raises(VaultTransactionError) as caught,
    ):
        vault_module.read_bounded_vault_file(candidate)

    assert caught.value.category == "candidate_too_large"


def test_vault_reader_rejects_nonregular_candidate(tmp_path: Path) -> None:
    with pytest.raises(VaultTransactionError) as caught:
        vault_module.read_bounded_vault_file(tmp_path)

    assert caught.value.category == "candidate_read_failed"


def test_in_memory_vault_bound_counts_utf8_bytes() -> None:
    with patch.object(vault_module, "MAX_FILE_SIZE", 4):
        assert _bounded_candidate_text("éé") == "éé"
        with pytest.raises(VaultTransactionError) as caught:
            _bounded_candidate_text("ééx")

    assert caught.value.category == "candidate_too_large"


def test_active_file_vault_read_is_descriptor_and_growth_bounded(
    tmp_path: Path,
) -> None:
    active_path = tmp_path / "active.enc"
    vault = PassphraseVault(str(active_path), backend="file")
    active_path.write_bytes(b"abcd")

    with patch.object(vault_module, "MAX_FILE_SIZE", 4):
        assert vault.read_raw_vault() == "abcd"

    active_path.write_bytes(b"abcde")
    with (
        patch.object(vault_module, "MAX_FILE_SIZE", 4),
        patch.object(
            vault_module,
            "_vault_descriptor_regular_file_size",
            return_value=4,
        ),
        pytest.raises(VaultTransactionError) as caught,
    ):
        vault.read_raw_vault()

    assert caught.value.category == "candidate_too_large"


def test_active_file_vault_rejects_nonregular_storage(tmp_path: Path) -> None:
    active_path = tmp_path / "active.enc"
    active_path.mkdir()
    vault = PassphraseVault(str(active_path), backend="file")

    with pytest.raises(VaultTransactionError) as caught:
        vault.read_raw_vault()

    assert caught.value.category == "candidate_read_failed"


def test_active_vault_crud_rejects_oversize_before_key_derivation(
    tmp_path: Path,
) -> None:
    active_path = tmp_path / "active.enc"
    active_path.write_bytes(b"abcde")
    vault = PassphraseVault(str(active_path), backend="file")

    with (
        patch.object(vault_module, "MAX_FILE_SIZE", 4),
        patch.object(vault_module, "derive_key") as derive_key,
        pytest.raises(ValueError),
    ):
        vault.list_labels(TEST_PASSWORD)

    derive_key.assert_not_called()


def test_oversize_active_vault_aborts_transaction_before_backup_or_write(
    tmp_path: Path,
) -> None:
    candidate_vault = PassphraseVault(str(tmp_path / "candidate.enc"), backend="file")
    candidate_vault.store_passphrase("label", "value", TEST_PASSWORD)
    candidate = candidate_vault.read_raw_vault()
    assert candidate is not None
    candidate_size = len(candidate.encode("utf-8"))

    active_path = tmp_path / "active.enc"
    active_bytes = b"x" * (candidate_size + 1)
    active_path.write_bytes(active_bytes)
    active_vault = PassphraseVault(str(active_path), backend="file")

    with (
        patch.object(vault_module, "MAX_FILE_SIZE", candidate_size),
        patch.object(
            active_vault,
            "write_raw_vault",
            wraps=active_vault.write_raw_vault,
        ) as write_raw,
        pytest.raises(VaultTransactionError) as caught,
    ):
        active_vault.import_raw_vault(candidate, TEST_PASSWORD)

    assert caught.value.category == "active_read_failed"
    write_raw.assert_not_called()
    assert active_path.read_bytes() == active_bytes
    assert list(active_vault.backup_dir.glob("vault_backup_*.enc")) == []


def test_active_file_vault_write_rejects_oversize_without_replacement(
    tmp_path: Path,
) -> None:
    active_path = tmp_path / "active.enc"
    active_path.write_bytes(b"old")
    vault = PassphraseVault(str(active_path), backend="file")

    with patch.object(vault_module, "MAX_FILE_SIZE", 4):
        vault.write_raw_vault("éé")
        with pytest.raises(ValueError):
            vault.write_raw_vault("ééx")

    assert active_path.read_bytes() == "éé".encode()
    assert _temporary_files(tmp_path, active_path) == []


def test_file_to_keychain_migration_rejects_oversize_before_backend_write(
    tmp_path: Path,
) -> None:
    active_path = tmp_path / "active.enc"
    active_path.write_bytes(b"abcde")
    vault = PassphraseVault(str(active_path), backend="file")

    with (
        patch.object(vault_module, "MAX_FILE_SIZE", 4),
        patch(
            "secure_string_cipher.keychain_backend.KeychainVaultBackend"
        ) as keychain_class,
        pytest.raises(VaultTransactionError),
    ):
        vault.migrate_to_keychain(TEST_PASSWORD)

    keychain_class.assert_not_called()


def test_keychain_active_read_and_write_apply_utf8_byte_bound() -> None:
    keychain = MagicMock()
    keychain.load_vault.return_value = "ééx"
    vault = object.__new__(PassphraseVault)
    vault._backend = BACKEND_KEYCHAIN
    vault._keychain = keychain

    with patch.object(vault_module, "MAX_FILE_SIZE", 4):
        with pytest.raises(ValueError):
            vault.read_raw_vault()
        with pytest.raises(ValueError):
            vault.write_raw_vault("ééx")

    keychain.store_vault.assert_not_called()
