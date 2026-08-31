"""Transactional vault import, restore, backup, and rollback tests."""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from secure_string_cipher import cli_args
from secure_string_cipher.core import encrypt_text
from secure_string_cipher.passphrase_manager import (
    PassphraseVault,
    VaultTransactionError,
    _compute_vault_hmac,
    read_bounded_vault_file,
    validate_raw_vault,
)

FIXTURE_DIRECTORY = Path(__file__).parents[1] / "fixtures" / "vault"
MANIFEST = json.loads((FIXTURE_DIRECTORY / "manifest.json").read_text(encoding="utf-8"))
CANDIDATE_MASTER: str = MANIFEST["public_test_credential"]
ACTIVE_MASTER = "Public-Test-Only-Active-Master-2026!"  # pragma: allowlist secret
WRONG_MASTER = "Wrong-Test-Only-Candidate-Master-2026!"  # pragma: allowlist secret
EXPECTED_ENTRIES: dict[str, str] = MANIFEST["expected_entries"]


def _fixture_raw() -> bytes:
    encoded = (FIXTURE_DIRECTORY / MANIFEST["fixture"]["filename"]).read_text(
        encoding="ascii"
    )
    return base64.b64decode(encoded.strip(), validate=True)


def _build_raw(plaintext: str, master: str = CANDIDATE_MASTER) -> str:
    encrypted = encrypt_text(plaintext, master)
    salt = b"\xcd" * 32
    digest = _compute_vault_hmac(encrypted, master, salt)
    return f"SSCVAULT\n{salt.hex()}\n---DATA---\n{encrypted}\n---HMAC---\n{digest}"


def _authenticated_cipher_mutation(raw: bytes, offset: int) -> bytes:
    lines = raw.decode("utf-8").split("\n")
    encrypted = bytearray(base64.b64decode(lines[3], validate=True))
    encrypted[offset] ^= 1
    lines[3] = base64.b64encode(encrypted).decode("ascii")
    salt = bytes.fromhex(lines[1])
    lines[5] = _compute_vault_hmac(lines[3], CANDIDATE_MASTER, salt)
    return "\n".join(lines).encode()


class RecordingVault(PassphraseVault):
    """Minimal backend double that records transaction call ordering."""

    def __init__(self, raw: str | None) -> None:
        self.raw = raw
        self.calls: list[tuple[str, str | None]] = []
        self.failure: str | None = None
        self.read_count = 0
        self.write_count = 0
        self.backups: list[str] = []
        self._backend = "file"

    def read_raw_vault(self) -> str | None:
        self.read_count += 1
        self.calls.append(("read", None))
        if self.failure == "initial_read" and self.read_count == 1:
            raise OSError("read failed")
        if self.failure == "readback" and self.read_count == 2:
            raise OSError("read-back failed")
        return self.raw

    def write_raw_vault(self, vault_contents: str) -> None:
        self.write_count += 1
        self.calls.append(("write", vault_contents))
        if self.failure in {"write", "write_and_rollback"} and self.write_count == 1:
            self.raw = vault_contents
            raise OSError("write failed after mutation")
        if (
            self.failure in {"rollback_write", "write_and_rollback"}
            and self.write_count == 2
        ):
            raise OSError("rollback failed")
        self.raw = vault_contents

    def delete_vault_storage(self) -> None:
        self.calls.append(("delete", None))
        if self.failure == "rollback_delete":
            raise OSError("rollback delete failed")
        self.raw = None

    def _publish_backup(
        self,
        vault_contents: str,
        *,
        preserve_identifiers: frozenset[str] = frozenset(),
    ) -> str:
        self.calls.append(("backup", vault_contents))
        if self.failure == "backup":
            raise OSError("backup failed")
        self.backups.append(vault_contents)
        return "vault_backup_test.enc"


def test_valid_import_backs_up_then_publishes_and_verifies(tmp_path: Path) -> None:
    vault = PassphraseVault(str(tmp_path / "active.enc"), backend="file")
    vault.store_passphrase("active", "before", ACTIVE_MASTER)
    previous = vault.read_raw_vault()

    backup_identifier = vault.import_raw_vault(_fixture_raw(), CANDIDATE_MASTER)

    assert backup_identifier is not None
    assert vault.list_labels(CANDIDATE_MASTER) == sorted(EXPECTED_ENTRIES)
    backup_path = vault.backup_dir / backup_identifier
    assert backup_path.read_text(encoding="utf-8") == previous
    if os.name != "nt":
        assert backup_path.stat().st_mode & 0o777 == 0o600
    assert list(vault.backup_dir.glob(f".{backup_identifier}.*.tmp")) == []


def test_valid_restore_keeps_selected_backup_and_backs_up_active(
    tmp_path: Path,
) -> None:
    vault = PassphraseVault(str(tmp_path / "active.enc"), backend="file")
    vault.store_passphrase("active", "before", ACTIVE_MASTER)
    selected = vault._publish_backup(_fixture_raw().decode("utf-8"))
    selected_path = vault.backup_dir / selected

    previous_backup = vault.restore_from_backup(selected, CANDIDATE_MASTER)

    assert selected_path.exists()
    assert vault.list_labels(CANDIDATE_MASTER) == sorted(EXPECTED_ENTRIES)
    assert previous_backup is not None
    assert (vault.backup_dir / previous_backup).exists()


def test_restore_never_rotates_out_selected_oldest_backup(tmp_path: Path) -> None:
    vault = PassphraseVault(str(tmp_path / "active.enc"), backend="file")
    vault.store_passphrase("active", "before", ACTIVE_MASTER)
    identifiers = [
        f"vault_backup_2026082{index}T120000_000000Z_{index:08x}.enc"
        for index in range(1, 7)
    ]

    with patch(
        "secure_string_cipher.passphrase_manager._new_backup_identifier",
        side_effect=identifiers,
    ):
        for index, identifier in enumerate(identifiers[:5], start=1):
            assert vault._publish_backup(_fixture_raw().decode()) == identifier
            os.utime(vault.backup_dir / identifier, (index, index))

        selected = identifiers[0]
        vault.restore_from_backup(selected, CANDIDATE_MASTER)

    retained = {record.identifier for record in vault.list_backup_records()}
    assert selected in retained
    assert len(retained) == 5
    assert identifiers[1] not in retained


def test_import_retains_new_snapshot_despite_future_backup_mtimes(
    tmp_path: Path,
) -> None:
    vault = PassphraseVault(str(tmp_path / "active.enc"), backend="file")
    vault.store_passphrase("active", "before", ACTIVE_MASTER)
    previous = vault.read_raw_vault()
    existing_identifiers = [
        f"vault_backup_future_{index:08x}.enc" for index in range(5)
    ]
    snapshot_identifier = "vault_backup_current_snapshot.enc"

    for index, identifier in enumerate(existing_identifiers, start=1):
        with patch(
            "secure_string_cipher.passphrase_manager._new_backup_identifier",
            return_value=identifier,
        ):
            vault._publish_backup(_fixture_raw().decode())
        future_time = 4_102_444_800 + index
        os.utime(vault.backup_dir / identifier, (future_time, future_time))

    with patch(
        "secure_string_cipher.passphrase_manager._new_backup_identifier",
        return_value=snapshot_identifier,
    ):
        returned_identifier = vault.import_raw_vault(_fixture_raw(), CANDIDATE_MASTER)

    assert returned_identifier == snapshot_identifier
    assert (vault.backup_dir / snapshot_identifier).read_text() == previous
    assert len(vault.list_backup_records()) == 5


def _invalid_candidates() -> list[object]:
    raw = _fixture_raw()
    lines = raw.decode().split("\n")
    corrupt_hmac = lines.copy()
    corrupt_hmac[5] = ("0" if corrupt_hmac[5][0] != "0" else "1") + corrupt_hmac[5][1:]
    boundaries: list[tuple[bytes, str]] = []
    for index in range(1, 6):
        marker = sum(len(line) + 1 for line in lines[:index]) - 1
        boundaries.append((raw[:marker], f"truncated-boundary-{index}"))
    return [
        pytest.param(raw, WRONG_MASTER, id="wrong-master"),
        pytest.param("\n".join(corrupt_hmac).encode(), CANDIDATE_MASTER, id="hmac"),
        pytest.param(
            _authenticated_cipher_mutation(raw, 60),
            CANDIDATE_MASTER,
            id="encrypted-body",
        ),
        pytest.param(
            _authenticated_cipher_mutation(raw, -1),
            CANDIDATE_MASTER,
            id="authentication-tag",
        ),
        pytest.param(
            _build_raw("not-json").encode(), CANDIDATE_MASTER, id="decrypted-json"
        ),
        pytest.param(
            _build_raw('{"label":1}').encode(), CANDIDATE_MASTER, id="json-schema"
        ),
        pytest.param(raw[:-1], CANDIDATE_MASTER, id="hmac-truncated"),
        pytest.param(raw + b"\n", CANDIDATE_MASTER, id="terminal-lf"),
        pytest.param(raw + b"\r\n", CANDIDATE_MASTER, id="terminal-crlf"),
        *[
            pytest.param(candidate, CANDIDATE_MASTER, id=case)
            for candidate, case in boundaries
        ],
    ]


@pytest.mark.parametrize(("candidate", "master"), _invalid_candidates())
def test_prepublication_validation_failures_preserve_exact_active_state(
    candidate: bytes, master: str
) -> None:
    previous = _fixture_raw().decode("utf-8")
    vault = RecordingVault(previous)

    with pytest.raises(VaultTransactionError) as caught:
        vault.import_raw_vault(candidate, master)

    assert caught.value.category == "candidate_validation_failed"
    assert caught.value.rollback_attempted is False
    assert vault.raw == previous
    assert vault.backups == []
    assert vault.calls == []


def test_candidate_larger_than_import_bound_is_rejected_before_io() -> None:
    vault = RecordingVault(_fixture_raw().decode())
    with patch("secure_string_cipher.passphrase_manager.MAX_FILE_SIZE", 16):
        with pytest.raises(VaultTransactionError) as caught:
            vault.import_raw_vault(b"x" * 17, CANDIDATE_MASTER)
    assert caught.value.category == "candidate_too_large"
    assert vault.calls == []


def test_bounded_file_reader_checks_size_before_and_after_read(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.enc"
    candidate.write_bytes(b"x" * 17)
    with patch("secure_string_cipher.passphrase_manager.MAX_FILE_SIZE", 16):
        with pytest.raises(VaultTransactionError) as caught:
            read_bounded_vault_file(candidate)
    assert caught.value.category == "candidate_too_large"


@pytest.mark.parametrize(
    ("failure", "category", "expected_calls"),
    [
        ("initial_read", "active_read_failed", ["read"]),
        ("backup", "backup_failed", ["read", "backup"]),
    ],
)
def test_prepublication_backend_failures_never_write(
    failure: str, category: str, expected_calls: list[str]
) -> None:
    previous = _fixture_raw().decode()
    vault = RecordingVault(previous)
    vault.failure = failure

    with pytest.raises(VaultTransactionError) as caught:
        vault.import_raw_vault(_fixture_raw(), CANDIDATE_MASTER)

    assert caught.value.category == category
    assert [call[0] for call in vault.calls] == expected_calls
    assert not any(call[0] == "write" for call in vault.calls)
    assert vault.raw == previous


@pytest.mark.parametrize("failure", ["write", "readback"])
def test_postwrite_failure_rolls_back_and_reports_success(failure: str) -> None:
    previous = _build_raw('{"previous":"value"}', ACTIVE_MASTER)
    vault = RecordingVault(previous)
    vault.failure = failure

    with pytest.raises(VaultTransactionError) as caught:
        vault.import_raw_vault(_fixture_raw(), CANDIDATE_MASTER)

    assert caught.value.category == "publication_failed"
    assert caught.value.rollback_attempted is True
    assert caught.value.rollback_succeeded is True
    assert caught.value.backup_identifier == "vault_backup_test.enc"
    assert vault.raw == previous
    assert vault.backups == [previous]
    assert [call[0] for call in vault.calls] == [
        "read",
        "backup",
        "write",
        *(["read"] if failure == "readback" else []),
        "write",
        "read",
    ]


def test_postwrite_validation_failure_rolls_back() -> None:
    previous = _build_raw('{"previous":"value"}', ACTIVE_MASTER)
    candidate = _fixture_raw().decode()
    vault = RecordingVault(previous)
    real_validator = validate_raw_vault
    validation_count = 0

    def fail_second_validation(contents: str | bytes, master: str) -> dict[str, str]:
        nonlocal validation_count
        validation_count += 1
        if validation_count == 2:
            raise ValueError("post-write validation failed")
        return real_validator(contents, master)

    with (
        patch(
            "secure_string_cipher.passphrase_manager.validate_raw_vault",
            side_effect=fail_second_validation,
        ),
        pytest.raises(VaultTransactionError) as caught,
    ):
        vault.import_raw_vault(candidate, CANDIDATE_MASTER)

    assert caught.value.rollback_succeeded is True
    assert vault.raw == previous
    assert vault.backups == [previous]
    assert [call[0] for call in vault.calls] == [
        "read",
        "backup",
        "write",
        "read",
        "write",
        "read",
    ]


def test_rollback_failure_reports_high_severity_state() -> None:
    previous = _build_raw('{"previous":"value"}', ACTIVE_MASTER)
    vault = RecordingVault(previous)
    vault.failure = "write_and_rollback"

    with pytest.raises(VaultTransactionError) as caught:
        vault.import_raw_vault(_fixture_raw(), CANDIDATE_MASTER)

    assert caught.value.category == "rollback_failed"
    assert caught.value.rollback_attempted is True
    assert caught.value.rollback_succeeded is False
    assert "may be inconsistent" in str(caught.value)
    assert vault.raw == _fixture_raw().decode()
    assert vault.backups == [previous]
    assert [call[0] for call in vault.calls] == [
        "read",
        "backup",
        "write",
        "write",
    ]


def test_new_destination_is_removed_when_postwrite_verification_fails() -> None:
    vault = RecordingVault(None)
    vault.failure = "readback"

    with pytest.raises(VaultTransactionError) as caught:
        vault.import_raw_vault(_fixture_raw(), CANDIDATE_MASTER)

    assert caught.value.rollback_succeeded is True
    assert vault.raw is None
    assert [call[0] for call in vault.calls] == [
        "read",
        "write",
        "read",
        "delete",
        "read",
    ]


def test_backup_collision_retries_without_overwrite(tmp_path: Path) -> None:
    vault = PassphraseVault(str(tmp_path / "active.enc"), backend="file")
    collision = "vault_backup_collision.enc"
    unique = "vault_backup_unique.enc"
    existing = vault.backup_dir / collision
    existing.write_bytes(b"existing backup")

    with patch(
        "secure_string_cipher.passphrase_manager._new_backup_identifier",
        side_effect=[collision, unique],
    ):
        identifier = vault._publish_backup("new backup")

    assert identifier == unique
    assert existing.read_bytes() == b"existing backup"
    assert (vault.backup_dir / unique).read_text() == "new backup"


def test_repeated_backups_in_same_interval_are_unique(tmp_path: Path) -> None:
    vault = PassphraseVault(str(tmp_path / "active.enc"), backend="file")
    identifiers = [
        "vault_backup_20260829T120000_000001Z_aaaaaaaa.enc",
        "vault_backup_20260829T120000_000001Z_bbbbbbbb.enc",
    ]
    with patch(
        "secure_string_cipher.passphrase_manager._new_backup_identifier",
        side_effect=identifiers,
    ):
        first = vault._publish_backup("first")
        second = vault._publish_backup("second")
    assert first != second
    assert (vault.backup_dir / first).read_text() == "first"
    assert (vault.backup_dir / second).read_text() == "second"


def test_backup_publication_failure_preserves_active_and_cleans_temp(
    tmp_path: Path,
) -> None:
    vault = PassphraseVault(str(tmp_path / "active.enc"), backend="file")
    vault.store_passphrase("active", "before", ACTIVE_MASTER)
    previous = vault.read_raw_vault()

    with (
        patch("secure_string_cipher.atomic_io.os.replace", side_effect=OSError("disk")),
        pytest.raises(VaultTransactionError) as caught,
    ):
        vault.import_raw_vault(_fixture_raw(), CANDIDATE_MASTER)

    assert caught.value.category == "backup_failed"
    assert vault.read_raw_vault() == previous
    assert list(vault.backup_dir.glob(".*.tmp")) == []


def test_failed_restore_preserves_selected_backup_active_bytes_and_cleans_temps(
    tmp_path: Path,
) -> None:
    vault = PassphraseVault(str(tmp_path / "active.enc"), backend="file")
    vault.store_passphrase("active", "before", ACTIVE_MASTER)
    previous = vault.read_raw_vault()
    identifiers = [
        f"vault_backup_2026082{index}T120000_000000Z_{index:08x}.enc"
        for index in range(1, 7)
    ]
    for index, identifier in enumerate(identifiers[:5], start=1):
        with patch(
            "secure_string_cipher.passphrase_manager._new_backup_identifier",
            return_value=identifier,
        ):
            vault._publish_backup(_fixture_raw().decode())
        os.utime(vault.backup_dir / identifier, (index, index))

    real_replace = os.replace
    replace_count = 0

    def fail_active_publication(source: str | Path, destination: str | Path) -> None:
        nonlocal replace_count
        replace_count += 1
        if replace_count == 2:
            raise OSError("active publication failed")
        real_replace(source, destination)

    selected = identifiers[0]
    with (
        patch(
            "secure_string_cipher.passphrase_manager._new_backup_identifier",
            return_value=identifiers[5],
        ),
        patch(
            "secure_string_cipher.atomic_io.os.replace",
            side_effect=fail_active_publication,
        ),
        pytest.raises(VaultTransactionError) as caught,
    ):
        vault.restore_from_backup(selected, CANDIDATE_MASTER)

    retained = {record.identifier for record in vault.list_backup_records()}
    assert caught.value.category == "publication_failed"
    assert caught.value.rollback_succeeded is True
    assert vault.read_raw_vault() == previous
    assert selected in retained
    assert len(retained) == 5
    assert list(tmp_path.glob(".active.enc.*.tmp")) == []
    assert list(vault.backup_dir.glob(".*.tmp")) == []


@pytest.mark.parametrize("ending", [b"", b"\n", b"\r\n"])
def test_cli_import_canonicalizes_one_legacy_transport_ending(
    tmp_path: Path, ending: bytes
) -> None:
    candidate = tmp_path / "candidate.vault"
    candidate.write_bytes(_fixture_raw() + ending)
    vault = MagicMock()
    vault.backend = "keychain"
    vault.vault_exists.return_value = False
    vault.import_raw_vault.return_value = None

    with (
        patch(
            "secure_string_cipher.cli_args.PassphraseVault", return_value=vault
        ) as cls,
        patch(
            "secure_string_cipher.cli_args._prompt_master_password",
            return_value=CANDIDATE_MASTER,
        ),
    ):
        result = cli_args.cmd_vault_import(argparse.Namespace(file=str(candidate)))

    assert result == cli_args.EXIT_SUCCESS
    cls.assert_called_once_with()
    vault.import_raw_vault.assert_called_once_with(
        _fixture_raw(), CANDIDATE_MASTER, backup_current=True
    )


@pytest.mark.parametrize(
    "candidate_bytes",
    [
        _fixture_raw() + b"\n\n",
        _fixture_raw() + b"\r\n\r\n",
        _fixture_raw() + b"\r",
        _fixture_raw() + b" ",
        _fixture_raw() + b"\t",
        b"\n" + _fixture_raw(),
        _fixture_raw().replace(b"\n", b"\r\n"),
    ],
)
def test_cli_import_rejects_other_transport_changes_before_confirmation(
    tmp_path: Path, candidate_bytes: bytes
) -> None:
    candidate = tmp_path / "candidate.vault"
    candidate.write_bytes(candidate_bytes)
    vault = MagicMock()
    vault.backend = "file"

    with (
        patch("secure_string_cipher.cli_args.PassphraseVault", return_value=vault),
        patch(
            "secure_string_cipher.cli_args._prompt_master_password",
            return_value=CANDIDATE_MASTER,
        ),
        pytest.raises(SystemExit) as caught,
    ):
        cli_args.cmd_vault_import(argparse.Namespace(file=str(candidate)))

    assert caught.value.code == cli_args.EXIT_AUTH_ERROR
    vault.vault_exists.assert_not_called()
    vault.import_raw_vault.assert_not_called()


def test_cli_export_to_import_round_trip_is_byte_exact(tmp_path: Path) -> None:
    raw = _fixture_raw()
    export_vault = MagicMock()
    export_vault.list_labels.return_value = sorted(EXPECTED_ENTRIES)
    export_vault.read_raw_vault.return_value = raw.decode("utf-8")

    class BinaryCapture:
        def __init__(self) -> None:
            self.buffer = io.BytesIO()

        def isatty(self) -> bool:
            return False

    capture = BinaryCapture()
    with (
        patch("secure_string_cipher.cli_args._get_vault", return_value=export_vault),
        patch(
            "secure_string_cipher.cli_args._prompt_master_password",
            return_value=CANDIDATE_MASTER,
        ),
        patch.object(cli_args.sys, "stdout", capture),
    ):
        assert cli_args.cmd_vault_export(argparse.Namespace()) == cli_args.EXIT_SUCCESS

    exported = capture.buffer.getvalue()
    assert exported == raw

    candidate = tmp_path / "round-trip.vault"
    candidate.write_bytes(exported)
    import_vault = MagicMock()
    import_vault.backend = "file"
    import_vault.vault_exists.return_value = False
    import_vault.import_raw_vault.return_value = None
    with (
        patch(
            "secure_string_cipher.cli_args.PassphraseVault", return_value=import_vault
        ),
        patch(
            "secure_string_cipher.cli_args._prompt_master_password",
            return_value=CANDIDATE_MASTER,
        ),
    ):
        assert (
            cli_args.cmd_vault_import(argparse.Namespace(file=str(candidate)))
            == cli_args.EXIT_SUCCESS
        )

    import_vault.import_raw_vault.assert_called_once_with(
        raw, CANDIDATE_MASTER, backup_current=True
    )


def test_transaction_preserves_previous_raw_bytes_while_publishing_canonical() -> None:
    previous = _build_raw('{"previous":"value"}', ACTIVE_MASTER) + "\r\n"
    canonical_candidate = _fixture_raw().decode("utf-8")
    vault = RecordingVault(previous)

    vault.import_raw_vault(canonical_candidate, CANDIDATE_MASTER)

    assert vault.backups == [previous]
    assert vault.raw == canonical_candidate


def test_cli_import_cancellation_causes_no_writes(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.vault"
    candidate.write_bytes(_fixture_raw())
    vault = MagicMock()
    vault.backend = "file"
    vault.vault_exists.return_value = True

    with (
        patch("secure_string_cipher.cli_args.PassphraseVault", return_value=vault),
        patch(
            "secure_string_cipher.cli_args._prompt_master_password",
            return_value=CANDIDATE_MASTER,
        ),
        patch("builtins.input", return_value="n"),
        pytest.raises(SystemExit) as caught,
    ):
        cli_args.cmd_vault_import(argparse.Namespace(file=str(candidate)))

    assert caught.value.code == cli_args.EXIT_INPUT_ERROR
    vault.import_raw_vault.assert_not_called()
    vault.write_raw_vault.assert_not_called()


def test_cli_restore_uses_configured_backend_and_cancellation_writes_nothing() -> None:
    vault = MagicMock()
    vault.backend = "keychain"
    vault.vault_exists.return_value = True

    with (
        patch(
            "secure_string_cipher.cli_args.PassphraseVault", return_value=vault
        ) as cls,
        patch(
            "secure_string_cipher.cli_args._prompt_master_password",
            return_value=CANDIDATE_MASTER,
        ),
        patch("builtins.input", return_value="n"),
        pytest.raises(SystemExit) as caught,
    ):
        cli_args.cmd_vault_restore(
            argparse.Namespace(identifier="vault_backup_selected.enc")
        )

    assert caught.value.code == cli_args.EXIT_INPUT_ERROR
    cls.assert_called_once_with()
    vault.validate_backup.assert_called_once_with(
        "vault_backup_selected.enc", CANDIDATE_MASTER
    )
    vault.restore_from_backup.assert_not_called()
    vault.write_raw_vault.assert_not_called()


def test_transaction_error_and_logs_never_expose_secrets(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret_entry = "transaction-secret-value"  # pragma: allowlist secret
    secret_master = "Transaction-Secret-Master-2026!"  # pragma: allowlist secret
    candidate = _build_raw(json.dumps({"label": secret_entry}), secret_master)
    vault = RecordingVault(_fixture_raw().decode())
    vault.failure = "write"

    with pytest.raises(VaultTransactionError) as caught:
        vault.import_raw_vault(candidate, secret_master)

    exposed = f"{caught.value}\n{caplog.text}"
    assert secret_entry not in exposed
    assert secret_master not in exposed
    assert candidate not in exposed
