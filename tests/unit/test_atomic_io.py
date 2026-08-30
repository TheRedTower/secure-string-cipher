"""Regression tests for atomic binary publication."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from secure_string_cipher.atomic_io import atomic_binary_writer
from secure_string_cipher.utils import CryptoError


def _temporary_files(directory: Path, destination: Path) -> list[Path]:
    return list(directory.glob(f".{destination.name}.*.tmp"))


def test_creates_new_file_with_exact_bytes(tmp_path: Path) -> None:
    destination = tmp_path / "output.bin"
    payload = b"\x00exact payload\xff"

    with atomic_binary_writer(destination) as writer:
        writer.write(payload)

    assert destination.read_bytes() == payload


def test_refuses_existing_destination_without_overwrite(tmp_path: Path) -> None:
    destination = tmp_path / "output.bin"
    destination.write_bytes(b"original")

    with pytest.raises(CryptoError, match="already exists"):
        with atomic_binary_writer(destination) as writer:
            writer.write(b"replacement")

    assert destination.read_bytes() == b"original"
    assert _temporary_files(tmp_path, destination) == []


def test_refuses_dangling_symlink_destination_without_overwrite(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "output.bin"
    try:
        destination.symlink_to(tmp_path / "missing-target")
    except (NotImplementedError, OSError):  # pragma: no cover - platform support
        pytest.skip("symbolic links are unavailable")

    with pytest.raises(CryptoError, match="already exists"):
        with atomic_binary_writer(destination) as writer:
            writer.write(b"replacement")

    assert destination.is_symlink()
    assert os.readlink(destination) == str(tmp_path / "missing-target")
    assert _temporary_files(tmp_path, destination) == []


def test_replaces_existing_destination_with_overwrite(tmp_path: Path) -> None:
    destination = tmp_path / "output.bin"
    destination.write_bytes(b"original")

    with atomic_binary_writer(destination, overwrite=True) as writer:
        writer.write(b"replacement")

    assert destination.read_bytes() == b"replacement"


def test_caller_exception_preserves_existing_destination(tmp_path: Path) -> None:
    destination = tmp_path / "output.bin"
    destination.write_bytes(b"original")

    with pytest.raises(RuntimeError, match="injected"):
        with atomic_binary_writer(destination, overwrite=True) as writer:
            writer.write(b"partial")
            raise RuntimeError("injected")

    assert destination.read_bytes() == b"original"
    assert _temporary_files(tmp_path, destination) == []


def test_caller_exception_leaves_no_new_destination(tmp_path: Path) -> None:
    destination = tmp_path / "output.bin"

    with pytest.raises(RuntimeError, match="injected"):
        with atomic_binary_writer(destination) as writer:
            writer.write(b"partial")
            raise RuntimeError("injected")

    assert not destination.exists()
    assert _temporary_files(tmp_path, destination) == []


def test_fsync_failure_preserves_existing_destination(tmp_path: Path) -> None:
    destination = tmp_path / "output.bin"
    destination.write_bytes(b"original")

    with (
        patch("secure_string_cipher.atomic_io.os.fsync", side_effect=OSError("disk")),
        pytest.raises(OSError, match="disk"),
    ):
        with atomic_binary_writer(destination, overwrite=True) as writer:
            writer.write(b"replacement")

    assert destination.read_bytes() == b"original"
    assert _temporary_files(tmp_path, destination) == []


def test_directory_fsync_failure_is_best_effort_after_publication(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "output.bin"
    destination.write_bytes(b"original")

    with patch(
        "secure_string_cipher.atomic_io.os.fsync",
        side_effect=[None, OSError("directory sync")],
    ):
        with atomic_binary_writer(destination, overwrite=True) as writer:
            writer.write(b"replacement")

    assert destination.read_bytes() == b"replacement"
    assert _temporary_files(tmp_path, destination) == []


def test_replace_failure_preserves_existing_destination(tmp_path: Path) -> None:
    destination = tmp_path / "output.bin"
    destination.write_bytes(b"original")

    with (
        patch("secure_string_cipher.atomic_io.os.replace", side_effect=OSError("disk")),
        pytest.raises(OSError, match="disk"),
    ):
        with atomic_binary_writer(destination, overwrite=True) as writer:
            writer.write(b"replacement")

    assert destination.read_bytes() == b"original"
    assert _temporary_files(tmp_path, destination) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission check")
def test_output_mode_is_owner_only(tmp_path: Path) -> None:
    destination = tmp_path / "output.bin"

    with atomic_binary_writer(destination) as writer:
        writer.write(b"secret")

    assert destination.stat().st_mode & 0o777 == 0o600


def test_permissive_output_mode_is_rejected_before_creation(tmp_path: Path) -> None:
    destination = tmp_path / "output.bin"

    with pytest.raises(CryptoError, match="owner-only mode 0o600"):
        with atomic_binary_writer(destination, mode=0o644):
            pytest.fail("writer must not be yielded")

    assert not destination.exists()
    assert _temporary_files(tmp_path, destination) == []


def test_missing_parent_fails_cleanly(tmp_path: Path) -> None:
    destination = tmp_path / "missing" / "output.bin"

    with pytest.raises(CryptoError, match="does not exist"):
        with atomic_binary_writer(destination):
            pass

    assert not destination.exists()


def test_non_directory_parent_fails_cleanly(tmp_path: Path) -> None:
    parent = tmp_path / "not-a-directory"
    parent.write_bytes(b"data")
    destination = parent / "output.bin"

    with pytest.raises(CryptoError, match="not a directory"):
        with atomic_binary_writer(destination):
            pass


def test_large_payload_is_written_completely(tmp_path: Path) -> None:
    destination = tmp_path / "large.bin"
    payload = os.urandom(2 * 1024 * 1024 + 17)

    with atomic_binary_writer(destination) as writer:
        writer.write(payload)

    assert destination.read_bytes() == payload
