"""Safe writes (FORMAT.md section 7.5) and the commit point they promise."""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

import pytest

from secure_string_cipher import fs


def _failing_dir_sync(code: int) -> Callable[[int], None]:
    real = os.fsync

    def fsync(fd: int) -> None:
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(code, os.strerror(code))
        real(fd)

    return fsync


@pytest.mark.parametrize("replace", [True, False])
def test_a_failed_folder_sync_is_reported_after_the_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replace: bool
) -> None:
    if os.name != "posix":
        pytest.skip("folders are synced on POSIX only")
    path = tmp_path / "out"
    monkeypatch.setattr(os, "fsync", _failing_dir_sync(errno.EIO))
    with pytest.raises(fs.NotDurable):
        fs.write_atomic(path, lambda out: out.write(b"new"), replace=replace)
    assert path.read_bytes() == b"new"  # the write did happen
    assert [p.name for p in tmp_path.iterdir()] == ["out"]


def test_a_folder_that_cannot_be_synced_is_not_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "out"
    monkeypatch.setattr(os, "fsync", _failing_dir_sync(errno.EINVAL))
    fs.write_atomic(path, lambda out: out.write(b"new"), replace=False)
    assert path.read_bytes() == b"new"


def test_replace_swaps_the_whole_file(tmp_path: Path) -> None:
    path = tmp_path / "out"
    path.write_bytes(b"old and longer")
    fs.write_atomic(path, lambda out: out.write(b"new"), replace=True)
    assert path.read_bytes() == b"new"
    with pytest.raises(FileExistsError):
        fs.write_atomic(path, lambda out: out.write(b"x"), replace=False)
    assert [p.name for p in tmp_path.iterdir()] == ["out"]


def test_an_error_while_writing_leaves_the_old_file(tmp_path: Path) -> None:
    path = tmp_path / "out"
    path.write_bytes(b"old")

    def broken(out: BinaryIO) -> None:
        raise RuntimeError

    with pytest.raises(RuntimeError):
        fs.write_atomic(path, broken, replace=True)
    assert path.read_bytes() == b"old"
    assert [p.name for p in tmp_path.iterdir()] == ["out"]
