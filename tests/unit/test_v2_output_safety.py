import os
from pathlib import Path

import pytest

from secure_string_cipher.utils import CryptoError
from secure_string_cipher.v2.output import (
    process_with_two_pass_auth,
    safe_atomic_output,
    validate_path_safety,
)


def test_validate_path_safety(tmp_path):
    dest = tmp_path / "file.txt"
    dest.touch()

    # Valid
    assert validate_path_safety(dest) == dest

    # Symlink file
    sym_file = tmp_path / "sym.txt"
    sym_file.symlink_to(dest)
    with pytest.raises(CryptoError, match="Symlinks not allowed"):
        validate_path_safety(sym_file)

    # Symlink parent
    sym_dir = tmp_path / "sym_dir"
    sym_dir.symlink_to(tmp_path, target_is_directory=True)
    sym_dest = sym_dir / "file.txt"
    with pytest.raises(CryptoError, match="Symlinks not allowed"):
        validate_path_safety(sym_dest)

    # Symlink further up the tree (grandparent, not the immediate parent) —
    # a symlinked ancestor anywhere in the path is still an escape from the
    # intended directory, not just at the leaf or the immediate parent.
    real_subdir = tmp_path / "real_subdir"
    real_subdir.mkdir()
    sym_grandparent = tmp_path / "sym_grandparent"
    sym_grandparent.symlink_to(real_subdir, target_is_directory=True)
    deep_dest = sym_grandparent / "nested" / "file.txt"
    with pytest.raises(CryptoError, match="Symlinks not allowed"):
        validate_path_safety(deep_dest)

    # Parent does not exist
    bad_parent = tmp_path / "nonexistent" / "file.txt"
    with pytest.raises(CryptoError, match="Parent directory does not exist"):
        validate_path_safety(bad_parent)


def test_safe_atomic_output_success(tmp_path):
    dest = tmp_path / "out.txt"
    with safe_atomic_output(dest) as writer:
        writer.write(b"data")

    assert dest.read_bytes() == b"data"


def test_safe_atomic_output_overwrite(tmp_path):
    dest = tmp_path / "out.txt"
    dest.write_bytes(b"old")

    with pytest.raises(CryptoError, match="already exists"):
        with safe_atomic_output(dest):
            pass

    with safe_atomic_output(dest, overwrite=True) as writer:
        writer.write(b"new")

    assert dest.read_bytes() == b"new"


def test_safe_atomic_output_failure_cleans_up_and_preserves(tmp_path):
    dest = tmp_path / "out.txt"
    dest.write_bytes(b"old")

    class TestError(Exception):
        pass

    with pytest.raises(TestError):
        with safe_atomic_output(dest, overwrite=True) as writer:
            writer.write(b"partial")
            raise TestError("failed")

    assert dest.read_bytes() == b"old"

    # Check no temp files left
    temps = list(tmp_path.glob(".*.tmp"))
    assert len(temps) == 0


def test_two_pass_auth_success(tmp_path):
    dest = tmp_path / "out.txt"

    auth_called = False

    def auth():
        nonlocal auth_called
        auth_called = True

    def write(writer):
        writer.write(b"ok")

    process_with_two_pass_auth(auth, write, dest)

    assert auth_called
    assert dest.read_bytes() == b"ok"


def test_two_pass_auth_failure_on_first_pass(tmp_path):
    dest = tmp_path / "out.txt"

    class AuthError(Exception):
        pass

    def auth():
        raise AuthError("auth failed")

    def write(writer):
        writer.write(b"ok")  # pragma: no cover

    with pytest.raises(AuthError):
        process_with_two_pass_auth(auth, write, dest)

    assert not dest.exists()
    temps = list(tmp_path.glob(".*.tmp"))
    assert len(temps) == 0


def test_two_pass_auth_failure_on_second_pass(tmp_path):
    dest = tmp_path / "out.txt"
    dest.write_bytes(b"old")

    def auth():
        pass

    def write(writer):
        writer.write(b"partial")
        raise ValueError("corrupt late tag or unexpected framing")

    with pytest.raises(ValueError, match="corrupt late tag"):
        process_with_two_pass_auth(auth, write, dest, overwrite=True)

    assert dest.read_bytes() == b"old"
    temps = list(tmp_path.glob(".*.tmp"))
    assert len(temps) == 0


def test_os_errors_during_write(tmp_path, monkeypatch):
    dest = tmp_path / "out.txt"

    def mock_fsync(fd):
        raise OSError("Disk full")

    monkeypatch.setattr(os, "fsync", mock_fsync)

    with pytest.raises(OSError, match="Disk full"):
        with safe_atomic_output(dest) as writer:
            writer.write(b"data")

    assert not dest.exists()
    temps = list(tmp_path.glob(".*.tmp"))
    assert len(temps) == 0


def test_cleanup_failure_is_suppressed(tmp_path, monkeypatch):
    dest = tmp_path / "out.txt"

    def mock_unlink(self):
        raise OSError("Permission denied")

    monkeypatch.setattr(Path, "unlink", mock_unlink)

    with pytest.raises(ValueError):
        with safe_atomic_output(dest):
            raise ValueError("abort")

    # The unlink OSError is suppressed, but the original ValueError bubbles up


class TestSystemSymlinkAllowlistIsLiteral:
    """The allowlist exempts only the literal allowlisted path.

    Matching a symlink's *target* instead would exempt any attacker-created
    symlink pointing at an allowlisted path. On a system where /var is an
    ordinary directory (Linux), `evil -> /var` would then let
    `evil/tmp/key.ssckey` redirect a keyfile or lock write into /var/tmp.
    """

    def test_symlink_pointing_at_an_allowlisted_path_is_still_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from secure_string_cipher.v2 import paths as v2_paths

        target = tmp_path / "allowlisted"
        target.mkdir()
        evil = tmp_path / "evil"
        evil.symlink_to(target)

        # Stand in for /var on a platform where it is a real directory.
        monkeypatch.setattr(v2_paths, "SYSTEM_SYMLINK_ALLOWLIST", frozenset({target}))

        assert v2_paths.is_allowed_system_symlink(evil) is False
        with pytest.raises(OSError, match="symlink"):
            v2_paths.reject_symlink_components(evil / "sub" / "key.ssckey")
        with pytest.raises(CryptoError, match="Symlinks not allowed"):
            validate_path_safety(evil / "sub" / "out.ssc")

    def test_the_allowlisted_component_itself_is_still_exempt(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """macOS ships /var as a symlink, which is why the exemption exists."""
        from secure_string_cipher.v2 import paths as v2_paths

        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)

        monkeypatch.setattr(v2_paths, "SYSTEM_SYMLINK_ALLOWLIST", frozenset({link}))

        assert v2_paths.is_allowed_system_symlink(link) is True
        v2_paths.reject_symlink_components(link / "sub" / "key.ssckey")
