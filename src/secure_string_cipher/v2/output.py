from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

from secure_string_cipher.atomic_io import atomic_binary_writer
from secure_string_cipher.utils import CryptoError
from secure_string_cipher.v2.paths import is_allowed_system_symlink


def validate_path_safety(path: Path | str) -> Path:
    """Validate that path and every ancestor component are safe for I/O.

    A symlinked *ancestor* further up the tree (e.g. /safe/link/subdir/out,
    where only `link` is a symlink) is just as much an escape from the
    intended directory as a symlinked target or immediate parent — checking
    only those two lets an attacker-controlled grandparent symlink redirect
    the whole path silently. The one exception is a small allowlist of
    known-benign OS-level symlinks (v2/paths.py::SYSTEM_SYMLINK_ALLOWLIST),
    shared with the keyfile and lock-file checks so v2 applies one policy.
    """
    p = Path(path)
    absolute_path = p if p.is_absolute() else Path.cwd() / p

    for current in [absolute_path, *absolute_path.parents]:
        if current == current.parent:
            break
        try:
            if current.is_symlink() and not is_allowed_system_symlink(current):
                raise CryptoError(f"Symlinks not allowed: {current}")
        except OSError as e:
            raise CryptoError(f"Unable to validate path: {current}") from e

    parent = p.parent
    if not parent.exists():
        raise CryptoError(f"Parent directory does not exist: {parent}")
    if not parent.is_dir():
        raise CryptoError(f"Parent is not a directory: {parent}")
    return p


@contextmanager
def safe_atomic_output(
    destination: Path | str, overwrite: bool = False
) -> Iterator[BinaryIO]:
    """Atomic binary writer with path safety checks."""
    dest_path = validate_path_safety(destination)

    with atomic_binary_writer(dest_path, overwrite=overwrite, mode=0o600) as writer:
        yield writer


def process_with_two_pass_auth(
    auth_pass_fn: Callable[[], None],
    write_pass_fn: Callable[[BinaryIO], None],
    destination: Path | str,
    overwrite: bool = False,
) -> None:
    """
    Perform a two-pass operation for metadata-derived destinations.
    The first pass fully authenticates the data without writing.
    The second pass writes the authenticated data to the destination.
    """
    dest_path = validate_path_safety(destination)

    if dest_path.exists() and not overwrite:
        raise CryptoError(f"Output file already exists: {dest_path}")

    # First pass: authenticate without writing
    auth_pass_fn()

    # Second pass: write
    with safe_atomic_output(dest_path, overwrite=overwrite) as writer:
        write_pass_fn(writer)
