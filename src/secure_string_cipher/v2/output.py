from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

from secure_string_cipher.atomic_io import atomic_binary_writer
from secure_string_cipher.utils import CryptoError


def validate_path_safety(path: Path | str) -> Path:
    """Validate that path and its parent are safe for I/O."""
    p = Path(path)
    if p.is_symlink():
        raise CryptoError(f"Symlinks not allowed: {p}")
    parent = p.parent
    if parent.is_symlink():
        raise CryptoError(f"Parent directory symlinks not allowed: {parent}")
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
