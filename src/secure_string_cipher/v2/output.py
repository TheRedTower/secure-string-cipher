from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

from secure_string_cipher.atomic_io import atomic_binary_writer
from secure_string_cipher.utils import CryptoError

# Mirrors core.py's _SYSTEM_SYMLINK_ALLOWLIST: some OS installs make a stable
# system path (macOS's /var -> /private/var, notably) a symlink. Rejecting
# every ancestor unconditionally would reject ordinary paths under /var,
# including every pytest tmp_path on macOS. Kept as its own copy rather than
# importing core.py's private constant — v1 and v2 are separate parallel
# implementations by design (see docs/V2_MANAGED_KEYS_ARCHITECTURE.md).
_SYSTEM_SYMLINK_ALLOWLIST = {Path("/var")}


def validate_path_safety(path: Path | str) -> Path:
    """Validate that path and every ancestor component are safe for I/O.

    A symlinked *ancestor* further up the tree (e.g. /safe/link/subdir/out,
    where only `link` is a symlink) is just as much an escape from the
    intended directory as a symlinked target or immediate parent — checking
    only those two lets an attacker-controlled grandparent symlink redirect
    the whole path silently. The one exception is a small allowlist of
    known-benign OS-level symlinks (see _SYSTEM_SYMLINK_ALLOWLIST above).
    """
    p = Path(path)
    absolute_path = p if p.is_absolute() else Path.cwd() / p

    for current in [absolute_path, *absolute_path.parents]:
        if current == current.parent:
            break
        try:
            if current.is_symlink():
                resolved = current.resolve(strict=False)
                allowed = any(
                    allowed_path == current or resolved == allowed_path
                    for allowed_path in _SYSTEM_SYMLINK_ALLOWLIST
                )
                if not allowed:
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
