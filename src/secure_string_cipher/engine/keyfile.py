"""Key files, `.ssckey` (VAULT.md section 6): one key as text.

A key file is a plaintext bearer secret: anyone who has it has the key.
"""

from __future__ import annotations

import base64
import binascii
import errno
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from secure_string_cipher import fs
from secure_string_cipher.engine import access, armor
from secure_string_cipher.errors import FormatError, Reason

BEGIN = b"-----BEGIN SSC KEY-----"
END = b"-----END SSC KEY-----"
MAX_SIZE = 1024
LABEL = re.compile(r"[a-z][a-z0-9._-]{0,63}")
CREATED = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_KEY_TEXT = re.compile(r"[A-Za-z0-9_-]{43}")


def _bad(message: str) -> FormatError:
    return FormatError(Reason.KEYFILE, message)


def timestamp(when: datetime | None = None) -> str:
    """The entry timestamp form, `YYYY-MM-DDTHH:MM:SSZ`, in UTC."""
    when = datetime.now(UTC) if when is None else when.astimezone(UTC)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class KeyFile:
    label: str
    created: str
    key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not LABEL.fullmatch(self.label):
            raise ValueError(f"Not a valid label: {self.label!r}")
        if not valid_timestamp(self.created):
            raise ValueError(f"Not a valid timestamp: {self.created!r}")
        if len(self.key) != access.KEY_SIZE:
            raise ValueError(f"A key must be {access.KEY_SIZE} bytes.")

    @property
    def key_id(self) -> bytes:
        return access.key_id(self.key)

    def to_bytes(self) -> bytes:
        key_text = base64.urlsafe_b64encode(self.key).rstrip(b"=")
        return (
            b"\n".join(
                [
                    BEGIN,
                    b"Label: " + self.label.encode(),
                    b"Created: " + self.created.encode(),
                    b"Key-ID: " + self.key_id.hex().encode(),
                    key_text,
                    END,
                ]
            )
            + b"\n"
        )


def valid_timestamp(text: str) -> bool:
    """Whether `text` is a real time in the entry timestamp form."""
    if not CREATED.fullmatch(text):
        return False
    try:
        datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return False
    return True


def _field(line: bytes, name: bytes) -> str:
    prefix = name + b": "
    if not line.startswith(prefix):
        raise _bad(f"Expected the {name.decode()} field.")
    try:
        return line[len(prefix) :].decode("ascii")
    except UnicodeDecodeError:
        raise _bad(f"The {name.decode()} field is not ASCII.") from None


def _key(line: bytes) -> bytes:
    try:
        text = line.decode("ascii")
    except UnicodeDecodeError:
        raise _bad("The key line is not ASCII.") from None
    if not _KEY_TEXT.fullmatch(text):
        raise _bad("The key line is not 43 Base64url characters.")
    try:
        key = base64.urlsafe_b64decode(text + "=")
    except (binascii.Error, ValueError):
        raise _bad("The key line is not valid Base64url.") from None
    if base64.urlsafe_b64encode(key).rstrip(b"=") != line:
        raise _bad("The key line is not canonical Base64url.")
    return key


def is_keyfile(data: bytes) -> bool:
    """SSC recognises a key file by its BEGIN line, never by its name."""
    return data.startswith(BEGIN)


def parse(data: bytes) -> KeyFile:
    """Parse a key file strictly, and check its Key-ID."""
    if len(data) > MAX_SIZE:
        raise _bad("A key file is at most 1 KiB.")
    lines = armor.split_lines(data)
    if len(lines) != 6 or lines[0] != BEGIN or lines[-1] != END:
        raise _bad("This is not one SSC key file.")
    label = _field(lines[1], b"Label")
    created = _field(lines[2], b"Created")
    key_id_text = _field(lines[3], b"Key-ID")
    key = _key(lines[4])
    if not LABEL.fullmatch(label):
        raise _bad("The label is not valid.")
    if not valid_timestamp(created):
        raise _bad("The Created timestamp is not valid.")
    if not re.fullmatch(r"[0-9a-f]{32}", key_id_text):
        raise _bad("The Key-ID is not 32 lowercase hex characters.")
    if bytes.fromhex(key_id_text) != access.key_id(key):
        raise FormatError(
            Reason.KEYFILE_KEY_ID,
            "The key file's Key-ID does not match its key: it is damaged or edited.",
        )
    return KeyFile(label, created, key)


# POSIX-only open flags; 0 where the platform lacks them.
_NOFOLLOW: int = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY: int = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK: int = getattr(os, "O_NONBLOCK", 0)
_BINARY: int = getattr(os, "O_BINARY", 0)
# Directories are opened search-only where possible (O_PATH on Linux,
# O_SEARCH on macOS), so a parent with execute but not read permission
# still works, as it does for an ordinary open.
_SEARCH: int = getattr(os, "O_PATH", 0) or getattr(os, "O_SEARCH", 0) or os.O_RDONLY


def _refuse_symlink(path: Path) -> PermissionError:
    return PermissionError(f"Refusing a key file reached through a symlink: {path}")


def _open_at(name: str, flags: int, dir_fd: int, path: Path) -> int:
    """Open one component under `dir_fd`, refusing a symlink. O_NOFOLLOW
    makes the open itself fail on a link swapped in after the check, and the
    check turns the platform's error for that into one clear refusal."""
    if stat.S_ISLNK(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode):
        raise _refuse_symlink(path)
    try:
        return os.open(name, flags | _NOFOLLOW, dir_fd=dir_fd)
    except OSError as error:
        if error.errno in (errno.ELOOP, getattr(errno, "EMLINK", errno.ELOOP)):
            raise _refuse_symlink(path) from None
        raise


def _open_no_symlinks(path: Path) -> int:
    """Open `path` for reading without following a symlink anywhere on the
    way to it (CLI.md section 1), and without blocking on a FIFO."""
    # Absolute, but not normalised: collapsing "alias/.." here would skip
    # checking `alias`, and could name a different file than the kernel would.
    path = path if path.is_absolute() else Path.cwd() / path
    if os.open in os.supports_dir_fd and _NOFOLLOW and _DIRECTORY:
        # Walk one component at a time from the root, so no component can
        # be swapped for a link between the check and the open.
        fd = os.open(path.anchor, _SEARCH | _DIRECTORY)
        try:
            for part in path.parts[1:-1]:
                following = _open_at(part, _SEARCH | _DIRECTORY, fd, path)
                os.close(fd)
                fd = following
            return _open_at(path.name, os.O_RDONLY | _NONBLOCK, fd, path)
        finally:
            os.close(fd)
    # Windows has no dir_fd: check each component, then open.
    for component in (path, *path.parents):
        if component.is_symlink() or component.is_junction():
            raise _refuse_symlink(path)
    return os.open(path, os.O_RDONLY | _BINARY)


def read(path: str | os.PathLike[str]) -> KeyFile:
    """Read a key file under the credential-file rules (CLI.md section 1):
    a regular file, not reached through a symlink, and on POSIX not readable
    by group or others."""
    path = Path(path)
    fd = _open_no_symlinks(path)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise PermissionError(f"A key file must be a regular file: {path}")
        if os.name == "posix" and info.st_mode & 0o044:
            raise PermissionError(
                f"A key file must not be readable by others (chmod 600): {path}"
            )
    except BaseException:
        os.close(fd)
        raise
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(MAX_SIZE + 1)
    return parse(data)


def write(path: str | os.PathLike[str], keyfile: KeyFile) -> None:
    """Write a new key file, owner-only. It never replaces an existing file,
    and a failed write leaves nothing at `path` (FORMAT.md section 7.5)."""
    path = Path(path)
    if os.path.lexists(path):
        raise FileExistsError(errno.EEXIST, "A file is already there", str(path))
    fs.write_atomic(path, lambda out: out.write(keyfile.to_bytes()), replace=False)
