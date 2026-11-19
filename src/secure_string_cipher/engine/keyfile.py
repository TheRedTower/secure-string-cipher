"""Key files, `.ssckey` (VAULT.md section 6): one key as text.

A key file is a plaintext bearer secret: anyone who has it has the key.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

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
        if not _valid_created(self.created):
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


def _valid_created(text: str) -> bool:
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
    if not _valid_created(created):
        raise _bad("The Created timestamp is not valid.")
    if not re.fullmatch(r"[0-9a-f]{32}", key_id_text):
        raise _bad("The Key-ID is not 32 lowercase hex characters.")
    if bytes.fromhex(key_id_text) != access.key_id(key):
        raise FormatError(
            Reason.KEYFILE_KEY_ID,
            "The key file's Key-ID does not match its key: it is damaged or edited.",
        )
    return KeyFile(label, created, key)


def read(path: str | os.PathLike[str]) -> KeyFile:
    """Read a key file under the credential-file rules (CLI.md section 1):
    a regular file, not a symlink, and on POSIX not readable by group or
    others."""
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    if path.is_symlink():
        raise PermissionError(f"Refusing a symlinked key file: {path}")
    fd = os.open(path, flags)
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
    """Write a new key file, owner-only. It never replaces an existing file."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(Path(path), flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(keyfile.to_bytes())
