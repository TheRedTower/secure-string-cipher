"""Parser and serializer for V2 .ssckey files."""

from __future__ import annotations

import base64
import contextlib
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from secure_string_cipher.v2.key_identity import compute_fingerprint

_KEY_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")

__all__ = [
    "KeyFileData",
    "parse_keyfile_content",
    "serialize_keyfile_content",
    "load_keyfile",
    "save_keyfile",
]

HEADER_BEGIN = "-----BEGIN SSC SYMMETRIC KEY-----"
HEADER_END = "-----END SSC SYMMETRIC KEY-----"


@dataclass(frozen=True, slots=True)
class KeyFileData:
    """Contents of a .ssckey file."""

    version: int
    key_id: str
    key_type: str
    kdf: str
    fingerprint: str
    created_at: str
    secret_bytes: bytes

    def __post_init__(self) -> None:
        if self.version != 1:
            raise ValueError("Unsupported keyfile version")
        if not isinstance(self.key_id, str) or not _KEY_ID_RE.match(self.key_id):
            raise ValueError("key_id must match pattern ^[a-z][a-z0-9._-]{0,63}$")
        if self.key_type != "symmetric-key":
            raise ValueError("Unsupported key type")
        if self.kdf != "hkdf-sha256":
            raise ValueError("Unsupported KDF")
        if not self.fingerprint.startswith("ssc-k1-") or len(self.fingerprint) != 59:
            raise ValueError("Invalid fingerprint format")
        # Validate timestamp format
        try:
            if not self.created_at.endswith("Z"):
                raise ValueError
            datetime.fromisoformat(self.created_at[:-1]).replace(tzinfo=timezone.utc)
        except ValueError as e:
            raise ValueError(
                "Created timestamp must be in YYYY-MM-DDTHH:MM:SSZ format"
            ) from e

        if len(self.secret_bytes) != 32:
            raise ValueError("secret_bytes must be exactly 32 bytes")


def _decode_b64_unpadded(b64_str: str) -> bytes:
    """Decode strict URL-safe Base64 without padding."""
    if "=" in b64_str:
        raise ValueError("Base64 padding is not permitted")
    if "+" in b64_str or "/" in b64_str:
        raise ValueError("Standard Base64 characters are not permitted")
    if any(c.isspace() for c in b64_str):
        raise ValueError("Whitespace in Base64 is not permitted")

    padded = b64_str + "=" * (-len(b64_str) % 4)
    decoded = base64.urlsafe_b64decode(padded)

    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != b64_str:
        raise ValueError("Invalid Base64 trailing bits")

    return decoded


def _encode_b64_unpadded(data: bytes) -> str:
    """Encode to strict URL-safe Base64 without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def parse_keyfile_content(content: str) -> KeyFileData:
    """Parse a V2 .ssckey file content and validate its integrity.

    Accepts canonical LF, or uniform CRLF converted at the outer armour boundary.
    Rejects mixed line endings or bare carriage returns.
    """
    if "\r" in content:
        without_crlf = content.replace("\r\n", "")
        if "\r" in without_crlf:
            raise ValueError("Mixed or invalid line endings: bare CR not permitted")
        if "\n" in without_crlf:
            raise ValueError(
                "Mixed line endings are not permitted (found both CRLF and LF)"
            )
        content = content.replace("\r\n", "\n")

    if not content.endswith("\n"):
        raise ValueError("Keyfile content must end with a newline")
    content = content[:-1]

    lines = content.split("\n")
    if len(lines) != 10:
        raise ValueError("Invalid keyfile format: incorrect number of lines")

    if lines[0] != HEADER_BEGIN:
        raise ValueError("Invalid BEGIN delimiter")
    if not lines[1].startswith("Version: "):
        raise ValueError("Missing or misplaced Version field")
    version = int(lines[1].split(": ", 1)[1])

    if not lines[2].startswith("Key-ID: "):
        raise ValueError("Missing or misplaced Key-ID field")
    key_id = lines[2].split(": ", 1)[1]

    if not lines[3].startswith("Type: "):
        raise ValueError("Missing or misplaced Type field")
    key_type = lines[3].split(": ", 1)[1]

    if not lines[4].startswith("KDF: "):
        raise ValueError("Missing or misplaced KDF field")
    kdf = lines[4].split(": ", 1)[1]

    if not lines[5].startswith("Fingerprint: "):
        raise ValueError("Missing or misplaced Fingerprint field")
    fingerprint = lines[5].split(": ", 1)[1]

    if not lines[6].startswith("Created: "):
        raise ValueError("Missing or misplaced Created field")
    created_at = lines[6].split(": ", 1)[1]

    if lines[7] != "":
        raise ValueError("Missing empty line before secret")

    b64_secret = lines[8]
    secret_bytes = _decode_b64_unpadded(b64_secret)

    if lines[9] != HEADER_END:
        raise ValueError("Invalid END delimiter")

    computed_fingerprint = compute_fingerprint(secret_bytes)
    if computed_fingerprint != fingerprint:
        raise ValueError("Fingerprint mismatch")

    return KeyFileData(
        version=version,
        key_id=key_id,
        key_type=key_type,
        kdf=kdf,
        fingerprint=fingerprint,
        created_at=created_at,
        secret_bytes=secret_bytes,
    )


def serialize_keyfile_content(data: KeyFileData) -> str:
    """Serialize KeyFileData to a V2 .ssckey string with LF endings."""
    b64_secret = _encode_b64_unpadded(data.secret_bytes)
    return "\n".join(
        [
            HEADER_BEGIN,
            f"Version: {data.version}",
            f"Key-ID: {data.key_id}",
            f"Type: {data.key_type}",
            f"KDF: {data.kdf}",
            f"Fingerprint: {data.fingerprint}",
            f"Created: {data.created_at}",
            "",
            b64_secret,
            HEADER_END,
            "",  # One final LF
        ]
    )


def load_keyfile(path: Path) -> KeyFileData:
    """Load and parse a .ssckey file with strict permission and bounds checks.

    Uses O_NOFOLLOW and fstat where supported to mitigate TOCTOU symlink race conditions.
    """
    if not path.is_file():
        raise OSError(f"{path} is not a regular file")

    # Python 3.8+ resolves strict=True, but we want to reject symlinks
    if path.is_symlink():
        raise OSError(f"{path} is a symlink, which is not permitted for keyfiles")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(f"{path} is not a regular file")

        # Check if POSIX permissions allow group/other access
        if os.name == "posix":
            if st.st_mode & 0o077:
                raise OSError(
                    f"{path} has insecure permissions (group or other access)"
                )

        if st.st_size > 8192:
            raise ValueError("Keyfile exceeds maximum permitted size (8192 bytes)")

        raw_bytes = b""
        while len(raw_bytes) <= 8192:
            chunk = os.read(fd, 8192 - len(raw_bytes) + 1)
            if not chunk:
                break
            raw_bytes += chunk
            if len(raw_bytes) > 8192:
                raise ValueError("Keyfile exceeds maximum permitted size (8192 bytes)")

        content = raw_bytes.decode("utf-8")
    finally:
        os.close(fd)

    return parse_keyfile_content(content)


def save_keyfile(data: KeyFileData, path: Path) -> None:
    """Serialize and save KeyFileData to the target path atomically with 0600 permissions."""
    if path.is_symlink():
        raise OSError(f"{path} is a symlink, which is not permitted for keyfiles")
    if path.parent.is_symlink():
        raise OSError(
            f"{path.parent} is a symlink, which is not permitted for keyfiles"
        )

    content = serialize_keyfile_content(data)
    content_bytes = content.encode("utf-8")

    tmp_path = path.with_suffix(path.suffix + ".tmp")

    created = False
    try:
        # Use os.open to strictly create with O_EXCL and 0600
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        try:
            os.write(fd, content_bytes)
        finally:
            os.close(fd)

        # Atomically replace
        os.replace(tmp_path, path)

        # Defense-in-depth: enforce 0600 on destination on POSIX
        if os.name == "posix":
            with contextlib.suppress(OSError):
                os.chmod(path, 0o600)
    except BaseException:
        if created:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
        raise
