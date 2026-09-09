"""Unit tests for V2 .ssckey file format."""

import base64
import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from secure_string_cipher.v2.key_identity import compute_fingerprint
from secure_string_cipher.v2.keyfile import (
    HEADER_BEGIN,
    HEADER_END,
    KeyFileData,
    load_keyfile,
    parse_keyfile_content,
    save_keyfile,
    serialize_keyfile_content,
)

VALID_SECRET = b"\x00" * 32
VALID_FINGERPRINT = compute_fingerprint(VALID_SECRET)
VALID_B64_SECRET = base64.urlsafe_b64encode(VALID_SECRET).decode("ascii").rstrip("=")

VALID_KEYFILE = f"""{HEADER_BEGIN}
Version: 1
Key-ID: test-key-1
Type: symmetric-key
KDF: hkdf-sha256
Fingerprint: {VALID_FINGERPRINT}
Created: 2026-09-09T00:00:00Z

{VALID_B64_SECRET}
{HEADER_END}
"""


def test_parse_valid_keyfile():
    """Parsing a valid keyfile should succeed."""
    data = parse_keyfile_content(VALID_KEYFILE)
    assert data.version == 1
    assert data.key_id == "test-key-1"
    assert data.key_type == "symmetric-key"
    assert data.kdf == "hkdf-sha256"
    assert data.fingerprint == VALID_FINGERPRINT
    assert data.created_at == "2026-09-09T00:00:00Z"
    assert data.secret_bytes == VALID_SECRET


def test_parse_crlf():
    """Parsing CRLF lines should succeed."""
    crlf_content = VALID_KEYFILE.replace("\n", "\r\n")
    data = parse_keyfile_content(crlf_content)
    assert data.secret_bytes == VALID_SECRET


def test_serialize_valid_keyfile():
    """Serializing KeyFileData should produce canonical format."""
    data = KeyFileData(
        version=1,
        key_id="test-key-1",
        key_type="symmetric-key",
        kdf="hkdf-sha256",
        fingerprint=VALID_FINGERPRINT,
        created_at="2026-09-09T00:00:00Z",
        secret_bytes=VALID_SECRET,
    )
    serialized = serialize_keyfile_content(data)
    assert serialized == VALID_KEYFILE


def test_parse_invalid_fingerprint():
    """Parsing a keyfile with mismatched fingerprint should fail."""
    invalid_content = VALID_KEYFILE.replace(VALID_FINGERPRINT, "ssc-k1-" + "A" * 45)
    with pytest.raises(
        ValueError, match="Fingerprint mismatch|Invalid fingerprint format"
    ):
        parse_keyfile_content(invalid_content)


def test_parse_invalid_b64_padding():
    """Parsing secret with Base64 padding should fail."""
    content = VALID_KEYFILE.replace(VALID_B64_SECRET, VALID_B64_SECRET + "=")
    with pytest.raises(ValueError, match="Base64 padding is not permitted"):
        parse_keyfile_content(content)


def test_parse_invalid_b64_chars():
    """Parsing secret with standard Base64 chars (+, /) should fail."""
    content = VALID_KEYFILE.replace(VALID_B64_SECRET, VALID_B64_SECRET[:-1] + "+")
    with pytest.raises(
        ValueError, match="Standard Base64 characters are not permitted"
    ):
        parse_keyfile_content(content)


def test_parse_invalid_secret_length():
    """Parsing secret that is not 32 bytes should fail."""
    short_secret = b"\x00" * 31
    short_b64 = base64.urlsafe_b64encode(short_secret).decode("ascii").rstrip("=")
    content = VALID_KEYFILE.replace(VALID_B64_SECRET, short_b64)
    with pytest.raises(
        ValueError,
        match="managed_secret must be exactly 32 bytes|secret_bytes must be exactly 32 bytes",
    ):
        parse_keyfile_content(content)


def test_parse_missing_empty_line():
    """Parsing keyfile without the empty line should fail."""
    content = VALID_KEYFILE.replace(
        "Created: 2026-09-09T00:00:00Z\n\n", "Created: 2026-09-09T00:00:00Z\n"
    )
    with pytest.raises(
        ValueError,
        match="Invalid keyfile format: incorrect number of lines|Missing empty line before secret",
    ):
        parse_keyfile_content(content)


def test_parse_invalid_timestamp():
    """Parsing an invalid timestamp should fail."""
    content = VALID_KEYFILE.replace(
        "Created: 2026-09-09T00:00:00Z", "Created: 2026-09-09 00:00:00"
    )
    with pytest.raises(
        ValueError, match="Created timestamp must be in YYYY-MM-DDTHH:MM:SSZ format"
    ):
        parse_keyfile_content(content)


def test_load_keyfile_symlink(tmp_path: Path):
    """Loading from a symlink should fail."""
    target = tmp_path / "target.ssckey"
    target.write_text(VALID_KEYFILE)
    symlink = tmp_path / "link.ssckey"
    symlink.symlink_to(target)

    with pytest.raises(OSError, match="is a symlink"):
        load_keyfile(symlink)


def test_save_keyfile_symlink(tmp_path: Path):
    """Saving to a symlink should fail."""
    data = parse_keyfile_content(VALID_KEYFILE)
    target = tmp_path / "target.ssckey"
    target.touch()
    symlink = tmp_path / "link.ssckey"
    symlink.symlink_to(target)

    with pytest.raises(OSError, match="is a symlink"):
        save_keyfile(data, symlink)


@patch("os.name", "posix")
def test_load_keyfile_insecure_permissions(tmp_path: Path):
    """Loading a keyfile with group/other access on POSIX should fail."""
    keyfile = tmp_path / "test.ssckey"
    keyfile.write_text(VALID_KEYFILE)
    # chmod to 0644 (group readable)
    keyfile.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

    with pytest.raises(OSError, match="insecure permissions"):
        load_keyfile(keyfile)


def test_load_keyfile_too_large(tmp_path: Path):
    """Loading a keyfile that is too large should fail."""
    keyfile = tmp_path / "test.ssckey"
    # Create a 9000 byte file
    keyfile.write_bytes(b"A" * 9000)
    keyfile.chmod(0o600)

    with pytest.raises(ValueError, match="exceeds maximum permitted size"):
        load_keyfile(keyfile)


def test_save_and_load_roundtrip(tmp_path: Path):
    """Save and load should correctly roundtrip data and set secure permissions."""
    data = parse_keyfile_content(VALID_KEYFILE)
    path = tmp_path / "roundtrip.ssckey"

    save_keyfile(data, path)

    loaded_data = load_keyfile(path)
    assert data == loaded_data

    # On POSIX, check that permissions are 0600
    if os.name == "posix":
        st = path.stat()
        assert (st.st_mode & 0o777) == 0o600


def test_parse_mixed_line_endings_rejected():
    """Mixed line endings (CRLF and LF) must be rejected."""
    # Convert only first newline to CRLF
    mixed = VALID_KEYFILE.replace(f"{HEADER_BEGIN}\n", f"{HEADER_BEGIN}\r\n", 1)
    with pytest.raises(ValueError, match="Mixed line endings are not permitted"):
        parse_keyfile_content(mixed)


def test_parse_bare_cr_rejected():
    """Bare CR line endings must be rejected."""
    bare_cr = VALID_KEYFILE.replace("\n", "\r")
    with pytest.raises(ValueError, match="bare CR not permitted"):
        parse_keyfile_content(bare_cr)


def test_parse_missing_trailing_newline_accepted():
    """The transport permits omission of the single final line ending."""
    no_newline = VALID_KEYFILE.rstrip("\n")
    assert parse_keyfile_content(no_newline) == parse_keyfile_content(VALID_KEYFILE)


def test_key_file_data_invalid_key_id():
    """Invalid key IDs in KeyFileData must be rejected."""
    for invalid_id in ["", "Test-key", "1key", "-key", "key with space", "k" * 65]:
        with pytest.raises(ValueError, match="key_id must match pattern"):
            KeyFileData(
                version=1,
                key_id=invalid_id,
                key_type="symmetric-key",
                kdf="hkdf-sha256",
                fingerprint=VALID_FINGERPRINT,
                created_at="2026-09-09T00:00:00Z",
                secret_bytes=VALID_SECRET,
            )


def test_save_keyfile_cleanup_on_failure(tmp_path: Path):
    """If write or replace fails in save_keyfile, temp file must be cleaned up."""
    data = parse_keyfile_content(VALID_KEYFILE)
    path = tmp_path / "failure_test.ssckey"
    tmp_path_file = path.with_suffix(path.suffix + ".tmp")

    with patch("os.link", side_effect=OSError("Disk write error")):
        with pytest.raises(OSError, match="Disk write error"):
            save_keyfile(data, path)

    assert not tmp_path_file.exists()
    assert list(tmp_path.glob(".*.tmp")) == []


def test_secret_is_excluded_from_repr():
    data = parse_keyfile_content(VALID_KEYFILE)
    assert "secret_bytes" not in repr(data)
    assert repr(VALID_SECRET) not in repr(data)


def test_save_never_replaces_existing_key(tmp_path: Path):
    path = tmp_path / "existing.ssckey"
    path.write_bytes(b"previous synthetic key")
    with pytest.raises(FileExistsError):
        save_keyfile(parse_keyfile_content(VALID_KEYFILE), path)
    assert path.read_bytes() == b"previous synthetic key"


def test_save_rejects_destination_created_during_publication(tmp_path: Path):
    path = tmp_path / "raced.ssckey"
    real_link = os.link

    def create_competing_key(source, destination):
        Path(destination).write_bytes(b"competing synthetic key")
        real_link(source, destination)

    with (
        patch("os.link", side_effect=create_competing_key),
        pytest.raises(FileExistsError),
    ):
        save_keyfile(parse_keyfile_content(VALID_KEYFILE), path)
    assert path.read_bytes() == b"competing synthetic key"
    assert list(tmp_path.glob(".*.tmp")) == []


def test_keyfile_rejects_symlinked_ancestor(tmp_path: Path):
    real = tmp_path / "real"
    (real / "nested").mkdir(parents=True)
    link = tmp_path / "alias"
    link.symlink_to(real, target_is_directory=True)
    data = parse_keyfile_content(VALID_KEYFILE)
    save_keyfile(data, real / "nested" / "test.ssckey")
    with pytest.raises(OSError, match="symlink"):
        load_keyfile(link / "nested" / "test.ssckey")
    with pytest.raises(OSError, match="symlink"):
        save_keyfile(data, link / "nested" / "new.ssckey")


@pytest.mark.parametrize(
    "created",
    [
        "2026-09-09Z",
        "2026-09-09 00:00:00Z",
        "2026-09-09T00:00:00.1Z",
        "2026-02-30T00:00:00Z",
    ],
)
def test_keyfile_rejects_noncanonical_dates(created):
    with pytest.raises(ValueError):
        parse_keyfile_content(VALID_KEYFILE.replace("2026-09-09T00:00:00Z", created))
